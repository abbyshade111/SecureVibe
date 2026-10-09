//! What counts as fixed text: a literal, a name bound only to fixed text (`Fixed`), and the bindings
//! read to tell. Moved out of `ast.rs` unchanged on 9 October 2026 (architecture assessment, item 11).

use super::*;

/// Node kinds that are a value written in the source, with nothing substituted into them.
///
/// A template string is only a literal when nothing is interpolated, which is exactly the distinction
/// that matters: `` `SELECT 1` `` is a constant and `` `SELECT ${id}` `` is the bug this looks for.
///
/// `fixed` holds the names in the same file whose value is fixed text (`Fixed::of`), so `QUERY`,
/// `SCHEMA`, and `SORT_ORDERS[key]` are judged as the text they stand for.
pub(super) fn is_literal(node: tree_sitter::Node, source: &[u8], fixed: &Fixed) -> bool {
    if fixed.holds(node, source) {
        return true;
    }
    const LITERAL_KINDS: &[&str] = &[
        "string",
        "string_literal",
        "raw_string_literal",
        "interpreted_string_literal",
        "concatenated_string",
        "template_string",
        "integer",
        "float",
        "number",
        "true",
        "false",
        "none",
        "null",
        // Ruby's backtick form. `ls -la` is as fixed as any string; `ls #{dir}` is not, and the
        // interpolation check below is what tells them apart — the same test every other kind gets.
        "subshell",
        // C#'s plain strings and Kotlin's, whose grammar gives an interpolated one no node of its
        // own — see `has_interpolation` for how those two are told apart.
        "verbatim_string_literal",
        // PHP's double-quoted strings, which interpolate `$name` without any `{}` around it.
        "encapsed_string",
        "string_value",
        // Swift's strings, one line and several. Interpolation is `\(x)`, which the grammar gives a
        // node of its own; see `has_interpolation`.
        "line_string_literal",
        "multi_line_string_literal",
        // PHP's backtick form, which interpolates `$name` the way its double-quoted strings do.
        "shell_command_expression",
        // Shell: a bare word, a single-quoted string (which expands nothing), and a double-quoted one,
        // which is `string` like everyone else's and is told apart by `has_interpolation`.
        "word",
        "raw_string",
    ];

    // Swift's argument, labeled or not, is judged by the value it carries: the label is part of
    // the text a pattern can read, and never part of what was built.
    if node.kind() == "value_argument" {
        return node
            .child_by_field_name("value")
            .is_some_and(|value| is_literal(value, source, fixed));
    }
    // `["-c", "ls"]` is as fixed as the strings in it, and `["-c", cmd]` is not: a command handed to
    // a shell as the second element of a list is the Dart, Swift, and Rust way to write `sh -c`.
    // Python's grammar calls a list `list` (and a tuple `tuple`), JavaScript's and TypeScript's
    // `array`, so `run(["ls", "-la"], shell=True)` is a fixed command too.
    // Backlog 215, Python: `a if c else b` is fixed when both values are; `SEP.join(pieces)` when
    // the separator is and the pieces are a list of fixed text written in place, or a list the
    // function itself builds only of fixed text (`fixed_list`), never a name the file binds once,
    // since a module's list can be appended to from any function; an f-string when everything put
    // into it is.
    if fixed.python {
        if node.kind() == "conditional_expression"
            && let Some(branches) = choice_branches(node, source)
        {
            return branches.len() == 2
                && branches.into_iter().all(|b| is_literal(b, source, fixed));
        }
        if node.kind() == "call"
            && called_name(node, source) == Some("join")
            && let Some(function) = node.child_by_field_name("function")
            && function.kind() == "attribute"
            && let Some(separator) = function.child_by_field_name("object")
            && let Some(arguments) = node.child_by_field_name("arguments")
        {
            let mut c = arguments.walk();
            let args: Vec<_> = arguments
                .named_children(&mut c)
                .filter(|a| a.kind() != "comment")
                .collect();
            return is_literal(separator, source, fixed)
                && matches!(args.as_slice(), [pieces]
                    if (matches!(pieces.kind(), "list" | "tuple") && is_literal(*pieces, source, fixed))
                        || fixed.fixed_list(*pieces, source));
        }
        if node.kind() == "string" {
            let mut c = node.walk();
            let interpolations: Vec<_> = node
                .named_children(&mut c)
                .filter(|p| p.kind() == "interpolation")
                .collect();
            if !interpolations.is_empty() {
                return interpolations.into_iter().all(|i| {
                    let mut c = i.walk();
                    // A format spec with a value of its own in it (`{x:{width}}`) is built too.
                    !i.named_children(&mut c)
                        .any(|p| p.kind() == "format_specifier" && has_interpolation(p, source))
                        && i.child_by_field_name("expression")
                            .is_some_and(|e| is_literal(e, source, fixed))
                });
            }
        }
    }
    if matches!(
        node.kind(),
        "list_literal" | "array_literal" | "array_expression" | "list" | "tuple" | "array" | "set"
    ) {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .filter(|c| c.kind() != "type_arguments")
            .all(|c| is_literal(c, source, fixed));
    }

    // `"a" + "b"` is still a constant; `"a" + name` is not. Python's `a or b` and a bracketed
    // expression are fixed when what is inside them is.
    if matches!(
        node.kind(),
        "binary_operator"
            | "binary_expression"
            | "additive_expression"
            | "concatenation"
            | "boolean_operator"
            | "parenthesized_expression"
    ) {
        let mut cursor = node.walk();
        return node.named_child_count() > 0
            && node
                .named_children(&mut cursor)
                .filter(|c| c.kind() != "comment")
                .all(|c| is_literal(c, source, fixed));
    }
    // Rust's macros that are read when the code is compiled: `env!("OUT_DIR")` and
    // `include_str!("schema.sql")` are fixed text in the program, whatever anyone sends it. `format!` is
    // not among them: it runs with the program.
    if node.kind() == "macro_invocation" {
        return compile_time_text(node, source);
    }
    if !LITERAL_KINDS.contains(&node.kind()) {
        return false;
    }
    // Anything with a value substituted into it was built, not written: a JavaScript template string
    // with `${…}` and a Python f-string with `{…}` are the same thing under different node names, and
    // an f-string is still a plain `string` node in its grammar. Missing this reports every SQL query
    // built with an f-string as a constant, which is the case the rule exists for.
    !has_interpolation(node, source)
}

/// Rust's macros the compiler expands into fixed text, so what they give is in the program before it
/// runs: the build's environment, a file's contents, where in the source the call is, a token written
/// out as text, and `concat!` of these, which the compiler accepts only when all it joins is literal.
pub(super) const COMPILE_TIME_MACROS: &[&str] = &[
    "env",
    "option_env",
    "include_str",
    "include_bytes",
    "file",
    "line",
    "column",
    "module_path",
    "stringify",
    "concat",
];

/// Whether a Rust macro call gives text fixed when the code is compiled: one of
/// `COMPILE_TIME_MACROS`, by its own name or a path ending in it (`std::env!`).
pub(super) fn compile_time_text(node: tree_sitter::Node, source: &[u8]) -> bool {
    node.child_by_field_name("macro")
        .and_then(|m| m.utf8_text(source).ok())
        .is_some_and(|name| COMPILE_TIME_MACROS.contains(&name.rsplit("::").next().unwrap_or(name)))
}

/// Whether an argument is safe by a rule's `safeArgumentPattern` whichever way it goes. A pattern
/// reads how the argument starts, so `redirect("/home" if not nxt else nxt)` starts like a path on
/// the same site and was taken for one (item 19 of the review of 1 to 4 October). A choice between
/// values (`a if c else b`, `c ? a : b`, `a or b`, `a and b`, `a || b`, `a && b`, `a ?? b`) is safe
/// only when every value it can give is: by the pattern, or written out.
pub(super) fn safe_in_every_branch(
    node: tree_sitter::Node,
    source: &[u8],
    pattern: &regex::Regex,
    fixed: &Fixed,
) -> bool {
    match choice_branches(node, source) {
        None => node
            .utf8_text(source)
            .is_ok_and(|text| pattern.is_match(text)),
        Some(branches) => {
            !branches.is_empty()
                && branches.into_iter().all(|branch| {
                    is_literal(branch, source, fixed)
                        || safe_in_every_branch(branch, source, pattern, fixed)
                })
        }
    }
}

/// Whether every piece of a value built by joining text is fixed text or matches `pattern`: the
/// two sides of a `+`, each `${…}` of a template string, each `{…}` of a Python f-string, and each
/// value a choice can give. Anything else is judged whole, by `pattern`.
pub(super) fn safe_in_every_piece(
    node: tree_sitter::Node,
    source: &[u8],
    pattern: &regex::Regex,
    fixed: &Fixed,
) -> bool {
    if is_literal(node, source, fixed) {
        return true;
    }
    if let Some(branches) = choice_branches(node, source) {
        return !branches.is_empty()
            && branches
                .into_iter()
                .all(|branch| safe_in_every_piece(branch, source, pattern, fixed));
    }
    let named = || {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|c| c.kind() != "comment")
            .collect::<Vec<_>>()
    };
    let operator = node
        .child_by_field_name("operator")
        .and_then(|o| o.utf8_text(source).ok());
    let pieces: Vec<tree_sitter::Node> = match node.kind() {
        "binary_expression" | "binary_operator" if operator == Some("+") => named(),
        "parenthesized_expression" => named(),
        // `${…}` holds its expression; the text between them is fixed.
        "template_string" => named()
            .into_iter()
            .filter(|c| c.kind() == "template_substitution")
            .flat_map(|c| {
                let mut cursor = c.walk();
                c.named_children(&mut cursor).collect::<Vec<_>>()
            })
            .collect(),
        // An f-string's `{…}` is an `interpolation` whose `expression` is the value.
        "string" if named().iter().any(|c| c.kind() == "interpolation") => named()
            .into_iter()
            .filter(|c| c.kind() == "interpolation")
            .filter_map(|c| c.child_by_field_name("expression"))
            .collect(),
        _ => {
            return node
                .utf8_text(source)
                .is_ok_and(|text| pattern.is_match(text));
        }
    };
    !pieces.is_empty()
        && pieces
            .into_iter()
            .all(|piece| safe_in_every_piece(piece, source, pattern, fixed))
}

/// The values a choice can give; `None` when the node is not a choice between values, and none at
/// all when it is one whose values cannot be told apart, which nothing can then vouch for.
pub(super) fn choice_branches<'t>(
    node: tree_sitter::Node<'t>,
    source: &[u8],
) -> Option<Vec<tree_sitter::Node<'t>>> {
    let field = |name: &str| node.child_by_field_name(name);
    let named = || {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|c| c.kind() != "comment")
            .collect::<Vec<_>>()
    };
    match node.kind() {
        // Python's `a if c else b` has no field names: the value, the condition, the other value.
        "conditional_expression" if field("consequence").is_none() => {
            Some(match named().as_slice() {
                [yes, _, no] => vec![*yes, *no],
                _ => Vec::new(),
            })
        }
        "conditional_expression" | "ternary_expression" | "conditional" => {
            Some(match (field("consequence"), field("alternative")) {
                (Some(yes), Some(no)) => vec![yes, no],
                _ => Vec::new(),
            })
        }
        // `a or b` and `a and b` in Python and Ruby, `a || b`, `a && b`, and `a ?? b` elsewhere:
        // either side may be given, and `'/home' && next` gives the right one.
        "boolean_operator" | "binary_expression" | "binary" => {
            let operator = field("operator")
                .and_then(|o| o.utf8_text(source).ok())
                .unwrap_or_default();
            matches!(operator, "or" | "and" | "||" | "&&" | "??").then(|| {
                match (field("left"), field("right")) {
                    (Some(left), Some(right)) => vec![left, right],
                    _ => Vec::new(),
                }
            })
        }
        "parenthesized_expression" => match named().as_slice() {
            [only] if choice_branches(*only, source).is_some() => Some(vec![*only]),
            _ => None,
        },
        _ => None,
    }
}

/// Whether anything is substituted into this literal, however deeply.
pub(super) fn has_interpolation(node: tree_sitter::Node, source: &[u8]) -> bool {
    // Kotlin's `"select $n"` has no interpolation node at all: the grammar splits it into plain
    // `string_content` children and the bare `$` becomes one of them. Measured rather than guessed,
    // because the obvious discriminators are both wrong — a plain string has one `string_content`
    // and so does nothing else, while `"cost \$5"` has two of them either side of an
    // `escape_sequence`. The `$` standing alone as its own node is what actually distinguishes
    // them, and an escaped one never does.
    if node.kind() == "string_literal" {
        let mut cursor = node.walk();
        if node
            .named_children(&mut cursor)
            .any(|c| c.kind() == "string_content" && c.utf8_text(source).map(str::trim) == Ok("$"))
        {
            return true;
        }
    }

    // PHP puts a plain `variable_name` inside a double-quoted string, with no wrapper node to
    // recognize: `"select ... $name"` is a built string that looks like a literal to the list below.
    if matches!(node.kind(), "encapsed_string" | "shell_command_expression") {
        let mut cursor = node.walk();
        if node
            .named_children(&mut cursor)
            .any(|c| c.kind() != "string_content" && c.kind() != "escape_sequence")
        {
            return true;
        }
    }

    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "interpolation"
                | "template_substitution"
                | "string_interpolation"
                | "format_specifier"
                | "interpolated_expression"
                | "simple_expansion"
                | "expansion"
                | "command_substitution"
                | "process_substitution"
                | "arithmetic_expansion"
        ) || has_interpolation(child, source)
    })
}

/// The names in one file that stand for fixed text, worked out once before any rule runs.
///
/// A1 of the deep review: seven of family-hub's eight SQL findings were a query held in a constant,
/// `execute(QUERY, (uid,))`, which the rules read as a name and so as something built. A name counts
/// as fixed when the file binds it exactly once and that binding is fixed text, or names fixed text, or
/// it is an ALL_CAPS name bound once at the top of the module, whatever it holds (a module's
/// constants are written once, before any request exists). A name bound twice, reassigned with `+=`,
/// taken as a function's parameter, or used as a loop variable anywhere in the file is not fixed:
/// which binding reaches the call cannot be told without following the code, so none is trusted.
///
/// A table is a name bound once to a dictionary (or a JavaScript object) whose values are all fixed:
/// `SORT_ORDERS[key]`, `SORT_ORDERS.get(key, SORT_ORDERS["newest"])` give fixed text, whatever the key.
///
/// Read for Python, JavaScript, TypeScript, and Go. Other languages get no fixed names, which only
/// keeps the rules as they were.
#[derive(Debug, Default)]
pub(crate) struct Fixed {
    pub(super) names: BTreeSet<String>,
    pub(super) tables: BTreeSet<String>,
    /// Names every binding of which is a value read back from the app's database (`row =
    /// cur.fetchone()`, `for row in rows`), or text built only from those and fixed text: a path
    /// made of them is the app's own id, usually, not what a person typed (A1's leftovers).
    pub(super) from_database: BTreeSet<String>,
    /// Names every binding of which is a call to a function whose name says it checks what it is
    /// given (`next_url = safe_next(raw)`), with those functions' names, ready to be shown.
    pub(super) checked: BTreeMap<String, String>,
    /// Backlog 215: the file is Python, whose names are also judged in their own function (`local`).
    pub(super) python: bool,
    /// Tables whose every key is fixed text too, so a name checked against them is one of those keys.
    pub(super) keyed: BTreeSet<String>,
    /// How deep `local` is in judging one name by another, so a name defined by itself
    /// (`sort = sort + ""`) ends instead of going round for ever.
    pub(super) depth: std::cell::Cell<u8>,
}

/// One binding of a name: the value it was given, when the code says, and whether it sits at the top
/// of the module.
pub(super) struct Binding<'a> {
    pub(super) value: Option<tree_sitter::Node<'a>>,
    pub(super) top: bool,
    /// For a loop variable, what the loop goes over.
    pub(super) over: Option<tree_sitter::Node<'a>>,
}

impl Fixed {
    pub(crate) fn of(root: tree_sitter::Node, source: &[u8]) -> Fixed {
        let mut bindings: BTreeMap<String, Vec<Binding>> = BTreeMap::new();
        collect_bindings(root, source, &mut bindings);
        let mut fixed = Fixed {
            python: root.kind() == "module",
            ..Fixed::default()
        };
        // A name may stand for another (`SQL = BASE + " WHERE id = ?"`), so this runs until nothing
        // more is found; each round adds at least one name or stops.
        loop {
            let mut found = false;
            for (name, binds) in &bindings {
                let [only] = binds.as_slice() else { continue };
                if fixed.names.contains(name) || fixed.tables.contains(name) {
                    continue;
                }
                let Some(value) = only.value else { continue };
                if matches!(value.kind(), "dictionary" | "object") {
                    if table_is_fixed(value, source, &fixed) {
                        fixed.tables.insert(name.clone());
                        if keys_are_fixed(value, source, &fixed) {
                            fixed.keyed.insert(name.clone());
                        }
                        found = true;
                    }
                } else if is_literal(value, source, &fixed) || (only.top && is_constant_name(name))
                {
                    fixed.names.insert(name.clone());
                    found = true;
                }
            }
            if !found {
                break;
            }
        }
        // Names read back from the database, and what is built from them alone, the same way.
        loop {
            let mut found = false;
            for (name, binds) in &bindings {
                if fixed.from_database.contains(name) || fixed.names.contains(name) {
                    continue;
                }
                let read_back = |b: &Binding| match (b.value, b.over) {
                    (Some(value), _) => {
                        is_database_read(value, source)
                            || built_from_database(value, source, &fixed)
                    }
                    (None, Some(over)) => {
                        is_database_read(over, source)
                            || (over.kind() == "identifier"
                                && fixed
                                    .from_database
                                    .contains(over.utf8_text(source).unwrap_or("")))
                    }
                    (None, None) => false,
                };
                if !binds.is_empty() && binds.iter().all(read_back) {
                    fixed.from_database.insert(name.clone());
                    found = true;
                }
            }
            if !found {
                break;
            }
        }
        for (name, binds) in &bindings {
            let checkers: Option<BTreeSet<String>> = binds
                .iter()
                .map(|b| b.value.and_then(|v| checker_called(v, source)))
                .collect();
            if let Some(checkers) = checkers {
                let named: Vec<String> = checkers.iter().map(|c| format!("`{c}`")).collect();
                fixed.checked.insert(name.clone(), named.join(" or "));
            }
        }
        fixed
    }

    /// Whether `node` is built only from fixed text and values read back from the database, with at
    /// least one of the second.
    pub(crate) fn read_back(&self, node: tree_sitter::Node, source: &[u8]) -> bool {
        built_from_database(node, source, self)
    }

    /// The checking function `node` passed through, when it is a call to one or a name that only
    /// ever holds what one returned.
    pub(crate) fn checked_by(&self, node: tree_sitter::Node, source: &[u8]) -> Option<String> {
        if node.kind() == "identifier" {
            return self.checked.get(node.utf8_text(source).ok()?).cloned();
        }
        checker_called(node, source).map(|c| format!("`{c}`"))
    }

    /// Whether this node is a fixed name, or a lookup in a fixed table.
    fn holds(&self, node: tree_sitter::Node, source: &[u8]) -> bool {
        if self.python
            && node.kind() == "identifier"
            && let Some(fixed) = self.local(node, source)
        {
            return fixed;
        }
        if self.names.is_empty() && self.tables.is_empty() {
            return false;
        }
        let text = |n: tree_sitter::Node| n.utf8_text(source).unwrap_or("");
        let table = |n: Option<tree_sitter::Node>| {
            n.is_some_and(|n| n.kind() == "identifier" && self.tables.contains(text(n)))
        };
        match node.kind() {
            "identifier" => self.names.contains(text(node)),
            // `TABLE[key]`, Python's and JavaScript's.
            "subscript" => table(node.child_by_field_name("value")),
            "subscript_expression" => table(node.child_by_field_name("object")),
            // Python's `TABLE.get(key)` and `TABLE.get(key, <fixed>)`.
            "call" => {
                let Some(function) = node.child_by_field_name("function") else {
                    return false;
                };
                if function.kind() != "attribute"
                    || !table(function.child_by_field_name("object"))
                    || function.child_by_field_name("attribute").map(text) != Some("get")
                {
                    return false;
                }
                let Some(arguments) = node.child_by_field_name("arguments") else {
                    return false;
                };
                let mut cursor = arguments.walk();
                arguments
                    .named_children(&mut cursor)
                    .filter(|c| c.kind() != "comment")
                    .skip(1)
                    .all(|c| is_literal(c, source, self))
            }
            _ => false,
        }
    }

    /// Backlog 215: a Python name judged in the function it is used in. `None` when that function
    /// does not bind it, so the file's own judgment stands. Otherwise fixed when a guard before the
    /// use leaves the function unless the name is one of a fixed list (`guarded`), or when the
    /// function binds it exactly once, not as a parameter, to fixed text. A Flask app binds `sort` in
    /// several routes, which the file-wide judgment cannot trust; in its own function it is one
    /// assignment. Anything that may bind it unseen (`global`, `nonlocal`, `with ... as`, an import,
    /// an exception's name) makes it not fixed.
    fn local(&self, node: tree_sitter::Node, source: &[u8]) -> Option<bool> {
        let function = enclosing_function(node)?;
        let name = node.utf8_text(source).ok()?;
        let mut bindings: BTreeMap<String, Vec<Binding>> = BTreeMap::new();
        collect_bindings(function, source, &mut bindings);
        let binds = bindings.get(name)?;
        if binds_unseen(function, name, source) {
            return Some(false);
        }
        if self.depth.get() >= 8 {
            return Some(false);
        }
        self.depth.set(self.depth.get() + 1);
        // A list, a set, or a dictionary can be changed after it is bound (`clauses.append(x)`,
        // handed to a function), so one binding to fixed items says nothing on its own: a list is
        // judged by everything done to it (`fixed_list`), and the others are not fixed here.
        let fixed = self.guarded(function, node, name, source)
            || match binds.as_slice() {
                [only] => only.value.is_some_and(|value| match value.kind() {
                    "list" => self.fixed_list(node, source),
                    "set"
                    | "dictionary"
                    | "list_comprehension"
                    | "set_comprehension"
                    | "dictionary_comprehension" => false,
                    _ => is_literal(value, source, self),
                }),
                _ => false,
            };
        self.depth.set(self.depth.get() - 1);
        Some(fixed)
    }

    /// Whether a statement of the function's own body, before `node`, is `if name not in FIXED:` with
    /// no `elif` or `else` and a block that always leaves (its last statement a `return`, a `raise`,
    /// or a call to `abort`), and nothing after that statement binds the name again. `FIXED` is a
    /// list, tuple or set of fixed text, a name for one, or a table whose keys are all fixed.
    fn guarded(
        &self,
        function: tree_sitter::Node,
        node: tree_sitter::Node,
        name: &str,
        source: &[u8],
    ) -> bool {
        let Some(body) = function.child_by_field_name("body") else {
            return false;
        };
        let text = |n: tree_sitter::Node| n.utf8_text(source).unwrap_or("");
        let mut cursor = body.walk();
        let statements: Vec<_> = body.named_children(&mut cursor).collect();
        statements.iter().enumerate().any(|(i, guard)| {
            if guard.kind() != "if_statement" || guard.end_byte() > node.start_byte() {
                return false;
            }
            let mut c = guard.walk();
            if guard
                .children_by_field_name("alternative", &mut c)
                .next()
                .is_some()
            {
                return false;
            }
            let Some(condition) = guard.child_by_field_name("condition") else {
                return false;
            };
            if condition.kind() != "comparison_operator" {
                return false;
            }
            let mut c = condition.walk();
            let parts: Vec<_> = condition.children(&mut c).collect();
            let [left, operator @ .., right] = parts.as_slice() else {
                return false;
            };
            let operator: Vec<&str> = operator.iter().map(|o| text(*o)).collect();
            if left.kind() != "identifier"
                || text(*left) != name
                || operator != ["not in"] && operator != ["not", "in"]
            {
                return false;
            }
            let list_fixed = is_literal(*right, source, self)
                || (right.kind() == "identifier" && self.keyed.contains(text(*right)));
            let leaves = guard
                .child_by_field_name("consequence")
                .and_then(|block| {
                    let mut c = block.walk();
                    block
                        .named_children(&mut c)
                        .filter(|s| s.kind() != "comment")
                        .last()
                })
                .is_some_and(|last| match last.kind() {
                    "return_statement" | "raise_statement" => true,
                    "expression_statement" => last
                        .named_child(0)
                        .is_some_and(|call| called_name(call, source) == Some("abort")),
                    _ => false,
                });
            let bound_after = statements[i + 1..].iter().any(|later| {
                let mut after: BTreeMap<String, Vec<Binding>> = BTreeMap::new();
                collect_bindings(*later, source, &mut after);
                after.contains_key(name)
            });
            list_fixed && leaves && !bound_after
        })
    }

    /// Backlog 215: whether a Python name is a list of fixed text in the function it is used in:
    /// bound there once, not as a parameter, to a list of fixed items, and otherwise only ever
    /// grown with `append` or `extend` of fixed items or joined. Any other use (handed to a function,
    /// indexed, sorted in place) could change it, and makes it not fixed.
    fn fixed_list(&self, node: tree_sitter::Node, source: &[u8]) -> bool {
        if !self.python || node.kind() != "identifier" {
            return false;
        }
        let Some(function) = enclosing_function(node) else {
            return false;
        };
        let Ok(name) = node.utf8_text(source) else {
            return false;
        };
        let mut bindings: BTreeMap<String, Vec<Binding>> = BTreeMap::new();
        collect_bindings(function, source, &mut bindings);
        let Some([only]) = bindings.get(name).map(Vec::as_slice) else {
            return false;
        };
        let Some(value) = only.value else {
            return false;
        };
        if value.kind() != "list"
            || !is_literal(value, source, self)
            || binds_unseen(function, name, source)
        {
            return false;
        }
        let mut uses = Vec::new();
        identifiers_named(function, name, source, &mut uses);
        uses.into_iter().all(|use_| {
            // The use being judged: what reaches the call is the list as it stands there.
            if use_ == node {
                return true;
            }
            let parent = use_.parent();
            // Its one binding, `name = [...]`.
            if parent.is_some_and(|p| {
                p.kind() == "assignment" && p.child_by_field_name("left") == Some(use_)
            }) {
                return true;
            }
            // `SEP.join(name)`: the argument of a join, which reads it.
            if let Some(arguments) = parent.filter(|p| p.kind() == "argument_list")
                && let Some(call) = arguments.parent()
                && called_name(call, source) == Some("join")
            {
                return true;
            }
            // `name.append(fixed)`, `name.extend([fixed, ...])`.
            let Some(attribute) = parent.filter(|p| {
                p.kind() == "attribute" && p.child_by_field_name("object") == Some(use_)
            }) else {
                return false;
            };
            let Some(call) = attribute.parent().filter(|c| c.kind() == "call") else {
                return false;
            };
            if !matches!(called_name(call, source), Some("append" | "extend")) {
                return false;
            }
            call.child_by_field_name("arguments")
                .is_some_and(|arguments| {
                    let mut c = arguments.walk();
                    let args: Vec<_> = arguments
                        .named_children(&mut c)
                        .filter(|a| a.kind() != "comment")
                        .collect();
                    !args.is_empty() && args.into_iter().all(|a| is_literal(a, source, self))
                })
        })
    }
}

/// The Python function a node sits in, directly: a lambda or a class in between is a scope of its
/// own, and gives none.
pub(super) fn enclosing_function(node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut current = node.parent()?;
    loop {
        match current.kind() {
            "function_definition" => return Some(current),
            "lambda" | "class_definition" | "module" => return None,
            _ => current = current.parent()?,
        }
    }
}

/// Every identifier under `node` spelled `name`.
pub(super) fn identifiers_named<'a>(
    node: tree_sitter::Node<'a>,
    name: &str,
    source: &[u8],
    out: &mut Vec<tree_sitter::Node<'a>>,
) {
    if node.kind() == "identifier" && node.utf8_text(source) == Ok(name) {
        out.push(node);
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        identifiers_named(child, name, source, out);
    }
}

/// Whether something in the function may bind `name` in a way `collect_bindings` does not record:
/// `global` and `nonlocal`, which hand it to another scope, `with ... as name`, `except ... as name`,
/// and an import. Any of them makes the name not fixed.
pub(super) fn binds_unseen(function: tree_sitter::Node, name: &str, source: &[u8]) -> bool {
    let mut uses = Vec::new();
    identifiers_named(function, name, source, &mut uses);
    uses.iter().any(|use_| {
        let mut current = *use_;
        for _ in 0..4 {
            let Some(parent) = current.parent() else {
                return false;
            };
            if matches!(
                parent.kind(),
                "global_statement"
                    | "nonlocal_statement"
                    | "as_pattern_target"
                    | "as_pattern"
                    | "aliased_import"
                    | "import_statement"
                    | "import_from_statement"
                    | "except_clause"
            ) {
                // `with open(p) as name` and `except E as name` bind it; a name read in the
                // expression before `as` does not.
                return !matches!(parent.kind(), "as_pattern" | "except_clause")
                    || parent.child_by_field_name("alias").is_some_and(|alias| {
                        alias.start_byte() <= use_.start_byte()
                            && use_.end_byte() <= alias.end_byte()
                    })
                    || (parent.kind() == "except_clause"
                        && parent.named_children(&mut parent.walk()).any(|c| {
                            c.kind() == "as_pattern"
                                && c.child_by_field_name("alias").is_some_and(|alias| {
                                    alias.start_byte() <= use_.start_byte()
                                        && use_.end_byte() <= alias.end_byte()
                                })
                        }));
            }
            current = parent;
        }
        false
    })
}

/// A dictionary whose every key is fixed text: `{"title": "title", "created": "created_at"}`.
pub(super) fn keys_are_fixed(node: tree_sitter::Node, source: &[u8], fixed: &Fixed) -> bool {
    let mut cursor = node.walk();
    let entries: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .collect();
    !entries.is_empty()
        && entries.iter().all(|entry| {
            entry.kind() == "pair"
                && entry
                    .child_by_field_name("key")
                    .is_some_and(|k| is_literal(k, source, fixed))
        })
}

/// The name a call is made by: `f` in `f(x)`, `fetchone` in `cur.execute(q).fetchone()`. An
/// `await` in front is looked through.
pub(super) fn called_name<'a>(node: tree_sitter::Node, source: &'a [u8]) -> Option<&'a str> {
    let node = if node.kind() == "await" || node.kind() == "await_expression" {
        node.named_child(u32::try_from(node.named_child_count().checked_sub(1)?).ok()?)?
    } else {
        node
    };
    if !matches!(node.kind(), "call" | "call_expression") {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    let name = match function.kind() {
        "identifier" => function,
        "attribute" => function.child_by_field_name("attribute")?,
        "member_expression" => function.child_by_field_name("property")?,
        _ => return None,
    };
    name.utf8_text(source).ok()
}

/// A call that reads rows back from a database: DB-API's `fetchone`, SQLAlchemy's `first` and
/// `scalar`, Flask-SQLAlchemy's `get_or_404`, and the ORMs' `findOne`, `findUnique`, and the like.
/// `get` is not one: `request.args.get("f")` is the very thing the rule is for.
pub(super) fn is_database_read(node: tree_sitter::Node, source: &[u8]) -> bool {
    called_name(node, source).is_some_and(|name| {
        matches!(
            name,
            "fetchone"
                | "fetchall"
                | "fetchmany"
                | "fetchrow"
                | "fetchval"
                | "first"
                | "one"
                | "one_or_none"
                | "scalar"
                | "scalar_one"
                | "scalar_one_or_none"
                | "get_or_404"
                | "first_or_404"
                | "one_or_404"
                | "findOne"
                | "findOneBy"
                | "findUnique"
                | "findFirst"
                | "findById"
                | "findByPk"
        )
    })
}

/// The name of the function `node` calls, when that name says it checks what it is given:
/// `safe_next`, `is_safe_url`, `validate_redirect`, `allowed_destination`, `clean_path`.
pub(super) fn checker_called(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let name = called_name(node, source)?;
    let lower = name.to_ascii_lowercase();
    [
        "safe", "valid", "allowed", "check", "clean", "saniti", "verif", "trusted",
    ]
    .iter()
    .any(|word| lower.contains(word))
    .then(|| name.to_owned())
}

/// Whether `node` is built only from fixed text and values read back from the database, with at
/// least one of the second. A call's function is not a value (`os.path.join` builds; it is not
/// built from), nor is an attribute's or a keyword's name.
pub(super) fn built_from_database(node: tree_sitter::Node, source: &[u8], fixed: &Fixed) -> bool {
    fn walk(node: tree_sitter::Node, source: &[u8], fixed: &Fixed, seen: &mut bool) -> bool {
        if is_database_read(node, source) {
            *seen = true;
            return true;
        }
        if is_literal(node, source, fixed) {
            return true;
        }
        let text = node.utf8_text(source).unwrap_or("");
        match node.kind() {
            "identifier" => {
                let read_back = fixed.from_database.contains(text);
                *seen |= read_back;
                read_back
            }
            "call" | "call_expression" => node
                .child_by_field_name("arguments")
                .is_some_and(|a| walk(a, source, fixed, seen)),
            "attribute" => node
                .child_by_field_name("object")
                .is_some_and(|o| walk(o, source, fixed, seen)),
            "member_expression" => node
                .child_by_field_name("object")
                .is_some_and(|o| walk(o, source, fixed, seen)),
            "keyword_argument" => node
                .child_by_field_name("value")
                .is_some_and(|v| walk(v, source, fixed, seen)),
            // The text between the braces of an f-string or a template, and the parts of a string
            // around them.
            "string_content" | "string_start" | "string_end" | "string_fragment"
            | "escape_sequence" | "comment" => true,
            _ => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                !children.is_empty() && children.into_iter().all(|c| walk(c, source, fixed, seen))
            }
        }
    }
    let mut seen = false;
    walk(node, source, fixed, &mut seen) && seen
}

/// `QUERY`, `UPLOAD_DIR`: the way a module's constants are named.
pub(super) fn is_constant_name(name: &str) -> bool {
    name.len() > 1
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A dictionary or object whose every value is fixed. A spread (`**base`, `...base`) is not.
pub(super) fn table_is_fixed(node: tree_sitter::Node, source: &[u8], fixed: &Fixed) -> bool {
    let mut cursor = node.walk();
    let entries: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .collect();
    !entries.is_empty()
        && entries.iter().all(|entry| {
            entry.kind() == "pair"
                && entry
                    .child_by_field_name("value")
                    .is_some_and(|v| is_literal(v, source, fixed))
        })
}

/// Whether a binding sits at the top of the module: its statement's parent is the file itself.
pub(super) fn at_top(node: tree_sitter::Node) -> bool {
    let mut current = node;
    for _ in 0..4 {
        let Some(parent) = current.parent() else {
            return false;
        };
        match parent.kind() {
            "module" | "program" | "source_file" => return true,
            "expression_statement"
            | "lexical_declaration"
            | "variable_declaration"
            | "export_statement"
            | "const_declaration"
            | "var_declaration"
            | "assignment" => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

/// Every place in the file that binds a name, with the value when the code gives one.
pub(super) fn collect_bindings<'a>(
    node: tree_sitter::Node<'a>,
    source: &[u8],
    out: &mut BTreeMap<String, Vec<Binding<'a>>>,
) {
    let mut add = |name: tree_sitter::Node<'a>, value: Option<tree_sitter::Node<'a>>, top: bool| {
        if let Ok(text) = name.utf8_text(source) {
            out.entry(text.to_owned()).or_default().push(Binding {
                value,
                top,
                over: None,
            });
        }
    };
    // Every identifier under a node, each as a binding with no known value: tuple unpacking, loop
    // variables, parameters.
    fn names_under<'a>(node: tree_sitter::Node<'a>, found: &mut Vec<tree_sitter::Node<'a>>) {
        if node.kind() == "identifier" {
            found.push(node);
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            names_under(child, found);
        }
    }
    // Every name a destructuring pattern binds: `{ a, b: c }` binds `a` and `c`, `[d, ...e]` binds
    // `d` and `e`. A key renamed (`b`) is a property's name, not a binding, and is left out.
    fn pattern_names<'a>(node: tree_sitter::Node<'a>, found: &mut Vec<tree_sitter::Node<'a>>) {
        match node.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => found.push(node),
            "pair_pattern" => {
                if let Some(value) = node.child_by_field_name("value") {
                    pattern_names(value, found);
                }
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    pattern_names(child, found);
                }
            }
        }
    }
    let field = |name: &str| node.child_by_field_name(name);
    match node.kind() {
        // Python `x = v`, JavaScript `x = v`.
        "assignment" | "assignment_expression" => {
            if let Some(left) = field("left") {
                if left.kind() == "identifier" {
                    add(left, field("right"), at_top(node));
                } else {
                    let mut names = Vec::new();
                    if matches!(
                        left.kind(),
                        "pattern_list" | "tuple_pattern" | "list_pattern"
                    ) {
                        names_under(left, &mut names);
                    }
                    for name in names {
                        add(name, None, false);
                    }
                }
            }
        }
        // JavaScript `const x = v`, `let x`.
        "variable_declarator" => {
            if let Some(name) = field("name") {
                if name.kind() == "identifier" {
                    add(name, field("value"), at_top(node));
                } else {
                    let mut names = Vec::new();
                    names_under(name, &mut names);
                    for n in names {
                        add(n, None, false);
                    }
                }
            }
        }
        // `x += v`, Python's `(x := v)`: a second binding, or one whose value is not plain text.
        "augmented_assignment" | "augmented_assignment_expression" | "update_expression" => {
            if let Some(left) = field("left").or_else(|| field("argument"))
                && left.kind() == "identifier"
            {
                add(left, None, false);
            }
        }
        "named_expression" => {
            if let Some(name) = field("name") {
                add(name, None, false);
            }
        }
        // Loop variables, in statements and comprehensions, with what the loop goes over.
        "for_statement" | "for_in_statement" | "for_in_clause" => {
            if let Some(left) = field("left") {
                let mut names = Vec::new();
                names_under(left, &mut names);
                let over = field("right");
                for n in names {
                    if let Ok(text) = n.utf8_text(source) {
                        out.entry(text.to_owned()).or_default().push(Binding {
                            value: None,
                            top: false,
                            over,
                        });
                    }
                }
            }
        }
        // A JavaScript arrow function's one parameter written without brackets, `x => …`, which its
        // grammar keeps outside any parameter list (item 24 of the review of 1 to 4 October).
        "arrow_function" => {
            if let Some(param) = field("parameter")
                && param.kind() == "identifier"
            {
                add(param, None, false);
            }
        }
        // Parameters, in every function and lambda: their names only, never what their defaults name.
        "parameters" | "formal_parameters" | "lambda_parameters" | "parameter_list" => {
            let mut cursor = node.walk();
            for param in node.named_children(&mut cursor) {
                // A destructured parameter binds every name in its pattern (item 24 of the review
                // of 1 to 4 October): `({ query }) => …` and `([first, rest]) => …`.
                let pattern = match param.kind() {
                    "object_pattern" | "array_pattern" => Some(param),
                    "required_parameter" | "optional_parameter" => param
                        .child_by_field_name("pattern")
                        .filter(|p| p.kind() != "identifier"),
                    "assignment_pattern" => param
                        .child_by_field_name("left")
                        .filter(|p| p.kind() != "identifier"),
                    _ => None,
                };
                if let Some(pattern) = pattern {
                    let mut names = Vec::new();
                    pattern_names(pattern, &mut names);
                    for name in names {
                        add(name, None, false);
                    }
                    continue;
                }
                let name = match param.kind() {
                    "identifier" => Some(param),
                    "default_parameter" | "typed_default_parameter" => {
                        param.child_by_field_name("name")
                    }
                    "assignment_pattern" => param.child_by_field_name("left"),
                    "required_parameter" | "optional_parameter" => {
                        param.child_by_field_name("pattern")
                    }
                    "typed_parameter" => {
                        let mut c = param.walk();
                        param
                            .named_children(&mut c)
                            .find(|n| n.kind() == "identifier")
                    }
                    "parameter_declaration" | "variadic_parameter_declaration" => {
                        let mut c = param.walk();
                        let names: Vec<_> = param.children_by_field_name("name", &mut c).collect();
                        for n in names {
                            add(n, None, false);
                        }
                        None
                    }
                    _ => None,
                };
                if let Some(name) = name
                    && name.kind() == "identifier"
                {
                    add(name, None, false);
                }
            }
        }
        // Go: `const Q = "..."`, `var q = "..."`, `q := "..."`, `q = "..."`.
        "const_spec" | "var_spec" => {
            let mut c = node.walk();
            let names: Vec<_> = node.children_by_field_name("name", &mut c).collect();
            let values: Vec<_> = field("value")
                .map(|list| {
                    let mut c = list.walk();
                    list.named_children(&mut c).collect()
                })
                .unwrap_or_default();
            let top = at_top(node);
            for (i, name) in names.into_iter().enumerate() {
                let value = (values.len() == 1 && i == 0).then(|| values[0]);
                add(name, value, top);
            }
        }
        "short_var_declaration" | "assignment_statement" => {
            let list = |f: &str| -> Vec<tree_sitter::Node<'a>> {
                node.child_by_field_name(f)
                    .map(|l| {
                        let mut c = l.walk();
                        l.named_children(&mut c).collect()
                    })
                    .unwrap_or_default()
            };
            let (left, right) = (list("left"), list("right"));
            for (i, name) in left.iter().enumerate() {
                if name.kind() == "identifier" {
                    let value = (left.len() == right.len()).then(|| right[i]);
                    add(*name, value, false);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_bindings(child, source, out);
    }
}
