//! Rules that read the code itself, rather than the text of it.
//!
//! Everything else in `sv-check` works on strings. That is right for credentials, where the thing being
//! looked for *is* a string, and wrong for "is this SQL built by pasting a variable into it", where a
//! regex either misses the case split over two lines or fires on the word `execute` in a comment.
//!
//! So this parses. tree-sitter was taken as a dependency where a YAML crate was not, for the reason that
//! decides these: there is no honest hand-rolled alternative to a parser, it is actively maintained, and
//! four grammars build in about four seconds.
//!
//! # Queries are data, judgment is code
//!
//! `data/ast-rules.json` holds a tree-sitter query per language, so teaching a rule about Ruby is a data
//! entry. What a query cannot express is judgment — "the argument is a literal, so this `eval` is ugly
//! rather than dangerous" — and that lives here, in Rust, where it can be tested. It is the same split
//! as the secrets scanner: patterns as data, the decision about what they mean as code.
//!
//! # A language with no grammar is a language not read
//!
//! `sv-scan` counts more languages than this module can parse. A language with no grammar compiled in
//! is not scanned, and that is reported rather than left to look like a clean result, the same way the
//! secrets scanner reports the files it skipped. Ruby, then C#, then C++ were the standing example of
//! this in turn, each until it got a grammar; Objective-C is the one the tests below use now, so the
//! case stays exercised rather than becoming untestable the day the list is empty.

use crate::finding::{Confidence, Finding, Location, Severity};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AstRule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub requirement_ids: Vec<String>,
    pub cwe: Vec<String>,
    pub description: String,
    pub impact: String,
    pub fix: String,
    /// When true, a match whose `@arg` capture is a plain literal is not reported.
    ///
    /// `eval("1 + 1")` cannot be made to run anything the author did not write. Reporting it next to
    /// `eval(request.args["x"])` at the same seriousness is how a rule teaches people to skip its
    /// findings.
    #[serde(default)]
    pub literal_argument_is_safe: bool,
    /// The called name a match must have, per language, as a regular expression over `@fn`.
    ///
    /// Per language because the dangerous names differ: Python's are `eval`, `exec` and `compile`,
    /// JavaScript's are `eval` and `Function`. One pattern for all of them would either miss some or
    /// report the wrong ones.
    ///
    /// Not a `#match?` predicate in the query: the Rust binding parses those and then does not apply
    /// them, so a rule written that way matches every call in the file while looking correct. Load
    /// refuses any query containing one.
    #[serde(default)]
    pub function_patterns: BTreeMap<String, String>,
    /// The same, per language, for the `@mod` capture — the object or module the call is on.
    #[serde(default)]
    pub module_patterns: BTreeMap<String, String>,
    /// Per language, what the name of the function around `@hit` must match, written as lower-case
    /// words joined by `_` whatever the code's own style (`verifyToken`, `VerifyToken`, and
    /// `verify_token` are all `verify_token`).
    ///
    /// `except: return True` is a fault in `verify_token` and ordinary in `is_cached`, and how far
    /// the handler sits inside the function is not something a query can say, since a pattern
    /// matches only children it names. A function with no name of its own (a lambda, a callback)
    /// is passed over for the one around it, or the name it is assigned to (`const requireAuth =
    /// (req, res, next) => …`). A match with no named function around it is not reported.
    #[serde(default)]
    pub enclosing_function_patterns: BTreeMap<String, String>,
    /// Per language, what one of the names given to the value at `@hit` must match, written as
    /// words as `enclosingFunctionPatterns` writes them: the variable, field, or keyword argument
    /// it is assigned to on its way out of the function (`otp = str(random.randint(…))`,
    /// `user.reset_token = Math.random()`, `send(code=random.choice(…))`), or the function itself
    /// (`def generate_otp(): …`).
    ///
    /// `random.randint(100000, 999999)` is a fault in a sign-in code and ordinary in a dice game,
    /// and what the code is for is said only by the names around it. A match none of whose names
    /// matches is not reported.
    #[serde(default)]
    pub value_name_patterns: BTreeMap<String, String>,
    /// Per language, what the `@arg` capture's text must match for the call to be reported at all.
    ///
    /// For the rules whose danger is in *which* value is passed rather than whether it was built:
    /// `createHash("md5")` and `createHash("sha256")` are the same call with a literal argument, and
    /// only the first is a finding. A match with no `@arg` capture is not reported, so a query that
    /// forgets the capture reports nothing rather than everything.
    #[serde(default)]
    pub argument_patterns: BTreeMap<String, String>,
    /// Per language, what `@arg` must match in place of `argumentPatterns` when the call states
    /// its hash: a pattern over the `@hash` capture, and the argument pattern that goes with it.
    ///
    /// PBKDF2 needs 600,000 rounds with SHA-256 and 210,000 with SHA-512 (OWASP), so one figure
    /// for every hash either misses SHA-256 counts between the two or reports SHA-512 counts that
    /// are fine. A match whose `@hash` is missing, or matches none of the patterns (a hash passed
    /// in a variable, another hash, a hash set somewhere else), is judged by `argumentPatterns`
    /// as before. Where a query captures more than one node as `@hash` (a shell option and its
    /// value), their texts are joined by a space, in the order they appear.
    #[serde(default)]
    pub argument_patterns_by_hash: BTreeMap<String, BTreeMap<String, String>>,
    /// Per language, an `@arg` text that is known to be safe, so the call is not reported.
    ///
    /// Narrow on purpose, and each one written for a named idiom: `redirect(url_for("index"))` builds
    /// its destination from the app's own routes, and `res.sendFile(path.join(__dirname, "a.html"))`
    /// joins nothing but fixed text onto the app's own folder. Neither is a literal, and reporting
    /// either beside the real thing is how a rule teaches people to skip it.
    #[serde(default)]
    pub safe_argument_patterns: BTreeMap<String, String>,
    /// When true, an argument pieced together (`"<p>" + escape(name)`, `` `<p>${escape(name)}</p>` ``,
    /// `f"<p>{escape(name)}</p>"`) is safe when every piece is fixed text or matches
    /// `safeArgumentPatterns`, rather than only when the whole of it matches.
    ///
    /// HTML is written by joining fixed markup to escaped values, so a rule that looked only at
    /// the whole would report every page built the safe way beside the one that is not.
    #[serde(default)]
    pub safe_argument_pieces_read: bool,
    /// Per language, what the `@kw` capture's text must match for the call to be reported: the name
    /// of a keyword argument the danger depends on.
    ///
    /// `subprocess.run(cmd, shell=True)` hands `cmd` to a shell and `subprocess.run(cmd, check=True)`
    /// does not, and a query cannot tell `shell` from `check` without a text predicate, which the
    /// Rust binding does not apply. A match with no `@kw` capture is not reported.
    #[serde(default)]
    pub keyword_patterns: BTreeMap<String, String>,
    /// Per language, calls whose argument that matters is not the first: a pattern over `@fn`, and
    /// the position (from 0) of the argument to judge in its place.
    ///
    /// Go's `db.QueryContext(ctx, query)` takes the query second; judging the first argument judged
    /// `ctx`, a name, which is never fixed text, so every such call was reported (A1 of the deep review).
    #[serde(default)]
    pub argument_positions: BTreeMap<String, BTreeMap<String, usize>>,
    /// Per language, calls with a name too common to report on its name alone: a pattern over
    /// `@fn`, and what the argument judged must look like for the call to be reported.
    ///
    /// `db.get("SELECT … " + id)` is a query, and `cache.get(key)` is not; both are `get`. Reading
    /// only the name would report every `get` in the app, and leaving the name out missed every
    /// query sent through it (H1 of the deep review: node-sqlite3's `all`, `get`, and `run`).
    #[serde(default)]
    pub arguments_for_common_names: BTreeMap<String, BTreeMap<String, String>>,
    /// When the argument judged is a plain name, not text visibly built in the call, and the call
    /// passes values after it, the finding's confidence is lowered and it says why: values passed
    /// beside a query are how placeholders work, so the query may already be safe. Text built in the
    /// call itself (an f-string, a `+`, a template) keeps the rule's confidence.
    #[serde(default)]
    pub bound_parameters_lower_confidence: bool,
    /// When the argument is built only from fixed text and values read back from the app's database
    /// (`os.path.join(UPLOAD_DIR, row["id"])`, with `row` from `fetchone`), the finding says so: such
    /// a value is usually one the app made itself. Read in Python, JavaScript, and TypeScript, the
    /// languages whose bindings `Fixed` reads. The finding stays, at the rule's own confidence.
    #[serde(default)]
    pub says_when_read_from_database: bool,
    /// When the argument is a call to a function whose name says it checks what it is given
    /// (`redirect(safe_next(url))`), or a name only ever bound to one, the finding names the
    /// function: no rule can read every such function, and one named so usually does what it says.
    #[serde(default)]
    pub says_when_checked: bool,
    /// When true, `argumentPatterns` also matches through a name: a name in `@arg` that the function
    /// around the call sets, in an assignment or a declaration, to text the pattern matches.
    ///
    /// `email = userinfo["email"]` and then `User.query.filter_by(email=email)` is the same lookup as
    /// `filter_by(email=userinfo["email"])`, and the usual way it is written. Read in the function
    /// around the call (or the whole file outside any function), since a name set in another
    /// function is another variable; in shell, the whole script, where variables are global.
    #[serde(default)]
    pub argument_names_read: bool,
    /// When true, `functionPatterns` also matches through a name: the name a `@fn` begins with
    /// (`s` in `s.user` or `s["user"]`) read as what the function around it sets it to.
    ///
    /// `s = req.session` and then `s.user = claims.email` records the provider's address as who is
    /// signed in, as `req.session.user = claims.email` does. The name is read where
    /// `argumentNamesRead` reads one, and each value it is set to is put in its place, so the
    /// pattern is matched against `req.session.user`.
    #[serde(default)]
    pub function_names_read: bool,
    /// One tree-sitter query per language. A language absent here is one this rule says nothing about.
    pub queries: BTreeMap<String, String>,
    /// Patterns added to the `typescript` query for files that may hold JSX (`.tsx`, `.astro`).
    ///
    /// TypeScript's own grammar has no JSX, so a query naming `jsx_attribute` would not compile
    /// for a `.ts` file, and the rule would stop claiming anything there. JavaScript's grammar
    /// reads JSX in every file, so its patterns go in its own query.
    #[serde(default)]
    pub jsx_query: Option<String>,
    /// Languages `sv` reads that have nothing for this rule to find, each with the reason.
    ///
    /// Go has no `eval`, and a Go file cannot hide one. Without this entry a Go file would stop the
    /// rule claiming anything for a mixed app, because a language the rule reads nothing in is
    /// otherwise a language it has not ruled out. Each entry is a statement about the language, so
    /// it carries its reason, and a language cannot have both this and a query.
    #[serde(default)]
    pub nothing_to_find: BTreeMap<String, String>,
    /// What the rule looks for, in plain words, shown beside a clean result so it says what was
    /// looked for and not only how many files were read.
    ///
    /// "1 shell file" beside a path-traversal rule reads as "your shell scripts were checked for path
    /// traversal", when in shell the rule only looks at commands given a web request variable. A
    /// clean result is a claim about what the rule can see, and it should say so.
    #[serde(default)]
    pub looks_for: String,
    /// Per language, where the rule looks for something narrower than `looks_for` says.
    #[serde(default)]
    pub looks_for_in: BTreeMap<String, String>,
    /// A rule that can show the fault present and never its absence, so a run that finds nothing
    /// credits nothing. Not finding a `ws://` address written into the code is not every WebSocket
    /// being encrypted: the address is usually built at run time, where no rule can see it.
    #[serde(default)]
    pub findings_only: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(rename = "_comment", default)]
    _comment: String,
    rules: Vec<AstRule>,
}

/// A query compiled the first time a file in its language is read, and kept for the process.
///
/// Compiling every query eagerly cost 0.87 s of the 0.96 s every `sv check` spent before reading a
/// file (27 September 2026, review item 6): 143 queries across fifteen languages, Swift alone a
/// quarter of a second, paid in full by a Python app that would parse none of them. The source is
/// still checked when the rules load — the text predicates, the pattern-without-query cases — and
/// `AstRules::compile_all` compiles everything for the test that guards the data file, so a query
/// tree-sitter cannot compile is still caught in CI rather than on the first app in that language.
struct LazyQuery {
    grammar: Language,
    source: String,
    compiled: OnceLock<Result<Query, String>>,
}

impl LazyQuery {
    fn new(grammar: Language, source: &str) -> Self {
        LazyQuery {
            grammar,
            source: source.to_owned(),
            compiled: OnceLock::new(),
        }
    }

    /// The compiled query, or why tree-sitter refused it.
    fn get(&self) -> Result<&Query, &str> {
        self.compiled
            .get_or_init(|| Query::new(&self.grammar, &self.source).map_err(|e| e.to_string()))
            .as_ref()
            .map_err(String::as_str)
    }
}

/// A rule with its queries, one per language, each compiled on first use.
struct Compiled {
    rule: AstRule,
    queries: BTreeMap<String, LazyQuery>,
    /// The `typescript` query against the TSX grammar, for `.tsx` files.
    tsx: Option<LazyQuery>,
    function: BTreeMap<String, regex::Regex>,
    module: BTreeMap<String, regex::Regex>,
    enclosing: BTreeMap<String, regex::Regex>,
    value_name: BTreeMap<String, regex::Regex>,
    argument: BTreeMap<String, regex::Regex>,
    safe_argument: BTreeMap<String, regex::Regex>,
    keyword: BTreeMap<String, regex::Regex>,
    positions: BTreeMap<String, Vec<(regex::Regex, usize)>>,
    common_names: BTreeMap<String, Vec<(regex::Regex, regex::Regex)>>,
    by_hash: BTreeMap<String, Vec<(regex::Regex, regex::Regex)>>,
}

pub struct AstRules {
    compiled: Vec<Compiled>,
}

impl AstRules {
    /// Every rule as it was loaded. Used by the citation guard, which reads each rule's own words
    /// back against the requirement it names.
    pub fn rules(&self) -> impl Iterator<Item = &AstRule> {
        self.compiled.iter().map(|c| &c.rule)
    }

    /// Every rule, with the languages it can read and the requirements it is about.
    ///
    /// Needed to say what a clean scan covered: a rule is evidence only for the languages it has a
    /// query for, so a rule with a Python query says nothing about a Go file it never looked at.
    pub fn coverage(&self) -> Vec<(&str, Vec<&str>, Vec<&str>)> {
        self.compiled
            .iter()
            .map(|c| {
                (
                    c.rule.id.as_str(),
                    c.queries.keys().map(String::as_str).collect(),
                    c.rule.requirement_ids.iter().map(String::as_str).collect(),
                )
            })
            .collect()
    }
}

/// The languages a grammar is compiled in for.
fn grammar(language: &str) -> Option<Language> {
    Some(match language {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        // Not a language of its own to anything but the parser: `.tsx` is TypeScript with JSX in it,
        // and the plain TypeScript grammar gives up inside the first tag. Rules are written once, as
        // `typescript`, and compiled a second time against this grammar.
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "csharp" => tree_sitter_c_sharp::LANGUAGE.into(),
        "kotlin" => tree_sitter_kotlin_ng::LANGUAGE.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "swift" => tree_sitter_swift::LANGUAGE.into(),
        "dart" => tree_sitter_dart::LANGUAGE.into(),
        "shell" => tree_sitter_bash::LANGUAGE.into(),
        _ => return None,
    })
}

/// A piece of script taken out of a page, and where it sat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// The language to parse it as: `javascript`, or `typescript` when the page says so.
    pub language: &'static str,
    pub code: String,
    /// How many lines came before it, so a finding can name the line in the page rather than in
    /// the fragment. A reader given line 3 of something they cannot see is worse off than one
    /// given nothing.
    pub line_offset: usize,
}

/// What a page holds, and what could not be taken out of it.
#[derive(Debug, Default)]
pub struct HtmlScan {
    pub fragments: Vec<Fragment>,
    /// Something code-shaped that the extractor did not take. While this is true the page is still
    /// unread, and every rule stays silent about the whole app.
    ///
    /// One function decides both halves on purpose. When "does this page hold code" and "what code
    /// does this page hold" are answered by two pieces of code, they drift, and the direction they
    /// drift in is a page declared read whose code nobody extracted.
    pub left_behind: Option<String>,
}

/// Takes the script out of a page.
///
/// Handles the three places code really lives in markup: a `<script>` element, an `on…=` handler
/// attribute, and a `javascript:` URL in any attribute. A `<script src=…>` with nothing between its
/// tags holds no code — the file it names is parsed like any other. Anything else code-shaped is
/// left behind by name rather than ignored.
///
/// Tags are read the way a browser's tokenizer reads them (WHATWG HTML, "tokenization"), because a
/// page is written for a browser and anything this reads differently is a place to hide in. An
/// unquoted value ends at whitespace or `>`; `/` separates attributes as a space does; a comment and
/// the body of a `<textarea>` hold no tags.
pub fn html_fragments(source: &str) -> HtmlScan {
    page_fragments(source, false)
}

/// `html_fragments`, with every `<script>` read as TypeScript when `typescript_scripts` is set: an
/// Astro page's scripts are, whatever their tag says, since Astro compiles them as TypeScript.
fn page_fragments(source: &str, typescript_scripts: bool) -> HtmlScan {
    let mut out = HtmlScan::default();
    let markup = match read_markup(source) {
        Ok(markup) => markup,
        Err(reason) => {
            out.left_behind = Some(reason);
            return out;
        }
    };
    let line_of = |at: usize| source[..at].matches('\n').count();

    // Script elements.
    let mut accounted = 0usize;
    for script in &markup.scripts {
        let body = &source[script.body.clone()];
        accounted += count_schemes(body);
        if !body.trim().is_empty() {
            out.fragments.push(Fragment {
                language: if typescript_scripts {
                    "typescript"
                } else {
                    script.language
                },
                code: body.to_owned(),
                line_offset: line_of(script.body.start),
            });
        }
    }

    // Attributes: a handler is a statement, which parses as JavaScript on its own, and a URL may be
    // a program.
    for attribute in &markup.attributes {
        let raw = &source[attribute.value.clone()];
        accounted += count_schemes(raw);
        let (value, unread_reference) = decode_character_references(raw);
        let handler = is_handler(&attribute.name);
        let program = javascript_url_program(&value);
        if unread_reference && (handler || program.is_some()) {
            // A named reference this does not know may be one a browser turns into a character of
            // the program, and a guessed program is worse than a page named as unread.
            out.left_behind =
                Some("a character reference inside code that this does not decode".to_owned());
            return out;
        }
        if handler {
            if !value.trim().is_empty() {
                out.fragments.push(Fragment {
                    language: "javascript",
                    code: value,
                    line_offset: line_of(attribute.value.start),
                });
            }
        } else if let Some(program) = program {
            out.fragments.push(Fragment {
                language: "javascript",
                code: percent_decode(&program),
                line_offset: line_of(attribute.value.start),
            });
        } else if looks_like_a_disguised_scheme(&value) {
            out.left_behind = Some(
                "a value that is nearly a `javascript:` URL, spelled with a character a browser \
                 does not remove"
                    .to_owned(),
            );
            return out;
        }
    }

    // Every occurrence has to be accounted for. One outside every attribute value and script body
    // read above sits somewhere this does not model — text, a comment, a template language's own
    // syntax — and the page keeps its silence rather than pretend.
    if count_schemes(source) > accounted {
        out.left_behind = Some(
            "a `javascript:` outside any attribute or script this read, so what it belongs to is \
             a guess"
                .to_owned(),
        );
        return out;
    }

    // Finally: anything taken out has to be code the grammar can actually read. A fragment that
    // does not parse yields no findings, which is indistinguishable from a fragment that was clean
    // — so a page holding a `<script>` full of a template language, or a URL this decoded wrongly,
    // is left unread rather than counted as examined.
    //
    // This catches less than it looks like it does, and the reason is worth knowing: the JavaScript
    // grammar includes JSX, so a Vue or React template parses cleanly and reaches the rules as
    // markup rather than being refused. Handlebars, ERB and Jinja do not.
    if let Some(bad) = out
        .fragments
        .iter()
        .find(|f| !parses_cleanly(f.language, &f.code))
    {
        out.left_behind = Some(format!(
            "something taken out of this page is not {} the grammar can read",
            bad.language
        ));
    }
    out
}

/// An attribute of a start tag: its name in lower case, and where its value sits in the page.
struct Attribute {
    name: String,
    value: std::ops::Range<usize>,
}

/// A `<script>` element's body, and the language its tag says it holds.
struct Script {
    language: &'static str,
    body: std::ops::Range<usize>,
}

#[derive(Default)]
struct Markup {
    attributes: Vec<Attribute>,
    scripts: Vec<Script>,
}

/// Elements whose body is text to a browser, not tags. A `<textarea>` holding `<a onclick=…>` shows
/// those characters; it does not make a link.
const RAW_TEXT: [&str; 5] = ["script", "style", "textarea", "title", "xmp"];

/// ASCII whitespace as the HTML tokenizer means it.
fn is_html_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// Every start tag's attributes, and every script body, read the way a browser's tokenizer does.
///
/// Every delimiter here is ASCII, so byte positions are always character boundaries, and the page
/// is lowered with `to_ascii_lowercase` for the same reason: full Unicode lowering can change a
/// string's length and move every position after it.
fn read_markup(source: &str) -> Result<Markup, String> {
    let bytes = source.as_bytes();
    let lower = source.to_ascii_lowercase();
    let len = bytes.len();
    let mut markup = Markup::default();
    let mut at = 0usize;
    while let Some(found) = source[at..].find('<') {
        let open = at + found;
        if lower[open..].starts_with("<!--") {
            // A comment ends at the first `-->`; one never closed runs to the end of the page.
            match lower[open + 4..].find("-->") {
                Some(i) => at = open + 4 + i + 3,
                None => break,
            }
            continue;
        }
        let next = bytes.get(open + 1).copied();
        if matches!(next, Some(b'!' | b'?' | b'/')) {
            // A declaration, a processing instruction, or an end tag: nothing a browser runs.
            match source[open..].find('>') {
                Some(i) => at = open + i + 1,
                None => break,
            }
            continue;
        }
        if !next.is_some_and(|b| b.is_ascii_alphabetic()) {
            // A `<` that starts no tag is text.
            at = open + 1;
            continue;
        }

        let mut i = open + 1;
        while i < len && !is_html_space(bytes[i]) && bytes[i] != b'/' && bytes[i] != b'>' {
            i += 1;
        }
        let name = lower[open + 1..i].to_owned();
        let first_attribute = markup.attributes.len();
        loop {
            while i < len && (is_html_space(bytes[i]) || bytes[i] == b'/') {
                i += 1;
            }
            if i >= len {
                return Err(format!("a `<{name}` tag that is never closed"));
            }
            if bytes[i] == b'>' {
                i += 1;
                break;
            }
            // A name may begin with `=`; after its first character, `=` ends it.
            let name_start = i;
            i += 1;
            while i < len && !is_html_space(bytes[i]) && !matches!(bytes[i], b'/' | b'>' | b'=') {
                i += 1;
            }
            let attribute_name = lower[name_start..i].to_owned();
            let mut j = i;
            while j < len && is_html_space(bytes[j]) {
                j += 1;
            }
            if j >= len || bytes[j] != b'=' {
                // No value; what follows is the next attribute.
                i = j;
                continue;
            }
            j += 1;
            while j < len && is_html_space(bytes[j]) {
                j += 1;
            }
            let value = match bytes.get(j) {
                Some(&quote @ (b'"' | b'\'')) => {
                    let Some(close) = source[j + 1..].find(quote as char) else {
                        return Err(format!("a `<{name}` tag with a quote that is never closed"));
                    };
                    i = j + 1 + close + 1;
                    j + 1..j + 1 + close
                }
                _ => {
                    // Unquoted: the value ends at whitespace or at the end of the tag, and every
                    // other character — quotes, `=`, `/` — is part of it.
                    let start = j;
                    while j < len && !is_html_space(bytes[j]) && bytes[j] != b'>' {
                        j += 1;
                    }
                    i = j;
                    start..j
                }
            };
            markup.attributes.push(Attribute {
                name: attribute_name,
                value,
            });
        }
        at = i;

        if !RAW_TEXT.contains(&name.as_str()) {
            continue;
        }
        // The body runs to the first end tag of the same name, and only a real one: `</scripts`
        // does not end a script.
        let closing = format!("</{name}");
        let mut search = at;
        let close = loop {
            match lower[search..].find(&closing) {
                Some(i) => {
                    let after = search + i + closing.len();
                    if bytes
                        .get(after)
                        .is_none_or(|&b| is_html_space(b) || b == b'/' || b == b'>')
                    {
                        break Some(search + i);
                    }
                    search = after;
                }
                None => break None,
            }
        };
        let Some(close) = close else {
            if name == "script" {
                return Err("a `<script>` with no `</script>` after it".to_owned());
            }
            // The rest of the page is that element's text.
            break;
        };
        if name == "script" {
            // `lang="ts"` is how a Vue component says so; `type="text/typescript"` is the older way.
            let typescript = markup.attributes[first_attribute..].iter().any(|a| {
                let value = lower[a.value.clone()].trim();
                (a.name == "lang" && value == "ts") || value.contains("typescript")
            });
            markup.scripts.push(Script {
                language: if typescript {
                    "typescript"
                } else {
                    "javascript"
                },
                body: at..close,
            });
        }
        at = close;
    }
    Ok(markup)
}

/// Whether an attribute is an event handler, whose value a browser runs as a statement.
fn is_handler(name: &str) -> bool {
    name.strip_prefix("on")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphabetic()))
}

/// How many times the scheme is written, plainly, in some text.
fn count_schemes(text: &str) -> usize {
    text.to_ascii_lowercase().matches("javascript:").count()
}

/// The program in a `javascript:` URL, if that is what this attribute value is.
///
/// A browser's URL parser (WHATWG URL) first strips leading and trailing control characters and
/// spaces, then removes every tab and newline anywhere in the value, and only then reads the
/// scheme. So `java&#9;script:` runs, and so does `javascript:go(\n)` as `go()`. This does the same
/// two steps, in that order, and nothing more.
fn javascript_url_program(value: &str) -> Option<String> {
    let trimmed = value.trim_matches(|c: char| c <= ' ');
    let cleaned: String = trimmed
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let head = cleaned.get(.."javascript:".len())?;
    head.eq_ignore_ascii_case("javascript:")
        .then(|| cleaned["javascript:".len()..].to_owned())
}

/// Whether a value that is not a `javascript:` URL is nearly one.
///
/// A browser removes tabs and newlines from inside a scheme and nothing else, so `java\u{1}script:`
/// does not run. That is this reading of the URL specification, though, and the cost of being wrong
/// about it is a false clean: a value that becomes the scheme once every control character is taken
/// out keeps the page unread rather than be passed on the strength of a reading.
fn looks_like_a_disguised_scheme(value: &str) -> bool {
    let collapsed: String = value
        .chars()
        .take(64)
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    collapsed.len() >= "javascript:".len()
        && collapsed.is_char_boundary("javascript:".len())
        && collapsed[.."javascript:".len()].eq_ignore_ascii_case("javascript:")
}

/// Turns `%20` back into a space, and leaves anything that is not a complete escape alone.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // A decode that does not produce text is a decode this had no business doing.
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// Whether the grammar can read this fragment without falling over.
///
/// `has_error` is the whole point. Tree-sitter always returns a tree, so a fragment of something
/// that is not this language parses into a wreck that matches no rule and reports nothing — which
/// reads exactly like a fragment that was clean.
fn parses_cleanly(language: &str, code: &str) -> bool {
    let Some(grammar) = grammar(language) else {
        return false;
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return false;
    }
    match parser.parse(code, None) {
        Some(tree) => !tree.root_node().has_error(),
        None => false,
    }
}

/// Puts back the character references a browser decodes in an attribute value.
///
/// Numeric references (`&#9;`, `&#x6A;`, with or without the `;`) are decoded exactly. Named ones
/// are decoded for every name that stands for an ASCII character, which covers every name that can
/// spell a scheme or a statement. The second half of the answer says whether a named reference was
/// left as written: most such names are ones a browser leaves alone too, but a few hundred stand for
/// a letter JavaScript accepts in a name, so where it matters the caller treats it as unread.
///
/// Not modeled: the legacy references a browser still decodes without a `;` (`&amp`, `&lt`) — left
/// as written, where they make a statement the grammar refuses rather than a different statement.
fn decode_character_references(text: &str) -> (String, bool) {
    let mut out = String::with_capacity(text.len());
    let mut unread = false;
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let after = &rest[1..];
        if let Some(number) = after.strip_prefix('#') {
            let (digits, radix) = match number.strip_prefix(['x', 'X']) {
                Some(hex) => (hex, 16),
                None => (number, 10),
            };
            let count = digits
                .bytes()
                .take_while(|b| {
                    if radix == 16 {
                        b.is_ascii_hexdigit()
                    } else {
                        b.is_ascii_digit()
                    }
                })
                .count();
            if count > 0 {
                // Zero, a surrogate, or past the end of Unicode is U+FFFD to a browser.
                let decoded = u32::from_str_radix(&digits[..count], radix)
                    .ok()
                    .filter(|&n| n != 0)
                    .and_then(char::from_u32)
                    .unwrap_or('\u{FFFD}');
                out.push(decoded);
                rest = &digits[count..];
                rest = rest.strip_prefix(';').unwrap_or(rest);
                continue;
            }
        } else {
            let length = after
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric())
                .count();
            if length > 0 && after[length..].starts_with(';') {
                if let Some(decoded) = named_reference(&after[..length]) {
                    out.push(decoded);
                    rest = &after[length + 1..];
                    continue;
                }
                unread = true;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    (out, unread)
}

/// The named references that stand for an ASCII character, plus the no-break space.
fn named_reference(name: &str) -> Option<char> {
    Some(match name {
        "lt" | "LT" => '<',
        "gt" | "GT" => '>',
        "quot" | "QUOT" => '"',
        "apos" => '\'',
        "amp" | "AMP" => '&',
        "Tab" => '\t',
        "NewLine" => '\n',
        "colon" => ':',
        "lpar" => '(',
        "rpar" => ')',
        "sol" => '/',
        "bsol" => '\\',
        "semi" => ';',
        "comma" => ',',
        "period" => '.',
        "excl" => '!',
        "quest" => '?',
        "num" => '#',
        "percnt" => '%',
        "equals" => '=',
        "plus" => '+',
        "lsqb" | "lbrack" => '[',
        "rsqb" | "rbrack" => ']',
        "lcub" | "lbrace" => '{',
        "rcub" | "rbrace" => '}',
        "grave" | "DiacriticalGrave" => '`',
        "ast" | "midast" => '*',
        "dollar" => '$',
        "commat" => '@',
        "Hat" => '^',
        "lowbar" | "UnderBar" => '_',
        "verbar" | "vert" | "VerticalLine" => '|',
        "nbsp" | "NonBreakingSpace" => '\u{A0}',
        _ => return None,
    })
}

/// Whether `sv` can read this language at all.
pub fn is_supported(language: &str) -> bool {
    grammar(language).is_some()
}

impl AstRules {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: RuleFile =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        let mut compiled = Vec::new();
        for rule in file.rules {
            let mut queries = BTreeMap::new();
            for (language, source) in &rule.queries {
                // A `#match?` here is silently ignored by the binding, so the rule would match every
                // call in every file and look right doing it. Refuse it rather than let it through.
                anyhow::ensure!(
                    !source.contains("#match?") && !source.contains("#eq?"),
                    "rule {} has a {language} query using a text predicate, which this binding parses \
                     and does not apply — use functionPattern or modulePattern instead",
                    rule.id
                );
                let grammar = grammar(language).with_context(|| {
                    format!(
                        "rule {} names language `{language}`, which has no grammar",
                        rule.id
                    )
                })?;
                queries.insert(language.clone(), LazyQuery::new(grammar, source));
            }
            let compile_patterns = |patterns: &BTreeMap<String, String>, what: &str| {
                patterns
                    .iter()
                    .map(|(language, source)| {
                        regex::Regex::new(source)
                            .map(|re| (language.clone(), re))
                            .with_context(|| {
                                format!("rule {} has an unusable {what} for {language}", rule.id)
                            })
                    })
                    .collect::<Result<BTreeMap<_, _>>>()
            };
            let function = compile_patterns(&rule.function_patterns, "functionPattern")?;
            let module = compile_patterns(&rule.module_patterns, "modulePattern")?;
            let enclosing = compile_patterns(
                &rule.enclosing_function_patterns,
                "enclosingFunctionPattern",
            )?;
            let value_name = compile_patterns(&rule.value_name_patterns, "valueNamePattern")?;
            let argument = compile_patterns(&rule.argument_patterns, "argumentPattern")?;
            let safe_argument =
                compile_patterns(&rule.safe_argument_patterns, "safeArgumentPattern")?;
            let keyword = compile_patterns(&rule.keyword_patterns, "keywordPattern")?;
            let mut positions = BTreeMap::new();
            for (language, by_name) in &rule.argument_positions {
                anyhow::ensure!(
                    queries.contains_key(language),
                    "rule {} has an argumentPosition for {language} but no {language} query",
                    rule.id
                );
                let mut compiled_positions = Vec::new();
                for (pattern, position) in by_name {
                    let re = regex::Regex::new(pattern).with_context(|| {
                        format!(
                            "rule {} has an unusable argumentPosition for {language}",
                            rule.id
                        )
                    })?;
                    compiled_positions.push((re, *position));
                }
                positions.insert(language.clone(), compiled_positions);
            }
            let mut common_names = BTreeMap::new();
            for (language, by_name) in &rule.arguments_for_common_names {
                anyhow::ensure!(
                    queries.contains_key(language),
                    "rule {} has argumentsForCommonNames for {language} but no {language} query",
                    rule.id
                );
                let mut pairs = Vec::new();
                for (name, argument) in by_name {
                    let compile = |source: &str| {
                        regex::Regex::new(source).with_context(|| {
                            format!(
                                "rule {} has an unusable argumentsForCommonNames entry for {language}",
                                rule.id
                            )
                        })
                    };
                    pairs.push((compile(name)?, compile(argument)?));
                }
                common_names.insert(language.clone(), pairs);
            }
            let mut by_hash = BTreeMap::new();
            for (language, by_name) in &rule.argument_patterns_by_hash {
                anyhow::ensure!(
                    queries.contains_key(language),
                    "rule {} has argumentPatternsByHash for {language} but no {language} query",
                    rule.id
                );
                let mut pairs = Vec::new();
                for (hash, argument) in by_name {
                    let compile = |source: &str| {
                        regex::Regex::new(source).with_context(|| {
                            format!(
                                "rule {} has an unusable argumentPatternsByHash entry for {language}",
                                rule.id
                            )
                        })
                    };
                    pairs.push((compile(hash)?, compile(argument)?));
                }
                by_hash.insert(language.clone(), pairs);
            }
            // A pattern for a language the rule has no query in is a pattern that never runs, and
            // the rule reads as if it had been taught that language.
            for (what, patterns) in [
                ("functionPattern", &rule.function_patterns),
                ("modulePattern", &rule.module_patterns),
                (
                    "enclosingFunctionPattern",
                    &rule.enclosing_function_patterns,
                ),
                ("valueNamePattern", &rule.value_name_patterns),
                ("argumentPattern", &rule.argument_patterns),
                ("safeArgumentPattern", &rule.safe_argument_patterns),
                ("keywordPattern", &rule.keyword_patterns),
            ] {
                if let Some(language) = patterns.keys().find(|l| !queries.contains_key(*l)) {
                    anyhow::bail!(
                        "rule {} has a {what} for {language} but no {language} query",
                        rule.id
                    );
                }
            }
            for language in rule.looks_for_in.keys() {
                anyhow::ensure!(
                    rule.queries.contains_key(language),
                    "rule {} says what it looks for in `{language}`, and has no {language} query",
                    rule.id
                );
            }
            for (language, why) in &rule.nothing_to_find {
                anyhow::ensure!(
                    grammar(language).is_some(),
                    "rule {} says there is nothing to find in `{language}`, which has no grammar",
                    rule.id
                );
                anyhow::ensure!(
                    !rule.queries.contains_key(language),
                    "rule {} has a {language} query and also says there is nothing to find in \
                     {language}",
                    rule.id
                );
                anyhow::ensure!(
                    !why.trim().is_empty(),
                    "rule {} says there is nothing to find in {language} without saying why",
                    rule.id
                );
            }
            anyhow::ensure!(
                rule.jsx_query.is_none() || rule.queries.contains_key("typescript"),
                "rule {} has a jsxQuery and no typescript query to add it to",
                rule.id
            );
            let tsx = rule.queries.get("typescript").map(|source| {
                let source = match &rule.jsx_query {
                    Some(jsx) => format!("{source}\n{jsx}"),
                    None => source.clone(),
                };
                LazyQuery::new(grammar("tsx").expect("tsx is compiled in"), &source)
            });
            compiled.push(Compiled {
                rule,
                queries,
                tsx,
                function,
                module,
                enclosing,
                value_name,
                argument,
                safe_argument,
                keyword,
                positions,
                common_names,
                by_hash,
            });
        }
        Ok(AstRules { compiled })
    }

    pub fn len(&self) -> usize {
        self.compiled.len()
    }

    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }

    /// Compiles every query in every language now, and names the first one tree-sitter refuses.
    ///
    /// For the test that guards the data file. A command compiles only the languages it meets, so
    /// without this a query written wrong would first fail on someone's app in that language.
    pub fn compile_all(&self) -> Result<()> {
        for c in &self.compiled {
            for (language, query) in &c.queries {
                query.get().map_err(|why| {
                    anyhow::anyhow!(
                        "rule {} has a {language} query tree-sitter cannot compile: {why}",
                        c.rule.id
                    )
                })?;
            }
            if let Some(tsx) = &c.tsx {
                tsx.get().map_err(|why| {
                    anyhow::anyhow!(
                        "rule {} has a typescript query the TSX grammar cannot compile: {why}",
                        c.rule.id
                    )
                })?;
            }
        }
        Ok(())
    }

    /// The languages any rule has a query for.
    pub fn languages(&self) -> BTreeSet<&str> {
        self.compiled
            .iter()
            .flat_map(|c| c.queries.keys())
            .map(String::as_str)
            .collect()
    }
}

/// Node kinds that are a value written in the source, with nothing substituted into them.
///
/// A template string is only a literal when nothing is interpolated, which is exactly the distinction
/// that matters: `` `SELECT 1` `` is a constant and `` `SELECT ${id}` `` is the bug this looks for.
///
/// `fixed` holds the names in the same file whose value is fixed text (`Fixed::of`), so `QUERY`,
/// `SCHEMA`, and `SORT_ORDERS[key]` are judged as the text they stand for.
fn is_literal(node: tree_sitter::Node, source: &[u8], fixed: &Fixed) -> bool {
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
const COMPILE_TIME_MACROS: &[&str] = &[
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
fn compile_time_text(node: tree_sitter::Node, source: &[u8]) -> bool {
    node.child_by_field_name("macro")
        .and_then(|m| m.utf8_text(source).ok())
        .is_some_and(|name| COMPILE_TIME_MACROS.contains(&name.rsplit("::").next().unwrap_or(name)))
}

/// Whether an argument is safe by a rule's `safeArgumentPattern` whichever way it goes. A pattern
/// reads how the argument starts, so `redirect("/home" if not nxt else nxt)` starts like a path on
/// the same site and was taken for one (item 19 of the review of 1 to 4 October). A choice between
/// values (`a if c else b`, `c ? a : b`, `a or b`, `a and b`, `a || b`, `a && b`, `a ?? b`) is safe
/// only when every value it can give is: by the pattern, or written out.
fn safe_in_every_branch(
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
fn safe_in_every_piece(
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
fn choice_branches<'t>(
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
fn has_interpolation(node: tree_sitter::Node, source: &[u8]) -> bool {
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
    names: BTreeSet<String>,
    tables: BTreeSet<String>,
    /// Names every binding of which is a value read back from the app's database (`row =
    /// cur.fetchone()`, `for row in rows`), or text built only from those and fixed text: a path
    /// made of them is the app's own id, usually, not what a person typed (A1's leftovers).
    from_database: BTreeSet<String>,
    /// Names every binding of which is a call to a function whose name says it checks what it is
    /// given (`next_url = safe_next(raw)`), with those functions' names, ready to be shown.
    checked: BTreeMap<String, String>,
    /// Backlog 215: the file is Python, whose names are also judged in their own function (`local`).
    python: bool,
    /// Tables whose every key is fixed text too, so a name checked against them is one of those keys.
    keyed: BTreeSet<String>,
    /// How deep `local` is in judging one name by another, so a name defined by itself
    /// (`sort = sort + ""`) ends instead of going round for ever.
    depth: std::cell::Cell<u8>,
}

/// One binding of a name: the value it was given, when the code says, and whether it sits at the top
/// of the module.
struct Binding<'a> {
    value: Option<tree_sitter::Node<'a>>,
    top: bool,
    /// For a loop variable, what the loop goes over.
    over: Option<tree_sitter::Node<'a>>,
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
fn enclosing_function(node: tree_sitter::Node) -> Option<tree_sitter::Node> {
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
fn identifiers_named<'a>(
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
fn binds_unseen(function: tree_sitter::Node, name: &str, source: &[u8]) -> bool {
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
fn keys_are_fixed(node: tree_sitter::Node, source: &[u8], fixed: &Fixed) -> bool {
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
fn called_name<'a>(node: tree_sitter::Node, source: &'a [u8]) -> Option<&'a str> {
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
fn is_database_read(node: tree_sitter::Node, source: &[u8]) -> bool {
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
fn checker_called(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
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
fn built_from_database(node: tree_sitter::Node, source: &[u8], fixed: &Fixed) -> bool {
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
fn is_constant_name(name: &str) -> bool {
    name.len() > 1
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A dictionary or object whose every value is fixed. A spread (`**base`, `...base`) is not.
fn table_is_fixed(node: tree_sitter::Node, source: &[u8], fixed: &Fixed) -> bool {
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
fn at_top(node: tree_sitter::Node) -> bool {
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
fn collect_bindings<'a>(
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

#[derive(Debug, Default)]
pub struct AstScan {
    pub findings: Vec<Finding>,
    /// Languages present in the app that no grammar reads, so nothing is claimed about them.
    pub unread_languages: BTreeSet<String>,
    pub files_parsed: usize,
    /// How many files were parsed in each language.
    pub parsed_by_language: BTreeMap<String, usize>,
    /// Rules that ran over everything they could read and found nothing.
    pub verified: Vec<crate::Verified>,
    /// Files in a language `sv` reads whose parse came back with an error in it.
    ///
    /// Whatever sat inside the error was not read, and the parser says nothing about how much that
    /// was. A `.tsx` file once went through a grammar with no JSX, lost everything inside its first
    /// tag, and still counted as read — so an `eval` in a click handler was missed and the report
    /// listed the requirement against `eval` as checked. Findings from such a file still stand; what
    /// it cannot do is support a claim that something is absent.
    pub unparsed_files: Vec<String>,
    /// Files in a language `sv` reads that were not read at all, with the reason: over the size
    /// limit, not text, or unreadable. Like `unparsed_files`, these keep a rule from claiming
    /// anything is absent; unlike a skipped folder, which is a choice, an unread file is a hole.
    pub unread_files: Vec<(String, String)>,
    /// The rules the files above keep from claiming anything is absent, each with the first file
    /// that does.
    ///
    /// A file that was not opened holds back every rule that reads its language. A file that did not
    /// parse cleanly holds back only the rules whose call could be in it: a rule reports a call only
    /// when the call's name matches its pattern, so if no word in the file matches, even a perfect
    /// parse would have found nothing there. Until 4 October 2026 one such file held back every rule
    /// for the whole app (H25 of the deep review), and since every rule reads JavaScript, one
    /// vendored script the parser choked on silenced the report's every code claim.
    pub held_back: BTreeMap<String, String>,
    /// Rules that met a language `sv` reads but the rule has not been taught, and so claim nothing.
    ///
    /// A shell-command rule with no Rust query that met a Rust file has not ruled out a shell
    /// command built in Rust. Before this was kept, such a rule claimed the requirement on the
    /// strength of the Python beside it.
    pub untaught: Vec<Untaught>,
    /// Rules whose query for a language met in this app would not compile, so they did not run
    /// there. Like an unread file, this keeps every rule from claiming anything is absent.
    pub broken_queries: Vec<BrokenQuery>,
    /// Templates that hold a general-purpose language no grammar here reads (`.ejs`, `.erb`, `.jsp`,
    /// and the rest of `sv_scan::ecosystems::CODE_TEMPLATES`), so the report can name the files that
    /// put their kind in `unread_languages` (ADR-054).
    pub unread_templates: Vec<String>,
    /// `.sql` files, which no rule reads and which hold nothing back: the injection rules look at how
    /// the app's code builds a query, not at a file of SQL (ADR-054). Named so their silence is not
    /// taken for a reading.
    pub sql_files: Vec<String>,
}

/// One rule, and the languages in this app it was not able to look in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untaught {
    pub rule_id: String,
    pub title: String,
    pub languages: Vec<String>,
}

/// Runs every rule that has a query for this language over one file.
pub fn scan_file(rules: &AstRules, language: &str, relative: &str, source: &str) -> Vec<Finding> {
    read_file(rules, language, relative, source).findings
}

/// A rule whose query for a language tree-sitter refused to compile, so the rule did not run on
/// the files in that language.
///
/// Queries compile on first use (`LazyQuery`), and the data file's are all compiled by a test, so
/// this names a rule file edited after that test last ran. It is carried rather than swallowed
/// because a rule that did not run must not read as a rule that found nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokenQuery {
    pub rule_id: String,
    pub language: String,
    pub why: String,
}

/// What reading one file produced.
pub struct FileRead {
    pub findings: Vec<Finding>,
    /// The parse came back with an error in it, so some of the file was not read.
    pub parse_error: bool,
    /// Rules that could not run on this file because their query would not compile.
    pub broken: Vec<BrokenQuery>,
    /// Findings whose value is a parameter of the Python function around them, for `scan_listing`
    /// to look up that function's calls across the app.
    pub parameter_destinations: Vec<ParameterDestination>,
}

/// A finding whose value is a parameter of the Python function it sits in
/// (`def go(destination): return redirect(destination)`), and so is whatever that function's
/// callers pass (family-hub item 7, the redirect half of A1).
#[derive(Debug, Clone)]
pub struct ParameterDestination {
    pub rule_id: String,
    pub file: String,
    pub line: usize,
    /// The function the finding sits in, and the parameter.
    pub function: String,
    pub parameter: String,
    /// Where the parameter comes among those a caller passes by position, `self` and `cls` left out
    /// of a method's; `None` when it can only be passed by name.
    pub position: Option<usize>,
    /// The parameter's default, when it has one, as written.
    pub default: Option<String>,
}

/// Runs every rule over one file, and says whether the whole file was understood.
///
/// A `.tsx` file is parsed with the TSX grammar and matched with the rule's `typescript` query
/// compiled against it; everything else about it — the patterns, the coverage it counts towards — is
/// TypeScript's.
pub fn read_file(rules: &AstRules, language: &str, relative: &str, source: &str) -> FileRead {
    let unread = FileRead {
        findings: Vec::new(),
        parse_error: true,
        broken: Vec::new(),
        parameter_destinations: Vec::new(),
    };
    let mut broken = Vec::new();
    // An Astro page's code is TypeScript whose `{…}` may hold JSX, as a `.tsx` file's does.
    let lower = relative.to_lowercase();
    let tsx = language == "typescript" && (lower.ends_with(".tsx") || lower.ends_with(".astro"));
    let Some(grammar) = grammar(if tsx { "tsx" } else { language }) else {
        return unread;
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return unread;
    }
    let Some(tree) = parser.parse(source, None) else {
        return unread;
    };
    // The names that stand for fixed text, in the languages whose bindings `Fixed` reads.
    let fixed = if matches!(language, "python" | "javascript" | "typescript" | "go") {
        Fixed::of(tree.root_node(), source.as_bytes())
    } else {
        Fixed::default()
    };

    let mut out = Vec::new();
    let mut parameter_destinations = Vec::new();
    for compiled in &rules.compiled {
        let query = if tsx {
            compiled.tsx.as_ref()
        } else {
            compiled.queries.get(language)
        };
        let Some(query) = query else {
            continue;
        };
        let query = match query.get() {
            Ok(query) => query,
            // The rule is not run on this file, and says so, rather than quietly reading as clean.
            Err(why) => {
                broken.push(BrokenQuery {
                    rule_id: compiled.rule.id.clone(),
                    language: language.to_owned(),
                    why: why.to_owned(),
                });
                continue;
            }
        };
        let arg_index = query.capture_index_for_name("arg");
        let hit_index = query.capture_index_for_name("hit");
        let fn_index = query.capture_index_for_name("fn");
        let mod_index = query.capture_index_for_name("mod");
        let kw_index = query.capture_index_for_name("kw");
        let hash_index = query.capture_index_for_name("hash");
        let text_of = |m: &tree_sitter::QueryMatch, index: Option<u32>| -> Option<String> {
            let index = index?;
            let capture = m.captures().iter().find(|c| c.index == index)?;
            capture
                .node
                .utf8_text(source.as_bytes())
                .ok()
                .map(str::to_owned)
        };
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
        while let Some(m) = matches.next() {
            // The name filters the query cannot apply for itself.
            if let Some(pattern) = compiled.function.get(language) {
                match text_of(m, fn_index) {
                    Some(name) if pattern.is_match(&name) => {}
                    Some(name)
                        if compiled.rule.function_names_read
                            && fn_index
                                .and_then(|index| m.captures().iter().find(|c| c.index == index))
                                .is_some_and(|c| {
                                    read_through_name(
                                        c.node,
                                        &name,
                                        source.as_bytes(),
                                        pattern,
                                        language,
                                    )
                                }) => {}
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.module.get(language) {
                match text_of(m, mod_index) {
                    Some(name) if pattern.is_match(&name) => {}
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.enclosing.get(language) {
                let named = hit_index
                    .and_then(|index| m.captures().iter().find(|c| c.index == index))
                    .and_then(|c| enclosing_function_name(c.node, source.as_bytes()));
                match named {
                    Some(name) if pattern.is_match(&words_of(&name)) => {}
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.value_name.get(language) {
                let named = hit_index
                    .and_then(|index| m.captures().iter().find(|c| c.index == index))
                    .is_some_and(|c| {
                        value_names(c.node, source.as_bytes())
                            .iter()
                            .any(|name| pattern.is_match(&words_of(name)))
                    });
                if !named {
                    continue;
                }
            }
            // The argument to judge: the `@arg` capture, or for a call named in `argumentPositions`,
            // the argument at that position in the same call.
            let mut arg_node = arg_index
                .and_then(|index| m.captures().iter().find(|c| c.index == index))
                .map(|c| c.node);
            if let Some(positions) = compiled.positions.get(language)
                && let Some(name) = text_of(m, fn_index)
                && let Some((_, position)) = positions.iter().find(|(re, _)| re.is_match(&name))
            {
                // In the grammars that wrap each argument (PHP's `argument`, Kotlin's and Swift's
                // `value_argument`, C#'s `argument`), the list is one level further up, and the value
                // is the wrapper's last part, after any name it is given.
                let wrapped =
                    |n: tree_sitter::Node| matches!(n.kind(), "argument" | "value_argument");
                let list = arg_node
                    .and_then(|n| n.parent())
                    .and_then(|p| if wrapped(p) { p.parent() } else { Some(p) });
                arg_node = list.and_then(|list| {
                    let mut cursor = list.walk();
                    let chosen = list
                        .named_children(&mut cursor)
                        .filter(|c| c.kind() != "comment")
                        .nth(*position)?;
                    if wrapped(chosen) {
                        let mut inner = chosen.walk();
                        chosen.named_children(&mut inner).last()
                    } else {
                        Some(chosen)
                    }
                });
                // A call without that many arguments is not the call the position was written for.
                if arg_node.is_none() {
                    continue;
                }
            }
            let arg_text = arg_node.and_then(|n| n.utf8_text(source.as_bytes()).ok());
            if let Some(pairs) = compiled.common_names.get(language)
                && let Some(name) = text_of(m, fn_index)
                && let Some((_, argument)) = pairs.iter().find(|(re, _)| re.is_match(&name))
                && !arg_text.is_some_and(|text| argument.is_match(text))
            {
                continue;
            }
            // The hash the call states, if the query reads one: every node captured as `@hash`,
            // in the order they appear.
            let hash_text = hash_index.and_then(|index| {
                let mut nodes: Vec<_> = m
                    .captures()
                    .iter()
                    .filter(|c| c.index == index)
                    .map(|c| c.node)
                    .collect();
                nodes.sort_by_key(|n| n.start_byte());
                let texts = nodes
                    .iter()
                    .map(|n| n.utf8_text(source.as_bytes()).ok())
                    .collect::<Option<Vec<_>>>()?;
                (!texts.is_empty()).then(|| texts.join(" "))
            });
            // A stated hash with its own figure is judged by that figure; anything else by the
            // rule's own argument pattern.
            let for_hash = compiled.by_hash.get(language).and_then(|pairs| {
                let hash = hash_text.as_deref()?;
                pairs
                    .iter()
                    .find(|(pattern, _)| pattern.is_match(hash))
                    .map(|(_, argument)| argument)
            });
            if let Some(pattern) = for_hash.or_else(|| compiled.argument.get(language)) {
                match arg_text {
                    Some(text) if pattern.is_match(text) => {}
                    Some(_)
                        if compiled.rule.argument_names_read
                            && arg_node.is_some_and(|arg| {
                                name_set_to(arg, source.as_bytes(), pattern, language == "shell")
                            }) => {}
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.keyword.get(language) {
                match text_of(m, kw_index) {
                    Some(name) if pattern.is_match(&name) => {}
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.safe_argument.get(language)
                && match arg_node {
                    Some(arg) if compiled.rule.safe_argument_pieces_read => {
                        safe_in_every_piece(arg, source.as_bytes(), pattern, &fixed)
                    }
                    Some(arg) => safe_in_every_branch(arg, source.as_bytes(), pattern, &fixed),
                    None => arg_text.is_some_and(|text| pattern.is_match(text)),
                }
            {
                continue;
            }
            // A literal argument means the call cannot be made to do anything the author did not
            // write, and so does a name the same file binds once to fixed text.
            if compiled.rule.literal_argument_is_safe
                && let Some(arg) = arg_node
                && is_literal(arg, source.as_bytes(), &fixed)
            {
                continue;
            }
            // A plain name handed over with values beside it is how placeholders are used.
            let bound_parameters = compiled.rule.bound_parameters_lower_confidence
                && arg_node.is_some_and(|arg| {
                    matches!(
                        arg.kind(),
                        "identifier" | "attribute" | "member_expression" | "selector_expression"
                    ) && arg.parent().is_some_and(|list| {
                        let mut cursor = list.walk();
                        list.named_children(&mut cursor)
                            .filter(|c| c.kind() != "comment")
                            .count()
                            > 1
                    })
                });
            // A path made of the app's own stored values, or a value a checking function returned:
            // the finding stays, and says why it may be safe (A1's leftovers).
            let read_back = compiled.rule.says_when_read_from_database
                && arg_node.is_some_and(|arg| fixed.read_back(arg, source.as_bytes()));
            let checked_by = compiled
                .rule
                .says_when_checked
                .then(|| arg_node.and_then(|arg| fixed.checked_by(arg, source.as_bytes())))
                .flatten();
            let node = hit_index
                .and_then(|index| m.captures().iter().find(|c| c.index == index))
                .map(|c| c.node)
                .or_else(|| m.captures().first().map(|c| c.node));
            let Some(node) = node else { continue };
            // A destination that is the enclosing function's parameter is whatever its callers
            // pass; `scan_listing` looks them up once every file is read.
            if compiled.rule.says_when_checked
                && language == "python"
                && !bound_parameters
                && !read_back
                && checked_by.is_none()
                && let Some(arg) = arg_node
                && let Some((function, parameter, position, default)) =
                    enclosing_parameter(arg, source.as_bytes())
            {
                parameter_destinations.push(ParameterDestination {
                    rule_id: compiled.rule.id.clone(),
                    file: relative.to_owned(),
                    line: node.start_position().row + 1,
                    function,
                    parameter,
                    position,
                    default,
                });
            }
            out.push(crate::finding::found(Finding {
                also_reported_by: Vec::new(),
                fingerprint: String::new(),
                earlier_fingerprints: Vec::new(),
                marked_test_code: false,
                bundled_library: None,
                outranked: None,
                also_on_this_line: Vec::new(),
                rule_id: compiled.rule.id.clone(),
                title: compiled.rule.title.clone(),
                severity: compiled.rule.severity,
                confidence: if bound_parameters {
                    Confidence::Low
                } else {
                    compiled.rule.confidence
                },
                location: Location {
                    file: relative.to_owned(),
                    line: node.start_position().row + 1,
                },
                secret: None,
                requirement_ids: compiled.rule.requirement_ids.clone(),
                cwe: compiled.rule.cwe.clone(),
                description: if bound_parameters {
                    format!(
                        "{} The query here is a name, handed over with values beside it, which is \
                         how placeholders are used, so it may already be safe: read where the \
                         name is given its text before changing anything.",
                        compiled.rule.description
                    )
                } else if read_back {
                    format!(
                        "{} The path here is built from fixed text and a value read back from the \
                         app's own database, which is usually one the app made itself, such as the \
                         id it gave a file when it saved it, so it may already be safe: check that \
                         nothing a person typed is ever stored in that field before changing \
                         anything.",
                        compiled.rule.description
                    )
                } else if let Some(checker) = &checked_by {
                    format!(
                        "{} The value here passed through {checker} first, whose name says it \
                         checks it, so it may already be safe: read that function to be sure it \
                         lets through only what it should before changing anything.",
                        compiled.rule.description
                    )
                } else {
                    compiled.rule.description.clone()
                },
                impact: compiled.rule.impact.clone(),
                fix: compiled.rule.fix.clone(),
            }));
        }
    }
    out.sort_by(|a, b| {
        a.location
            .line
            .cmp(&b.location.line)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    out.dedup_by(|a, b| a.rule_id == b.rule_id && a.location.line == b.location.line);
    FileRead {
        findings: out,
        parse_error: tree.root_node().has_error(),
        broken,
        parameter_destinations,
    }
}

/// The nodes that set a name to a value, in the grammars `sv` reads: an assignment (`x = v`,
/// `$x = v`, `x := v`, and the shell's `x=v`) or a declaration with a value (`let x = v`,
/// `String x = v`, `var x = v`).
const SETTERS: &[&str] = &[
    "assignment",
    "assignment_expression",
    "assignment_statement",
    "short_var_declaration",
    "var_spec",
    "variable_assignment",
    "variable_declarator",
];

/// The nodes that are a function, a method, or a closure, in the grammars `sv` reads.
const FUNCTIONS: &[&str] = &[
    "function_definition",
    "function_declaration",
    "function_expression",
    "function",
    "generator_function_declaration",
    "arrow_function",
    "method_definition",
    "method_declaration",
    "constructor_declaration",
    "local_function_statement",
    "lambda",
    "lambda_expression",
    "func_literal",
    "method",
    "singleton_method",
    "anonymous_function",
    "anonymous_function_creation_expression",
    "function_item",
    "closure_expression",
];

/// The name of the nearest function around `node` that has one: its own (`def verify_token`,
/// `bool VerifyToken(…)`, C++'s `Auth::check` as `check`, Dart's through its signature), or, for
/// one with none, the name it is assigned to or stored under (`const requireAuth = (…) => …`,
/// `exports.verify = …`, `{ isAllowed: function … }`). A function with neither is passed over for
/// the one around it.
fn enclosing_function_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    let text = |n: tree_sitter::Node| n.utf8_text(source).ok().map(str::to_owned);
    // The last part of a qualified or dotted name: `Auth::check`, `exports.verify`.
    let last = |s: String| {
        s.rsplit(['.', ':'])
            .next()
            .map(|p| p.trim().trim_start_matches('$').to_owned())
            .filter(|p| !p.is_empty())
    };
    let mut current = node.parent();
    while let Some(f) = current {
        current = f.parent();
        if !FUNCTIONS.contains(&f.kind()) {
            continue;
        }
        if let Some(name) = f.child_by_field_name("name") {
            return text(name).and_then(last);
        }
        // Dart: the name is in the signature, one or two levels down.
        if let Some(signature) = f.child_by_field_name("signature") {
            let mut look = Some(signature);
            while let Some(s) = look {
                if let Some(name) = s.child_by_field_name("name") {
                    return text(name).and_then(last);
                }
                look = s.named_child(0);
            }
        }
        // C and C++: through the declarators to the name, `Auth::check(int)` read as `check`.
        if let Some(mut declarator) = f.child_by_field_name("declarator") {
            while let Some(inner) = declarator.child_by_field_name("declarator") {
                declarator = inner;
            }
            return text(declarator).and_then(last);
        }
        // A function with no name of its own, named by what it is assigned to.
        if let Some(parent) = f.parent() {
            let named = match parent.kind() {
                "variable_declarator" | "public_field_definition" | "field_definition" => {
                    parent.child_by_field_name("name")
                }
                "assignment_expression" | "assignment" => parent.child_by_field_name("left"),
                "pair" => parent.child_by_field_name("key"),
                _ => None,
            };
            if let Some(name) = named.and_then(text).and_then(last) {
                return Some(name);
            }
        }
    }
    None
}

/// The names a value is given on its way out of the function it is made in: each variable, field,
/// or keyword argument it is assigned to (`otp = str(random.randint(…))` gives `otp`;
/// `user.reset_token = …` gives `reset_token`; `code, err := …` gives `code` and `err`), then the
/// name of the function around it.
fn value_names(node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let text = |n: tree_sitter::Node| n.utf8_text(source).unwrap_or("").to_owned();
    // The last part of a written target: `self.otp`, `$user->reset_token`, `@code`, `"otp"`.
    let last = |s: &str| -> Option<String> {
        s.rsplit(['.', ':', '>', '[', ']', '(', ')', ' '])
            .map(|p| p.trim().trim_matches(['"', '\'', '$', '@', '*', '&']))
            .find(|p| !p.is_empty())
            .map(str::to_owned)
    };
    let mut out = Vec::new();
    let mut current = node.parent();
    while let Some(n) = current {
        if FUNCTIONS.contains(&n.kind()) {
            break;
        }
        let target = match n.kind() {
            "assignment"
            | "assignment_expression"
            | "augmented_assignment"
            | "augmented_assignment_expression"
            | "short_var_declaration"
            | "assignment_statement" => n.child_by_field_name("left"),
            "variable_declarator"
            | "initialized_variable_definition"
            | "var_spec"
            | "public_field_definition"
            | "field_definition"
            | "keyword_argument"
            | "variable_assignment" => n.child_by_field_name("name"),
            // C and C++: `int otp = …`, `char *code = …`.
            "init_declarator" => n.child_by_field_name("declarator"),
            "pair" => n.child_by_field_name("key"),
            "let_declaration" => n.child_by_field_name("pattern"),
            // Kotlin's `val otp: Int = …`: the name is the declaration's first part, before its type.
            "property_declaration" => {
                let mut cursor = n.walk();
                n.named_children(&mut cursor)
                    .find(|c| c.kind() == "variable_declaration")
                    .and_then(|v| v.named_child(0))
            }
            _ => None,
        };
        if let Some(target) = target {
            out.extend(text(target).split(',').filter_map(last));
        }
        current = n.parent();
    }
    out.extend(enclosing_function_name(node, source));
    out
}

/// A function's name as lower-case words joined by `_`: `verifyToken`, `VerifyToken`,
/// `verify_token`, and `verify-token` are all `verify_token`, `isJWTValid` is `is_jwt_valid`, and
/// `authorized?` is `authorized`.
fn words_of(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        // `_`, `-`, and anything else that is not a letter or a digit (Ruby's `authorized?`).
        if !c.is_alphanumeric() {
            if !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            continue;
        }
        if c.is_uppercase() && i > 0 {
            let previous = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            // A new word starts at a capital after a small letter or a digit (`verifyToken`), or
            // at the last capital of a run followed by a small letter (`JWTValid`).
            let starts_word = previous.is_lowercase()
                || previous.is_ascii_digit()
                || (previous.is_uppercase() && next_lower);
            if starts_word && !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
        }
        out.extend(c.to_lowercase());
    }
    out.trim_end_matches('_').to_owned()
}

/// Whether a name in `arg` is set, in the function around it, to text `pattern` matches. With
/// `whole_file`, anywhere in the file: a shell variable is global unless declared `local`, so one set
/// in another function is the same variable.
fn name_set_to(
    arg: tree_sitter::Node,
    source: &[u8],
    pattern: &regex::Regex,
    whole_file: bool,
) -> bool {
    let text = |n: tree_sitter::Node| n.utf8_text(source).unwrap_or("");
    // The names in the argument, `$` left off PHP's.
    let mut names = BTreeSet::new();
    let mut stack = vec![arg];
    while let Some(node) = stack.pop() {
        // A name after a dot (`u.email`) or a keyword's own name (`email=` in Python) is a field
        // or a parameter, not a variable the function sets.
        let member = node.parent().is_some_and(|parent| {
            ["attribute", "property", "name", "field"]
                .iter()
                .any(|field| is_field_of(parent, field, node))
        });
        // JavaScript's `{ email }` is a name too, written as a property.
        if matches!(
            node.kind(),
            "identifier" | "variable_name" | "shorthand_property_identifier"
        ) && !member
        {
            names.insert(text(node).trim_start_matches('$'));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    if names.is_empty() {
        return false;
    }
    // The function around the call, or the file.
    let mut scope = arg;
    while let Some(parent) = scope.parent() {
        scope = parent;
        if !whole_file && FUNCTIONS.contains(&scope.kind()) {
            break;
        }
    }
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if SETTERS.contains(&node.kind()) {
            let target = ["left", "name", "pattern"]
                .iter()
                .find_map(|f| node.child_by_field_name(f));
            let value = ["right", "value"]
                .iter()
                .find_map(|f| node.child_by_field_name(f))
                .or_else(|| {
                    let mut cursor = node.walk();
                    node.named_children(&mut cursor).last()
                });
            if let (Some(target), Some(value)) = (target, value)
                && text(target)
                    .split(',')
                    .any(|t| names.contains(t.trim().trim_start_matches('$')))
                && pattern.is_match(text(value))
            {
                return true;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

/// Whether `written` (the text of `node`, such as `s.user`) matches `pattern` once the name it begins
/// with is read as a value the function around it sets that name to: `s = req.session` makes it
/// `req.session.user`. In PHP only a reference counts (`$s = &$_SESSION`): `$s = $_SESSION` is a copy, and
/// writing to it changes nothing in the session.
fn read_through_name(
    node: tree_sitter::Node,
    written: &str,
    source: &[u8],
    pattern: &regex::Regex,
    language: &str,
) -> bool {
    static HEAD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^\$?[A-Za-z_][A-Za-z0-9_]*").expect("a fixed pattern")
    });
    let text = |n: tree_sitter::Node| n.utf8_text(source).unwrap_or("");
    let Some(head) = HEAD.find(written) else {
        return false;
    };
    let rest = &written[head.end()..];
    let name = head.as_str().trim_start_matches('$');
    let mut scope = node;
    while let Some(parent) = scope.parent() {
        scope = parent;
        if FUNCTIONS.contains(&scope.kind()) {
            break;
        }
    }
    let mut stack = vec![scope];
    while let Some(setter) = stack.pop() {
        let by_reference = setter.kind() == "reference_assignment_expression";
        if (SETTERS.contains(&setter.kind()) && language != "php") || by_reference {
            let target = ["left", "name", "pattern"]
                .iter()
                .find_map(|f| setter.child_by_field_name(f));
            let value = ["right", "value"]
                .iter()
                .find_map(|f| setter.child_by_field_name(f));
            if let (Some(target), Some(value)) = (target, value)
                && text(target).trim().trim_start_matches('$') == name
            {
                // PHP's `$s = &$_SESSION`: the grammar keeps the `&` out of the value.
                if pattern.is_match(&format!("{}{rest}", text(value).trim())) {
                    return true;
                }
            }
        }
        let mut cursor = setter.walk();
        stack.extend(setter.named_children(&mut cursor));
    }
    false
}

/// When `node` is a bare name that is a parameter of the Python function around it: the function's
/// name, the parameter's, where it comes among the parameters a caller passes by position (`self`
/// or `cls` left out of a method), and its default as written.
fn enclosing_parameter(
    node: tree_sitter::Node,
    source: &[u8],
) -> Option<(String, String, Option<usize>, Option<String>)> {
    if node.kind() != "identifier" {
        return None;
    }
    let name = node.utf8_text(source).ok()?;
    let mut function = node.parent();
    while let Some(f) = function {
        if f.kind() == "function_definition" {
            break;
        }
        // A lambda's or a class's own names are not the function's.
        if matches!(f.kind(), "lambda" | "class_definition") {
            return None;
        }
        function = f.parent();
    }
    let function = function?;
    let function_name = function
        .child_by_field_name("name")?
        .utf8_text(source)
        .ok()?;
    // A parameter the function gives another value is no longer what its callers passed.
    if binds_name(function.child_by_field_name("body")?, name, source) {
        return None;
    }
    let parameters = function.child_by_field_name("parameters")?;
    // A method, called as `obj.method(...)`, is not passed its `self` or `cls`.
    let method = function
        .parent()
        .and_then(|block| block.parent())
        .is_some_and(|p| p.kind() == "class_definition")
        || function
            .parent()
            .filter(|p| p.kind() == "decorated_definition")
            .and_then(|d| d.parent())
            .and_then(|block| block.parent())
            .is_some_and(|p| p.kind() == "class_definition");
    let mut position = 0usize;
    let mut by_position = true;
    let mut cursor = parameters.walk();
    for (index, parameter) in parameters.named_children(&mut cursor).enumerate() {
        let (own, default) = match parameter.kind() {
            "identifier" => (parameter.utf8_text(source).ok(), None),
            "typed_parameter" => (
                parameter
                    .named_child(0)
                    .and_then(|n| n.utf8_text(source).ok()),
                None,
            ),
            "default_parameter" | "typed_default_parameter" => (
                parameter
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok()),
                parameter
                    .child_by_field_name("value")
                    .and_then(|n| n.utf8_text(source).ok()),
            ),
            // After `*` or `*args`, parameters can only be passed by name.
            "list_splat_pattern" | "keyword_separator" => {
                by_position = false;
                continue;
            }
            _ => continue,
        };
        if method && index == 0 && matches!(own, Some("self" | "cls")) {
            continue;
        }
        if own == Some(name) {
            return Some((
                function_name.to_owned(),
                name.to_owned(),
                by_position.then_some(position),
                default.map(str::to_owned),
            ));
        }
        position += 1;
    }
    // A name the function does not take is one it found elsewhere.
    None
}

/// Whether anything in `body` gives `name` a value: an assignment, `+=`, `:=`, a `for` or `with`
/// target, an `except ... as`, or a `del`. Nested functions and classes are their own scope.
fn binds_name(body: tree_sitter::Node, name: &str, source: &[u8]) -> bool {
    fn targets(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
        match node.kind() {
            "assignment" | "augmented_assignment" => node.child_by_field_name("left"),
            "named_expression" => node.child_by_field_name("name"),
            "for_statement" | "for_in_clause" => node.child_by_field_name("left"),
            "as_pattern" => node.child_by_field_name("alias"),
            "delete_statement" => node.named_child(0),
            _ => None,
        }
    }
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if let Some(target) = targets(node) {
            let mut inner = vec![target];
            while let Some(t) = inner.pop() {
                if t.kind() == "identifier" && t.utf8_text(source) == Ok(name) {
                    return true;
                }
                let mut cursor = t.walk();
                inner.extend(t.named_children(&mut cursor));
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !matches!(child.kind(), "function_definition" | "class_definition") {
                stack.push(child);
            }
        }
    }
    false
}

/// Adds to each finding whose value is a Python function's parameter what that function's calls
/// across the app's Python pass, when every one passes what the rule counts as safe on its own
/// (`url_for(...)`, a path on this site): family-hub item 7, where `redirect(destination)` was
/// flagged though every caller passed `url_for("home.index")`, and the AI tool removed the
/// parameter to clear the finding. The finding stays, at the rule's confidence, and says so; the
/// owner's decision for a destination a function checked (A1, 5 October 2026) was to keep it and
/// name what to check.
///
/// Said only when the calls are all there is to see: at least one call, every use of the name a
/// call or its own definition or an import, and no call that spreads its arguments (`*args`).
fn note_callers(
    rules: &AstRules,
    listing: &sv_scan::files::Listing,
    scan: &mut AstScan,
    pending: &[ParameterDestination],
) {
    if pending.is_empty() {
        return;
    }
    let Some(grammar) = grammar("python") else {
        return;
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return;
    }
    let files: Vec<(String, String, tree_sitter::Tree)> = listing
        .app_files()
        .filter(|e| e.language == Some("python"))
        .filter_map(|e| {
            let text = e.read_text().ok()?;
            let tree = parser.parse(&text, None)?;
            Some((e.relative.clone(), text, tree))
        })
        .collect();
    for destination in pending {
        let Some(safe) = rules
            .compiled
            .iter()
            .find(|c| c.rule.id == destination.rule_id)
            .and_then(|c| c.safe_argument.get("python"))
        else {
            continue;
        };
        let mut passed: Vec<(String, usize)> = Vec::new();
        let mut all_safe = true;
        for (file, text, tree) in &files {
            let Some(calls) = calls_of(tree.root_node(), text.as_bytes(), &destination.function)
            else {
                all_safe = false;
                break;
            };
            for (line, arguments) in calls {
                let given = arguments.and_then(|args| {
                    argument(
                        args,
                        text.as_bytes(),
                        &destination.parameter,
                        destination.position,
                    )
                });
                let value = match given {
                    Some(Ok(value)) => Some(value),
                    // A spread of arguments: what reaches the parameter is not written here.
                    Some(Err(())) => None,
                    None => destination.default.clone(),
                };
                match value {
                    Some(value) if safe.is_match(value.trim()) => passed.push((file.clone(), line)),
                    _ => all_safe = false,
                }
            }
            if !all_safe {
                break;
            }
        }
        if !all_safe || passed.is_empty() {
            continue;
        }
        let Some(finding) = scan.findings.iter_mut().find(|f| {
            f.rule_id == destination.rule_id
                && f.location.file == destination.file
                && f.location.line == destination.line
        }) else {
            continue;
        };
        let n = passed.len();
        let mut places: Vec<String> = passed
            .iter()
            .take(5)
            .map(|(file, line)| format!("`{file}` line {line}"))
            .collect();
        if n > 5 {
            places.push(format!("{} more", n - 5));
        }
        finding.description = format!(
            "{} The value here is `{}`, a parameter of `{}`, and {} in this app's Python passes \
             the app's own route or a path on this site ({}), so it may already be safe: check that \
             nothing else calls `{}`, such as code `sv` did not read or another function of the \
             same name, before changing anything. Removing the parameter only to make this finding \
             go away is not a fix.",
            finding.description,
            destination.parameter,
            destination.function,
            if n == 1 {
                "its one call".to_owned()
            } else {
                format!("each of its {n} calls")
            },
            and_list(&places),
            destination.function,
        );
    }
}

/// Every call of `function` in a Python file, by its line and its argument list, called by its name
/// (`go(...)`) or as an attribute (`auth.go(...)`). `None` when the name is used in any other way,
/// such as handed to something else to call, since its calls are then not all here to read.
fn calls_of<'a>(
    root: tree_sitter::Node<'a>,
    source: &[u8],
    function: &str,
) -> Option<Vec<(usize, Option<tree_sitter::Node<'a>>)>> {
    let mut calls = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
        if node.kind() != "identifier" || node.utf8_text(source) != Ok(function) {
            continue;
        }
        let parent = node.parent()?;
        let is_field = |p: tree_sitter::Node, field: &str| {
            p.child_by_field_name(field)
                .is_some_and(|c| c.id() == node.id())
        };
        fn called(callee: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
            callee
                .parent()
                .filter(|call| call.kind() == "call" && is_field_of(*call, "function", callee))
        }
        if parent.kind() == "function_definition" && is_field(parent, "name") {
            continue;
        }
        if parent.kind() == "keyword_argument" && is_field(parent, "name") {
            continue;
        }
        if let Some(call) = called(node) {
            calls.push((
                call.start_position().row + 1,
                call.child_by_field_name("arguments"),
            ));
            continue;
        }
        if parent.kind() == "attribute"
            && is_field(parent, "attribute")
            && let Some(call) = called(parent)
        {
            calls.push((
                call.start_position().row + 1,
                call.child_by_field_name("arguments"),
            ));
            continue;
        }
        let mut up = Some(parent);
        let mut imported = false;
        while let Some(p) = up {
            if matches!(p.kind(), "import_statement" | "import_from_statement") {
                imported = true;
                break;
            }
            up = p.parent();
        }
        if !imported {
            return None;
        }
    }
    Some(calls)
}

/// Whether `child` is `parent`'s field of that name.
fn is_field_of(parent: tree_sitter::Node, field: &str, child: tree_sitter::Node) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|c| c.id() == child.id())
}

/// What a call passes for a parameter: the keyword argument of its name, or the argument at its
/// position. `None` when it passes none; `Some(Err(()))` when it spreads arguments (`*args`,
/// `**kwargs`), so what reaches the parameter is not written in the call.
fn argument(
    arguments: tree_sitter::Node,
    source: &[u8],
    parameter: &str,
    position: Option<usize>,
) -> Option<Result<String, ()>> {
    let mut cursor = arguments.walk();
    let mut positional = Vec::new();
    let mut spread = false;
    for argument in arguments.named_children(&mut cursor) {
        match argument.kind() {
            "keyword_argument" => {
                let name = argument
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok());
                if name == Some(parameter) {
                    return argument
                        .child_by_field_name("value")
                        .and_then(|v| v.utf8_text(source).ok())
                        .map(|v| Ok(v.to_owned()));
                }
            }
            "list_splat" | "dictionary_splat" => spread = true,
            "comment" => {}
            _ => positional.push(argument),
        }
    }
    if spread {
        return Some(Err(()));
    }
    position
        .and_then(|p| positional.get(p))
        .and_then(|a| a.utf8_text(source).ok())
        .map(|a| Ok(a.to_owned()))
}

/// Runs the rules over every source file in the app whose language has a grammar.
///
/// Languages present but unread are recorded rather than skipped quietly. A Ruby app scanned by a tool
/// with no Ruby grammar produces no findings, and "no findings" is what a clean app produces too.
pub fn scan_dir(rules: &AstRules, app_dir: &std::path::Path) -> AstScan {
    scan_listing(rules, &sv_scan::files::Listing::of(app_dir))
}

/// `scan_dir`, over a listing already made.
pub fn scan_listing(rules: &AstRules, listing: &sv_scan::files::Listing) -> AstScan {
    let mut scan = AstScan::default();
    let mut parameter_destinations = Vec::new();
    for entry in listing.app_files() {
        if entry.extension.as_deref() == Some("sql") {
            scan.sql_files.push(entry.relative.clone());
            continue;
        }
        let Some(language) = entry.language else {
            continue;
        };
        if language == "notebook" {
            match entry.read_text() {
                Ok(source) => read_notebook(rules, &entry.relative, &source, &mut scan),
                Err(why) => {
                    scan.unread_files
                        .push((entry.relative.clone(), why.explain().to_owned()));
                    hold_back(rules, &mut scan, "python", &entry.relative, None);
                }
            }
            continue;
        }
        if !is_supported(language) {
            // Present, and not read. The rules have nothing to say about this file and the report
            // should say that rather than let its silence be read as approval.
            //
            // Except for a page that holds no code. `html` covers `.html`, `.vue` and `.svelte`,
            // and almost every web application has at least one — so counting every page as unread
            // silenced every rule for nearly every real app, which is a great deal of silence
            // bought by a file that in most cases hides nothing at all.
            if language == "html" {
                match entry.read_text() {
                    Ok(source) => read_page(rules, &entry.relative, &source, &mut scan),
                    // A page that cannot be opened is the one case where nothing at all is known
                    // about it.
                    Err(_) => {
                        scan.unread_languages.insert("html".to_owned());
                    }
                }
                continue;
            }
            if sv_scan::ecosystems::CODE_TEMPLATES.contains(&language) {
                scan.unread_templates.push(entry.relative.clone());
            }
            scan.unread_languages.insert(language.to_owned());
            continue;
        }
        let source = match entry.read_text() {
            Ok(source) => source,
            Err(why) => {
                scan.unread_files
                    .push((entry.relative.clone(), why.explain().to_owned()));
                hold_back(rules, &mut scan, language, &entry.relative, None);
                continue;
            }
        };
        scan.files_parsed += 1;
        *scan
            .parsed_by_language
            .entry(language.to_owned())
            .or_default() += 1;
        let read = read_file(rules, language, &entry.relative, &source);
        if read.parse_error {
            scan.unparsed_files.push(entry.relative.clone());
            hold_back(rules, &mut scan, language, &entry.relative, Some(&source));
        }
        scan.findings.extend(read.findings);
        parameter_destinations.extend(read.parameter_destinations);
        note_broken(&mut scan, read.broken);
    }
    note_callers(rules, listing, &mut scan, &parameter_destinations);
    scan.findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });
    scan.untaught = untaught(rules, &scan);
    scan.verified = clean_rules(rules, &scan);
    scan
}

/// Records the rules a file not read in full keeps from claiming anything is absent: every rule that
/// reads `language` when the file was not opened (`source` is `None`), and when it was opened and
/// did not parse cleanly, every such rule whose call could be in it.
fn hold_back(
    rules: &AstRules,
    scan: &mut AstScan,
    language: &str,
    relative: &str,
    source: Option<&str>,
) {
    for compiled in &rules.compiled {
        if !compiled.queries.contains_key(language) {
            continue;
        }
        let could_be_there = match (source, compiled.function.get(language)) {
            (Some(source), Some(pattern)) if names_only(pattern.as_str()) => {
                names_in(source).any(|n| pattern.is_match(n))
            }
            // Not opened, a rule that does not narrow by name, or a name pattern that can match
            // more than one word: anything could be there.
            _ => true,
        };
        if could_be_there {
            scan.held_back
                .entry(compiled.rule.id.clone())
                .or_insert_with(|| relative.to_owned());
        }
    }
}

/// Every word in `source` that a call's name could be, whatever the parser made of the rest.
///
/// A name in every grammar `sv` reads is letters, digits, `_`, and `$`, with Ruby's `?` or `!` at
/// the end. Each run of those is given, and each part of a run joined by `-` as well as the whole,
/// since a shell command's name may hold one and elsewhere it is an operator. A word given here that
/// is not a name only makes a rule more cautious, never less.
fn names_in(source: &str) -> impl Iterator<Item = &str> {
    static WORD: OnceLock<regex::Regex> = OnceLock::new();
    let word = WORD.get_or_init(|| {
        regex::Regex::new(r"[A-Za-z0-9_$]+(?:-[A-Za-z0-9_$]+)*[?!]?").expect("a fixed pattern")
    });
    word.find_iter(source).flat_map(|m| {
        let whole = m.as_str();
        let parts = whole.contains('-').then(|| whole.split('-'));
        std::iter::once(whole).chain(parts.into_iter().flatten())
    })
}

/// Whether a name pattern can match only what `names_in` gives: a single word. Only patterns made of
/// letters, digits, `_`, alternatives, groups, anchors, and `?`, `!`, `*`, `+` (with `\$` for a
/// literal dollar) count. Anything else, such as a quoted path (`"/bin/sh"`), the shell's `.`, a
/// name with its module (`hashlib.pbkdf2_hmac`), or a character class, may match text no word is,
/// so the words in a file cannot rule it out.
fn names_only(pattern: &str) -> bool {
    pattern
        .replace("\\$", "")
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_|()^$?!*+".contains(c))
}

/// Records each rule-and-language whose query would not compile, once, however many files met it.
fn note_broken(scan: &mut AstScan, broken: Vec<BrokenQuery>) {
    for b in broken {
        if !scan.broken_queries.contains(&b) {
            scan.broken_queries.push(b);
        }
    }
}

/// Every rule, with the languages read in this app that it has neither a query for nor a reason
/// to have none.
fn untaught(rules: &AstRules, scan: &AstScan) -> Vec<Untaught> {
    rules
        .compiled
        .iter()
        .filter_map(|c| {
            let languages: Vec<String> = scan
                .parsed_by_language
                .iter()
                .filter(|(language, n)| {
                    **n > 0
                        && !c.queries.contains_key(*language)
                        && !c.rule.nothing_to_find.contains_key(*language)
                })
                .map(|(language, _)| language.clone())
                .collect();
            (!languages.is_empty()).then(|| Untaught {
                rule_id: c.rule.id.clone(),
                title: c.rule.title.clone(),
                languages,
            })
        })
        .collect()
}

/// The rules that read everything they could have read, and found nothing.
///
/// Fail closed three times over. A rule says nothing unless it parsed at least one file in a
/// language it has a query for — a SQL rule that never saw a line of Python has not established
/// that the app builds no queries by hand. No rule says anything at all while a language present in
/// the app goes unread, because the injection it looks for could be sitting in the Ruby nobody
/// parsed. And a rule says nothing while a language that *was* read is one it was never taught:
/// the parser having read the Swift does not mean this rule looked in it. Nor while a file it reads
/// was not opened, or did not parse cleanly and holds a word its call could be named (`held_back`).
fn clean_rules(rules: &AstRules, scan: &AstScan) -> Vec<crate::Verified> {
    if !scan.unread_languages.is_empty() || !scan.broken_queries.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (rule_id, languages, requirement_ids) in rules.coverage() {
        if rules.rules().any(|r| r.id == rule_id && r.findings_only) {
            continue;
        }
        if scan.findings.iter().any(|f| f.rule_id == rule_id)
            || scan.untaught.iter().any(|u| u.rule_id == rule_id)
            || scan.held_back.contains_key(rule_id)
        {
            continue;
        }
        let rule = rules.rules().find(|r| r.id == rule_id);
        // Files read, grouped by what the rule looks for in them: the rule's own words, or the
        // narrower ones it has for a language.
        let mut groups: Vec<(&str, Vec<String>)> = Vec::new();
        for language in &languages {
            let Some(n) = scan.parsed_by_language.get(*language).copied() else {
                continue;
            };
            if n == 0 {
                continue;
            }
            let mut files = format!("{n} {language} file{}", if n == 1 { "" } else { "s" });
            // The calls the rule reads in this language, so "nothing found" says where it looked
            // (deep review, improvement 2): a call not named is one it did not read. A language
            // with words of its own (`looksForIn`) already says where the rule looks there.
            if let Some((names, more)) = rule
                .filter(|r| !r.looks_for_in.contains_key(*language))
                .and_then(|r| r.function_patterns.get(*language))
                .and_then(|p| calls_named(p))
            {
                let names: Vec<String> = names.into_iter().map(|n| format!("`{n}`")).collect();
                files = if more {
                    format!(
                        "{files} (the calls it reads: {}, and others like them)",
                        names.join(", ")
                    )
                } else {
                    format!("{files} (the calls it reads: {})", and_list(&names))
                };
            }
            let phrase = rule
                .and_then(|r| r.looks_for_in.get(*language))
                .or(rule.map(|r| &r.looks_for))
                .map(String::as_str)
                .unwrap_or("");
            match groups.iter_mut().find(|(p, _)| *p == phrase) {
                Some((_, files_for)) => files_for.push(files),
                None => groups.push((phrase, vec![files])),
            }
        }
        if groups.is_empty() {
            continue;
        }
        // The rule's own words first, then each narrower one.
        groups.sort_by_key(|(p, _)| rule.is_none_or(|r| *p != r.looks_for));
        let scope = groups
            .iter()
            .map(|(phrase, files)| {
                let files = and_list(files);
                if phrase.is_empty() {
                    files
                } else {
                    format!("{phrase}, in {files}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        out.push(crate::Verified::new(rule_id, &requirement_ids, scope));
    }
    out
}

/// The call names a `functionPatterns` entry stands for, when it is a list of names
/// (`^(system|popen)$`), and whether it also stands for others that are not plain names, such as a
/// shell named in quotes or a family of names. `None` when it names none plainly.
fn calls_named(pattern: &str) -> Option<(Vec<String>, bool)> {
    let body = pattern.strip_prefix('^')?.strip_suffix('$')?;
    let body = body
        .strip_prefix('(')
        .and_then(|b| b.strip_suffix(')'))
        .unwrap_or(body);
    let mut alternatives = Vec::new();
    let (mut depth, mut start) = (0usize, 0);
    for (i, c) in body.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => {
                alternatives.push(&body[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    alternatives.push(&body[start..]);
    let plain = |a: &str| {
        let a = a.replace("\\$", "$");
        let mut chars = a.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    };
    let names: Vec<String> = alternatives
        .iter()
        .filter(|a| plain(a))
        .map(|a| a.replace("\\$", "$"))
        .collect();
    let more = names.len() < alternatives.len();
    (!names.is_empty()).then_some((names, more))
}

/// "a", "a and b", "a, b, and c".
pub(crate) fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// Reads the script out of a page and scans it as the language it is.
///
/// The page counts as read only when nothing code-shaped was left behind. A page whose script all
/// came out is one nothing is hiding in; a page with a `javascript:` URL still silences every rule,
/// because the extractor did not take that and saying otherwise would be the whole failure this
/// guards against.
fn read_page(rules: &AstRules, relative: &str, source: &str, scan: &mut AstScan) {
    // H2 of the deep review: a Svelte or Vue template runs code of its own (`on:click={() => …}`,
    // `{expression}`, `@click="…"`, `:href="…"`, `v-…`, `{{ … }}`) that is neither a `<script>` nor an
    // `on…=` handler. It is taken out here and read with the page's scripts.
    let template = template_code(relative, source);
    // Svelte's braces are read before its markup, as Svelte's own compiler reads them, so the markup
    // is given to the tokenizer with each one blanked out: otherwise `onclick={() => go()}` is a
    // handler `{()` that ends at the first space, and `=>` closes the tag.
    let blanked;
    let markup = match &template {
        Some(Ok(t)) if !t.spans.is_empty() => {
            blanked = blank_out(source, &t.spans);
            blanked.as_str()
        }
        _ => source,
    };
    let astro = relative.to_ascii_lowercase().ends_with(".astro");
    let page = page_fragments(markup, astro);
    if page.left_behind.is_some() {
        scan.unread_languages.insert("html".to_owned());
        return;
    }
    // Template code is in the language of the page's scripts: TypeScript when one says so. An Astro
    // page's header, template, and scripts are all TypeScript, which Astro compiles them as.
    let language = if astro || page.fragments.iter().any(|f| f.language == "typescript") {
        "typescript"
    } else {
        "javascript"
    };
    let mut fragments = page.fragments;
    // The grammar each piece is tried with: an Astro `{…}` may hold JSX.
    let grammar = if astro { "tsx" } else { language };
    let mut whole = true;
    match template {
        None => {}
        Some(Err(_)) => whole = false,
        Some(Ok(t)) => {
            // Each piece is checked on its own, so one the grammar cannot read does not cost the
            // rest; the ones it can are read together, as one fragment, at their own lines.
            let (read, unread): (Vec<_>, Vec<_>) = t
                .pieces
                .into_iter()
                .partition(|p| parses_cleanly(grammar, &p.code));
            whole = unread.is_empty();
            // A backstop against this and `template_holds_code` drifting apart: a page that holds
            // template code and gave none up was not read.
            if read.is_empty() && whole && template_holds_code(relative, source) {
                whole = false;
            }
            if !read.is_empty() {
                fragments.push(Fragment {
                    language,
                    code: joined(source, &read),
                    line_offset: 0,
                });
            }
        }
    }
    if !whole {
        // Its scripts are still read and what they find stands, but the page is named as not fully
        // read, and every rule whose call could be named in it is kept from claiming it clean.
        scan.unparsed_files.push(relative.to_owned());
        hold_back(rules, scan, language, relative, Some(source));
    }
    if fragments.is_empty() {
        // A page of markup. Nothing to read, and nothing hidden.
        return;
    }

    scan.files_parsed += 1;
    for fragment in &fragments {
        // Counted under the language actually parsed. A page holding JavaScript is a file in which
        // JavaScript was read, and the rules that claim coverage of JavaScript really did read it.
        *scan
            .parsed_by_language
            .entry(fragment.language.to_owned())
            .or_default() += 1;
        let read = read_file(rules, fragment.language, relative, &fragment.code);
        note_broken(scan, read.broken);
        for mut finding in read.findings {
            // Back to the line in the page. Without this a reader is sent to line 3 of something
            // that does not exist as a file.
            finding.location.line += fragment.line_offset;
            scan.findings.push(finding);
        }
    }
}

/// Reads a Jupyter notebook's code cells as Python (ADR-054), each line at the line it is on in the
/// notebook, so a finding sends the reader to the right place in the file.
///
/// A notebook whose kernel is another language is that language unread. A notebook that is not JSON
/// `sv` can read is a file not opened. Lines Python cannot read, IPython's `%magic` and `!command`
/// lines and its `%%` cell magics, are blanked before the parse, and every rule whose call could be
/// named in them is kept from claiming the app clean, as for a page not fully read: `!rm -rf {path}`
/// runs a shell command no rule looked at. A few magics that run nothing of the app's own
/// (`NOTEBOOK_SETTINGS`) are only blanked.
fn read_notebook(rules: &AstRules, relative: &str, source: &str, scan: &mut AstScan) {
    let notebook = match notebook_python(source) {
        Ok(notebook) => notebook,
        Err(NotebookUnread::Language(language)) => {
            scan.unread_languages.insert(language);
            return;
        }
        Err(NotebookUnread::NotRead(why)) => {
            scan.unread_files.push((relative.to_owned(), why));
            hold_back(rules, scan, "python", relative, None);
            return;
        }
    };
    let read = read_file(rules, "python", relative, &notebook.code);
    scan.files_parsed += 1;
    *scan
        .parsed_by_language
        .entry("python".to_owned())
        .or_default() += 1;
    if read.parse_error || !notebook.unread.is_empty() {
        scan.unparsed_files.push(relative.to_owned());
        let held = if read.parse_error {
            source
        } else {
            &notebook.unread
        };
        hold_back(rules, scan, "python", relative, Some(held));
    }
    scan.findings.extend(read.findings);
    note_broken(scan, read.broken);
}

/// Line magics that change only how the notebook shows or reloads things, and run none of the app's
/// code: blanked, and not counted as unread.
const NOTEBOOK_SETTINGS: &[&str] = &[
    "matplotlib",
    "load_ext",
    "reload_ext",
    "autoreload",
    "config",
];

/// A notebook's Python, and the lines in it Python cannot read.
#[derive(Debug, PartialEq)]
struct NotebookCode {
    /// The code cells' Python, each line where it is in the notebook, with blank lines between.
    code: String,
    /// The `%` and `!` lines and `%%` cells taken out of it, one after another.
    unread: String,
}

#[derive(Debug, PartialEq)]
enum NotebookUnread {
    /// The notebook's kernel is this language, not Python.
    Language(String),
    /// The notebook could not be read, and why.
    NotRead(String),
}

/// The Python in a notebook's code cells.
///
/// Notebooks as Jupyter saves them list each cell's source a line to a JSON string, one string to a
/// line of the file, so each line is found in the file, in order, and put on that line. When one
/// cannot be (a notebook written on a single line, or by a tool that escapes text differently), the
/// cells are read one after another instead, and a finding's line counts the code cells' lines.
fn notebook_python(source: &str) -> Result<NotebookCode, NotebookUnread> {
    let not_read = |why: &str| NotebookUnread::NotRead(why.to_owned());
    let doc: serde_json::Value = serde_json::from_str(source)
        .map_err(|_| not_read("not a notebook `sv` could read: its JSON did not parse"))?;
    let language = doc
        .pointer("/metadata/language_info/name")
        .or_else(|| doc.pointer("/metadata/kernelspec/language"))
        .and_then(|l| l.as_str());
    if let Some(language) = language
        && !language.eq_ignore_ascii_case("python")
    {
        return Err(NotebookUnread::Language(language.to_lowercase()));
    }
    let cells = doc
        .get("cells")
        .and_then(|c| c.as_array())
        .ok_or_else(|| not_read("not a notebook `sv` could read: it has no list of cells"))?;

    // Each code cell's lines, as the notebook stores them (a list of strings, or one string).
    let mut stored: Vec<Vec<String>> = Vec::new();
    for cell in cells {
        if cell.get("cell_type").and_then(|t| t.as_str()) != Some("code") {
            continue;
        }
        let lines = match cell.get("source") {
            Some(serde_json::Value::Array(parts)) => parts
                .iter()
                .map(|p| p.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>(),
            Some(serde_json::Value::String(text)) => {
                Some(text.split_inclusive('\n').map(str::to_owned).collect())
            }
            None => Some(Vec::new()),
            _ => None,
        }
        .ok_or_else(|| not_read("not a notebook `sv` could read: a cell's source is not text"))?;
        stored.push(lines);
    }

    // Each line as Python reads it: the line, or nothing with the line put among the unread.
    let mut unread = String::new();
    let mut python: Vec<Vec<String>> = Vec::new();
    for lines in &stored {
        let first = lines.first().map(|l| l.trim_start()).unwrap_or("");
        let whole_cell_unread = first.starts_with("%%");
        let mut out = Vec::new();
        for line in lines {
            let text = line.strip_suffix('\n').unwrap_or(line);
            let trimmed = text.trim_start();
            let magic = trimmed.starts_with('%') || trimmed.starts_with('!');
            if whole_cell_unread || magic {
                let name = trimmed
                    .trim_start_matches(['%', '!'])
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or("");
                let setting = trimmed.starts_with('%')
                    && !trimmed.starts_with("%%")
                    && NOTEBOOK_SETTINGS.contains(&name);
                if !setting {
                    unread.push_str(text);
                    unread.push('\n');
                }
                out.push(String::new());
            } else {
                out.push(text.to_owned());
            }
        }
        python.push(out);
    }

    // Where each stored line is in the file: its JSON string, found after the one before it.
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(source.match_indices('\n').map(|(i, _)| i + 1))
        .collect();
    let line_of = |at: usize| line_starts.partition_point(|&s| s <= at) - 1;
    let mut placed: Vec<(usize, &str)> = Vec::new();
    let mut cursor = 0;
    let mut last_line = None;
    'place: {
        for (lines, out) in stored.iter().zip(&python) {
            for (line, text) in lines.iter().zip(out) {
                let Ok(encoded) = serde_json::to_string(line) else {
                    break 'place;
                };
                let Some(found) = source[cursor..].find(&encoded) else {
                    break 'place;
                };
                let at = cursor + found;
                let n = line_of(at);
                if last_line.is_some_and(|l| n <= l) {
                    break 'place;
                }
                placed.push((n, text));
                last_line = Some(n);
                cursor = at + encoded.len();
            }
        }
        let mut code = vec![""; line_starts.len()];
        for (n, text) in placed {
            code[n] = text;
        }
        return Ok(NotebookCode {
            code: code.join("\n"),
            unread,
        });
    }
    // One cell after another, with a blank line between.
    let code = python
        .iter()
        .map(|out| out.join("\n"))
        .collect::<Vec<_>>()
        .join("\n\n");
    Ok(NotebookCode { code, unread })
}

/// Whether a `.svelte` or `.vue` page's markup, outside its `<script>` and `<style>` elements and its
/// comments, holds code the template runs. Svelte reads every `{` in its markup as the start of an
/// expression; Vue runs `{{ … }}` and the values of attributes named `@…`, `:…`, and `v-…`. Other
/// pages are left to `html_fragments`. Kept apart from `template_code`, which takes the code out, as
/// a check on it.
fn template_holds_code(relative: &str, source: &str) -> bool {
    let lower = relative.to_lowercase();
    if lower.ends_with(".ejs") {
        // Any tag but a comment, `<%#`, or a literal `<%`, written `<%%`.
        static EJS: OnceLock<regex::Regex> = OnceLock::new();
        let ejs = EJS.get_or_init(|| regex::Regex::new(r"<%[^#%]").expect("a fixed pattern"));
        return ejs.is_match(source);
    }
    if lower.ends_with(".astro") {
        let markup = match astro_frontmatter(source) {
            None => source.to_owned(),
            Some(Err(_)) => return true,
            Some(Ok((body, span))) => {
                if !source[body].trim().is_empty() {
                    return true;
                }
                blank_out(source, &[span])
            }
        };
        let Ok(ranges) = outside_code_elements(&markup) else {
            return true;
        };
        // Any `{` but one opening a comment, `{/* … */}`.
        static EXPRESSION: OnceLock<regex::Regex> = OnceLock::new();
        let expression = EXPRESSION.get_or_init(|| {
            regex::Regex::new(r"\{\s*(?:[^/\s]|/[^*]|$)").expect("a fixed pattern")
        });
        return ranges.into_iter().any(|r| expression.is_match(&markup[r]));
    }
    let svelte = lower.ends_with(".svelte");
    if !svelte && !lower.ends_with(".vue") {
        return false;
    }
    let Ok(ranges) = outside_code_elements(source) else {
        return true;
    };
    let markup: String = ranges.into_iter().map(|r| &source[r]).collect();
    if svelte {
        return markup.contains('{');
    }
    static VUE: OnceLock<regex::Regex> = OnceLock::new();
    let vue = VUE.get_or_init(|| {
        regex::Regex::new(r#"\{\{|[\s<]([@:]|v-)[A-Za-z0-9_.:\[\]-]*\s*="#)
            .expect("a fixed pattern")
    });
    vue.is_match(&markup)
}

/// A piece of code a Svelte or Vue template runs, written as a statement the grammar reads, and
/// where in the page it starts.
#[derive(Debug)]
struct TemplatePiece {
    code: String,
    at: usize,
}

/// The code a Svelte or Vue page's template runs.
#[derive(Debug, Default)]
struct Template {
    pieces: Vec<TemplatePiece>,
    /// Where Svelte's `{…}` sit, braces included.
    spans: Vec<std::ops::Range<usize>>,
}

/// The code in a `.svelte` or `.vue` page's template, or why it could not all be taken out; `None`
/// for any other page.
fn template_code(relative: &str, source: &str) -> Option<Result<Template, String>> {
    let lower = relative.to_ascii_lowercase();
    if lower.ends_with(".svelte") {
        Some(svelte_template(source))
    } else if lower.ends_with(".vue") {
        Some(vue_template(source))
    } else if lower.ends_with(".astro") {
        Some(astro_template(source))
    } else if lower.ends_with(".ejs") {
        Some(ejs_template(source))
    } else {
        None
    }
}

/// An Astro page's `---` header: where its code is, and where the header is with both fences. `None`
/// for a page with none; an error for a header that is never closed.
#[allow(clippy::type_complexity)]
fn astro_frontmatter(
    source: &str,
) -> Option<Result<(std::ops::Range<usize>, std::ops::Range<usize>), String>> {
    let start = source.len() - source.trim_start().len();
    let rest = source[start..].strip_prefix("---")?;
    if !rest.starts_with(['\n', '\r']) {
        return None;
    }
    let body = start + 3;
    let Some(j) = source[body..].find("\n---") else {
        return Some(Err("a `---` header with no `---` to close it".to_owned()));
    };
    let end = body + j;
    Some(Ok((body..end, start..end + 4)))
}

/// The code in an Astro page: its `---` header, read as TypeScript where it is, and every `{…}` in
/// its markup outside its scripts, styles, and comments, which Astro runs as an expression (a `{…}`
/// may hold JSX: `{items.map((i) => <li>{i}</li>)}`). The page's scripts are read by `html_fragments`.
fn astro_template(source: &str) -> Result<Template, String> {
    let mut out = Template::default();
    let markup = match astro_frontmatter(source) {
        None => source.to_owned(),
        Some(result) => {
            let (body, span) = result?;
            if !source[body.clone()].trim().is_empty() {
                out.pieces.push(TemplatePiece {
                    code: source[body.clone()].to_owned(),
                    at: body.start,
                });
            }
            out.spans.push(span.clone());
            blank_out(source, &[span])
        }
    };
    let mut next = 0;
    for range in outside_code_elements(&markup)? {
        let mut at = range.start.max(next);
        while at < range.end {
            let Some(i) = markup[at..range.end].find('{') else {
                break;
            };
            let open = at + i;
            let close = closing_brace(&markup, open)
                .ok_or_else(|| "a `{` with no `}` to close it".to_owned())?;
            let inner = source[open + 1..close].trim();
            let comment = inner.starts_with("/*") && inner.ends_with("*/");
            if !inner.is_empty() && !comment {
                let code = match inner.strip_prefix("...") {
                    // A spread of attributes, `<Card {...props} />`.
                    Some(e) => format!("({{...{e}}});"),
                    None => format!("({inner});"),
                };
                out.pieces.push(TemplatePiece { code, at: open + 1 });
            }
            out.spans.push(open..close + 1);
            at = close + 1;
        }
        next = at;
    }
    Ok(out)
}

/// The code in an EJS page's tags, as the one JavaScript program EJS compiles them into, each line
/// where it is in the page: `<% code %>` as it is, `<%= value %>` and `<%- value %>` as the value
/// they write out, and `<%# … %>` not at all. Each tag starts a statement, as in EJS's own output, so
/// `<% if (a) { %> … <% } %>` reads as `if (a) { … }`.
///
/// EJS ends each `<% %>` with a line break, and the program here cannot add lines without moving
/// every line after it, so a `//` comment in one with another tag after it on the same line would
/// hide that tag's code. Such a page is not read in full.
fn ejs_template(source: &str) -> Result<Template, String> {
    fn blank(into: &mut String, text: &str) {
        into.extend(text.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
    }
    let mut out = Template::default();
    let mut program = String::with_capacity(source.len());
    let mut any = false;
    let mut comment_open_on = None;
    let line_of = |at: usize| source[..at].matches('\n').count();
    let mut at = 0;
    while let Some(i) = source[at..].find("<%") {
        let open = at + i;
        blank(&mut program, &source[at..open]);
        let after = &source[open + 2..];
        if after.starts_with('%') {
            // `<%%`, a literal `<%` in the page.
            blank(&mut program, "<%%");
            at = open + 3;
            continue;
        }
        if comment_open_on == Some(line_of(open)) {
            return Err(
                "a `//` comment in a `<% %>` with another tag after it on its line".to_owned(),
            );
        }
        let mark = after.chars().next().filter(|c| "=-#_".contains(*c));
        let body_start = open + 2 + mark.map_or(0, |_| 1);
        let Some(j) = source[body_start..].find("%>") else {
            return Err("a `<%` with no `%>` to close it".to_owned());
        };
        let mut body_end = body_start + j;
        // `-%>` and `_%>` trim the white space after the tag.
        if body_end > body_start && source[..body_end].ends_with(['-', '_']) {
            body_end -= 1;
        }
        let close = body_start + j + 2;
        let body = &source[body_start..body_end];
        let opener = &source[open..body_start];
        let closer = &source[body_end..close];
        match mark {
            Some('#') => blank(&mut program, &source[open..close]),
            Some('=') | Some('-') => {
                // `<%=` is three characters: `;(` and a space.
                program.push_str(";( ");
                program.push_str(body);
                program.push(')');
                blank(&mut program, &closer[1..]);
                any = true;
            }
            _ => {
                program.push(';');
                blank(&mut program, &opener[1..]);
                program.push_str(body);
                blank(&mut program, closer);
                any = true;
                comment_open_on = body
                    .rsplit('\n')
                    .next()
                    .filter(|l| l.contains("//"))
                    .map(|_| line_of(close));
            }
        }
        out.spans.push(open..close);
        at = close;
    }
    blank(&mut program, &source[at..]);
    if any {
        out.pieces.push(TemplatePiece {
            code: program,
            at: 0,
        });
    }
    Ok(out)
}

/// Every `{…}` in a Svelte page outside its scripts, styles, and comments: Svelte reads each as an
/// expression or a block (`{#if …}`, `{#each … as …}`, `{@html …}`), in text and attributes alike.
fn svelte_template(source: &str) -> Result<Template, String> {
    let mut out = Template::default();
    let mut next = 0;
    for range in outside_code_elements(source)? {
        let mut at = range.start.max(next);
        while at < range.end {
            let Some(i) = source[at..range.end].find('{') else {
                break;
            };
            let open = at + i;
            let close = closing_brace(source, open)
                .ok_or_else(|| "a `{` with no `}` to close it".to_owned())?;
            if let Some(code) = svelte_statements(&source[open + 1..close])? {
                out.pieces.push(TemplatePiece { code, at: open + 1 });
            }
            out.spans.push(open..close + 1);
            at = close + 1;
        }
        next = at;
    }
    Ok(out)
}

/// What one Svelte `{…}` runs, as statements; `None` for one that runs nothing (`{/if}`, `{:else}`).
/// A pattern that names values (`{#each items as item}`) is written as an arrow function's
/// parameters, so it is read where a default value in it could run code.
fn svelte_statements(inner: &str) -> Result<Option<String>, String> {
    let t = inner.trim_start();
    // The rest after a block's keyword, when the keyword is followed by a space or nothing.
    let after = |keyword: &str| {
        t.strip_prefix(keyword)
            .filter(|r| r.is_empty() || r.starts_with(char::is_whitespace))
            .map(str::trim)
    };
    if t.starts_with('/') || t.trim_end() == ":else" {
        return Ok(None);
    }
    if let Some(e) = after("#if")
        .or_else(|| after(":else if"))
        .or_else(|| after("#key"))
        .or_else(|| after("@html"))
        .or_else(|| after("@render"))
        .or_else(|| after("@attach"))
    {
        return Ok(Some(format!("({e});")));
    }
    if let Some(rest) = after("#each") {
        let Some((list, binding)) = split_top(rest, " as ") else {
            return Ok(Some(format!("({rest});")));
        };
        let mut code = format!("({list});");
        let (params, key) = match trailing_group(binding) {
            Some((params, key)) => (params, Some(key)),
            None => (binding, None),
        };
        code.push_str(&format!(" (({params}) => 0);"));
        if let Some(key) = key {
            code.push_str(&format!(" ({key});"));
        }
        return Ok(Some(code));
    }
    if let Some(rest) = after("#await") {
        let (promise, pattern) =
            match split_top(rest, " then ").or_else(|| split_top(rest, " catch ")) {
                Some((promise, pattern)) => (promise, pattern.trim()),
                None => (rest, ""),
            };
        let mut code = format!("({promise});");
        if !pattern.is_empty() {
            code.push_str(&format!(" (({pattern}) => 0);"));
        }
        return Ok(Some(code));
    }
    if let Some(pattern) = after(":then").or_else(|| after(":catch")) {
        return Ok((!pattern.is_empty()).then(|| format!("(({pattern}) => 0);")));
    }
    if let Some(declaration) = after("@const") {
        return Ok(Some(format!("const {declaration};")));
    }
    if let Some(e) = after("@debug") {
        return Ok((!e.is_empty()).then(|| format!("({e});")));
    }
    if let Some(snippet) = after("#snippet") {
        return Ok(Some(format!("function {snippet} {{}}")));
    }
    if let Some(e) = t.strip_prefix("...") {
        return Ok(Some(format!("({{...{e}}});")));
    }
    if t.starts_with(['#', ':', '@']) {
        let word: String = t.chars().take_while(|c| !c.is_whitespace()).collect();
        return Err(format!("a `{{{word}` block this does not know"));
    }
    Ok(Some(format!("({inner});")))
}

/// Every directive value and every `{{ … }}` in a Vue page. Vue runs the value of each attribute
/// named `@…` or `v-on:…` as a handler, `v-for`'s as a loop, `#…` and `v-slot`'s as a slot's
/// parameters, and the value of every other `:…`, `.…`, and `v-…` attribute as an expression.
fn vue_template(source: &str) -> Result<Template, String> {
    static LANG: OnceLock<regex::Regex> = OnceLock::new();
    let lang = LANG.get_or_init(|| {
        regex::Regex::new(r#"<template\b[^>]*\slang\s*=\s*["']?([a-z0-9-]+)"#)
            .expect("a fixed pattern")
    });
    if let Some(found) = lang.captures(&source.to_ascii_lowercase())
        && &found[1] != "html"
    {
        return Err(format!(
            "a template written in {}, which this does not read",
            &found[1]
        ));
    }
    let mut out = Template::default();
    for attribute in &read_markup(source)?.attributes {
        let name = attribute.name.as_str();
        let directive = name.starts_with(['@', ':', '#', '.']) || name.starts_with("v-");
        if !directive {
            continue;
        }
        if name.contains('[') {
            return Err("a directive whose name is worked out when the page runs".to_owned());
        }
        let (value, unread) = decode_character_references(&source[attribute.value.clone()]);
        if unread {
            return Err("a character reference inside code that this does not decode".to_owned());
        }
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let code = if name.starts_with('@') || name.starts_with("v-on:") {
            format!("(function ($event) {{ {value} ;}});")
        } else if name == "v-for" {
            let (alias, list) = split_top(value, " in ")
                .or_else(|| split_top(value, " of "))
                .ok_or_else(|| "a `v-for` with no `in` or `of`".to_owned())?;
            let alias = alias.trim();
            let alias = alias
                .strip_prefix('(')
                .and_then(|a| a.strip_suffix(')'))
                .unwrap_or(alias);
            format!("(({alias}) => 0); ({list});")
        } else if name.starts_with('#') || name.starts_with("v-slot") {
            format!("(({value}) => 0);")
        } else {
            format!("({value});")
        };
        out.pieces.push(TemplatePiece {
            code,
            at: attribute.value.start,
        });
    }
    for range in outside_code_elements(source)? {
        let mut at = range.start;
        while at < range.end {
            let Some(i) = source[at..range.end].find("{{") else {
                break;
            };
            let open = at + i + 2;
            // Vue's own reading: the expression ends at the first `}}`.
            let close = source[open..]
                .find("}}")
                .map(|j| open + j)
                .ok_or_else(|| "a `{{` with no `}}` after it".to_owned())?;
            let (inner, unread) = decode_character_references(&source[open..close]);
            if unread {
                return Err(
                    "a character reference inside code that this does not decode".to_owned(),
                );
            }
            out.pieces.push(TemplatePiece {
                code: format!("({inner});"),
                at: open,
            });
            at = close + 2;
        }
    }
    out.pieces.sort_by_key(|p| p.at);
    Ok(out)
}

/// The parts of a page outside its `<script>` and `<style>` elements and its comments.
fn outside_code_elements(source: &str) -> Result<Vec<std::ops::Range<usize>>, String> {
    // ASCII lowering keeps every byte where it was; every position found is at an ASCII byte.
    let lower = source.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = Vec::new();
    let (mut start, mut at) = (0, 0);
    while let Some(i) = lower[at..].find('<') {
        let open = at + i;
        let rest = &lower[open..];
        let end = if let Some(comment) = rest.strip_prefix("<!--") {
            Some(
                comment
                    .find("-->")
                    .map_or(lower.len(), |j| open + 4 + j + 3),
            )
        } else if let Some(name) = ["script", "style"].into_iter().find(|n| {
            rest[1..].starts_with(n)
                && bytes
                    .get(open + 1 + n.len())
                    .is_none_or(|&b| is_html_space(b) || b == b'>' || b == b'/')
        }) {
            let close = format!("</{name}");
            let Some(j) = rest.find(&close) else {
                return Err(format!("a `<{name}>` with no `</{name}>` after it"));
            };
            Some(
                lower[open + j..]
                    .find('>')
                    .map_or(lower.len(), |k| open + j + k + 1),
            )
        } else {
            None
        };
        match end {
            Some(end) => {
                out.push(start..open);
                start = end;
                at = end;
            }
            None => at = open + 1,
        }
        if at >= lower.len() {
            break;
        }
    }
    out.push(start.min(source.len())..source.len());
    Ok(out)
}

/// Where the `}` that closes the `{` at `open` is, reading the JavaScript between them: braces in a
/// string do not count, and a template string's `${…}` does.
fn closing_brace(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    // What is open, innermost last: `{` a brace, `` ` `` a template string.
    let mut stack = vec![b'{'];
    let mut i = open + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if stack.last() == Some(&b'`') {
            match b {
                b'\\' => i += 1,
                b'`' => {
                    stack.pop();
                }
                b'$' if bytes.get(i + 1) == Some(&b'{') => {
                    stack.push(b'{');
                    i += 1;
                }
                _ => {}
            }
        } else {
            match b {
                b'\'' | b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    if i >= bytes.len() {
                        return None;
                    }
                }
                b'`' | b'{' => stack.push(b),
                b'}' => {
                    stack.pop();
                    if stack.is_empty() {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// The text before and after the first `separator` that sits outside every bracket and string.
fn split_top<'a>(text: &'a str, separator: &str) -> Option<(&'a str, &'a str)> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            quote @ (b'\'' | b'"' | b'`') => {
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if depth == 0 && text.is_char_boundary(i) && text[i..].starts_with(separator) => {
                return Some((&text[..i], &text[i + separator.len()..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// A Svelte `{#each}` binding's key: the `(…)` it ends with, after a space, and what comes before.
fn trailing_group(binding: &str) -> Option<(&str, &str)> {
    let binding = binding.trim_end();
    if !binding.ends_with(')') {
        return None;
    }
    let bytes = binding.as_bytes();
    let mut depth = 0i32;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    let before = &binding[..i];
                    return (before.ends_with(char::is_whitespace) && !before.trim().is_empty())
                        .then(|| (before.trim_end(), &binding[i + 1..binding.len() - 1]));
                }
            }
            _ => {}
        }
    }
    None
}

/// The page with every byte of these spans replaced by `_`, except line breaks, so every position
/// and line number stays where it was.
fn blank_out(source: &str, spans: &[std::ops::Range<usize>]) -> String {
    let mut out = String::with_capacity(source.len());
    let mut at = 0;
    for span in spans {
        out.push_str(&source[at..span.start]);
        for c in source[span.clone()].chars() {
            if c == '\n' {
                out.push('\n');
            } else {
                out.extend(std::iter::repeat_n('_', c.len_utf8()));
            }
        }
        at = span.end;
    }
    out.push_str(&source[at..]);
    out
}

/// The pieces as one program, each on the line of the page it came from, so a finding's line is
/// the page's.
fn joined(source: &str, pieces: &[TemplatePiece]) -> String {
    let mut code = String::new();
    let mut line = 0;
    for piece in pieces {
        let target = source[..piece.at].matches('\n').count();
        while line < target {
            code.push('\n');
            line += 1;
        }
        code.push_str(&piece.code);
        code.push(' ');
        line += piece.code.matches('\n').count();
    }
    code
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod html_tests;
