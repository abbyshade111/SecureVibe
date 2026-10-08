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
            let tsx = rule
                .queries
                .get("typescript")
                .map(|source| LazyQuery::new(grammar("tsx").expect("tsx is compiled in"), source));
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
    if matches!(
        node.kind(),
        "list_literal" | "array_literal" | "array_expression" | "list" | "tuple" | "array"
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
        let mut fixed = Fixed::default();
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
            out.push(Finding {
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
            });
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
mod tests {
    #[test]
    fn a_pattern_of_names_is_read_as_its_names_and_anything_else_as_more() {
        let names = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            calls_named("^(system|popen)$"),
            Some((names(&["system", "popen"]), false))
        );
        assert_eq!(calls_named("^Command$"), Some((names(&["Command"]), false)));
        assert_eq!(
            calls_named("^(query|\\$queryRawUnsafe)$"),
            Some((names(&["query", "$queryRawUnsafe"]), false))
        );
        assert_eq!(
            calls_named("^(Command|\"(/bin/)?(sh|bash)\")$"),
            Some((names(&["Command"]), true))
        );
        assert_eq!(calls_named("^(EVP_des\\w*|DES_\\w+)$"), None);
        // Two groups, not one: neither half is read as a name.
        assert_eq!(calls_named("^(a)|(b)$"), None);
        assert_eq!(calls_named("system"), None);
    }

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn astro_and_ejs_code_is_read_at_its_own_lines() {
        // ADR-054, Later: the code in an Astro page and in an EJS page is read, each `eval` on line 4
        // of its page, found there, with the page fully read.
        let rules = rules();
        let read = |name: &str, source: &str| {
            let mut scan = AstScan::default();
            read_page(rules, name, source, &mut scan);
            scan
        };
        let head = "---\nimport Card from './Card.astro';\nconst items: string[] = [];\n";
        // A header two lines long with its closing fence, so the markup starts on line 4.
        let short = "---\nconst items: string[] = [];\n---\n";
        for (name, page) in [
            // The header, as TypeScript.
            (
                "Header.astro",
                format!("{head}const x: string = eval(Astro.url.search);\n---\n<p>{{x}}</p>\n"),
            ),
            // A `{…}` in the markup, with JSX in it.
            (
                "Expression.astro",
                format!("{short}<ul>{{items.map((i) => <li>{{eval(i)}}</li>)}}</ul>\n"),
            ),
            ("Attribute.astro", format!("{short}<a href={{eval(next)}}>x</a>\n")),
            ("Spread.astro", format!("{short}<Card {{...eval(p)}} />\n")),
            // A script, which Astro compiles as TypeScript.
            (
                "Script.astro",
                "<p>x</p>\n<script>\n  const n: number = 1;\n  eval(location.hash);\n</script>\n"
                    .to_owned(),
            ),
            // No header at all.
            ("Bare.astro", "<main>\n  <h1>Hi</h1>\n</main>\n{eval(x)}\n".to_owned()),
            ("Code.ejs", "<html>\n<body>\n<p>x</p>\n<% eval(code) %>\n</body>\n".to_owned()),
            ("Escaped.ejs", "<ul>\n<li>a</li>\n<li>b</li>\n<%= eval(name) %>\n</ul>\n".to_owned()),
            ("Raw.ejs", "<ul>\n<li>a</li>\n<li>b</li>\n<%- eval(body) -%>\n</ul>\n".to_owned()),
            // One program across the tags, as EJS compiles it.
            (
                "Block.ejs",
                "<% if (user) { %>\n  <p>Hi</p>\n<% } else { %>\n  <p><%= eval(guest) %></p>\n<% } %>\n"
                    .to_owned(),
            ),
            (
                "Loop.ejs",
                "<ul>\n<% items.forEach(function (item) { %>\n  <li><%= item %></li>\n<% eval(item) }) %>\n</ul>\n"
                    .to_owned(),
            ),
            // A tag in a page's script is blanked there, and the script around it read.
            (
                "Script.ejs",
                "<p>x</p>\n<script>\n  var data = <%- JSON.stringify(data) %>;\n  eval(location.hash);\n</script>\n"
                    .to_owned(),
            ),
        ] {
            let scan = read(name, &page);
            assert!(scan.unparsed_files.is_empty(), "{name}: {page}");
            assert!(scan.unread_languages.is_empty(), "{name}: {page}");
            let found: Vec<_> = scan
                .findings
                .iter()
                .map(|f| (f.rule_id.as_str(), f.location.line))
                .collect();
            assert_eq!(found, [("ast.dynamic-code-execution", 4)], "{name}: {page}");
        }

        // What runs nothing is read as nothing: an EJS comment, a literal `<%`, and an Astro comment.
        for (name, page) in [
            ("Comment.ejs", "<%# eval(x) %>\n<p><%%= not code %></p>\n"),
            ("Comment.astro", "---\n---\n<p>{/* eval(x) */}</p>\n"),
            (
                "Plain.astro",
                "---\nconst title = 'Hi';\n---\n<h1>{title}</h1>\n",
            ),
            (
                "Plain.ejs",
                "<h1><%= title %></h1>\n<% if (a) { %>x<% } %>\n",
            ),
        ] {
            let scan = read(name, page);
            assert!(scan.unparsed_files.is_empty(), "{name}: {page}");
            assert!(scan.unread_languages.is_empty(), "{name}: {page}");
            assert!(scan.findings.is_empty(), "{name}: {:?}", scan.findings);
        }

        // What cannot all be taken out leaves the page not fully read.
        for (name, page) in [
            ("Open.ejs", "<p><% eval(x) </p>\n"),
            // EJS ends the first tag's line, so its comment does not hide `eval`; here it would.
            ("Comment.ejs", "<% let a = 1 // note %><% eval(x) %>\n"),
            ("Open.astro", "---\nconst a = 1;\n<p>{a}</p>\n"),
            ("Brace.astro", "---\n---\n<p>{eval(x)</p>\n"),
        ] {
            let scan = read(name, page);
            assert_eq!(scan.unparsed_files, [name], "{name}: {page}");
        }
    }

    #[test]
    fn template_code_is_read_as_code() {
        // H2 of the deep review: `on:click={() => eval(code)}` in a Svelte page gave no finding, and
        // the page counted as read. Each place a Svelte or Vue template runs code, holding `eval`, on
        // line 4 of the page; each must be found there, with the page fully read.
        let rules = rules();
        let read = |name: &str, source: &str| {
            let mut scan = AstScan::default();
            read_page(rules, name, source, &mut scan);
            scan
        };
        let script = "<script>\n  let count = 0;\n</script>\n";
        let ts = "<script lang=\"ts\">\n  let count: number = 0;\n</script>\n";
        let vue = |markup: &str| format!("{script}<template>{markup}\n</template>\n");
        for (name, page) in [
            (
                "Click.svelte",
                format!("{script}<button on:click={{() => eval(code)}}>Go</button>\n"),
            ),
            // Svelte 5's handlers are plain attributes; the space in the arrow must not end it.
            (
                "Click5.svelte",
                format!("{script}<button onclick={{() => eval(code)}}>Go</button>\n"),
            ),
            ("Text.svelte", format!("{script}<p>{{eval(note)}}</p>\n")),
            (
                "Quoted.svelte",
                format!("{script}<p class=\"note {{eval(kind)}}\">x</p>\n"),
            ),
            (
                "If.svelte",
                format!("{script}{{#if eval(x)}}<p>x</p>{{/if}}\n"),
            ),
            (
                "ElseIf.svelte",
                format!("{script}{{#if a}}a{{:else if eval(x)}}b{{/if}}\n"),
            ),
            (
                "Each.svelte",
                format!("{script}{{#each eval(list) as item}}<p>{{item}}</p>{{/each}}\n"),
            ),
            (
                "Key.svelte",
                format!("{script}{{#each list as item, i (eval(item))}}<p>{{i}}</p>{{/each}}\n"),
            ),
            (
                "Await.svelte",
                format!("{script}{{#await eval(p) then v}}<p>{{v}}</p>{{/await}}\n"),
            ),
            ("Html.svelte", format!("{script}{{@html eval(body)}}\n")),
            ("Const.svelte", format!("{script}{{@const x = eval(y)}}\n")),
            (
                "Spread.svelte",
                format!("{script}<a {{...eval(p)}}>x</a>\n"),
            ),
            (
                "Typed.svelte",
                format!("{ts}<p>{{eval(note as string)}}</p>\n"),
            ),
            (
                "Click.vue",
                vue("<button @click=\"eval(code)\">Go</button>"),
            ),
            (
                "On.vue",
                vue("<button v-on:click=\"eval(code)\">Go</button>"),
            ),
            ("Bind.vue", vue("<a :href=\"eval(next)\">Back</a>")),
            ("If.vue", vue("<p v-if=\"eval(x)\">x</p>")),
            ("For.vue", vue("<p v-for=\"(item, i) in eval(list)\">x</p>")),
            ("Html.vue", vue("<p v-html=\"eval(body)\"></p>")),
            ("Text.vue", vue("<p>{{ eval(note) }}</p>")),
            (
                "Escaped.vue",
                vue("<p :title=\"eval(&quot;x&quot; + y)\">x</p>"),
            ),
            ("Slot.vue", vue("<p #item=\"{ x = eval(y) }\">x</p>")),
        ] {
            let scan = read(name, &page);
            assert!(scan.unparsed_files.is_empty(), "{name}: {page}");
            assert!(scan.unread_languages.is_empty(), "{name}: {page}");
            let found: Vec<_> = scan
                .findings
                .iter()
                .map(|f| (f.rule_id.as_str(), f.location.line))
                .collect();
            assert_eq!(found, [("ast.dynamic-code-execution", 4)], "{name}: {page}");
        }

        // Template code with nothing to find is read too, braces in strings and template strings
        // included, and a page of markup has nothing taken out of it.
        for (name, page) in [
            (
                "Strings.svelte",
                format!("{script}<p title={{\"}}\"}}>{{`a ${{ {{b: 1}}.b }} }}`}}</p>\n"),
            ),
            (
                "Plain.svelte",
                format!("{script}<h1>Notes</h1>\n<style>h1 {{ color: red }}</style>\n"),
            ),
            (
                "Comment.svelte",
                format!("{script}<!-- {{ not code -->\n<p>x</p>\n"),
            ),
            ("Plain.vue", vue("<a href=\"/x\" class=\"b\">x</a>")),
            (
                "Obj.vue",
                vue("<p :class=\"{ a: b, c: d }\" @click=\"n++; go()\">x</p>"),
            ),
            ("index.html", "<p>Use {name} here</p>\n".to_owned()),
        ] {
            let scan = read(name, &page);
            assert!(
                scan.unparsed_files.is_empty() && scan.findings.is_empty(),
                "{name}: {:?} {:?}",
                scan.unparsed_files,
                scan.findings
            );
        }

        // What cannot be taken out, or is not code the grammar reads, leaves the page named as not
        // fully read, and holds back each rule whose call is named in it. Its script is still read.
        for (name, page) in [
            ("Open.svelte", format!("{script}<p>{{eval(x)</p>\n")),
            ("Unknown.svelte", format!("{script}{{#nope eval(x)}}\n")),
            ("Garbled.svelte", format!("{script}<p>{{eval(x) y}}</p>\n")),
            ("Garbled.vue", vue("<p :title=\"eval(x) y\">x</p>")),
            ("Dynamic.vue", vue("<p :[eval(k)]=\"v\">x</p>")),
            (
                "Pug.vue",
                format!("{script}<template lang=\"pug\">\np(@click=\"eval(x)\")\n</template>\n"),
            ),
            ("OpenText.vue", vue("<p>{{ eval(x) </p>")),
            // One piece read and one not: the page is still not fully read.
            (
                "Mixed.svelte",
                format!("{script}<p>{{count}}</p><p>{{eval(x) y}}</p>\n"),
            ),
            // Vue reads a `<textarea>`'s body as text, so nothing is taken out of it, while the older
            // test of the page sees an `@click`. While the two disagree the page is not counted read.
            (
                "Textarea.vue",
                vue("<textarea><b @click=\"eval(x)\"></b></textarea>"),
            ),
        ] {
            let scan = read(name, &page);
            assert_eq!(scan.unparsed_files, [name], "{name}: {page}");
            assert!(
                scan.held_back.contains_key("ast.dynamic-code-execution"),
                "{name}: {:?}",
                scan.held_back
            );
            assert!(scan.files_parsed >= 1, "{name}: its script is still read");
        }
    }

    /// The rules, loaded once for the whole test binary: each query is compiled the first time a
    /// test needs it and kept, where loading them anew for every case made the 46 tests here spend
    /// most of their time compiling the same queries again (8 October 2026).
    fn rules() -> &'static AstRules {
        static RULES: std::sync::OnceLock<AstRules> = std::sync::OnceLock::new();
        RULES.get_or_init(|| {
            AstRules::load(
                &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json"),
            )
            .expect("rules load")
        })
    }

    fn scan(language: &str, source: &str) -> Vec<Finding> {
        scan_file(rules(), language, &format!("src/app.{language}"), source)
    }

    /// The one finding `rule` makes in `source`, read as `file`.
    fn only_finding(rule: &str, language: &str, file: &str, source: &str) -> Finding {
        let found: Vec<Finding> = scan_file(rules(), language, file, source)
            .into_iter()
            .filter(|f| f.rule_id == rule)
            .collect();
        assert_eq!(found.len(), 1, "{rule} in {source}: {found:?}");
        found.into_iter().next().unwrap()
    }

    #[test]
    fn a_path_made_of_the_app_s_own_stored_values_says_so() {
        // A1's leftover 2, from the owner's study: an attachment's file name is the id the app gave
        // it when it was saved, read back from the database. The finding stays, and says so; a path
        // with anything else in it does not.
        let rule = "ast.file-path-from-value";
        const SAYS: &str = "read back from the app's own database";
        let head = "import os\nfrom flask import request, send_file\nUPLOAD_DIR = 'uploads'\n";
        let read_back = [
            "def get(aid):\n    row = db().execute('SELECT id FROM files WHERE id = ?', (aid,)).fetchone()\n    return send_file(os.path.join(UPLOAD_DIR, row['id']))\n",
            "def get(aid):\n    row = db().execute('SELECT id FROM files WHERE id = ?', (aid,)).fetchone()\n    path = os.path.join(UPLOAD_DIR, row['id'])\n    return send_file(path)\n",
            "def all_files():\n    for row in db().execute('SELECT id FROM files').fetchall():\n        open(os.path.join(UPLOAD_DIR, f\"{row['id']}.pdf\"))\n",
            "def get(aid):\n    attachment = Attachment.query.get_or_404(aid)\n    return send_file(os.path.join(UPLOAD_DIR, attachment.stored_name))\n",
        ];
        for body in read_back {
            let finding = only_finding(rule, "python", "app.py", &format!("{head}{body}"));
            assert!(
                finding
                    .description
                    .contains("read back from the app's own database"),
                "{body}: {}",
                finding.description
            );
        }
        let typed = [
            // What a person sent.
            "def get():\n    return send_file(os.path.join(UPLOAD_DIR, request.args['f']))\n",
            // A stored value and what a person sent, together.
            "def get(aid):\n    row = db().execute('SELECT id FROM files WHERE id = ?', (aid,)).fetchone()\n    return send_file(os.path.join(UPLOAD_DIR, row['id'], request.args['f']))\n",
            // A name set from the database in one place and from the request in another.
            "def get(aid):\n    row = db().execute('SELECT id FROM files').fetchone()\n    return send_file(os.path.join(UPLOAD_DIR, row['id']))\n\ndef put():\n    row = request.get_json()\n    open(os.path.join(UPLOAD_DIR, row['id']), 'w')\n",
            // `get` is a dictionary's, not a database's.
            "def get():\n    name = request.args.get('f')\n    return send_file(os.path.join(UPLOAD_DIR, name))\n",
        ];
        for body in typed {
            let found: Vec<Finding> =
                scan_file(rules(), "python", "app.py", &format!("{head}{body}"))
                    .into_iter()
                    .filter(|f| f.rule_id == rule)
                    .collect();
            assert!(!found.is_empty(), "{body}: the control found nothing");
            assert!(
                found.iter().all(|f| !f.description.contains(SAYS)),
                "{body}: {found:?}"
            );
        }
        // The same in JavaScript, through an ORM's read.
        let finding = only_finding(
            rule,
            "javascript",
            "app.js",
            "const path = require('path');\nconst UPLOAD_DIR = 'uploads';\napp.get('/f/:id', async (req, res) => {\n  const file = await prisma.attachment.findUnique({ where: { id: req.params.id } });\n  res.sendFile(path.join(UPLOAD_DIR, file.storedName));\n});\n",
        );
        assert!(finding.description.contains(SAYS), "{finding:?}");
    }

    #[test]
    fn a_destination_every_caller_fills_with_the_apps_own_route_says_so() {
        // family-hub item 7: `redirect(destination)`, where every caller passed
        // `url_for("home.index")`, and the AI tool removed the parameter to clear the finding. The
        // finding stays in every case; only what it says changes.
        const SAYS: &str = "passes the app's own route or a path on this site";
        let scan_app = |name: &str, files: &[(&str, &str)]| {
            let dir =
                std::env::temp_dir().join(format!("sv-ast-callers-{name}-{}", std::process::id()));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).unwrap();
            for (file, text) in files {
                std::fs::write(dir.join(file), text).unwrap();
            }
            let scan = scan_dir(rules(), &dir);
            std::fs::remove_dir_all(&dir).ok();
            let found: Vec<Finding> = scan
                .findings
                .into_iter()
                .filter(|f| f.rule_id == "ast.open-redirect")
                .collect();
            assert_eq!(found.len(), 1, "{name}: the finding stays: {found:?}");
            found.into_iter().next().unwrap()
        };
        let signin = "from flask import redirect, session\n\n\
                      def finish_sign_in(user, destination):\n    \
                      session['uid'] = user.id\n    \
                      return redirect(destination)\n";
        let views = |calls: &str| {
            format!(
                "from flask import url_for, request\nfrom signin import finish_sign_in\n\n{calls}"
            )
        };

        // Every caller passes the app's own route, by position or by name: said, with each call.
        let finding = scan_app(
            "all-own",
            &[
                ("signin.py", signin),
                (
                    "views.py",
                    &views(
                        "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n\n\
                         def join(user):\n    return finish_sign_in(user, destination='/welcome')\n",
                    ),
                ),
            ],
        );
        assert!(
            finding.description.contains(SAYS),
            "{}",
            finding.description
        );
        for part in [
            "`destination`, a parameter of `finish_sign_in`",
            "each of its 2 calls",
            "`views.py` line 5",
            "`views.py` line 8",
            "is not a fix",
        ] {
            assert!(
                finding.description.contains(part),
                "{part}: {}",
                finding.description
            );
        }

        // A default the callers leave alone, and a method called on its object.
        let defaulted = scan_app(
            "default",
            &[(
                "app.py",
                "from flask import redirect, url_for\n\n\
                 def finish(user, destination=url_for('home.index')):\n    return redirect(destination)\n\n\
                 def login(user):\n    return finish(user)\n",
            )],
        );
        assert!(
            defaulted.description.contains("its one call"),
            "{}",
            defaulted.description
        );
        let method = scan_app(
            "method",
            &[(
                "app.py",
                "from flask import redirect, url_for\n\n\
                 class Auth:\n    def go(self, destination):\n        return redirect(destination)\n\n\
                 def login(auth):\n    return auth.go(url_for('home.index'))\n",
            )],
        );
        assert!(method.description.contains(SAYS), "{}", method.description);

        // Not said: a caller passes what came in the request; the function is handed to something
        // else to call; nobody calls it; it gives the parameter another value; a call spreads its
        // arguments; the parameter can only be passed by name and the caller leaves it out.
        for (name, files) in [
            (
                "one-from-request",
                vec![
                    ("signin.py", signin.to_owned()),
                    (
                        "views.py",
                        views(
                            "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n\n\
                             def back(user):\n    return finish_sign_in(user, request.args.get('next'))\n",
                        ),
                    ),
                ],
            ),
            (
                "handed-on",
                vec![
                    ("signin.py", signin.to_owned()),
                    (
                        "views.py",
                        views(
                            "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n\n\
                             HOOKS = [finish_sign_in]\n",
                        ),
                    ),
                ],
            ),
            ("no-callers", vec![("signin.py", signin.to_owned())]),
            (
                "reassigned",
                vec![
                    (
                        "signin.py",
                        signin.replace(
                            "    return redirect(destination)",
                            "    destination = request.args.get('next') or destination\n    \
                             return redirect(destination)",
                        ),
                    ),
                    (
                        "views.py",
                        views(
                            "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n",
                        ),
                    ),
                ],
            ),
            (
                "spread",
                vec![
                    ("signin.py", signin.to_owned()),
                    (
                        "views.py",
                        views(
                            "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n\n\
                             def other(pair):\n    return finish_sign_in(*pair)\n",
                        ),
                    ),
                ],
            ),
            // The default is the app's own route, but a spread may fill the parameter with anything.
            (
                "spread-over-default",
                vec![(
                    "app.py",
                    "from flask import redirect, url_for\n\n\
                     def finish(user, destination=url_for('home.index')):\n    return redirect(destination)\n\n\
                     def login(args):\n    return finish(*args)\n"
                        .to_owned(),
                )],
            ),
            (
                "by-name-only",
                vec![(
                    "app.py",
                    "from flask import redirect, url_for\n\n\
                     def finish(user, *, destination):\n    return redirect(destination)\n\n\
                     def login(user):\n    return finish(user, url_for('home.index'))\n"
                        .to_owned(),
                )],
            ),
        ] {
            let files: Vec<(&str, &str)> = files.iter().map(|(f, t)| (*f, t.as_str())).collect();
            let finding = scan_app(name, &files);
            assert!(
                !finding.description.contains(SAYS),
                "{name}: {}",
                finding.description
            );
        }
    }

    #[test]
    fn a_destination_that_passed_through_a_checking_function_names_it() {
        // A1's leftover 3: `safe_next` sends anything but a path on this site to the home page. No
        // rule can read every such function; one named so usually does what it says, so the finding
        // stays and names it.
        let rule = "ast.open-redirect";
        const SAYS: &str = "first, whose name says it checks it";
        let head = "from flask import redirect, request\n";
        let checked = [
            "def done():\n    return redirect(safe_next(request.args.get('next')))\n",
            "def done():\n    next_url = safe_next(request.args.get('next'))\n    return redirect(next_url)\n",
        ];
        for body in checked {
            let finding = only_finding(rule, "python", "app.py", &format!("{head}{body}"));
            assert!(
                finding
                    .description
                    .contains("passed through `safe_next` first"),
                "{body}: {}",
                finding.description
            );
        }
        // Checked by one function in one place and another in another: both are named.
        let both = "def done():\n    next_url = safe_next(request.args.get('next'))\n    return redirect(next_url)\n\ndef other():\n    next_url = clean_url(request.args.get('next'))\n    return redirect(next_url)\n";
        let found: Vec<Finding> = scan_file(rules(), "python", "app.py", &format!("{head}{both}"))
            .into_iter()
            .filter(|f| f.rule_id == rule)
            .collect();
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found.iter().all(|f| f
                .description
                .contains("passed through `clean_url` or `safe_next` first")),
            "{found:?}"
        );
        let unchecked = [
            "def done():\n    return redirect(request.args.get('next'))\n",
            // Checked in one place and not in another: which one reaches the call is not known.
            "def done():\n    next_url = safe_next(request.args.get('next'))\n    return redirect(next_url)\n\ndef other():\n    next_url = request.args.get('next')\n    return redirect(next_url)\n",
            // A function named for something else.
            "def done():\n    return redirect(build_url(request.args.get('next')))\n",
        ];
        for body in unchecked {
            let found: Vec<Finding> =
                scan_file(rules(), "python", "app.py", &format!("{head}{body}"))
                    .into_iter()
                    .filter(|f| f.rule_id == rule)
                    .collect();
            assert!(!found.is_empty(), "{body}: the control found nothing");
            assert!(
                found.iter().all(|f| !f.description.contains(SAYS)),
                "{body}: {found:?}"
            );
        }
        let finding = only_finding(
            rule,
            "javascript",
            "app.js",
            "app.get('/done', (req, res) => {\n  res.redirect(isSafeRedirect(req.query.next));\n});\n",
        );
        assert!(
            finding
                .description
                .contains("passed through `isSafeRedirect` first"),
            "{finding:?}"
        );
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn the_words_in_a_file_rule_out_only_what_a_name_pattern_can_match() {
        let words: Vec<&str> =
            names_in("x = a.eval(q)\nclickhouse-client --query \"$Q\" && ok? go!").collect();
        for w in [
            "x",
            "a",
            "eval",
            "q",
            "clickhouse-client",
            "clickhouse",
            "client",
            "query",
            "$Q",
            "ok?",
            "go!",
        ] {
            assert!(words.contains(&w), "{w}: {words:?}");
        }
        assert!(names_only("^(eval|Function)$"));
        assert!(names_only("^(query|\\$queryRawUnsafe)$"));
        for wider in [
            "^(Command|\"(/bin/|/usr/bin/)?(sh|bash)\")$",
            "^(cat|\\.)$",
            "(^|\\.)(pbkdf2_hmac)$",
            "(^|::)(pbkdf2)$",
            "^ev.l$",
            "^[a-z]+$",
            "^exists\\?$",
        ] {
            assert!(!names_only(wider), "{wider}");
        }
        // The real rules: most name patterns are words, so a broken file holds back only what it
        // names; the shell's are not, and are always held back.
        let rules = rules();
        let by_rule = |id: &str, language: &str| {
            let c = rules.compiled.iter().find(|c| c.rule.id == id).unwrap();
            names_only(c.function[language].as_str())
        };
        assert!(by_rule("ast.dynamic-code-execution", "javascript"));
        assert!(by_rule("ast.sql-built-by-hand", "typescript"));
        assert!(by_rule("ast.sql-built-by-hand", "python"));
        assert!(!by_rule("ast.shell-command", "shell"));
        assert!(!by_rule("ast.weak-password-key-derivation", "python"));
    }

    #[test]
    fn every_query_in_the_data_file_compiles() {
        // A query tree-sitter cannot compile is a rule that silently never fires, which looks exactly
        // like a rule finding nothing. Queries compile on first use, so loading proves nothing about
        // them; this compiles every one, in every language, so a rule written wrong fails here and
        // not on the first app in that language.
        let rules = rules();
        assert!(rules.len() >= 4, "only {} rules loaded", rules.len());
        assert!(rules.languages().contains("python"));
        rules.compile_all().expect("every query compiles");
    }

    #[test]
    fn a_query_that_will_not_compile_stops_the_rule_claiming_a_clean_result() {
        // Loading accepts it, because compiling happens on first use. Meeting a Python file then
        // names the rule as one that could not run, and the clean-result gate stays shut.
        let rules = rules_from(ONE_RULE).expect("loads: nothing checks the query text at load");
        assert!(rules.compile_all().is_err());
        let read = read_file(&rules, "python", "src/app.py", "x = 1\n");
        assert_eq!(read.broken.len(), 1, "{:?}", read.broken);
        assert_eq!(read.broken[0].rule_id, "test.rule");
        assert_eq!(read.broken[0].language, "python");
        assert!(read.findings.is_empty());

        let dir = std::env::temp_dir().join(format!("sv-ast-broken-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.py"), "x = 1\n").unwrap();
        std::fs::write(dir.join("b.py"), "y = 2\n").unwrap();
        let scan = scan_dir(&rules, &dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(scan.files_parsed, 2);
        assert_eq!(
            scan.broken_queries.len(),
            1,
            "named once, not once per file"
        );
        assert!(scan.verified.is_empty(), "{:?}", scan.verified);
    }

    /// Writes a rule file to a scratch path so load-time refusals can be exercised.
    fn rules_from(json: &str) -> anyhow::Result<AstRules> {
        let dir = std::env::temp_dir().join(format!("sv-ast-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("rules-{}.json", json.len()));
        std::fs::write(&path, json).unwrap();
        let loaded = AstRules::load(&path);
        std::fs::remove_file(&path).ok();
        loaded
    }

    const ONE_RULE: &str = r#"{"rules":[{
        "id":"test.rule","title":"t","severity":"high","confidence":"high",
        "requirementIds":[],"cwe":[],"description":"d","impact":"i","fix":"f",
        "queries":{"python":"QUERY"}}]}"#;

    #[test]
    fn a_query_using_a_text_predicate_is_refused_at_load() {
        // The predicate that started this: tree-sitter's Rust binding parses `#match?` and then does
        // not apply it, so a rule written with one matches every call in the file while looking exactly
        // right. Every rule here did that, and the tests caught it only because they asserted what was
        // NOT a finding. Refusing the query is what stops it coming back.
        let refused = rules_from(&ONE_RULE.replace(
            "QUERY",
            "(call function: (identifier) @fn) @hit (#match? @fn \\\"^eval$\\\")",
        ));
        let error = match refused {
            Ok(_) => panic!("a text predicate must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("does not apply"), "{error}");
    }

    #[test]
    fn a_rule_naming_a_language_with_no_grammar_is_refused_at_load() {
        // Quietly dropping it would leave a rule that claims to cover a language and never runs.
        // Objective-C stands in for that here. This test has named Ruby, then C#, then C++, each until
        // the language got a grammar, which is the right way round for a test like this to break.
        let refused = rules_from(&ONE_RULE.replace("\"python\"", "\"objc\""));
        let error = match refused {
            Ok(_) => panic!("an unknown language must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("no grammar"), "{error}");
    }

    #[test]
    fn a_query_tree_sitter_cannot_compile_is_refused_by_compile_all() {
        let rules = rules_from(&ONE_RULE.replace("QUERY", "(this is not a query"))
            .expect("loading reads the text; compiling waits for a file in that language");
        let error = match rules.compile_all() {
            Ok(_) => panic!("a broken query must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("cannot compile"), "{error}");
        assert!(error.contains("test.rule"), "{error}");
    }

    fn one_rule(extra: &str) -> String {
        format!(
            r#"{{"rules": [{{"id": "t", "title": "t", "severity": "high", "confidence": "high",
                "requirementIds": ["V1.3.2"], "cwe": [], "description": "", "impact": "", "fix": "",
                "queries": {{"python": "(call) @hit"}} {extra} }}]}}"#
        )
    }

    #[test]
    fn nothing_to_find_is_refused_beside_a_query_without_a_reason_or_without_a_grammar() {
        let both = one_rule(r#", "nothingToFind": {"python": "Python has no such thing."}"#);
        let err = rules_from(&both).err().expect("refused").to_string();
        assert!(err.contains("also says there is nothing to find"), "{err}");

        let no_reason = one_rule(r#", "nothingToFind": {"go": "  "}"#);
        let err = rules_from(&no_reason).err().expect("refused").to_string();
        assert!(err.contains("without saying why"), "{err}");

        let no_grammar = one_rule(r#", "nothingToFind": {"objc": "Objective-C has none."}"#);
        let err = rules_from(&no_grammar).err().expect("refused").to_string();
        assert!(err.contains("no grammar"), "{err}");

        let fine = one_rule(r#", "nothingToFind": {"go": "Go has no eval."}"#);
        assert!(rules_from(&fine).is_ok());
    }

    #[test]
    fn a_pattern_for_a_language_the_rule_has_no_query_in_is_refused_at_load() {
        // It would never run, and the rule would read as if it had been taught that language.
        let refused = rules_from(
            &ONE_RULE
                .replace(
                    "\"queries\"",
                    "\"argumentPatterns\":{\"go\":\"md5\"},\"queries\"",
                )
                .replace("QUERY", "(call) @hit"),
        );
        let error = match refused {
            Ok(_) => panic!("a pattern with no query must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("no go query"), "{error}");
    }

    #[test]
    fn a_figure_for_a_named_hash_is_refused_where_the_rule_has_no_query_or_an_unusable_pattern() {
        let without_query = rules_from(&one_rule(
            r#", "argumentPatternsByHash": {"go": {"sha256": "^1$"}}"#,
        ));
        let error = format!("{:#}", without_query.err().expect("no go query"));
        assert!(error.contains("no go query"), "{error}");
        let unusable = rules_from(&one_rule(
            r#", "argumentPatternsByHash": {"python": {"sha256": "("}}"#,
        ));
        let error = format!("{:#}", unusable.err().expect("an unusable pattern"));
        assert!(error.contains("unusable argumentPatternsByHash"), "{error}");
        // And a usable one loads, so the two refusals above are about what they say.
        assert!(
            rules_from(&one_rule(
                r#", "argumentPatternsByHash": {"python": {"sha256": "^1$"}}"#
            ))
            .is_ok()
        );
    }

    #[test]
    fn python_eval_of_a_request_value_is_found() {
        let findings = scan(
            "python",
            "from flask import request\n\ndef run():\n    return eval(request.args['code'])\n",
        );
        assert!(
            ids(&findings).contains(&"ast.dynamic-code-execution"),
            "{findings:?}"
        );
        assert_eq!(findings[0].location.line, 4);
    }

    #[test]
    fn python_eval_of_a_literal_is_not_reported() {
        // `eval("1 + 1")` cannot be made to run anything the author did not write. Reporting it beside
        // a real one, at the same seriousness, is how a rule teaches people to skip its findings.
        let findings = scan("python", "x = eval('1 + 1')\n");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn javascript_eval_and_new_function_are_both_found() {
        let findings = scan(
            "javascript",
            "const f = new Function(req.body.src);\neval(req.query.x);\n",
        );
        assert_eq!(findings.len(), 2, "{findings:?}");
    }

    #[test]
    fn a_template_string_with_nothing_in_it_is_a_literal() {
        // The distinction the whole literal check turns on.
        let interpolated = scan(
            "javascript",
            "db.query(`SELECT * FROM t WHERE id = ${id}`);\n",
        );
        assert!(
            ids(&interpolated).contains(&"ast.sql-built-by-hand"),
            "{interpolated:?}"
        );
        let constant = scan("javascript", "db.query(`SELECT * FROM t`);\n");
        assert!(
            constant.is_empty(),
            "a constant query is not a finding: {constant:?}"
        );
    }

    #[test]
    fn python_sql_built_with_an_f_string_is_found() {
        let findings = scan(
            "python",
            "def get(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
        );
        assert!(
            ids(&findings).contains(&"ast.sql-built-by-hand"),
            "{findings:?}"
        );
    }

    #[test]
    fn python_sql_with_bound_parameters_is_not_a_finding() {
        // The correct way to do it must not be reported, or the rule is worse than nothing.
        let findings = scan(
            "python",
            "cur.execute('SELECT * FROM users WHERE name = ?', (name,))\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_shell_command_built_from_a_value_is_found() {
        let python = scan("python", "import os\nos.system('rm -rf ' + path)\n");
        assert!(ids(&python).contains(&"ast.shell-command"), "{python:?}");

        let js = scan(
            "javascript",
            "const { exec } = require('child_process');\nexec(`ls ${dir}`);\n",
        );
        assert!(ids(&js).contains(&"ast.shell-command"), "{js:?}");
    }

    #[test]
    fn a_fixed_shell_command_is_not_reported() {
        let findings = scan("python", "import os\nos.system('ls -la')\n");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn python_pickle_and_unsafe_yaml_are_found() {
        let findings = scan(
            "python",
            "import pickle, yaml\n\ndef load(blob, text):\n    a = pickle.loads(blob)\n    b = yaml.load(text)\n    return a, b\n",
        );
        assert!(
            ids(&findings).contains(&"ast.unsafe-deserialization"),
            "{findings:?}"
        );
        assert_eq!(findings.len(), 2, "both calls are findings: {findings:?}");
    }

    #[test]
    fn yaml_safe_load_is_not_reported() {
        let findings = scan("python", "import yaml\nd = yaml.safe_load(text)\n");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_comment_mentioning_a_dangerous_call_is_not_a_finding() {
        // The reason this parses rather than greps. A regex over the text reports both of these.
        let findings = scan("python", "# never use eval(user_input) here\nx = 1\n");
        assert!(findings.is_empty(), "{findings:?}");
        let in_string = scan("python", "message = 'do not call eval(x)'\n");
        assert!(in_string.is_empty(), "{in_string:?}");
    }

    #[test]
    fn a_call_split_over_several_lines_is_still_found() {
        // The other reason: a regex anchored to one line misses this, and reformatting an app should
        // not change whether it has a vulnerability.
        let findings = scan(
            "python",
            "cur.execute(\n    f\"SELECT * FROM t WHERE id = {user_id}\"\n)\n",
        );
        assert!(
            ids(&findings).contains(&"ast.sql-built-by-hand"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_language_with_no_grammar_yields_nothing_rather_than_pretending() {
        // Objective-C is read by `sv-scan` — it counts towards what an app is written in, through
        // `.m`/`.mm` — and has no grammar here, which is the combination that has to stay silent
        // rather than guess.
        assert!(scan_file(rules(), "objc", "app.m", "system(argv[1]);").is_empty());
        assert!(!is_supported("objc"));
        assert!(is_supported("python") && is_supported("typescript") && is_supported("cpp"));
    }

    #[test]
    fn the_three_new_grammars_read_their_own_languages() {
        // The point of adding them. Each snippet is the shape somebody would really write.
        for (language, file, source, expected) in [
            (
                "ruby",
                "app.rb",
                "db.execute(\"select * from t where n = \" + name)",
                "ast.sql-built-by-hand",
            ),
            (
                "ruby",
                "app.rb",
                "Marshal.load(params[:blob])",
                "ast.unsafe-deserialization",
            ),
            (
                "php",
                "app.php",
                "<?php $db->query(\"select * from t where n = \" . $name);",
                "ast.sql-built-by-hand",
            ),
            (
                "php",
                "app.php",
                "<?php unserialize($_GET[\"blob\"]);",
                "ast.unsafe-deserialization",
            ),
            (
                "java",
                "App.java",
                "class A { void f(String n) { stmt.executeQuery(\"select * from t where n = \" + n); } }",
                "ast.sql-built-by-hand",
            ),
            (
                "java",
                "App.java",
                "class A { void f() { new ObjectInputStream(in).readObject(); } }",
                "ast.unsafe-deserialization",
            ),
        ] {
            let findings = scan_file(rules(), language, file, source);
            assert!(
                ids(&findings).contains(&expected),
                "{language}: expected {expected}, got {:?}",
                ids(&findings)
            );
        }
    }

    #[test]
    fn ruby_backticks_are_a_shell_command_and_a_fixed_one_is_not_reported() {
        // The backtick form has no method name to match, so it is its own pattern. `ls` cannot be
        // made to run anything else; `ls #{dir}` can, and the literal check is what tells them
        // apart — the same rule the rest of this file runs on.
        let dangerous = scan_file(rules(), "ruby", "app.rb", "`ls #{params[:dir]}`");
        assert!(
            ids(&dangerous).contains(&"ast.shell-command-backticks"),
            "{dangerous:?}"
        );
        let fixed = scan_file(rules(), "ruby", "app.rb", "`ls -la`");
        assert!(
            !ids(&fixed).contains(&"ast.shell-command-backticks"),
            "a fixed command cannot be made to run anything else: {fixed:?}"
        );
    }

    #[test]
    fn what_comes_out_of_a_page_and_what_is_left_behind() {
        // One function answers both halves on purpose. When "does this page hold code" and "what
        // code does this page hold" are decided separately they drift, and the direction they
        // drift in is a page declared read whose code nobody extracted.
        let markup = html_fragments("<html><body><h1>Notes</h1></body></html>");
        assert!(markup.fragments.is_empty() && markup.left_behind.is_none());

        let external = html_fragments("<html><script src=\"app.js\"></script></html>");
        assert!(
            external.fragments.is_empty() && external.left_behind.is_none(),
            "the file it names is parsed like any other: {external:?}"
        );

        let whitespace = html_fragments("<html><script src=\"a.js\">\n  \n</script></html>");
        assert!(whitespace.fragments.is_empty() && whitespace.left_behind.is_none());

        let inline = html_fragments("<html><script>eval(x)</script></html>");
        assert_eq!(inline.fragments.len(), 1);
        assert_eq!(inline.fragments[0].language, "javascript");
        assert_eq!(inline.fragments[0].code, "eval(x)");
        assert!(inline.left_behind.is_none());

        let shouting = html_fragments("<html><SCRIPT>eval(x)</SCRIPT></html>");
        assert_eq!(
            shouting.fragments.len(),
            1,
            "tags match whatever their case"
        );
        assert_eq!(
            shouting.fragments[0].code, "eval(x)",
            "and the code comes out with its own case intact"
        );

        let typed = html_fragments("<script lang=\"ts\">const x: string = y</script>");
        assert_eq!(typed.fragments[0].language, "typescript");

        let handler = html_fragments("<button onclick=\"go(location.hash)\">go</button>");
        assert_eq!(handler.fragments.len(), 1);
        assert_eq!(handler.fragments[0].code, "go(location.hash)");

        let entities = html_fragments("<button onclick=\"go(&quot;a&quot; &amp; b)\">go</button>");
        assert_eq!(
            entities.fragments[0].code, "go(\"a\" & b)",
            "an entity can hide a quote, and must be put back before parsing"
        );

        let unclosed = html_fragments("<html><script>eval(x)");
        assert!(
            unclosed.left_behind.is_some(),
            "a script with no end cannot be bounded, so the page stays unread"
        );

        let url = html_fragments("<a href=\"javascript:go()\">go</a>");
        assert_eq!(url.fragments.len(), 1, "{url:?}");
        assert_eq!(url.fragments[0].code, "go()");
        assert!(url.left_behind.is_none());

        let shouting_url = html_fragments("<a href=\"JavaScript: go()\">go</a>");
        assert_eq!(
            shouting_url.fragments[0].code, " go()",
            "the scheme is matched whatever its case, and a browser skips the space"
        );

        let escaped_url = html_fragments("<a href=\"javascript:go(%22x%22)\">go</a>");
        assert_eq!(
            escaped_url.fragments[0].code, "go(\"x\")",
            "a percent escape has to come back before the grammar sees it"
        );

        let unquoted = html_fragments("<a href=javascript:go()>go</a>");
        assert_eq!(
            unquoted.fragments[0].code, "go()",
            "an unquoted value ends at the end of the tag: {unquoted:?}"
        );

        let split_scheme = html_fragments("<a href=\"java\tscript:go()\">go</a>");
        assert_eq!(
            split_scheme.fragments[0].code, "go()",
            "a browser removes the tab before it reads the scheme, and so does this: {split_scheme:?}"
        );

        let not_code = html_fragments(
            "<script type=\"text/x-template\">{{#each i}}<li>{{this}}</li>{{/each}}</script>",
        );
        assert!(
            not_code.left_behind.is_some(),
            "a fragment the grammar cannot read reports nothing, which must not read as clean: \
             {not_code:?}"
        );

        // And the limit of that, measured rather than assumed: the JavaScript grammar includes JSX,
        // so a Vue template parses cleanly and is not refused. It reaches the rules as markup.
        let jsx_shaped =
            html_fragments("<script type=\"text/x-template\"><div v-if=\"a\">x</div></script>");
        assert!(jsx_shaped.left_behind.is_none(), "{jsx_shaped:?}");

        let two = html_fragments("<script src=\"a.js\"></script><script>eval(x)</script>");
        assert_eq!(
            two.fragments.len(),
            1,
            "the second one is the one with code"
        );
    }

    #[test]
    fn a_page_is_read_the_way_a_browser_reads_it() {
        // Each of these runs in a browser. Before this reading, the first four were a page counted
        // as read with nothing taken out of it: a false clean.
        for (page, code) in [
            (
                "<button onclick=eval(location.hash)>x</button>",
                "eval(location.hash)",
            ),
            (
                "<img/onerror=\"eval(location.hash)\" src=x>",
                "eval(location.hash)",
            ),
            (
                "<a href=\"java&#9;script:eval(location.hash)\">go</a>",
                "eval(location.hash)",
            ),
            ("<a href=\"java&Tab;script:go()\">go</a>", "go()"),
            ("<a href=\"&#x6A;avascript&colon;go()\">go</a>", "go()"),
            ("<a href=\"&#106avascript:go()\">go</a>", "go()"),
            ("<a href=\"\u{1} javascript:go()\">go</a>", "go()"),
            ("<a href=\"javascript:go(\n)\">go</a>", "go()"),
            ("<body onload=init()>", "init()"),
            ("<a href='javascript:go()'>go</a>", "go()"),
            ("<a href = javascript:go()>go</a>", "go()"),
            ("<a title=\"x>y\" onclick=\"go()\">go</a>", "go()"),
            ("<script data-note=\"a>b\">go()</script>", "go()"),
        ] {
            let scan = html_fragments(page);
            assert!(scan.left_behind.is_none(), "{page:?} is read: {scan:?}");
            let codes: Vec<&str> = scan.fragments.iter().map(|f| f.code.as_str()).collect();
            assert_eq!(codes, vec![code], "{page:?}");
        }

        // Where an unquoted value ends is not a guess: at whitespace, and what follows is the next
        // attribute. `b` is a name with no value, not the rest of the program.
        let split = html_fragments("<a href=javascript:a b>go</a>");
        assert_eq!(split.fragments.len(), 1, "{split:?}");
        assert_eq!(split.fragments[0].code, "a");

        // And the other side: things that look like code and are not.
        for page in [
            "<a title=\"use javascript: sparingly\">x</a>",
            "<textarea><a onclick=go(1 2)></textarea>",
            "<title><a onclick=go(1 2)></title>",
            "<script>location = \"javascript:void(0)\"</script>",
        ] {
            let scan = html_fragments(page);
            assert!(scan.left_behind.is_none(), "{page:?}: {scan:?}");
            assert!(
                scan.fragments.iter().all(|f| f.code != "go(1 2)"),
                "{page:?} holds no code a browser runs: {scan:?}"
            );
        }

        // What still keeps a page unread, each for its own reason.
        for (page, why) in [
            ("<p>try javascript:go() in the bar</p>", "text"),
            ("<!-- <a href=javascript:go()> -->", "a comment"),
            (
                "<a href=\"java\u{1}script:go()\">go</a>",
                "a control character in the scheme",
            ),
            (
                "<a onclick=\"&alpha;()\">go</a>",
                "a reference this does not decode",
            ),
            // The one above is also refused by the grammar, so on its own it does not show the
            // reference check does anything. This one parses with the reference left as written —
            // `x & alpha; (1)` — while a browser runs `xα(1)`, a different program.
            (
                "<a onclick=\"x&alpha;(1)\">go</a>",
                "a reference this does not decode, in code that parses without it",
            ),
            ("<a href=\"javascript:go()>go</a>", "a quote never closed"),
            ("<a href=javascript:go()", "a tag never closed"),
            ("<script>go()</scripts>", "a script never closed"),
        ] {
            let scan = html_fragments(page);
            assert!(scan.left_behind.is_some(), "{why}: {page:?} {scan:?}");
        }
    }

    #[test]
    fn an_unquoted_handler_reaches_the_rules() {
        // The whole chain, not only the extraction: the page this was written for is the one where
        // a handler with no quotes was a page declared read and clean.
        let page =
            "<html>\n<body>\n<button onclick=eval(location.hash)>go</button>\n</body>\n</html>\n";
        let extracted = html_fragments(page);
        assert!(extracted.left_behind.is_none(), "{extracted:?}");
        let fragment = &extracted.fragments[0];
        let findings = scan_file(rules(), fragment.language, "index.html", &fragment.code);
        assert_eq!(ids(&findings), vec!["ast.dynamic-code-execution"]);
        assert_eq!(findings[0].location.line + fragment.line_offset, 3);
    }

    #[test]
    fn a_finding_in_a_page_names_the_line_in_the_page() {
        // A reader sent to line 3 of a fragment they cannot see is worse off than one given
        // nothing at all.
        let page = "<html>\n<body>\n<h1>Notes</h1>\n<script>\neval(location.hash)\n</script>\n</body>\n</html>\n";
        let extracted = html_fragments(page);
        assert_eq!(extracted.fragments.len(), 1);
        let fragment = &extracted.fragments[0];
        let findings = scan_file(rules(), fragment.language, "index.html", &fragment.code);
        assert_eq!(ids(&findings), vec!["ast.dynamic-code-execution"]);
        assert_eq!(
            findings[0].location.line + fragment.line_offset,
            5,
            "`eval` is on line 5 of the page"
        );
    }

    #[test]
    fn the_four_newest_grammars_read_their_own_languages() {
        for (language, file, source, expected) in [
            (
                "csharp",
                "App.cs",
                "class A { void F(string n) { cmd.ExecuteReader(\"select * from t where n = \" + n); } }",
                "ast.sql-built-by-hand",
            ),
            (
                "csharp",
                "App.cs",
                "class A { void F() { BinaryFormatter.Deserialize(stream); } }",
                "ast.unsafe-deserialization",
            ),
            (
                "kotlin",
                "App.kt",
                "fun f(n: String) { db.rawQuery(\"select * from t where n = \" + n, null) }",
                "ast.sql-built-by-hand",
            ),
            (
                "rust",
                "app.rs",
                "fn f(n: &str) { conn.execute(&format!(\"select * from t where n = {n}\"), []); }",
                "ast.sql-built-by-hand",
            ),
            (
                "c",
                "app.c",
                "void f(char *d) { char b[99]; sprintf(b, \"ls %s\", d); system(b); }",
                "ast.shell-command",
            ),
            (
                "cpp",
                "app.cpp",
                "void f(const std::string &d) { std::string cmd = \"ls \" + d; system(cmd.c_str()); }",
                "ast.shell-command",
            ),
            (
                "cpp",
                "app.cpp",
                "void f(sqlite3 *db, const std::string &name) { std::string q = \"select * from t where n = '\" + name + \"'\"; sqlite3_exec(db, q.c_str(), nullptr, nullptr, nullptr); }",
                "ast.sql-built-by-hand",
            ),
        ] {
            let findings = scan_file(rules(), language, file, source);
            assert!(
                ids(&findings).contains(&expected),
                "{language}: expected {expected}, got {:?}",
                ids(&findings)
            );
        }
    }

    #[test]
    fn a_kotlin_string_template_is_not_a_literal_but_an_escaped_dollar_is() {
        // Kotlin's grammar gives an interpolated string no node of its own: `"select $n"` is three
        // plain `string_content` children with the `$` standing alone as one of them, and that last
        // part is the whole discriminator. Measured rather than guessed: counting the children
        // instead would report an escaped `\$`, which leaves two of them either side of an
        // `escape_sequence`.
        let built = scan_file(
            rules(),
            "kotlin",
            "App.kt",
            "fun f(n: String) { db.execSQL(\"select * from t where n = $n\") }",
        );
        assert!(
            ids(&built).contains(&"ast.sql-built-by-hand"),
            "a Kotlin template is a built string: {built:?}"
        );

        let escaped = scan_file(
            rules(),
            "kotlin",
            "App.kt",
            "fun f() { db.execSQL(\"select * from prices where label = 'cost \\$5'\") }",
        );
        assert!(
            !ids(&escaped).contains(&"ast.sql-built-by-hand"),
            "an escaped dollar is written out, not substituted: {escaped:?}"
        );

        let plain = scan_file(
            rules(),
            "kotlin",
            "App.kt",
            "fun f() { db.execSQL(\"select 1\") }",
        );
        assert!(!ids(&plain).contains(&"ast.sql-built-by-hand"), "{plain:?}");
    }

    #[test]
    fn a_csharp_json_deserialise_is_not_reported() {
        // `Deserialize` is what every JSON library is called with. Only the receiver makes it the
        // dangerous one, and reporting the safe case would teach somebody to skip the rule.
        let safe = scan_file(
            rules(),
            "csharp",
            "App.cs",
            "class A { void F() { JsonSerializer.Deserialize(body); } }",
        );
        assert!(
            !ids(&safe).contains(&"ast.unsafe-deserialization"),
            "{safe:?}"
        );
    }

    #[test]
    fn a_php_string_that_interpolates_a_variable_is_not_a_literal() {
        // PHP puts a bare `$name` inside a double-quoted string with no wrapper node, so the string
        // looks exactly like a written-out one to a check that only knows about `${…}` and `#{…}`.
        // Missing this reports every PHP query built the most natural way as a constant, which is
        // the case the rule exists for.
        let built = scan_file(
            rules(),
            "php",
            "app.php",
            "<?php $db->query(\"select * from t where n = $name\");",
        );
        assert!(
            ids(&built).contains(&"ast.sql-built-by-hand"),
            "an interpolated PHP string is a built string: {built:?}"
        );
        let fixed = scan_file(
            rules(),
            "php",
            "app.php",
            "<?php $db->query(\"select * from t where n = ?\");",
        );
        assert!(
            !ids(&fixed).contains(&"ast.sql-built-by-hand"),
            "a written-out query is not a finding: {fixed:?}"
        );
    }

    #[test]
    fn the_usual_query_calls_of_each_language_are_read_and_their_safe_forms_are_not_reported() {
        // H1 of the deep review: nine real injections through the libraries people use gave no
        // finding, while V1.2.4 was marked checked. Each is here, with the same call written safely.
        let sql = "ast.sql-built-by-hand";
        let cases: &[(&str, &str, &str, bool)] = &[
            // better-sqlite3 and node-sqlite3.
            (
                "javascript",
                "app.js",
                "function f(db, n) { return db.prepare(`SELECT * FROM t WHERE n = '${n}'`).all(); }",
                true,
            ),
            (
                "javascript",
                "app.js",
                "function f(db, n) { return db.prepare('SELECT * FROM t WHERE n = ?').all(n); }",
                false,
            ),
            (
                "javascript",
                "app.js",
                "function f(db, n) { db.all(\"SELECT * FROM t WHERE n = '\" + n + \"'\", cb); }",
                true,
            ),
            (
                "javascript",
                "app.js",
                "function f(db, n) { db.all('SELECT * FROM t WHERE n = ?', [n], cb); }",
                false,
            ),
            (
                "javascript",
                "app.js",
                "function f(db, id) { db.run(`DELETE FROM t WHERE id = ${id}`); }",
                true,
            ),
            (
                "javascript",
                "app.js",
                "function f(db, sql) { db.exec(sql); }",
                true,
            ),
            // Prisma's unsafe call, and its safe tagged template.
            (
                "typescript",
                "app.ts",
                "async function f(p: any, n: string) { return p.$queryRawUnsafe(`SELECT * FROM t WHERE n = '${n}'`); }",
                true,
            ),
            (
                "typescript",
                "app.ts",
                "async function f(p: any, n: string) { return p.$queryRaw`SELECT * FROM t WHERE n = ${n}`; }",
                false,
            ),
            // PHP: mysqli takes the connection first, and PDO's prepare.
            (
                "php",
                "app.php",
                "<?php function f($conn, $n) { return mysqli_query($conn, \"SELECT * FROM t WHERE n = '$n'\"); }",
                true,
            ),
            (
                "php",
                "app.php",
                "<?php function f($conn) { return mysqli_query($conn, \"SELECT * FROM t\"); }",
                false,
            ),
            (
                "php",
                "app.php",
                "<?php function f($pdo, $n) { return $pdo->prepare(\"SELECT * FROM t WHERE n = '\" . $n . \"'\"); }",
                true,
            ),
            (
                "php",
                "app.php",
                "<?php function f($pdo) { return $pdo->prepare(\"SELECT * FROM t WHERE n = ?\"); }",
                false,
            ),
            // Java: JDBC's prepareStatement and Spring's JdbcTemplate.
            (
                "java",
                "A.java",
                "class A { void f(Connection c, String n) throws Exception { c.prepareStatement(\"SELECT * FROM t WHERE n = '\" + n + \"'\"); } }",
                true,
            ),
            (
                "java",
                "A.java",
                "class A { void f(Connection c) throws Exception { c.prepareStatement(\"SELECT * FROM t WHERE n = ?\"); } }",
                false,
            ),
            (
                "java",
                "A.java",
                "class A { void f(JdbcTemplate j, String n) { j.queryForList(\"SELECT * FROM t WHERE n = '\" + n + \"'\"); } }",
                true,
            ),
            (
                "java",
                "A.java",
                "class A { void f(JdbcTemplate j, String n) { j.update(\"UPDATE t SET n = '\" + n + \"'\"); } }",
                true,
            ),
            (
                "java",
                "A.java",
                "class A { void f(Map<String, String> m, String k, String v) { m.update(k + v); } }",
                false,
            ),
            // C#: a command built with `new`, and Dapper.
            (
                "csharp",
                "A.cs",
                "class A { void F(SqlConnection c, string n) { var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = '\" + n + \"'\", c); } }",
                true,
            ),
            (
                "csharp",
                "A.cs",
                "class A { void F(SqlConnection c) { var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = @n\", c); } }",
                false,
            ),
            (
                "csharp",
                "A.cs",
                "class A { void F(IDbConnection c, string n) { c.Query<T>($\"SELECT * FROM t WHERE n = '{n}'\"); } }",
                true,
            ),
            (
                "csharp",
                "A.cs",
                "class A { void F(Runner r, string n) { r.Execute(n + \"!\"); } }",
                false,
            ),
            // Ruby: Active Record's `where` with interpolation, and with a placeholder or a hash.
            (
                "ruby",
                "app.rb",
                "def f(n)\n  User.where(\"name = '#{n}'\")\nend\n",
                true,
            ),
            (
                "ruby",
                "app.rb",
                "def f(n)\n  User.where(\"name = ?\", n)\nend\n",
                false,
            ),
            (
                "ruby",
                "app.rb",
                "def f(n)\n  User.where(name: n)\nend\n",
                false,
            ),
            // pandas.
            (
                "python",
                "app.py",
                "def f(con, n):\n    return pd.read_sql(f\"SELECT * FROM t WHERE n = '{n}'\", con)\n",
                true,
            ),
            (
                "python",
                "app.py",
                "def f(con, n):\n    return pd.read_sql(\"SELECT * FROM t WHERE n = ?\", con, params=(n,))\n",
                false,
            ),
            // The common names stay quiet when what they are given is not a query.
            (
                "javascript",
                "app.js",
                "function f(cache, key) { return cache.get(key); }",
                false,
            ),
            (
                "javascript",
                "app.js",
                "function f(re, s) { return re.exec(s); }",
                false,
            ),
            (
                "javascript",
                "app.js",
                "app.get('/notes', (req, res) => res.send('ok'));",
                false,
            ),
        ];
        let mut wrong = Vec::new();
        for (language, file, code, expected) in cases {
            assert!(
                parses_cleanly(language, code),
                "the fixture must parse, or a pass proves nothing: {code}"
            );
            let found = ids(&scan_file(rules(), language, file, code)).contains(&sql);
            if found != *expected {
                wrong.push(format!("{language}: expected {expected}: {code}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn next_js_and_modern_node_redirects_and_file_calls_are_read() {
        // H5 of the deep review: each of these went unreported while TypeScript was claimed checked.
        let redirect = "ast.open-redirect";
        let file = "ast.file-path-from-value";
        let cases: &[(&str, &str, &str, &str, bool)] = &[
            // Next.js's `redirect` from `next/navigation`, and `NextResponse.redirect`.
            (
                redirect,
                "typescript",
                "page.tsx",
                "export default function P({ searchParams }: any) { redirect(searchParams.next); }",
                true,
            ),
            (
                redirect,
                "typescript",
                "page.tsx",
                "export default function P() { redirect('/login'); }",
                false,
            ),
            (
                redirect,
                "typescript",
                "middleware.ts",
                "export function middleware(req: any) { return NextResponse.redirect(req.nextUrl.searchParams.get('to')); }",
                true,
            ),
            (
                redirect,
                "typescript",
                "middleware.ts",
                "export function middleware(req: any) { return NextResponse.redirect(new URL('/login', req.url)); }",
                false,
            ),
            (
                redirect,
                "typescript",
                "middleware.ts",
                "export function middleware(req: any) { return NextResponse.redirect(new URL('//evil.test', req.url)); }",
                true,
            ),
            // The browser's own way.
            (
                "ast.open-redirect",
                "javascript",
                "app.js",
                "const to = new URLSearchParams(location.search).get('to'); window.location = to;",
                true,
            ),
            (
                redirect,
                "javascript",
                "app.js",
                "function go(u) { window.location.href = u; }",
                true,
            ),
            (
                redirect,
                "javascript",
                "app.js",
                "function go(u) { location.href = u; }",
                true,
            ),
            (
                redirect,
                "javascript",
                "app.js",
                "function go(u) { location.assign(u); }",
                true,
            ),
            (
                redirect,
                "javascript",
                "app.js",
                "function go(u) { window.location.replace(u); }",
                true,
            ),
            (
                redirect,
                "javascript",
                "app.js",
                "window.location.href = '/home';",
                false,
            ),
            (
                redirect,
                "javascript",
                "app.js",
                "function f(s, a) { return s.replace(a, ''); }",
                false,
            ),
            (
                redirect,
                "javascript",
                "app.js",
                "function f(el, u) { el.href = u; }",
                false,
            ),
            // `fs/promises`, imported by name or reached through `fs.promises`.
            (
                file,
                "javascript",
                "app.mjs",
                "import { readFile } from 'fs/promises';\nexport async function f(req) { return readFile(req.query.name); }",
                true,
            ),
            (
                file,
                "typescript",
                "app.ts",
                "import { writeFile } from 'node:fs/promises';\nexport async function f(n: string) { await writeFile(n, 'x'); }",
                true,
            ),
            (
                file,
                "javascript",
                "app.js",
                "async function f(req) { return fs.promises.readFile(req.params.p); }",
                true,
            ),
            (
                file,
                "javascript",
                "app.mjs",
                "import { readFile } from 'fs/promises';\nexport async function f() { return readFile(path.join(__dirname, 'a.html')); }",
                false,
            ),
            (
                file,
                "javascript",
                "app.mjs",
                "import { readFile } from 'fs/promises';\nexport async function f() { return readFile('config.json'); }",
                false,
            ),
            (
                file,
                "javascript",
                "app.js",
                "function f(url) { return download(url); }",
                false,
            ),
        ];
        let mut wrong = Vec::new();
        for (rule, language, name, code, expected) in cases {
            let parses = parses_cleanly(
                if name.ends_with(".tsx") {
                    "tsx"
                } else {
                    language
                },
                code,
            );
            assert!(
                parses,
                "the fixture must parse, or a pass proves nothing: {code}"
            );
            let found = ids(&scan_file(rules(), language, name, code)).contains(rule);
            if found != *expected {
                wrong.push(format!("{rule}, expected {expected}: {code}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn a_ruby_load_on_something_that_is_not_a_deserialiser_is_not_reported() {
        // `load` is far too common a method name to report on its own. The receiver is what makes
        // it a deserialization, and over-reporting here would teach somebody to skip the rule.
        // A lower-case receiver is an `identifier`, which the query's own shape excludes.
        let findings = scan_file(rules(), "ruby", "app.rb", "config.load(path)");
        assert!(
            !ids(&findings).contains(&"ast.unsafe-deserialization"),
            "{findings:?}"
        );
        // A capitalized one is a `constant`, which the query does match — so only the receiver
        // pattern stops it. Without this case the pattern could be deleted and every test here
        // would still pass, because the one above was being excluded by the node kind instead.
        let other_constant = scan_file(rules(), "ruby", "app.rb", "Settings.load(path)");
        assert!(
            !ids(&other_constant).contains(&"ast.unsafe-deserialization"),
            "a constant that is not a deserializer must not be reported: {other_constant:?}"
        );
        let real = scan_file(rules(), "ruby", "app.rb", "YAML.load(untrusted)");
        assert!(
            ids(&real).contains(&"ast.unsafe-deserialization"),
            "{real:?}"
        );
    }

    /// One found case and one not-found case for every language each of these rules has a query in.
    ///
    /// Each `false` line is the correct way to do the same thing, or the idiom a careless rule would
    /// report — the negative half is what stops a query that matches every call from passing.
    #[rustfmt::skip]
    const WITNESSES: &[(&str, &str, &str, bool)] = &[
        // Paths.
        ("ast.file-path-from-value", "python", "open(os.path.join(UPLOADS, request.args['name']))", true),
        ("ast.file-path-from-value", "python", "open(os.path.join(UPLOADS, secure_filename(f.filename)))", false),
        ("ast.file-path-from-value", "python", "open(os.path.join(os.path.dirname(__file__), 'schema.sql'))", false),
        ("ast.file-path-from-value", "python", "return send_file(request.args['path'])", true),
        ("ast.file-path-from-value", "python", "open('config.toml')", false),
        ("ast.file-path-from-value", "javascript", "fs.readFileSync(req.query.file)", true),
        ("ast.file-path-from-value", "javascript", "res.sendFile(path.join(__dirname, 'public', 'index.html'))", false),
        ("ast.file-path-from-value", "javascript", "res.sendFile(path.join(__dirname, req.params.name))", true),
        ("ast.file-path-from-value", "typescript", "await fs.readFile(`uploads/${req.params.name}`)", true),
        ("ast.file-path-from-value", "typescript", "fs.readFileSync('package.json')", false),
        ("ast.file-path-from-value", "go", "f, err := os.Open(r.URL.Query().Get(\"f\"))", true),
        ("ast.file-path-from-value", "go", "f, err := os.Open(\"config.json\")", false),
        ("ast.file-path-from-value", "php", "<?php echo file_get_contents($_GET['page']);", true),
        ("ast.file-path-from-value", "php", "<?php echo file_get_contents('about.html');", false),
        ("ast.file-path-from-value", "ruby", "File.read(params[:name])", true),
        ("ast.file-path-from-value", "ruby", "File.read('config.yml')", false),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { new FileInputStream(n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f() { new FileInputStream(\"app.properties\"); } }", false),
        ("ast.file-path-from-value", "csharp", "class A { void F(string n) { var t = File.ReadAllText(n); } }", true),
        ("ast.file-path-from-value", "csharp", "class A { void F() { var t = File.ReadAllText(\"a.json\"); } }", false),
        // A bare constant is the app's own configuration, not a request value.
        ("ast.file-path-from-value", "python", "with open(CONFIG_PATH) as f: pass", false),
        ("ast.file-path-from-value", "javascript", "fs.readFileSync(CERT_FILE)", false),
        ("ast.file-path-from-value", "ruby", "File.read(SETTINGS_FILE)", false),
        ("ast.file-path-from-value", "php", "<?php $s = file_get_contents(SETTINGS_FILE);", false),
        ("ast.file-path-from-value", "python", "with open(CONFIG_PATH + name) as f: pass", true),
        // The same method name on something that is not the file system.
        ("ast.file-path-from-value", "javascript", "const entry = zip.readFile(req.query.name)", false),
        ("ast.file-path-from-value", "go", "conn, err := pool.Open(r.FormValue(\"db\"))", false),
        ("ast.file-path-from-value", "ruby", "log = Logger.new(path)", false),
        ("ast.file-path-from-value", "csharp", "class A { void F(string n) { var t = Cache.Open(n); } }", false),
        // Hashes.
        ("ast.weak-hash-function", "python", "digest = hashlib.md5(password.encode()).hexdigest()", true),
        ("ast.weak-hash-function", "python", "etag = hashlib.md5(body, usedforsecurity=False).hexdigest()", false),
        ("ast.weak-hash-function", "python", "digest = hashlib.sha256(data).hexdigest()", false),
        ("ast.weak-hash-function", "javascript", "crypto.createHash('md5').update(pw).digest('hex')", true),
        ("ast.weak-hash-function", "javascript", "crypto.createHash('sha256').update(pw).digest('hex')", false),
        ("ast.weak-hash-function", "typescript", "crypto.createHash(\"SHA1\").update(x)", true),
        ("ast.weak-hash-function", "typescript", "crypto.createHash(\"sha512\").update(x)", false),
        ("ast.weak-hash-function", "go", "sum := md5.Sum([]byte(pw))", true),
        ("ast.weak-hash-function", "go", "sum := sha256.Sum256([]byte(pw))", false),
        ("ast.weak-hash-function", "php", "<?php $h = md5($password);", true),
        ("ast.weak-hash-function", "php", "<?php $h = password_hash($password, PASSWORD_DEFAULT);", false),
        ("ast.weak-hash-function", "ruby", "Digest::MD5.hexdigest(password)", true),
        ("ast.weak-hash-function", "ruby", "Digest::SHA256.hexdigest(password)", false),
        ("ast.weak-hash-function", "java", "class A { void f() throws Exception { MessageDigest.getInstance(\"MD5\"); } }", true),
        ("ast.weak-hash-function", "java", "class A { void f() throws Exception { MessageDigest.getInstance(\"SHA-256\"); } }", false),
        ("ast.weak-hash-function", "csharp", "class A { void F() { using var h = MD5.Create(); } }", true),
        ("ast.weak-hash-function", "csharp", "class A { void F() { using var h = SHA256.Create(); } }", false),
        ("ast.weak-hash-function", "kotlin", "fun f() { val d = MessageDigest.getInstance(\"SHA-1\") }", true),
        ("ast.weak-hash-function", "kotlin", "fun f() { val d = MessageDigest.getInstance(\"SHA-256\") }", false),
        ("ast.weak-hash-function", "go", "h := sha256.New()", false),
        // Ciphers.
        ("ast.weak-cipher", "python", "cipher = AES.new(key, AES.MODE_ECB)", true),
        ("ast.weak-cipher", "python", "cipher = AES.new(key, AES.MODE_GCM)", false),
        ("ast.weak-cipher", "python", "c = Cipher(algorithms.AES(key), modes.ECB())", true),
        ("ast.weak-cipher", "python", "c = Cipher(algorithms.AES(key), modes.GCM(iv))", false),
        ("ast.weak-cipher", "javascript", "crypto.createCipheriv('aes-128-ecb', key, null)", true),
        ("ast.weak-cipher", "javascript", "crypto.createCipheriv('aes-256-gcm', key, iv)", false),
        ("ast.weak-cipher", "typescript", "crypto.createCipheriv(\"des-ede3-cbc\", key, iv)", true),
        ("ast.weak-cipher", "typescript", "crypto.createCipheriv(\"chacha20-poly1305\", key, iv)", false),
        ("ast.weak-cipher", "go", "block, err := des.NewTripleDESCipher(key)", true),
        ("ast.weak-cipher", "go", "block, err := aes.NewCipher(key)", false),
        ("ast.weak-cipher", "php", "<?php openssl_encrypt($data, 'aes-128-ecb', $key);", true),
        ("ast.weak-cipher", "php", "<?php openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);", false),
        ("ast.weak-cipher", "ruby", "c = OpenSSL::Cipher.new('des-ede3-cbc')", true),
        ("ast.weak-cipher", "ruby", "c = OpenSSL::Cipher.new('aes-256-gcm')", false),
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES\"); } }", true),
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES/GCM/NoPadding\"); } }", false),
        ("ast.weak-cipher", "csharp", "class A { void F(Aes a) { a.Mode = CipherMode.ECB; } }", true),
        ("ast.weak-cipher", "csharp", "class A { void F(Aes a) { a.Mode = CipherMode.CBC; } }", false),
        ("ast.weak-cipher", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\") }", true),
        ("ast.weak-cipher", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/GCM/NoPadding\") }", false),
        // Generating a key names the algorithm and no mode: "AES" here is not ECB.
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { KeyGenerator.getInstance(\"AES\"); } }", false),
        ("ast.weak-cipher", "kotlin", "fun f() { val k = KeyGenerator.getInstance(\"AES\") }", false),
        // Redirects.
        ("ast.open-redirect", "python", "return redirect(request.args.get('next'))", true),
        ("ast.open-redirect", "python", "return redirect(url_for('index'))", false),
        ("ast.open-redirect", "python", "return redirect('/login')", false),
        ("ast.open-redirect", "javascript", "res.redirect(req.query.returnTo)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/dashboard')", false),
        ("ast.open-redirect", "typescript", "res.redirect(req.body.next as string)", true),
        ("ast.open-redirect", "typescript", "res.redirect(`/items`)", false),
        ("ast.open-redirect", "go", "http.Redirect(w, r, r.URL.Query().Get(\"next\"), http.StatusFound)", true),
        ("ast.open-redirect", "go", "http.Redirect(w, r, \"/login\", http.StatusFound)", false),
        ("ast.open-redirect", "javascript", "router.redirect(from, to)", false),
        ("ast.open-redirect", "go", "cache.Redirect(w, r, next, 302)", false),
        ("ast.open-redirect", "php", "<?php header('Location: ' . $_GET['next']);", true),
        ("ast.open-redirect", "php", "<?php header('Content-Type: ' . $type);", false),
        ("ast.open-redirect", "ruby", "redirect_to params[:return_to]", true),
        ("ast.open-redirect", "ruby", "redirect_to root_path", false),
        ("ast.open-redirect", "java", "class A { void f(HttpServletResponse r, String u) throws Exception { r.sendRedirect(u); } }", true),
        ("ast.open-redirect", "java", "class A { void f(HttpServletResponse r) throws Exception { r.sendRedirect(\"/home\"); } }", false),
        ("ast.open-redirect", "csharp", "class C { IActionResult F(string returnUrl) { return Redirect(returnUrl); } }", true),
        ("ast.open-redirect", "csharp", "class C { IActionResult F() { return Redirect(Url.Action(\"Index\")); } }", false),
        // Dart and Swift, and the gaps the per-language rule showed in the others. Every rule has
        // both halves in both languages, or says there is nothing to find in it.
        ("ast.dynamic-code-execution", "dart", "void f(String u) { Isolate.spawnUri(Uri.parse(u), [], null); }", true),
        ("ast.dynamic-code-execution", "dart", "void f(String p) { Isolate.spawnUri(Uri.file(p), [], null); }", true),
        ("ast.dynamic-code-execution", "dart", "void f() { Isolate.spawnUri(Uri.parse('worker.dart'), [], null); }", false),
        ("ast.dynamic-code-execution", "dart", "void f() { Isolate.spawn(worker, null); }", false),
        ("ast.dynamic-code-execution", "swift", "func f(code: String) { ctx.evaluateScript(code) }", true),
        ("ast.dynamic-code-execution", "swift", "func f(s: String) { let e = NSExpression(format: s) }", true),
        ("ast.dynamic-code-execution", "swift", "func f() { ctx.evaluateScript(\"1 + 1\") }", false),
        ("ast.dynamic-code-execution", "swift", "func f(x: Int) { let e = NSExpression(format: \"%d + 1\", x) }", false),
        ("ast.dynamic-code-execution", "csharp", "class A { async void F(string c) { await CSharpScript.EvaluateAsync(c); } }", true),
        ("ast.dynamic-code-execution", "csharp", "class A { async void F() { await CSharpScript.EvaluateAsync(\"1 + 1\"); } }", false),
        ("ast.dynamic-code-execution", "kotlin", "fun f(code: String) { engine.eval(code) }", true),
        ("ast.dynamic-code-execution", "kotlin", "fun f() { engine.eval(\"1 + 1\") }", false),
        // A1 of the deep review: a name the file binds once to fixed text is that text. Quiet: a
        // module constant, the prompt test's SCHEMA and its table of fixed queries, a name bound once,
        // a chain of constants. Still reported: the name reassigned, built with `+=`, taken as a
        // parameter, used as a loop variable, a constant joined with a value, a table with a spread.
        ("ast.sql-built-by-hand", "python", "QUERY = \"SELECT * FROM notes WHERE user_id = ?\"\ndef f(db, uid):\n    db.execute(QUERY, (uid,))\n", false),
        ("ast.sql-built-by-hand", "python", "SCHEMA = \"\"\"CREATE TABLE notes (id INTEGER)\"\"\"\ndef f(db):\n    db.executescript(SCHEMA)\n", false),
        ("ast.sql-built-by-hand", "python", "SORT_ORDERS = {\"newest\": \"SELECT * FROM n ORDER BY t DESC\", \"oldest\": \"SELECT * FROM n ORDER BY t\"}\ndef f(db, key, uid):\n    sql = SORT_ORDERS.get(key, SORT_ORDERS[\"newest\"])\n    db.execute(sql, (uid,))\n", false),
        ("ast.sql-built-by-hand", "python", "def f(db, key):\n    sql = \"SELECT 1\"\n    db.execute(sql)\n", false),
        ("ast.sql-built-by-hand", "python", "BASE = \"SELECT * FROM n\"\nWHERE = BASE + \" WHERE id = ?\"\ndef f(db, i):\n    db.execute(WHERE, (i,))\n", false),
        ("ast.sql-built-by-hand", "python", "def f(db, name):\n    sql = \"SELECT 1\"\n    sql = \"SELECT * FROM t WHERE n = '\" + name + \"'\"\n    db.execute(sql)\n", true),
        ("ast.sql-built-by-hand", "python", "def f(db, name):\n    sql = \"SELECT * FROM t WHERE n = \"\n    sql += name\n    db.execute(sql)\n", true),
        ("ast.sql-built-by-hand", "python", "def f(db, sql):\n    db.execute(sql)\ndef g(db):\n    sql = \"SELECT 1\"\n", true),
        ("ast.sql-built-by-hand", "python", "def f(db, names):\n    for sql in names:\n        db.execute(sql)\nsql = \"SELECT 1\"\n", true),
        ("ast.sql-built-by-hand", "python", "QUERY = \"SELECT * FROM t WHERE n = \"\ndef f(db, request):\n    db.execute(QUERY + request.args[\"n\"])\n", true),
        ("ast.sql-built-by-hand", "python", "TABLE = {**OTHER, \"a\": \"SELECT 1\"}\ndef f(db, k):\n    db.execute(TABLE[k])\n", true),
        ("ast.sql-built-by-hand", "python", "SORT_ORDERS = {\"newest\": \"SELECT 1\"}\ndef f(db, key, request):\n    db.execute(SORT_ORDERS.get(key, request.args[\"sql\"]))\n", true),
        ("ast.sql-built-by-hand", "javascript", "const LIST = 'SELECT * FROM notes WHERE user_id = ?';\nfunction f(db, uid) { return db.query(LIST, [uid]); }", false),
        ("ast.sql-built-by-hand", "javascript", "let sql = 'SELECT 1';\nfunction f(db, x) { sql = sql + x; return db.query(sql); }", true),
        // Item 24 of the review of 1 to 4 October: a parameter written without brackets, or
        // unpacked from an object or a list, was not counted as a parameter, so a constant of the
        // same name made it look fixed.
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = sql => db.query(sql);", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = ({ sql }) => db.query(sql);", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = ({ q: sql }) => db.query(sql);", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nfunction f([sql]) { return db.query(sql); }", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nfunction f({ sql } = {}) { return db.query(sql); }", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = () => db.query(sql);", false),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = ({ q: other }) => db.query(sql);", false),
        ("ast.sql-built-by-hand", "go", "package main\nconst q = \"SELECT * FROM notes WHERE user_id = $1\"\nfunc f(ctx context.Context, db *sql.DB, uid int) { db.QueryContext(ctx, q, uid) }", false),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(ctx context.Context, db *sql.DB, name string) { db.QueryContext(ctx, \"SELECT * FROM t WHERE n = '\"+name+\"'\") }", true),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(db *sql.DB) { db.Query(\"SELECT 1\") }", false),
        // The review of 1 to 4 October, item 18: query calls these languages' code uses as often as
        // the ones the rule read.
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(ctx context.Context, db *sql.DB, n string) { db.QueryRowContext(ctx, \"SELECT * FROM t WHERE n = '\"+n+\"'\") }", true),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(db *sql.DB, n string) { db.Prepare(\"SELECT * FROM t WHERE n = '\"+n+\"'\") }", true),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(ctx context.Context, db *sql.DB, n string) { db.PrepareContext(ctx, \"SELECT * FROM t WHERE n = '\"+n+\"'\") }", true),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(ctx context.Context, db *sql.DB, n string) { db.QueryRowContext(ctx, \"SELECT * FROM t WHERE n = $1\", n) }", false),
        ("ast.sql-built-by-hand", "kotlin", "fun f(c: Connection, n: String) { val s = c.prepareStatement(\"SELECT * FROM t WHERE n = '\" + n + \"'\") }", true),
        ("ast.sql-built-by-hand", "kotlin", "fun f(c: Connection) { val s = c.prepareStatement(\"SELECT * FROM t WHERE n = ?\") }", false),
        ("ast.sql-built-by-hand", "csharp", "class A { void F(SqlCommand cmd, string n) { cmd.CommandText = \"SELECT * FROM t WHERE n = '\" + n + \"'\"; cmd.ExecuteReader(); } }", true),
        ("ast.sql-built-by-hand", "csharp", "class A { void F(string n) { var cmd = new SqlCommand { CommandText = \"SELECT * FROM t WHERE n = '\" + n + \"'\" }; } }", true),
        ("ast.sql-built-by-hand", "csharp", "class A { void F(SqlCommand cmd) { cmd.CommandText = \"SELECT * FROM t WHERE n = @n\"; cmd.ExecuteReader(); } }", false),
        ("ast.sql-built-by-hand", "csharp", "class A { void F(Label l, string n) { l.Text = \"Hello \" + n; } }", false),
        // Same-site paths: one slash and then an ordinary path character cannot leave the site.
        ("ast.open-redirect", "python", "return redirect(f\"/notes/{note_id}\")", false),
        ("ast.open-redirect", "python", "return redirect(\"/notes/\" + str(note_id))", false),
        // Item 19 of the review of 1 to 4 October: a destination was judged by how it starts, so a
        // choice whose first value is a path on the same site was taken for one, and so was a path
        // whose first character after the slash is a `%` that formatting fills in.
        ("ast.open-redirect", "python", "return redirect(\"/home\" if not nxt else nxt)", true),
        ("ast.open-redirect", "python", "return redirect(nxt or \"/home\")", true),
        ("ast.open-redirect", "python", "return redirect(\"/notes/\" + str(i) or nxt)", true),
        ("ast.open-redirect", "python", "return redirect(\"/home\" and nxt)", true),
        ("ast.open-redirect", "python", "return redirect((\"/home\" if ok else nxt))", true),
        ("ast.open-redirect", "python", "return redirect((\"/home\" if ok else \"/notes\"))", false),
        ("ast.open-redirect", "python", "return redirect((\"/home\" if ok else request.args[\"next\"]))", true),
        ("ast.open-redirect", "python", "return redirect(\"/%s\" % nxt)", true),
        ("ast.open-redirect", "python", "return redirect(\"/home\" if ok else \"/notes\")", false),
        ("ast.open-redirect", "python", "return redirect(\"/home\" if ok else url_for(\"index\"))", false),
        ("ast.open-redirect", "python", "return redirect(\"/notes/%d\" % note_id)", false),
        ("ast.open-redirect", "python", "return redirect(\"/caf%C3%A9/\" + slug)", false),
        ("ast.open-redirect", "javascript", "res.redirect(req.query.next ?? '/home')", true),
        ("ast.open-redirect", "javascript", "res.redirect(req.query.next || '/home')", true),
        ("ast.open-redirect", "javascript", "res.redirect('/home' && req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/notes/' + id || req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/notes/' + id ?? req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/notes/' + id || '/home')", false),
        ("ast.open-redirect", "javascript", "res.redirect(ok ? '/a' : req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect(ok ? '/a' : '/b/' + id)", false),
        ("ast.open-redirect", "python", "return redirect(\"/\" + next_url)", true),
        ("ast.open-redirect", "python", "return redirect(f\"/{next_url}\")", true),
        ("ast.open-redirect", "python", "return redirect(\"//\" + host)", true),
        ("ast.open-redirect", "javascript", "res.redirect(`/users/${id}`)", false),
        ("ast.open-redirect", "javascript", "res.redirect(`/${req.query.next}`)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/\\t/' + host)", true),
        // Python's subprocess handed a built command with shell=True, which `ast.shell-command`'s
        // names never reached (found testing the prompt library, 4 October 2026). Every function the
        // rule names, then the safe forms: a list and no shell, a fixed string, and shell=True with
        // the keyword it must be.
        ("ast.shell-command-shell-true", "python", "subprocess.run(f'notes-export \"{title}\" out.pdf', shell=True)", true),
        ("ast.shell-command-shell-true", "python", "subprocess.call('ls ' + folder, shell=True)", true),
        ("ast.shell-command-shell-true", "python", "subprocess.check_call(cmd, shell=True)", true),
        ("ast.shell-command-shell-true", "python", "out = subprocess.check_output('grep %s log' % word, shell=True)", true),
        ("ast.shell-command-shell-true", "python", "p = subprocess.Popen(command, shell=True, stdout=PIPE)", true),
        ("ast.shell-command-shell-true", "python", "run(f'convert {name}', check=True, shell=True)", true),
        ("ast.shell-command-shell-true", "python", "subprocess.run(['notes-export', title, 'out.pdf'])", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(['notes-export', title, 'out.pdf'], check=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(cmd, check=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run('ls -la', shell=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(cmd, shell=False)", false),
        ("ast.shell-command-shell-true", "python", "pool.map(cmd, shell=True)", false),
        ("ast.shell-command-shell-true", "javascript", "spawn(`recipe-pdf \"${title}\" out.pdf`, { shell: true })", true),
        ("ast.shell-command-shell-true", "javascript", "cp.execFile('recipe-pdf', [title, file], { shell: true }, done)", true),
        ("ast.shell-command-shell-true", "javascript", "child_process.spawnSync(cmd, { cwd: dir, shell: true })", true),
        ("ast.shell-command-shell-true", "javascript", "execFile('recipe-pdf', [title, file], done)", false),
        ("ast.shell-command-shell-true", "javascript", "spawn('ls -la', { shell: true })", false),
        // A fixed list of arguments is as fixed as a fixed string (the review of 1 to 4 October,
        // item 22): Python's grammar calls it a `list` or a `tuple`, JavaScript's an `array`.
        ("ast.shell-command-shell-true", "python", "subprocess.run(['ls', '-la'], shell=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(('ls', '-la'), shell=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(['ls', folder], shell=True)", true),
        ("ast.shell-command-shell-true", "javascript", "spawn('ls', ['-la'], { shell: true })", false),
        ("ast.shell-command-shell-true", "typescript", "spawn('ls', ['-la'], { shell: true })", false),
        ("ast.shell-command-shell-true", "javascript", "spawn('ls', ['-la', dir], { shell: true })", true),
        ("ast.shell-command-shell-true", "javascript", "spawn(cmd, { shell: false })", false),
        ("ast.shell-command-shell-true", "javascript", "spawn(cmd, { detached: true })", false),
        ("ast.shell-command-shell-true", "typescript", "spawn(`convert ${name}`, { shell: true })", true),
        ("ast.shell-command-shell-true", "typescript", "execFile('convert', [name], { timeout: 5000 })", false),
        ("ast.shell-command-shell-true", "dart", "void f(String dir) { Process.run('ls', [dir], runInShell: true); }", true),
        ("ast.shell-command-shell-true", "dart", "void f() { Process.run('ls', ['-la'], runInShell: true); }", false),
        ("ast.shell-command-shell-true", "dart", "void f(String dir) { Process.run('ls', [dir]); }", false),
        ("ast.shell-command-shell-true", "dart", "void f(String dir) { Process.run('ls', [dir], includeParentEnvironment: true); }", false),
        ("ast.shell-command", "dart", "void f(String cmd) { Process.run('sh', ['-c', cmd]); }", true),
        ("ast.shell-command", "dart", "void f(String dir) { Process.run(\"/bin/bash\", [\"-c\", \"ls $dir\"]); }", true),
        ("ast.shell-command", "dart", "void f(String exe) { Process.start(exe, []); }", true),
        ("ast.shell-command", "dart", "void f() { Process.run('sh', ['-c', 'ls -la']); }", false),
        ("ast.shell-command", "dart", "void f(String branch) { Process.run('git', ['log', branch]); }", false),
        ("ast.shell-command", "dart", "void f(String cmd) { Pool.run('sh', ['-c', cmd]); }", false),
        ("ast.shell-command", "dart", "void f() { Process.run('sh', <String>['-c', 'ls -la']); }", false),
        ("ast.shell-command", "dart", "void f() { Process.runSync('/bin/sh', <String>['-c', 'date']); }", false),
        ("ast.shell-command", "swift", "func f() { task.arguments = [\"-c\", \"ls \" + \"-la\"] }", false),
        ("ast.shell-command", "swift", "func f(cmd: String) { task.arguments = [\"-c\", cmd] }", true),
        ("ast.shell-command", "swift", "func f(cmd: String) { let p = Process.launchedProcess(launchPath: \"/bin/sh\", arguments: [\"-c\", cmd]) }", true),
        ("ast.shell-command", "swift", "func f(cmd: String) { system(cmd) }", true),
        ("ast.shell-command", "swift", "func f() { task.arguments = [\"-c\", \"ls -la\"] }", false),
        ("ast.shell-command", "swift", "func f(name: String) { task.arguments = [\"log\", name] }", false),
        ("ast.shell-command", "swift", "func f() { system(\"ls\") }", false),
        ("ast.shell-command", "go", "func f(c string) { exec.Command(\"sh\", \"-c\", c).Run() }", true),
        ("ast.shell-command", "go", "func f(ctx context.Context, c string) { exec.CommandContext(ctx, \"bash\", \"-c\", c).Run() }", true),
        ("ast.shell-command", "go", "func f(name string) { exec.Command(name).Run() }", true),
        ("ast.shell-command", "go", "func f() { exec.Command(\"sh\", \"-c\", \"ls -la\").Run() }", false),
        ("ast.shell-command", "go", "func f(b string) { exec.Command(\"git\", \"log\", b).Run() }", false),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery(\"select * from notes where name = '$n'\");", true),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery('select * from notes where name = ' + n);", true),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery('select * from notes where name = ?', [n]);", false),
        ("ast.sql-built-by-hand", "dart", "Future f(String t) => db.query(t, where: 'id = ?', whereArgs: [1]);", false),
        ("ast.sql-built-by-hand", "dart", "Future f() => db.rawQuery('select * ' + 'from notes');", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) { sqlite3_exec(db, \"delete from notes where name = '\\(n)'\", nil, nil, nil) }", true),
        ("ast.sql-built-by-hand", "swift", "func f(q: String) throws { try db.execute(sql: q) }", true),
        ("ast.sql-built-by-hand", "swift", "func f() { sqlite3_exec(db, \"create table notes (name text)\", nil, nil, nil) }", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) throws { try db.execute(literal: \"insert into notes values (\\(n))\") }", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) throws { try db.execute(sql: \"insert into notes values (?)\", arguments: [n]) }", false),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) { let o = NSKeyedUnarchiver.unarchiveObject(with: d) }", true),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) throws { let o = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(d) }", true),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) throws { let o = try NSKeyedUnarchiver.unarchivedObject(ofClass: Note.self, from: d) }", false),
        ("ast.unsafe-deserialization", "javascript", "const obj = serialize.unserialize(req.cookies.profile)", true),
        ("ast.unsafe-deserialization", "javascript", "const obj = JSON.parse(req.cookies.profile)", false),
        ("ast.unsafe-deserialization", "typescript", "const obj = unserialize(req.body.data as string)", true),
        ("ast.unsafe-deserialization", "typescript", "const obj = JSON.parse(req.body.data as string)", false),
        ("ast.shell-command-backticks", "php", "<?php $out = `ls {$_GET['dir']}`;", true),
        ("ast.shell-command-backticks", "php", "<?php $out = `cat $file`;", true),
        ("ast.shell-command-backticks", "php", "<?php $out = `ls -la`;", false),
        ("ast.shell-command-backticks", "php", "<?php echo `whoami`;", false),
        ("ast.file-path-from-value", "dart", "Future f(Request r) => File(r.url.queryParameters['f']!).readAsString();", true),
        ("ast.file-path-from-value", "dart", "Future f(String name) => File('uploads/$name').readAsString();", true),
        ("ast.file-path-from-value", "dart", "Future f() => File('config.json').readAsString();", false),
        ("ast.file-path-from-value", "swift", "func f(p: String) { let d = FileManager.default.contents(atPath: p) }", true),
        ("ast.file-path-from-value", "swift", "func f(p: String) throws { let s = try String(contentsOfFile: p) }", true),
        ("ast.file-path-from-value", "swift", "func f() throws { let s = try String(contentsOfFile: \"/etc/app.conf\") }", false),
        ("ast.file-path-from-value", "swift", "func f(n: Int) { let s = String(describing: n) }", false),
        ("ast.file-path-from-value", "swift", "func f() throws { let d = try Data(contentsOf: URL(fileURLWithPath: \"/etc/app.conf\")) }", false),
        ("ast.file-path-from-value", "kotlin", "fun f(name: String) { val t = File(name).readText() }", true),
        ("ast.file-path-from-value", "kotlin", "fun f() { val t = File(\"app.conf\").readText() }", false),
        ("ast.file-path-from-value", "rust", "fn f(p: &str) { let t = fs::read_to_string(p); }", true),
        ("ast.file-path-from-value", "rust", "fn f(p: String) { let t = File::open(&p); }", true),
        ("ast.file-path-from-value", "rust", "fn f() { let t = File::open(\"app.toml\"); }", false),
        ("ast.file-path-from-value", "rust", "fn f(p: &str) { let t = Path::new(p); }", false),
        ("ast.file-path-from-value", "rust", "fn f() { let t = File::open(env!(\"CARGO_MANIFEST_DIR\")); }", false),
        ("ast.file-path-from-value", "rust", "fn f() { let t = fs::read_to_string(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/data.json\")); }", false),
        ("ast.file-path-from-value", "rust", "fn f() { let t = File::open(std::env!(\"OUT_DIR\")); }", false),
        ("ast.file-path-from-value", "rust", "fn f(dir: &str) { let t = File::open(format!(\"{}/data.json\", dir)); }", true),
        ("ast.file-path-from-value", "c", "void f(const char *p) { FILE *fp = fopen(p, \"r\"); }", true),
        ("ast.file-path-from-value", "c", "void f(void) { FILE *fp = fopen(\"/etc/app.conf\", \"r\"); }", false),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &p) { FILE *fp = fopen(p.c_str(), \"r\"); }", true),
        ("ast.file-path-from-value", "cpp", "void f() { FILE *fp = fopen(\"/etc/app.conf\", \"r\"); }", false),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => md5.convert(b).toString();", true),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => sha1.convert(b).toString();", true),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => sha256.convert(b).toString();", false),
        ("ast.weak-hash-function", "swift", "func f(d: Data) { let h = Insecure.MD5.hash(data: d) }", true),
        ("ast.weak-hash-function", "swift", "func f(p: UnsafeRawPointer, n: CC_LONG) { CC_SHA1(p, n, &out) }", true),
        ("ast.weak-hash-function", "swift", "func f(d: Data) { let h = SHA256.hash(data: d) }", false),
        ("ast.weak-hash-function", "swift", "func f(p: UnsafeRawPointer, n: CC_LONG) { CC_SHA256(p, n, &out) }", false),
        ("ast.weak-hash-function", "rust", "fn f(b: &[u8]) { let d = md5::compute(b); }", true),
        ("ast.weak-hash-function", "rust", "fn f() { let h = Sha1::new(); }", true),
        ("ast.weak-hash-function", "rust", "fn f() { let h = Sha256::new(); }", false),
        ("ast.weak-hash-function", "c", "void f(const unsigned char *d, size_t n, unsigned char *o) { MD5(d, n, o); }", true),
        ("ast.weak-hash-function", "c", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha1(), NULL); }", true),
        ("ast.weak-hash-function", "c", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha256(), NULL); }", false),
        ("ast.weak-hash-function", "cpp", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha1(), nullptr); }", true),
        ("ast.weak-hash-function", "cpp", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha256(), nullptr); }", false),
        ("ast.weak-cipher", "dart", "final e = Encrypter(AES(key, mode: AESMode.ecb));", true),
        ("ast.weak-cipher", "dart", "final c = ECBBlockCipher(AESEngine());", true),
        ("ast.weak-cipher", "dart", "final e = Encrypter(AES(key, mode: AESMode.gcm));", false),
        ("ast.weak-cipher", "swift", "func f() { let s = CCCrypt(op, CCAlgorithm(kCCAlgorithmDES), 0, k, n, nil, i, m, o, l, &w) }", true),
        ("ast.weak-cipher", "swift", "func f() throws { let a = try AES(key: k, blockMode: ECB()) }", true),
        ("ast.weak-cipher", "swift", "func f() throws { let b = try AES.GCM.seal(d, using: key) }", false),
        ("ast.weak-cipher", "swift", "func f() { let s = CCCrypt(op, CCAlgorithm(kCCAlgorithmAES), 0, k, n, iv, i, m, o, l, &w) }", false),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, k, NULL); }", true),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_des_ede3_cbc(), NULL, k, iv); }", true),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, iv); }", false),
        ("ast.weak-cipher", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), nullptr, k, nullptr); }", true),
        ("ast.weak-cipher", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, k, iv); }", false),
        ("ast.open-redirect", "dart", "Response f(Request r) => Response.found(r.url.queryParameters['next']!);", true),
        ("ast.open-redirect", "dart", "void f(HttpRequest r, String next) { r.response.redirect(Uri.parse(next)); }", true),
        ("ast.open-redirect", "dart", "Response f() => Response.found('/login');", false),
        ("ast.open-redirect", "dart", "void f(HttpRequest r) { r.response.redirect(Uri.parse('/home')); }", false),
        ("ast.open-redirect", "swift", "func f(req: Request, next: String) -> Response { return req.redirect(to: next) }", true),
        ("ast.open-redirect", "swift", "func f(req: Request) -> Response { return req.redirect(to: \"/login\") }", false),
        ("ast.open-redirect", "swift", "func f(req: Request, next: String) -> Response { return req.redirect(to: \"/r/\\(next)\") }", true),
        ("ast.open-redirect", "kotlin", "fun f(next: String) { call.respondRedirect(next) }", true),
        ("ast.open-redirect", "kotlin", "fun f() { call.respondRedirect(\"/login\") }", false),
        ("ast.open-redirect", "rust", "async fn f(q: Query<Next>) -> Redirect { Redirect::to(&q.next) }", true),
        ("ast.open-redirect", "rust", "async fn f() -> Redirect { Redirect::to(\"/login\") }", false),
        // Shell scripts.
        ("ast.dynamic-code-execution", "shell", "eval \"$1\"", true),
        ("ast.dynamic-code-execution", "shell", "eval \"set -- $ARGS\"", true),
        ("ast.dynamic-code-execution", "shell", "eval 'export PATH=/opt/bin:$PATH'", false),
        ("ast.dynamic-code-execution", "shell", "eval \"$(ssh-agent -s)\"", false),
        ("ast.shell-command", "shell", "sh -c \"ls $dir\"", true),
        ("ast.shell-command", "shell", "/bin/bash -c \"$1\"", true),
        ("ast.shell-command", "shell", "bash -c 'ls -la'", false),
        ("ast.shell-command", "shell", "sh -c \"echo \\$HOME\"", false),
        ("ast.shell-command", "shell", "ls -c \"$dir\"", false),
        // A bare word, a `${…}`, a `$(…)`, and quoting mixed within one argument.
        ("ast.shell-command", "shell", "bash -c date", false),
        ("ast.sql-built-by-hand", "shell", "psql -c VACUUM", false),
        ("ast.shell-command", "shell", "sh -c \"ls \"'-la'", false),
        ("ast.sql-built-by-hand", "shell", "psql -c 'select '\"count(*)\"' from notes'", false),
        ("ast.dynamic-code-execution", "shell", "eval \"${CMD}\"", true),
        ("ast.shell-command", "shell", "sh -c \"rm -rf ${dir}\"", true),
        ("ast.shell-command", "shell", "sh -c \"ls $(cat dirs.txt)\"", true),
        ("ast.dynamic-code-execution", "shell", "eval \"$(cat script.txt)\"", true),
        ("ast.sql-built-by-hand", "shell", "psql -c \"select * from notes where name = '$1'\"", true),
        ("ast.sql-built-by-hand", "shell", "sqlite3 app.db \"delete from notes where id = $ID\"", true),
        ("ast.sql-built-by-hand", "shell", "psql -c 'select count(*) from notes'", false),
        ("ast.sql-built-by-hand", "shell", "psql -h \"$HOST\" -d notes", false),
        ("ast.file-path-from-value", "shell", "cat \"/srv/files/$QUERY_STRING\"", true),
        ("ast.file-path-from-value", "shell", "rm -f /tmp/upload${PATH_INFO}", true),
        ("ast.file-path-from-value", "shell", "cat \"$CONFIG_FILE\"", false),
        ("ast.file-path-from-value", "shell", "echo \"$QUERY_STRING\"", false),
        ("ast.file-path-from-value", "shell", "file=\"${QUERY_STRING#name=}\"\ncat \"/srv/files/$file\"\n", true),
        ("ast.file-path-from-value", "shell", "serve() {\n  local name\n  name=$(printf '%s' \"$PATH_INFO\" | tr -d '.')\n  rm -f \"/tmp/uploads/$name\"\n}\n", true),
        ("ast.file-path-from-value", "shell", "parse() {\n  target=\"$QUERY_STRING\"\n}\nserve() {\n  cat \"$target\"\n}\n", true),
        ("ast.file-path-from-value", "shell", "file=\"$CONFIG_DIR/app.conf\"\ncat \"$file\"\n", false),
        ("ast.file-path-from-value", "shell", "name=\"$QUERY_STRING\"\necho \"$name\"\n", false),
        ("ast.file-path-from-value", "shell", "log=\"/var/log/QUERY_STRING.log\"\ncat \"$log\"\n", false),
        ("ast.weak-hash-function", "shell", "md5sum release.tar.gz", true),
        ("ast.weak-hash-function", "shell", "openssl dgst -sha1 release.tar.gz", true),
        ("ast.weak-hash-function", "shell", "sha256sum -c release.sha256", false),
        ("ast.weak-hash-function", "shell", "openssl dgst -sha256 release.tar.gz", false),
        ("ast.weak-cipher", "shell", "openssl enc -des3 -in secrets.txt -out secrets.enc", true),
        ("ast.weak-cipher", "shell", "openssl enc -aes-128-ecb -in a -out b", true),
        ("ast.weak-cipher", "shell", "openssl enc -aes-256-cbc -pbkdf2 -in a -out b", false),
        ("ast.open-redirect", "shell", "echo \"Location: $QUERY_STRING\"", true),
        ("ast.open-redirect", "shell", "printf 'Location: %s\\r\\n\\r\\n' \"$next\"", true),
        ("ast.open-redirect", "shell", "echo \"Location: /login\"", false),
        ("ast.open-redirect", "shell", "echo \"Content-Type: $type\"", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sh", true),
        ("ast.download-piped-to-shell", "shell", "wget -qO- https://example.com/install | sudo bash -s -- -y", true),
        ("ast.download-piped-to-shell", "shell", "bash <(curl -s https://example.com/setup.sh)", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://example.com/key.gpg | sudo tee /etc/apt/keyrings/example.gpg", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsSLo install.sh https://example.com/install.sh && sha256sum -c install.sha256 && sh install.sh", false),
        ("ast.download-piped-to-shell", "shell", "cat notes.txt | sh", false),
        // The interpreter runs the download only when it takes its program from standard input
        // (cato-pipeline's finding, 28 September 2026). These still run it:
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | bash", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sh -s", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | bash -x -s -- --yes", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sh -s stable", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | python3", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | python3 -", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | python3 -u", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | node -", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | perl", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sudo -E sh", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | /usr/bin/bash", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | FOO=1 bash", true),
        // And these read it as data, with the program given another way:
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | python3 -c 'import sys, json; print(json.load(sys.stdin)[\"id\"])'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | python3 -m json.tool", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | python3 parse.py", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | /usr/bin/python3 -I -c 'print(1)'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | sh -c 'wc -l'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | bash -ec 'wc -l'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | bash count.sh", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | perl -ne 'print if /id/'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | ruby -e 'puts STDIN.read.size'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | node -e 'process.stdin.pipe(process.stdout)'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | sudo python3 parse.py", false),
        // An interpreter's name as an argument to something else is not the interpreter.
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://example.com/langs.txt | grep -i python", false),
        // The last three a rule had not been taught.
        ("ast.shell-command", "rust", "fn f(c: &str) { Command::new(\"sh\").arg(\"-c\").arg(c).output(); }", true),
        ("ast.shell-command", "rust", "fn f(c: &str) { Command::new(\"/bin/bash\").args([\"-c\", c]).status(); }", true),
        ("ast.shell-command", "rust", "fn f(c: &str) { std::process::Command::new(\"sh\").args(&[\"-c\", c]).spawn(); }", true),
        ("ast.shell-command", "rust", "fn f(exe: &str) { Command::new(exe).spawn(); }", true),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"sh\").arg(\"-c\").arg(\"ls -la\").output(); }", false),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"sh\").args([\"-c\", \"ls -la\"]).output(); }", false),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"bash\").args(&[\"-c\", \"date\"]).output(); }", false),
        ("ast.shell-command", "rust", "fn f(b: &str) { Command::new(\"git\").arg(\"log\").arg(b).output(); }", false),
        ("ast.shell-command", "rust", "fn f(b: &str) { Command::new(\"git\").args([\"log\", b]).output(); }", false),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::des_ede3_cbc(); }", true),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::aes_128_ecb(); }", true),
        ("ast.weak-cipher", "rust", "fn f(k: &[u8]) { let c = TdesEde3::new_from_slice(k); }", true),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let e = ecb::Encryptor::<Aes128>::new(k); }", true),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::aes_256_gcm(); }", false),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let e = cbc::Encryptor::<Aes128>::new(k, iv); }", false),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let c = Aes256Gcm::new(k); }", false),
        ("ast.open-redirect", "c", "void f(const char *u) { printf(\"Location: %s\\r\\n\\r\\n\", u); }", true),
        ("ast.open-redirect", "c", "void f(const char *u) { fprintf(stdout, \"Location: %s\\n\\n\", u); }", true),
        ("ast.open-redirect", "c", "void f(void) { printf(\"Location: /login\\n\\n\"); }", false),
        ("ast.open-redirect", "c", "void f(void) { printf(\"Location: %s\\n\\n\", \"/login\"); }", false),
        ("ast.open-redirect", "c", "void f(const char *t) { printf(\"Content-Type: %s\\n\\n\", t); }", false),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { printf(\"Location: %s\\r\\n\\r\\n\", u.c_str()); }", true),
        ("ast.open-redirect", "cpp", "void f() { printf(\"Location: /login\\n\\n\"); }", false),
        ("ast.sql-built-by-hand", "c", "void f(sqlite3 *db, const char *q) { sqlite3_exec(db, q, 0, 0, 0); }", true),
        ("ast.sql-built-by-hand", "c", "void f(sqlite3 *db) { sqlite3_exec(db, \"SELECT 1\", 0, 0, 0); }", false),
        ("ast.sql-built-by-hand", "c", "void f(PGconn *c, const char *q) { PQexec(c, q); }", true),
        ("ast.sql-built-by-hand", "c", "void f(MYSQL *c) { mysql_query(c, \"SELECT 1\"); }", false),
        ("ast.shell-command", "cpp", "void f(const std::string &c) { std::system(c.c_str()); }", true),
        ("ast.shell-command", "cpp", "void f(const char *c) { ::system(c); }", true),
        ("ast.shell-command", "cpp", "void f() { std::system(\"ls -l\"); }", false),
        ("ast.shell-command", "cpp", "void f(const std::string &m) { Logger::system(m); }", false),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &p) { FILE *fp = std::fopen(p.c_str(), \"r\"); }", true),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &p) { std::remove(p.c_str()); }", true),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &p) { std::filesystem::remove(p); }", true),
        ("ast.file-path-from-value", "cpp", "void f(const char *p) { ::unlink(p); }", true),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &k) { Cache::remove(k); }", false),
        ("ast.sql-built-by-hand", "cpp", "void f(sqlite3 *db, const std::string &q) { ::sqlite3_exec(db, q.c_str(), nullptr, nullptr, nullptr); }", true),
        ("ast.sql-built-by-hand", "cpp", "void f(sqlite3 *db) { ::sqlite3_exec(db, \"SELECT 1\", nullptr, nullptr, nullptr); }", false),
        ("ast.weak-hash-function", "cpp", "void f(const unsigned char *d, size_t n, unsigned char *o) { ::MD5(d, n, o); }", true),
        ("ast.weak-hash-function", "cpp", "void f(const std::string &d) { Hasher::MD5(d); }", false),
        ("ast.weak-cipher", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, ::EVP_des_ede3_cbc(), nullptr, k, iv); }", true),
        ("ast.unauthenticated-encryption", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, ::EVP_aes_256_cbc(), nullptr, k, iv); }", true),
        ("ast.digest-compared-with-equals", "cpp", "bool f(const unsigned char *mac, const unsigned char *expected) { return std::memcmp(mac, expected, 32) == 0; }", true),
        ("ast.digest-compared-with-equals", "cpp", "bool f(const char *buf, const char *other) { return std::memcmp(buf, other, 8) == 0; }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f(const char *pw, const unsigned char *s, unsigned char *o) { ::PKCS5_PBKDF2_HMAC(pw, 8, s, 16, 1000, EVP_sha256(), 32, o); }", true),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { std::printf(\"Location: %s\\r\\n\\r\\n\", u.c_str()); }", true),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { std::cout << \"Location: \" << u << \"\\r\\n\\r\\n\"; }", true),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { cout << \"Location: \" << u; }", true),
        ("ast.open-redirect", "cpp", "void f() { std::cout << \"Location: /login\\r\\n\\r\\n\"; }", false),
        ("ast.open-redirect", "cpp", "void f() { std::cout << \"Location: \" << \"/login\"; }", false),
        ("ast.open-redirect", "cpp", "void f(const std::string &n) { std::cout << \"Hello: \" << n; }", false),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { std::cerr << \"Location: \" << u; }", false),
        // Two false alarms from the owner's first build (27 September 2026): a regular expression's
        // `exec` read as a shell command, and a test client's `.query({...})` read as SQL.
        ("ast.shell-command", "javascript", "const m = re.exec(code);", false),
        ("ast.shell-command", "javascript", "const m = /id=(\\d+)/.exec(line);", false),
        ("ast.shell-command", "javascript", "child_process.exec('ls ' + dir);", true),
        ("ast.shell-command", "javascript", "cp.execSync(`rm -rf ${target}`);", true),
        ("ast.shell-command", "javascript", "require('child_process').exec(cmd);", true),
        ("ast.shell-command", "javascript", "const { exec } = require('child_process'); exec(cmd);", true),
        ("ast.shell-command", "typescript", "const m: RegExpExecArray | null = pattern.exec(input);", false),
        ("ast.shell-command", "typescript", "childProcess.exec(`git log ${ref}`);", true),
        ("ast.sql-built-by-hand", "javascript", "await request(app).get('/').query({ q: term });", false),
        ("ast.sql-built-by-hand", "javascript", "db.query('SELECT * FROM t WHERE id = ' + id);", true),
        ("ast.sql-built-by-hand", "javascript", "await this.pool.query(`DELETE FROM notes WHERE id = ${id}`);", true),
        ("ast.sql-built-by-hand", "typescript", "await request(app).post('/search').query({ term });", false),
        ("ast.sql-built-by-hand", "typescript", "await db!.query(`SELECT * FROM t WHERE name = '${name}'`);", true),
        // Encryption that keeps data secret and cannot show it was changed (V11.3.3). ECB and the
        // retired ciphers are ast.weak-cipher's; these are the modes left once those are gone.
        ("ast.unauthenticated-encryption", "python", "cipher = AES.new(key, AES.MODE_CBC, iv)", true),
        ("ast.unauthenticated-encryption", "python", "c = Cipher(algorithms.AES(key), modes.CTR(nonce))", true),
        ("ast.unauthenticated-encryption", "python", "cipher = AES.new(key, AES.MODE_GCM)", false),
        ("ast.unauthenticated-encryption", "python", "c = Cipher(algorithms.AES(key), modes.GCM(iv))", false),
        ("ast.unauthenticated-encryption", "javascript", "crypto.createCipheriv('aes-256-cbc', key, iv)", true),
        ("ast.unauthenticated-encryption", "javascript", "crypto.createCipheriv('aes-256-gcm', key, iv)", false),
        ("ast.unauthenticated-encryption", "typescript", "crypto.createDecipheriv(\"aes-128-ctr\", key, iv)", true),
        ("ast.unauthenticated-encryption", "typescript", "crypto.createCipheriv(\"chacha20-poly1305\", key, iv)", false),
        ("ast.unauthenticated-encryption", "go", "mode := cipher.NewCBCEncrypter(block, iv)", true),
        ("ast.unauthenticated-encryption", "go", "stream := cipher.NewCTR(block, iv)", true),
        ("ast.unauthenticated-encryption", "go", "aead, err := cipher.NewGCM(block)", false),
        ("ast.unauthenticated-encryption", "php", "<?php openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);", true),
        ("ast.unauthenticated-encryption", "php", "<?php openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);", false),
        ("ast.unauthenticated-encryption", "ruby", "c = OpenSSL::Cipher.new('aes-256-cbc')", true),
        ("ast.unauthenticated-encryption", "ruby", "c = OpenSSL::Cipher.new('aes-256-gcm')", false),
        ("ast.unauthenticated-encryption", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES/CBC/PKCS5Padding\"); } }", true),
        ("ast.unauthenticated-encryption", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES/GCM/NoPadding\"); } }", false),
        ("ast.unauthenticated-encryption", "csharp", "class A { void F(Aes a) { a.Mode = CipherMode.CBC; } }", true),
        ("ast.unauthenticated-encryption", "csharp", "class A { void F(byte[] k) { var g = new AesGcm(k); } }", false),
        ("ast.unauthenticated-encryption", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/CTR/NoPadding\") }", true),
        ("ast.unauthenticated-encryption", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/GCM/NoPadding\") }", false),
        ("ast.unauthenticated-encryption", "dart", "final e = Encrypter(AES(key, mode: AESMode.cbc));", true),
        ("ast.unauthenticated-encryption", "dart", "final c = CBCBlockCipher(AESEngine());", true),
        ("ast.unauthenticated-encryption", "dart", "final e = Encrypter(AES(key, mode: AESMode.gcm));", false),
        ("ast.unauthenticated-encryption", "swift", "func f() throws { let a = try AES(key: k, blockMode: CBC(iv: iv)) }", true),
        ("ast.unauthenticated-encryption", "swift", "func f() throws { let b = try AES.GCM.seal(d, using: key) }", false),
        ("ast.unauthenticated-encryption", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, k, iv); }", true),
        ("ast.unauthenticated-encryption", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, iv); }", false),
        ("ast.unauthenticated-encryption", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), nullptr, k, iv); }", true),
        ("ast.unauthenticated-encryption", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, k, iv); }", false),
        ("ast.unauthenticated-encryption", "rust", "fn f() { let c = Cipher::aes_256_cbc(); }", true),
        ("ast.unauthenticated-encryption", "rust", "fn f(k: &Key) { let e = cbc::Encryptor::<Aes128>::new(k, iv); }", true),
        ("ast.unauthenticated-encryption", "rust", "fn f() { let c = Cipher::aes_256_gcm(); }", false),
        ("ast.unauthenticated-encryption", "rust", "fn f(k: &Key) { let c = Aes256Gcm::new(k); }", false),
        ("ast.unauthenticated-encryption", "shell", "openssl enc -aes-256-cbc -pbkdf2 -in a -out b", true),
        ("ast.unauthenticated-encryption", "shell", "openssl enc -aes-256-ctr -in a -out b", true),
        ("ast.unauthenticated-encryption", "shell", "openssl dgst -sha256 report.txt", false),
        // Four forms the path and redirect rules missed.
        ("ast.open-redirect", "javascript", "res.redirect(301, req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect(301, '/home')", false),
        ("ast.open-redirect", "typescript", "res.redirect(302, req.body.returnTo)", true),
        ("ast.open-redirect", "typescript", "res.redirect(302, \"/login\")", false),
        ("ast.file-path-from-value", "ruby", "send_file params[:path]", true),
        ("ast.file-path-from-value", "ruby", "send_file(params[:name], disposition: 'attachment')", true),
        ("ast.file-path-from-value", "ruby", "send_file 'public/terms.pdf'", false),
        ("ast.file-path-from-value", "ruby", "send_file Rails.root.join('public', 'report.pdf')", false),
        ("ast.file-path-from-value", "ruby", "send_message params[:text]", false),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { Path p = Paths.get(n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { Path p = Path.of(\"uploads\", n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f() { Path p = Path.of(\"uploads\", \"a.txt\"); } }", false),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { Path p = Path.of(n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f() { Path p = Paths.get(\"app.properties\"); } }", false),
        ("ast.file-path-from-value", "java", "class A { void f(java.util.Map<String, String> m, String n) { m.get(n); } }", false),
        ("ast.file-path-from-value", "php", "<?php include $_GET['page'];", true),
        ("ast.file-path-from-value", "php", "<?php require_once($page);", true),
        ("ast.file-path-from-value", "php", "<?php include 'header.php';", false),
        ("ast.file-path-from-value", "php", "<?php require_once __DIR__ . '/config.php';", false),
        ("ast.file-path-from-value", "php", "<?php require_once(dirname(__FILE__) . '/lib.php');", false),
        // The H5 follow-up: five differences from a second build of H5, ported onto its rules.
        // (a) `new URL("/path", base)` stays on the site only when the base is the request's own address.
        ("ast.open-redirect", "javascript", "return NextResponse.redirect(new URL('/login', req.query.next))", true),
        ("ast.open-redirect", "javascript", "return NextResponse.redirect(new URL('/login', request.url))", false),
        ("ast.open-redirect", "typescript", "return NextResponse.redirect(new URL('/account', searchParams.get('base')!))", true),
        ("ast.open-redirect", "typescript", "return NextResponse.redirect(new URL(\"/\", req.nextUrl))", false),
        ("ast.open-redirect", "typescript", "return NextResponse.redirect(new URL('/login', next))", true),
        // (b) The other frameworks' and the browser's redirects.
        ("ast.open-redirect", "javascript", "permanentRedirect(params.to)", true),
        ("ast.open-redirect", "javascript", "permanentRedirect('/new-home')", false),
        ("ast.open-redirect", "typescript", "permanentRedirect(params.to as string)", true),
        ("ast.open-redirect", "typescript", "permanentRedirect(`/posts/${post.id}`)", false),
        ("ast.open-redirect", "javascript", "return Response.redirect(url.searchParams.get('to'), 302)", true),
        ("ast.open-redirect", "javascript", "return Response.redirect('https://example.com/', 301)", false),
        ("ast.open-redirect", "typescript", "return Response.redirect(url.searchParams.get('to')!, 302)", true),
        ("ast.open-redirect", "typescript", "return Response.redirect('https://example.com/', 301)", false),
        ("ast.open-redirect", "javascript", "res.location(req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.location('/ok')", false),
        ("ast.open-redirect", "typescript", "res.location(req.query.next as string)", true),
        ("ast.open-redirect", "typescript", "res.location('/ok')", false),
        ("ast.open-redirect", "javascript", "document.location = params.get('next')", true),
        ("ast.open-redirect", "javascript", "document.location = '/home'", false),
        ("ast.open-redirect", "typescript", "top.location.href = next", true),
        ("ast.open-redirect", "typescript", "self.location.href = '/home'", false),
        ("ast.open-redirect", "javascript", "throw redirect(303, url.searchParams.get('redirectTo'))", true),
        ("ast.open-redirect", "javascript", "throw redirect(303, '/login')", false),
        ("ast.open-redirect", "typescript", "throw redirect(303, url.searchParams.get('redirectTo') ?? '/')", true),
        ("ast.open-redirect", "typescript", "throw redirect(303, '/login')", false),
        // (c) A string called `location` has a `replace` of its own; the browser's `location` on `window` is the redirect.
        ("ast.open-redirect", "javascript", "const slug = location.replace(/\\s+/g, '-')", false),
        ("ast.open-redirect", "javascript", "window.location.replace(next)", true),
        ("ast.open-redirect", "typescript", "const city = location.replace(old, fresh)", false),
        ("ast.open-redirect", "typescript", "document.location.replace(next)", true),
        ("ast.open-redirect", "javascript", "location.assign(next)", true),
        ("ast.open-redirect", "typescript", "location.assign('/')", false),
        // (d) The folder the app was started from, and the ES module's own folder, are the app's own.
        ("ast.file-path-from-value", "typescript", "const md = await readFile(path.join(process.cwd(), 'posts', params.slug + '.md'), 'utf8')", true),
        ("ast.file-path-from-value", "typescript", "const md = await readFile(path.join(process.cwd(), 'posts', 'about.md'), 'utf8')", false),
        ("ast.file-path-from-value", "javascript", "const t = await readFile(path.join(process.cwd(), req.query.name))", true),
        ("ast.file-path-from-value", "javascript", "const t = await readFile(path.join(process.cwd(), 'content', 'index.md'))", false),
        ("ast.file-path-from-value", "javascript", "createReadStream(path.join(import.meta.dirname, req.params.file)).pipe(res)", true),
        ("ast.file-path-from-value", "javascript", "createReadStream(path.join(import.meta.dirname, 'public', 'app.js')).pipe(res)", false),
        ("ast.file-path-from-value", "typescript", "const s = readFileSync(new URL(name, import.meta.url), 'utf8')", true),
        ("ast.file-path-from-value", "typescript", "const s = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8')", false),
        ("ast.file-path-from-value", "javascript", "const s = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8')", false),
        // WebSocket addresses written into the code.
        // Tokens and passwords written into the browser's storage (6 October 2026).
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('token', data.token);", true),
        ("ast.token-in-browser-storage", "javascript", "window.localStorage.setItem(\"accessToken\", res.access_token);", true),
        ("ast.token-in-browser-storage", "javascript", "sessionStorage.setItem(`refresh_token`, r);", true),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('auth', JSON.stringify(session));", true),
        ("ast.token-in-browser-storage", "javascript", "localStorage['jwt'] = jwt;", true),
        ("ast.token-in-browser-storage", "javascript", "localStorage.idToken = t;", true),
        ("ast.token-in-browser-storage", "javascript", "document.cookie = `token=${t}; path=/`;", true),
        ("ast.token-in-browser-storage", "javascript", "document.cookie = 'access=' + t;", true),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('theme', 'dark');", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('csrfToken', c);", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('fcmToken', pushToken);", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('tokenExpiresAt', String(exp));", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('author', name);", false),
        ("ast.token-in-browser-storage", "javascript", "const t = localStorage.getItem('token');", false),
        ("ast.token-in-browser-storage", "javascript", "cache.setItem('token', t);", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.removeItem('token');", false),
        ("ast.password-in-browser-storage", "javascript", "localStorage.setItem('password', form.password);", true),
        ("ast.password-in-browser-storage", "javascript", "sessionStorage.setItem(\"userPassword\", pw);", true),
        ("ast.password-in-browser-storage", "javascript", "localStorage.pwd = pw;", true),
        ("ast.password-in-browser-storage", "javascript", "sessionStorage['password'] = pw;", true),
        ("ast.password-in-browser-storage", "javascript", "document.cookie = 'password=' + pw;", true),
        ("ast.password-in-browser-storage", "javascript", "localStorage.setItem('showPassword', 'true');", false),
        ("ast.password-in-browser-storage", "javascript", "localStorage.setItem('passwordStrength', score);", false),
        ("ast.password-in-browser-storage", "javascript", "localStorage.setItem('rememberPassword', '1');", false),
        ("ast.password-in-browser-storage", "javascript", "const p = localStorage.getItem('password');", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('token', data.token);", true),
        ("ast.token-in-browser-storage", "typescript", "window.localStorage.setItem(\"accessToken\", res.access_token);", true),
        ("ast.token-in-browser-storage", "typescript", "sessionStorage.setItem(`refresh_token`, r);", true),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('auth', JSON.stringify(session));", true),
        ("ast.token-in-browser-storage", "typescript", "localStorage['jwt'] = jwt;", true),
        ("ast.token-in-browser-storage", "typescript", "localStorage.idToken = t;", true),
        ("ast.token-in-browser-storage", "typescript", "document.cookie = `token=${t}; path=/`;", true),
        ("ast.token-in-browser-storage", "typescript", "document.cookie = 'access=' + t;", true),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('theme', 'dark');", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('csrfToken', c);", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('fcmToken', pushToken);", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('tokenExpiresAt', String(exp));", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('author', name);", false),
        ("ast.token-in-browser-storage", "typescript", "const t = localStorage.getItem('token');", false),
        ("ast.token-in-browser-storage", "typescript", "cache.setItem('token', t);", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.removeItem('token');", false),
        ("ast.password-in-browser-storage", "typescript", "localStorage.setItem('password', form.password);", true),
        ("ast.password-in-browser-storage", "typescript", "sessionStorage.setItem(\"userPassword\", pw);", true),
        ("ast.password-in-browser-storage", "typescript", "localStorage.pwd = pw;", true),
        ("ast.password-in-browser-storage", "typescript", "sessionStorage['password'] = pw;", true),
        ("ast.password-in-browser-storage", "typescript", "document.cookie = 'password=' + pw;", true),
        ("ast.password-in-browser-storage", "typescript", "localStorage.setItem('showPassword', 'true');", false),
        ("ast.password-in-browser-storage", "typescript", "localStorage.setItem('passwordStrength', score);", false),
        ("ast.password-in-browser-storage", "typescript", "localStorage.setItem('rememberPassword', '1');", false),
        ("ast.password-in-browser-storage", "typescript", "const p = localStorage.getItem('password');", false),
        ("ast.plaintext-websocket-url", "python", "ws = create_connection(\"ws://chat.example.com/live\")", true),
        ("ast.plaintext-websocket-url", "python", "ws = create_connection(\"wss://chat.example.com/live\")", false),
        ("ast.plaintext-websocket-url", "python", "ws = create_connection('ws://localhost:8765')", false),
        ("ast.plaintext-websocket-url", "javascript", "const s = new WebSocket('ws://chat.example.com/socket')", true),
        ("ast.plaintext-websocket-url", "javascript", "const s = new WebSocket(`wss://${location.host}/socket`)", false),
        ("ast.plaintext-websocket-url", "javascript", "const s = new WebSocket(`ws://${host}/socket`)", false),
        ("ast.plaintext-websocket-url", "javascript", "const u = url.replace('ws://', 'wss://')", false),
        ("ast.plaintext-websocket-url", "javascript", "const s = new WebSocket('ws://127.0.0.1:3000')", false),
        ("ast.plaintext-websocket-url", "typescript", "const s: WebSocket = new WebSocket(\"ws://feed.example.org\")", true),
        ("ast.plaintext-websocket-url", "typescript", "const s: WebSocket = new WebSocket(\"wss://feed.example.org\")", false),
        ("ast.plaintext-websocket-url", "go", "c, _, err := websocket.DefaultDialer.Dial(\"ws://chat.example.com/ws\", nil)", true),
        ("ast.plaintext-websocket-url", "go", "c, _, err := websocket.DefaultDialer.Dial(\"wss://chat.example.com/ws\", nil)", false),
        ("ast.plaintext-websocket-url", "php", "<?php $c = new Client('ws://chat.example.com/socket');", true),
        ("ast.plaintext-websocket-url", "php", "<?php $c = new Client('wss://chat.example.com/socket');", false),
        ("ast.plaintext-websocket-url", "ruby", "ws = WebSocket::Client::Simple.connect 'ws://chat.example.com'", true),
        ("ast.plaintext-websocket-url", "ruby", "ws = WebSocket::Client::Simple.connect 'wss://chat.example.com'", false),
        ("ast.plaintext-websocket-url", "java", "class A { void f() throws Exception { new URI(\"ws://chat.example.com/ws\"); } }", true),
        ("ast.plaintext-websocket-url", "java", "class A { void f() throws Exception { new URI(\"wss://chat.example.com/ws\"); } }", false),
        ("ast.plaintext-websocket-url", "csharp", "class A { void F() { var u = new Uri(\"ws://chat.example.com/ws\"); } }", true),
        ("ast.plaintext-websocket-url", "csharp", "class A { void F() { var u = new Uri(\"wss://chat.example.com/ws\"); } }", false),
        ("ast.plaintext-websocket-url", "kotlin", "val request = Request.Builder().url(\"ws://chat.example.com/ws\").build()", true),
        ("ast.plaintext-websocket-url", "kotlin", "val request = Request.Builder().url(\"wss://chat.example.com/ws\").build()", false),
        ("ast.plaintext-websocket-url", "dart", "void f() { final c = WebSocketChannel.connect(Uri.parse('ws://chat.example.com/ws')); }", true),
        ("ast.plaintext-websocket-url", "dart", "void f() { final c = WebSocketChannel.connect(Uri.parse('wss://chat.example.com/ws')); }", false),
        ("ast.plaintext-websocket-url", "swift", "let url = URL(string: \"ws://chat.example.com/ws\")!", true),
        ("ast.plaintext-websocket-url", "swift", "let url = URL(string: \"wss://chat.example.com/ws\")!", false),
        ("ast.plaintext-websocket-url", "rust", "fn f() { let r = connect_async(\"ws://chat.example.com/ws\"); }", true),
        ("ast.plaintext-websocket-url", "rust", "fn f() { let r = connect_async(\"wss://chat.example.com/ws\"); }", false),
        ("ast.plaintext-websocket-url", "c", "void f(void) { lws_client_connect(\"ws://chat.example.com/ws\"); }", true),
        ("ast.plaintext-websocket-url", "c", "void f(void) { lws_client_connect(\"wss://chat.example.com/ws\"); }", false),
        ("ast.plaintext-websocket-url", "cpp", "void f() { lws_client_connect(\"ws://chat.example.com/ws\"); }", true),
        ("ast.plaintext-websocket-url", "cpp", "void f() { lws_client_connect(\"wss://chat.example.com/ws\"); }", false),
        ("ast.plaintext-websocket-url", "shell", "websocat ws://chat.example.com/ws", true),
        ("ast.plaintext-websocket-url", "shell", "websocat wss://chat.example.com/ws", false),
        ("ast.plaintext-websocket-url", "shell", "websocat ws://localhost:8080/ws", false),
        // Signatures compared with an ordinary equals.
        ("ast.digest-compared-with-equals", "python", "ok = hmac.new(k, body, hashlib.sha256).hexdigest() == sig", true),
        ("ast.digest-compared-with-equals", "python", "ok = sig != hmac.digest(k, body, 'sha256')", true),
        ("ast.digest-compared-with-equals", "python", "ok = hmac.compare_digest(hmac.new(k, body, hashlib.sha256).hexdigest(), sig)", false),
        ("ast.digest-compared-with-equals", "python", "ok = hashlib.sha256(body).hexdigest() == checksum", false),
        ("ast.digest-compared-with-equals", "javascript", "if (crypto.createHmac('sha256', k).update(b).digest('hex') === sig) { go(); }", true),
        ("ast.digest-compared-with-equals", "javascript", "if (sig !== createHmac('sha256', k).update(b).digest('hex')) { stop(); }", true),
        ("ast.digest-compared-with-equals", "javascript", "const ok = crypto.timingSafeEqual(crypto.createHmac('sha256', k).update(b).digest(), sig);", false),
        ("ast.digest-compared-with-equals", "javascript", "if (crypto.createHash('sha256').update(b).digest('hex') === sum) { go(); }", false),
        ("ast.digest-compared-with-equals", "typescript", "const ok: boolean = createHmac('sha256', k).update(b).digest('hex') == sig;", true),
        ("ast.digest-compared-with-equals", "typescript", "const ok: boolean = timingSafeEqual(createHmac('sha256', k).update(b).digest(), sig);", false),
        ("ast.digest-compared-with-equals", "php", "<?php if (hash_hmac('sha256', $body, $key) == $sig) { go(); }", true),
        ("ast.digest-compared-with-equals", "php", "<?php if (hash_equals(hash_hmac('sha256', $body, $key), $sig)) { go(); }", false),
        ("ast.digest-compared-with-equals", "ruby", "ok = OpenSSL::HMAC.hexdigest('SHA256', key, body) == sig", true),
        ("ast.digest-compared-with-equals", "ruby", "ok = Rack::Utils.secure_compare(OpenSSL::HMAC.hexdigest('SHA256', key, body), sig)", false),
        ("ast.digest-compared-with-equals", "go", "package m\nfunc f() bool { return bytes.Equal(mac.Sum(nil), sig) }", true),
        ("ast.digest-compared-with-equals", "go", "package m\nfunc f() bool { return hex.EncodeToString(mac.Sum(nil)) == sig }", true),
        ("ast.digest-compared-with-equals", "go", "package m\nfunc f() bool { return hmac.Equal(mac.Sum(nil), sig) }", false),
        ("ast.digest-compared-with-equals", "go", "package m\nfunc f() bool { return bytes.Equal(h.Sum(nil), want) }", false),
        ("ast.digest-compared-with-equals", "java", "class A { boolean f() { return Arrays.equals(mac.doFinal(body), sig); } }", true),
        ("ast.digest-compared-with-equals", "java", "class A { boolean f() { return Hex.encodeHexString(mac.doFinal(body)).equals(sig); } }", true),
        ("ast.digest-compared-with-equals", "java", "class A { boolean f() { return MessageDigest.isEqual(mac.doFinal(body), sig); } }", false),
        ("ast.digest-compared-with-equals", "kotlin", "fun f() = mac.doFinal(body).contentEquals(sig)", true),
        ("ast.digest-compared-with-equals", "kotlin", "fun f() = hex(mac.doFinal(body)) == sig", true),
        ("ast.digest-compared-with-equals", "kotlin", "fun f() = MessageDigest.isEqual(mac.doFinal(body), sig)", false),
        ("ast.digest-compared-with-equals", "csharp", "class A { bool F() { return hmac.ComputeHash(body).SequenceEqual(sig); } }", true),
        ("ast.digest-compared-with-equals", "csharp", "class A { bool F() { return Convert.ToHexString(HMACSHA256.HashData(key, body)) == sig; } }", true),
        ("ast.digest-compared-with-equals", "csharp", "class A { bool F() { return CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(body), sig); } }", false),
        ("ast.digest-compared-with-equals", "rust", "fn f() -> bool { mac.finalize().into_bytes().as_slice() == sig }", true),
        ("ast.digest-compared-with-equals", "rust", "fn f() -> bool { mac.verify_slice(sig).is_ok() }", false),
        ("ast.digest-compared-with-equals", "rust", "fn f() -> bool { hasher.finalize().as_slice() == want }", false),
        ("ast.digest-compared-with-equals", "c", "int f(void) { return memcmp(mac, sig, 32) == 0; }", true),
        ("ast.digest-compared-with-equals", "c", "int f(void) { return CRYPTO_memcmp(mac, sig, 32) == 0; }", false),
        ("ast.digest-compared-with-equals", "c", "int f(void) { return memcmp(buf, header, 4) == 0; }", false),
        ("ast.digest-compared-with-equals", "cpp", "bool f() { return memcmp(expected_mac, sig, 32) == 0; }", true),
        ("ast.digest-compared-with-equals", "cpp", "bool f() { return sodium_memcmp(expected_mac, sig, 32) == 0; }", false),
        ("ast.digest-compared-with-equals", "dart", "bool f() => Hmac(sha256, key).convert(body).toString() == sig;", true),
        ("ast.digest-compared-with-equals", "dart", "bool f() => sha256.convert(body).toString() == checksum;", false),
        ("ast.digest-compared-with-equals", "swift", "let ok = Data(HMAC<SHA256>.authenticationCode(for: body, using: key)) == sig", true),
        ("ast.digest-compared-with-equals", "swift", "let ok = HMAC<SHA256>.isValidAuthenticationCode(sig, authenticating: body, using: key)", false),
        // Model files loaded by a reader that can run code.
        ("ast.model-loaded-with-pickle", "python", "model = joblib.load('model.joblib')", true),
        ("ast.model-loaded-with-pickle", "python", "state = torch.load(path, weights_only=False)", true),
        ("ast.model-loaded-with-pickle", "python", "m = AutoModel.from_pretrained(name, trust_remote_code=True)", true),
        ("ast.model-loaded-with-pickle", "python", "state = torch.load(path, weights_only=True)", false),
        ("ast.model-loaded-with-pickle", "python", "settings = json.load(f)", false),
        // Models downloaded by name without a commit.
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained('bert-org/bert-base')", true),
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained('bert-org/bert-base', revision='main')", true),
        ("ast.model-download-not-pinned", "python", "p = hf_hub_download(repo_id='org/model', filename='w.safetensors')", true),
        ("ast.model-download-not-pinned", "python", "p = pipeline('text-generation', model='org/model')", true),
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained('bert-org/bert-base', revision='0123456789abcdef0123456789abcdef01234567')", false),
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained('./models/bert')", false),
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained(settings.model_dir)", false),
        ("ast.model-download-not-pinned", "javascript", "const p = await pipeline('sentiment-analysis', 'Xenova/distilbert');", true),
        ("ast.model-download-not-pinned", "javascript", "const p = await pipeline('sentiment-analysis', 'Xenova/distilbert', { revision: '0123456789abcdef0123456789abcdef01234567' });", false),
        ("ast.model-download-not-pinned", "typescript", "const p = await pipeline('sentiment-analysis', 'Xenova/distilbert');", true),
        ("ast.model-download-not-pinned", "typescript", "const p = await pipeline('sentiment-analysis', 'Xenova/distilbert', { revision: '0123456789abcdef0123456789abcdef01234567' });", false),
        // Hosted models asked for by a name that moves.
        ("ast.floating-model-name", "python", "r = client.messages.create(model='claude-3-5-sonnet-latest', messages=m)", true),
        ("ast.floating-model-name", "python", "r = client.messages.create(model='claude-sonnet-4-5-20250929', messages=m)", false),
        ("ast.floating-model-name", "python", "runner = 'ubuntu-latest'", false),
        ("ast.floating-model-name", "javascript", "const r = await openai.chat.completions.create({ model: 'chatgpt-4o-latest', messages });", true),
        ("ast.floating-model-name", "javascript", "const r = await openai.chat.completions.create({ model: 'gpt-4o-2024-08-06', messages });", false),
        ("ast.floating-model-name", "typescript", "const model: string = `gemini-flash-latest`;", true),
        ("ast.floating-model-name", "typescript", "const model: string = `gemini-2.5-flash`;", false),
        ("ast.floating-model-name", "go", "package m\nvar model = \"mistral-large-latest\"", true),
        ("ast.floating-model-name", "go", "package m\nvar model = \"mistral-large-2411\"", false),
        ("ast.floating-model-name", "ruby", "resp = client.chat(parameters: { model: \"llama3:latest\" })", true),
        ("ast.floating-model-name", "ruby", "resp = client.chat(parameters: { model: \"llama3:8b\" })", false),
        ("ast.floating-model-name", "php", "<?php $model = 'claude-3-opus-latest';", true),
        ("ast.floating-model-name", "php", "<?php $model = 'claude-3-opus-20240229';", false),
        ("ast.floating-model-name", "java", "class A { String model = \"gpt-4o-latest\"; }", true),
        ("ast.floating-model-name", "java", "class A { String model = \"gpt-4o\"; }", false),
        ("ast.floating-model-name", "csharp", "class A { string model = \"codestral-latest\"; }", true),
        ("ast.floating-model-name", "csharp", "class A { string model = \"codestral-2501\"; }", false),
        ("ast.floating-model-name", "kotlin", "val model = \"gpt-4o-latest\"", true),
        ("ast.floating-model-name", "kotlin", "val model = \"gpt-4o-2024-08-06\"", false),
        ("ast.floating-model-name", "dart", "const model = 'gemini-pro-latest';", true),
        ("ast.floating-model-name", "dart", "const model = 'gemini-2.5-pro';", false),
        ("ast.floating-model-name", "swift", "let model = \"claude-3-7-sonnet-latest\"", true),
        ("ast.floating-model-name", "swift", "let model = \"claude-3-7-sonnet-20250219\"", false),
        ("ast.floating-model-name", "rust", "fn f() { let model = \"mistral-small-latest\"; }", true),
        ("ast.floating-model-name", "rust", "fn f() { let model = \"mistral-small-2503\"; }", false),
        ("ast.floating-model-name", "c", "const char *model = \"llama3:latest\";", true),
        ("ast.floating-model-name", "c", "const char *model = \"llama3:8b\";", false),
        ("ast.floating-model-name", "cpp", "const char *model = \"qwen2.5:latest\";", true),
        ("ast.floating-model-name", "cpp", "const char *model = \"qwen2.5:7b\";", false),
        ("ast.floating-model-name", "shell", "ollama run llama3:latest", true),
        ("ast.floating-model-name", "shell", "docker pull node:latest", false),
        // A key made from a password with too few rounds: only a count written into the code, below
        // 210,000, and never a key length that sits in the same call.
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 1000)", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=100_000)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, settings.ROUNDS)", false),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=600000)", false),
        ("ast.weak-password-key-derivation", "python", "x = resize(img, w, h, 1000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha512', pw, salt, 209_999)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha512', pw, salt, 210_000)", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 10000, 32, 'sha256');", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.pbkdf2(pw, salt, 1000, 64, 'sha512', done);", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);", true),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 600000, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, ROUNDS, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);", false),
        // `deriveBits` takes the key's length third: 256 bits, not 256 rounds.
        ("ast.weak-password-key-derivation", "javascript", "const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, 256);", false),
        // Only the `iterations` key is the count, whatever other number sits beside it.
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', saltLength: 16, iterations: 600000, hash: 'SHA-256' }, base, aes, false, use);", false),
        ("ast.weak-password-key-derivation", "typescript", "const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' }, base, 256);", true),
        ("ast.weak-password-key-derivation", "typescript", "const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, 256);", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 1000, 32, 'sha256');", true),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 600_000, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "java", "class A { void f() { KeySpec s = new PBEKeySpec(pw, salt, 1000, 256); } }", true),
        ("ast.weak-password-key-derivation", "java", "class A { void f() { KeySpec s = new PBEKeySpec(pw, salt, 600000, 256); } }", false),
        ("ast.weak-password-key-derivation", "java", "class A { void f() { KeySpec s = new PBEKeySpec(pw, salt, rounds, 256); } }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 4096, 32, sha256.New) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 600_000, 32, sha256.New) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, n, 32, sha256.New) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := cache.Key(a, b, 100, 2) }", false),
        // The standard library's crypto/pbkdf2 (Go 1.24) takes the hash first and the count fourth.
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha256.New, pw, salt, 4096, 32) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha512.New, pw, salt, 100_000, keyLen) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha512.New, pw, salt, 210_000, 64) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha256.New, pw, salt, cfg.Rounds, 32) }", false),
        // x/crypto's order with a password read from a field: its fourth argument is the key's length, and
        // its last is the hash, so it is not read as the standard library's count.
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(cfg.Password, salt, 600_000, 32, sha256.New) }", false),
        // And with the hash passed in a variable, where only the hash coming first tells the two apart.
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 600_000, 32, h) }", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha256\", $pw, $salt, 1000, 32);", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 10000, \"sha256\");", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha256\", $pw, $salt, 600000, 32);", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 600000, \"sha256\");", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 1000, 32, d)", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 20_000, length: 32, hash: 'sha256')", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 600_000, 32, d)", false),
        ("ast.weak-password-key-derivation", "ruby", "k = Legacy.pbkdf2_hmac(pw, salt, 1000, 32, d)", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 600000, length: 32, hash: 'sha256')", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 1000, HashAlgorithmName.SHA256); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var b = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 10000, HashAlgorithmName.SHA256, 32); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 600000, HashAlgorithmName.SHA256); } }", false),
        // Two arguments: 1,000 rounds of SHA-1, without the code saying so.
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(password, 16); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, rounds); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 600000, HashAlgorithmName.SHA256); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var p = new Point(1, 2); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var x = Rfc2898DeriveBytes.Create(pw, salt); } }", false),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1000, EVP_sha256(), 32, out); }", true),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 600000, EVP_sha256(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC_SHA1(pw, n, salt, sn, 2048, 32, out); }", true),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1300000, EVP_sha1(), 32, out); }", false),
        // SHA-1 needs 1,300,000 rounds, where the call names it (6 October 2026): below that is
        // reported, at it is not, and the same count with SHA-512 is not.
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1000000, EVP_sha512(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha1', pw, salt, 1_000_000)", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=s, iterations=600000)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha1', pw, salt, 1_300_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha512', pw, salt, 1_000_000)", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 1000000, 32, 'sha1');", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-1' }, base, aes, false, use);", true),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 1300000, 32, 'sha1');", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 1_000_000, 32, 'sha1');", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 1_000_000, 32, sha1.New) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha1.New, pw, salt, 1_300_000, 32) }", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha1\", $pw, $salt, 1000000, 32);", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 1300000, 'sha1');", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 1_000_000, length: 32, hash: 'sha1')", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 1000000, HashAlgorithmName.SHA1); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 1300000, HashAlgorithmName.SHA1); } }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2::<Hmac<Sha1>>(pw, salt, 1_000_000, &mut key); }", true),
        ("ast.weak-password-key-derivation", "dart", "final k = Pbkdf2(macAlgorithm: Hmac.sha1(), iterations: 1000000, bits: 256);", true),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, pwLen, salt, saltLen, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1000000, &key, 32) }", true),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -md sha1 -iter 1300000 -in a -out b", false),
        ("ast.weak-password-key-derivation", "kotlin", "fun f() { val s = PBEKeySpec(pw, salt, 1000, 256) }", true),
        ("ast.weak-password-key-derivation", "kotlin", "fun f() { val s = PBEKeySpec(pw, salt, 600_000, 256) }", false),
        ("ast.weak-password-key-derivation", "kotlin", "fun f() { val s = PBEKeySpec(pw, salt, rounds, 256) }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, 1000, &mut key); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { let k = pbkdf2_hmac_array::<Sha256, 32>(pw, salt, 4_096u32); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, 600_000, &mut key); }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { resize(img, w, 100, &mut out); }", false),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 1000, bits: 256); }", true),
        ("ast.weak-password-key-derivation", "dart", "void f() { final p = Pbkdf2Parameters(salt, 10000, 32); }", true),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 600000, bits: 256); }", false),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 1000, &key, 32) }", true),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600000, &key, 32) }", false),
        ("ast.weak-password-key-derivation", "shell", "openssl pkcs12 -export -iter 1000 -in cert.pem -out cert.p12", true),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -in a -out b", false),
        ("ast.weak-password-key-derivation", "shell", "openssl rand -hex 32", false),
        // Counts between 210,000 and 600,000: reported where the call itself names SHA-256, and not
        // where it names SHA-512, or names no hash this rule can read (a variable, a hash set
        // elsewhere, or a default).
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 300_000)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac(\"SHA256\", pw, salt, 599999)", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=300000)", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(iterations=300000, length=32, salt=s, algorithm=hashes.SHA256())", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(hashes.SHA256(), 32, s, 300000)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha512', pw, salt, 300_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=s, iterations=300000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac(name, pw, salt, 300_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=algo, length=32, salt=s, iterations=300000)", false),
        // Another keyword that happens to hold the text is not the hash.
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=algo, label='sha256', length=32, salt=s, iterations=300000)", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 300000, 32, 'sha256');", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.pbkdf2(pw, salt, 300_000, 32, 'SHA256', done);", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 300000, hash: 'SHA-256' }, base, aes, false, use);", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', hash: { name: 'SHA-256' }, salt, iterations: 300000 }, base, aes, false, use);", true),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 600000, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 300000, 32, 'sha512');", false),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 300000, hash: 'SHA-512' }, base, aes, false, use);", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 300000, 32, digest);", false),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 300000, hash }, base, aes, false, use);", false),
        // A pair other than `hash` holding the text is not the hash.
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'sha256', salt, iterations: 300000, hash }, base, aes, false, use);", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 300_000, 32, 'sha256');", true),
        ("ast.weak-password-key-derivation", "typescript", "const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 300000, hash: 'SHA-256' }, base, 256);", true),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 600_000, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 300_000, 32, 'sha512');", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 300_000, 32, digest);", false),
        // Java and Kotlin name the hash in `SecretKeyFactory.getInstance(...)`, not in the key spec,
        // so a count between the two figures is not judged.
        ("ast.weak-password-key-derivation", "java", "class A { void f() { KeySpec s = new PBEKeySpec(pw, salt, 300000, 256); } }", false),
        ("ast.weak-password-key-derivation", "kotlin", "fun f() { val s = PBEKeySpec(pw, salt, 300_000, 256) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 300_000, 32, sha256.New) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha256.New, pw, salt, 300_000, 32) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 600_000, 32, sha256.New) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 300_000, 32, sha512.New) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha512.New, pw, salt, 300_000, 64) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 300_000, 32, h) }", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha256\", $pw, $salt, 300000, 32);", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 300000, 'sha256');", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha256\", $pw, $salt, 600000, 32);", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha512\", $pw, $salt, 300000, 32);", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 300000, 'sha512');", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2($algo, $pw, $salt, 300000, 32);", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 300_000, 32, OpenSSL::Digest::SHA256.new)", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 300_000, 32, OpenSSL::Digest.new('SHA256'))", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 300_000, length: 32, hash: 'sha256')", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, hash: 'SHA256', salt: s, iterations: 300_000, length: 32)", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 600_000, 32, OpenSSL::Digest::SHA256.new)", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 300_000, 32, OpenSSL::Digest::SHA512.new)", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 300_000, length: 32, hash: 'sha512')", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 300_000, 32, d)", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 300000, HashAlgorithmName.SHA256); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var b = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 300_000, HashAlgorithmName.SHA256, 32); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var b = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 600_000, HashAlgorithmName.SHA256, 32); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 300000, HashAlgorithmName.SHA512); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 300000, alg); } }", false),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, EVP_sha256(), 32, out); }", true),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, EVP_sha512(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, md, 32, out); }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, EVP_sha256(), 32, out); }", true),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 600000, EVP_sha256(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, EVP_sha512(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, md, 32, out); }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, 300_000, &mut key); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::<Hmac<sha2::Sha256>>(pw, salt, 300_000, &mut key); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { let k = pbkdf2_hmac_array::<Sha256, 32>(pw, salt, 300_000u32); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<Sha512>(pw, salt, 300_000, &mut key); }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<D>(pw, salt, 300_000, &mut key); }", false),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 300000, bits: 256); }", true),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(iterations: 300000, bits: 256, macAlgorithm: Hmac.sha256()); }", true),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: Hmac.sha512(), iterations: 300000, bits: 256); }", false),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: mac, iterations: 300000, bits: 256); }", false),
        // pointycastle names the hash in the `KeyDerivator`, not in the parameters.
        ("ast.weak-password-key-derivation", "dart", "void f() { final p = Pbkdf2Parameters(salt, 300000, 32); }", false),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 300000, &key, 32) }", true),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), 300000, &key, 32) }", false),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, prf, 300000, &key, 32) }", false),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -d -pbkdf2 -iter 300000 -md sha256 -in a -out b", true),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -d -md sha256 -pbkdf2 -iter 300000 -in a -out b", true),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -in a -out b", false),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -iter 300000 -md sha512 -in a -out b", false),
        // `enc`'s default digest is SHA-256, but nothing in the line says so.
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -iter 300000 -in a -out b", false),
        // In `pkcs12`, `-md` is the digest of the file's MAC, not of the key derivation.
        ("ast.weak-password-key-derivation", "shell", "openssl pkcs12 -export -iter 300000 -md sha256 -in cert.pem -out cert.p12", false),
        // Static files from the app's own folder: the handler given the code's folder or the
        // current one, beside the same handler given a folder of its own.
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static(__dirname))", true),
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static('.'))", true),
        ("ast.static-files-from-app-folder", "javascript", "app.use(serveStatic(process.cwd(), { index: false }))", true),
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static(path.join(__dirname)))", true),
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static(path.join(__dirname, 'public')))", false),
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static('public'))", false),
        ("ast.static-files-from-app-folder", "javascript", "app.use('/static', express.static('./dist'))", false),
        ("ast.static-files-from-app-folder", "typescript", "app.use(express.static(process.cwd()))", true),
        ("ast.static-files-from-app-folder", "typescript", "app.use(express.static(path.resolve(__dirname, '../public')))", false),
        ("ast.static-files-from-app-folder", "python", "app = Flask(__name__, static_folder='.', static_url_path='')", true),
        ("ast.static-files-from-app-folder", "python", "app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))", true),
        ("ast.static-files-from-app-folder", "python", "app.mount('/', StaticFiles(directory='.', html=True), name='site')", true),
        ("ast.static-files-from-app-folder", "python", "app.mount('/', StaticFiles(directory=Path(__file__).resolve().parent))", true),
        ("ast.static-files-from-app-folder", "python", "app = Flask(__name__, static_folder='static')", false),
        ("ast.static-files-from-app-folder", "python", "app.mount('/static', StaticFiles(directory='static'), name='static')", false),
        ("ast.static-files-from-app-folder", "python", "app = Flask(__name__)", false),
        ("ast.static-files-from-app-folder", "go", "http.Handle(\"/\", http.FileServer(http.Dir(\".\")))", true),
        ("ast.static-files-from-app-folder", "go", "http.Handle(\"/\", http.FileServer(http.FS(os.DirFS(\".\"))))", true),
        ("ast.static-files-from-app-folder", "go", "r.Static(\"/\", \"./\")", true),
        ("ast.static-files-from-app-folder", "go", "http.Handle(\"/\", http.FileServer(http.Dir(\"./public\")))", false),
        ("ast.static-files-from-app-folder", "go", "e.Static(\"/static\", \"assets\")", false),
        ("ast.static-files-from-app-folder", "shell", "python3 -m http.server 8000", true),
        ("ast.static-files-from-app-folder", "shell", "python -m http.server", true),
        ("ast.static-files-from-app-folder", "shell", "python3 -m http.server 8000 --directory public", false),
        ("ast.static-files-from-app-folder", "shell", "python3 -m http.server -d dist", false),
        ("ast.static-files-from-app-folder", "shell", "python3 -m venv .venv", false),
        ("ast.static-files-from-app-folder", "shell", "php -S 0.0.0.0:8080", true),
        ("ast.static-files-from-app-folder", "shell", "php -S localhost:8000 -t .", true),
        ("ast.static-files-from-app-folder", "shell", "php -S 0.0.0.0:8080 -t public", false),
        ("ast.static-files-from-app-folder", "shell", "php -S 0.0.0.0:8080 -t ./public router.php", false),
        ("ast.static-files-from-app-folder", "shell", "php artisan serve", false),
        ("ast.static-files-from-app-folder", "ruby", "class App < Sinatra::Base\n  set :public_folder, __dir__\nend", true),
        ("ast.static-files-from-app-folder", "ruby", "set :public_folder, File.dirname(__FILE__)", true),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"\"], root: \".\"", true),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, :urls => [\"/\"], :root => Dir.pwd", true),
        ("ast.static-files-from-app-folder", "ruby", "run Rack::Files.new(\".\")", true),
        ("ast.static-files-from-app-folder", "ruby", "set :public_folder, File.join(__dir__, \"public\")", false),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"/css\", \"/images\"], root: \"public\"", false),
        ("ast.static-files-from-app-folder", "ruby", "run Rack::Files.new(\"public\")", false),
        ("ast.static-files-from-app-folder", "ruby", "set :port, 8080", false),
        ("ast.static-files-from-app-folder", "java", "class W implements WebMvcConfigurer { public void addResourceHandlers(ResourceHandlerRegistry r) { r.addResourceHandler(\"/**\").addResourceLocations(\"file:./\"); } }", true),
        ("ast.static-files-from-app-folder", "java", "class W { void f(ResourceHandlerRegistry r) { r.addResourceHandler(\"/**\").addResourceLocations(\"file:\" + System.getProperty(\"user.dir\")); } }", true),
        ("ast.static-files-from-app-folder", "java", "class A { void f(JavalinConfig config) { config.staticFiles.add(\".\", Location.EXTERNAL); } }", true),
        ("ast.static-files-from-app-folder", "java", "class W { void f(ResourceHandlerRegistry r) { r.addResourceHandler(\"/**\").addResourceLocations(\"classpath:/static/\"); } }", false),
        ("ast.static-files-from-app-folder", "java", "class A { void f(JavalinConfig config) { config.staticFiles.add(\"/public\", Location.CLASSPATH); } }", false),
        ("ast.static-files-from-app-folder", "java", "class A { void f(List<String> xs) { xs.add(\".\"); } }", false),
        ("ast.static-files-from-app-folder", "java", "class W { void f(ResourceHandlerRegistry r, String uploads) { r.addResourceHandler(\"/files/**\").addResourceLocations(\"file:\" + uploads); } }", false),
        // Rack's `Static` with no `root:` serves the folder the app was started in (`Dir.pwd`, read from
        // rack's lib/rack/static.rb), but only below its `urls:`; a `urls:` of "" or "/" is every path.
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"\"]", true),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, :urls => [\"/\"], :index => \"index.html\"", true),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"/media\"]", false),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"/css\", \"/images\"]", false),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"\"], root: \"public\"", false),
        // Spark's external folder is a `File` of the path as given, so "." is the folder the app was
        // started from (spark's resource/ExternalResource.java).
        ("ast.static-files-from-app-folder", "java", "class A { void f() { staticFiles.externalLocation(\".\"); } }", true),
        ("ast.static-files-from-app-folder", "java", "class A { void f() { Spark.externalStaticFileLocation(System.getProperty(\"user.dir\")); } }", true),
        ("ast.static-files-from-app-folder", "java", "class A { void f() { staticFiles.externalLocation(\"/var/www/public\"); } }", false),
        ("ast.static-files-from-app-folder", "java", "class A { void f() { staticFiles.externalLocation(\"/\"); } }", false),
        ("ast.static-files-from-app-folder", "java", "class A { void f() { staticFiles.location(\"/public\"); } }", false),
        // Ktor's `staticFiles(remotePath, dir: File)` and `staticPaths(remotePath, dir: Path)` (ktor's
        // http/content/StaticContent.kt), and Spark from Kotlin.
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module() {\n    routing {\n        staticFiles(\"/\", File(\".\"))\n    }\n}", true),
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module() {\n    routing { staticPaths(\"/files\", Path(\".\")) }\n}", true),
        ("ast.static-files-from-app-folder", "kotlin", "fun main() {\n    staticFiles.externalLocation(System.getProperty(\"user.dir\"))\n}", true),
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module() {\n    routing { staticFiles(\"/static\", File(\"public\")) }\n}", false),
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module() {\n    routing { staticResources(\"/\", \"static\") }\n}", false),
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module(uploads: String) {\n    routing { staticFiles(\"/uploads\", File(uploads)) }\n}", false),
        ("ast.static-files-from-app-folder", "csharp", "class P { void M(WebApplication app) { app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(Directory.GetCurrentDirectory()) }); } }", true),
        ("ast.static-files-from-app-folder", "csharp", "class P { void M(WebApplication app, IWebHostEnvironment env) { app.UseFileServer(new FileServerOptions { FileProvider = new PhysicalFileProvider(env.ContentRootPath) }); } }", true),
        ("ast.static-files-from-app-folder", "csharp", "class P { void M(WebApplication app) { app.UseStaticFiles(); } }", false),
        ("ast.static-files-from-app-folder", "csharp", "class P { void M(WebApplication app) { app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), \"assets\")) }); } }", false),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> Router { Router::new().nest_service(\"/\", ServeDir::new(\".\")) }", true),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> Router { Router::new().fallback_service(ServeDir::new(\"./\")) }", true),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> Router { Router::new().fallback_service(ServeDir::new(env!(\"CARGO_MANIFEST_DIR\"))) }", true),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> App<()> { App::new().service(actix_files::Files::new(\"/\", \"./\")) }", true),
        ("ast.static-files-from-app-folder", "rust", "fn routes() { let r = warp::fs::dir(\".\"); }", true),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> Router { Router::new().nest_service(\"/assets\", ServeDir::new(\"assets\")) }", false),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> App<()> { App::new().service(Files::new(\"/static\", \"./static\")) }", false),
        ("ast.static-files-from-app-folder", "rust", "fn f() { let v = Vec::new(); let d = warp::fs::dir(\"public\"); }", false),
        ("ast.token-audience-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], options={\"verify_aud\": False})", true),
        ("ast.token-audience-not-checked", "python", "claims = jose_jwt.decode(token, key, options={'verify_aud': False})", true),
        ("ast.token-audience-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], options=dict(verify_aud=False))", true),
        ("ast.token-audience-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], audience=\"my-api\", options={\"verify_aud\": True})", false),
        ("ast.token-audience-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], options={\"verify_exp\": False})", false),
        ("ast.token-audience-not-checked", "python", "settings = {\"verify_aud_label\": False}", false),
        ("ast.token-audience-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { algorithm: 'RS256', verify_aud: false })", true),
        ("ast.token-audience-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { :verify_aud => false })", true),
        ("ast.token-audience-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { aud: 'my-api', verify_aud: true })", false),
        ("ast.token-audience-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { verify_expiration: false })", false),
        ("ast.token-audience-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { ValidateIssuer = true, ValidateAudience = false }; } }", true),
        ("ast.token-audience-not-checked", "csharp", "class A { void M(TokenValidationParameters p) { p.ValidateAudience = false; } }", true),
        ("ast.token-audience-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { ValidateAudience = true, ValidAudience = \"my-api\" }; } }", false),
        ("ast.token-audience-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { ValidateLifetime = false }; } }", false),
        ("ast.token-audience-not-checked", "rust", "fn m() { let mut v = Validation::new(Algorithm::RS256); v.validate_aud = false; }", true),
        ("ast.token-audience-not-checked", "rust", "fn m() { let v = Validation { validate_aud: false, ..Default::default() }; }", true),
        ("ast.token-audience-not-checked", "rust", "fn m() { let mut v = Validation::new(Algorithm::RS256); v.set_audience(&[\"my-api\"]); v.validate_aud = true; }", false),
        ("ast.token-audience-not-checked", "rust", "fn m() { let mut v = Validation::new(Algorithm::RS256); v.validate_exp = false; }", false),
        ("ast.token-audience-not-checked", "go", "package m\nfunc f() { v := provider.Verifier(&oidc.Config{SkipClientIDCheck: true}) }", true),
        ("ast.token-audience-not-checked", "go", "package m\nfunc f() { t, err := jwt.Parse(s, keyFunc, jwt.WithoutClaimsValidation()) }", true),
        ("ast.token-audience-not-checked", "go", "package m\nfunc f() { v := provider.Verifier(&oidc.Config{ClientID: \"my-api\", SkipClientIDCheck: false}) }", false),
        ("ast.token-audience-not-checked", "go", "package m\nfunc f() { t, err := jwt.Parse(s, keyFunc, jwt.WithAudience(\"my-api\")) }", false),
        // A token read with its signature check switched off (gap analysis, item 11).
        ("ast.token-signature-not-checked", "python", "claims = jwt.decode(token, options={\"verify_signature\": False})", true),
        ("ast.token-signature-not-checked", "python", "claims = jwt.decode(token, key, options=dict(verify_signature=False))", true),
        ("ast.token-signature-not-checked", "python", "claims = jose_jwt.decode(token, key, options={'verify_signature': False})", true),
        ("ast.token-signature-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"])", false),
        ("ast.token-signature-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], options={\"verify_signature\": True})", false),
        ("ast.token-signature-not-checked", "python", "r = requests.get(url, verify=False)", false),
        ("ast.token-signature-not-checked", "ruby", "decoded = JWT.decode(token, nil, false)", true),
        ("ast.token-signature-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { algorithm: 'RS256' })", false),
        ("ast.token-signature-not-checked", "ruby", "decoded = Base64.decode(text)", false),
        ("ast.token-signature-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { RequireSignedTokens = false }; } }", true),
        ("ast.token-signature-not-checked", "csharp", "class A { void M(TokenValidationParameters p) { p.RequireSignedTokens = false; } }", true),
        ("ast.token-signature-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { RequireSignedTokens = true, ValidateIssuerSigningKey = true }; } }", false),
        ("ast.token-signature-not-checked", "rust", "fn m() { let mut v = Validation::new(Algorithm::HS256); v.insecure_disable_signature_validation(); }", true),
        ("ast.token-signature-not-checked", "rust", "fn m(t: &str) { let d = dangerous_insecure_decode::<Claims>(t); }", true),
        ("ast.token-signature-not-checked", "rust", "fn m(t: &str) { let d = jsonwebtoken::dangerous_insecure_decode::<Claims>(t); }", true),
        ("ast.token-signature-not-checked", "rust", "fn m(t: &str, k: &DecodingKey) { let d = decode::<Claims>(t, k, &Validation::new(Algorithm::RS256)); }", false),
        ("ast.token-signature-not-checked", "go", "package m\nfunc f() { t, _, err := jwt.NewParser().ParseUnverified(s, &claims) }", true),
        ("ast.token-signature-not-checked", "go", "package m\nfunc f() { t, err := jwt.Parse(s, keyFunc) }", false),
        ("ast.token-signature-not-checked", "java", "class A { void f() { Jwts.parser().unsecured().build().parse(token); } }", true),
        ("ast.token-signature-not-checked", "java", "class A { void f() { Jwts.parser().verifyWith(key).build().parseSignedClaims(token); } }", false),
        // Request-forgery protection switched off (gap analysis, item 11).
        ("ast.csrf-protection-off", "python", "from django.views.decorators.csrf import csrf_exempt\n\n@csrf_exempt\ndef pay(request):\n    return charge(request)", true),
        ("ast.csrf-protection-off", "python", "@app.route('/hook', methods=['POST'])\n@csrf.exempt\ndef hook():\n    return 'ok'", true),
        ("ast.csrf-protection-off", "python", "urlpatterns = [path('pay/', csrf_exempt(views.pay))]", true),
        ("ast.csrf-protection-off", "python", "app.config['WTF_CSRF_ENABLED'] = False", true),
        ("ast.csrf-protection-off", "python", "class Config:\n    WTF_CSRF_ENABLED = False", true),
        ("ast.csrf-protection-off", "python", "app.config.update(WTF_CSRF_ENABLED=False)", true),
        ("ast.csrf-protection-off", "python", "settings = {\"WTF_CSRF_ENABLED\": False}", true),
        ("ast.csrf-protection-off", "python", "@csrf_protect\ndef pay(request):\n    return charge(request)", false),
        ("ast.csrf-protection-off", "python", "app.config['WTF_CSRF_ENABLED'] = True", false),
        ("ast.csrf-protection-off", "python", "from django.views.decorators.csrf import csrf_exempt", false),
        ("ast.csrf-protection-off", "python", "csrf_exempt_paths = ['/hook']", false),
        ("ast.csrf-protection-off", "ruby", "class PaymentsController < ApplicationController\n  skip_forgery_protection\nend", true),
        ("ast.csrf-protection-off", "ruby", "class PaymentsController < ApplicationController\n  skip_forgery_protection only: :create\nend", true),
        ("ast.csrf-protection-off", "ruby", "class HooksController < ApplicationController\n  skip_before_action :verify_authenticity_token\nend", true),
        ("ast.csrf-protection-off", "ruby", "class ApplicationController < ActionController::Base\n  protect_from_forgery with: :exception\n  before_action :verify_authenticity_token\nend", false),
        ("ast.csrf-protection-off", "ruby", "class A < ApplicationController\n  skip_before_action :authenticate_user!\nend", false),
        ("ast.csrf-protection-off", "java", "class S { SecurityFilterChain f(HttpSecurity http) throws Exception { return http.csrf().disable().build(); } }", true),
        ("ast.csrf-protection-off", "java", "class S { SecurityFilterChain f(HttpSecurity http) throws Exception { http.csrf(csrf -> csrf.disable()); return http.build(); } }", true),
        ("ast.csrf-protection-off", "java", "class S { SecurityFilterChain f(HttpSecurity http) throws Exception { http.csrf(AbstractHttpConfigurer::disable); return http.build(); } }", true),
        ("ast.csrf-protection-off", "java", "class S { SecurityFilterChain f(HttpSecurity http) throws Exception { http.csrf(Customizer.withDefaults()); return http.build(); } }", false),
        ("ast.csrf-protection-off", "java", "class S { void f(HttpSecurity http) throws Exception { http.cors().disable(); } }", false),
        ("ast.csrf-protection-off", "csharp", "[IgnoreAntiforgeryToken]\npublic class HooksController : Controller { }", true),
        ("ast.csrf-protection-off", "csharp", "class P { void M(WebApplication app) { app.MapPost(\"/pay\", Pay).DisableAntiforgery(); } }", true),
        ("ast.csrf-protection-off", "csharp", "[ValidateAntiForgeryToken]\npublic class PayController : Controller { }", false),
        ("ast.csrf-protection-off", "javascript", "export default { kit: { csrf: { checkOrigin: false } } };", true),
        ("ast.csrf-protection-off", "javascript", "export default { kit: { csrf: { checkOrigin: true } } };", false),
        ("ast.csrf-protection-off", "typescript", "export default defineConfig({ security: { checkOrigin: false } });", true),
        ("ast.csrf-protection-off", "typescript", "const options = { strict: false };", false),
        // A template built from a value (gap analysis, item 11).
        ("ast.template-built-from-value", "python", "def hello():\n    name = request.args.get('name')\n    return render_template_string(f'<h1>Hello {name}</h1>')", true),
        ("ast.template-built-from-value", "python", "def page(body):\n    return flask.render_template_string('<main>' + body + '</main>')", true),
        ("ast.template-built-from-value", "python", "def page(src):\n    return env.from_string(src).render()", true),
        ("ast.template-built-from-value", "python", "def hello():\n    return render_template_string('<h1>Hello {{ name }}</h1>', name=request.args.get('name'))", false),
        ("ast.template-built-from-value", "python", "PAGE = '<h1>{{ title }}</h1>'\n\ndef page():\n    return render_template_string(PAGE, title='Home')", false),
        ("ast.template-built-from-value", "python", "def page(name):\n    return render_template('page.html', name=name)", false),
        ("ast.template-built-from-value", "javascript", "app.get('/', (req, res) => res.send(ejs.render(req.query.tpl, {})));", true),
        ("ast.template-built-from-value", "javascript", "const t = Handlebars.compile(source);", true),
        ("ast.template-built-from-value", "javascript", "const t = _.template(`<b>${req.body.name}</b>`);", true),
        ("ast.template-built-from-value", "javascript", "const t = Handlebars.compile('<b>{{name}}</b>');", false),
        ("ast.template-built-from-value", "javascript", "res.render(view, { name });", false),
        ("ast.template-built-from-value", "typescript", "const html: string = nunjucks.renderString(input, { user });", true),
        ("ast.template-built-from-value", "typescript", "const html: string = nunjucks.renderString('Hi {{ user }}', { user });", false),
        ("ast.template-built-from-value", "ruby", "def show\n  render html: ERB.new(params[:t]).result(binding)\nend", true),
        ("ast.template-built-from-value", "ruby", "def show\n  Liquid::Template.parse(params[:t]).render\nend", true),
        ("ast.template-built-from-value", "ruby", "def show\n  ERB.new('<%= @name %>').result(binding)\nend", false),
        ("ast.template-built-from-value", "ruby", "def show\n  User.new(params[:user])\nend", false),
        ("ast.template-built-from-value", "php", "<?php\n$html = $twig->createTemplate($_GET['t'])->render([]);", true),
        ("ast.template-built-from-value", "php", "<?php\n$html = $twig->createTemplate('Hello {{ name }}')->render(['name' => $n]);", false),
        ("ast.template-built-from-value", "csharp", "class A { string M(string input) { return Template.Parse(input).Render(); } }", true),
        ("ast.template-built-from-value", "csharp", "class A { string M() { return Template.Parse(\"Hello {{ name }}\").Render(); } }", false),
        ("ast.template-built-from-value", "csharp", "class A { int M(string input) { return int.Parse(input); } }", false),
        ("ast.template-built-from-value", "csharp", "class A { DateTime M(string input) { return DateTime.Parse(input); } }", false),
        ("ast.account-found-by-provider-email", "python", "user = User.query.filter_by(email=token[\"userinfo\"][\"email\"]).first()", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    userinfo = oauth.google.authorize_access_token()[\"userinfo\"]\n    email = userinfo[\"email\"]\n    user = User.query.filter_by(email=email).first()\n", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    idinfo = id_token.verify_oauth2_token(tok, requests.Request(), CLIENT_ID)\n    row = db.execute(\"SELECT id FROM users WHERE email = ?\", (idinfo.get(\"email\"),)).fetchone()\n", true),
        ("ast.account-found-by-provider-email", "python", "user = User.query.filter_by(sub=token[\"userinfo\"][\"sub\"]).first()", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    sub, email = userinfo[\"sub\"], userinfo[\"email\"]\n    user = User.query.filter_by(email=email).first()\n", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    email = userinfo[\"email\"]\n    stored = db.session.execute(select(User.email).where(User.sub == userinfo[\"sub\"])).scalar()\n", false),
        ("ast.account-found-by-provider-email", "python", "def login():\n    email = request.form[\"email\"]\n    user = User.query.filter_by(email=email).first()\n", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    email = userinfo[\"email\"]\n    send_welcome(email)\n", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    email = userinfo[\"email\"]\ndef login():\n    user = User.query.filter_by(email=email).first()\n", false),
        ("ast.account-found-by-provider-email", "javascript", "passport.use(new GoogleStrategy(opts, async (at, rt, profile, done) => { const user = await User.findOne({ email: profile.emails[0].value }); done(null, user); }));", true),
        ("ast.account-found-by-provider-email", "javascript", "async function callback(req) { const payload = ticket.getPayload(); const email = ticket.getPayload().email; return prisma.user.findUnique({ where: { email } }); }", true),
        ("ast.account-found-by-provider-email", "javascript", "async function callback(req) { const claims = tokenSet.claims(); return prisma.user.findUnique({ where: { email: claims.email } }); }", true),
        ("ast.account-found-by-provider-email", "javascript", "passport.use(new GoogleStrategy(opts, async (at, rt, profile, done) => { const user = await User.findOne({ googleId: profile.id }); done(null, user); }));", false),
        ("ast.account-found-by-provider-email", "javascript", "async function login(req) { const email = req.body.email; return prisma.user.findUnique({ where: { email } }); }", false),
        ("ast.account-found-by-provider-email", "javascript", "async function callback() { await mailer.send({ to: claims.email, subject: 'Welcome' }); }", false),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/callback', async (req, res) => { const claims = tokenSet.claims(); res.render('welcome', { email: claims.email }); });", false),
        ("ast.account-found-by-provider-email", "typescript", "export async function signIn(claims: Claims) { return db.user.findFirst({ where: { email: claims.email } }); }", true),
        ("ast.account-found-by-provider-email", "typescript", "export async function signIn(userInfo: UserInfo) { const email: string = userInfo.email; return users.findOneBy({ email }); }", true),
        ("ast.account-found-by-provider-email", "typescript", "export async function signIn(claims: Claims) { return db.user.findFirst({ where: { sub: claims.sub } }); }", false),
        ("ast.account-found-by-provider-email", "typescript", "export async function signIn(form: Form) { const email: string = form.email; return users.findOneBy({ email }); }", false),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  auth = request.env['omniauth.auth']\n  user = User.find_by(email: auth.info.email)\nend\n", true),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  email = request.env['omniauth.auth']['info']['email']\n  user = User.find_or_create_by(email: email)\nend\n", true),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  auth = request.env['omniauth.auth']\n  user = User.find_by(provider: auth.provider, uid: auth.uid)\nend\n", false),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  user = User.find_by(email: params[:email])\nend\n", false),
        ("ast.account-found-by-provider-email", "go", "package m\nfunc callback() { var claims struct{ Email string }\n idToken.Claims(&claims)\n db.Where(\"email = ?\", claims.Email).First(&user) }", true),
        ("ast.account-found-by-provider-email", "go", "package m\nfunc callback() { email := userInfo.Email\n row := db.QueryRow(\"SELECT id FROM users WHERE email = $1\", email) }", true),
        ("ast.account-found-by-provider-email", "go", "package m\nfunc callback() { var claims struct{ Subject string }\n idToken.Claims(&claims)\n db.Where(\"sub = ?\", claims.Subject).First(&user) }", false),
        ("ast.account-found-by-provider-email", "go", "package m\nfunc login(r *http.Request) { email := r.FormValue(\"email\")\n row := db.QueryRow(\"SELECT id FROM users WHERE email = $1\", email) }", false),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $user = User::where('email', Socialite::driver('google')->user()->getEmail())->first(); }", true),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $googleUser = Socialite::driver('google')->user();\n $email = $googleUser->getEmail();\n $user = User::firstOrCreate(['email' => $email]); }", true),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $googleUser = Socialite::driver('google')->user();\n $user = User::where('google_id', $googleUser->getId())->first(); }", false),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction login($request) { $email = $request->input('email');\n $user = User::where('email', $email)->first(); }", false),
        ("ast.account-found-by-provider-email", "java", "class C { User f(OidcUser oidcUser) { return userRepository.findByEmail(oidcUser.getEmail()); } }", true),
        ("ast.account-found-by-provider-email", "java", "class C { User f(OAuth2User principal) { String email = principal.getAttribute(\"email\"); return userRepository.findByEmail(email); } }", true),
        ("ast.account-found-by-provider-email", "java", "class C { User f(OidcUser oidcUser) { return userRepository.findBySubject(oidcUser.getSubject()); } }", false),
        ("ast.account-found-by-provider-email", "java", "class C { User f(LoginForm form) { String email = form.getEmail(); return userRepository.findByEmail(email); } }", false),
        ("ast.account-found-by-provider-email", "csharp", "class C { async Task F() { var user = await _userManager.FindByEmailAsync(info.Principal.FindFirstValue(ClaimTypes.Email)); } }", true),
        ("ast.account-found-by-provider-email", "csharp", "class C { async Task F() { var email = info.Principal.FindFirstValue(ClaimTypes.Email);\n var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email); } }", true),
        ("ast.account-found-by-provider-email", "csharp", "class C { async Task F() { var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey); } }", false),
        ("ast.account-found-by-provider-email", "csharp", "class C { async Task F(LoginModel model) { var user = await _userManager.FindByEmailAsync(model.Email); } }", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    token = oauth.google.authorize_access_token()\n    session[\"user\"] = token[\"userinfo\"][\"email\"]\n", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    token = oauth.google.authorize_access_token()\n    session[\"user\"] = token[\"userinfo\"][\"sub\"]\n    session[\"email\"] = token[\"userinfo\"][\"email\"]\n", false),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/callback', async (req, res) => { const claims = tokenSet.claims(); req.session.userId = claims.email; });", true),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/callback', async (req, res) => { const claims = tokenSet.claims(); req.session.userId = claims.sub; req.session.email = claims.email; });", false),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  session[:user_id] = request.env['omniauth.auth']['info']['email']\nend\n", true),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  session[:user_id] = request.env['omniauth.auth']['uid']\nend\n", false),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $googleUser = Socialite::driver('google')->user();\n $_SESSION['user_id'] = $googleUser->getEmail(); }", true),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $googleUser = Socialite::driver('google')->user();\n $_SESSION['user_id'] = $googleUser->getId(); }", false),
        // The session under another name (`functionNamesRead`): `examples/oidc-notes`' own shape, a
        // helper that returns the session; `req.session` held in a name; and iron-session's call.
        ("ast.account-found-by-provider-email", "javascript", "function session(req, res) { return sessions.get(req.headers.cookie); }\nhttp.createServer(async (req, res) => {\n  const s = session(req, res);\n  s.user = claims.email;\n});", true),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/cb', async (req, res) => {\n  const sess = req.session;\n  sess.userId = userinfo.email;\n});", true),
        ("ast.account-found-by-provider-email", "typescript", "export async function GET(req: Request) {\n  const s = await getIronSession(cookies(), options);\n  s.user = claims.email;\n  await s.save();\n}", true),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/cb', async (req, res) => {\n  const s = cache;\n  s.user = claims.email;\n});", false),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/cb', async (req, res) => {\n  const s = req.session;\n  s.email = claims.email;\n});", false),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/cb', async (req, res) => {\n  const s = req.session;\n  s.user = claims.sub;\n});", false),
        ("ast.account-found-by-provider-email", "javascript", "function other(req) { const s = req.session; }\napp.get('/cb', async (req, res) => {\n  s.user = claims.email;\n});", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    s = session\n    s[\"user\"] = userinfo[\"email\"]\n", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    s = dict(session)\n    s[\"user\"] = userinfo[\"email\"]\n", false),
        ("ast.account-found-by-provider-email", "ruby", "def callback\n  s = session\n  s[:user_id] = auth.info.email\nend", true),
        ("ast.account-found-by-provider-email", "ruby", "def callback\n  s = {}\n  s[:user_id] = auth.info.email\nend", false),
        // PHP copies an array on assignment, so only a reference is the session under another name.
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $s = &$_SESSION; $googleUser = Socialite::driver('google')->user();\n $s['user_id'] = $googleUser->getEmail(); }", true),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $s = $_SESSION; $googleUser = Socialite::driver('google')->user();\n $s['user_id'] = $googleUser->getEmail(); }", false),
        // A token's own `jku`, `x5u`, or `jwk` handed to what fetches or makes its key (V9.1.3). The
        // quiet cases: a fixed address, a check against a list, a log line, an address parsed for
        // its host, and a token being made with a `jku` of the app's own.
        ("ast.token-key-source-from-token", "python", "keys = requests.get(jwt.get_unverified_header(token)[\"jku\"]).json()", true),
        ("ast.token-key-source-from-token", "python", "client = PyJWKClient(header.get(\"jku\"))", true),
        ("ast.token-key-source-from-token", "python", "cert = urlopen(header['x5u']).read()", true),
        ("ast.token-key-source-from-token", "python", "key = jwk.construct(header[\"jwk\"])", true),
        ("ast.token-key-source-from-token", "python", "claims = jwt.decode(token, PyJWK(header[\"jwk\"]).key, algorithms=[\"RS256\"])", true),
        ("ast.token-key-source-from-token", "python", "claims = jose_jwt.decode(token, header[\"jwk\"], algorithms=[\"RS256\"])", true),
        ("ast.token-key-source-from-token", "python", "client = PyJWKClient(JWKS_URL)", false),
        ("ast.token-key-source-from-token", "python", "keys = requests.get(KEY_SETS[header[\"kid\"]]).json()", false),
        ("ast.token-key-source-from-token", "python", "if header[\"jku\"] not in TRUSTED_KEY_SETS:\n    raise Unauthorized()", false),
        ("ast.token-key-source-from-token", "python", "trusted = is_trusted(header[\"jku\"])", false),
        ("ast.token-key-source-from-token", "python", "log.info(\"token names %s\", header[\"jku\"])", false),
        ("ast.token-key-source-from-token", "python", "host = urlparse(header[\"jku\"]).netloc", false),
        ("ast.token-key-source-from-token", "python", "token = jwt.encode(claims, key, algorithm=\"RS256\", headers={\"jku\": JWKS_URL})", false),
        ("ast.token-key-source-from-token", "python", "keys = requests.get(jku_url).json()", false),
        ("ast.token-key-source-from-token", "javascript", "const res = await fetch(decoded.header.jku);", true),
        ("ast.token-key-source-from-token", "javascript", "const client = jwksClient({ jwksUri: decoded.header.jku });", true),
        ("ast.token-key-source-from-token", "javascript", "const keys = createRemoteJWKSet(new URL(header.x5u));", true),
        ("ast.token-key-source-from-token", "javascript", "const key = await importJWK(header.jwk, 'RS256');", true),
        ("ast.token-key-source-from-token", "javascript", "jwt.verify(token, jwkToPem(decoded.header.jwk));", true),
        ("ast.token-key-source-from-token", "javascript", "const keys = createRemoteJWKSet(new URL(JWKS_URL));", false),
        ("ast.token-key-source-from-token", "javascript", "if (!TRUSTED.includes(decoded.header.jku)) throw new Error('untrusted');", false),
        ("ast.token-key-source-from-token", "javascript", "const host = new URL(decoded.header.jku).host;", false),
        ("ast.token-key-source-from-token", "javascript", "console.log('token names', decoded.header.jku);", false),
        ("ast.token-key-source-from-token", "javascript", "const t = jwt.sign(claims, key, { algorithm: 'RS256', header: { jku: JWKS_URL } });", false),
        ("ast.token-key-source-from-token", "typescript", "const res: Response = await fetch(decoded.header.jku as string);", true),
        ("ast.token-key-source-from-token", "typescript", "const key = await importJWK(protectedHeader.jwk!, 'ES256');", true),
        ("ast.token-key-source-from-token", "typescript", "const keys = createRemoteJWKSet(new URL(config.jwksUrl));", false),
        ("ast.token-key-source-from-token", "typescript", "const ok: boolean = TRUSTED.has(decoded.header.jku as string);", false),
        ("ast.token-key-source-from-token", "go", "package m\nfunc f(token *jwt.Token) { resp, err := http.Get(token.Header[\"jku\"].(string)) }", true),
        ("ast.token-key-source-from-token", "go", "package m\nfunc f(ctx context.Context, token *jwt.Token) { set, err := jwk.Fetch(ctx, token.Header[\"jku\"].(string)) }", true),
        ("ast.token-key-source-from-token", "go", "package m\nfunc f(ctx context.Context) { set, err := jwk.Fetch(ctx, jwksURL) }", false),
        ("ast.token-key-source-from-token", "go", "package m\nfunc f(token *jwt.Token) { ok := trusted(token.Header[\"jku\"].(string)) }", false),
        ("ast.token-key-source-from-token", "ruby", "keys = Net::HTTP.get(URI(header[\"jku\"]))", true),
        ("ast.token-key-source-from-token", "ruby", "key = JWT::JWK.import(header[\"jwk\"])", true),
        ("ast.token-key-source-from-token", "ruby", "keys = HTTParty.get(header[:jku])", true),
        ("ast.token-key-source-from-token", "ruby", "keys = Net::HTTP.get(URI(JWKS_URL))", false),
        ("ast.token-key-source-from-token", "ruby", "raise Unauthorized unless TRUSTED.include?(header[\"jku\"])", false),
        ("ast.token-key-source-from-token", "php", "<?php $keys = $http->get($header->jku);", true),
        ("ast.token-key-source-from-token", "php", "<?php $key = JWK::parseKey($header['jwk']);", true),
        ("ast.token-key-source-from-token", "php", "<?php $keys = file_get_contents(JWKS_URL);", false),
        ("ast.token-key-source-from-token", "php", "<?php if (!in_array($header->jku, TRUSTED, true)) { throw new Exception('untrusted'); }", false),
        ("ast.token-key-source-from-token", "java", "class A { void m(JWSHeader header) throws Exception { var keys = new RemoteJWKSet<>(header.getJWKURL().toURL()); } }", true),
        ("ast.token-key-source-from-token", "java", "class A { void m(DecodedJWT jwt) throws Exception { var p = new UrlJwkProvider(new URL(jwt.getHeaderClaim(\"jku\").asString())); } }", true),
        ("ast.token-key-source-from-token", "java", "class A { void m(JWSHeader header) throws Exception { var v = new RSASSAVerifier(header.getJWK().toRSAKey()); } }", true),
        ("ast.token-key-source-from-token", "java", "class A { void m() throws Exception { var p = new UrlJwkProvider(new URL(JWKS_URL)); } }", false),
        ("ast.token-key-source-from-token", "java", "class A { boolean m(JWSHeader header) { return TRUSTED.contains(header.getJWKURL()); } }", false),
        ("ast.token-key-source-from-token", "csharp", "class A { async Task M(JwtSecurityToken token) { var keys = await http.GetStringAsync(token.Header[\"jku\"].ToString()); } }", true),
        ("ast.token-key-source-from-token", "csharp", "class A { void M(JsonWebToken token) { var key = new JsonWebKey(token.GetHeaderValue<string>(\"jwk\")); } }", true),
        ("ast.token-key-source-from-token", "csharp", "class A { async Task M() { var keys = await http.GetStringAsync(JwksUrl); } }", false),
        ("ast.token-key-source-from-token", "csharp", "class A { bool M(JwtSecurityToken token) { return Trusted.Contains(token.Header[\"jku\"].ToString()); } }", false),
        ("ast.token-key-source-from-token", "rust", "async fn f(header: Header) { let keys = reqwest::get(header.jku.unwrap()).await; }", true),
        ("ast.token-key-source-from-token", "rust", "fn f(header: Header) { let key = DecodingKey::from_jwk(&header.jwk.unwrap()); }", true),
        ("ast.token-key-source-from-token", "rust", "async fn f() { let keys = reqwest::get(JWKS_URL).await; }", false),
        ("ast.token-key-source-from-token", "rust", "fn f(header: Header) -> bool { TRUSTED.contains(&header.jku.unwrap_or_default().as_str()) }", false),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader) { val keys = RemoteJWKSet<SecurityContext>(header.jwkurl.toURL()) }", true),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader) { val p = UrlJwkProvider(URL(header.x509CertURL.toString())) }", true),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader) { val keys = RemoteJWKSet<SecurityContext>(header.getJWKURL().toURL()) }", true),
        ("ast.token-key-source-from-token", "kotlin", "suspend fun m(jwt: DecodedJWT) { val keys = client.get(jwt.getHeaderClaim(\"jku\").asString()) }", true),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader) { val v = RSASSAVerifier(header.jwk.toRSAKey()) }", true),
        ("ast.token-key-source-from-token", "kotlin", "fun m() { val keys = RemoteJWKSet<SecurityContext>(URL(JWKS_URL)) }", false),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader): Boolean = TRUSTED.contains(header.jwkurl)", false),
        ("ast.token-key-source-from-token", "dart", "Future<void> f(Map header) async { final keys = await http.get(Uri.parse(header['jku'])); }", true),
        ("ast.token-key-source-from-token", "dart", "void f(Map header) { final key = JWTKey.fromJWK(header['jwk']); }", true),
        ("ast.token-key-source-from-token", "dart", "Future<void> f() async { final keys = await http.get(Uri.parse(jwksUrl)); }", false),
        ("ast.token-key-source-from-token", "dart", "bool f(Map header) { return trusted.contains(header['jku']); }", false),
        ("ast.token-key-source-from-token", "swift", "func f(header: JWTHeader) async throws { let (keys, _) = try await URLSession.shared.data(from: URL(string: header.jku!)!) }", true),
        ("ast.token-key-source-from-token", "swift", "func f(header: JWTHeader) throws { let task = URLSession.shared.dataTask(with: URL(string: header.x5u!)!) }", true),
        ("ast.token-key-source-from-token", "swift", "func f() async throws { let (keys, _) = try await URLSession.shared.data(from: jwksURL) }", false),
        ("ast.token-key-source-from-token", "swift", "func f(header: JWTHeader) -> Bool { return trusted.contains(header.jku ?? \"\") }", false),
        ("ast.token-key-source-from-token", "c", "void f(CURL *curl, jwt_t *jwt) { curl_easy_setopt(curl, CURLOPT_URL, jwt_get_header(jwt, \"jku\")); }", true),
        ("ast.token-key-source-from-token", "c", "void f(cjose_header_t *h, cjose_err *err) { cjose_jwk_t *k = cjose_jwk_import(cjose_header_get(h, \"jwk\", err), 0, err); }", true),
        ("ast.token-key-source-from-token", "c", "void f(CURL *curl) { curl_easy_setopt(curl, CURLOPT_URL, JWKS_URL); }", false),
        ("ast.token-key-source-from-token", "c", "int f(jwt_t *jwt) { return is_trusted(jwt_get_header(jwt, \"jku\")); }", false),
        ("ast.token-key-source-from-token", "cpp", "void f(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& d) { auto r = cpr::Get(cpr::Url{d.get_header_claim(\"jku\").as_string()}); }", true),
        ("ast.token-key-source-from-token", "cpp", "void f(CURL* curl, jwt_t* jwt) { curl_easy_setopt(curl, CURLOPT_URL, jwt_get_header(jwt, \"x5u\")); }", true),
        ("ast.token-key-source-from-token", "cpp", "void f() { auto r = cpr::Get(cpr::Url{JWKS_URL}); }", false),
        ("ast.token-key-source-from-token", "cpp", "bool f(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& d) { return trusted.count(d.get_header_claim(\"jku\").as_string()) > 0; }", false),
        ("ast.insecure-random-for-code", "python", "def send_login_email(user):\n    otp = str(random.randint(100000, 999999))\n    mail(user, otp)\n", true),
        ("ast.insecure-random-for-code", "python", "def generate_backup_codes():\n    return [''.join(random.choices(ALPHABET, k=10)) for _ in range(8)]\n", true),
        ("ast.insecure-random-for-code", "python", "def forgot(user):\n    user.reset_token = '%032x' % random.getrandbits(128)\n", true),
        ("ast.insecure-random-for-code", "python", "def forgot(user):\n    send(user, verification_code=random.randint(0, 999999))\n", true),
        ("ast.insecure-random-for-code", "python", "def send_login_email(user):\n    otp = str(secrets.randbelow(900000) + 100000)\n    mail(user, otp)\n", false),
        ("ast.insecure-random-for-code", "python", "def send_login_email(user):\n    otp = ''.join(secrets.choice(DIGITS) for _ in range(6))\n    mail(user, otp)\n", false),
        ("ast.insecure-random-for-code", "python", "def roll():\n    color_code = random.choice(COLORS)\n    return random.randint(1, 6)\n", false),
        ("ast.insecure-random-for-code", "javascript", "function sendCode(user) { const otpCode = Math.floor(100000 + Math.random() * 900000); mail(user, otpCode); }", true),
        ("ast.insecure-random-for-code", "javascript", "async function forgot(user) { user.resetToken = Math.random().toString(36).slice(2); await user.save(); }", true),
        ("ast.insecure-random-for-code", "javascript", "const generateOtp = () => String(Math.floor(Math.random() * 1e6)).padStart(6, '0');", true),
        ("ast.insecure-random-for-code", "javascript", "function sendCode(user) { const otpCode = crypto.randomInt(100000, 1000000); mail(user, otpCode); }", false),
        ("ast.insecure-random-for-code", "javascript", "function shuffle(cards) { const pick = Math.floor(Math.random() * cards.length); return cards[pick]; }", false),
        ("ast.insecure-random-for-code", "typescript", "export function makeVerificationCode(): string { return String(Math.floor(Math.random() * 1_000_000)); }", true),
        ("ast.insecure-random-for-code", "typescript", "export function jitter(ms: number): number { return ms + Math.random() * 100; }", false),
        ("ast.insecure-random-for-code", "java", "class A { String sendOtp() { String otp = String.valueOf(new Random().nextInt(900000) + 100000); return otp; } }", true),
        ("ast.insecure-random-for-code", "java", "class A { int resetCode() { return ThreadLocalRandom.current().nextInt(1000000); } }", true),
        ("ast.insecure-random-for-code", "java", "class A { String sendOtp() { String otp = String.valueOf(new SecureRandom().nextInt(900000) + 100000); return otp; } }", false),
        ("ast.insecure-random-for-code", "java", "class A { int roll() { int face = new Random().nextInt(6) + 1; return face; } }", false),
        ("ast.insecure-random-for-code", "kotlin", "fun notify(user: User) { val otp: Int = Random.nextInt(100000, 999999); mail(user, otp) }", true),
        ("ast.insecure-random-for-code", "kotlin", "fun roll() { val face = Random.nextInt(1, 7); show(face) }", false),
        ("ast.insecure-random-for-code", "go", "package m\nfunc sendOtp() { code := rand.Intn(900000) + 100000; mail(code) }", true),
        ("ast.insecure-random-for-code", "go", "package m\nfunc newResetToken() string { return fmt.Sprintf(\"%x\", rand.Int63()) }", true),
        ("ast.insecure-random-for-code", "go", "package m\nfunc newResetToken() string { b := make([]byte, 32); rand.Read(b); return hex.EncodeToString(b) }", false),
        ("ast.insecure-random-for-code", "go", "package m\nfunc backoff() time.Duration { return time.Duration(rand.Intn(1000)) * time.Millisecond }", false),
        ("ast.insecure-random-for-code", "php", "<?php function sendOtp($user) { $otp = rand(100000, 999999); mail($user, $otp); }", true),
        ("ast.insecure-random-for-code", "php", "<?php function forgot($user) { $user->reset_token = uniqid('', true); }", true),
        ("ast.insecure-random-for-code", "php", "<?php function sendOtp($user) { $otp = random_int(100000, 999999); mail($user, $otp); }", false),
        ("ast.insecure-random-for-code", "php", "<?php function pickColor() { $color = array_rand($colors); return $color; }", false),
        ("ast.insecure-random-for-code", "ruby", "def send_otp(user)\n  otp = rand(100_000..999_999)\n  mail(user, otp)\nend\n", true),
        ("ast.insecure-random-for-code", "ruby", "def forgot(user)\n  user.reset_token = Random.new.rand(10**20).to_s\nend\n", true),
        ("ast.insecure-random-for-code", "ruby", "def send_otp(user)\n  otp = SecureRandom.random_number(1_000_000)\n  mail(user, otp)\nend\n", false),
        ("ast.insecure-random-for-code", "ruby", "def send_otp(user)\n  otp = SecureRandom.rand(1_000_000)\n  mail(user, otp)\nend\n", false),
        ("ast.insecure-random-for-code", "ruby", "def roll\n  face = rand(1..6)\n  face\nend\n", false),
        ("ast.insecure-random-for-code", "csharp", "class A { void SendOtp() { var otp = new Random().Next(100000, 999999); Mail(otp); } }", true),
        ("ast.insecure-random-for-code", "csharp", "class A { int MakeRecoveryCode() { return Random.Shared.Next(1000000); } }", true),
        ("ast.insecure-random-for-code", "csharp", "class A { void SendOtp() { var otp = RandomNumberGenerator.GetInt32(100000, 999999); Mail(otp); } }", false),
        ("ast.insecure-random-for-code", "csharp", "class A { int Roll() { var face = new Random().Next(1, 7); return face; } }", false),
        ("ast.insecure-random-for-code", "dart", "void sendOtp() { final otp = Random().nextInt(900000) + 100000; mail(otp); }", true),
        ("ast.insecure-random-for-code", "dart", "void sendOtp() { final otp = Random.secure().nextInt(900000) + 100000; mail(otp); }", false),
        ("ast.insecure-random-for-code", "dart", "void roll() { final face = Random().nextInt(6) + 1; show(face); }", false),
        ("ast.insecure-random-for-code", "c", "void notify(struct user *u) { int otp = rand() % 1000000; mail(u, otp); }", true),
        ("ast.insecure-random-for-code", "c", "int roll(void) { int face = rand() % 6 + 1; return face; }", false),
        ("ast.insecure-random-for-code", "cpp", "void notify(User& u) { int otp = std::rand() % 1000000; mail(u, otp); }", true),
        ("ast.insecure-random-for-code", "cpp", "int roll() { int face = std::rand() % 6 + 1; return face; }", false),
        ("ast.insecure-random-for-code", "shell", "notify() {\n  otp=$RANDOM\n  mail \"$1\" \"$otp\"\n}\n", true),
        ("ast.insecure-random-for-code", "shell", "make_reset_code() {\n  echo \"${RANDOM}${RANDOM}\"\n}\n", true),
        ("ast.insecure-random-for-code", "shell", "backoff() {\n  delay=$RANDOM\n  sleep $((delay % 5))\n}\n", false),
        // A web framework's debug mode switched on in the code.
        ("ast.debug-mode-on", "python", "if __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=True)\n", true),
        ("ast.debug-mode-on", "python", "if __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=False)\n", false),
        ("ast.debug-mode-on", "python", "app.run(debug=os.environ.get('FLASK_DEBUG') == '1')\n", false),
        ("ast.debug-mode-on", "python", "asyncio.run(main(), debug=True)\n", false),
        ("ast.debug-mode-on", "python", "socketio.run(app, debug=True)\n", true),
        ("ast.debug-mode-on", "python", "from werkzeug.serving import run_simple\nrun_simple('0.0.0.0', 5000, app, use_debugger=True)\n", true),
        ("ast.debug-mode-on", "python", "run_simple('0.0.0.0', 5000, app, use_reloader=True)\n", false),
        ("ast.debug-mode-on", "python", "app = FastAPI(title='Notes', debug=True)\n", true),
        ("ast.debug-mode-on", "python", "app = Starlette(debug=True, routes=routes)\n", true),
        ("ast.debug-mode-on", "python", "app = FastAPI(title='Notes')\n", false),
        ("ast.debug-mode-on", "python", "app = Flask(__name__)\napp.debug = True\n", true),
        ("ast.debug-mode-on", "python", "class Export:\n    def __init__(self):\n        self.debug = True\n", false),
        ("ast.debug-mode-on", "python", "app.config['DEBUG'] = True\n", true),
        ("ast.debug-mode-on", "python", "app.config['TESTING'] = True\n", false),
        ("ast.debug-mode-on", "python", "app.config.update(DEBUG=True, SECRET_KEY=key)\n", true),
        ("ast.debug-mode-on", "python", "app.config.update(TESTING=True)\n", false),
        ("ast.debug-mode-on", "python", "app.config.from_mapping(DEBUG=True)\n", true),
        ("ast.debug-mode-on", "python", "from bottle import run\nrun(app, host='0.0.0.0', port=8080, debug=True)\n", true),
        ("ast.debug-mode-on", "python", "run(app, host='0.0.0.0', port=8080)\n", false),
        ("ast.debug-mode-on", "python", "SECRET_KEY = os.environ['SECRET_KEY']\nDEBUG = True\nALLOWED_HOSTS = []\n", true),
        ("ast.debug-mode-on", "python", "DEBUG = os.environ.get('DJANGO_DEBUG') == '1'\n", false),
        ("ast.debug-mode-on", "python", "class DevelopmentConfig(Config):\n    DEBUG = True\n", false),
        ("ast.debug-mode-on", "python", "def settings():\n    DEBUG = True\n    return DEBUG\n", false),
        ("ast.debug-mode-on", "shell", "export FLASK_APP=app.py\nexport FLASK_DEBUG=1\nflask run\n", true),
        ("ast.debug-mode-on", "shell", "FLASK_DEBUG=true python app.py\n", true),
        ("ast.debug-mode-on", "shell", "export FLASK_DEBUG=0\nflask run\n", false),
        ("ast.debug-mode-on", "shell", "flask --app app run --debug --port 8000\n", true),
        ("ast.debug-mode-on", "shell", "flask --app app run --port 8000\n", false),
        ("ast.debug-mode-on", "shell", "gunicorn --debug app:app\n", false),
        ("ast.check-passes-on-error", "python", "def verify_token(t):\n    try:\n        jwt.decode(t, KEY, algorithms=['HS256'])\n        return True\n    except Exception:\n        return True\n", true),
        ("ast.check-passes-on-error", "python", "class Perms:\n    @staticmethod\n    def has_permission(user, thing):\n        try:\n            return lookup(user, thing)\n        except KeyError:\n            log.warning('no entry')\n            return True\n", true),
        ("ast.check-passes-on-error", "python", "def verify_token(t):\n    try:\n        jwt.decode(t, KEY, algorithms=['HS256'])\n        return True\n    except Exception:\n        return False\n", false),
        ("ast.check-passes-on-error", "python", "def is_cached(key):\n    try:\n        return key in CACHE\n    except Exception:\n        return True\n", false),
        ("ast.check-passes-on-error", "python", "def invalidate_session(s):\n    try:\n        s.clear()\n    except Exception:\n        return True\n", false),
        ("ast.check-passes-on-error", "javascript", "function verifyToken(t) { try { jwt.verify(t, KEY); return true; } catch (e) { return true; } }", true),
        ("ast.check-passes-on-error", "javascript", "const requireAuth = (req, res, next) => { try { req.user = jwt.verify(req.cookies.t, KEY); next(); } catch (e) { next(); } };", true),
        ("ast.check-passes-on-error", "javascript", "exports.isAllowed = async (u, r) => { try { return await acl.check(u, r); } catch (e) { return true; } };", true),
        ("ast.check-passes-on-error", "javascript", "const requireAuth = (req, res, next) => { try { req.user = jwt.verify(req.cookies.t, KEY); next(); } catch (e) { next(e); } };", false),
        ("ast.check-passes-on-error", "javascript", "function verifyToken(t) { try { jwt.verify(t, KEY); return true; } catch (e) { return false; } }", false),
        ("ast.check-passes-on-error", "javascript", "function loadPrefs() { try { return JSON.parse(s); } catch (e) { return true; } }", false),
        ("ast.check-passes-on-error", "typescript", "class AuthGuard { canActivate(ctx: ExecutionContext): boolean { try { return this.check(ctx); } catch (e) { return true; } } }", true),
        ("ast.check-passes-on-error", "typescript", "class AuthGuard { canActivate(ctx: ExecutionContext): boolean { try { return this.check(ctx); } catch (e) { throw new UnauthorizedException(); } } }", false),
        ("ast.check-passes-on-error", "ruby", "def authorized?(user)\n  policy.check!(user)\nrescue StandardError => e\n  Rails.logger.warn(e)\n  true\nend\n", true),
        ("ast.check-passes-on-error", "ruby", "def verify_signature(sig)\n  begin\n    webhook.verify!(body, sig)\n  rescue\n    return true\n  end\nend\n", true),
        ("ast.check-passes-on-error", "ruby", "def authorized?(user)\n  policy.check!(user)\nrescue StandardError\n  false\nend\n", false),
        ("ast.check-passes-on-error", "ruby", "def warm_cache\n  load_all\nrescue StandardError\n  true\nend\n", false),
        ("ast.check-passes-on-error", "php", "<?php function verifyToken($t) { try { JWT::decode($t, $k); return true; } catch (Exception $e) { return TRUE; } }", true),
        ("ast.check-passes-on-error", "php", "<?php function verifyToken($t) { try { JWT::decode($t, $k); return true; } catch (Exception $e) { return false; } }", false),
        ("ast.check-passes-on-error", "java", "class A { boolean isAuthorized(User u) { try { return acl.check(u); } catch (Exception e) { return true; } } }", true),
        ("ast.check-passes-on-error", "java", "class A { boolean isAuthorized(User u) { try { return acl.check(u); } catch (Exception e) { return false; } } }", false),
        ("ast.check-passes-on-error", "csharp", "class A { bool ValidateToken(string t) { try { handler.ValidateToken(t, p, out _); return true; } catch (Exception) { return true; } } }", true),
        ("ast.check-passes-on-error", "csharp", "class A { bool ValidateToken(string t) { try { handler.ValidateToken(t, p, out _); return true; } catch (Exception) { return false; } } }", false),
        ("ast.check-passes-on-error", "kotlin", "fun verifyToken(t: String): Boolean { try { verifier.verify(t) } catch (e: Exception) { return true }; return true }", true),
        ("ast.check-passes-on-error", "kotlin", "fun verifyToken(t: String): Boolean = try { verifier.verify(t); true } catch (e: Exception) { true }", true),
        ("ast.check-passes-on-error", "kotlin", "fun verifyToken(t: String): Boolean = try { verifier.verify(t); true } catch (e: Exception) { false }", false),
        ("ast.check-passes-on-error", "swift", "func verifyToken(_ t: String) -> Bool { do { try verifier.verify(t) } catch { return true }; return true }", true),
        ("ast.check-passes-on-error", "swift", "func verifyToken(_ t: String) -> Bool { do { try verifier.verify(t) } catch { return false }; return true }", false),
        ("ast.check-passes-on-error", "dart", "bool verifyToken(String t) { try { verifier.verify(t); } catch (e) { return true; } return true; }", true),
        ("ast.check-passes-on-error", "dart", "class A { bool isAllowed(String u) { try { return acl.check(u); } on FormatException { return true; } } }", true),
        ("ast.check-passes-on-error", "dart", "bool verifyToken(String t) { try { verifier.verify(t); } catch (e) { return false; } return true; }", false),
        ("ast.check-passes-on-error", "go", "package m\nfunc verifyToken(t string) bool { _, err := jwt.Parse(t, keyFunc); if err != nil { return true }; return true }", true),
        ("ast.check-passes-on-error", "go", "package m\nfunc (a *Auth) CheckAccess(u string) (bool, error) { ok, err := a.acl.Allowed(u); if err != nil { return true, nil }; return ok, nil }", true),
        ("ast.check-passes-on-error", "go", "package m\nfunc verifyToken(t string) bool { _, err := jwt.Parse(t, keyFunc); if err != nil { return false }; return true }", false),
        ("ast.check-passes-on-error", "go", "package m\nfunc isAllowed(u string) bool { r := roles[u]; if r != nil { return true }; return false }", false),
        ("ast.check-passes-on-error", "go", "package m\nfunc loadConfig(p string) bool { _, err := os.Stat(p); if err != nil { return true }; return false }", false),
        ("ast.check-passes-on-error", "rust", "fn verify_token(t: &str) -> bool { decode::<Claims>(t, &KEY, &V).map(|_| true).unwrap_or(true) }", true),
        ("ast.check-passes-on-error", "rust", "fn is_allowed(u: &User) -> bool { match acl.check(u) { Ok(ok) => ok, Err(_) => true } }", true),
        ("ast.check-passes-on-error", "rust", "fn verify_token(t: &str) -> bool { decode::<Claims>(t, &KEY, &V).map(|_| true).unwrap_or(false) }", false),
        ("ast.check-passes-on-error", "rust", "fn is_allowed(u: &User) -> bool { match acl.check(u) { Ok(_) => true, Err(_) => false } }", false),
        ("ast.check-passes-on-error", "cpp", "bool Auth::verifyToken(const std::string& t) { try { verifier.verify(t); return true; } catch (...) { return true; } }", true),
        ("ast.check-passes-on-error", "cpp", "bool Auth::verifyToken(const std::string& t) { try { verifier.verify(t); return true; } catch (...) { return false; } }", false),
        ("ast.check-passes-on-error", "shell", "verify_checksum() {\n  sha256sum -c \"$1.sha256\" || return 0\n  return 0\n}\n", true),
        ("ast.check-passes-on-error", "shell", "verify_checksum() {\n  sha256sum -c \"$1.sha256\" || return 1\n  return 0\n}\n", false),
        ("ast.check-passes-on-error", "shell", "cleanup() {\n  rm -f \"$TMP\" || return 0\n}\n", false),
    ];

    #[test]
    fn a_query_name_handed_over_with_values_is_reported_with_low_confidence() {
        // A1 of the deep review: values passed beside a query are how placeholders are used, so a
        // query that is only a name the file does not settle is reported, but as possible.
        let rules = rules();
        let sql = |source: &str| -> Vec<Finding> {
            scan_file(rules, "python", "src/app.py", source)
                .into_iter()
                .filter(|f| f.rule_id == "ast.sql-built-by-hand")
                .collect()
        };
        let named = sql("def f(db, sql, uid):\n    db.execute(sql, (uid,))\n");
        assert_eq!(named.len(), 1, "{named:?}");
        assert_eq!(named[0].confidence, Confidence::Low);
        assert!(
            named[0].description.contains("how placeholders are used"),
            "{}",
            named[0].description
        );

        // The control: the same name with nothing beside it, and text built in the call itself even
        // with values beside it, keep the rule's own confidence.
        let alone = sql("def f(db, sql):\n    db.execute(sql)\n");
        assert_eq!(alone.len(), 1, "{alone:?}");
        assert_eq!(alone[0].confidence, Confidence::Medium);
        let built = sql(
            "def f(db, name, uid):\n    db.execute(f\"SELECT * FROM t WHERE n = '{name}'\", (uid,))\n",
        );
        assert_eq!(built.len(), 1, "{built:?}");
        assert_eq!(built[0].confidence, Confidence::Medium);
        assert!(!built[0].description.contains("placeholders are used"));
    }

    #[test]
    fn a_name_is_fixed_only_where_the_file_binds_it_once_to_fixed_text() {
        // `Fixed` read directly, so a rule's own filters cannot hide what it decided.
        let fixed_names = |language: &str, source: &str| -> (Vec<String>, Vec<String>) {
            let mut parser = Parser::new();
            parser.set_language(&grammar(language).unwrap()).unwrap();
            let tree = parser.parse(source, None).unwrap();
            let fixed = Fixed::of(tree.root_node(), source.as_bytes());
            (
                fixed.names.into_iter().collect(),
                fixed.tables.into_iter().collect(),
            )
        };
        let (names, tables) = fixed_names(
            "python",
            "UPLOAD_DIR = os.environ[\"DIR\"]\nQ = \"SELECT 1\"\nT = {\"a\": \"x\", \"b\": Q}\ndef f(p, q2=Q):\n    once = \"text\"\n    twice = \"a\"\n    twice = \"b\"\n    for loop in p:\n        pass\n    up = 1\n    up += 1\ndef g():\n    lower_top = request.x\n",
        );
        assert_eq!(names, ["Q", "UPLOAD_DIR", "once"], "{names:?}");
        assert_eq!(tables, ["T"], "{tables:?}");
        // A parameter's default names a constant without binding it: Q stays fixed above, and q2,
        // the parameter, is not.
        let (names, _) = fixed_names(
            "go",
            "package main\nconst q = \"SELECT 1\"\nvar v = \"x\"\nfunc f(ctx context.Context, p string) { w := \"y\"; w = p }\n",
        );
        assert_eq!(names, ["q", "v"], "{names:?}");
        let (names, tables) = fixed_names(
            "javascript",
            "const A = 'x';\nlet b = 'y';\nb = b + z;\nconst T = { k: A, l: 'm' };\nfunction f(c = A) { const d = `t`; }\n",
        );
        assert_eq!(names, ["A", "d"], "{names:?}");
        assert_eq!(tables, ["T"], "{tables:?}");
    }

    #[test]
    fn a_pbkdf2_count_below_1_300_000_is_reported_where_the_call_names_sha_1() {
        // Where naming SHA-1 also fires another rule (the hash itself in C, C++, and Ruby's
        // `Digest::SHA1`; `openssl enc`'s unauthenticated cipher), the witness table above cannot
        // hold a positive, so these are here, each with its count at 1,300,000 as the control.
        let rules = rules();
        for (language, below, at) in [
            (
                "c",
                "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1299999, EVP_sha1(), 32, out); }",
                "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1300000, EVP_sha1(), 32, out); }",
            ),
            (
                "cpp",
                "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1000000, EVP_sha1(), 32, out); }",
                "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1300000, EVP_sha1(), 32, out); }",
            ),
            (
                "ruby",
                "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 1_000_000, 32, OpenSSL::Digest::SHA1.new)",
                "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 1_300_000, 32, OpenSSL::Digest::SHA1.new)",
            ),
            (
                "shell",
                "openssl enc -aes-256-cbc -pbkdf2 -md sha1 -iter 1000000 -in a -out b",
                "openssl enc -aes-256-cbc -pbkdf2 -md sha1 -iter 1300000 -in a -out b",
            ),
        ] {
            let fires = |source: &str| {
                ids(&scan_file(
                    rules,
                    language,
                    &format!("src/app.{language}"),
                    source,
                ))
                .contains(&"ast.weak-password-key-derivation")
            };
            assert!(fires(below), "{language}: {below}");
            assert!(!fires(at), "{language}: {at}");
        }
    }

    #[test]
    fn a_functions_name_is_read_as_its_words_whatever_its_style() {
        for (name, words) in [
            ("verifyToken", "verify_token"),
            ("VerifyToken", "verify_token"),
            ("verify_token", "verify_token"),
            ("verify-token", "verify_token"),
            ("isJWTValid", "is_jwt_valid"),
            ("authorized?", "authorized"),
            ("check2FA", "check2_fa"),
            ("__init__", "init"),
        ] {
            assert_eq!(words_of(name), words, "{name}");
        }
    }

    #[test]
    fn the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one() {
        let rules = rules();
        let mut wrong = Vec::new();
        for (rule, language, source, expected) in WITNESSES {
            let findings = scan_file(rules, language, &format!("src/app.{language}"), source);
            let found = ids(&findings).contains(rule);
            if found != *expected {
                wrong.push(format!(
                    "{rule} in {language} {} `{source}`",
                    if *expected { "missed" } else { "reported" }
                ));
            }
            // A negative that another rule reports is still a negative for this one, but a
            // positive that fires a second, unrelated rule is a query matching too much.
            if *expected && let Some(other) = findings.iter().find(|f| f.rule_id != *rule) {
                wrong.push(format!(
                    "{rule} in {language}: `{source}` also fired {}",
                    other.rule_id
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));

        // Every language each of these rules claims has a witness both ways. A query with no found
        // case is a query that may never fire; one with no not-found case may fire on everything.
        //
        // Which pairs that covers: every language of the four rules written with this table, every
        // rule's Dart, Swift, and shell, and any other language the table has a line for at all. The older
        // rules' first languages are witnessed by the tests above instead.
        const WRITTEN_WITH_THIS_TABLE: &[&str] = &[
            "ast.file-path-from-value",
            "ast.weak-hash-function",
            "ast.weak-cipher",
            "ast.open-redirect",
            "ast.plaintext-websocket-url",
            "ast.unauthenticated-encryption",
            "ast.digest-compared-with-equals",
            "ast.model-loaded-with-pickle",
            "ast.model-download-not-pinned",
            "ast.floating-model-name",
            "ast.weak-password-key-derivation",
            "ast.static-files-from-app-folder",
            "ast.token-audience-not-checked",
            "ast.token-key-source-from-token",
            "ast.account-found-by-provider-email",
            "ast.check-passes-on-error",
            "ast.insecure-random-for-code",
        ];
        let mut unwitnessed = Vec::new();
        for (rule_id, languages, _) in rules.coverage() {
            for language in languages {
                let owed = WRITTEN_WITH_THIS_TABLE.contains(&rule_id)
                    || matches!(language, "dart" | "swift" | "shell")
                    || WITNESSES
                        .iter()
                        .any(|(r, l, ..)| *r == rule_id && *l == language);
                if !owed {
                    continue;
                }
                for want in [true, false] {
                    if !WITNESSES
                        .iter()
                        .any(|(r, l, _, e)| *r == rule_id && *l == language && *e == want)
                    {
                        unwitnessed.push(format!("{rule_id} {language} has no {want} case"));
                    }
                }
            }
        }
        assert!(unwitnessed.is_empty(), "{}", unwitnessed.join("\n"));
    }

    /// Prints the parse tree of a snippet, for writing a query against what the grammar really
    /// produces rather than what it plausibly does. Not a test; run by hand:
    ///
    /// `SV_DUMP_LANG=dart SV_DUMP_SRC='…' cargo test -p sv-check --lib dump_trees -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn dump_trees() {
        let lang = std::env::var("SV_DUMP_LANG").unwrap();
        let src = std::env::var("SV_DUMP_SRC").unwrap();
        let mut parser = Parser::new();
        parser.set_language(&grammar(&lang).unwrap()).unwrap();
        let tree = parser.parse(&src, None).unwrap();
        println!("{}", tree.root_node().to_sexp());
    }
}
