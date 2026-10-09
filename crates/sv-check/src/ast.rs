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

mod fixed;
mod html;
mod templates;
pub(crate) use fixed::*;
pub use html::*;
use templates::*;

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
    /// Per ecosystem (as the bill of materials names it: `npm`, `Python`, `Go`, `PHP`), packages
    /// that build queries through calls of their own this rule does not read, each with those calls
    /// in a few words. While the app ships one, the rule claims nothing.
    ///
    /// knex's `whereRaw("name = '" + name + "'")` is the same flaw as a query joined by hand, and a
    /// rule that has not been taught `whereRaw` finds nothing in it. Until 9 October 2026 that
    /// nothing credited V1.2.4 for an app whose every query went through such a call (the gap
    /// analysis of 7 October 2026, finding 1). A package comes off the list in the change that
    /// teaches the rule its calls.
    #[serde(default)]
    pub unread_packages: BTreeMap<String, BTreeMap<String, String>>,
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
    /// Rules that claim nothing because the app ships a package that builds queries through calls
    /// the rule does not read (`AstRule::unread_packages`), set by [`hold_back_for_packages`].
    pub held_back_by_packages: Vec<HeldBackByPackage>,
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

/// One rule kept from claiming anything by a package the app ships, and the calls of that package
/// the rule does not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldBackByPackage {
    pub rule_id: String,
    pub ecosystem: String,
    pub package: String,
    pub calls: String,
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
/// Takes back the clean result of every rule whose `unread_packages` names a package the app uses,
/// and says which package: the rule cannot see the queries built through it, so finding nothing is
/// no evidence they keep values apart (ADR-018, Later, 9 October 2026). Findings stay. `uses` is
/// every (ecosystem, name) the app's lockfiles list or its manifests declare: an app with only a
/// `package.json` lists nothing in its bill of materials and still uses knex.
pub fn hold_back_for_packages<'a>(
    rules: &AstRules,
    scan: &mut AstScan,
    uses: impl IntoIterator<Item = (&'a str, &'a str)>,
) {
    let uses: Vec<(&str, &str)> = uses.into_iter().collect();
    for rule in rules.rules() {
        for (ecosystem, packages) in &rule.unread_packages {
            for (_, name) in uses.iter().filter(|(e, _)| e == ecosystem) {
                let Some((package, calls)) = packages
                    .iter()
                    .find(|(listed, _)| package_names_match(listed, name))
                else {
                    continue;
                };
                if !scan.held_back_by_packages.iter().any(|h| {
                    h.rule_id == rule.id && h.ecosystem == *ecosystem && h.package == *package
                }) {
                    scan.held_back_by_packages.push(HeldBackByPackage {
                        rule_id: rule.id.clone(),
                        ecosystem: ecosystem.clone(),
                        package: package.clone(),
                        calls: calls.clone(),
                    });
                }
            }
        }
    }
    let held = &scan.held_back_by_packages;
    scan.verified
        .retain(|v| !held.iter().any(|h| h.rule_id == v.check_id));
}

/// A package's name as a rule writes it against the name a manifest gave, without regard to case or
/// to `-`, `_`, and `.`: Python's rule (PEP 503), and harmless elsewhere, where names are written in
/// lower case and a name still matches itself.
fn package_names_match(listed: &str, shipped: &str) -> bool {
    let normal = |name: &str| name.to_ascii_lowercase().replace(['_', '.'], "-");
    listed == shipped || normal(listed) == normal(shipped)
}

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
    let words_only = |p: &str| {
        p.replace("\\$", "")
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_|()^$?!*+".contains(c))
    };
    // A chained call written as a trailing `|\.(?:a|b)$` (knex's `db('t').whereRaw(…)`, whose whole
    // chain is the name matched) can be in a file only as one of its names, so it narrows no less
    // than the names before it when every one of them is among those names.
    if let Some((rest, chained)) = pattern.rsplit_once("|\\.(?:")
        && let Some(names) = chained.strip_suffix(")$")
        && words_only(rest)
        && words_only(names)
    {
        let listed: Vec<&str> = rest
            .split(|c: char| "|()^$".contains(c))
            .filter(|w| !w.is_empty())
            .collect();
        return names.split('|').all(|n| listed.contains(&n));
    }
    words_only(pattern)
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
    // A chained form after the names (`|\\.(?:whereRaw)$`) repeats names already among them.
    let pattern = pattern
        .rsplit_once("|\\.(?:")
        .filter(|(_, chained)| chained.ends_with(")$"))
        .map_or(pattern, |(names, _)| names);
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

#[cfg(test)]
mod tests;

#[cfg(test)]
mod body_whole_tests;
#[cfg(test)]
mod fetch_tests;
#[cfg(test)]
mod html_tests;

#[cfg(test)]
mod orm_raw_tests;

#[cfg(test)]
mod orm_npm_tests;

#[cfg(test)]
mod orm_django_laravel_tests;
