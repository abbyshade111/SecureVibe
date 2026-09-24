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
//! # Queries are data, judgement is code
//!
//! `data/ast-rules.json` holds a tree-sitter query per language, so teaching a rule about Ruby is a data
//! entry. What a query cannot express is judgement — "the argument is a literal, so this `eval` is ugly
//! rather than dangerous" — and that lives here, in Rust, where it can be tested. It is the same split
//! as the secrets scanner: patterns as data, the decision about what they mean as code.
//!
//! # A language with no grammar is a language not read
//!
//! Ruby, PHP and Java have no grammar compiled in yet, so files in them are not scanned — and that is
//! reported rather than left to look like a clean result, the same way the secrets scanner reports the
//! files it skipped.

use crate::finding::{Confidence, Finding, Location, Severity};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
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
    /// One tree-sitter query per language. A language absent here is one this rule says nothing about.
    pub queries: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(rename = "_comment", default)]
    _comment: String,
    rules: Vec<AstRule>,
}

/// A rule with its queries compiled, one per language.
struct Compiled {
    rule: AstRule,
    queries: BTreeMap<String, Query>,
    function: BTreeMap<String, regex::Regex>,
    module: BTreeMap<String, regex::Regex>,
}

pub struct AstRules {
    compiled: Vec<Compiled>,
}

/// The languages a grammar is compiled in for.
fn grammar(language: &str) -> Option<Language> {
    Some(match language {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
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
                let query = Query::new(&grammar, source).with_context(|| {
                    format!(
                        "rule {} has a {language} query tree-sitter cannot compile",
                        rule.id
                    )
                })?;
                queries.insert(language.clone(), query);
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
            compiled.push(Compiled {
                rule,
                queries,
                function,
                module,
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
fn is_literal(node: tree_sitter::Node) -> bool {
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
    ];

    // `"a" + "b"` is still a constant; `"a" + name` is not.
    if matches!(node.kind(), "binary_operator" | "binary_expression") {
        let mut cursor = node.walk();
        return node.named_children(&mut cursor).all(is_literal);
    }
    if !LITERAL_KINDS.contains(&node.kind()) {
        return false;
    }
    // Anything with a value substituted into it was built, not written: a JavaScript template string
    // with `${…}` and a Python f-string with `{…}` are the same thing under different node names, and
    // an f-string is still a plain `string` node in its grammar. Missing this reports every SQL query
    // built with an f-string as a constant, which is the case the rule exists for.
    !has_interpolation(node)
}

/// Whether anything is substituted into this literal, however deeply.
fn has_interpolation(node: tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "interpolation" | "template_substitution" | "string_interpolation" | "format_specifier"
        ) || has_interpolation(child)
    })
}

#[derive(Debug, Default)]
pub struct AstScan {
    pub findings: Vec<Finding>,
    /// Languages present in the app that no grammar reads, so nothing is claimed about them.
    pub unread_languages: BTreeSet<String>,
    pub files_parsed: usize,
}

/// Runs every rule that has a query for this language over one file.
pub fn scan_file(rules: &AstRules, language: &str, relative: &str, source: &str) -> Vec<Finding> {
    let Some(grammar) = grammar(language) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for compiled in &rules.compiled {
        let Some(query) = compiled.queries.get(language) else {
            continue;
        };
        let arg_index = query.capture_index_for_name("arg");
        let hit_index = query.capture_index_for_name("hit");
        let fn_index = query.capture_index_for_name("fn");
        let mod_index = query.capture_index_for_name("mod");
        let text_of = |m: &tree_sitter::QueryMatch, index: Option<u32>| -> Option<String> {
            let index = index?;
            let capture = m.captures.iter().find(|c| c.index == index)?;
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
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.module.get(language) {
                match text_of(m, mod_index) {
                    Some(name) if pattern.is_match(&name) => {}
                    _ => continue,
                }
            }
            // A literal argument means the call cannot be made to do anything the author did not write.
            if compiled.rule.literal_argument_is_safe
                && let Some(index) = arg_index
                && let Some(capture) = m.captures.iter().find(|c| c.index == index)
                && is_literal(capture.node)
            {
                continue;
            }
            let node = hit_index
                .and_then(|index| m.captures.iter().find(|c| c.index == index))
                .map(|c| c.node)
                .or_else(|| m.captures.first().map(|c| c.node));
            let Some(node) = node else { continue };
            out.push(Finding {
                rule_id: compiled.rule.id.clone(),
                title: compiled.rule.title.clone(),
                severity: compiled.rule.severity,
                confidence: compiled.rule.confidence,
                location: Location {
                    file: relative.to_owned(),
                    line: node.start_position().row + 1,
                },
                secret: None,
                requirement_ids: compiled.rule.requirement_ids.clone(),
                cwe: compiled.rule.cwe.clone(),
                description: compiled.rule.description.clone(),
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
    out
}

/// Runs the rules over every source file in the app whose language has a grammar.
///
/// Languages present but unread are recorded rather than skipped quietly. A Ruby app scanned by a tool
/// with no Ruby grammar produces no findings, and "no findings" is what a clean app produces too.
pub fn scan_dir(rules: &AstRules, app_dir: &std::path::Path) -> AstScan {
    let mut scan = AstScan::default();
    walk(app_dir, app_dir, rules, &mut scan);
    scan.findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });
    scan
}

fn walk(root: &std::path::Path, dir: &std::path::Path, rules: &AstRules, scan: &mut AstScan) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if sv_scan::ecosystems::SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(root, &path, rules, scan);
            continue;
        }
        let Some(extension) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let Some(language) = sv_scan::ecosystems::language_of(&extension.to_lowercase()) else {
            continue;
        };
        if !is_supported(language) {
            // Present, and not read. The rules have nothing to say about this file and the report
            // should say that rather than let its silence be read as approval.
            scan.unread_languages.insert(language.to_owned());
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        scan.files_parsed += 1;
        scan.findings
            .extend(scan_file(rules, language, &relative, &source));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn rules() -> AstRules {
        AstRules::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json"))
            .expect("rules load")
    }

    fn scan(language: &str, source: &str) -> Vec<Finding> {
        scan_file(&rules(), language, &format!("src/app.{language}"), source)
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn every_query_in_the_data_file_compiles() {
        // A query tree-sitter cannot compile is a rule that silently never fires, which looks exactly
        // like a rule finding nothing.
        let rules = rules();
        assert!(rules.len() >= 4, "only {} rules loaded", rules.len());
        assert!(rules.languages().contains("python"));
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
        // Quietly dropping it would leave a rule that claims to cover Ruby and never runs.
        let refused = rules_from(&ONE_RULE.replace("\"python\"", "\"ruby\""));
        let error = match refused {
            Ok(_) => panic!("an unknown language must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("no grammar"), "{error}");
    }

    #[test]
    fn a_query_tree_sitter_cannot_compile_is_refused_at_load() {
        let refused = rules_from(&ONE_RULE.replace("QUERY", "(this is not a query"));
        let error = match refused {
            Ok(_) => panic!("a broken query must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("cannot compile"), "{error}");
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
        assert!(scan_file(&rules(), "ruby", "app.rb", "eval(params[:x])").is_empty());
        assert!(!is_supported("ruby"));
        assert!(is_supported("python") && is_supported("typescript"));
    }
}
