//! `sv brief`: what one feature brings, before it is built (`data/feature-briefs.json`).
//!
//! The plan (`plan.rs`) speaks for the whole app; a brief speaks for one feature about to be built:
//! sign-in, uploads, payments, an AI feature, and the rest the data file names. Like the plan, it
//! is built from the report's own parts, so the two cannot disagree: the requirements are the
//! report's applicable ones that the feature brings, and the tests to write are the report's own,
//! for those requirements. Its own parts are the design-time prompts for the decisions to make
//! first, the coding rules that cite one of its requirements, and the settings `sv run` needs to
//! test it, quoted from the starter `securevibe.toml` so they cannot drift from the spec.
//!
//! # What it is worth
//!
//! Nothing, as evidence: a brief says what a feature will be held to, never what was built.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use sv_frameworks::applicability::{ApplicabilityConfig, requirement_ids_gated_on};
use sv_frameworks::{Condition, Frameworks};

/// One table and key in `securevibe.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Setting {
    pub table: String,
    pub key: String,
}

/// A feature, as the data file names it.
#[derive(Debug, Clone)]
pub(crate) struct Feature {
    pub id: String,
    pub name: String,
    /// The conditions whose requirements it brings.
    pub conditions: Vec<Condition>,
    /// Requirements it brings that no condition gates.
    pub requirements: Vec<String>,
    /// Design-time prompts, by id.
    pub prompts: Vec<String>,
    /// Topics of the coding rules (`securevibe_guidance`) that bear on building it.
    pub guidance: Vec<String>,
    pub settings: Vec<Setting>,
}

#[derive(Debug, Clone)]
pub(crate) struct Features {
    pub features: Vec<Feature>,
}

impl Features {
    pub(crate) fn load(path: &std::path::Path) -> Result<Features> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let value: Value =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Self::from_value(&value).with_context(|| format!("reading {}", path.display()))
    }

    /// The features, every field required and every condition one `sv` knows: a feature whose
    /// condition is misspelt would otherwise bring nothing, and say so to nobody.
    fn from_value(value: &Value) -> Result<Features> {
        let text = |f: &Value, k: &str| -> Result<String> {
            f.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| format!("a feature has no `{k}`"))
        };
        let list = |f: &Value, k: &str| -> Result<Vec<Value>> {
            f.get(k)
                .and_then(Value::as_array)
                .cloned()
                .with_context(|| format!("a feature has no `{k}` list"))
        };
        let words = |f: &Value, k: &str| -> Result<Vec<String>> {
            list(f, k)?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .with_context(|| format!("`{k}` holds something that is not text"))
                })
                .collect()
        };
        let mut features = Vec::new();
        for f in value
            .get("features")
            .and_then(Value::as_array)
            .context("no `features` list")?
        {
            let id = text(f, "id")?;
            let conditions = words(f, "conditions")?
                .iter()
                .map(|c| {
                    Condition::from_name(c)
                        .with_context(|| format!("{id}: no condition is named `{c}`"))
                })
                .collect::<Result<Vec<_>>>()?;
            let settings = list(f, "settings")?
                .iter()
                .map(|s| {
                    Ok(Setting {
                        table: text(s, "table")?,
                        key: text(s, "key")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            features.push(Feature {
                name: text(f, "name")?,
                conditions,
                requirements: words(f, "requirements")?,
                prompts: words(f, "prompts")?,
                guidance: words(f, "guidance")?,
                settings,
                id,
            });
        }
        Ok(Features { features })
    }

    /// The feature named `id`, or an error naming every feature there is.
    pub(crate) fn get(&self, id: &str) -> Result<&Feature> {
        match self.features.iter().find(|f| f.id == id) {
            Some(f) => Ok(f),
            None => bail!(
                "there is no brief for `{id}`. The features with one: {}.",
                self.ids().join(", ")
            ),
        }
    }

    pub(crate) fn ids(&self) -> Vec<&str> {
        self.features.iter().map(|f| f.id.as_str()).collect()
    }
}

/// A requirement the feature brings that applies to this app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Applies {
    pub id: String,
    pub level: u8,
    pub description: String,
}

/// A design-time prompt, whole, for the AI coding tool to work from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptText {
    pub id: String,
    pub title: String,
    pub status: &'static str,
    pub text: String,
}

/// A coding rule on one of the topics that bear on building the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleRef {
    pub id: String,
    pub topic: String,
    pub rule: String,
}

/// A setting `sv run` needs, with the lines of the starter `securevibe.toml` that describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SettingBlock {
    pub table: String,
    pub key: String,
    pub lines: String,
}

/// One feature's brief, for one app.
#[derive(Debug, Clone)]
pub(crate) struct Brief {
    pub app: String,
    pub level: u8,
    pub feature: String,
    pub name: String,
    pub requirements: Vec<Applies>,
    /// Requirements the feature's own conditions gate, within the app's level, that do not apply
    /// yet because securevibe.toml does not say the app has the feature: what building it brings.
    pub pending: Vec<Applies>,
    /// The conditions securevibe.toml would have to answer yes for `pending` to apply.
    pub conditions: Vec<String>,
    /// How many of the feature's requirements neither apply nor are pending: above the app's
    /// level, or brought only by its own list and ruled out.
    pub not_applying: usize,
    pub prompts: Vec<PromptText>,
    pub rules: Vec<RuleRef>,
    pub tests: Vec<sv_report::TestToWrite>,
    pub settings: Vec<SettingBlock>,
}

/// Every requirement the feature brings, at every level: those its conditions gate (`gated`), and
/// those it names.
pub(crate) struct Brought {
    pub all: BTreeSet<String>,
    pub gated: BTreeSet<String>,
}

pub(crate) fn brought(
    feature: &Feature,
    frameworks: &Frameworks,
    config: &ApplicabilityConfig,
) -> Brought {
    let mut gated = BTreeSet::new();
    for c in &feature.conditions {
        gated.extend(requirement_ids_gated_on(frameworks, config, *c));
    }
    let mut all = gated.clone();
    all.extend(feature.requirements.iter().cloned());
    Brought { all, gated }
}

/// The lines of the starter `securevibe.toml` that describe `key` in `table`: its own line and the
/// indented ones under it. `None` when the starter file does not describe it.
pub(crate) fn setting_lines(table: &str, key: &str) -> Option<String> {
    let mut in_table = false;
    let mut out: Vec<&str> = Vec::new();
    for line in sv_manifest::spec::STARTER_MANIFEST.lines() {
        let bare = line.trim_start_matches('#').trim();
        if bare.starts_with('[') {
            if !out.is_empty() {
                break;
            }
            in_table = bare == format!("[{table}]");
            continue;
        }
        if !in_table {
            continue;
        }
        let names_key = bare
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with('='));
        if out.is_empty() {
            if names_key {
                out.push(line);
            }
        } else if line.starts_with("#  ") {
            // A key's own line has one space after the `#`; the lines that go on explaining it
            // are indented further.
            out.push(line);
        } else {
            break;
        }
    }
    (!out.is_empty()).then(|| out.join("\n"))
}

/// The brief for one feature of an app, from its report.
pub(crate) fn from_report(
    report: &sv_report::Report,
    feature: &Feature,
    brought: &Brought,
    frameworks: &Frameworks,
    design_prompts: &sv_check::prompts::Prompts,
    coding_rules: &sv_check::coding_rules::CodingRules,
) -> Brief {
    let requirements: Vec<Applies> = report
        .requirements
        .iter()
        .filter(|r| brought.all.contains(&r.id))
        .map(|r| Applies {
            id: r.id.clone(),
            level: r.level,
            description: r.description.clone(),
        })
        .collect();
    let applying: BTreeSet<&str> = requirements.iter().map(|r| r.id.as_str()).collect();
    // A requirement gated on the feature's own condition applies as soon as securevibe.toml says
    // yes to it, since an applicability rule's conditions are any-of; those within the app's level
    // that do not apply now are what building the feature brings.
    let mut pending: Vec<Applies> = brought
        .gated
        .iter()
        .filter(|id| !applying.contains(id.as_str()))
        .filter_map(|id| frameworks.requirements.get(id))
        .filter(|r| r.level <= report.target_level)
        .map(|r| Applies {
            id: r.id.clone(),
            level: r.level,
            description: r.description.clone(),
        })
        .collect();
    // The report's order for its tests to write: by level, ASVS before AISVS, then by number, so
    // C2.1.1 comes before C11.1.1.
    let order = |r: &Applies| {
        let numbers: Vec<u32> =
            r.id.trim_start_matches(|c: char| c.is_ascii_alphabetic())
                .split('.')
                .filter_map(|n| n.parse().ok())
                .collect();
        (r.level, !r.id.starts_with('V'), numbers)
    };
    pending.sort_by_key(order);
    let prompts = feature
        .prompts
        .iter()
        .filter_map(|id| design_prompts.prompts.iter().find(|p| &p.id == id))
        .map(|p| PromptText {
            id: p.id.clone(),
            title: p.title.clone(),
            status: p.status.as_str(),
            text: p.prompt.clone(),
        })
        .collect();
    // The coding rules cite AISVS Appendix C, how the AI coding tool works, never a requirement of
    // the app; so a feature names the topics that bear on building it, and the brief gives those.
    let rules = coding_rules
        .rules
        .iter()
        .filter(|r| feature.guidance.contains(&r.topic))
        .map(|r| RuleRef {
            id: r.id.clone(),
            topic: r.topic.clone(),
            rule: r.rule.clone(),
        })
        .collect();
    let tests = report
        .tests_to_write
        .iter()
        .filter(|t| applying.contains(t.id.as_str()))
        .cloned()
        .collect();
    let settings = feature
        .settings
        .iter()
        .filter_map(|s| {
            setting_lines(&s.table, &s.key).map(|lines| SettingBlock {
                table: s.table.clone(),
                key: s.key.clone(),
                lines,
            })
        })
        .collect();
    Brief {
        app: report.app_name.clone(),
        level: report.target_level,
        feature: feature.id.clone(),
        name: feature.name.clone(),
        not_applying: brought.all.len() - requirements.len() - pending.len(),
        conditions: feature
            .conditions
            .iter()
            .map(|c| c.name().to_owned())
            .collect(),
        requirements,
        pending,
        prompts,
        rules,
        tests,
        settings,
    }
}

/// The brief as data, for the MCP tool's structured result.
pub(crate) fn to_json(brief: &Brief) -> Value {
    json!({
        "app": brief.app,
        "level": brief.level,
        "feature": brief.feature,
        "name": brief.name,
        "requirements": brief.requirements.iter().map(|r| json!({
            "id": r.id, "level": r.level, "description": r.description,
        })).collect::<Vec<_>>(),
        "pending": brief.pending.iter().map(|r| json!({
            "id": r.id, "level": r.level, "description": r.description,
        })).collect::<Vec<_>>(),
        "conditions": brief.conditions,
        "notApplying": brief.not_applying,
        "prompts": brief.prompts.iter().map(|p| json!({
            "id": p.id, "title": p.title, "status": p.status, "text": p.text,
        })).collect::<Vec<_>>(),
        "rules": brief.rules.iter().map(|r| json!({
            "id": r.id, "topic": r.topic, "rule": r.rule,
        })).collect::<Vec<_>>(),
        "tests": brief.tests.iter().map(|t| json!({
            "id": t.id, "level": t.level, "description": t.description,
        })).collect::<Vec<_>>(),
        "settings": brief.settings.iter().map(|s| json!({
            "table": s.table, "key": s.key, "lines": s.lines,
        })).collect::<Vec<_>>(),
        "creditsNothing": true,
    })
}

/// The brief as Markdown, with the app's own name put through `fence` for the AI coding tool.
pub(crate) fn markdown_with(brief: &Brief, fence: &sv_report::fence::Fence) -> String {
    let mut out = String::new();
    let app = if brief.app.is_empty() {
        "this app".to_owned()
    } else {
        fence.wrap(&brief.app)
    };
    out.push_str(&format!(
        "# Before building: {} ({app}, level {})\n\n",
        brief.name, brief.level
    ));
    out.push_str(
        "What this feature will be held to, and what to decide, write, and give `sv run` while \
         building it. A brief credits nothing: it says what will be checked, not what was built.\n\n",
    );

    out.push_str("## 1. The requirements it brings\n\n");
    if brief.requirements.is_empty() {
        out.push_str("None of this feature's requirements applies to this app as it stands.\n");
    } else {
        out.push_str("These apply to the app now:\n\n");
    }
    for r in &brief.requirements {
        out.push_str(&format!(
            "- **{}** (level {}): {}\n",
            r.id, r.level, r.description
        ));
    }
    if !brief.pending.is_empty() {
        out.push_str(&format!(
            "\n### Once securevibe.toml says the app has it ({})\n\nsecurevibe.toml does not say \
             yet that the app has this feature, so these do not apply now. They will as soon as it \
             does, and the tests for them are written then (`sv plan` lists them):\n\n",
            brief
                .conditions
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(" or ")
        ));
        for r in &brief.pending {
            out.push_str(&format!(
                "- **{}** (level {}): {}\n",
                r.id, r.level, r.description
            ));
        }
    }
    if brief.not_applying > 0 {
        out.push_str(&format!(
            "\n{} more of this feature's requirements are above this app's level, or ruled out by \
             its answers. `sv report` says which.\n",
            brief.not_applying
        ));
    }

    out.push_str("\n## 2. Decide first\n\n");
    if brief.prompts.is_empty() {
        out.push_str(
            "No design-time prompt is written for this feature yet; `sv plan` lists the ones for \
             decisions every app makes.\n\n",
        );
    }
    for p in &brief.prompts {
        out.push_str(&format!(
            "### {} (`{}`, {})\n\n{}\n\n",
            p.title, p.id, p.status, p.text
        ));
    }

    out.push_str("## 3. Rules to code by\n\n");
    if brief.rules.is_empty() {
        out.push_str(
            "No topic of the coding rules bears on this feature in particular; \
             `securevibe_guidance` (`sv rules`) gives the rules for all of the work.\n",
        );
    }
    for r in &brief.rules {
        out.push_str(&format!("- {} (`{}`)\n", r.rule, r.topic));
    }

    out.push_str("\n## 4. Tests to write\n\n");
    if brief.tests.is_empty() {
        out.push_str("None: no requirement of this feature waits on a test.\n");
    }
    for t in &brief.tests {
        out.push_str(&format!(
            "- A test naming **{}** in its name or a comment: {}\n",
            t.id, t.description
        ));
    }

    out.push_str("\n## 5. What `sv run` needs in `securevibe.toml`\n\n");
    for s in &brief.settings {
        out.push_str(&format!(
            "In `[{}]`, `{}`:\n\n```toml\n{}\n```\n\n",
            s.table, s.key, s.lines
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features() -> Features {
        Features::load(&crate::feature_briefs_path()).unwrap()
    }

    #[test]
    fn every_setting_a_brief_names_is_one_the_starter_file_describes() {
        // A brief quotes the spec; a key it names that the spec does not describe would be a
        // setting that does not exist.
        for f in &features().features {
            assert!(!f.settings.is_empty(), "{}: no settings", f.id);
            for s in &f.settings {
                let lines = setting_lines(&s.table, &s.key).unwrap_or_else(|| {
                    panic!(
                        "{}: [{}] {} is not in the starter file",
                        f.id, s.table, s.key
                    )
                });
                assert!(lines.contains(&s.key), "{}: {lines}", f.id);
            }
        }
    }

    #[test]
    fn a_setting_is_quoted_with_the_lines_that_explain_it_and_no_more() {
        let upload = setting_lines("stack.run.users", "upload").unwrap();
        assert!(upload.starts_with("# upload = {"), "{upload}");
        assert!(
            upload.contains("`max-bytes` is the largest file"),
            "{upload}"
        );
        assert!(
            !upload.contains("reset"),
            "the next key is not part of it: {upload}"
        );
        let login = setting_lines("stack.run.users", "login").unwrap();
        assert_eq!(login.lines().count(), 1, "{login}");
        // A key named in another table is not this table's.
        assert!(setting_lines("stack.run.oidc", "upload").is_none());
        assert!(setting_lines("stack.run.users", "no-such-key").is_none());
        // `private` is in two tables, and each table gives its own.
        let oidc = setting_lines("stack.run.oidc", "private").unwrap();
        assert!(oidc.contains("signed-in person"), "{oidc}");
    }

    #[test]
    fn every_feature_names_real_requirements_prompts_and_unique_ids() {
        let data = crate::data_dir().unwrap();
        let frameworks = crate::load_frameworks(&data).unwrap();
        let prompts = crate::design_prompts().unwrap();
        let mut ids = BTreeSet::new();
        for f in &features().features {
            assert!(ids.insert(f.id.clone()), "{} twice", f.id);
            assert!(
                !f.conditions.is_empty() || !f.requirements.is_empty(),
                "{}: brings nothing",
                f.id
            );
            for r in &f.requirements {
                assert!(frameworks.requirements.contains_key(r), "{}: {r}", f.id);
            }
            for p in &f.prompts {
                assert!(prompts.prompts.iter().any(|q| &q.id == p), "{}: {p}", f.id);
            }
            let rules =
                sv_check::coding_rules::CodingRules::load(&crate::coding_rules_path()).unwrap();
            for t in &f.guidance {
                assert!(rules.topic_ids().contains(&t.as_str()), "{}: {t}", f.id);
            }
        }
    }

    #[test]
    fn a_condition_brings_the_requirements_the_applicability_rules_gate_on_it() {
        let data = crate::data_dir().unwrap();
        let frameworks = crate::load_frameworks(&data).unwrap();
        let config =
            ApplicabilityConfig::load_v2(&data.join("knowledge"), &crate::overlay_path()).unwrap();
        let all = features();
        let uploads = brought(all.get("uploads").unwrap(), &frameworks, &config).all;
        // V5.2.1 is the uploads chapter's own, and V5 is gated on `uploads`.
        assert!(uploads.contains("V5.2.1"), "{uploads:?}");
        assert!(
            !uploads.contains("V6.2.1"),
            "a password requirement is sign-in's"
        );
        let fetch = brought(all.get("fetch").unwrap(), &frameworks, &config);
        assert!(fetch.gated.is_empty(), "no condition: its own list only");
        let fetch = fetch.all;
        assert_eq!(
            fetch.into_iter().collect::<Vec<_>>(),
            ["V1.3.6", "V13.2.4", "V15.3.2"]
        );
        assert!(all.get("bookings").is_err());
    }
}
