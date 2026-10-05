//! `sv plan`: the design brief turned into a plan, before any code and at any time after (ADR-030).
//!
//! A plan is built from the report's own parts, so that it and a later report cannot disagree about
//! what applies: the requirements, the tests worth writing, the questions only the person can answer,
//! and the threats all come from `assemble_report`. Two parts are the plan's own: the design-time
//! prompts for the decisions to make before each feature, and what the app must give `sv run` so it
//! can be tested running, worked out from the brief's answers.
//!
//! # What it is worth
//!
//! Nothing, as evidence. A plan says what the app will be held to and what to build so it can be
//! checked; it says nothing about what was built, so no requirement changes status because of it.

use serde_json::{Value, json};
use sv_manifest::Manifest;

/// One thing the app must give `sv run`, in `securevibe.toml`, so a check of the running app can be
/// made rather than reported as not assessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunNeed {
    /// The table it goes in, such as `[stack.run.users]`.
    pub table: &'static str,
    /// The key in that table, such as `login`.
    pub key: &'static str,
    /// Why, in plain words: what `sv run` does with it.
    pub why: &'static str,
    /// Whether the brief already gives it.
    pub given: bool,
}

/// A design-time prompt that bears on this app, and whether it has been shown to work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptRef {
    pub id: String,
    pub title: String,
    pub status: &'static str,
}

/// A requirement that will apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Applies {
    pub id: String,
    pub level: u8,
    pub chapter: String,
    pub description: String,
}

/// A question only the person can answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decision {
    pub id: String,
    pub title: String,
}

/// A threat the brief's answers raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Threat {
    pub id: String,
    pub description: String,
    /// `not-verified`, or `cannot-place` when an unanswered question decides whether it applies.
    pub status: &'static str,
}

/// The plan, in the order a builder needs it.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub app: String,
    pub level: u8,
    pub requirements: Vec<Applies>,
    pub decisions: Vec<Decision>,
    pub prompts: Vec<PromptRef>,
    pub tests: Vec<sv_report::TestToWrite>,
    pub run: Vec<RunNeed>,
    pub threats: Vec<Threat>,
}

/// What `sv run` needs for each answer of the brief, in the order the spec describes them. A table
/// and key that the spec does not describe is refused by a test, so the plan cannot ask for a setting
/// that does not exist.
pub(crate) fn run_needs(manifest: &Manifest) -> Vec<RunNeed> {
    let run = &manifest.stack.run;
    let users = run.users.as_ref();
    let caps = &manifest.capabilities;
    // An unanswered capability is planned for, as the spec's rule 2 asks: unsure is yes.
    let maybe = |answer: Option<bool>| answer != Some(false);
    let mut out = Vec::new();
    let mut need = |table, key, why, given: bool| {
        out.push(RunNeed {
            table,
            key,
            why,
            given,
        })
    };

    need(
        "[stack.run]",
        "image",
        "the container image the app runs in",
        run.image.is_some(),
    );
    need(
        "[stack.run]",
        "start",
        "how to start the app, listening on 0.0.0.0 and the port in $PORT",
        run.start.is_some(),
    );
    need(
        "[stack.run]",
        "health",
        "a path that answers 200 once the app is up, so the checks start only then",
        run.health.is_some(),
    );
    need(
        "[stack.run]",
        "test",
        "how to run the app's own tests; a passing test whose name carries a requirement's id counts \
         as *checked*, the highest tier `sv` gives",
        run.test.is_some(),
    );
    if maybe(caps.auth) {
        need(
            "[stack.run.users]",
            "seed",
            "a command that makes two ordinary test accounts (and an admin, if there are admin pages) \
             from the names and passwords `sv` gives it, so it can sign in as each",
            users.is_some_and(|u| u.seed.is_some()),
        );
        need(
            "[stack.run.users]",
            "login",
            "the sign-in form, so `sv` can sign in and see what a signed-in person can reach",
            users.is_some_and(|u| u.login.is_some()),
        );
        need(
            "[stack.run.users]",
            "logout",
            "the sign-out form, so `sv` can check that signing out really ends the session",
            users.is_some_and(|u| u.logout.is_some()),
        );
        need(
            "[stack.run.users]",
            "private",
            "pages only a signed-in person should see, so `sv` can ask for them as a stranger",
            users.is_some_and(|u| !u.private.is_empty()),
        );
        need(
            "[stack.run.users]",
            "owned",
            "how a person makes a record of their own and reads it back, so `sv` can ask for one \
             person's record as another",
            users.is_some_and(|u| u.owned.is_some()),
        );
        need(
            "[stack.run.users]",
            "admin",
            "pages only an admin should see, if the app has any, so `sv` can ask for them as an \
             ordinary user",
            users.is_some_and(|u| !u.admin.is_empty()),
        );
    }
    if maybe(caps.oauth) {
        need(
            "[stack.run.oidc]",
            "start",
            "where sign-in through another service begins; for the run the app is given a test \
             provider of `sv`'s own, through OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET",
            run.oidc.is_some(),
        );
    }
    if maybe(caps.uploads) {
        need(
            "[stack.run.users]",
            "upload",
            "the upload form and the largest file the app accepts (`max-bytes`), so `sv` can send one \
             larger than that, and files that must not be run or shown as they are: a page, a \
             script, an SVG with a script in it, a name that climbs out of its folder",
            users.is_some_and(|u| u.upload.is_some()),
        );
    }
    if maybe(caps.email) {
        need(
            "[stack.run.users]",
            "reset",
            "the forgotten-password reset, read from the test mail server the run gives the app at \
             SMTP_HOST and SMTP_PORT",
            users.is_some_and(|u| u.reset.is_some()),
        );
    }
    if maybe(caps.payments) {
        need(
            "[stack.run.users]",
            "once",
            "an action that must happen only once, such as paying or taking the last of something, so \
             `sv` can send it twenty times at the same instant",
            users.is_some_and(|u| u.once.is_some()),
        );
    }
    if maybe(caps.ai.enabled) {
        need(
            "[stack.run.ai]",
            "chat",
            "how to send the AI feature a message; for the run the app is given a test model of \
             `sv`'s own, through OPENAI_BASE_URL and ANTHROPIC_BASE_URL, and nothing is spent",
            run.ai.is_some(),
        );
    }
    if maybe(caps.ai.web_search) {
        need(
            "[stack.run.fetch]",
            "request",
            "how to ask the app to fetch a web address, so `sv` can see whether it fetches one on its \
             own private network",
            run.fetch.is_some(),
        );
    }
    if maybe(caps.mcp_server) {
        need(
            "[stack.run.mcp-server]",
            "path",
            "where the app's own MCP server answers, so `sv` can try it from a page and under a name \
             it has never heard of",
            run.mcp_server.is_some(),
        );
    }
    out
}

fn status_word(status: sv_check::prompts::Status) -> &'static str {
    status.as_str()
}

/// The plan for an app, from its report, its brief, and the design-time prompts.
pub(crate) fn from_report(
    report: &sv_report::Report,
    manifest: &Manifest,
    design_prompts: &sv_check::prompts::Prompts,
) -> Plan {
    let applies: std::collections::BTreeSet<&str> =
        report.requirements.iter().map(|r| r.id.as_str()).collect();
    let prompts = design_prompts
        .prompts
        .iter()
        // A prompt aimed at requirements is given when one of them applies; one aimed at none is a
        // decision every app makes, and is always given.
        .filter(|p| {
            p.requirements.is_empty() || p.requirements.iter().any(|r| applies.contains(r.as_str()))
        })
        .map(|p| PromptRef {
            id: p.id.clone(),
            title: p.title.clone(),
            status: status_word(p.status),
        })
        .collect();
    let threats = report
        .threats
        .iter()
        .filter_map(|t| {
            let status = match t.status {
                sv_report::threats::ThreatStatus::NotVerified => "not-verified",
                sv_report::threats::ThreatStatus::CannotPlace => "cannot-place",
                // Found and checked are what a report says about code; a plan has none to say it of.
                _ => return None,
            };
            Some(Threat {
                id: t.id.clone(),
                description: t.description.clone(),
                status,
            })
        })
        .collect();
    Plan {
        app: report.app_name.clone(),
        level: report.target_level,
        requirements: report
            .requirements
            .iter()
            .map(|r| Applies {
                id: r.id.clone(),
                level: r.level,
                chapter: r.chapter.clone(),
                description: r.description.clone(),
            })
            .collect(),
        decisions: report
            .questions_for_you
            .iter()
            .map(|q| Decision {
                id: q.id.clone(),
                title: q.title.clone(),
            })
            .collect(),
        prompts,
        tests: report.tests_to_write.clone(),
        run: run_needs(manifest),
        threats,
    }
}

/// The plan as data, for the MCP tool's structured result.
pub(crate) fn to_json(plan: &Plan) -> Value {
    json!({
        "app": plan.app,
        "level": plan.level,
        "requirements": plan.requirements.iter().map(|r| json!({
            "id": r.id, "level": r.level, "chapter": r.chapter, "description": r.description,
        })).collect::<Vec<_>>(),
        "decisions": plan.decisions.iter().map(|d| json!({ "id": d.id, "title": d.title })).collect::<Vec<_>>(),
        "prompts": plan.prompts.iter().map(|p| json!({ "id": p.id, "title": p.title, "status": p.status })).collect::<Vec<_>>(),
        "tests": plan.tests.iter().map(|t| json!({ "id": t.id, "level": t.level, "description": t.description })).collect::<Vec<_>>(),
        "run": plan.run.iter().map(|n| json!({ "table": n.table, "key": n.key, "why": n.why, "given": n.given })).collect::<Vec<_>>(),
        "threats": plan.threats.iter().map(|t| json!({ "id": t.id, "description": t.description, "status": t.status })).collect::<Vec<_>>(),
        "creditsNothing": true,
    })
}

/// The plan as Markdown, for a person or the AI coding tool.
pub(crate) fn markdown(plan: &Plan) -> String {
    let mut out = String::new();
    // The name comes from the app's folder, so its line breaks and invisible characters are
    // written as escapes, as everywhere else text from the app reaches the AI coding tool.
    let name = if plan.app.is_empty() {
        "this app".to_owned()
    } else {
        sv_report::one_line(&plan.app)
    };
    out.push_str(&format!(
        "# A plan for {name}, at ASVS level {}\n\n",
        plan.level
    ));
    out.push_str(
        "This is a plan, not a check. It says what the app will be held to, what to decide before \
         each feature, and what to build so `sv` can check the app running. It credits nothing: \
         nothing here says a requirement is met. Run `sv report` once there is code.\n",
    );

    out.push_str(&format!(
        "\n## 1. The requirements that will apply ({})\n\n",
        plan.requirements.len()
    ));
    let mut chapter = "";
    for r in &plan.requirements {
        if r.chapter != chapter {
            chapter = &r.chapter;
            out.push_str(&format!("\n**{chapter}**\n\n"));
        }
        out.push_str(&format!(
            "- {} (level {}): {}\n",
            r.id, r.level, r.description
        ));
    }

    out.push_str("\n## 2. Decide before you build\n\n");
    if plan.prompts.is_empty() && plan.decisions.is_empty() {
        out.push_str("Nothing to decide that the brief has not already settled.\n");
    }
    if !plan.prompts.is_empty() {
        out.push_str(
            "Work through each of these with the AI coding tool before writing the feature it is \
             about (`sv prompts` prints them):\n\n",
        );
        for p in &plan.prompts {
            let mark = match p.status {
                "shown" => "shown to work",
                "not-shown" => "not tested: tried, and not shown to work",
                _ => "not tested: not tried yet",
            };
            out.push_str(&format!("- {} (`{}`, {mark})\n", p.title, p.id));
        }
    }
    if !plan.decisions.is_empty() {
        out.push_str(
            "\nQuestions only you can answer, in `security-notes.md` or `securevibe.toml` \
             (`sv questions` asks them one at a time):\n\n",
        );
        for d in &plan.decisions {
            out.push_str(&format!("- {}: {}\n", d.id, d.title));
        }
    }

    out.push_str(&format!(
        "\n## 3. The tests worth writing ({})\n\n",
        plan.tests.len()
    ));
    out.push_str(
        "Name each test with its requirement's id, such as `test_V8_2_1_a_member_cannot_read_another_\
         members_note`. Once written and passing, a test so named counts as *checked*, the highest \
         tier `sv` gives. Lowest level first:\n\n",
    );
    for t in &plan.tests {
        out.push_str(&format!(
            "- {} (level {}): {}\n",
            t.id, t.level, t.description
        ));
    }

    out.push_str("\n## 4. What the app must give `sv run`\n\n");
    out.push_str(
        "So that `sv report --run` can test the app running, rather than reporting those checks as \
         not assessed. Each goes in `securevibe.toml`; `sv init` describes each one.\n\n",
    );
    for n in &plan.run {
        out.push_str(&format!(
            "- {} `{}`{}: {}\n",
            n.table,
            n.key,
            if n.given { " (given)" } else { "" },
            n.why
        ));
    }

    out.push_str(&format!(
        "\n## 5. The threats the brief raises ({})\n\n",
        plan.threats.len()
    ));
    for t in &plan.threats {
        out.push_str(&format!(
            "- {}: {}{}\n",
            t.id,
            t.description,
            if t.status == "cannot-place" {
                " (whether it applies depends on a question not yet answered)"
            } else {
                ""
            }
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(text: &str) -> Manifest {
        Manifest::parse(text, std::path::Path::new("securevibe.toml")).expect("the manifest parses")
    }

    const BASE: &str = "manifest-version = 1\n[app]\nname = \"t\"\ndescription = \"\"\naudience = \"customers\"\n\
                        deployment = \"internet\"\n[stack]\nlanguages = [\"python\"]\n";

    /// Every table and key the plan can ask for, with every capability unanswered, so all are asked.
    fn every_need() -> Vec<RunNeed> {
        run_needs(&manifest(&format!("{BASE}[capabilities]\n")))
    }

    #[test]
    fn every_setting_the_plan_asks_for_is_one_the_spec_describes() {
        let spec = sv_manifest::spec::STARTER_MANIFEST;
        let needs = every_need();
        // The control: with nothing answered, every capability's needs are asked for.
        assert!(needs.len() >= 15, "{needs:?}");
        for n in &needs {
            let table = n.table.trim_matches(|c| c == '[' || c == ']');
            assert!(
                spec.contains(&format!("[{table}]")),
                "{} is not a table the spec describes",
                n.table
            );
            // A setting is a line, commented out or not, that starts with the key and then `=`.
            let set_here = spec.lines().any(|line| {
                let line = line.trim_start().trim_start_matches('#').trim_start();
                line.strip_prefix(n.key)
                    .is_some_and(|rest| rest.trim_start().starts_with('='))
            });
            assert!(
                set_here,
                "{} `{}` is not a setting the spec describes",
                n.table, n.key
            );
        }
    }

    #[test]
    fn a_capability_answered_no_needs_nothing_for_it() {
        let none = run_needs(&manifest(&format!(
            "{BASE}[capabilities]\nauth = false\noauth = false\nuploads = false\nemail = false\n\
             payments = false\nmcp-server = false\n[capabilities.ai]\nenabled = false\nweb-search = false\n"
        )));
        let keys: Vec<&str> = none.iter().map(|n| n.key).collect();
        assert_eq!(keys, ["image", "start", "health", "test"], "{none:?}");
        let signed_in = run_needs(&manifest(&format!(
            "{BASE}[capabilities]\nauth = true\noauth = false\nuploads = false\nemail = false\n\
             payments = false\nmcp-server = false\n[capabilities.ai]\nenabled = false\nweb-search = false\n"
        )));
        let keys: Vec<&str> = signed_in.iter().map(|n| n.key).collect();
        for key in ["seed", "login", "logout", "private", "owned"] {
            assert!(keys.contains(&key), "sign-in needs {key}: {keys:?}");
        }
    }

    #[test]
    fn a_setting_the_brief_already_gives_is_marked_given() {
        let needs = run_needs(&manifest(&format!(
            "{BASE}[stack.run]\nimage = \"python:3.12-slim\"\nstart = \"python app.py\"\n[capabilities]\nauth = false\n"
        )));
        let given = |key: &str| needs.iter().find(|n| n.key == key).unwrap().given;
        assert!(given("image") && given("start"));
        assert!(!given("health") && !given("test"));
    }
}
