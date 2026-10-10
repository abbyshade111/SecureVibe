//! What the server offers, in the words the AI coding tool reads: the tool list and each tool's
//! output shape, the design-time prompts, the starter specification, and a requirement's text.

use super::*;

/// The tools, each with the shape of its structured result where it has one.
pub(super) fn tools() -> Value {
    let mut list = tool_list();
    for tool in list.as_array_mut().into_iter().flatten() {
        let name = tool["name"].as_str().unwrap_or_default().to_owned();
        // A tool that reads an app can quote it, in its result or in what went wrong (deep review R9).
        if tool["inputSchema"]["properties"].get("path").is_some() {
            let description = tool["description"].as_str().unwrap_or_default();
            tool["description"] = json!(format!("{description} {}", sv_report::fence::ABOUT));
        }
        if let Some(schema) = output_schema(&name) {
            tool["outputSchema"] = schema;
        }
    }
    list
}

/// The shape of each tool's `structuredContent`, so a client can rely on it (2025-06-18 protocol).
///
/// Every field is named, the ones always present are required, and no other field is allowed: a
/// field added to a result without being added here fails `every_structured_result_has_the_shape_its_tool_declares`,
/// so the declaration cannot fall behind what is sent. A tool that answers only in text declares none.
pub(super) fn output_schema(tool: &str) -> Option<Value> {
    let string = json!({ "type": "string" });
    let count = json!({ "type": "integer", "minimum": 0 });
    let strings = json!({ "type": "array", "items": string });
    let object = |properties: Value, required: &[&str]| json!({ "type": "object", "properties": properties, "required": required, "additionalProperties": false });
    let finding = object(
        json!({
            "rule_id": string, "title": string,
            "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
            "confidence": { "type": "string", "enum": ["high", "medium", "low"] },
            "location": object(json!({ "file": string, "line": count }), &["file", "line"]),
            "secret": {
                "type": ["object", "null"],
                "properties": { "redacted": string, "length": count },
                "required": ["redacted", "length"],
                "additionalProperties": false
            },
            "requirement_ids": strings, "cwe": strings,
            "description": string, "impact": string, "fix": string,
            "also_reported_by": strings, "fingerprint": string, "earlier_fingerprints": strings,
            "marked_test_code": { "type": "boolean" },
            "bundled_library": string,
            // Why the report lists it apart (ADR-023, Later, 6 October 2026).
            "outranked": object(
                json!({
                    "why": { "type": "string", "enum": ["not-held-to", "checked-while-running"] },
                    "check": string,
                }),
                &["why"],
            ),
            // The other problems on the same line, each a finding of this same shape.
            "also_on_this_line": { "type": "array", "items": { "type": "object" } },
        }),
        &[
            "rule_id",
            "title",
            "severity",
            "confidence",
            "location",
            "secret",
            "requirement_ids",
            "cwe",
            "description",
            "impact",
            "fix",
        ],
    );
    // Which pages of a long answer a part holds, and every section there is (`crate::parts`). Sent only when the
    // answer comes in parts, so it is not required.
    let page = object(
        json!({ "section": string, "page": count, "pages": count }),
        &["section", "page", "pages"],
    );
    let part = object(
        json!({
            "shown": { "type": "array", "items": page },
            "sections": { "type": "array", "items": object(
                json!({ "section": string, "title": string, "pages": count, "fields": strings }),
                &["section", "title", "pages", "fields"],
            ) },
            "howToAsk": string,
        }),
        &["shown", "sections", "howToAsk"],
    );
    let counts = [
        "applicable",
        "needs_attention",
        "checked",
        "checked_in_part",
        "app_tested",
        "documented",
        "attested",
        "stated",
        "by_hand",
        "not_verified",
        "not_applicable",
        "not_assessed",
        "out_of_level",
        "ai_process",
    ];
    // One question only the person can answer, as the check's `questions` lists it.
    let question = object(
        json!({
            "id": string, "title": string, "how": string,
            "where_to_look": { "type": ["string", "null"] },
            "route": { "type": "string", "enum": ["write-it-down", "answer-in-the-manifest", "go-and-look"] },
            "where_means": { "type": ["string", "null"] },
        }),
        &[
            "id",
            "title",
            "how",
            "where_to_look",
            "route",
            "where_means",
        ],
    );
    let schema = match tool {
        "stackvet_check" => object(
            json!({
                "app": string,
                "targetLevel": count,
                "counts": object(
                    Value::Object(counts.iter().map(|c| ((*c).to_owned(), count.clone())).collect()),
                    &counts,
                ),
                "notExamined": { "type": "array", "items": object(
                    json!({
                        "what": string,
                        "why": string,
                        "reason": { "type": "string", "enum": [
                            "not-asked", "not-installed", "could-not-read", "no-reader", "stopped",
                            "person-only", "planned", "partial", "left-out", "outdated",
                        ] },
                        "requirements": strings,
                    }),
                    &["what", "why", "reason"],
                ) },
                "findings": { "type": "array", "items": finding },
                "needsAttention": strings,
                "claims": { "type": "array", "items": object(
                    json!({
                        "name": string,
                        "claimed": { "type": ["boolean", "null"] },
                        "found_in_code": { "type": ["boolean", "null"] },
                        "state": string,
                        "note": string,
                    }),
                    &["name", "claimed", "found_in_code", "state", "note"],
                ) },
                "undecided": { "type": "array", "items": object(
                    json!({ "id": string, "description": string, "chapter": string, "blocked_on": strings }),
                    &["id", "description", "chapter", "blocked_on"],
                ) },
                "questions": { "type": "array", "items": question.clone() },
                "part": part.clone(),
            }),
            // The lists are left out of a part that holds none of them (`crate::parts`).
            &["app", "targetLevel", "counts"],
        ),
        // Folded into `stackvet_check` on 9 October 2026, and still answering by this name, unlisted.
        "stackvet_questions" => object(
            json!({ "questions": { "type": "array", "items": question } }),
            &["questions"],
        ),
        "stackvet_guidance" => object(
            json!({
                "rules": { "type": "array", "items": object(
                    json!({ "id": string, "topic": string, "rule": string, "cites": strings }),
                    &["id", "topic", "rule", "cites"],
                ) },
                "prompts": { "type": "array", "items": object(
                    json!({ "id": string, "title": string, "text": string }),
                    &["id", "title", "text"],
                ) },
                "leftOut": count,
                "filteredBySecurevibeToml": { "type": "boolean" },
                "attribution": object(
                    json!({ "title": string, "authors": string, "url": string, "license": string, "licenseUrl": string, "changes": string }),
                    &["title", "authors", "url", "license", "licenseUrl", "changes"],
                ),
            }),
            &[
                "rules",
                "prompts",
                "leftOut",
                "filteredBySecurevibeToml",
                "attribution",
            ],
        ),
        "stackvet_plan" => {
            let item = |fields: &[&str]| {
                let properties: serde_json::Map<String, Value> = fields
                    .iter()
                    .map(|f| {
                        let kind = match *f {
                            "level" => count.clone(),
                            "given" => json!({ "type": "boolean" }),
                            _ => string.clone(),
                        };
                        ((*f).to_owned(), kind)
                    })
                    .collect();
                json!({ "type": "array", "items": object(Value::Object(properties), fields) })
            };
            object(
                json!({
                    "app": string, "level": count,
                    "requirements": item(&["id", "level", "chapter", "description"]),
                    "decisions": item(&["id", "title"]),
                    "prompts": item(&["id", "title", "status"]),
                    "tests": item(&["id", "level", "description"]),
                    "run": item(&["table", "key", "why", "given"]),
                    "threats": item(&["id", "description", "status"]),
                    "creditsNothing": { "type": "boolean" },
                    "part": part.clone(),
                }),
                // The lists are left out of a part that holds none of them (`crate::parts`).
                &["app", "level", "creditsNothing"],
            )
        }
        // `sv doctor`'s answers (backlog 0217, part 3).
        "stackvet_status" => object(
            json!({
                "lines": {
                    "type": "array",
                    "items": object(
                        json!({
                            "topic": string,
                            "state": { "type": "string", "enum": ["ready", "not-ready", "cannot-tell"] },
                            "says": string,
                        }),
                        &["topic", "state", "says"],
                    ),
                },
                "notReady": count.clone(),
                "creditsNothing": { "type": "boolean" },
            }),
            &["lines", "notReady", "creditsNothing"],
        ),
        "stackvet_preflight" => {
            let items = json!({
                "type": "array",
                "items": object(
                    json!({
                        "topic": string,
                        "answer": { "type": "string", "enum": ["look-at-this", "could-not-tell", "looks-right"] },
                        "says": string,
                    }),
                    &["topic", "answer", "says"],
                ),
            });
            object(
                json!({
                    "ran": { "type": "boolean" },
                    "credits": string,
                    "items": items.clone(),
                    // What `sv run` will check once the app runs, read in the code (ADR-035, Later).
                    "willLookFor": items,
                    "notRead": strings,
                }),
                &["ran", "credits", "items", "willLookFor", "notRead"],
            )
        }
        "stackvet_before" => {
            let item = |fields: &[(&str, Value)]| {
                let properties: serde_json::Map<String, Value> = fields
                    .iter()
                    .map(|(f, kind)| ((*f).to_owned(), kind.clone()))
                    .collect();
                let names: Vec<&str> = fields.iter().map(|(f, _)| *f).collect();
                json!({ "type": "array", "items": object(Value::Object(properties), &names) })
            };
            object(
                json!({
                    "waiting": { "type": "boolean" },
                    "app": string, "level": count, "feature": string, "name": string,
                    "requirements": item(&[("id", string.clone()), ("level", count.clone()), ("description", string.clone())]),
                    "pending": item(&[("id", string.clone()), ("level", count.clone()), ("description", string.clone())]),
                    "conditions": strings,
                    "notApplying": count,
                    "prompts": item(&[("id", string.clone()), ("title", string.clone()), ("status", string.clone()), ("text", string.clone())]),
                    "codingPrompts": item(&[("id", string.clone()), ("title", string.clone()), ("status", string.clone()), ("text", string.clone())]),
                    "rules": item(&[("id", string.clone()), ("topic", string.clone()), ("rule", string.clone())]),
                    "tests": item(&[("id", string.clone()), ("level", count.clone()), ("description", string.clone())]),
                    "settings": item(&[("table", string.clone()), ("key", string.clone()), ("lines", string.clone())]),
                    "creditsNothing": { "type": "boolean" },
                }),
                &[
                    "waiting",
                    "app",
                    "level",
                    "feature",
                    "name",
                    "requirements",
                    "pending",
                    "conditions",
                    "notApplying",
                    "prompts",
                    "codingPrompts",
                    "rules",
                    "tests",
                    "settings",
                    "creditsNothing",
                ],
            )
        }
        "stackvet_prompts" => object(
            json!({
                "prompts": { "type": "array", "items": object(
                    json!({
                        "id": string, "title": string, "prompt": string, "requirements": strings,
                        "sbdControls": strings,
                        "status": { "type": "string", "enum": ["shown", "not-shown", "untested"] },
                        "result": { "type": ["string", "null"] },
                        "forRequirements": strings,
                    }),
                    &["id", "title", "prompt", "requirements", "sbdControls", "status", "result"],
                ) },
                "credit": string,
                "report": string,
                "unproven": count,
            }),
            &["prompts", "credit"],
        ),
        "stackvet_notes_file" => object(
            json!({
                "file": string, "asked": count, "alreadyAnswered": count,
                "keptOutsideQuestions": { "type": "boolean" },
            }),
            &["file", "asked", "alreadyAnswered", "keptOutsideQuestions"],
        ),
        // With an id and an answer, what was recorded; with neither, the file made or refreshed,
        // as `stackvet_notes_file` gave it before it was folded in here.
        "stackvet_record_answer" => object(
            json!({
                "file": string, "id": string, "writtenBy": string,
                "asked": count, "alreadyAnswered": count,
                "keptOutsideQuestions": { "type": "boolean" },
            }),
            &["file"],
        ),
        "stackvet_write_report" => object(json!({ "files": strings }), &["files"]),
        "stackvet_bundle" => object(
            json!({
                "zip": string, "files": count, "appFiles": count,
                "leftOut": { "type": "array", "items": object(json!({ "path": string, "reason": string }), &["path", "reason"]) },
            }),
            &["zip", "files", "appFiles", "leftOut"],
        ),
        "stackvet_explain" => object(
            json!({
                "id": string, "chapter": string, "level": count,
                "levelBasis": { "type": ["string", "null"] },
                "description": string, "counterparts": strings,
            }),
            &[
                "id",
                "chapter",
                "level",
                "levelBasis",
                "description",
                "counterparts",
            ],
        ),
        _ => return None,
    };
    Some(schema)
}

/// The design-time prompts, offered as MCP prompts: what a client shows a person to choose from (in
/// Claude Code, as slash commands), rather than what the model decides to call. Only the design-time
/// file, because these are what to decide before any code, and choosing one is the person's
/// decision; the prompts for the coding stay with `stackvet_prompts` (BACKLOG, "Design-time help
/// before any code", item 2).
pub(super) fn design_prompts() -> Result<sv_check::prompts::Prompts, (i64, String)> {
    let paths = crate::prompts_paths();
    sv_check::prompts::Prompts::load_all(&[&paths[1]]).map_err(|e| (-32603, format!("{e:#}")))
}

/// What the person reads beside a prompt before choosing it: whether it has been shown to work, and
/// which Secure by Design controls it helps them answer. Every copy of a prompt says this, so "not
/// tested" and "shown" never read the same.
pub(super) fn prompt_description(p: &sv_check::prompts::Prompt) -> String {
    let status = p.status_sentence();
    if p.sbd_controls.is_empty() {
        status
    } else {
        format!(
            "{status} Helps you answer Secure by Design {} (you still answer each).",
            p.sbd_controls.join(", ")
        )
    }
}

pub(super) fn prompt_list() -> Result<Value, (i64, String)> {
    let prompts = design_prompts()?;
    let listed: Vec<Value> = prompts
        .prompts
        .iter()
        .map(|p| json!({ "name": p.id, "title": p.title, "description": prompt_description(p) }))
        // After them, the one for reading the report (backlog 0217 part 5).
        .chain(std::iter::once(json!({
            "name": crate::report_prompt::ID,
            "title": crate::report_prompt::TITLE,
            "description": crate::report_prompt::STATUS,
        })))
        .collect();
    Ok(json!({ "prompts": listed }))
}

/// One prompt, as the message the person sends: its text, then whether it was shown to work, that it
/// is an instruction and not evidence, and the credit its license asks for on every copy.
pub(super) fn get_prompt(params: &Value) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).ok_or((
        -32602,
        "prompts/get needs a name, as prompts/list gives".to_owned(),
    ))?;
    if name == crate::report_prompt::ID {
        return Ok(json!({
            "description": crate::report_prompt::STATUS,
            "messages": [{ "role": "user", "content": { "type": "text", "text": crate::report_prompt::with_mark() } }],
        }));
    }
    let prompts = design_prompts()?;
    let Some(p) = prompts.prompts.iter().find(|p| p.id == name) else {
        return Err((-32602, format!("there is no prompt called {name}")));
    };
    let description = prompt_description(p);
    let text = format!(
        "{}\n\n---\n{description} A prompt is an instruction, not evidence: check the app with \
         StackVet afterwards, whichever prompt you use.\n\n{}",
        p.prompt.trim_end(),
        prompts.credit.trim()
    );
    Ok(json!({
        "description": description,
        "messages": [{ "role": "user", "content": { "type": "text", "text": text } }],
    }))
}

pub(super) fn tool_list() -> Value {
    let path = json!({
        "type": "string",
        "description": "The app's folder, relative to the folder this server was started for. Defaults to that folder."
    });
    // For the two tools whose answer can come in parts (`crate::parts`).
    let section = |names: &[&str]| {
        let mut allowed: Vec<&str> = names.to_vec();
        allowed.push("all");
        json!({
            "type": "string",
            "enum": allowed,
            "description": "One section of the answer, as the list at the end of a long answer names them. Leave it out for the whole answer when it is short, or its start and that list when it is long; `all` gives the whole answer whatever its length."
        })
    };
    let page = json!({
        "type": "integer",
        "minimum": 1,
        "description": "Which page of the section, from 1, when the list says it has more than one. Defaults to 1."
    });
    json!([
        {
            "name": "stackvet_status",
            "title": "Is everything ready?",
            "description": "Whether StackVet is ready for this app, in one plain line each, marked ready, not ready, or can't tell: which StackVet this is, whether the folder is in git, whether stackvet.toml is there and reads, whether it says how to start the app, and whether Docker can start it for `sv report --run`. Inside StackVet's container, which cannot see Docker on the computer, that last one is can't tell. The same answers as `sv doctor` at a terminal. It credits nothing, writes nothing, and opens no network connection, so it cannot say whether a newer StackVet is out. Call it when setting up, or when something does not work and you want to know what is missing.",
            "inputSchema": { "type": "object", "properties": { "path": path.clone() } },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_spec",
            "title": "How to describe the app",
            "description": "The stackvet.toml the app needs before it can be checked, with instructions for filling it in. Write it into the app's folder: before any code, for the app as it will be, decided with the person; once there is code, from what the app really does. A claim the code contradicts is reported, and requirements only ever apply more because of it, never less.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_prompts",
            "title": "Prompts for the person to give you",
            "description": "Prompts from StackVet's library that ask an AI coding tool for something StackVet checks, such as keeping the app in git from the first file or building every database query with placeholders, and design-time prompts for what to decide before any code is written (who may do what, limits, logging, sign-in), each with the requirements it targets and, for a design-time prompt, the Secure by Design controls it helps the person answer. Each says whether it has been shown to work: an app built with it passed its check and the same app built without it failed. The others say whether they were tried and not shown to work, or not tried yet. Offer them to the person; following one is not evidence of anything, so check the app afterwards.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "requirement": {
                        "type": "string",
                        "description": "Only the prompts for this requirement or Secure by Design control, such as V1.2.4 or SBD-AC-03. Leave it out for all of them."
                    },
                    "path": {
                        "type": "string",
                        "description": "The app's folder. Give it for only the prompts for what the app's last report (stackvet-report/report.json, written by stackvet_write_report) shows unproven: a finding, nothing shown, or only an answer given by the person or the AI tool, with nothing checked, each prompt saying which of those requirements it is for. With no report there yet, write one first."
                    }
                }
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_plan",
            "title": "Plan the app before writing it",
            "description": "The plan for the app from its stackvet.toml, before any code and at any time after: the requirements that will apply, the design-time prompts to work through before each feature, the questions only the person can answer, the tests worth writing named by requirement id, what the app must give `sv run` in stackvet.toml so it can be tested running, and the threats the answers raise. Built from the same report as stackvet_check, so the two agree. A plan credits nothing and never says a requirement is met. Reads files only; never starts the app. A plan too long to take in whole (over about 40,000 characters) comes in parts: the first answer gives what to decide and what `sv run` needs, and ends with a list of every section and how to ask for each with `section` and `page`. Nothing is left out.",
            "inputSchema": { "type": "object", "properties": {
                "path": path.clone(),
                "section": section(crate::plan::SECTIONS),
                "page": page.clone(),
            } },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_before",
            "title": "Before building one feature",
            "description": "Before building one feature (sign-in, admin pages, uploads, payments, email, an AI feature, fetching a web address, records people own or share, API keys, background jobs, several customer organizations): the requirements it brings that apply to this app, the design-time prompts for the decisions to make first, the coding rules on the topics it touches and the coding prompts shown to work for its requirements, the tests to write named by requirement id, and the settings `sv run` needs in stackvet.toml to test it, quoted from the spec. Built from the same report as stackvet_plan. Asked before stackvet.toml exists, it gives everything the feature can bring, its decisions, prompts, rules, and settings, and says which requirements apply, and the tests, wait for the file (`waiting`). A brief credits nothing. Reads files only; never starts the app.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path.clone(),
                    "feature": {
                        "type": "string",
                        "enum": ["sign-in", "sign-in-elsewhere", "admin", "uploads", "payments", "email", "ai", "fetch", "owned-records", "api-keys", "background-jobs", "organizations"],
                        "description": "The feature about to be built."
                    }
                },
                "required": ["feature"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_guidance",
            "title": "Rules to follow while coding",
            "description": "The security rules to follow while you write this app, adapted from OWASP AISVS 1.0 Appendix C (AI-assisted secure coding), with its attribution and license (CC BY-SA 4.0): keeping keys out of the chat, treating fetched text as data, checking after each feature, adding only packages that exist, never merging your own work, writing CI workflows that keep secrets from forks. Rules that do not apply to the app, by its stackvet.toml, are left out. Call it before you start, and with a topic before work in that area. With no topic it ends with the prompts shown to work that are about the whole app. They are instructions, not a check: following them is not evidence of anything.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path.clone(),
                    "topic": {
                        "type": "string",
                        "enum": ["secrets", "untrusted-content", "checking", "review", "dependencies", "agent-limits", "ci-workflows", "provenance", "incidents"],
                        "description": "Only the rules on this topic. Leave it out for all of them."
                    }
                }
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_preflight",
            "title": "Will `sv run` be able to test it?",
            "description": "Once there is code: reads the app's files against what stackvet.toml tells `sv run` (the start command, listening on 0.0.0.0 at $PORT, the seed reading the SV_ accounts, tables the app makes itself, every path and sign-in field the settings name), and says for each whether it looks right, needs a look, or could not be told. Also says what `sv run` will check once the app runs (a limit on wrong passwords, the security headers, the session cookie's SameSite, a screen on what an AI feature is sent) when nothing in the code reads like a way of handling it. Reads files only and runs nothing, so \"looks right\" means the text was found, not that it works. Credits nothing.",
            "inputSchema": { "type": "object", "properties": { "path": path.clone() } },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_check",
            "title": "Check an app",
            "description": "Check the app against OWASP ASVS 5.0, AISVS 1.0 and the Secure by Design checklist: credentials in the code, configuration, rules that read the code, dependencies (listed, not compared with known vulnerabilities: that needs `--advisories` at a terminal), and which requirements apply. Reads files only; never starts the app. The result gives the counts, then what was NOT examined, then what needs attention with the file, line and fix. It never says a requirement passed, and nothing in it means the app is secure. It also gives the questions about the app that only a person can answer (how it is built, the rules it follows, and what to check by hand), in its section \"questions\": ask the person them one at a time, offering what you know of the code as a tip, and record their answers as that section says; answers you give yourself are recorded as yours and reported as weaker than the person's. A check too long to take in whole (over about 40,000 characters) comes in parts: the first answer gives what was not examined and the findings, and ends with a list of every section and how to ask for each with `section` and `page`. Nothing is left out.",
            "inputSchema": { "type": "object", "properties": {
                "path": path.clone(),
                "section": section(CHECK_SECTIONS),
                "page": page.clone(),
            } },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_write_report",
            "title": "Write the full report",
            "description": "Write the full reports into a folder inside the app (stackvet-report by default): report.html for a person, compliance.md, security.md, findings.sarif and report.json. Same checks as stackvet_check.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path,
                    "out": { "type": "string", "description": "Folder inside the app to write to, as a path relative to it: a new or empty one, or one sv wrote before. No `..`. Refused while another run is writing that folder, or when it holds a report from a run that started later." }
                }
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": false }
        },
        {
            "name": "stackvet_record_answer",
            "title": "Record an answer in the security notes",
            "description": "Write an answer under one question in security-notes.md (making the file if it is not there), in place of what was under it. Called with no id and no answer, it only makes or refreshes security-notes.md, where the person's written decisions go, keeping everything already written in it: answers stay under their questions, and any other text is kept word for word in a section of its own near the top; it refuses, writing nothing, when the file is not UTF-8 text or has two sections for one question. sv marks every answer this records as yours, `Written by: AI coding tool`, which the report counts for less than the person's own word; there is no way to mark it as theirs. Record what the person told you, or what you found in the code if they asked you to answer; then show them. If it says what they decided, they change the line to `Written by: owner` themselves and record it by running `sv review` in their own terminal; if you worked it out from the code and they agree, they leave the line as it is and confirm it through `sv review`, and the report shows it as your words a person confirmed. It fills a question with nothing under it, or replaces an answer marked `Written by: AI coding tool`; anything else under the question may be the person's own words and is never replaced.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": path.clone(),
                    "id": { "type": "string", "description": "The question's requirement id, as stackvet_check's section \"questions\" lists it, such as V6.1.1. Leave it and the answer out to only make or refresh the file." },
                    "answer": { "type": "string", "description": "Needed with an id. The answer, in a sentence or two of plain words, at least 40 characters, with no headings and no line starting with `>`. Leave out any line saying who wrote it; sv adds it." }
                }
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_explain",
            "title": "Explain a requirement",
            "description": "What a requirement asks for, in its framework's own words, with its level and where the level comes from. Takes an id such as V1.2.4, C9.5.4, AC.4.1 or SBD-AC-05.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": { "type": "string", "description": "The requirement id." } },
                "required": ["id"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stackvet_bundle",
            "title": "Bundle the app and its report",
            "description": "Write one zip beside the app (never inside it) holding the app's files, the full report, the bill of materials and a SHA-256 for every file, for the person to keep or hand on. It leaves out anything that could hold a secret (files the credential scan flagged, environment files, keys, databases, links, editor folders, files it could not read) and lists each with the reason. Offer it once the report is written, only if the person wants it. It cannot tell which files hold data about the app's people. The app must be a folder below the one this server was started for, since the zip goes beside it: with no `path`, it is refused.",
            // Its own `path`, required: the zip goes beside the app, so the server's own folder, the
            // default everywhere else, is always refused here (the documentation review, item 5).
            "inputSchema": {
                "type": "object",
                "properties": { "path": {
                    "type": "string",
                    "description": "The app's folder, relative to the folder this server was started for, and below it: the zip is written beside the app, so that folder itself cannot be bundled."
                } },
                "required": ["path"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        }
    ])
}

pub(super) fn spec() -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "{}\n{}{}",
                sv_manifest::spec::STARTER_MANIFEST,
                sv_manifest::spec::INSTRUCTIONS,
                crate::prompts_at_start()
            ),
        }],
        "isError": false,
    })
}

pub(super) fn explain(frameworks: &sv_frameworks::Frameworks, args: &Value) -> Result<Value> {
    let id = args
        .get("id")
        .and_then(Value::as_str)
        .context("stackvet_explain needs an id")?;
    let r = frameworks
        .get(id)
        .with_context(|| format!("{id} is not a requirement in any loaded framework"))?;
    let mut text = format!(
        "{id} ({}), level {}{}\n\n{}",
        r.chapter_name,
        r.level,
        r.level_basis
            .as_deref()
            .map(|b| format!(" — {b}"))
            .unwrap_or_default(),
        r.description
    );
    if !r.counterparts.is_empty() {
        text.push_str(&format!(
            "\n\nASVS requirements that ask the same thing: {}. Evidence about them is shown \
             beside this one as supporting, never as checking it.",
            r.counterparts.join(", ")
        ));
    }
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": {
            "id": id,
            "chapter": r.chapter_name,
            "level": r.level,
            "levelBasis": r.level_basis,
            "description": r.description,
            "counterparts": r.counterparts,
        },
        "isError": false,
    }))
}
