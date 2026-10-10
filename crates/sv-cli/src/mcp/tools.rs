//! The tools that read the app: the check and the reports built from it, the plan, the briefs, the
//! guidance and prompts, the notes file and an answer, and the bundle.

use super::*;

impl Server {
    /// The report for the app, built as `sv report` builds it, within the time limit.
    ///
    /// A check of a very large folder had no end, and the tool waited on it with nothing to say
    /// (BACKLOG, "Hardening the MCP server", item 6). The check now runs on a thread of its own; if
    /// the time runs out, the tool is told the check did not finish and that nothing was assessed,
    /// and how the person can run it at a terminal, where there is no limit. A thread cannot be
    /// stopped from outside, so the check runs on to its end and its result is dropped; until it
    /// ends, another check is refused rather than started beside it.
    /// How a check that gave no answer ended, for the record of the build loop (ADR-084).
    fn ended_as(&self, outcome: &'static str) {
        *self
            .last_outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(outcome);
    }

    pub(super) fn report_for(
        &self,
        app_dir: &Path,
        progress: &Progress,
    ) -> Result<sv_report::Report> {
        needs_manifest(app_dir, "check again")?;
        let mut last = self
            .last_check
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.as_ref().is_some_and(|check| !check.is_finished()) {
            return Err(crate::Remedy::error(
                format!(
                    "the last check ran out of time and is still finishing, so no other is started \
                     beside it. Nothing was assessed. At a terminal, with no time limit: {}.",
                    at_a_terminal(&app_dir.to_string_lossy(), "")
                ),
                "Ask again in a minute, or ask the person to run that command at a terminal.",
            ));
        }
        let (send, receive) = std::sync::mpsc::channel();
        let loaded = std::sync::Arc::clone(&self.loaded);
        let dir = app_dir.to_path_buf();
        let assemble = std::sync::Arc::clone(&self.check);
        let check = std::thread::Builder::new()
            .name("sv-check".to_owned())
            .spawn(move || {
                // The other end is gone when the time ran out; what is sent then has nowhere to go.
                let starting = |n, stage| {
                    let _ = send.send(FromCheck::Starting(n, stage));
                };
                let report = assemble(&dir, &loaded, &starting);
                let _ = send.send(FromCheck::Done(Box::new(report)));
            })
            .context("the check could not be started")?;
        *last = Some(check);
        let deadline = std::time::Instant::now() + self.time_limit;
        let outcome = loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match receive.recv_timeout(left) {
                Ok(FromCheck::Starting(n, stage)) => progress.starting(n, stage),
                Ok(FromCheck::Done(report)) => break Ok(*report),
                Err(e) => break Err(e),
            }
        };
        match outcome {
            Ok(report) => {
                // Sent, but the thread may not have ended yet; the next check would find it still
                // running and be refused. It has nothing left to do, so this wait is short.
                if let Some(check) = last.take() {
                    let _ = check.join();
                }
                if let Ok(report) = &report {
                    *self
                        .last_counts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(sv_report::LoopCounts::of(report));
                    *self
                        .last_fingerprints
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(crate::build_loop::fingerprints_of(
                            report.findings.iter().map(|f| f.fingerprint.as_str()),
                        ));
                }
                report
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.ended_as("timed-out");
                Err(crate::Remedy::error(
                    format!(
                        "the check did not finish within {} seconds, so nothing was assessed: this is \
                     not a pass and not a failure. The folder may be very large. At a terminal, with \
                     no time limit: {}.",
                        self.time_limit.as_secs_f64(),
                        at_a_terminal(&app_dir.to_string_lossy(), "")
                    ),
                    "Check a smaller folder with `path`, or ask the person to run that command at a \
                 terminal.",
                ))
            }
            // The check's thread ended without sending its report, which only a panic does: a fault
            // in `sv`, not in the app. What the panic said is the cause (backlog 226, part 2, item 16).
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.ended_as("crashed");
                let cause = last
                    .take()
                    .and_then(|check| check.join().err())
                    .map_or_else(|| "it gave no reason".to_owned(), |p| panic_words(&*p));
                Err(crate::Remedy::error(
                    format!(
                        "the check stopped before it finished, so nothing was assessed: this is not \
                         a pass and not a failure. It stopped on a fault in `sv`, not in the app: \
                         {cause}. At a terminal, the same check shows the whole error: {}.",
                        at_a_terminal(&app_dir.to_string_lossy(), "")
                    ),
                    "Ask the person to run that command at a terminal, and to pass what it says to \
                     whoever looks after `sv`.",
                ))
            }
        }
    }

    /// A check, whole when it fits what an AI coding tool takes in whole and in parts when it does not
    /// (`crate::parts`).
    pub(super) fn check(&self, args: &Value, progress: &Progress) -> Result<Value> {
        // Asked before the check runs, so a misspelt section is said at once.
        let ask = crate::parts::ask(args, "stackvet_check", CHECK_SECTIONS)?;
        let app_dir = self.app_dir(args)?;
        let report = self.report_for(&app_dir, progress)?;
        // The parts carry the questions only the person can answer in full, and so does the whole
        // answer, so the parts joined are still the whole (backlog 0187, part 10). Asked for with no
        // section, a check that would come whole without them but not with them comes whole with
        // them only counted, as before they were folded in, rather than in parts.
        let full = |fence: &sv_report::fence::Fence| summary_with(&report, fence, true);
        let mut with_questions = structured(&report);
        with_questions["questions"] = questions_in_order(&report);
        let fits = |text: String, data: &Value| {
            text.len() <= crate::parts::ANSWER_BUDGET
                && data.to_string().len() <= crate::parts::ANSWER_BUDGET
        };
        let counted = matches!(ask, crate::parts::Ask::First)
            && !fits(sv_report::fence::fenced(full), &with_questions);
        let whole_structured = if counted {
            structured(&report)
        } else {
            with_questions
        };
        crate::parts::respond(
            &crate::parts::Answer {
                tool: "stackvet_check",
                what: "check",
                sections: &|fence| check_sections(&report, fence, true),
                first: CHECK_FIRST,
                always: check_always(&report),
                whole_text: &|fence| summary_with(&report, fence, !counted),
                whole_structured,
            },
            &ask,
        )
    }

    /// The plan for an app from its brief (ADR-030): built from the same report as a check, so the
    /// two agree about what applies, and crediting nothing. Whole when it fits what an AI coding tool
    /// takes in whole, and in parts when it does not (`crate::parts`).
    pub(super) fn plan(&self, args: &Value, progress: &Progress) -> Result<Value> {
        let ask = crate::parts::ask(args, "stackvet_plan", crate::plan::SECTIONS)?;
        let app_dir = self.app_dir(args)?;
        let report = self.report_for(&app_dir, progress)?;
        let plan = crate::plan_for(&app_dir, &report)?;
        crate::parts::respond(
            &crate::parts::Answer {
                tool: "stackvet_plan",
                what: "plan",
                sections: &|fence| crate::plan::sections_with(&plan, fence),
                first: crate::plan::FIRST,
                always: crate::plan::always_json(&plan),
                whole_text: &|fence| crate::plan::markdown_with(&plan, fence),
                whole_structured: crate::plan::to_json(&plan),
            },
            &ask,
        )
    }

    /// What `sv run` will need, looked for in the code, with nothing run (ADR-035).
    pub(super) fn preflight(&self, args: &Value) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        // Asked here, so the remedy names the tool the AI coding tool has, not `sv init`.
        needs_manifest(&app_dir, "ask for the preflight again")?;
        let (items, ahead, unread) = crate::preflight::of(&app_dir)?;
        Ok(json!({
            "content": [{
                "type": "text",
                "text": sv_report::fence::fenced(|fence| crate::preflight::markdown_with(&items, &ahead, &unread, fence)),
            }],
            "structuredContent": crate::preflight::to_json(&items, &ahead, &unread),
            "isError": false,
        }))
    }

    /// Is everything ready (`crate::doctor`, as `sv doctor` gives it). The folder's name and what
    /// stackvet.toml says are the app's own text, so they are fenced; the rest is `sv`'s.
    pub(super) fn status(&self, args: &Value) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        let version = crate::doctor::version_line();
        let backend = || sv_run::detect().map(|_| ());
        let asked = crate::doctor::Asked {
            version: &version,
            data: sv_frameworks::data::dir(),
            in_container: std::env::var_os(super::IN_CONTAINER).is_some()
                || crate::connect::in_a_container(),
            backend: &backend,
        };
        let lines = crate::doctor::answers(&app_dir, &asked);
        let shown = args.get("path").and_then(Value::as_str).unwrap_or(".");
        let text = sv_report::fence::fenced(|fence| {
            crate::doctor::text_quoting(shown, &lines, &|t| fence.wrap(t))
        });
        let not_ready = lines
            .iter()
            .filter(|l| l.state == crate::doctor::State::NotReady)
            .count();
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": {
                "lines": lines.iter().map(|l| json!({
                    "topic": l.topic,
                    "state": match l.state {
                        crate::doctor::State::Ready => "ready",
                        crate::doctor::State::NotReady => "not-ready",
                        crate::doctor::State::CannotTell => "cannot-tell",
                    },
                    "says": l.said,
                })).collect::<Vec<_>>(),
                "notReady": not_ready,
                "creditsNothing": true,
            },
            "isError": false,
        }))
    }

    /// One feature's brief, before it is built: built from the same report as the plan, crediting
    /// nothing. The feature is checked before the report is built, so a misspelt one is said at once.
    pub(super) fn before(&self, args: &Value, progress: &Progress) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        let feature = args
            .get("feature")
            .and_then(Value::as_str)
            .context("stackvet_before needs `feature`")?;
        crate::brief::Features::load(&crate::feature_briefs_path())?.get(feature)?;
        // Before stackvet.toml is written, the brief gives what does not wait for it, rather
        // than refusing: builders ask for it first (the backlog, the delivery test of 6 October).
        let brief = if sv_manifest::locate(&app_dir)?.is_some() {
            let report = self.report_for(&app_dir, progress)?;
            crate::brief_for(&report, feature, &self.loaded)?
        } else {
            crate::brief_without_manifest(feature, &self.loaded)?
        };
        Ok(json!({
            "content": [{
                "type": "text",
                "text": sv_report::fence::fenced(|fence| crate::brief::markdown_with(&brief, fence)),
            }],
            "structuredContent": crate::brief::to_json(&brief),
            "isError": false,
        }))
    }

    /// The questions only a person can answer, for the tool to ask them one at a time.
    /// Answered by its old name only: it is `stackvet_check` with section "questions" now.
    pub(super) fn questions(&self, args: &Value, progress: &Progress) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        let report = self.report_for(&app_dir, progress)?;
        Ok(questions_answer(&report))
    }

    /// The rules to follow while writing the app, for all of it or one topic, from OWASP AISVS
    /// Appendix C, with its attribution and license. Reads nothing but stackvet.toml and the app's
    /// files to leave out rules that do not apply, and changes nothing.
    pub(super) fn guidance(&self, args: &Value) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        let found = crate::coding_rules_for(&app_dir)?;
        let topic = args
            .get("topic")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty());
        if let Some(topic) = topic {
            let known = found.rules.topic_ids();
            anyhow::ensure!(
                known.contains(&topic),
                "there is no topic {topic:?}; the topics are {}",
                known.join(", ")
            );
        }
        let given: Vec<Value> = found
            .rules
            .rules
            .iter()
            .filter(|r| found.given.contains(&r.id) && topic.is_none_or(|t| r.topic == t))
            .map(|r| json!({ "id": r.id, "topic": r.topic, "rule": r.rule, "cites": r.cites.keys().collect::<Vec<_>>() }))
            .collect();
        let mut text = found.markdown(topic);
        // With no topic, the whole app's prompts shown to work come with the rules: what to ask of
        // the code everywhere, as the brief for each feature gives that feature's (ADR-044).
        let prompts = if topic.is_none() {
            crate::whole_app_prompts(&self.loaded)?
        } else {
            Vec::new()
        };
        if !prompts.is_empty() {
            text.push_str(
                "\n## Prompts shown to work, for the whole app\n\nEach of these was given to an AI \
                 coding tool building an app, and `sv` found that the problem it is for went away. \
                 Follow them in all of the code, as you follow the rules above:\n\n",
            );
            for p in &prompts {
                text.push_str(&format!("### {} (`{}`)\n\n", p.title, p.id));
                for line in p.prompt.lines() {
                    text.push_str(&format!("> {line}\n"));
                }
                text.push('\n');
            }
        }
        if topic.is_some() && given.is_empty() {
            text = format!(
                "No rule on that topic applies to this app, according to stackvet.toml.\n\n{}\n",
                found.rules.credit()
            );
        }
        let a = &found.rules.attribution;
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": {
                "rules": given,
                "prompts": prompts.iter().map(|p| json!({ "id": p.id, "title": p.title, "text": p.prompt })).collect::<Vec<_>>(),
                "leftOut": if topic.is_none() { found.withheld } else { 0 },
                "filteredBySecurevibeToml": found.filtered,
                "attribution": {
                    "title": a.title, "authors": a.authors, "url": a.url,
                    "license": a.license, "licenseUrl": a.license_url, "changes": a.changes,
                },
            },
            "isError": false,
        }))
    }

    /// The library's prompts for the AI coding tool, for one requirement or all of them, each saying
    /// whether it has been shown to work. Reads only the library, and changes nothing.
    pub(super) fn prompts(&self, args: &Value) -> Result<Value> {
        let requirement = args
            .get("requirement")
            .and_then(Value::as_str)
            .filter(|q| !q.is_empty());
        if args.get("path").and_then(Value::as_str).is_some() {
            anyhow::ensure!(
                requirement.is_none(),
                "give either requirement or path, not both"
            );
            // The folder with the new name, or the old one while only it exists (ADR-062).
            let folder = sv_scan::ecosystems::default_report_dir_in(&self.app_dir(args)?);
            let folder_name = folder
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| sv_scan::ecosystems::DEFAULT_REPORT_DIR.to_owned());
            let report_name = format!("{folder_name}/report.json");
            let report = folder.join("report.json");
            // A link could point outside the root, as for every other file read here.
            if let Ok(meta) = std::fs::symlink_metadata(&report) {
                anyhow::ensure!(
                    !meta.file_type().is_symlink(),
                    "{report_name} is a link to somewhere else, so it is not read"
                );
            }
            let crate::ReportPrompts {
                prompts,
                offered,
                gaps,
                ..
            } = crate::prompts_for_report(&report)?;
            let chosen: Vec<Value> = offered
                .iter()
                .filter_map(|(id, for_ids)| {
                    let p = prompts.prompts.iter().find(|p| &p.id == id)?;
                    Some(json!({
                        "id": p.id, "title": p.title, "prompt": p.prompt,
                        "requirements": p.requirements, "sbdControls": p.sbd_controls,
                        "status": p.status.as_str(),
                        "result": p.tested.as_ref().map(|t| t.result.as_str()),
                        "forRequirements": for_ids,
                    }))
                })
                .collect();
            // The report is a file in the app's folder, so nothing in it is repeated as written: only
            // requirement ids the library itself names reach the text, each with fixed words for its
            // status.
            let offered_refs: Vec<(&sv_check::prompts::Prompt, Vec<String>)> = offered
                .iter()
                .filter_map(|(id, ids)| {
                    Some((prompts.prompts.iter().find(|p| &p.id == id)?, ids.clone()))
                })
                .collect();
            let text = prompts.gaps_markdown(
                &offered_refs,
                &gaps,
                &format!("the app's last report ({report_name})"),
            );
            return Ok(json!({
                "content": [{ "type": "text", "text": text }],
                "structuredContent": {
                    "prompts": chosen,
                    "credit": prompts.credit,
                    "report": report_name,
                    "unproven": gaps.len(),
                },
                "isError": false,
            }));
        }
        let (prompts, ids, text) = crate::prompts_for(&self.loaded.frameworks, requirement)?;
        let chosen: Vec<Value> = ids
            .iter()
            .filter_map(|id| prompts.prompts.iter().find(|p| &p.id == id))
            .map(|p| {
                json!({
                    "id": p.id, "title": p.title, "prompt": p.prompt,
                    "requirements": p.requirements, "sbdControls": p.sbd_controls,
                    "status": p.status.as_str(),
                    "result": p.tested.as_ref().map(|t| t.result.as_str()),
                })
            })
            .collect();
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": { "prompts": chosen, "credit": prompts.credit },
            "isError": false,
        }))
    }

    /// Makes or refreshes security-notes.md, so the tool can write the owner's decisions into it.
    pub(super) fn notes_file(&self, args: &Value) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        needs_manifest(&app_dir, "try again")?;
        // The one file this writes is inside a folder already held to the root, but the file itself
        // could be a link to somewhere else, and writing follows it. Refused before anything is
        // written, the same care `stackvet_write_report` takes with its folder.
        let target = app_dir.join("security-notes.md");
        if let Ok(meta) = std::fs::symlink_metadata(&target) {
            anyhow::ensure!(
                !meta.file_type().is_symlink(),
                "{} is a link to somewhere else, so it is not written",
                target.display()
            );
        }
        let written = crate::write_notes_file(&app_dir)?;
        let text = sv_report::fence::fenced(|fence| {
            format!(
                "Wrote {}, keeping every answer already in it. {} question{} apply, {} already \
                     answered. Record the person's decisions with stackvet_record_answer; \
                     stackvet_check lists the questions, in its section \"questions\".{}",
                fence.wrap(&written.path.display().to_string()),
                written.asked,
                if written.asked == 1 { "" } else { "s" },
                written.already,
                if written.kept {
                    format!(
                        " Some text in the file is not under any question; it is kept as it \
                             was, near the top under \"{}\", and not read as an answer.",
                        sv_check::notes::KEPT_HEADING.trim_start_matches("## ")
                    )
                } else {
                    String::new()
                }
            )
        });
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": {
                "file": written.path.display().to_string(),
                "asked": written.asked,
                "alreadyAnswered": written.already,
                "keptOutsideQuestions": written.kept,
            },
            "isError": false,
        }))
    }

    /// The AI coding tool's answer to one written-decision question, recorded under it in
    /// security-notes.md and marked as the tool's own.
    ///
    /// The tool used to edit the file itself, and once credited its own answers to the owner. Now
    /// `sv` writes the mark, and it is always `Written by: AI coding tool`: this server cannot tell
    /// whether the person said something or the tool only says they did, so it offers no way to say
    /// "the owner" (the owner's decision, 4 October 2026). The person changes the line themselves.
    ///
    /// Called with no id and no answer, it makes or refreshes the file and records nothing, which
    /// `stackvet_notes_file` did before it was folded in here (backlog 0187, part 10).
    pub(super) fn record_answer(&self, args: &Value) -> Result<Value> {
        if args.get("id").is_none() && args.get("answer").is_none() {
            return self.notes_file(args);
        }
        let app_dir = self.app_dir(args)?;
        let text = |key: &str| {
            args.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .with_context(|| format!("{key} is needed, as text"))
        };
        let id = text("id")?;
        let answer = text("answer")?;
        let written = crate::record_tool_answer(&app_dir, id, answer)?;
        let text = sv_report::fence::fenced(|fence| {
            format!(
                "Recorded under {} in {}, marked `Written by: AI coding tool`. The report counts \
                     it as stated by the AI coding tool, which is less than the person's own word, and \
                     asks again. Show the person what you wrote; if they agree with it, they can change \
                     that line to `Written by: owner` themselves and record it by running `sv review` \
                     in their own terminal. Do not change it or run `sv review` for them.",
                fence.wrap(id),
                fence.wrap(&written.path.display().to_string())
            )
        });
        Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": {
                "file": written.path.display().to_string(),
                "id": id,
                "writtenBy": sv_check::notes::BY_AI_TOOL,
            },
            "isError": false,
        }))
    }

    /// One zip beside the app: the app, its report and a SHA-256 for every file, with anything that could hold a
    /// secret left out and listed (see `bundle.rs`). Written beside the app and never inside it, and only where
    /// this server may write at all: below the folder it was started for.
    pub(super) fn bundle(&self, args: &Value, progress: &Progress) -> Result<Value> {
        let app_dir = self.app_dir(args)?;
        let name = crate::bundle::safe_name(
            &app_dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "app".to_owned()),
        );
        // Beside the app means in its parent, which has to be inside the root: when the app is the root itself,
        // the parent is somewhere this server was not started for.
        let parent = app_dir.parent().map(Path::to_path_buf).unwrap_or_default();
        if app_dir == self.root || !parent.starts_with(&self.root) {
            return Err(crate::Remedy::error(
                format!(
                    "the bundle is written beside the app, and beside {} would be outside {}, the \
                     folder this server was started for. At a terminal: {}.",
                    app_dir.display(),
                    self.root.display(),
                    this_sv_running("bundle", &app_dir.to_string_lossy())
                ),
                "Start the server for the folder that holds the app, or ask the person to run that \
                 command in a terminal.",
            ));
        }
        // Resolved through links, so a `-stackvet-bundle.zip` that is a link to somewhere else is refused
        // before anything is written.
        let zip = crate::bundle::resolve_for_writing(
            &parent.join(format!("{name}-{}", sv_frameworks::names::BUNDLE_SUFFIX)),
        );
        anyhow::ensure!(
            zip.starts_with(&self.root) && !zip.starts_with(&app_dir),
            "the bundle would be written to {}, which is outside {} or inside the app",
            zip.display(),
            self.root.display()
        );
        // A link is followed by the write, and a link to a file that does not exist yet resolves to nothing above:
        // it is refused by what it is, as the notes file is.
        if let Ok(meta) = std::fs::symlink_metadata(&zip) {
            anyhow::ensure!(
                !meta.file_type().is_symlink(),
                "{} is a link to somewhere else, so it is not written",
                zip.display()
            );
        }
        let report = self.report_for(&app_dir, progress)?;
        let outcome = crate::write_bundle(
            &app_dir,
            &zip,
            &report,
            "sv bundle (asked for through the MCP server)",
        )?;
        Ok(json!({
            "content": [{
                "type": "text",
                "text": sv_report::fence::fenced(|fence| outcome.summary_with(fence)),
            }],
            "structuredContent": {
                "zip": outcome.zip.display().to_string(),
                "files": outcome.files,
                "appFiles": outcome.included,
                "leftOut": outcome.left_out.iter().map(|(path, reason)| json!({"path": path, "reason": reason})).collect::<Vec<_>>(),
            },
            "isError": false,
        }))
    }
}

/// The questions only the person can answer, for the tool to ask them one at a time, as the old
/// name gave them: the interview's text, and the questions as structured items.
fn questions_answer(report: &sv_report::Report) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": sv_report::fence::fenced(|fence| sv_report::interview::text_with(report, fence)),
        }],
        "structuredContent": { "questions": report.questions_for_you },
        "isError": false,
    })
}

/// What a panic said, when it said it in words.
fn panic_words(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "it gave no reason in words".to_owned())
}
