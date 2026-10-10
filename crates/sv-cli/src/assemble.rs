//! `sv report`'s one pass over an app, in the stages it names (`REPORT_STAGES`): the app's files
//! read once (`static_scan`), then the report put together from them and from what else was asked
//! for. Each stage below is one function; what they hand each other is in `Scene` (what every stage
//! reads) and in what each returns. The order of the findings, the credits, the gaps, and the
//! `examined` list is the order the stages run in, which the verdict snapshots
//! (`crates/sv-cli/tests/verdicts.rs`) hold.
//!
//! Until 8 October 2026 this was one function of 1,590 lines in `main.rs` (the review of 8 October
//! 2026, item 7).

use super::*;

/// The stages of a report that `assemble_report_saying` names as it starts each, in order. The MCP
/// server passes them on, so a long check does not look stuck.
///
/// Every stage is announced on every run, in this order, so a count of them means the same each
/// time; the three that run only when asked say so in their names. They were one stage, "Putting
/// the report together", until `sv report --run --tools` sat in it for minutes without a word
/// (backlog 226, part 2, item 15).
pub const REPORT_STAGES: [&str; 10] = [
    "Reading the app's files",
    "Recognizing its languages and frameworks",
    "Listing the packages it uses",
    "Looking for keys and passwords",
    "Reading its configuration",
    "Reading its code",
    "Comparing its packages with known vulnerabilities, when there is a database",
    "Running the outside tools, when asked with --tools",
    "Running the app, when asked with --run",
    "Putting the report together",
];

/// One line of progress for a person watching `sv report`: which stage of how many, and what it is.
pub fn stage_line(n: usize, name: &str) -> String {
    format!("sv report: {} of {}, {name}", n + 1, REPORT_STAGES.len())
}

/// `assemble_report`, calling `starting` with each stage's number (from 0) and name as it begins.
/// What the design answers given as `planned` come to, when they are not a finding: each credits
/// nothing, and the report says which are plans, which are due an answer, and which `sv` cannot
/// follow (`sv_check::design`, "`planned`").
fn planned_gaps(planned: &[sv_check::design::Planned]) -> Vec<sv_report::Gap> {
    use sv_check::design::PlannedState;
    let of = |state: PlannedState| -> Vec<String> {
        planned
            .iter()
            .filter(|p| p.state == state)
            .map(|p| match &p.location {
                Some(path) => format!("{} (in `{path}`)", p.id),
                None => p.id.clone(),
            })
            .collect()
    };
    let decisions = |n: usize| format!("{n} design decision{}", if n == 1 { "" } else { "s" });
    let mut gaps = Vec::new();
    let not_yet = of(PlannedState::NoCodeYet);
    if !not_yet.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!("{} planned, not built yet", decisions(not_yet.len())),
            why: format!(
                "stackvet.toml answers these as planned, and the app has no code yet, so there is \
                 nothing to check: {}. A plan counts for nothing until it is built; once the code \
                 exists, a planned file that is not there is reported as decided, never built.",
                not_yet.join(", ")
            ),
        });
    }
    let due = of(PlannedState::FileIsThere);
    if !due.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!("{} planned, and the file is there now", decisions(due.len())),
            why: format!(
                "stackvet.toml still answers these as planned, and the file each names is in the \
                 app now: {}. Look at it, then change the answer to yes if it does what was decided, \
                 or to no if it does not. Until then it counts for nothing.",
                due.join(", ")
            ),
        });
    }
    let blind = of(PlannedState::NothingToLookFor);
    if !blind.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!("{} planned, with no file named", decisions(blind.len())),
            why: format!(
                "stackvet.toml answers these as planned without a `where`, and the app has code \
                 now, so `sv` cannot tell whether they were built: {}. Change each answer to yes, \
                 naming the file that does it, or to no.",
                blind.join(", ")
            ),
        });
    }
    gaps
}

/// What every stage reads: the app, the options, `sv`'s data, the manifest, the one reading of the
/// app's files, what the manifest's claims came to, and what this computer can check seals with.
#[derive(Clone, Copy)]
struct Scene<'a> {
    app_dir: &'a Path,
    options: &'a ReportOptions,
    loaded: &'a Loaded,
    manifest: &'a Manifest,
    /// The manifest's file name as read: the new name, or the old one (ADR-062).
    manifest_file: &'a str,
    static_scan: &'a static_scan::StaticScan,
    ctx: &'a sv_frameworks::applicability::ConditionContext,
    resolved: &'a [sv_manifest::ResolvedClaim],
    buckets: &'a sv_frameworks::applicability::Buckets,
    seals: &'a sv_check::seal::Checker,
}

/// What the advisory comparison came to.
pub struct Advisories {
    pub findings: Vec<sv_check::Finding>,
    pub verified: Vec<sv_check::Verified>,
    pub gaps: Vec<sv_report::Gap>,
}

/// What the outside tools came to.
pub struct Tools {
    pub verified: Vec<sv_check::Verified>,
    pub gaps: Vec<sv_report::Gap>,
}

/// What running the app came to, or why it was not run.
pub struct RunningApp {
    pub status: sv_report::RunStatus,
    pub note: Option<String>,
    pub steps: Vec<String>,
    pub test_output: Option<sv_check::suite::FailingOutput>,
    pub tests_examined: sv_report::Examined,
    pub probe_verified: Vec<sv_check::Verified>,
    pub test_verified: Vec<sv_check::Verified>,
}

/// The owner's word, from the notes, the decisions file, and the manifest's design and hand-check
/// answers: what it credits, and the catalogs the report prints the questions from.
pub struct PersonsWord {
    pub verified: Vec<sv_check::Verified>,
    pub notes_catalog: sv_check::notes::Catalog,
    pub design_questions: sv_check::design::Questions,
    pub human_checks: sv_check::human::HumanChecks,
    pub decisions_text: Option<String>,
}

/// `assemble_report`, calling `starting` with each stage's number (from 0) and name as it begins.
pub fn assemble_report_saying(
    app_dir: &Path,
    options: &ReportOptions,
    loaded: &Loaded,
    starting: &dyn Fn(usize, &'static str),
) -> Result<sv_report::Report> {
    // When each stage began, so the report can say how long each took (backlog 226, part 2, item
    // 13): a stage lasts until the next begins, the last until the report is put together.
    let began: std::cell::RefCell<Vec<(&'static str, std::time::Instant)>> = Default::default();
    let stage = |n: usize| {
        began
            .borrow_mut()
            .push((REPORT_STAGES[n], std::time::Instant::now()));
        starting(n, REPORT_STAGES[n])
    };
    let started = std::time::SystemTime::now();
    // The new name, or the old one while only it exists (ADR-062); the report says which.
    let located = sv_manifest::locate_or_bail(app_dir)?;
    let manifest_path = located.path.clone();
    let manifest_file = manifest_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| sv_frameworks::names::MANIFEST.to_owned());
    // Read once, so the hash recorded is of the very bytes parsed.
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest = Manifest::parse(&manifest_text, &manifest_path)?;
    let run_record = report_lock::run_record(started, manifest_text.as_bytes());
    // The same reading of the app `sv check` makes (`static_scan`): one walk of the folder, shared
    // by every check in this report (DESIGN, "One walk of the app"), the languages and packages,
    // the keys and passwords, the configuration, and the code. The bill of materials knows what
    // actually came out of each ecosystem, which is the difference between "this list is
    // approximate" and "this list is empty"; built once and handed to the lockfile check and the
    // findings below.
    let static_scan =
        static_scan::StaticScan::read(app_dir, &manifest.not_the_app().0, loaded, &stage)?;
    let (ctx, resolved) =
        sv_manifest::resolve(&manifest, &static_scan.scan_report.as_corroborator());
    let buckets = bucket(
        &loaded.frameworks,
        &loaded.config_rules,
        &ctx,
        manifest.target_level(),
    );
    // What this computer can check `sv review`'s seals with (`sv_check::seal`): the owner's own
    // answers count as theirs only when `sv review` recorded them for this app.
    let seals = sv_check::seal::Checker::for_app(app_dir);
    let scene = Scene {
        app_dir,
        options,
        loaded,
        manifest: &manifest,
        manifest_file: &manifest_file,
        static_scan: &static_scan,
        ctx: &ctx,
        resolved: &resolved,
        buckets: &buckets,
        seals: &seals,
    };
    stage(6);
    // What was examined, per family of findings, for a program reading report.json: the same
    // limits as the gaps, decided in the same places (DESIGN, "What was examined, for a program").
    let mut examined: Vec<sv_report::Examined> = vec![sv_report::Examined::ran("sbom.")];
    let advisories = advisories(&scene, &mut examined)?;

    let mut findings = Vec::new();
    findings.extend(advisories.findings);
    findings.extend(static_scan.secrets.findings.iter().cloned());
    findings.extend(static_scan.config.findings.iter().cloned());
    // The bill of materials speaks for itself here as it does in `sv check`: incomplete is a finding
    // against V15.1.2, complete is evidence for it, and exactly one of the two says anything. The
    // report used to read only its gaps, so a lockfile it could take nothing from was left to the
    // lockfile check, which saw a lockfile and passed it.
    findings.extend(sbom::incompleteness_finding(&static_scan.bill_of_materials));
    findings.extend(static_scan.code.findings.iter().cloned());

    stage(7);
    let tools = outside_tools(&scene, &mut findings, &mut examined)?;

    // Every limit `sv` knows about, said out loud. This list existing is the difference between a
    // report about an app and a report about the part of an app somebody happened to look at.
    let mut gaps = Vec::new();
    // Said first: a file read under its old name is the one thing here about `sv` and not the app.
    if let Some(note) = located.note() {
        gaps.push(sv_report::Gap {
            what: format!("the manifest, named {manifest_file}"),
            why: note,
        });
    }
    stage(8);
    let run = running_app(&scene, &mut findings, &mut gaps);
    stage(9);
    gaps.extend(tools.gaps);
    let manual_only = what_was_not_read(&scene, &mut gaps, &mut examined);
    gaps.extend(advisories.gaps);

    // Everything that ran, looked at what it needed to, and found nothing wrong. Each of these
    // fails closed on its own coverage, so the list is short on an app `sv` could not read fully —
    // which is the honest shape for it to have.
    let mut verified = static_scan.config.passed.clone();
    verified.extend(sbom::completeness_verified(&static_scan.bill_of_materials));
    verified.extend(static_scan.secrets.verified.iter().cloned());
    verified.extend(static_scan.code.verified.iter().cloned());
    verified.extend(run.probe_verified.iter().cloned());
    verified.extend(tools.verified);
    verified.extend(advisories.verified);
    verified.extend(run.test_verified.iter().cloned());

    let (named_in_tests, not_for_tests) = requirements_for_tests(&scene);
    let word = the_owners_word(&scene, &mut findings, &mut gaps)?;
    // A person's word goes to the report in the one list with the checks, each credit saying
    // which tier it rests on (`sv_check::Tier`, set where it was made); the report reads the tier,
    // not the list (8 October 2026).
    verified.extend(word.verified.iter().cloned());
    let coding_rules_cited = coding_rules_cited(&buckets)?;
    let mut report = put_together(
        &scene,
        Gathered {
            findings,
            verified,
            gaps,
            examined,
            manual_only,
            named_in_tests,
            not_for_tests,
            coding_rules_cited,
            run,
            word,
            run_record,
        },
    )?;
    report.timings = timings(&began.borrow(), std::time::Instant::now(), &report.examined);
    Ok(report)
}

/// How long each stage took, from when each began to when the next did (the last to `ended`), then
/// each outside tool, from the record of its run.
fn timings(
    began: &[(&'static str, std::time::Instant)],
    ended: std::time::Instant,
    examined: &[sv_report::Examined],
) -> Vec<sv_report::Timing> {
    let ms = |d: std::time::Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let mut timings: Vec<sv_report::Timing> = began
        .iter()
        .enumerate()
        .map(|(i, (what, at))| {
            let until = began.get(i + 1).map_or(ended, |(_, next)| *next);
            sv_report::Timing {
                what: (*what).to_owned(),
                took_ms: ms(until.saturating_duration_since(*at)),
            }
        })
        .collect();
    timings.extend(examined.iter().filter_map(|e| {
        let tool = e.tool.as_ref()?;
        Some(sv_report::Timing {
            what: format!("{}{}", sv_report::TOOL_TIMING, tool.program),
            took_ms: tool.took_ms,
        })
    }));
    timings
}

/// Known vulnerabilities, when the owner has pointed at a local advisory database, held to the
/// time frames in stackvet.toml exactly as `sv audit` holds them. Without a database this says
/// so: a report silent about known vulnerabilities reads as a report that found none.
fn advisories(scene: &Scene, examined: &mut Vec<sv_report::Examined>) -> Result<Advisories> {
    let Scene {
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        static_scan,
        ctx,
        resolved,
        buckets,
        seals,
    } = *scene;
    let static_scan::StaticScan {
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
    } = static_scan;
    let Loaded {
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
        ..
    } = loaded;
    let _ = (
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        ctx,
        resolved,
        buckets,
        seals,
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
    );

    let mut findings_from_advisories = Vec::new();

    // Known vulnerabilities, when the owner has pointed at a local advisory database, held to the
    // time frames in stackvet.toml exactly as `sv audit` holds them. Without a database this says
    // so: a report silent about known vulnerabilities reads as a report that found none.
    let mut advisory_verified = Vec::new();
    let mut advisory_gaps = Vec::new();
    match &options.advisories {
        None => {
            examined.push(sv_report::Examined::not_run(
                "advisory.",
                "no advisory database was given (--advisories)",
            ));
            advisory_gaps.push(sv_report::Gap {
                what: "known vulnerabilities in the packages this app ships".to_owned(),
                why: format!(
                    "{} `sv` does not fetch anything, because the list of packages an app depends \
                     on is yours: download an OSV export for this app's ecosystems, unpack it, and \
                     pass its folder with --advisories.{}",
                    options.why_no_advisories,
                    {
                        let mut names: Vec<&str> = bill_of_materials
                            .components
                            .iter()
                            .map(|c| c.ecosystem.as_str())
                            .collect();
                        names.sort_unstable();
                        names.dedup();
                        names
                            .iter()
                            .filter_map(|n| {
                                advisories::osv_download(n).map(|url| format!(" {n}: {url}."))
                            })
                            .collect::<String>()
                    }
                ),
            })
        }
        Some(dir) => {
            let advisories::Database {
                records: database,
                unread,
            } = advisories::read_database(dir)
                .with_context(|| format!("reading the advisory database at {}", dir.display()))?;
            if database.is_empty() {
                examined.push(sv_report::Examined::not_run(
                    "advisory.",
                    "the advisory database holds no records `sv` could read",
                ));
                advisory_gaps.push(sv_report::Gap {
                    what: "known vulnerabilities in the packages this app ships".to_owned(),
                    why: format!(
                        "{} holds no advisory records `sv` could read, so nothing was compared. \
                         An empty database and a healthy app look the same from here.",
                        dir.display()
                    ),
                });
            } else {
                let mut result = advisories::audit_against(
                    bill_of_materials,
                    &database,
                    manifest.policy.fix_within_days.as_ref(),
                    advisories::Day::today(),
                );
                // Whole only as `sv audit` counts it: every ecosystem covered, every version
                // comparable, and the list of packages itself complete.
                let mut short = Vec::new();
                if !unread.is_empty() {
                    short.push(format!(
                        "{} file{} in the advisory database could not be read ({})",
                        unread.len(),
                        if unread.len() == 1 { "" } else { "s" },
                        unread
                            .iter()
                            .take(3)
                            .map(|(name, _)| format!("`{name}`"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !result.uncovered.is_empty() {
                    let names: Vec<String> = result.uncovered.iter().cloned().collect();
                    short.push(format!(
                        "the database holds nothing about {}",
                        names.join(", ")
                    ));
                }
                if !result.uncomparable.is_empty() {
                    short.push(format!(
                        "{} package version(s) could not be compared",
                        result.uncomparable.len()
                    ));
                }
                if !bill_of_materials.is_complete() {
                    short.push("the list of packages is incomplete".to_owned());
                }
                // A finding that stops appearing because a different lockfile was read is not a
                // fixed finding, so a second lockfile nothing compared keeps this from `ran`.
                for passed in &bill_of_materials.passed_over {
                    short.push(format!(
                        "{} not read beside `{}`",
                        passed.not_read_list(),
                        passed.read
                    ));
                }
                // Nor is one that stops appearing because the manifest moved on and the lock did not.
                for disagreement in bill_of_materials
                    .disagreements
                    .iter()
                    .filter(|d| d.differs())
                {
                    short.push(format!(
                        "`{}` asks for other versions than `{}` has",
                        disagreement.manifest, disagreement.lockfile
                    ));
                }
                examined.push(if short.is_empty() {
                    sv_report::Examined::ran("advisory.")
                } else {
                    sv_report::Examined::partly("advisory.", short.join("; "))
                });
                // Records in a file nobody read were not compared, so nothing is credited on the
                // comparison, as `sv audit` credits nothing (the deep review's improvement 4).
                if !unread.is_empty() {
                    result.verified.clear();
                    advisory_gaps.push(sv_report::Gap {
                        what: "advisory files that could not be read".to_owned(),
                        why: format!(
                            "{}{}. The records in them were not compared with this app's packages.",
                            unread
                                .iter()
                                .take(10)
                                .map(|(name, why)| format!("`{name}`: {why}"))
                                .collect::<Vec<_>>()
                                .join("; "),
                            if unread.len() > 10 {
                                format!("; and {} more", unread.len() - 10)
                            } else {
                                String::new()
                            }
                        ),
                    });
                }
                findings_from_advisories = result.findings;
                advisory_verified = result.verified;
                if !result.uncovered.is_empty() {
                    advisory_gaps.push(sv_report::Gap {
                        what: format!(
                            "known vulnerabilities in this app's {} packages",
                            result
                                .uncovered
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        why: "the advisory database holds nothing about them, so they were not \
                              compared. That is not the same as their being clean."
                            .to_owned(),
                    });
                }
                if !result.uncomparable.is_empty() {
                    let n = result.uncomparable.len();
                    let shown: Vec<String> = result
                        .uncomparable
                        .iter()
                        .take(5)
                        .map(|(name, version)| format!("{name} {version}"))
                        .collect();
                    advisory_gaps.push(sv_report::Gap {
                        what: format!(
                            "whether {n} package version{} {} a known vulnerability ({}{})",
                            if n == 1 { "" } else { "s" },
                            if n == 1 { "has" } else { "have" },
                            shown.join(", "),
                            if n > 5 { ", …" } else { "" }
                        ),
                        why: "these versions could not be compared with any affected range, so \
                              nothing is claimed about them either way"
                            .to_owned(),
                    });
                }
            }
        }
    }
    Ok(Advisories {
        findings: findings_from_advisories,
        verified: advisory_verified,
        gaps: advisory_gaps,
    })
}

/// The language's own tool, where there is one and it is here. A tool that is not installed is
/// recorded as not run, with how to install it, never as having found nothing.
fn outside_tools(
    scene: &Scene,
    findings: &mut Vec<sv_check::Finding>,
    examined: &mut Vec<sv_report::Examined>,
) -> Result<Tools> {
    let Scene {
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        static_scan,
        ctx,
        resolved,
        buckets,
        seals,
    } = *scene;
    let static_scan::StaticScan {
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
    } = static_scan;
    let Loaded {
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
        ..
    } = loaded;
    let _ = (
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        ctx,
        resolved,
        buckets,
        seals,
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
    );

    let mut tool_verified = Vec::new();
    // The language's own tool, where there is one and it is here. A tool that is not installed is
    // recorded as not run, with how to install it — never as having found nothing.
    let mut tool_gaps = Vec::new();
    if options.run_tools {
        let adapters = adapters.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
        let languages: Vec<String> = scan_report.languages.iter().cloned().collect();
        let not_holding = adapters.not_holding(|condition| ctx.get(condition));
        // Ctrl-C while a tool runs stops the tool and everything it started, and the run ends
        // here, with the tools' private folder removed and the report folder let go of. Before
        // this, nothing caught Ctrl-C on this path: it ended `sv` alone, and the tool, in a process
        // group of its own, ran on with no limit (the review of 8 October 2026, item 1).
        sv_run::catch_interrupts();
        sv_check::adapters::stop_when(sv_run::interrupted);
        let outcome = sv_check::adapters::run_all_in(
            adapters,
            listing,
            &languages,
            &not_holding,
            &sv_check::adapters::scratch_dir(),
            secret_rules,
        );
        // What the tools got to before then is not a report of the app, so nothing is written.
        if sv_run::interrupted() {
            eprintln!(
                "Stopped with Ctrl-C. The outside tools were stopped and their reports removed; \
                 nothing was written."
            );
            report_lock::let_go_of_all();
            exit::exit_with(exit::INTERRUPTED);
        }
        examined.extend(adapters_examined(adapters, &languages, &outcome));
        findings.extend(outcome.findings);
        tool_verified = outcome.verified;
        for (id, why) in outcome.not_run {
            tool_gaps.push(sv_report::Gap {
                what: format!("what `{id}` would have found"),
                why,
            });
        }
    } else {
        match adapters {
            Ok(adapters) => {
                for adapter in adapters.all() {
                    examined.push(sv_report::Examined::not_run(
                        format!("{}.", adapter.id),
                        "outside tools run only with --tools",
                    ));
                }
                tool_gaps.push(sv_report::Gap {
                    what: "the security tool this language already has".to_owned(),
                    why: format!(
                        "{} {} each know their languages far better than the handful of rules \
                         built in here.",
                        options.why_no_tools,
                        tool_names(adapters)
                    ),
                });
            }
            // Which tools there are is not known, so none is named, and the report says why
            // rather than listing no outside tools as though there were none.
            Err(why) => tool_gaps.push(sv_report::Gap {
                what: "the security tool this language already has".to_owned(),
                why: format!(
                    "{} Which outside tools sv can run is not known either: {} could not be read \
                     ({why}).",
                    options.why_no_tools,
                    adapters_path().display()
                ),
            }),
        }
    }
    Ok(Tools {
        verified: tool_verified,
        gaps: tool_gaps,
    })
}

/// The app started behind the fence and asked questions, with its own tests run, when `--run` was
/// given; otherwise why it was not, as a gap.
fn running_app(
    scene: &Scene,
    findings: &mut Vec<sv_check::Finding>,
    gaps: &mut Vec<sv_report::Gap>,
) -> RunningApp {
    let Scene {
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        static_scan,
        ctx,
        resolved,
        buckets,
        seals,
    } = *scene;
    let static_scan::StaticScan {
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
    } = static_scan;
    let Loaded {
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
        ..
    } = loaded;
    let _ = (
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        ctx,
        resolved,
        buckets,
        seals,
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
    );

    let mut probe_verified = Vec::new();
    let mut test_verified = Vec::new();
    let mut test_output = None;
    // Whether the app's own tests were read for what they name (`tests.`), for `examined` and for
    // telling a review whose finding is gone from one nobody looked for (deep review R3).
    let mut tests_examined =
        sv_report::Examined::not_run("tests.", "the app's own tests run only with --run");
    let mut run_note = None;
    let mut run_steps: Vec<String> = Vec::new();
    let run_status;

    if options.run_the_app {
        match probe_the_running_app(manifest, app_dir, options.slow) {
            Ok((outcome, plan)) => {
                run_status = sv_report::RunStatus::Started {
                    image: plan.image.clone(),
                    asked: anonymous_requests(&plan).len(),
                    answered: outcome.probe_responses.len(),
                    signed_in: outcome.signed_in.is_some(),
                    tests: match &outcome.tests {
                        Some(t) if t.stopped_after.is_some() => "stopped",
                        other => {
                            sv_report::RunStatus::tests_state(other.as_ref().map(|t| t.exit_code))
                        }
                    }
                    .to_owned(),
                };
                let (running_findings, running_verified, signed_in_not_assessed) =
                    running_app_evidence(&outcome, &plan);
                findings.extend(running_findings);
                probe_verified = running_verified;
                // The summary, and the steps kept apart from it. Joining them made one
                // 381-word paragraph at the top of the report — the first thing the reader met,
                // and unreadable. The renderers lay the steps out as a list.
                let signed_in_steps: Vec<String> = outcome
                    .signed_in
                    .as_ref()
                    .map(|s| s.steps.clone())
                    .unwrap_or_default();
                let oidc_steps: Vec<String> = outcome
                    .oidc
                    .as_ref()
                    .map(|s| s.steps.clone())
                    .unwrap_or_default();
                let ai_steps: Vec<String> = outcome
                    .ai
                    .as_ref()
                    .map(|s| s.steps.clone())
                    .unwrap_or_default();
                // Every suite's steps, from the one list `sv run` prints from too.
                run_steps = outcome
                    .asked()
                    .into_iter()
                    .flat_map(|(_, asked)| asked.steps.iter().cloned())
                    .collect();
                let signed_in_note = if signed_in_steps.is_empty() {
                    String::new()
                } else {
                    format!(
                        " It was then asked {} more question{} as two signed-in test users.",
                        signed_in_steps.len(),
                        if signed_in_steps.len() == 1 { "" } else { "s" }
                    )
                };
                let oidc_note = if oidc_steps.is_empty() {
                    ""
                } else {
                    " Its sign-in through another service was asked about with a test provider of \
                     `sv`'s own, pointed at it for the run."
                };
                let ai_note = if ai_steps.is_empty() {
                    ""
                } else {
                    " Its AI feature was asked with a test model of `sv`'s own in place of the \
                     real one, so nothing was sent to an AI service and nothing was spent."
                };
                run_note = Some(format!(
                    "This app was started with {} and asked {} question{} while it ran, as \
                     somebody who had not signed in. It answered on {}.{signed_in_note}{oidc_note}{ai_note} {}",
                    plan.image,
                    outcome.probe_responses.len(),
                    if outcome.probe_responses.len() == 1 {
                        ""
                    } else {
                        "s"
                    },
                    plan.health_path,
                    outcome.fence.explain()
                ));
                if let (Some(note), Some(installed)) = (
                    run_note.as_mut(),
                    sv_run::install::sentence(&outcome.installed),
                ) {
                    note.push_str(&format!(" {installed}"));
                }
                if let (Some(note), Some(removed)) = (
                    run_note.as_mut(),
                    sv_run::cleanup::removed_sentence(&outcome.left_over_removed),
                ) {
                    note.push_str(&format!(" {removed}"));
                }
                if let (Some(note), Some(container)) =
                    (run_note.as_mut(), outcome.container.sentences())
                {
                    note.push_str(&format!(" {container}"));
                }
                if let (Some(note), Some(weaker)) =
                    (run_note.as_mut(), sv_run::weakening_note(&plan.start))
                {
                    note.push_str(&format!(" {weaker}"));
                }
                for (requirements, why) in signed_in_not_assessed {
                    // AISVS ids are the AI feature's, asked through the test model, which may not
                    // have involved signing in at all.
                    let how = if requirements.starts_with('C') {
                        "by asking the running app's AI feature through a test model"
                    } else {
                        "by asking the running app as a signed-in user"
                    };
                    gaps.push(sv_report::Gap {
                        what: format!("{requirements}, {how}"),
                        why,
                    });
                }
                gaps.extend(rate_limited_gap(&outcome.probes_rate_limited));
                gaps.extend(sidecar_lost_gap(outcome.sidecar_lost.as_deref()));
                // What asking it could not reach. These replace the "it was never started" gap
                // rather than removing it: the app running answers some questions and not others,
                // and the ones it cannot answer are the ones behind a login.
                for (requirements, why) in probes::running_app_gaps(
                    outcome.signed_in.is_some(),
                    &outcome.probe_responses,
                    &bill_of_materials.components,
                ) {
                    gaps.push(sv_report::Gap {
                        what: format!("{requirements}, by asking the running app"),
                        why,
                    });
                }
                match &outcome.tests {
                    Some(result) if result.stopped_after.is_some() => {
                        let after = result.stopped_after.unwrap_or(sv_run::TEST_LIMIT);
                        tests_examined = sv_report::Examined::not_run(
                            "tests.",
                            "the app's own tests were stopped before they finished",
                        );
                        gaps.push(sv_report::Gap {
                            what: "anything the app's own tests would have shown".to_owned(),
                            why: format!(
                                "they had not finished after {}, the most a test run may take, \
                                 and were stopped. A suite cut short credits nothing, whatever it \
                                 printed before it was stopped.",
                                sv_run::minutes(after)
                            ),
                        });
                        test_output = sv_check::suite::failing_output(
                            result.exit_code,
                            &result.output,
                            secret_rules,
                        )
                        .map(|t| sv_check::suite::FailingOutput {
                            stopped_after: Some(sv_run::minutes(after)),
                            ..t
                        });
                    }
                    Some(result) => {
                        // Only tests that name a requirement count, and only when something says
                        // they passed. Matching a test to a requirement by what it is called would
                        // credit one on the strength of a name somebody chose for other reasons.
                        let known: std::collections::BTreeSet<&str> =
                            frameworks.requirements.keys().map(String::as_str).collect();
                        let named = sv_check::suite::tests_naming_requirements_in(listing, &known);
                        let describe = |id: &str| {
                            frameworks
                                .requirements
                                .get(id)
                                .map(|r| r.description.clone())
                        };

                        // A suite that passed outright needs no report. One that did not is worth
                        // whatever its runner's own report says still passed — and nothing more,
                        // which is why an unreadable report falls back to crediting nothing rather
                        // than to crediting what it managed to understand.
                        let reported_cases = if result.exit_code == 0 {
                            None
                        } else {
                            match sv_check::suite::reported_cases(result.report.as_deref()) {
                                Some(Ok(cases)) => Some(cases),
                                Some(Err(unreadable)) => {
                                    gaps.push(sv_report::Gap {
                                        what: "which of the app's own tests passed".to_owned(),
                                        why: format!(
                                            "the suite failed (exit {}) and its report could not \
                                             be read: {}. Nothing is credited from it.",
                                            result.exit_code, unreadable.why
                                        ),
                                    });
                                    None
                                }
                                None => None,
                            }
                        };
                        tests_examined = match (result.exit_code, &reported_cases) {
                            (0, _) => sv_report::Examined::ran("tests."),
                            (_, Some(_)) => sv_report::Examined::partly(
                                "tests.",
                                "the suite failed, and only the tests its runner reported as \
                                 passing were read",
                            ),
                            (_, None) => sv_report::Examined::not_run(
                                "tests.",
                                "the suite failed and nothing says which of its tests passed",
                            ),
                        };
                        let suite_outcome = if result.exit_code == 0 {
                            sv_check::suite::SuiteOutcome::Passed
                        } else {
                            sv_check::suite::SuiteOutcome::Failed {
                                cases: reported_cases.as_deref(),
                            }
                        };
                        let (credited, mismatches) =
                            sv_check::suite::credit(&named, suite_outcome, &describe);

                        test_output = sv_check::suite::failing_output(
                            result.exit_code,
                            &result.output,
                            secret_rules,
                        );
                        if result.exit_code != 0 {
                            gaps.push(sv_report::Gap {
                                what: "anything the failing tests would have shown".to_owned(),
                                why: match (&reported_cases, credited.len()) {
                                    (Some(_), 0) => format!(
                                        "the suite failed (exit {}) and no test its runner \
                                         reported as passing names a requirement",
                                        result.exit_code
                                    ),
                                    (Some(_), n) => format!(
                                        "the suite failed (exit {}); {n} requirement {} from \
                                         tests its runner reported as passing, and the rest of \
                                         the suite says nothing either way",
                                        result.exit_code,
                                        if n == 1 { "claim comes" } else { "claims come" }
                                    ),
                                    (None, _) => format!(
                                        "they failed (exit {}) and nothing says which of them did, \
                                         so nothing can be concluded from them either way. {}",
                                        result.exit_code,
                                        result.report_note.as_deref().unwrap_or(
                                            "Declare test-report in stackvet.toml to have the \
                                             tests that did pass still count."
                                        )
                                    ),
                                },
                            });
                        } else if credited.is_empty() {
                            gaps.push(sv_report::Gap {
                                what: "what the app's own tests cover".to_owned(),
                                why: "the suite passed, and no test names the requirement it is \
                                      for, so nothing here can say which requirements they are \
                                      evidence about. `sv init` explains how to name them."
                                    .to_owned(),
                            });
                        }
                        findings.extend(mismatches);
                        test_verified = credited;
                    }
                    None => {
                        tests_examined = sv_report::Examined::not_run(
                            "tests.",
                            "stackvet.toml declares no test command",
                        );
                        gaps.push(sv_report::Gap {
                            what: "the app's own tests".to_owned(),
                            why: "stackvet.toml declares no test command".to_owned(),
                        })
                    }
                }
            }
            Err(reason) => {
                run_status = sv_report::RunStatus::CouldNotStart {
                    why: reason.clone(),
                };
                tests_examined = sv_report::Examined::not_run(
                    "tests.",
                    "--run was given and the app could not be run",
                );
                gaps.push(sv_report::Gap {
                    what: "the running app".to_owned(),
                    why: format!("--run was given and the app could not be run. {reason}"),
                })
            }
        }
    } else {
        run_status = sv_report::RunStatus::NotAsked {
            why: options.why_not_run.clone(),
        };
        gaps.push(sv_report::Gap {
            what: "the running app".to_owned(),
            why: format!(
                "{} Without it, nothing here has asked the app anything — what it sends to a \
                 browser, what it says when something goes wrong, which sites it accepts.",
                options.why_not_run
            ),
        });
    }
    RunningApp {
        status: run_status,
        note: run_note,
        steps: run_steps,
        test_output,
        tests_examined,
        probe_verified,
        test_verified,
    }
}

/// What no check read, each said as a gap: links, folders left out, files that did not parse,
/// languages without a parser, the checks that could not run, and the requirements that are design
/// review rather than scanning. Returns those last, for the report.
fn what_was_not_read(
    scene: &Scene,
    gaps: &mut Vec<sv_report::Gap>,
    examined: &mut Vec<sv_report::Examined>,
) -> std::collections::BTreeSet<String> {
    let Scene {
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        static_scan,
        ctx,
        resolved,
        buckets,
        seals,
    } = *scene;
    let static_scan::StaticScan {
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
    } = static_scan;
    let Loaded {
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
        ..
    } = loaded;
    let _ = (
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        ctx,
        resolved,
        buckets,
        seals,
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
    );

    if !listing.links.is_empty() {
        let shown: Vec<&str> = listing.links.iter().take(5).map(String::as_str).collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} symbolic link{} in the app, not followed",
                listing.links.len(),
                if listing.links.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "a link can lead outside the app, or back into it in a loop, so nothing here \
                 followed {}: {}{}. What it points at was not read by any check.",
                if listing.links.len() == 1 {
                    "it"
                } else {
                    "them"
                },
                shown.join(", "),
                if listing.links.len() > 5 {
                    format!(", and {} more", listing.links.len() - 5)
                } else {
                    String::new()
                }
            ),
        });
    }
    if !listing.skipped.is_empty() {
        let shown: Vec<String> = listing
            .skipped
            .iter()
            .take(5)
            .map(|(dir, why)| format!("`{dir}/` ({why})"))
            .collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} folder{} left out as installed or built code",
                listing.skipped.len(),
                if listing.skipped.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "a folder named like an ecosystem's output, beside the file that makes it so, holds \
                 code the app installed or built rather than wrote, and no check read it: {}{}. If \
                 one holds the app's own code, move it or rename the folder.",
                shown.join(", "),
                if listing.skipped.len() > 5 {
                    format!(", and {} more", listing.skipped.len() - 5)
                } else {
                    String::new()
                }
            ),
        });
    }
    if !listing.special.is_empty() {
        let shown: Vec<&str> = listing.special.iter().take(5).map(String::as_str).collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} {} in the app that {} not an ordinary file",
                listing.special.len(),
                if listing.special.len() == 1 {
                    "entry"
                } else {
                    "entries"
                },
                if listing.special.len() == 1 {
                    "is"
                } else {
                    "are"
                }
            ),
            why: format!(
                "a named pipe, a socket, or a device is not opened, since opening a pipe waits for \
                 something to write into it: {}{}. No check read {}.",
                shown.join(", "),
                if listing.special.len() > 5 {
                    format!(", and {} more", listing.special.len() - 5)
                } else {
                    String::new()
                },
                if listing.special.len() == 1 {
                    "it"
                } else {
                    "them"
                }
            ),
        });
    }
    if !code.unread_files.is_empty() {
        let shown: Vec<String> = code
            .unread_files
            .iter()
            .take(5)
            .map(|(file, why)| format!("{file} ({why})"))
            .collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} file{} in a language the rules read, not opened",
                code.unread_files.len(),
                if code.unread_files.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: format!(
                "{}{}. While part of the app went unread, no rule that reads these files' language \
                 can say it found nothing wrong.",
                shown.join("; "),
                if code.unread_files.len() > 5 {
                    format!("; and {} more", code.unread_files.len() - 5)
                } else {
                    String::new()
                }
            ),
        });
    }
    if !code.broken_queries.is_empty() {
        let shown: Vec<String> = code
            .broken_queries
            .iter()
            .map(|b| format!("{} for {} ({})", b.rule_id, b.language, b.why))
            .collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} code rule{} that could not run",
                code.broken_queries.len(),
                if code.broken_queries.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: format!(
                "{}. The rule's query for that language would not compile, so it read none of \
                 those files; while a rule did not run, no rule that reads code can say it found \
                 nothing wrong. This is a fault in sv's rule file, not in the app.",
                shown.join("; ")
            ),
        });
    }
    gaps.extend(not_the_app_gaps(manifest, scan_report));
    for (id, why) in &config.not_assessed {
        gaps.push(sv_report::Gap {
            what: format!("the check `{id}`"),
            why: why.clone(),
        });
    }
    if !secrets.coverage.skipped.is_empty() {
        // Each named, with why, so nobody has to go looking for which file it was.
        const SHOWN: usize = 5;
        let skipped = &secrets.coverage.skipped;
        let mut named: Vec<String> = skipped
            .iter()
            .take(SHOWN)
            .map(|(file, why)| format!("`{file}` ({why})"))
            .collect();
        if skipped.len() > SHOWN {
            named.push(format!(
                "and {} more, listed by `sv check`",
                skipped.len() - SHOWN
            ));
        }
        gaps.push(sv_report::Gap {
            what: format!(
                "{} file{} not read while looking for credentials",
                skipped.len(),
                if skipped.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "{}. A credential in a file nothing read is a credential nothing found.",
                named.join(", ")
            ),
        });
    }
    if !code.unread_languages.is_empty() {
        let mut names: Vec<&str> = code.unread_languages.iter().map(String::as_str).collect();
        names.sort_unstable();
        let mut why =
            "`sv` has no parser for these, so the rules that read code did not run on them"
                .to_owned();
        if !code.unread_templates.is_empty() {
            why.push_str(&format!(
                "; the templates are {}",
                shown_files(&code.unread_templates)
            ));
        }
        gaps.push(sv_report::Gap {
            what: format!("code written in {}", names.join(", ")),
            why,
        });
    }
    if !code.sql_files.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!("the SQL in {}", shown_files(&code.sql_files)),
            why: "no rule reads a file of SQL. Nothing is held back for it: the rules against \
                  queries built by hand look at how the app's code builds a query"
                .to_owned(),
        });
    }
    if !code.unparsed_files.is_empty() {
        let n = code.unparsed_files.len();
        let mut shown: Vec<&str> = code
            .unparsed_files
            .iter()
            .map(String::as_str)
            .take(5)
            .collect();
        if n > 5 {
            shown.push("…");
        }
        gaps.push(sv_report::Gap {
            what: format!(
                "part of {n} file{} that did not parse cleanly ({})",
                if n == 1 { "" } else { "s" },
                shown.join(", ")
            ),
            why: "whatever sat where the parser gave up was not read, so a rule whose call is named \
                  anywhere in these files cannot say it found nothing wrong anywhere in this app; a \
                  rule whose call is named nowhere in them could not have found it there. What was \
                  found stands"
                .to_owned(),
        });
    }
    gaps.extend(untaught_gaps(&code.untaught));
    gaps.extend(static_scan.package_gaps());
    examined.extend(static_scan.examined());
    if !scan_report.unread_extensions.is_empty() {
        let mut exts: Vec<&str> = scan_report
            .unread_extensions
            .iter()
            .map(String::as_str)
            .collect();
        exts.sort_unstable();
        gaps.push(sv_report::Gap {
            what: format!("files ending {}", exts.join(", ")),
            why:
                "the technology scan did not look in these, so no technology can be called absent \
                  on their account"
                    .to_owned(),
        });
    }
    // The Secure by Design checklist is design review, not scanning. Its controls are applicable
    // and every one is unverified — which is true of a great many ASVS requirements too, and the
    // difference matters: those could in principle be reached by some check, and these cannot be
    // reached by any, ever. Counting them together lets a reader think the scanner tried.
    let manual_only = buckets.manual_only(config_rules);
    let design_review = manual_only.len();
    if design_review > 0 {
        gaps.push(sv_report::Gap {
            what: format!(
                "{design_review} requirement{} that are design review, not scanning",
                if design_review == 1 { "" } else { "s" }
            ),
            why: "these ask how the system was designed and how it is run \u{2014} whether trust \
                  zones are enforced, whether an incident response plan is rehearsed, whether data \
                  has named owners. No check here reaches them and none ever will, so they are \
                  counted as applicable and unverified, and a person has to answer them."
                .to_owned(),
        });
    }
    gaps.extend(dependency_gaps(bill_of_materials));
    manual_only
}

/// Which requirements the app's tests name, and which no test of the app's could show.
fn requirements_for_tests(
    scene: &Scene,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let Scene {
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        static_scan,
        ctx,
        resolved,
        buckets,
        seals,
    } = *scene;
    let static_scan::StaticScan {
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
    } = static_scan;
    let Loaded {
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
        ..
    } = loaded;
    let _ = (
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        ctx,
        resolved,
        buckets,
        seals,
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
    );

    // Which requirements the app's tests name, read from the files whether or not the tests ran, so
    // the report can tell a requirement nobody has written a test for from one whose test did not
    // run here.
    let named_in_tests: std::collections::BTreeSet<String> = {
        let known: std::collections::BTreeSet<&str> =
            frameworks.requirements.keys().map(String::as_str).collect();
        sv_check::suite::tests_naming_requirements(app_dir, &known)
            .into_iter()
            .flat_map(|t| t.requirement_ids)
            .collect()
    };

    // What an application's own tests cannot show, so it is not listed as a test to write.
    let not_for_tests: std::collections::BTreeSet<String> = buckets
        .applicable
        .iter()
        .filter(|id| config_rules.not_for_tests(frameworks, id))
        .cloned()
        .collect();

    // The owner's answers, from the notes file beside the app. Absent when they have not run
    // `sv notes`, which is the common case and not a gap: the report then says the file exists to
    (named_in_tests, not_for_tests)
}

/// The owner's answers: the notes file, the decisions file, and the manifest's design questions
/// and checks made by hand, with a person's confirmations of what the AI tool said applied.
fn the_owners_word(
    scene: &Scene,
    findings: &mut Vec<sv_check::Finding>,
    gaps: &mut Vec<sv_report::Gap>,
) -> Result<PersonsWord> {
    let Scene {
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        static_scan,
        ctx,
        resolved,
        buckets,
        seals,
    } = *scene;
    let static_scan::StaticScan {
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
    } = static_scan;
    let Loaded {
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
        ..
    } = loaded;
    let _ = (
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        ctx,
        resolved,
        buckets,
        seals,
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
    );

    // The owner's answers, from the notes file beside the app. Absent when they have not run
    // `sv notes`, which is the common case and not a gap: the report then says the file exists to
    // be written.
    let notes_catalog = sv_check::notes::Catalog::load(&notes_path())?;
    let notes = match std::fs::read_to_string(app_dir.join(&notes_catalog.file)) {
        Ok(text) => sv_check::notes::evidence(
            &notes_catalog,
            &sv_check::notes::read_answers(&notes_catalog, &text),
            &notes_catalog.file,
            seals,
        ),
        Err(_) => {
            let asked = notes_catalog
                .sections
                .iter()
                .filter(|s| buckets.applicable.contains(&s.id))
                .count();
            if asked > 0 {
                gaps.push(sv_report::Gap {
                    what: format!(
                        "{asked} requirement{} that ask for a written decision",
                        if asked == 1 { "" } else { "s" }
                    ),
                    why: format!(
                        "No tool can answer these: they ask what your rules are, who may do what, \
                         and how long things are kept. Run `sv notes` to write {}, answer the \
                         questions in it, and they become documented. Your AI coding tool can \
                         ask you them: `sv questions` prints them for its chat.",
                        notes_catalog.file
                    ),
                });
            }
            sv_check::notes::Evidence::default()
        }
    };
    if !notes.unreadable.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "who wrote {} section{} of {}",
                notes.unreadable.len(),
                if notes.unreadable.len() == 1 { "" } else { "s" },
                notes_catalog.file
            ),
            why: format!(
                "Each section says who wrote it on one line, `{} {}` or `{} {}`, and {} names \
                 somebody else or says both, so nothing was made of it: {}.",
                sv_check::notes::WRITTEN_BY,
                sv_check::notes::BY_OWNER,
                sv_check::notes::WRITTEN_BY,
                sv_check::notes::BY_AI_TOOL,
                if notes.unreadable.len() == 1 {
                    "this one"
                } else {
                    "these"
                },
                notes.unreadable.join(", ")
            ),
        });
    }
    if !notes.not_read.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "what is under {} heading{} of your own in {}",
                notes.not_read.len(),
                if notes.not_read.len() == 1 { "" } else { "s" },
                notes_catalog.file
            ),
            why: format!(
                "A heading that is not one of the file's questions ends the answer above it, so \
                 what is under it was not read as an answer to anything: {}. Keeping notes of your \
                 own there is fine. If one of them is part of an answer, move it up into that \
                 answer, or use a `####` heading inside the answer instead.",
                notes.not_read.join("; ")
            ),
        });
    }
    // The decisions the design-time prompts write down (`sv_check::decisions`). Two sections count
    // toward Secure by Design controls, read as the notes are; the file's other sections are not
    // questions, so a heading `sv` does not read for credit is not reported as one left unread.
    let decisions_catalog = sv_check::notes::Catalog::load(&decisions_path())?;
    let decisions_text = std::fs::read_to_string(app_dir.join(&decisions_catalog.file)).ok();
    let decisions =
        decisions_text
            .as_deref()
            .map_or_else(sv_check::notes::Evidence::default, |text| {
                sv_check::notes::evidence(
                    &decisions_catalog,
                    &sv_check::notes::read_answers(&decisions_catalog, text),
                    &decisions_catalog.file,
                    seals,
                )
            });
    if !decisions.unreadable.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "who wrote {} section{} of {}",
                decisions.unreadable.len(),
                if decisions.unreadable.len() == 1 {
                    ""
                } else {
                    "s"
                },
                decisions_catalog.file
            ),
            why: format!(
                "Each section says who wrote it on one line, `{} {}` or `{} {}`, and {} names \
                 somebody else or says both, so nothing was made of it: {}.",
                sv_check::notes::WRITTEN_BY,
                sv_check::notes::BY_OWNER,
                sv_check::notes::WRITTEN_BY,
                sv_check::notes::BY_AI_TOOL,
                if decisions.unreadable.len() == 1 {
                    "this one"
                } else {
                    "these"
                },
                decisions.unreadable.join(", ")
            ),
        });
    }
    // A review by a person is the one thing that section can ask for, and no tool can do it, so
    // what it says is repeated here, where what was not examined is listed. Its words are not read
    // for a yes or a no, and credit nothing.
    // Who wrote it is said, from the section's own `Written by:` line: a section the AI coding tool
    // wrote, saying no person need look, read as the owner's own judgment (gap analysis 4.2).
    if let Some(said) = decisions_text
        .as_deref()
        .and_then(|text| sv_check::decisions::section(text, sv_check::decisions::BRING_IN_A_PERSON))
    {
        let writer = decisions_text.as_deref().and_then(|text| {
            sv_check::decisions::section_writer(text, sv_check::decisions::BRING_IN_A_PERSON)
        });
        let whose = match writer.as_deref() {
            Some(w) if w.eq_ignore_ascii_case(sv_check::notes::BY_OWNER) => {
                "in a section marked as written by you".to_owned()
            }
            Some(w) if w.eq_ignore_ascii_case(sv_check::notes::BY_AI_TOOL) => {
                "in a section your AI coding tool wrote".to_owned()
            }
            _ => "in a section that does not say who wrote it, so it counts as your AI coding \
                  tool's"
                .to_owned(),
        };
        gaps.push(sv_report::Gap {
            what: "a person's security review of the design".to_owned(),
            why: format!(
                "No tool can make it. Your {} says, under \"{}\", {whose}: \"{said}\"",
                sv_check::decisions::FILE,
                sv_check::decisions::BRING_IN_A_PERSON
            ),
        });
    }
    let documented: Vec<sv_check::Verified> = notes
        .documented
        .into_iter()
        .chain(decisions.documented)
        .collect();

    // The design questions, answered in stackvet.toml. `yes` is the owner's word and the weakest
    // tier here; `no`, and a `where` naming a file the app does not have, are findings.
    let design_questions = sv_check::design::Questions::load(&design_questions_path())?;
    let human_checks =
        sv_check::human::HumanChecks::load(&sv_frameworks::data::file("human-checks.json"))?;
    let design_answers: std::collections::BTreeMap<String, sv_check::design::Answer> = manifest
        .design
        .iter()
        .map(|(id, a)| {
            (
                id.clone(),
                sv_check::design::Answer {
                    answer: a.answer.clone(),
                    location: a.r#where.clone(),
                    by: a.by.clone(),
                    recorded: sv_check::seal::owner_recorded(
                        seals,
                        a.seal.as_deref(),
                        &sv_check::seal::design_answer_fields(id, a),
                    ),
                },
            )
        })
        .collect();
    let mut design = sv_check::design::evaluate(
        &design_questions,
        &design_answers,
        &|id| buckets.applicable.iter().any(|a| a == id),
        &|path| app_dir.join(path).exists(),
        // No source file and no dependency manifest is an app not written yet, which is when a
        // decision is a plan. A source file in a language `sv` cannot read is code too (the review
        // of 6 October, item 9).
        scan_report.files_read > 0
            || !scan_report.declared.is_empty()
            || !scan_report.unread_extensions.is_empty(),
    );
    findings.extend(
        design
            .findings
            .iter()
            .cloned()
            .map(|f| at_the_manifest(f, manifest_file)),
    );
    gaps.extend(planned_gaps(&design.planned));
    if !design.unreadable.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "your answer to {} design question{}",
                design.unreadable.len(),
                if design.unreadable.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: format!(
                "stackvet.toml answers {} with a word that is not yes, no, not-sure, or planned, or \
                 says it was answered `by` somebody other than \"owner\" or \"ai-tool\", so \
                 nothing could be made of it: {}.",
                if design.unreadable.len() == 1 {
                    "this"
                } else {
                    "these"
                },
                design.unreadable.join(", ")
            ),
        });
    }
    if !design.unanswered.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} question{} about how this app is built",
                design.unanswered.len(),
                if design.unanswered.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: format!(
                "No tool can settle these — whether input is validated on the server, whether the \
                 app's own services authenticate to each other. Answer them in the [design] \
                 section of stackvet.toml: {}. Your AI coding tool can ask you them: `sv \
                 questions` prints them for its chat.",
                design.unanswered.join(", ")
            ),
        });
    }

    // The checks made by hand, recorded in stackvet.toml. The owner's `done` is their word about
    // what they saw; `problem` is a finding; an old one is out of date and counts for nothing.
    let hand_answers: std::collections::BTreeMap<String, sv_check::hand::Answer> = manifest
        .checked_by_hand
        .iter()
        .map(|(id, a)| {
            (
                id.clone(),
                sv_check::hand::Answer {
                    result: a.result.clone(),
                    on: a.on.clone(),
                    by: a.by.clone(),
                    how: a.how.clone(),
                    recorded: sv_check::seal::owner_recorded(
                        seals,
                        a.seal.as_deref(),
                        &sv_check::seal::hand_check_fields(id, a),
                    ),
                },
            )
        })
        .collect();
    let mut hand = match sv_check::advisories::Day::today() {
        Some(today) => sv_check::hand::evaluate(
            &human_checks,
            &hand_answers,
            &|id| buckets.applicable.iter().any(|a| a == id),
            today,
        ),
        // A clock before 1970 cannot say whether a check is current, so none is counted.
        None => sv_check::hand::Outcome::default(),
    };
    findings.extend(
        hand.findings
            .iter()
            .cloned()
            .map(|f| at_the_manifest(f, manifest_file)),
    );
    if !hand.unreadable.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} check{} made by hand",
                hand.unreadable.len(),
                if hand.unreadable.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "stackvet.toml records {} in [checked-by-hand] in a way nothing could be made \
                 of, so it counts for nothing: {}.",
                if hand.unreadable.len() == 1 {
                    "this"
                } else {
                    "these"
                },
                hand.unreadable
                    .iter()
                    .map(|(id, why)| format!("{id} ({why})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        });
    }
    if !hand.out_of_date.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} check{} made by hand more than {} days ago",
                hand.out_of_date.len(),
                if hand.out_of_date.len() == 1 { "" } else { "s" },
                sv_check::hand::CURRENT_FOR_DAYS
            ),
            why: format!(
                "Certificates expire and apps change, so an old check counts for nothing. Make \
                 {} again and record the new date: {}.",
                if hand.out_of_date.len() == 1 {
                    "it"
                } else {
                    "them"
                },
                hand.out_of_date
                    .iter()
                    .map(|(id, on)| format!("{id}, checked on {on}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        });
    }
    // A person confirming what the AI tool said moves it up to their tier, shown as confirmed. What
    // does not hold stays the tool's word and is named with its reason. See `sv_check::confirm`.
    let confirmation = |c: &sv_manifest::Confirmed| sv_check::confirm::Confirmation {
        by: c.by.clone(),
        on: c.on.clone(),
        how: c.how.clone(),
        answer: c.answer.clone(),
        location: c.r#where.clone(),
        result: c.result.clone(),
        seal: c.seal.clone(),
    };
    let design_confirmations: std::collections::BTreeMap<
        String,
        (sv_check::confirm::Confirmation, String, Option<String>),
    > = manifest
        .design
        .iter()
        .filter_map(|(id, a)| {
            let c = a.confirmed.as_ref()?;
            Some((
                id.clone(),
                (confirmation(c), a.answer.clone(), a.r#where.clone()),
            ))
        })
        .collect();
    let hand_confirmations: std::collections::BTreeMap<
        String,
        (sv_check::confirm::Confirmation, String),
    > = manifest
        .checked_by_hand
        .iter()
        .filter_map(|(id, a)| {
            let c = a.confirmed.as_ref()?;
            Some((id.clone(), (confirmation(c), a.result.clone())))
        })
        .collect();
    let modified = |path: &str| {
        std::fs::metadata(app_dir.join(path))
            .and_then(|m| m.modified())
            .ok()
            .and_then(sv_check::advisories::Day::of)
    };
    let (confirmed_design, confirmed_hand) = match sv_check::advisories::Day::today() {
        Some(today) => (
            sv_check::confirm::apply(
                &mut design.stated,
                sv_check::confirm::DESIGN_CONFIRMED,
                &|id| {
                    let (c, answer, location) = design_confirmations.get(id)?;
                    Some((
                        c,
                        sv_check::confirm::Current::Design {
                            answer,
                            location: location.as_deref(),
                            modified: location.as_deref().and_then(modified),
                        },
                    ))
                },
                today,
                seals,
            ),
            sv_check::confirm::apply(
                &mut hand.stated,
                sv_check::confirm::HAND_CONFIRMED,
                &|id| {
                    let (c, result) = hand_confirmations.get(id)?;
                    Some((c, sv_check::confirm::Current::Hand { result }))
                },
                today,
                seals,
            ),
        ),
        None => Default::default(),
    };
    if let Some(why) = manifest.level_from_unanswered_data() {
        gaps.push(sv_report::Gap {
            what: "What information the app holds about people".to_owned(),
            why: why.to_owned(),
        });
    }
    if let Some(why) = manifest.level_from_unknown_data() {
        gaps.push(sv_report::Gap {
            what: "A kind of information the app holds that `sv` does not know".to_owned(),
            why,
        });
    }
    let not_counted: Vec<&(String, String)> = confirmed_design
        .not_counted
        .iter()
        .chain(confirmed_hand.not_counted.iter())
        .collect();
    if !not_counted.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} confirmation{} of what your AI coding tool said",
                not_counted.len(),
                if not_counted.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "stackvet.toml records {} in a way that does not count, so the tool's word is \
                 all there is and the question is asked again: {}.",
                if not_counted.len() == 1 {
                    "this confirmation"
                } else {
                    "these confirmations"
                },
                not_counted
                    .iter()
                    .map(|(id, why)| format!("{id} ({why})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        });
    }
    let attested: Vec<sv_check::Verified> = design
        .attested
        .iter()
        .chain(confirmed_design.confirmed.iter())
        .cloned()
        .collect();
    let by_hand: Vec<sv_check::Verified> = hand
        .by_owner
        .iter()
        .chain(confirmed_hand.confirmed.iter())
        .cloned()
        .collect();
    let stated: Vec<sv_check::Verified> = design
        .stated
        .iter()
        .chain(hand.stated.iter())
        .chain(notes.stated.iter())
        .chain(decisions.stated.iter())
        .cloned()
        .collect();
    // A person's word goes to the report in the one list with the checks, each credit saying
    // which tier it rests on (`sv_check::Tier`, set where it was made); the report reads the tier,
    // not the list (8 October 2026).
    let mut verified = documented;
    verified.extend(attested);
    verified.extend(by_hand);
    verified.extend(stated);
    Ok(PersonsWord {
        verified,
        notes_catalog,
        design_questions,
        human_checks,
        decisions_text,
    })
}

/// The Appendix C requirements the coding rules given to this app come from, for the report's
/// section on how the app is built with AI. The same rules `sv rules` would write.
fn coding_rules_cited(
    buckets: &sv_frameworks::applicability::Buckets,
) -> Result<std::collections::BTreeSet<String>> {
    // The Appendix C requirements the coding rules given to this app come from, for the report's
    // section on how the app is built with AI. The same rules `sv rules` would write.
    let coding_rules = sv_check::coding_rules::CodingRules::load(&coding_rules_path())?;
    let set_aside: std::collections::BTreeSet<&str> = buckets
        .not_applicable
        .iter()
        .map(|n| n.id.as_str())
        .collect();
    let is_set_aside = |id: &str| set_aside.contains(id);
    let coding_rules_cited: std::collections::BTreeSet<String> = coding_rules
        .for_app(Some(&is_set_aside))
        .into_iter()
        .flat_map(|r| r.cites.keys().cloned())
        .collect();
    Ok(coding_rules_cited)
}

/// Everything the stages gathered, for the last one.
pub struct Gathered {
    pub findings: Vec<sv_check::Finding>,
    pub verified: Vec<sv_check::Verified>,
    pub gaps: Vec<sv_report::Gap>,
    pub examined: Vec<sv_report::Examined>,
    pub manual_only: std::collections::BTreeSet<String>,
    pub named_in_tests: std::collections::BTreeSet<String>,
    pub not_for_tests: std::collections::BTreeSet<String>,
    pub coding_rules_cited: std::collections::BTreeSet<String>,
    pub run: RunningApp,
    pub word: PersonsWord,
    pub run_record: sv_report::RunRecord,
}

/// The last stage: what was examined completed, what a person set aside applied, the safe defaults
/// held to the running app, and the report built.
fn put_together(scene: &Scene, gathered: Gathered) -> Result<sv_report::Report> {
    let Scene {
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        static_scan,
        ctx,
        resolved,
        buckets,
        seals,
    } = *scene;
    let static_scan::StaticScan {
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
    } = static_scan;
    let Loaded {
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
        ..
    } = loaded;
    let _ = (
        app_dir,
        options,
        loaded,
        manifest,
        manifest_file,
        ctx,
        resolved,
        buckets,
        seals,
        listing,
        scan_report,
        bill_of_materials,
        secrets,
        config,
        code,
        frameworks,
        config_rules,
        threat_rules,
        secret_rules,
        adapters,
    );

    let Gathered {
        findings,
        verified,
        mut gaps,
        mut examined,
        manual_only,
        named_in_tests,
        not_for_tests,
        coding_rules_cited,
        run,
        word,
        run_record,
    } = gathered;
    let RunningApp {
        status: run_status,
        note: run_note,
        steps: run_steps,
        test_output,
        tests_examined,
        ..
    } = run;
    let PersonsWord {
        notes_catalog,
        design_questions,
        human_checks,
        decisions_text,
        ..
    } = word;
    examined.push(match &run_status {
        // Started is still only part of what the app could be asked: what sits behind a sign-in
        // it could not reach, and the requirements no question reaches, are in the gaps.
        sv_report::RunStatus::Started { .. } => sv_report::Examined::partly(
            "probe.",
            "the running app was asked what `sv` knows to ask; the gaps say what that could not reach",
        ),
        sv_report::RunStatus::NotAsked { why } | sv_report::RunStatus::CouldNotStart { why } => {
            sv_report::Examined::not_run("probe.", why.clone())
        }
    });
    examined.push(tests_examined);
    // The owner's answers in stackvet.toml are read on every run.
    examined.push(sv_report::Examined::ran("design."));
    examined.push(sv_report::Examined::ran("hand."));
    // The "Safe defaults" section's three switches (`sv_check::decisions`), each held to the check
    // of the running app that sees it. Made before what a person set aside is applied, so a review
    // of one of these findings is applied too (the review of 6 October, item 7); one whose running-app
    // finding a person set aside is dropped after.
    let safe_defaults = decisions_text
        .as_deref()
        .map(sv_check::decisions::safe_defaults)
        .unwrap_or_default();
    let app_ran = matches!(run_status, sv_report::RunStatus::Started { .. });
    // The decisions file is read whenever it is there; its safe defaults only with the app running.
    examined.push(match (&decisions_text, app_ran) {
        (None, _) => sv_report::Examined::not_run(
            "decisions.",
            format!("there is no {} beside the app", sv_check::decisions::FILE),
        ),
        (Some(_), true) => sv_report::Examined::ran("decisions."),
        (Some(_), false) => sv_report::Examined::partly(
            "decisions.",
            "its safe defaults are held to checks of the running app, which was not run",
        ),
    });
    // What a person set aside, matched by the fingerprint the report prints beside each finding.
    // An entry that matches nothing says whether its rule looked this time (deep review R3), so
    // `examined` is complete before this.
    // Merged, marked, the decisions and then the reviews applied, one per line: as `sv check`
    // counts them too (`static_scan::settle`).
    let reviewed = static_scan::settle(
        app_dir,
        &manifest.finding_review,
        findings,
        static_scan,
        &examined,
        loaded,
        seals,
        &safe_defaults.decided,
    );
    let findings = reviewed.findings;
    if !safe_defaults.unreadable.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} safe default{} in {}",
                safe_defaults.unreadable.len(),
                if safe_defaults.unreadable.len() == 1 {
                    ""
                } else {
                    "s"
                },
                sv_check::decisions::FILE
            ),
            why: format!(
                "Under \"{}\", each of these switches is decided as one of two values, and these \
                 lines say something else, so nothing was made of them: {}. Write `{}`.",
                sv_check::decisions::SAFE_DEFAULTS,
                safe_defaults.unreadable.join("; "),
                sv_check::decisions::SWITCHES
                    .iter()
                    .map(|s| format!("- {}: {}", s.name, s.safe))
                    .collect::<Vec<_>>()
                    .join("`, `")
            ),
        });
    }
    if !safe_defaults.missing.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} safe default{} not found in {}",
                safe_defaults.missing.len(),
                if safe_defaults.missing.len() == 1 {
                    ""
                } else {
                    "s"
                },
                sv_check::decisions::FILE
            ),
            why: format!(
                "The \"{}\" section has no line deciding {}, so nothing was held to the running \
                 app for it. Write `{}`.",
                sv_check::decisions::SAFE_DEFAULTS,
                safe_defaults.missing.join(", "),
                sv_check::decisions::SWITCHES
                    .iter()
                    .filter(|s| safe_defaults.missing.contains(&s.name))
                    .map(|s| format!("- {}: {}", s.name, s.safe))
                    .collect::<Vec<_>>()
                    .join("`, `")
            ),
        });
    }
    let held_safe = safe_defaults.decided.iter().filter(|d| d.safe).count();
    if held_safe > 0 && !app_ran {
        gaps.push(sv_report::Gap {
            what: format!(
                "{held_safe} safe default{} decided in {}",
                if held_safe == 1 { "" } else { "s" },
                sv_check::decisions::FILE
            ),
            why: "Each is held to a check of the running app, and the app was not run, so whether \
                  the app does what was decided was not looked at. `sv report --run` runs it."
                .to_owned(),
        });
    }
    // Why the app is held to its level, on whose word, and what level 2 would add (the gap
    // analysis of 7 October 2026, finding 17; ADR-024, Later, 9 October 2026).
    let level_why = sv_report::LevelWhy {
        because: manifest.level_because(),
        level_two_more: buckets
            .out_of_level
            .iter()
            .filter(|id| frameworks.get(id.as_str()).is_some_and(|r| r.level == 2))
            .count(),
        // A hints file that cannot be read is a gap in the report, not a line on stderr that the MCP
        // server's caller never sees (backlog 226, part 1, item 6).
        hints: level_hints(manifest, listing, &scan_report.set_apart).unwrap_or_else(|gap| {
            gaps.push(gap);
            Vec::new()
        }),
        confirmed: scope_confirmed(manifest, seals),
    };
    let mut report = sv_report::build(sv_report::Inputs {
        on_the_internet: manifest.app.deployment == sv_manifest::Deployment::Internet,
        ai_tool: sv_check::ai_tool::read(listing),
        app_name: if manifest.app.name.is_empty() {
            "This app"
        } else {
            &manifest.app.name
        },
        target_level: manifest.target_level(),
        // The run's own start time and id, on every page (backlog 226, part 2, item 12): the
        // clock was read once, when the run began, so the pages agree with `run_record`.
        generated: Some(run_record.describe()),
        made_by: sv_report::MadeBy {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit: env!("SV_GIT_COMMIT").to_owned(),
        },
        run_note,
        run_steps,
        test_output,
        run_status: Some(run_status),
        coding_rules_cited,
        frameworks,
        buckets,
        claims: resolved,
        findings,
        set_aside: reviewed.set_aside,
        reviews_not_counted: reviewed.not_counted,
        verified: &verified,
        gaps,
        manual_only,
        named_in_tests,
        not_for_tests,
        human: Some((&notes_catalog, &design_questions, &human_checks)),
        threats: Some((threat_rules, ctx)),
    });
    report.examined = examined;
    report.level_why = Some(level_why);
    // What kind of run this was, by what did not run (gap analysis 6.1).
    let reach_path = sv_frameworks::data::file("reach.json");
    let reach = std::fs::read_to_string(&reach_path)
        .map_err(anyhow::Error::from)
        .and_then(|text| sv_report::read_reach(&text))
        .with_context(|| format!("reading {}", reach_path.display()))?;
    report.not_run_this_time = sv_report::not_run_this_time(&report, &reach, options.run_tools);
    let file_gaps = static_scan.file_gaps();
    report.could_not_run = file_gaps.could_not_run;
    report.partly_read = file_gaps.partly;
    report.run_record = Some(run_record);
    report.manifest_file = manifest_file.to_owned();
    // A contradiction says what in the code contradicted the manifest, so whoever wrote the
    // manifest can see what to correct. "The code says otherwise" alone left the AI coding tool that
    // wrote it with nothing to go on; `sv scope` always said, and now the report does too.
    for claim in report
        .claims
        .iter_mut()
        .filter(|c| c.state == "contradicted")
    {
        if let Some(answer) = scan_report
            .answers
            .iter()
            .find(|a| a.condition.name() == claim.name && a.value == Some(true))
        {
            claim.note = format!(
                "{} What the code shows: {}.",
                claim.note,
                describe(&answer.evidence)
            );
        }
    }
    Ok(report)
}

/// A finding the manifest's answers made, pointed at the manifest by the name it has in this app.
fn at_the_manifest(mut finding: sv_check::Finding, manifest_file: &str) -> sv_check::Finding {
    if finding.location.file == sv_frameworks::names::MANIFEST {
        finding.location.file = manifest_file.to_owned();
    }
    finding
}

/// At level 1, what the app's own code shows that the answers setting the level do not (the gap
/// analysis of 7 October 2026, finding 17; ADR-024, Later, 9 October 2026). Nothing at level 2,
/// where there is nothing more to ask; and nothing, said on standard error, when the list of
/// names cannot be read, since a question missing is not a pass.
/// The hints file read, or the gap that says the code was not compared with the answers that set
/// the level, and why.
fn level_hints_from(path: &Path) -> Result<sv_check::level_hints::Hints, sv_report::Gap> {
    sv_check::level_hints::Hints::load(path).map_err(|why| sv_report::Gap {
        what: "whether the code agrees with the answers that set the level".to_owned(),
        why: format!(
            "sv's file of what to look for ({}) could not be read: {why}. So nothing here says \
             whether the code shows a level 1 app needs more, which is not the same as saying it \
             does not. Reinstall sv, or point SV_DATA_DIR at a complete copy of its data.",
            path.display()
        ),
    })
}

fn level_hints(
    manifest: &sv_manifest::Manifest,
    listing: &sv_scan::files::Listing,
    set_apart: &std::collections::BTreeSet<String>,
) -> Result<Vec<sv_check::level_hints::Hint>, sv_report::Gap> {
    if manifest.target_level() != 1 {
        return Ok(Vec::new());
    }
    let hints = level_hints_from(&sv_frameworks::data::file("level-hints.json"))?;
    let private_audience = matches!(
        manifest.app.audience,
        sv_manifest::Audience::JustMe | sv_manifest::Audience::MyTeam
    );
    Ok(sv_check::level_hints::find(
        listing,
        &hints,
        &sv_check::level_hints::Answers {
            private_audience,
            listed: manifest.data.listed(),
        },
        set_apart,
    ))
}

/// Whether the answers that set the level were confirmed through `sv review`, and whether that
/// still holds here (ADR-024, Later, 9 October 2026): the seal must hold on this computer, and
/// the answers must be the ones confirmed. `None` when nobody has confirmed them.
fn scope_confirmed(
    manifest: &sv_manifest::Manifest,
    seals: &sv_check::seal::Checker,
) -> Option<sv_report::ScopeConfirmed> {
    let entry = manifest.scope_review.as_ref()?;
    let fields = sv_check::seal::scope_review_fields(entry);
    Some(
        match seals.recorded(entry.seal.as_deref(), &sv_check::seal::as_strs(&fields)) {
            Err(why) => sv_report::ScopeConfirmed::NotCounted { why: why.why() },
            Ok(_) if !entry.still_holds_for(manifest) => sv_report::ScopeConfirmed::Changed {
                by: entry.by.clone(),
                on: entry.on.clone(),
            },
            Ok(sealed) => sv_report::ScopeConfirmed::Confirmed {
                by: entry.by.clone(),
                on: entry.on.clone(),
                sealed: match sealed {
                    sv_check::seal::Sealed::Here => " on this computer".to_owned(),
                    sv_check::seal::Sealed::Signed { key, from, lock } => {
                        format!(", {}", sv_check::seal::signed_with(&key, from, lock))
                    }
                },
            },
        },
    )
}
