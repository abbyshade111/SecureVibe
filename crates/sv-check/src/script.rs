//! The run's script: which suites are asked of the running app, in which order, and as whom, once
//! the app is up behind the fence.
//!
//! Until 8 October 2026 this lived in `crates/sv-run/src/docker.rs`, in the middle of the 568-line
//! function that also made the network, started the helpers and the app, and tore it all down, so
//! `sv-run` depended on `sv-check` (the reverse of the stated layering) and the order of the suites
//! could be tried only with Docker. Now the script is here, written against [`Services`]: what the
//! harness alone can do (a way to the app with the helpers it has, the helpers' readiness, the app's
//! log, a second copy of the app with the kill switch on, a seed, a look at whether the app is still
//! up), and nothing about containers. Its tests run it against a fake harness and show the order.
//! The Docker-only residue, the fence, the limits, the install step, the teardown, and the app's own
//! tests inside its container, stays in `sv-run` (the architecture assessment of 8 October 2026,
//! item 4, second half).

use crate::probes::{ProbeRequest, ProbeResponse};
use crate::running::Liveness;
use crate::signed_in::{Accounts, Http, Patient};
use std::cell::Cell;
use sv_manifest::{
    AiSection, FetchSection, McpServerSection, OidcSection, PolicySection, UsersSection,
};

/// What the manifest says the run can ask, and how, as the harness read it.
pub struct Plan<'a> {
    pub users: Option<&'a UsersSection>,
    pub policy: &'a PolicySection,
    pub oidc: Option<&'a OidcSection>,
    pub ai: Option<&'a AiSection>,
    pub mcp_server: Option<&'a McpServerSection>,
    pub fetch: Option<&'a FetchSection>,
    pub health_path: &'a str,
    /// Wait out the session timeouts the owner states (`sv run --slow`).
    pub slow: bool,
    /// The accounts this run made for its users, when it has users.
    pub accounts: Option<&'a Accounts>,
    /// The token the app's MCP server was told to accept, when it takes one.
    pub mcp_token: Option<&'a str>,
}

/// Which copy of the app a way to it reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The app as started.
    App,
    /// The second copy, with the kill switch on (C9.6.1), while it runs.
    SwitchedOff,
}

/// Whether a way to the app is given the test model, and which way: as the suites did before the
/// script moved here, some take the model only when it answers, and the kill-switch check takes it
/// as started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Model {
    #[default]
    None,
    /// The model, when the run has one and it answers its health check.
    IfAnswering,
    /// The model, when the run has one, answering or not.
    AsStarted,
}

/// Which helpers a way to the app is given. Each only when the run has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct With {
    pub mail: bool,
    /// The test identity provider, when it answers its health check.
    pub provider: bool,
    pub browser: bool,
    pub model: Model,
}

/// What only the harness can do for the script. `sv-run` implements it over Docker; the tests here
/// implement it over nothing, and record the order.
pub trait Services {
    /// A way to send requests to `target`, given these helpers, for as long as a suite runs.
    fn http<'s>(&'s self, target: Target, with: With) -> Box<dyn Http + 's>;
    /// The test model's address on the fenced network, when the run has one and it answers.
    fn model_canary(&self) -> Option<String>;
    /// The app's log so far, read after the questions whose events it should hold.
    fn app_log(&self) -> String;
    /// Runs the manifest's seed command in `target`, with the accounts in its environment.
    fn seed(&self, target: Target, seed: &str, accounts: &Accounts) -> Result<(), String>;
    /// Starts the second copy of the app with `setting` on, and waits until it answers.
    fn start_switched_off(&self, setting: &str) -> bool;
    /// Removes the second copy.
    fn remove_switched_off(&self);
    /// Whether the app is still up and answering, `after` what was just asked (V16.5.4).
    fn liveness(&self, after: &str) -> Liveness;
    /// Told as each suite begins, in a few words, so a person watching a long run sees it move
    /// (backlog 226, part 2, item 15). Nothing by default.
    fn starting(&self, _suite: &str) {}
}

/// What the script came to, in the order it was asked.
#[derive(Debug, Default)]
pub struct Outcome {
    pub probe_responses: Vec<ProbeResponse>,
    pub probes_rate_limited: Vec<String>,
    pub signed_in: Option<crate::signed_in::Outcome>,
    pub oidc: Option<crate::signed_in::Outcome>,
    pub mcp_server: Option<crate::signed_in::Outcome>,
    pub fetch: Option<crate::signed_in::Outcome>,
    pub ai: Option<crate::signed_in::Outcome>,
    pub liveness: Vec<Liveness>,
    /// How long each suite took, in milliseconds, in the order asked: from its start to the next
    /// one's, the last to the end of the script (backlog 226, part 2, item 13).
    pub timings: Vec<(&'static str, u64)>,
}

/// What the suites that ask as a signed-in user are given: the second test user, so nothing after
/// them depends on the first's session.
fn as_second_user<'a>(
    plan: &Plan<'a>,
) -> Option<(&'a UsersSection, &'a crate::signed_in::Account)> {
    plan.users
        .zip(plan.accounts)
        .map(|(users, accounts)| (users, &accounts.b))
}

/// The script, once the app is up: the anonymous questions; whether the app is still up; the
/// signed-in suites; sign-in through the test provider; the app as an MCP server; the feature that
/// fetches an address; the AI feature, with the kill switch tried on a second copy; and whether the
/// app is still up after all of that, when any of it was asked. Each suite runs only when the
/// manifest says how, and says so itself when it cannot.
pub fn run(services: &dyn Services, plan: &Plan, probes: &[ProbeRequest]) -> Outcome {
    let mut out = Outcome::default();
    // One budget of waiting for a rate limiter for the whole run (`MOST_WAITING`), shared by every
    // suite, so the run cannot wait five minutes in each of them (ADR-021, Later, 8 October 2026).
    let spent = Cell::new(0);
    // Each suite as it begins: said to the harness, and its start kept for its time.
    let begun: std::cell::RefCell<Vec<(&'static str, std::time::Instant)>> = Default::default();
    let begin = |suite: &'static str| {
        services.starting(suite);
        begun.borrow_mut().push((suite, std::time::Instant::now()));
    };

    // 4. The probes, while the app is up and the fence is in place. A request that gets no
    //    answer is left out rather than recorded as an empty response: "the app said nothing"
    //    and "the app has no Content-Security-Policy" are not the same sentence. So is one the
    //    app's rate limiter was still answering after waiting as it asked: its page is not the
    //    app's (`ask_anonymously`).
    {
        begin("the questions asked as somebody not signed in");
        let mut http = services.http(Target::App, With::default());
        let (responses, limited) =
            crate::signed_in::ask_anonymously_within(http.as_mut(), probes, &spent);
        out.probe_responses = responses;
        out.probes_rate_limited = limited;
    }
    out.liveness
        .push(services.liveness("the questions asked as somebody not signed in"));

    // 4b. As signed-in users, when stackvet.toml says how. After the anonymous probes, so
    //     those see the app as a stranger first; before the tests, which may change its data.
    out.signed_in = plan.users.zip(plan.accounts).map(|(users, accounts)| {
        begin("the questions asked as the test users");
        signed_in(services, plan, users, accounts, &spent)
    });

    // 4c. Signing in through the test provider, when the app signs in through another service.
    //     A provider that never came up leaves the way to it empty, and the check says so.
    // 4c, 4c', 4c'': each with a rate limiter's answer waited out, as the signed-in suites have
    //     it (`Patient`); until 8 October 2026 these three took the app's answers as they came.
    out.oidc = plan.oidc.map(|section| {
        begin("signing in through the test provider");
        let mut http = services.http(
            Target::App,
            With {
                provider: true,
                ..With::default()
            },
        );
        let mut patient = Patient::within(http.as_mut(), &spent);
        let mut out = crate::oidc::run(&mut patient, section);
        patient.settle(&mut out);
        out
    });

    // 4c'. The app as an MCP server, when stackvet.toml says where it answers.
    out.mcp_server = plan.mcp_server.map(|section| {
        begin("the app as an MCP server");
        let mut http = services.http(Target::App, With::default());
        let mut patient = Patient::within(http.as_mut(), &spent);
        let mut out = crate::mcp_server::run(&mut patient, section, plan.mcp_token);
        patient.settle(&mut out);
        out
    });

    // 4c''. A feature that fetches an address a person gives it, pointed at the test model's
    //      server, which records each fetch.
    out.fetch = plan.fetch.map(|section| {
        begin("the feature that fetches an address");
        let canary = services.model_canary();
        let mut http = services.http(
            Target::App,
            With {
                model: Model::IfAnswering,
                ..With::default()
            },
        );
        let context = crate::fetch::Context {
            signed_in: as_second_user(plan),
            canary: canary.as_deref(),
        };
        let mut patient = Patient::within(http.as_mut(), &spent);
        let mut out = crate::fetch::run(&mut patient, section, &context);
        patient.settle(&mut out);
        out
    });

    // 4d. The AI feature, through the test model, when stackvet.toml says how to reach it.
    //     Last of the questions, as the second test user when it needs one: nothing after it
    //     depends on that user's session. Not through `Patient`: the suite waits a limiter out
    //     itself where an answer matters, and its rate check (C11.2.2) sets out to make the app
    //     refuse, which a wait and a second try would unmake.
    out.ai = plan.ai.map(|section| {
        begin("the AI feature");
        ai(services, plan, section)
    });

    // Still up after everything else it was asked, while the sidecar can still ask it.
    if out.signed_in.is_some()
        || out.oidc.is_some()
        || out.ai.is_some()
        || out.mcp_server.is_some()
        || out.fetch.is_some()
    {
        out.liveness
            .push(services.liveness("the signed-in, sign-in, and AI questions as well"));
    }
    let ended = std::time::Instant::now();
    let begun = begun.into_inner();
    out.timings = begun
        .iter()
        .enumerate()
        .map(|(i, (suite, at))| {
            let until = begun.get(i + 1).map_or(ended, |(_, next)| *next);
            let took = until.saturating_duration_since(*at).as_millis();
            (*suite, u64::try_from(took).unwrap_or(u64::MAX))
        })
        .collect();
    out
}

/// The signed-in suites: the seed, when there is one, then everything the probes can ask, then
/// what the app wrote down about it.
fn signed_in(
    services: &dyn Services,
    plan: &Plan,
    users: &UsersSection,
    accounts: &Accounts,
    spent: &Cell<u64>,
) -> crate::signed_in::Outcome {
    let mut http = services.http(
        Target::App,
        With {
            mail: true,
            browser: true,
            model: Model::IfAnswering,
            ..With::default()
        },
    );
    if !users.problems().is_empty() {
        // Nothing is run or asked; the suite says what is missing.
        return crate::signed_in::run(http.as_mut(), users, accounts, true, plan.policy);
    }
    let seeded = match &users.seed {
        Some(seed) => match services.seed(Target::App, seed, accounts) {
            Ok(()) => true,
            Err(why) => {
                return crate::signed_in::Outcome {
                    not_assessed: vec![(
                        "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4".to_owned(),
                        why,
                    )],
                    ..Default::default()
                };
            }
        },
        None => false,
    };
    let mut out = crate::signed_in::run_within(
        http.as_mut(),
        users,
        accounts,
        seeded,
        plan.policy,
        plan.slow,
        spent,
    );
    drop(http);

    // Last of all, and only after everything the probes do: whether the app wrote any of it
    // down. Reading the log earlier would be reading it before the events happened.
    let log = services.app_log();
    let logged = crate::logs::evaluate(&out.log_markers, &log);
    out.findings.extend(logged.findings);
    out.verified.extend(logged.verified);
    out.not_assessed.extend(logged.not_assessed);
    out.steps.extend(logged.steps);
    out
}

/// The AI feature's suite, then what the app logged about it, then the kill switch on a second
/// copy of the app (C9.6.1), so the first and the declared tests are left as they were.
fn ai(services: &dyn Services, plan: &Plan, section: &AiSection) -> crate::signed_in::Outcome {
    let context = crate::ai::Context {
        signed_in: as_second_user(plan),
        policy: plan.policy,
        health: plan.health_path,
        seeded: plan.users.is_some_and(|u| u.seed.is_some()),
        owner: plan.accounts.map(|accounts| &accounts.a),
    };
    let (mut outcome, markers) = {
        let mut http = services.http(
            Target::App,
            With {
                model: Model::IfAnswering,
                ..With::default()
            },
        );
        crate::ai::run(http.as_mut(), section, &context)
    };
    // Then what the app wrote down about it, read after the questions, as the signed-in suite
    // reads its own markers.
    let log = services.app_log();
    crate::ai::logged(&markers, &log, &mut outcome);

    let started = match &section.kill_switch {
        Some(switch) if markers.model_reached => {
            services.start_switched_off(switch)
                && match (section.signed_in, plan.users, plan.accounts) {
                    (true, Some(users), Some(accounts)) => users.seed.as_ref().is_none_or(|seed| {
                        services.seed(Target::SwitchedOff, seed, accounts).is_ok()
                    }),
                    _ => true,
                }
        }
        _ => false,
    };
    {
        let mut http = services.http(
            Target::SwitchedOff,
            With {
                model: Model::AsStarted,
                ..With::default()
            },
        );
        crate::ai::kill_switch(
            http.as_mut(),
            section,
            &context,
            &markers,
            started,
            &mut outcome,
        );
    }
    services.remove_switched_off();
    outcome
}

#[cfg(test)]
mod progress_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A harness over nothing: every request goes unanswered, and every call is written down.
    struct Nothing {
        calls: RefCell<Vec<String>>,
    }

    struct Quiet;
    impl Http for Quiet {
        fn send(&mut self, _request: &ProbeRequest) -> Option<ProbeResponse> {
            None
        }
    }

    impl Services for Nothing {
        fn http<'s>(&'s self, target: Target, with: With) -> Box<dyn Http + 's> {
            self.calls
                .borrow_mut()
                .push(format!("http {target:?} {with:?}"));
            Box::new(Quiet)
        }
        fn model_canary(&self) -> Option<String> {
            self.calls.borrow_mut().push("model_canary".to_owned());
            None
        }
        fn app_log(&self) -> String {
            self.calls.borrow_mut().push("app_log".to_owned());
            String::new()
        }
        fn seed(&self, target: Target, _seed: &str, _accounts: &Accounts) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("seed {target:?}"));
            Ok(())
        }
        fn start_switched_off(&self, _setting: &str) -> bool {
            self.calls
                .borrow_mut()
                .push("start_switched_off".to_owned());
            false
        }
        fn remove_switched_off(&self) {
            self.calls
                .borrow_mut()
                .push("remove_switched_off".to_owned());
        }
        fn liveness(&self, after: &str) -> Liveness {
            self.calls.borrow_mut().push(format!("liveness: {after}"));
            Liveness {
                after: after.to_owned(),
                status: "running".to_owned(),
                restarts: 0,
                exit_code: 0,
                out_of_memory: false,
                answered: true,
            }
        }
    }

    fn accounts() -> Accounts {
        let account = |role: &str| crate::signed_in::Account {
            user: format!("sv-{role}@example.test"),
            password: format!("Sv-{role}-aZ9!"),
        };
        Accounts {
            a: account("a"),
            b: account("b"),
            admin: None,
            spare: "0123456789abcdef0123456789abcdef".to_owned(),
            totp: None,
            admin_totp_secret: None,
        }
    }

    fn first_words(calls: &[String]) -> Vec<String> {
        calls
            .iter()
            .map(|c| c.split(' ').take(2).collect::<Vec<_>>().join(" "))
            .collect()
    }

    #[test]
    fn with_nothing_in_the_manifest_only_the_anonymous_questions_and_one_look_are_made() {
        let harness = Nothing {
            calls: RefCell::new(Vec::new()),
        };
        let policy = PolicySection::default();
        let plan = Plan {
            users: None,
            policy: &policy,
            oidc: None,
            ai: None,
            mcp_server: None,
            fetch: None,
            health_path: "/",
            slow: false,
            accounts: None,
            mcp_token: None,
        };
        let out = run(&harness, &plan, &[]);
        assert_eq!(
            harness.calls.borrow().as_slice(),
            [
                "http App With { mail: false, provider: false, browser: false, model: None }",
                "liveness: the questions asked as somebody not signed in",
            ]
        );
        assert!(out.signed_in.is_none() && out.oidc.is_none() && out.ai.is_none());
        assert!(out.mcp_server.is_none() && out.fetch.is_none());
        assert_eq!(out.liveness.len(), 1);
    }

    #[test]
    fn every_suite_the_manifest_asks_for_runs_in_its_order_and_the_app_is_looked_at_again_after() {
        let harness = Nothing {
            calls: RefCell::new(Vec::new()),
        };
        let (users, policy) = (UsersSection::default(), PolicySection::default());
        let (oidc, ai) = (OidcSection::default(), AiSection::default());
        let (mcp, fetch) = (McpServerSection::default(), FetchSection::default());
        let accounts = accounts();
        let plan = Plan {
            users: Some(&users),
            policy: &policy,
            oidc: Some(&oidc),
            ai: Some(&ai),
            mcp_server: Some(&mcp),
            fetch: Some(&fetch),
            health_path: "/health",
            slow: false,
            accounts: Some(&accounts),
            mcp_token: Some("t"),
        };
        let out = run(&harness, &plan, &[]);
        let calls = harness.calls.borrow();
        // The setup: every suite was asked, each saying for itself what it could not do.
        assert!(out.signed_in.is_some() && out.oidc.is_some() && out.mcp_server.is_some());
        assert!(out.fetch.is_some() && out.ai.is_some());
        assert_eq!(out.liveness.len(), 2, "{calls:?}");
        // The order: anonymous first, then a look; signed in (with the mail server, the browser,
        // and the model when it answers); the provider; the MCP server; the fetch (the model's
        // address first); the AI feature, its log, the kill switch's copy (the model as started),
        // which is removed; then the second look.
        assert_eq!(
            calls.as_slice(),
            [
                "http App With { mail: false, provider: false, browser: false, model: None }",
                "liveness: the questions asked as somebody not signed in",
                "http App With { mail: true, provider: false, browser: true, model: IfAnswering }",
                "http App With { mail: false, provider: true, browser: false, model: None }",
                "http App With { mail: false, provider: false, browser: false, model: None }",
                "model_canary",
                "http App With { mail: false, provider: false, browser: false, model: IfAnswering }",
                "http App With { mail: false, provider: false, browser: false, model: IfAnswering }",
                "app_log",
                "http SwitchedOff With { mail: false, provider: false, browser: false, model: AsStarted }",
                "remove_switched_off",
                "liveness: the signed-in, sign-in, and AI questions as well",
            ],
            "{:?}",
            first_words(&calls)
        );
    }

    /// A harness whose app answers every request with its rate limiter, asking for a second's
    /// wait, and writes down what was sent and waited.
    struct Limited {
        sent: RefCell<Vec<String>>,
        waited: RefCell<u64>,
    }

    struct LimiterOnly<'a>(&'a Limited);
    impl Http for LimiterOnly<'_> {
        fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
            self.0.sent.borrow_mut().push(request.id.clone());
            Some(ProbeResponse {
                id: request.id.clone(),
                status: 429,
                headers: vec![("Retry-After".to_owned(), "1".to_owned())],
                body: "slow down".to_owned(),
            })
        }
        fn wait(&mut self, seconds: u64) {
            *self.0.waited.borrow_mut() += seconds;
        }
    }

    impl Services for Limited {
        fn http<'s>(&'s self, _target: Target, _with: With) -> Box<dyn Http + 's> {
            Box::new(LimiterOnly(self))
        }
        fn model_canary(&self) -> Option<String> {
            None
        }
        fn app_log(&self) -> String {
            String::new()
        }
        fn seed(&self, _: Target, _: &str, _: &Accounts) -> Result<(), String> {
            Ok(())
        }
        fn start_switched_off(&self, _: &str) -> bool {
            false
        }
        fn remove_switched_off(&self) {}
        fn liveness(&self, after: &str) -> Liveness {
            Liveness {
                after: after.to_owned(),
                status: "running".to_owned(),
                restarts: 0,
                exit_code: 0,
                out_of_memory: false,
                answered: true,
            }
        }
    }

    #[test]
    fn the_mcp_suite_waits_a_limiter_out_once_and_says_when_it_kept_answering() {
        // Until 8 October 2026 the OIDC, MCP, and fetch suites took a limiter's answer as the
        // app's. Now each goes through `Patient`: the request is sent again after the wait the
        // app asks for, and a limiter that keeps answering is said, as the signed-in suites say it.
        let harness = Limited {
            sent: RefCell::new(Vec::new()),
            waited: RefCell::new(0),
        };
        let policy = PolicySection::default();
        let mcp = McpServerSection {
            path: "/mcp".to_owned(),
            ..McpServerSection::default()
        };
        let plan = Plan {
            users: None,
            policy: &policy,
            oidc: None,
            ai: None,
            mcp_server: Some(&mcp),
            fetch: None,
            health_path: "/",
            slow: false,
            accounts: None,
            mcp_token: None,
        };
        let out = run(&harness, &plan, &[]);
        let sent = harness.sent.borrow();
        // The setup: the suite asked, and was answered by the limiter each time.
        let first = sent.iter().filter(|id| *id == "mcp-initialize").count();
        assert_eq!(first, 2, "sent once, waited, sent once more: {sent:?}");
        assert!(*harness.waited.borrow() >= 1, "waited as the app asked");
        let mcp = out.mcp_server.expect("the MCP suite ran");
        assert!(
            mcp.steps
                .iter()
                .any(|s| s.contains("rate limiter was still answering")),
            "{:?}",
            mcp.steps
        );
        assert!(
            mcp.verified.is_empty(),
            "nothing is credited behind a limiter"
        );
    }

    #[test]
    fn the_run_waits_for_a_limiter_at_most_once_over_all_its_suites() {
        // One budget (`MOST_WAITING`) for the run: with the limiter answering everything, the
        // MCP and fetch suites together wait no longer than one suite alone may.
        let harness = Limited {
            sent: RefCell::new(Vec::new()),
            waited: RefCell::new(0),
        };
        let policy = PolicySection::default();
        let mcp = McpServerSection {
            path: "/mcp".to_owned(),
            ..McpServerSection::default()
        };
        let fetch = FetchSection::default();
        let plan = Plan {
            users: None,
            policy: &policy,
            oidc: None,
            ai: None,
            mcp_server: Some(&mcp),
            fetch: Some(&fetch),
            health_path: "/",
            slow: false,
            accounts: None,
            mcp_token: None,
        };
        let _ = run(&harness, &plan, &[]);
        assert!(
            *harness.waited.borrow() <= crate::signed_in::MOST_WAITING,
            "waited {} seconds over the run",
            harness.waited.borrow()
        );
    }

    #[test]
    fn the_kill_switch_copy_is_started_only_when_the_model_was_reached() {
        // With a harness that answers nothing the model is never reached, so the copy is never
        // started: the test above shows no `start_switched_off`. This holds the other half: the
        // suite is still asked about the switch, and told the copy did not start.
        let harness = Nothing {
            calls: RefCell::new(Vec::new()),
        };
        let policy = PolicySection::default();
        let ai = AiSection {
            kill_switch: Some("AI_DISABLED=1".to_owned()),
            ..AiSection::default()
        };
        let plan = Plan {
            users: None,
            policy: &policy,
            oidc: None,
            ai: Some(&ai),
            mcp_server: None,
            fetch: None,
            health_path: "/",
            slow: false,
            accounts: None,
            mcp_token: None,
        };
        let out = run(&harness, &plan, &[]);
        let calls = harness.calls.borrow();
        assert!(
            !calls.iter().any(|c| c == "start_switched_off"),
            "{calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == "remove_switched_off"),
            "{calls:?}"
        );
        let ai = out.ai.unwrap();
        assert!(
            ai.not_assessed
                .iter()
                .any(|(ids, _)| ids.contains("C9.6.1")),
            "{:?}",
            ai.not_assessed
        );
    }
}
