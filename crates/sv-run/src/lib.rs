//! Running the app, so the checks that need a running app have something to check.
//!
//! v1 gets its strongest evidence by running the code: seeded users, DAST probes, a real test
//! suite. Keeping that across arbitrary stacks means the manifest declares how to build, start and
//! test, and `sv` does it inside a fence.
//!
//! # The fence, and what measuring it changed
//!
//! v1 fences a child process with `sandbox-exec` on macOS or a network namespace on Linux, and
//! probes it over `127.0.0.1`. The obvious translation — publish a container port to loopback and
//! probe that — does not work, and this was measured rather than reasoned about:
//!
//! | | `--internal` network | default bridge |
//! |---|---|---|
//! | sidecar on the same network reaches the app | yes | yes |
//! | app can reach 1.1.1.1:53 | **blocked** | succeeded |
//! | host reaches a published port | **no** | yes |
//!
//! An `--internal` network is exactly the fence wanted — no outbound, no DNS — and it is
//! unreachable from the host, published port or not. Moving to a bridge to make host probing work
//! removes the fence altogether. So the probes run from a **sidecar container on the same internal
//! network**, and nothing is published to the host at all.
//!
//! (The first two attempts at that measurement proved nothing: `alpine:3` has no `httpd` applet, so
//! every container exited immediately and reported "outbound blocked" while not running. Then
//! `example.com`'s old address, long decommissioned, made the default bridge look fenced too. The
//! table above comes from a run with a live target and a host baseline confirming outbound is
//! possible from this machine in the first place.)
//!
//! # What happens where there is no backend
//!
//! It reports `not assessed` — never `pass`, never `fail`. A machine without Docker is the normal
//! case for most people running `sv`, and a runner that assumed one would report their apps as
//! failing rather than as unrun. That is the same rule as a scanner that did not run not being a
//! clean result.

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use sv_manifest::Manifest;

pub mod cleanup;
pub mod docker;

/// Why the app could not be run. Every one of these produces `not assessed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CannotRun {
    /// No container backend on this machine.
    NoBackend { checked: String },
    /// The manifest does not say how to start the app.
    NoRunCommand { missing: Vec<String> },
    /// The backend is there but refused.
    BackendFailed { detail: String },
    /// The app was started and never became healthy.
    NeverReady { waited_seconds: u64, detail: String },
}

impl CannotRun {
    /// Plain language, for the reports and the terminal.
    pub fn explain(&self) -> String {
        match self {
            CannotRun::NoBackend { checked } => format!(
                "No container backend on this computer ({checked}). Everything that needs the app \
                 running is reported as not assessed — not as passing, and not as failing."
            ),
            CannotRun::NoRunCommand { missing } => format!(
                "securevibe.toml does not say how to run this app ({} not set under [stack.run]), \
                 so everything that needs it running is reported as not assessed.",
                missing.join(", ")
            ),
            CannotRun::BackendFailed { detail } => format!(
                "The container backend refused: {detail}. Everything that needs the app running \
                 is reported as not assessed."
            ),
            CannotRun::NeverReady {
                waited_seconds,
                detail,
            } => format!(
                "The app started but never answered on its health path within {waited_seconds}s. \
                 {detail} This is reported as not assessed rather than as a failure: an app that \
                 will not start under `sv` has not been shown to be insecure."
            ),
        }
    }
}

/// How to build, start and test the app, taken from the manifest and checked over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub image: String,
    pub build: Option<String>,
    pub start: String,
    pub test: Option<String>,
    /// Where the test command writes a JUnit XML report, relative to the app folder.
    pub test_report: Option<String>,
    /// How long the test command may run before it is stopped.
    pub test_limit: Duration,
    pub health_path: String,
    /// Where the app's code is.
    pub app_dir: PathBuf,
    /// The port the app listens on inside the container.
    pub port: u16,
    /// How to sign in, when securevibe.toml says. Absent means the probes sign in as nobody.
    pub users: Option<sv_manifest::UsersSection>,
    /// The numbers the owner states as policy, for the probes that hold the app to them.
    pub policy: sv_manifest::PolicySection,
    /// How the app signs in through another service, when securevibe.toml says. The run then
    /// starts a test provider of `sv`'s own and points the app at it.
    pub oidc: Option<sv_manifest::OidcSection>,
    /// How to talk to the app's AI feature, when securevibe.toml says. The run then starts a test
    /// model of `sv`'s own and points the app at it.
    pub ai: Option<sv_manifest::AiSection>,
    /// Where the app answers GraphQL and WebSocket connections, when securevibe.toml says.
    pub graphql: Option<String>,
    pub websocket: Option<String>,
    /// Whether other programs are meant to use this app's API, as securevibe.toml claims it.
    /// Introspection is allowed for an API meant for others and not otherwise (V4.3.2), so the
    /// answer to that question depends on this one, and silence here leaves it unanswered.
    pub public_api: Option<bool>,
    /// Wait out the session timeouts the owner states (`sv run --slow`). Off unless asked for: it
    /// can take as long as the timeouts, up to an hour and a half.
    pub slow: bool,
}

/// The port the app is told to listen on. Fixed rather than chosen: nothing is published to the
/// host, so there is nothing to collide with, and a constant is one less thing to get wrong.
pub const APP_PORT: u16 = 8080;

/// The only place inside the container a test runner may write.
///
/// The app's own folder is mounted read-only, deliberately — `sv` reads code, it does not let the
/// code it is checking rewrite itself mid-check — so a runner asked to write a JUnit report into
/// the project simply cannot, and the first version of `test-report` failed exactly that way. This
/// is a tmpfs: in memory, gone when the container goes, and never on the owner's disk.
pub const REPORT_DIR: &str = "/sv-reports";

/// Where a declared report really lands, so a relative path does not mean "in the read-only app".
pub fn report_path(declared: &str) -> String {
    if declared.starts_with('/') {
        declared.to_owned()
    } else {
        format!("{REPORT_DIR}/{}", declared.trim_start_matches("./"))
    }
}

impl RunPlan {
    /// Reads the plan out of the manifest, or says exactly what is missing.
    pub fn from_manifest(manifest: &Manifest, app_dir: &Path) -> Result<Self, CannotRun> {
        let run = &manifest.stack.run;
        let mut missing = Vec::new();
        let image = non_empty(&run.image);
        let start = non_empty(&run.start);
        if image.is_none() {
            missing.push("image".to_owned());
        }
        if start.is_none() {
            missing.push("start".to_owned());
        }
        if !missing.is_empty() {
            return Err(CannotRun::NoRunCommand { missing });
        }
        Ok(RunPlan {
            image: image.expect("checked above"),
            build: non_empty(&run.build),
            start: start.expect("checked above"),
            test: non_empty(&run.test),
            test_report: non_empty(&run.test_report),
            test_limit: match run.test_time_limit {
                Some(seconds) if seconds > 0 => Duration::from_secs(seconds),
                _ => TEST_LIMIT,
            },
            health_path: non_empty(&run.health).unwrap_or_else(|| "/".to_owned()),
            // Absolute, always. Docker reads a relative path as the *name* of a named volume and
            // refuses it, which turns "sv was run from the wrong directory" into an error message
            // about invalid characters in a volume name.
            app_dir: app_dir
                .canonicalize()
                .unwrap_or_else(|_| app_dir.to_path_buf()),
            port: APP_PORT,
            users: run.users.clone(),
            policy: manifest.policy.clone(),
            oidc: run.oidc.clone(),
            ai: run.ai.clone(),
            graphql: run.graphql.clone(),
            websocket: run.websocket.clone(),
            public_api: manifest.capabilities.public_api,
            slow: false,
        })
    }
}

/// An empty string in a manifest is the template's placeholder, not an answer.
fn non_empty(field: &Option<String>) -> Option<String> {
    field
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// What a run produced.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Whether the app came up and answered.
    pub healthy: bool,
    /// The declared test command's exit status, when one was declared and run.
    pub tests: Option<TestResult>,
    /// Which fence actually applied, for the reports to state.
    pub fence: Fence,
    /// What the probes asked the app while it was up, and what it answered.
    pub probe_responses: Vec<sv_check::probes::ProbeResponse>,
    /// What asking as signed-in users showed, when securevibe.toml says how to sign in.
    pub signed_in: Option<sv_check::signed_in::Outcome>,
    /// What signing in through the test provider showed, when the app signs in through another
    /// service. Kept apart from `signed_in`: an app whose only sign-in is "Sign in with …" was not
    /// asked any of the signed-in questions, and folding the two together would say it was.
    pub oidc: Option<sv_check::signed_in::Outcome>,
    /// What asking the app's AI feature through the test model showed, when securevibe.toml says
    /// how to reach it.
    pub ai: Option<sv_check::signed_in::Outcome>,
    /// Containers and networks an earlier run on this machine left behind when its process was
    /// stopped outright, removed before this run started. See `cleanup`.
    pub left_over_removed: Vec<String>,
}

/// Two ordinary test accounts and, when asked for, an admin, each with a password made for this run.
///
/// Fresh every run and never written anywhere but the app's own container: they exist to be signed
/// in with once. The password carries every kind of character a password rule asks for, so an app
/// with a strict policy still accepts it.
pub fn new_accounts(with_admin: bool, with_totp: bool) -> sv_check::signed_in::Accounts {
    let account = |role: &str| {
        let tag = random_hex(6);
        sv_check::signed_in::Account {
            user: format!("sv-{role}-{tag}@example.test"),
            password: format!("Sv-{}-aZ9!", random_hex(12)),
        }
    };
    sv_check::signed_in::Accounts {
        a: account("a"),
        b: account("b"),
        admin: with_admin.then(|| account("admin")),
        spare: random_hex(16),
        // Twenty random bytes: the secret length RFC 4226 recommends, and what authenticator apps
        // make. Taken from the same random hex, two characters to a byte.
        totp: with_totp.then(|| sv_check::signed_in::TotpAccount {
            account: account("totp"),
            secret: random_hex(20)
                .as_bytes()
                .chunks(2)
                .map(|pair| {
                    u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0)
                })
                .collect(),
        }),
    }
}

/// Random bytes as hex, from the operating system. A clock-based value would repeat between runs
/// started in the same instant, and a password is the one thing here that must not be guessable.
fn random_hex(bytes: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    assert!(filled, "no source of randomness for test passwords");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    pub exit_code: i32,
    pub output: String,
    /// The JUnit XML the runner wrote, when one was declared and was really there afterwards.
    ///
    /// `None` covers every way this can go wrong — not declared, not written, unreadable — and they
    /// are told apart by `report_note` rather than by an empty string, because "the runner wrote no
    /// report" and "the report says nothing failed" must never arrive as the same thing.
    pub report: Option<String>,
    /// What happened when the report was looked for, when it did not simply work.
    pub report_note: Option<String>,
    /// Set when the suite was still running at its time limit and was stopped. Nothing it did is
    /// credited then: a suite cut short has not said which of its tests pass.
    pub stopped_after: Option<Duration>,
}

/// Which fence was in force. Reports say which applied, as v1's do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fence {
    /// A Docker network created with `--internal`: no outbound, no DNS, verified by measurement.
    DockerInternalNetwork,
    /// No fence was applied. Nothing should run under this; it exists so a report can say so.
    None,
}

impl Fence {
    pub fn explain(self) -> &'static str {
        match self {
            Fence::DockerInternalNetwork => {
                "The app ran on a container network created with `--internal`: it could not reach \
                 the internet, could not resolve any name, and nothing was published to this \
                 computer. The checks reached it from a second container on the same network."
            }
            Fence::None => {
                "No network fence was applied. The app could reach the internet while it ran."
            }
        }
    }
}

/// A container backend. A trait because most machines running `sv` will have none, and that case
/// has to be a first-class answer rather than a crash.
pub trait Backend {
    fn name(&self) -> String;
    /// Whether this backend is usable right now. Checked by using it, not by finding a binary:
    /// `docker` on the PATH with no daemon behind it is not a backend.
    fn available(&self) -> Result<(), CannotRun>;
    /// Starts the app, waits for it, asks it `probes`, runs the declared tests, and tears it down.
    ///
    /// The probes belong inside this call rather than beside it: they need the app up and the fence
    /// in place, and both of those exist only between the health check and the teardown.
    fn run(
        &self,
        plan: &RunPlan,
        probes: &[sv_check::probes::ProbeRequest],
    ) -> Result<RunOutcome, CannotRun>;
}

/// The backend to use, or why there is none.
pub fn detect() -> Result<Box<dyn Backend>, CannotRun> {
    let docker = docker::DockerBackend::new();
    match docker.available() {
        Ok(()) => Ok(Box::new(docker)),
        Err(e) => Err(e),
    }
}

/// Runs a command and hands back stdout+stderr with the status, or the reason it could not start.
/// How long any one Docker call may take before `sv` stops waiting for it. Generous, because
/// building an image or pulling one is a Docker call too; the point is that no call waits forever.
/// The long waits of `sv run --slow` happen between calls, not inside one.
pub const CALL_LIMIT: Duration = Duration::from_secs(30 * 60);

/// How long the app's own test suite may run, unless securevibe.toml says otherwise
/// (`[stack.run] test-time-limit`, in seconds).
pub const TEST_LIMIT: Duration = Duration::from_secs(10 * 60);

/// What became of a command given a time limit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Ran {
    /// It finished: its exit code (-1 when a signal ended it), and everything it printed.
    Finished(i32, String),
    /// It was still running at the limit and was stopped: what it had printed by then.
    Stopped(String),
}

/// Runs a command, stopping it if it is still running after `limit`. Output and errors are read
/// as they come, so a command that prints a great deal cannot stall on a full pipe.
pub(crate) fn run_within(command: &mut Command, limit: Duration) -> Result<Ran, String> {
    use std::io::Read;
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let read = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let out = read(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = read(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let mut text = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
    text.push_str(&String::from_utf8_lossy(&err.join().unwrap_or_default()));
    Ok(match status {
        Some(status) => Ran::Finished(status.code().unwrap_or(-1), text),
        None => Ran::Stopped(text),
    })
}

/// A Docker call, within `CALL_LIMIT`. One that runs out of time is an error naming the limit, so
/// a hung daemon or a stuck container ends the run with a reason instead of hanging it.
pub(crate) fn output_of(command: &mut Command) -> Result<(i32, String), String> {
    output_within(command, CALL_LIMIT)
}

fn output_within(command: &mut Command, limit: Duration) -> Result<(i32, String), String> {
    match run_within(command, limit)? {
        Ran::Finished(code, text) => Ok((code, text)),
        Ran::Stopped(_) => Err(format!(
            "it was still running after {}, the limit `sv` sets on any one Docker call, so it was stopped",
            sv_check::suite::limit_in_words(limit)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_command_that_finishes_in_time_gives_its_code_and_everything_it_printed() {
        let ran = run_within(
            Command::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]),
            Duration::from_secs(20),
        )
        .unwrap();
        match ran {
            Ran::Finished(3, text) => {
                assert!(text.contains("out") && text.contains("err"), "{text:?}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_command_still_running_at_its_limit_is_stopped_with_what_it_printed() {
        let started = std::time::Instant::now();
        let ran = run_within(
            Command::new("sh").args(["-c", "echo started; exec sleep 30"]),
            Duration::from_millis(500),
        )
        .unwrap();
        assert_eq!(ran, Ran::Stopped("started\n".to_owned()));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "stopped at the limit, not when it ended: {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_prints_a_great_deal_does_not_stall_on_a_full_pipe() {
        // Far more than a pipe holds (64 KB on Linux): read only at the end, this would never finish.
        let ran = run_within(
            Command::new("sh").args(["-c", "yes 0123456789 | head -c 2000000"]),
            Duration::from_secs(20),
        )
        .unwrap();
        match ran {
            Ran::Finished(0, text) => assert_eq!(text.len(), 2_000_000),
            other => panic!("{:?}", std::mem::discriminant(&other)),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_docker_call_that_runs_out_of_time_is_an_error_that_names_the_limit() {
        let err = output_within(
            Command::new("sh").args(["-c", "exec sleep 30"]),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(err.contains("still running after 1 second"), "{err}");
        assert_eq!(
            output_within(
                Command::new("sh").args(["-c", "echo hi"]),
                Duration::from_secs(20)
            ),
            Ok((0, "hi\n".to_owned()))
        );
        assert_eq!(CALL_LIMIT, Duration::from_secs(30 * 60));
    }

    #[test]
    fn a_limit_is_said_as_a_person_says_it() {
        use sv_check::suite::limit_in_words;
        assert_eq!(limit_in_words(TEST_LIMIT), "10 minutes");
        assert_eq!(limit_in_words(Duration::from_secs(60)), "1 minute");
        assert_eq!(limit_in_words(Duration::from_secs(90)), "90 seconds");
        assert_eq!(limit_in_words(Duration::from_secs(1)), "1 second");
    }

    #[test]
    fn the_test_limit_is_ten_minutes_unless_securevibe_toml_says_otherwise() {
        let plan = |seconds: Option<u64>| {
            let mut m = Manifest::default();
            m.stack.run.image = Some("busybox:1.36".to_owned());
            m.stack.run.start = Some("true".to_owned());
            m.stack.run.test_time_limit = seconds;
            RunPlan::from_manifest(&m, Path::new("."))
                .unwrap()
                .test_limit
        };
        assert_eq!(plan(None), TEST_LIMIT);
        assert_eq!(plan(Some(0)), TEST_LIMIT, "no limit at all is not a limit");
        assert_eq!(plan(Some(45)), Duration::from_secs(45));
    }

    #[test]
    fn every_run_makes_its_own_accounts_with_passwords_nobody_could_guess() {
        let one = new_accounts(true, true);
        let two = new_accounts(false, false);
        assert!(two.admin.is_none(), "no admin unless one was asked for");
        assert!(
            two.totp.is_none(),
            "no two-factor account unless one was asked for"
        );
        let totp = one
            .totp
            .as_ref()
            .expect("a two-factor account when asked for");
        assert_eq!(
            totp.secret.len(),
            20,
            "RFC 4226's recommended secret length"
        );
        assert_ne!(
            totp.secret,
            new_accounts(false, true).totp.unwrap().secret,
            "every run's secret is its own"
        );
        assert!(
            totp.secret.iter().any(|b| *b != 0),
            "a secret of zeros is what a failed parse would leave"
        );
        let admin = one.admin.as_ref().expect("an admin when asked for");
        let passwords = [
            &one.a.password,
            &one.b.password,
            &admin.password,
            &two.a.password,
        ];
        for (i, p) in passwords.iter().enumerate() {
            assert!(p.len() >= 24, "{p}");
            // Every kind of character a password rule asks for.
            assert!(
                p.chars().any(|c| c.is_ascii_uppercase())
                    && p.chars().any(|c| c.is_ascii_lowercase())
            );
            assert!(
                p.chars().any(|c| c.is_ascii_digit()) && p.chars().any(|c| !c.is_alphanumeric())
            );
            for other in &passwords[i + 1..] {
                assert_ne!(p, other, "two accounts share a password");
            }
        }
        assert_ne!(one.a.user, one.b.user);
        assert_ne!(one.a.user, two.a.user, "accounts are fresh every run");
    }

    #[test]
    fn a_manifest_that_does_not_say_how_to_run_says_which_parts_are_missing() {
        let m = Manifest::default();
        let err = RunPlan::from_manifest(&m, Path::new(".")).unwrap_err();
        assert_eq!(
            err,
            CannotRun::NoRunCommand {
                missing: vec!["image".to_owned(), "start".to_owned()]
            }
        );
        assert!(err.explain().contains("not assessed"));
    }

    #[test]
    fn the_templates_empty_placeholders_are_not_answers() {
        // `sv init` prints `image = ""`, and an AI tool that leaves it that way has not answered.
        // Treating "" as a command would produce a container that fails for a reason nobody can read.
        let mut m = Manifest::default();
        m.stack.run.image = Some("   ".to_owned());
        m.stack.run.start = Some(String::new());
        let err = RunPlan::from_manifest(&m, Path::new(".")).unwrap_err();
        assert_eq!(
            err,
            CannotRun::NoRunCommand {
                missing: vec!["image".to_owned(), "start".to_owned()]
            }
        );
    }

    #[test]
    fn a_complete_manifest_produces_a_plan() {
        let mut m = Manifest::default();
        m.stack.run.image = Some("python:3.12-slim".to_owned());
        m.stack.run.start = Some("gunicorn app:app".to_owned());
        m.stack.run.health = Some("/healthz".to_owned());
        let plan = RunPlan::from_manifest(&m, Path::new("/tmp/app")).unwrap();
        assert_eq!(plan.image, "python:3.12-slim");
        assert_eq!(plan.health_path, "/healthz");
        assert_eq!(plan.port, APP_PORT);
        assert_eq!(plan.test, None, "no test command declared");
    }

    #[test]
    fn the_app_directory_is_made_absolute() {
        // Docker treats a relative `-v` source as a named volume, so a relative path here fails
        // with a message about invalid characters that says nothing about the real cause.
        let mut m = Manifest::default();
        m.stack.run.image = Some("busybox:1.36".to_owned());
        m.stack.run.start = Some("httpd -f".to_owned());
        let plan = RunPlan::from_manifest(&m, Path::new(".")).unwrap();
        assert!(
            plan.app_dir.is_absolute(),
            "app_dir must be absolute, got {}",
            plan.app_dir.display()
        );
    }

    #[test]
    fn a_missing_health_path_defaults_to_the_root() {
        let mut m = Manifest::default();
        m.stack.run.image = Some("nginx".to_owned());
        m.stack.run.start = Some("nginx -g 'daemon off;'".to_owned());
        assert_eq!(
            RunPlan::from_manifest(&m, Path::new("."))
                .unwrap()
                .health_path,
            "/"
        );
    }

    #[test]
    fn every_reason_the_app_could_not_run_says_not_assessed_or_why() {
        // These strings are what an owner reads. None of them may imply the app failed a check.
        for reason in [
            CannotRun::NoBackend {
                checked: "docker".into(),
            },
            CannotRun::NoRunCommand {
                missing: vec!["image".into()],
            },
            CannotRun::BackendFailed {
                detail: "daemon refused".into(),
            },
            CannotRun::NeverReady {
                waited_seconds: 30,
                detail: "no reply".into(),
            },
        ] {
            let text = reason.explain();
            assert!(
                text.contains("not assessed") || text.contains("not been shown"),
                "every reason must say the result is not assessed, not that something failed: {text}"
            );
            assert!(
                !text.to_lowercase().contains("insecure") || text.contains("has not been shown"),
                "a reason must not read as a security verdict: {text}"
            );
        }
    }
}
