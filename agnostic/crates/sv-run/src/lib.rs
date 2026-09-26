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
use sv_manifest::Manifest;

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
    pub health_path: String,
    /// Where the app's code is.
    pub app_dir: PathBuf,
    /// The port the app listens on inside the container.
    pub port: u16,
    /// How to sign in, when securevibe.toml says. Absent means the probes sign in as nobody.
    pub users: Option<sv_manifest::UsersSection>,
    /// The numbers the owner states as policy, for the probes that hold the app to them.
    pub policy: sv_manifest::PolicySection,
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
}

/// Two ordinary test accounts and, when asked for, an admin, each with a password made for this run.
///
/// Fresh every run and never written anywhere but the app's own container: they exist to be signed
/// in with once. The password carries every kind of character a password rule asks for, so an app
/// with a strict policy still accepts it.
pub fn new_accounts(with_admin: bool) -> sv_check::signed_in::Accounts {
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
pub(crate) fn output_of(command: &mut Command) -> Result<(i32, String), String> {
    match command.output() {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            Ok((out.status.code().unwrap_or(-1), text))
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_run_makes_its_own_accounts_with_passwords_nobody_could_guess() {
        let one = new_accounts(true);
        let two = new_accounts(false);
        assert!(two.admin.is_none(), "no admin unless one was asked for");
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
