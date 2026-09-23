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
    pub health_path: String,
    /// Where the app's code is.
    pub app_dir: PathBuf,
    /// The port the app listens on inside the container.
    pub port: u16,
}

/// The port the app is told to listen on. Fixed rather than chosen: nothing is published to the
/// host, so there is nothing to collide with, and a constant is one less thing to get wrong.
pub const APP_PORT: u16 = 8080;

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
            health_path: non_empty(&run.health).unwrap_or_else(|| "/".to_owned()),
            // Absolute, always. Docker reads a relative path as the *name* of a named volume and
            // refuses it, which turns "sv was run from the wrong directory" into an error message
            // about invalid characters in a volume name.
            app_dir: app_dir
                .canonicalize()
                .unwrap_or_else(|_| app_dir.to_path_buf()),
            port: APP_PORT,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    pub exit_code: i32,
    pub output: String,
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
    fn run(&self, plan: &RunPlan) -> Result<RunOutcome, CannotRun>;
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
