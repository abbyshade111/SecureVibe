//! The Docker backend.
//!
//! Shape of a run, and why each step is the way it is:
//!
//! 1. Create a per-run network with `--internal`. Measured: no outbound, no DNS, and unreachable
//!    from this computer. That last part is the reason there is no published port anywhere below.
//! 2. Start the app on it, with its folder mounted read-only and no credentials in its environment.
//! 3. Wait for it to answer its health path — from a **sidecar container on the same network**,
//!    because the host cannot reach it.
//! 4. Run the declared test command inside the app container.
//! 5. Tear everything down, whatever happened.

use crate::{Backend, CannotRun, Fence, RunOutcome, RunPlan, TestResult, output_of};
use std::process::Command;

/// How long to wait for the app to answer before calling it not assessed.
const READY_TIMEOUT_SECONDS: u64 = 60;
/// The image the probes run from. Tiny, and already needed for the health check.
const PROBE_IMAGE: &str = "busybox:1.36";

pub struct DockerBackend {
    binary: String,
}

impl Default for DockerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerBackend {
    pub fn new() -> Self {
        Self {
            binary: "docker".to_owned(),
        }
    }

    fn docker(&self, args: &[&str]) -> Result<(i32, String), String> {
        let mut c = Command::new(&self.binary);
        c.args(args);
        output_of(&mut c)
    }
}

impl Backend for DockerBackend {
    fn name(&self) -> String {
        "Docker".to_owned()
    }

    fn available(&self) -> Result<(), CannotRun> {
        // `docker info` and not `docker --version`: the version prints happily with no daemon
        // behind it, and a backend that cannot run anything is not a backend.
        match self.docker(&["info", "--format", "{{.ServerVersion}}"]) {
            Ok((0, _)) => Ok(()),
            Ok((_, detail)) => Err(CannotRun::NoBackend {
                checked: format!("`docker info` failed: {}", first_line(&detail)),
            }),
            Err(e) => Err(CannotRun::NoBackend {
                checked: format!("`docker` could not be started: {e}"),
            }),
        }
    }

    fn run(&self, plan: &RunPlan) -> Result<RunOutcome, CannotRun> {
        let run_id = format!("sv-{}", std::process::id());
        let network = format!("{run_id}-net");
        let app = format!("{run_id}-app");
        let guard = Teardown {
            backend: self,
            network: network.clone(),
            container: app.clone(),
        };

        // 1. The fence.
        self.docker(&["network", "create", "--internal", &network])
            .map_err(|e| CannotRun::BackendFailed { detail: e })
            .and_then(|(code, out)| {
                if code == 0 {
                    Ok(())
                } else {
                    Err(CannotRun::BackendFailed {
                        detail: first_line(&out),
                    })
                }
            })?;

        // 1b. Do not take the flag's word for it. Asking Docker whether the network really is
        // internal costs one call and turns "we passed --internal" into "the fence is there".
        // If a future edit drops the flag, or a daemon ignores it, this stops the run before any
        // untrusted code starts, rather than running it unfenced and reporting a clean result.
        self.verify_fenced(&network)?;

        // 2. The app. Its folder is mounted read-only: `sv` reads code, it does not let the code
        //    it is checking rewrite itself mid-check. No port is published — nothing on this
        //    computer could reach it anyway, and saying so in the arguments keeps that honest.
        let mount = format!("{}:/app:ro", plan.app_dir.display());
        let port_env = format!("PORT={}", plan.port);
        let command = match &plan.build {
            Some(build) => format!("cd /app && {build} && {}", plan.start),
            None => format!("cd /app && {}", plan.start),
        };
        let (code, out) = self
            .docker(&[
                "run",
                "-d",
                "--name",
                &app,
                "--network",
                &network,
                "-v",
                &mount,
                "-w",
                "/app",
                "-e",
                &port_env,
                // Nothing of the owner's reaches the app: no API keys, no home directory.
                "--env-file",
                "/dev/null",
                &plan.image,
                "sh",
                "-c",
                &command,
            ])
            .map_err(|e| CannotRun::BackendFailed { detail: e })?;
        if code != 0 {
            return Err(CannotRun::BackendFailed {
                detail: first_line(&out),
            });
        }

        // 3. Ready, judged from inside the fence.
        let healthy = self.wait_until_ready(&network, &app, plan);
        if !healthy {
            let logs = self
                .docker(&["logs", "--tail", "20", &app])
                .map(|(_, o)| o)
                .unwrap_or_default();
            drop(guard);
            return Err(CannotRun::NeverReady {
                waited_seconds: READY_TIMEOUT_SECONDS,
                detail: format!("Its last output was: {}", first_line(&logs)),
            });
        }

        // 4. The declared tests, inside the app container so they see what the app sees.
        let tests = plan.test.as_ref().and_then(|test_command| {
            self.docker(&["exec", &app, "sh", "-c", test_command])
                .ok()
                .map(|(exit_code, output)| TestResult { exit_code, output })
        });

        drop(guard);
        Ok(RunOutcome {
            healthy,
            tests,
            fence: Fence::DockerInternalNetwork,
        })
    }
}

impl DockerBackend {
    /// Confirms with the daemon that the network really is internal. Fail secure: anything other
    /// than a clear "true" stops the run.
    pub fn verify_fenced(&self, network: &str) -> Result<(), CannotRun> {
        match self.docker(&["network", "inspect", "-f", "{{.Internal}}", network]) {
            Ok((0, out)) if out.trim() == "true" => Ok(()),
            Ok((0, out)) => Err(CannotRun::BackendFailed {
                detail: format!(
                    "the network `{network}` is not internal (Docker reports Internal={}), so the \
                     app would have been able to reach the internet while it ran",
                    out.trim()
                ),
            }),
            Ok((_, out)) => Err(CannotRun::BackendFailed {
                detail: format!("could not confirm the fence: {}", first_line(&out)),
            }),
            Err(e) => Err(CannotRun::BackendFailed {
                detail: format!("could not confirm the fence: {e}"),
            }),
        }
    }

    /// Polls the health path from a throw-away container on the same internal network.
    ///
    /// This is the part that could not be done from the host. An `--internal` network is
    /// unreachable from this computer whether or not a port is published, so the probe has to live
    /// inside the fence with the app.
    fn wait_until_ready(&self, network: &str, app: &str, plan: &RunPlan) -> bool {
        let url = format!("http://{app}:{}{}", plan.port, plan.health_path);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(READY_TIMEOUT_SECONDS);
        while std::time::Instant::now() < deadline {
            // If the app has already given up, waiting the full minute tells nobody anything.
            if let Ok((_, status)) = self.docker(&["inspect", "-f", "{{.State.Status}}", app])
                && status.trim() == "exited"
            {
                return false;
            }
            if let Ok((0, _)) = self.docker(&[
                "run",
                "--rm",
                "--network",
                network,
                PROBE_IMAGE,
                "wget",
                "-q",
                "-T",
                "3",
                "-O",
                "/dev/null",
                &url,
            ]) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        false
    }
}

/// Removes the container and the network however the run ended, including on an early return.
struct Teardown<'a> {
    backend: &'a DockerBackend,
    network: String,
    container: String,
}

impl Drop for Teardown<'_> {
    fn drop(&mut self) {
        let _ = self.backend.docker(&["rm", "-f", &self.container]);
        let _ = self.backend.docker(&["network", "rm", &self.network]);
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no detail")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_is_judged_by_the_daemon_not_the_binary() {
        // `docker --version` prints happily with no daemon behind it. A backend that cannot run
        // anything must not report itself as available, or every app on such a machine is reported
        // as failing rather than as unrun.
        let backend = DockerBackend {
            binary: "definitely-not-a-real-binary-xyz".to_owned(),
        };
        let err = backend.available().unwrap_err();
        match err {
            CannotRun::NoBackend { checked } => {
                assert!(checked.contains("could not be started"), "{checked}")
            }
            other => panic!("expected NoBackend, got {other:?}"),
        }
    }

    #[test]
    fn the_fence_explains_itself_without_overstating() {
        let text = Fence::DockerInternalNetwork.explain();
        assert!(text.contains("could not reach the internet"));
        assert!(Fence::None.explain().contains("No network fence"));
    }

    #[test]
    fn first_line_survives_empty_and_blank_output() {
        assert_eq!(first_line(""), "no detail");
        assert_eq!(first_line("\n\n  \n"), "no detail");
        assert_eq!(first_line("\n  real message  \nsecond"), "real message");
    }
}
