//! The Docker backend.
//!
//! Shape of a run, and why each step is the way it is:
//!
//! 1. Create a per-run network with `--internal`. Measured: no outbound, no DNS, and unreachable
//!    from this computer. That last part is the reason there is no published port anywhere below.
//! 2. Start the app on it, with its folder mounted read-only and no credentials in its environment.
//! 3. Wait for it to answer its health path — from a **sidecar container on the same network**,
//!    because the host cannot reach it. The sidecar is started once and every request after is an
//!    `exec` into it: a container started per request cost about half a second each, and a
//!    signed-in run makes twenty-odd requests.
//! 4. Ask the probes, anonymous and signed in, through the same sidecar; then remove it.
//! 5. Run the declared test command inside the app container.
//! 6. Tear everything down, whatever happened.

use crate::{Backend, CannotRun, Fence, REPORT_DIR, RunOutcome, RunPlan, TestResult, output_of};
use std::process::Command;

/// How long to wait for the app to answer before calling it not assessed.
const READY_TIMEOUT_SECONDS: u64 = 60;
/// The image the probes run from. Tiny, and already needed for the health check.
const PROBE_IMAGE: &str = "busybox:1.36";
/// The mail server the app is given when the probes need to read its email: Mailpit, which keeps
/// every message it is sent and answers questions about them over HTTP. Pinned to a minor release,
/// as the probe image is, so a run does not change under the owner because a new one came out.
const MAIL_IMAGE: &str = "axllent/mailpit:v1.31";
/// Where the app sends its mail on the mail server, and where the probes read it.
const SMTP_PORT: u16 = 1025;
const MAIL_API_PORT: u16 = 8025;
/// How long to wait for an email the app may send after it has already answered.
const MAIL_WAIT_SECONDS: u64 = 10;
/// How long the sidecar may live if nothing removes it. It is removed as soon as the probes are
/// done, and by the teardown whatever happens; this is the bound for a run that dies without either,
/// so a crash cannot leave a container behind on the owner's machine for longer than this.
const SIDECAR_SECONDS: u64 = 900;

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

    fn run(
        &self,
        plan: &RunPlan,
        probes: &[sv_check::probes::ProbeRequest],
    ) -> Result<RunOutcome, CannotRun> {
        let run_id = format!("sv-{}-{}", std::process::id(), next_run_number());
        let network = format!("{run_id}-net");
        let app = format!("{run_id}-app");
        let sidecar = format!("{run_id}-probe");
        let mail_name = format!("{run_id}-mail");
        let guard = Teardown {
            backend: self,
            network: network.clone(),
            containers: vec![app.clone(), sidecar.clone(), mail_name.clone()],
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

        // 1c. A mail server, when a check needs to read what the app emails. Started before the app so
        //     it is there to be sent to, on the same fenced network, and nowhere else: mail sent to it
        //     goes no further. If it cannot be started the run goes on without it, and the checks
        //     that needed it say so.
        let wants_mail = plan
            .users
            .as_ref()
            .is_some_and(|u| u.reset.is_some() || u.email_code.is_some());
        let mail =
            (wants_mail && self.start_mail(&network, &mail_name)).then_some(mail_name.as_str());

        // 2. The app. Its folder is mounted read-only: `sv` reads code, it does not let the code
        //    it is checking rewrite itself mid-check. No port is published — nothing on this
        //    computer could reach it anyway, and saying so in the arguments keeps that honest.
        let mount = format!("{}:/app:ro", plan.app_dir.display());
        let port_env = format!("PORT={}", plan.port);
        let mail_env: Vec<String> = mail
            .map(|host| {
                vec![
                    format!("SMTP_HOST={host}"),
                    format!("SMTP_PORT={SMTP_PORT}"),
                    format!("SMTP_URL=smtp://{host}:{SMTP_PORT}"),
                ]
            })
            .unwrap_or_default();
        let command = match &plan.build {
            Some(build) => format!("cd /app && {build} && {}", plan.start),
            None => format!("cd /app && {}", plan.start),
        };
        let mut args: Vec<&str> = vec![
            "run",
            "-d",
            "--name",
            &app,
            "--network",
            &network,
            "-v",
            &mount,
            // The one writable place, and it is in memory rather than on the owner's disk.
            // `/app` is read-only on purpose, so a test runner has nowhere to put its report
            // unless something is provided — which is how the first version of `test-report`
            // failed: the runner could not write the file and the report read as "no report",
            // correctly but uselessly. Findings are still only ever read out with `exec`.
            "--tmpfs",
            REPORT_DIR,
            "-w",
            "/app",
            "-e",
            &port_env,
            // Nothing of the owner's reaches the app: no API keys, no home directory.
            "--env-file",
            "/dev/null",
        ];
        for pair in &mail_env {
            args.extend(["-e", pair.as_str()]);
        }
        args.extend([plan.image.as_str(), "sh", "-c", command.as_str()]);
        let (code, out) = self
            .docker(&args)
            .map_err(|e| CannotRun::BackendFailed { detail: e })?;
        if code != 0 {
            return Err(CannotRun::BackendFailed {
                detail: first_line(&out),
            });
        }

        // 3. Ready, judged from inside the fence, by the sidecar every request goes through. If it
        //    cannot be started, each request starts a container of its own instead, as before:
        //    slower, and the same answers.
        let via = if self.start_sidecar(&network, &sidecar) {
            Via::Sidecar(&sidecar)
        } else {
            Via::FreshContainer(&network)
        };
        let healthy = self.wait_until_ready(&via, &app, plan);
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

        // 4. The probes, while the app is up and the fence is in place. A request that gets no
        //    answer is left out rather than recorded as an empty response: "the app said nothing"
        //    and "the app has no Content-Security-Policy" are not the same sentence.
        let probe_responses = probes
            .iter()
            .filter_map(|request| self.probe(&via, &app, plan.port, request))
            .collect();

        // 4b. As signed-in users, when securevibe.toml says how. After the anonymous probes, so
        //     those see the app as a stranger first; before the tests, which may change its data.
        let signed_in = plan
            .users
            .as_ref()
            .map(|users| self.signed_in(&via, &app, mail, plan, users));

        // Nothing after this point sends a request, so the sidecar goes now rather than waiting on
        // the tests, which can take as long as they like. The mail server with it: nothing reads it
        // after the probes.
        let _ = self.docker(&["rm", "-f", &sidecar]);
        if mail.is_some() {
            let _ = self.docker(&["rm", "-f", &mail_name]);
        }

        // 5. The declared tests, inside the app container so they see what the app sees.
        let tests = plan.test.as_ref().and_then(|test_command| {
            // A report left over from a previous run — committed into the repository, or baked into
            // the image — would be read as this run's result and credit tests that never ran here.
            // So it is removed first, and after the run the file must be there or nothing is read.
            // This is the same rule as a missing tool in the adapters: absent never reads as clean.
            let report_path = plan.test_report.as_ref().map(|p| crate::report_path(p));
            let removed_stale = report_path.as_ref().map(|path| {
                self.docker(&["exec", &app, "sh", "-c", &format!("rm -f -- '{path}'")])
                    .map(|(code, _)| code == 0)
                    .unwrap_or(false)
            });
            let (exit_code, output) = self
                .docker(&["exec", &app, "sh", "-c", test_command])
                .ok()?;
            let (report, report_note) = match (&report_path, removed_stale) {
                (None, _) => (
                    None,
                    Some(
                        "securevibe.toml declares no test-report, so only the exit code is known                          and a suite with one failing test credits nothing"
                            .to_owned(),
                    ),
                ),
                (Some(path), Some(false)) => (
                    None,
                    Some(format!(
                        "a report left over from an earlier run could not be removed from {path},                          so anything found there now cannot be trusted to be this run's"
                    )),
                ),
                (Some(path), _) => match self.docker(&["exec", &app, "cat", "--", path]) {
                    Ok((0, xml)) if !xml.trim().is_empty() => (Some(xml), None),
                    Ok((0, _)) => (
                        None,
                        Some(format!("the test runner wrote nothing to {path}")),
                    ),
                    _ => (
                        None,
                        Some(format!(
                            "the test runner wrote no report to {path}; only the exit code is known"
                        )),
                    ),
                },
            };
            Some(TestResult {
                exit_code,
                output,
                report,
                report_note,
            })
        });

        drop(guard);
        Ok(RunOutcome {
            healthy,
            tests,
            fence: Fence::DockerInternalNetwork,
            probe_responses,
            signed_in,
        })
    }
}

/// Requests to the app, made from the sidecar on the fenced network — the same way the anonymous
/// probes are made, so signing in happens inside the fence too.
struct DockerHttp<'a> {
    backend: &'a DockerBackend,
    via: &'a Via<'a>,
    app: &'a str,
    port: u16,
    /// The mail server's name on the fenced network, when the run has one.
    mail: Option<&'a str>,
}

impl sv_check::signed_in::Http for DockerHttp<'_> {
    fn send(
        &mut self,
        request: &sv_check::probes::ProbeRequest,
    ) -> Option<sv_check::probes::ProbeResponse> {
        self.backend.probe(self.via, self.app, self.port, request)
    }

    fn mail(&mut self, to: &str, at_least: usize) -> Option<Vec<String>> {
        let host = self.mail?;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(MAIL_WAIT_SECONDS);
        let ids = loop {
            // A mail server that does not answer is not an empty mailbox: the check is told there is
            // nothing to read, not that nothing was sent.
            let listing =
                self.backend
                    .fetch(self.via, host, MAIL_API_PORT, "/api/v1/messages?limit=500")?;
            let ids = mail_ids_to(&listing, to)?;
            if ids.len() >= at_least || std::time::Instant::now() >= deadline {
                break ids;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        };
        Some(
            ids.iter()
                .filter_map(|id| {
                    let path = format!("/api/v1/message/{id}");
                    let message = self.backend.fetch(self.via, host, MAIL_API_PORT, &path)?;
                    mail_text(&message)
                })
                .collect(),
        )
    }
}

/// How the mail server is started. Separate so its hardening can be checked without starting it.
fn mail_args<'a>(network: &'a str, name: &'a str) -> Vec<&'a str> {
    vec![
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--network",
        network,
        "--read-only",
        "--tmpfs",
        "/tmp",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        MAIL_IMAGE,
        "--smtp-auth-accept-any",
        "--smtp-auth-allow-insecure",
    ]
}

/// The messages sent to this address, oldest first, from Mailpit's list of messages.
///
/// Matched on every recipient field, since an app may put its user in `Bcc`, and without regard to
/// case, since an address's domain has none. `None` when the answer is not a list at all.
fn mail_ids_to(listing: &str, to: &str) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(listing).ok()?;
    let messages = value.get("messages")?.as_array()?;
    let mut ids: Vec<String> = messages
        .iter()
        .filter(|m| {
            ["To", "Cc", "Bcc"].iter().any(|field| {
                m.get(field).and_then(|v| v.as_array()).is_some_and(|list| {
                    list.iter().any(|r| {
                        r.get("Address")
                            .and_then(|a| a.as_str())
                            .is_some_and(|a| a.eq_ignore_ascii_case(to))
                    })
                })
            })
        })
        .filter_map(|m| m.get("ID")?.as_str().map(str::to_owned))
        .collect();
    // Mailpit lists the newest first.
    ids.reverse();
    Some(ids)
}

/// One message's text: the plain part and the HTML part both, since a link may be in either.
fn mail_text(message: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(message).ok()?;
    let part = |name: &str| value.get(name).and_then(|v| v.as_str()).unwrap_or("");
    Some(format!("{}\n{}", part("Text"), part("HTML")))
}

impl DockerBackend {
    /// Makes the accounts, then asks what they can do.
    fn signed_in(
        &self,
        via: &Via,
        app: &str,
        mail: Option<&str>,
        plan: &RunPlan,
        users: &sv_manifest::UsersSection,
    ) -> sv_check::signed_in::Outcome {
        let accounts = crate::new_accounts(
            !users.admin.is_empty(),
            users.totp.is_some() && users.seed.is_some(),
        );
        let mut http = DockerHttp {
            backend: self,
            via,
            app,
            port: plan.port,
            mail,
        };
        if !users.problems().is_empty() {
            // Nothing is run or asked; the suite says what is missing.
            return sv_check::signed_in::run(&mut http, users, &accounts, true, &plan.policy);
        }
        let seeded = match &users.seed {
            Some(seed) => {
                let mut args: Vec<String> = vec!["exec".into()];
                let mut env = vec![
                    ("SV_USER_A", accounts.a.user.clone()),
                    ("SV_PASSWORD_A", accounts.a.password.clone()),
                    ("SV_USER_B", accounts.b.user.clone()),
                    ("SV_PASSWORD_B", accounts.b.password.clone()),
                ];
                if let Some(admin) = &accounts.admin {
                    env.push(("SV_ADMIN", admin.user.clone()));
                    env.push(("SV_ADMIN_PASSWORD", admin.password.clone()));
                }
                if let Some(totp) = &accounts.totp {
                    env.push(("SV_USER_TOTP", totp.account.user.clone()));
                    env.push(("SV_PASSWORD_TOTP", totp.account.password.clone()));
                    env.push(("SV_TOTP_SECRET", sv_check::totp::base32(&totp.secret)));
                }
                for (k, v) in env {
                    args.push("-e".into());
                    args.push(format!("{k}={v}"));
                }
                args.extend([
                    app.to_owned(),
                    "sh".into(),
                    "-c".into(),
                    format!("cd /app && {seed}"),
                ]);
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                match self.docker(&args) {
                    Ok((0, _)) => true,
                    Ok((code, out)) => {
                        return sv_check::signed_in::Outcome {
                            not_assessed: vec![(
                                "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4".to_owned(),
                                format!(
                                    "The seed command in securevibe.toml failed (exit {code}): {}. \
                                     With no accounts there is nobody to sign in as.",
                                    first_line(&out)
                                ),
                            )],
                            ..Default::default()
                        };
                    }
                    Err(e) => {
                        return sv_check::signed_in::Outcome {
                            not_assessed: vec![(
                                "V8.2.1, V8.2.2, V7.2.4, V7.4.1, V3.5.1, V3.3.2, V3.3.4".to_owned(),
                                format!("The seed command could not be started: {e}."),
                            )],
                            ..Default::default()
                        };
                    }
                }
            }
            None => false,
        };
        let mut out = sv_check::signed_in::run(&mut http, users, &accounts, seeded, &plan.policy);

        // Last of all, and only after everything the probes do: whether the app wrote any of it
        // down. Reading the log earlier would be reading it before the events happened.
        let log = self
            .docker(&["logs", "--tail", "2000", app])
            .map(|(_, out)| out)
            .unwrap_or_default();
        let logged = sv_check::logs::evaluate(&out.log_markers, &log);
        out.findings.extend(logged.findings);
        out.verified.extend(logged.verified);
        out.not_assessed.extend(logged.not_assessed);
        out.steps.extend(logged.steps);
        out
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

    /// Starts the container every request to the app is sent from, on the app's fenced network.
    ///
    /// It has nothing to write and nothing to be allowed, so it is given neither: a read-only file
    /// system, no capabilities, and no way to gain privileges. It runs `sleep` and nothing else until
    /// a request is `exec`ed into it. `--rm` and the time limit mean a run that dies without its
    /// teardown still leaves nothing behind for long.
    fn start_sidecar(&self, network: &str, name: &str) -> bool {
        let limit = SIDECAR_SECONDS.to_string();
        matches!(
            self.docker(&[
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "--network",
                network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                PROBE_IMAGE,
                "sleep",
                &limit,
            ]),
            Ok((0, _))
        )
    }

    /// Starts the mail server on the app's fenced network.
    ///
    /// Hardened as the sidecar is, but for one place to write: Mailpit keeps its messages in a file,
    /// and that file goes in memory rather than anywhere on this computer. It accepts any user name
    /// and password over plain SMTP, so an app written to sign in to its mail server is not refused
    /// by this one; there is nothing behind it to protect.
    fn start_mail(&self, network: &str, name: &str) -> bool {
        matches!(self.docker(&mail_args(network, name)), Ok((0, _)))
    }

    /// Runs a command where requests to the app are made from: in the sidecar, or in a throw-away
    /// container on the same internal network when there is no sidecar.
    fn inside_fence(&self, via: &Via, command: &[&str]) -> Result<(i32, String), String> {
        let mut args = self.fence_args(via);
        args.extend_from_slice(command);
        self.docker(&args)
    }

    /// How a container that talks to the app is started, either way. Separate so the two paths can
    /// be compared without starting anything.
    fn fence_args<'a>(&self, via: &Via<'a>) -> Vec<&'a str> {
        match via {
            Via::Sidecar(name) => vec!["exec", name],
            // The same hardening as the sidecar. It had none of it: the flags were added where the
            // fast path was written and not where the fallback already lived, so a run that could
            // not start a sidecar quietly made every request from a container with its capabilities
            // and a writable file system — while the comment said the fallback was only slower.
            Via::FreshContainer(network) => vec![
                "run",
                "--rm",
                "--network",
                network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                PROBE_IMAGE,
            ],
        }
    }

    /// Polls the health path from inside the fence.
    ///
    /// This is the part that could not be done from the host. An `--internal` network is
    /// unreachable from this computer whether or not a port is published, so the probe has to live
    /// inside the fence with the app.
    fn wait_until_ready(&self, via: &Via, app: &str, plan: &RunPlan) -> bool {
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
            if let Ok((0, _)) =
                self.inside_fence(via, &["wget", "-q", "-T", "3", "-O", "/dev/null", &url])
            {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        false
    }
}

/// Where requests to the app are sent from.
enum Via<'a> {
    /// The run's sidecar, by name: each request is an `exec` into it.
    Sidecar(&'a str),
    /// A container started for the one request, on this network, when there is no sidecar.
    FreshContainer(&'a str),
}

/// Removes the containers and the network however the run ended, including on an early return.
struct Teardown<'a> {
    backend: &'a DockerBackend,
    network: String,
    containers: Vec<String>,
}

impl Drop for Teardown<'_> {
    fn drop(&mut self) {
        for container in &self.containers {
            let _ = self.backend.docker(&["rm", "-f", container]);
        }
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

/// A number that is different for every run in this process.
///
/// The names were the process id alone, which is unique between processes and constant within one.
/// Two runs in the same process therefore asked the daemon for a network that already existed, and
/// the second failed — found by running the fence tests without `--test-threads=1`, where three of
/// them went red at once with `network with name sv-37867-net already exists`. It is not only a test
/// problem: a single process that checks two apps, or rebuilds one, hits it the same way.
fn next_run_number() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------------------------
// Probing the running app

/// Base64, written out rather than taken as a dependency.
///
/// The request is handed to the sidecar encoded so that nothing in a header value can end the shell
/// command it travels in. A probe that sends `Origin: https://x.invalid` is harmless; one that can be
/// made to send a quote and a semicolon is a command injection in the security scanner, which would be
/// a poor advertisement.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - i * 6)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Writes out the request to send, or refuses to send one at all.
///
/// The path comes from the app's own manifest (`health_path`), so it is not something `sv` wrote. A
/// newline anywhere in a request line or a header lets that text add headers, or a second request,
/// of its own. There is no safe repair for that — a stripped path is a different request from the
/// one asked for — so the whole request is refused, and a probe with no answer is already reported
/// as unanswered rather than as a pass.
fn request_bytes(request: &sv_check::probes::ProbeRequest, host: &str) -> Option<String> {
    let unsafe_text = |s: &str| s.contains(['\r', '\n', ' ', '\t']);
    if unsafe_text(&request.method) || unsafe_text(&request.path) || unsafe_text(host) {
        return None;
    }
    if request
        .headers
        .iter()
        .any(|(name, value)| name.contains([':', '\r', '\n']) || value.contains(['\r', '\n']))
    {
        return None;
    }
    let mut raw = format!(
        "{} {} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n",
        request.method, request.path
    );
    for (name, value) in &request.headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    // A body is framed by its length, so nothing in it can be read as a second request: the server
    // stops at the byte count, whatever the body contains.
    if let Some(body) = &request.body {
        raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    } else {
        raw.push_str("\r\n");
    }
    Some(raw)
}

impl DockerBackend {
    /// Fetches a whole body from a service inside the fence other than the app: the mail server.
    ///
    /// Not through `probe`, which keeps only the start of a body — enough to judge an error page, and
    /// not enough to hold a list of messages or an HTML email.
    fn fetch(&self, via: &Via, host: &str, port: u16, path: &str) -> Option<String> {
        let request = sv_check::probes::ProbeRequest {
            id: "mail".to_owned(),
            method: "GET".to_owned(),
            path: path.to_owned(),
            headers: Vec::new(),
            body: None,
        };
        let raw = request_bytes(&request, host)?;
        let script = format!(
            "echo {} | base64 -d | nc -w 5 {host} {port}",
            base64(raw.as_bytes())
        );
        let (_, out) = self.inside_fence(via, &["sh", "-c", &script]).ok()?;
        let (head, body) = out.split_once("\r\n\r\n")?;
        head.split_whitespace()
            .nth(1)
            .is_some_and(|status| status == "200")
            .then(|| body.to_owned())
    }
}

/// Turns a raw HTTP response into the shape the probes read.
fn parse_response(id: &str, raw: &str) -> Option<sv_check::probes::ProbeResponse> {
    // A header block ends at the first blank line; tolerate a server that uses bare newlines.
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .unwrap_or((raw, ""));
    let mut lines = head.lines();
    let status = lines
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_owned()))
        .collect();
    Some(sv_check::probes::ProbeResponse {
        id: id.to_owned(),
        status,
        headers,
        // Enough to recognize a stack trace, not enough to copy a page out of somebody's app.
        body: body.chars().take(4000).collect(),
    })
}

impl DockerBackend {
    /// Makes one request to the app from inside the fence.
    ///
    /// HTTP is spoken directly over a socket rather than through a client, for two reasons found by
    /// trying the alternative: `wget` returns no body at all for a 404 or a 500, which is exactly the
    /// response the error-page probe needs to read, and it cannot send a method other than GET or POST.
    fn probe(
        &self,
        via: &Via,
        app: &str,
        port: u16,
        request: &sv_check::probes::ProbeRequest,
    ) -> Option<sv_check::probes::ProbeResponse> {
        let raw = request_bytes(request, app)?;
        let script = format!(
            "echo {} | base64 -d | nc -w 5 {app} {port}",
            base64(raw.as_bytes())
        );
        let (code, out) = self.inside_fence(via, &["sh", "-c", &script]).ok()?;
        if code != 0 && out.trim().is_empty() {
            return None;
        }
        parse_response(&request.id, &out)
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    /// The flags a container making requests to the app must carry, whichever path started it.
    const HARDENING: [&str; 4] = ["--read-only", "--cap-drop", "ALL", "no-new-privileges"];

    #[test]
    fn both_ways_of_reaching_the_app_are_fenced_the_same() {
        // The sidecar was hardened where it was written; the fallback three lines away was not, so
        // a run that could not start a sidecar made every request from a container with its
        // capabilities and a writable file system. The two paths are compared against each other
        // rather than each read on its own, because that is the shape the mistake had: correct in
        // one place and absent beside it.
        let backend = DockerBackend::new();
        let fresh = backend.fence_args(&Via::FreshContainer("net"));
        for flag in HARDENING {
            assert!(
                fresh.contains(&flag),
                "the fallback container is missing {flag}: {fresh:?}"
            );
        }
        assert!(
            fresh.contains(&"--network"),
            "and it still has to be on the fenced network: {fresh:?}"
        );
        // Measured against a real sidecar on 25 September 2026, with the host reaching 1.1.1.1:53
        // as the control: outbound blocked, DNS blocked, every path read-only, CapEff all zeroes.
    }

    #[test]
    fn the_mail_server_is_fenced_and_hardened_like_the_sidecar() {
        let args = mail_args("sv-1-net", "sv-1-mail");
        for flag in HARDENING {
            assert!(args.contains(&flag), "{flag} missing: {args:?}");
        }
        let at = args.iter().position(|a| *a == "--network").unwrap();
        assert_eq!(args[at + 1], "sv-1-net");
        // Nothing published: the only way to it is from inside the fence.
        assert!(
            !args
                .iter()
                .any(|a| *a == "-p" || a.starts_with("--publish"))
        );
    }

    #[test]
    fn mail_is_matched_to_its_address_in_any_recipient_field_oldest_first() {
        // As Mailpit answers: newest first, a message sent with the user only in Bcc, and one for
        // somebody else.
        let listing = r#"{"messages":[
            {"ID":"3","To":[{"Name":"","Address":"A@Example.test"}],"Cc":null,"Bcc":[]},
            {"ID":"2","To":[{"Address":"other@example.test"}],"Cc":[],"Bcc":[]},
            {"ID":"1","To":[],"Cc":[],"Bcc":[{"Address":"a@example.test"}]}
        ]}"#;
        assert_eq!(
            mail_ids_to(listing, "a@example.test"),
            Some(vec!["1".to_owned(), "3".to_owned()])
        );
        assert_eq!(mail_ids_to(listing, "nobody@example.test"), Some(vec![]));
        // Not a list at all is not an empty mailbox.
        assert_eq!(mail_ids_to("<html>502</html>", "a@example.test"), None);
    }

    #[test]
    fn a_messages_text_has_both_its_parts() {
        let text =
            mail_text(r#"{"Text":"plain http://x/reset?token=1","HTML":"<a href='y'>"}"#).unwrap();
        assert!(
            text.contains("token=1") && text.contains("<a href='y'>"),
            "{text}"
        );
        assert!(
            mail_text(r#"{"HTML":"<p>only html</p>"}"#)
                .unwrap()
                .contains("only html")
        );
    }

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> sv_check::probes::ProbeRequest {
        sv_check::probes::ProbeRequest {
            id: "t".into(),
            method: method.into(),
            path: path.into(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: None,
        }
    }

    #[test]
    fn a_body_goes_out_framed_by_its_length() {
        // A body is the one part of a request that may contain anything, newlines included; its
        // length is what stops the server reading past it into a second request.
        let mut r = req(
            "POST",
            "/login",
            &[("Content-Type", "application/x-www-form-urlencoded")],
        );
        r.body = Some("user=a&password=b\r\n\r\nGET /admin HTTP/1.0".into());
        let raw = request_bytes(&r, "app").expect("a body does not stop the request");
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        assert_eq!(body, r.body.as_deref().unwrap());
    }

    #[test]
    fn an_ordinary_request_is_written_out_in_full() {
        let raw = request_bytes(
            &req("GET", "/healthz", &[("Origin", "https://x.invalid")]),
            "app",
        )
        .expect("nothing wrong with this one");
        assert_eq!(
            raw,
            "GET /healthz HTTP/1.0\r\nHost: app\r\nConnection: close\r\nOrigin: https://x.invalid\r\n\r\n"
        );
    }

    #[test]
    fn a_newline_in_the_path_sends_nothing() {
        // The path is the app's own `health_path`, out of its manifest. Sending it as given would
        // let it add headers, or a whole second request, to what `sv` asked.
        assert!(request_bytes(&req("GET", "/a\r\nX-Injected: 1", &[]), "app").is_none());
        assert!(request_bytes(&req("GET", "/a\nX-Injected: 1", &[]), "app").is_none());
        // A space would break the request line into a different request just as effectively.
        assert!(request_bytes(&req("GET", "/a HTTP/1.1", &[]), "app").is_none());
    }

    #[test]
    fn a_newline_in_a_header_sends_nothing_either() {
        // Second witness, of a different shape: the header block rather than the request line, and
        // the name as well as the value.
        assert!(
            request_bytes(&req("GET", "/", &[("Origin", "a\r\nX-Injected: 1")]), "app").is_none()
        );
        assert!(request_bytes(&req("GET", "/", &[("X\r\nY", "z")]), "app").is_none());
        assert!(request_bytes(&req("GET", "/", &[("X: Y", "z")]), "app").is_none());
        // And the method, which is the third place text reaches the request line.
        assert!(request_bytes(&req("GET /x HTTP/1.1\r\n", "/", &[]), "app").is_none());
        // The container name too, though `sv` chooses that one.
        assert!(request_bytes(&req("GET", "/", &[]), "app\r\nX: 1").is_none());
    }

    #[test]
    fn every_request_the_suite_makes_goes_out_and_none_of_them_would_if_tampered_with() {
        // Second witness for the header check, of a different shape: the real suite rather than a
        // hand-written request, and a loop rather than one case — so a header `sv` adds later is
        // covered the day it is added.
        let requests = sv_check::probes::requests("/healthz");
        assert!(requests.len() >= 4);
        for request in &requests {
            assert!(
                request_bytes(request, "app").is_some(),
                "the suite's own request must be sendable: {request:?}"
            );
            let mut tampered = request.clone();
            tampered
                .headers
                .push(("X-Added".to_owned(), "value\r\nX-Injected: 1".to_owned()));
            assert!(
                request_bytes(&tampered, "app").is_none(),
                "a header carrying a newline must stop the whole request: {tampered:?}"
            );
        }
    }

    #[test]
    fn a_refused_request_never_reaches_the_encoder() {
        // What the refusal is for: whatever is encoded is what the sidecar's shell will run. This
        // asserts the dangerous text is absent from the thing that gets sent, not merely that some
        // Option was None.
        let bad = req("GET", "/a\r\nX-Injected: 1", &[]);
        assert!(request_bytes(&bad, "app").is_none());
        let good = req("GET", "/healthz", &[]);
        let encoded = base64(request_bytes(&good, "app").unwrap().as_bytes());
        assert!(!encoded.is_empty());
        assert!(
            !encoded.contains(['\'', ';', '|', '`', '$', ' ']),
            "{encoded}"
        );
    }

    #[test]
    fn base64_matches_the_known_encodings() {
        // Checked against values anybody can verify, rather than against this function's own output.
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(
            base64(b"GET / HTTP/1.0\r\n\r\n"),
            "R0VUIC8gSFRUUC8xLjANCg0K"
        );
    }

    #[test]
    fn a_raw_response_is_split_into_status_headers_and_body() {
        let raw = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nSet-Cookie: a=b; HttpOnly\r\n\r\n<h1>nope</h1>";
        let parsed = parse_response("missing", raw).expect("parses");
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.header("content-type"), Some("text/html"));
        assert_eq!(parsed.body, "<h1>nope</h1>");
    }

    #[test]
    fn a_header_value_containing_a_colon_keeps_it() {
        // `Location: https://x/y` splits on the wrong colon if the split is not limited to the first.
        let raw = "HTTP/1.1 302 Found\r\nLocation: https://example.com/next\r\n\r\n";
        let parsed = parse_response("r", raw).expect("parses");
        assert_eq!(parsed.header("location"), Some("https://example.com/next"));
    }

    #[test]
    fn a_response_using_bare_newlines_is_still_read() {
        let parsed = parse_response("r", "HTTP/1.0 200 OK\nX-A: b\n\nbody here").expect("parses");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.header("x-a"), Some("b"));
        assert_eq!(parsed.body, "body here");
    }

    #[test]
    fn something_that_is_not_http_is_not_invented_into_a_response() {
        assert!(parse_response("r", "").is_none());
        assert!(parse_response("r", "connection refused").is_none());
        assert!(parse_response("r", "HTTP/1.1 notanumber OK\r\n\r\n").is_none());
    }
}
