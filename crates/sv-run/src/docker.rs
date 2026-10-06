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

use crate::{Backend, CannotRun, Fence, RunFailed, RunOutcome, RunPlan, TestResult, output_of};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

/// How long to wait for the app to answer before calling it not assessed.
const READY_TIMEOUT_SECONDS: u64 = 60;
/// The image the probes run from. Tiny, and already needed for the health check.
const PROBE_IMAGE: &str = "busybox:1.36";

/// The one place a container that talks to the app may write: in memory, where nothing written can
/// be run, and only big enough for the request it is about to send.
const PROBE_TMPFS: &str = "/tmp:rw,noexec,nosuid,size=16m";
/// Ways of giving the fenced network's bridge no address of its own on the host, tried in order.
/// `--internal` stops traffic leaving for the internet, but the bridge's gateway address is the host
/// itself (on Docker Desktop and Colima, the virtual machine), so without one of these the app could
/// reach anything listening there (the deep review of 4 October 2026, S2). Containers on the network
/// still reach one another. The first is Docker's own option for an internal network with no gateway
/// (Docker 28 and later); the second is the older one. Which was used is said if the check fails.
const NO_GATEWAY: &[&str] = &[
    "com.docker.network.bridge.gateway_mode_ipv4=isolated",
    "com.docker.network.bridge.inhibit_ipv4=true",
];
/// A port the gateway check knocks on: whatever answers there, open or refused, is the host's stack
/// answering, which is what the fence must not allow.
const GATEWAY_PORT: &str = "9";
/// The mail server the app is given when the probes need to read its email: Mailpit, which keeps
/// every message it is sent and answers questions about them over HTTP. Pinned to a minor release,
/// as the probe image is, so a run does not change under the owner because a new one came out.
const MAIL_IMAGE: &str = "axllent/mailpit:v1.31";
/// The test OpenID Connect provider runs in a stock Node image: its script uses built-in modules
/// only, because the fence has no route to a package registry.
const PROVIDER_IMAGE: &str = "node:22-alpine";
const PROVIDER_PORT: u16 = 9000;
const PROVIDER_SCRIPT: &str = include_str!("../assets/oidc-provider.mjs");
/// The test model the app's AI feature is pointed at, in the same stock Node image. See
/// `assets/model-provider.mjs`.
const MODEL_PORT: u16 = 9100;
const MODEL_SCRIPT: &str = include_str!("../assets/model-provider.mjs");
/// What the app is given as its API keys for the test model: something to send, and nothing that
/// would work anywhere else.
const MODEL_KEY: &str = "sv-test-model-key-not-a-real-key";
/// The client id the app is told to use. Not a secret: the provider checks it only to refuse a
/// sign-in the app did not ask for with its own configuration.
const PROVIDER_CLIENT_ID: &str = "sv-test-client";
/// The headless browser, pinned to one version so a run today and a run next month draw pages the
/// same way. Its DevTools port is reached only from the driver, which shares its network.
const BROWSER_IMAGE: &str = "chromedp/headless-shell:151.0.7922.109";
/// What drives it: a script of `sv`'s own, run in the same stock Node image as the test provider.
const DRIVER_SCRIPT: &str = include_str!("../assets/browser-driver.mjs");
/// Where the app sends its mail on the mail server, and where the probes read it.
const SMTP_PORT: u16 = 1025;
const MAIL_API_PORT: u16 = 8025;
/// How long to wait for an email the app may send after it has already answered.
const MAIL_WAIT_SECONDS: u64 = 10;
/// What every container `sv` starts may use at most: memory (with no swap beyond it), processes, and
/// processors. The app is code `sv` was asked to check, not code it trusts, and without these an app
/// that leaks memory or starts processes without end could take this computer down with it (the deep
/// review of 4 October 2026, S9). Its in-memory folders count against the same memory. Two gigabytes
/// and 512 processes are far more than an app answering a few hundred requests and running its tests
/// needs; the processors are two, or fewer when Docker has fewer, since Docker refuses more.
const MEMORY_LIMIT: &str = "2g";
const PROCESS_LIMIT: &str = "512";
const MOST_CPUS: u64 = 2;

/// How long the sidecar may live if nothing removes it. It is removed as soon as the probes are
/// done, and by the teardown whatever happens; this is the bound for a run that dies without either,
/// so a crash cannot leave a container behind on the owner's machine for longer than this.
const SIDECAR_SECONDS: u64 = 900;

pub struct DockerBackend {
    binary: String,
    /// What everything this backend starts is labeled with: this machine and this process.
    owner: String,
    /// The processors each container may use, asked of Docker once, when the first is started.
    /// `None` when Docker would not say, and then no processor limit is set.
    cpus: OnceLock<Option<String>>,
    /// The run under way, if one is: everything started while it is set carries it as `RUN_LABEL`,
    /// and its teardown removes exactly what carries it.
    run: std::sync::Mutex<Option<String>>,
    /// How far the containers' clock is ahead of this computer's, in seconds, measured once (`clock_offset`).
    clock_offset: OnceLock<i64>,
}

/// The label naming the one run a container or network belongs to. The owner label says which
/// process made it, for the next run's cleanup after a crash; this one says which run, so a
/// teardown removes only that run's and never another's (the deep review of 4 October 2026, S10).
const RUN_LABEL: &str = "org.securevibe.run";

impl Default for DockerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerBackend {
    pub fn new() -> Self {
        Self {
            binary: "docker".to_owned(),
            owner: crate::cleanup::owner(),
            cpus: OnceLock::new(),
            run: std::sync::Mutex::new(None),
            clock_offset: OnceLock::new(),
        }
    }

    /// How far the clock the app's containers read is ahead of this computer's, in seconds, asked of the
    /// fence's container once. On a Mac, Docker runs in a virtual machine whose clock can fall behind
    /// after the computer sleeps, and a two-factor code made by this computer's clock is then one the
    /// app, reading the machine's, refuses (the deep review's improvement 5). 0 when it cannot be read.
    fn clock_offset(&self, via: &Via) -> i64 {
        *self
            .clock_offset
            .get_or_init(|| self.read_clock_offset(via).unwrap_or(0))
    }

    /// One reading of the containers' clock against this computer's: `None` when it could not be read.
    fn read_clock_offset(&self, via: &Via) -> Option<i64> {
        let before = host_now();
        let read = self.inside_fence(via, &["date", "+%s"]);
        let after = host_now();
        match read {
            Ok((0, out)) => out
                .trim()
                .parse::<u64>()
                .ok()
                .map(|theirs| offset_from(before, theirs, after)),
            _ => None,
        }
    }

    /// The last 2000 lines the app wrote, to its output and its errors, in the order it wrote them.
    ///
    /// `docker logs` gives the two streams apart, and they were read one after the other, so a
    /// window between two markers on one stream held nothing the app wrote to the other in between
    /// (item 15 of the review of 1 to 4 October). Each line now comes with the time Docker took it,
    /// and the two are put back in that order.
    fn app_log(&self, app: &str) -> String {
        self.docker(&["logs", "--timestamps", "--tail", "2000", app])
            .map(|(_, out)| interleaved(&out))
            .unwrap_or_default()
    }

    fn docker(&self, args: &[&str]) -> Result<(i32, String), String> {
        let mut c = Command::new(&self.binary);
        c.args(self.prepared(args));
        output_of(&mut c)
    }

    /// As `docker`, with `secrets` in the Docker program's own environment, for arguments that name
    /// them with `-e NAME` and no value: Docker then copies each from its own environment. A value on
    /// the command line can be read by any other user of the computer while the command runs; a
    /// process's environment only by its own user (the deep review's improvement 5).
    fn docker_with_secrets(
        &self,
        args: &[&str],
        secrets: &[(&str, String)],
    ) -> Result<(i32, String), String> {
        let mut c = Command::new(&self.binary);
        c.args(self.prepared(args));
        c.envs(secrets.iter().map(|(k, v)| (*k, v.as_str())));
        output_of(&mut c)
    }

    /// A Docker call's arguments as they are sent: labeled, and, for one that starts a container,
    /// limited. Every container this backend starts goes through here, so none is missed.
    fn prepared(&self, args: &[&str]) -> Vec<String> {
        let mut labeled = crate::cleanup::labeled(args, &self.owner);
        let at = match args {
            ["run", ..] | ["create", ..] => Some(1),
            ["network", "create", ..] => Some(2),
            _ => None,
        };
        if let Some(at) = at
            && let Some(run) = self.run.lock().ok().and_then(|run| run.clone())
        {
            labeled.splice(at..at, ["--label".to_owned(), format!("{RUN_LABEL}={run}")]);
        }
        if !matches!(args, ["run", ..] | ["create", ..]) {
            return labeled;
        }
        let cpus = self.cpus.get_or_init(|| {
            let mut c = Command::new(&self.binary);
            c.args(["info", "--format", "{{.NCPU}}"]);
            match output_of(&mut c) {
                Ok((0, out)) => cpus_for(&out),
                _ => None,
            }
        });
        limited(labeled, cpus.as_deref())
    }

    /// Removes the containers, then the networks, that runs on this machine left behind when their
    /// process was killed outright. What it removed, by name.
    fn remove_leftovers(&self) -> Vec<String> {
        let machine = crate::cleanup::this_machine();
        let filter = format!("label={}", crate::cleanup::OWNER_LABEL);
        let format = format!(
            "{{{{.Names}}}}\t{{{{.Label \"{}\"}}}}",
            crate::cleanup::OWNER_LABEL
        );
        let network_format = format.replace(".Names", ".Name");
        let left = |args: &[&str]| -> Vec<String> {
            match self.docker(args) {
                Ok((0, out)) => out
                    .lines()
                    .filter_map(|line| line.split_once('\t'))
                    .filter(|(_, label)| {
                        crate::cleanup::is_leftover(label.trim(), &machine, crate::cleanup::alive)
                    })
                    .map(|(name, _)| name.trim().to_owned())
                    .collect(),
                _ => Vec::new(),
            }
        };
        let mut removed = Vec::new();
        for name in left(&["ps", "-a", "--filter", &filter, "--format", &format]) {
            if matches!(self.docker_cleanup(&["rm", "-f", &name]), Ok((0, _))) {
                removed.push(name);
            }
        }
        for name in left(&[
            "network",
            "ls",
            "--filter",
            &filter,
            "--format",
            &network_format,
        ]) {
            if matches!(self.docker_cleanup(&["network", "rm", &name]), Ok((0, _))) {
                removed.push(name);
            }
        }
        removed
    }

    /// A Docker call that removes what the run made. It still runs after Ctrl-C, since removing
    /// things is the point of catching it, and gets two minutes rather than twenty.
    fn docker_cleanup(&self, args: &[&str]) -> Result<(i32, String), String> {
        let mut c = Command::new(&self.binary);
        c.args(args);
        crate::bounded_output(&mut c, Duration::from_secs(120), true)
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
    ) -> Result<RunOutcome, RunFailed> {
        // Before anything is started, so Ctrl-C from here on removes what was.
        crate::catch_interrupts();
        // First, and outside the run proper, so that a run that then fails still says what it
        // removed.
        let left_over_removed = self.remove_leftovers();
        self.run_after_cleanup(plan, probes, left_over_removed.clone())
            .map_err(|reason| RunFailed {
                reason,
                left_over_removed,
            })
    }
}

impl DockerBackend {
    /// The run itself, once what earlier runs left has been removed.
    fn run_after_cleanup(
        &self,
        plan: &RunPlan,
        probes: &[sv_check::probes::ProbeRequest],
        left_over_removed: Vec<String>,
    ) -> Result<RunOutcome, CannotRun> {
        let run_id = run_id(std::process::id(), next_run_number(), &crate::random_hex(4));
        if let Ok(mut run) = self.run.lock() {
            *run = Some(run_id.clone());
        }
        let network = format!("{run_id}-net");
        let app = format!("{run_id}-app");
        let sidecar = format!("{run_id}-probe");
        let mail_name = format!("{run_id}-mail");
        let provider_name = format!("{run_id}-idp");
        let browser_name = format!("{run_id}-browser");
        let model_name = format!("{run_id}-model");
        let switched_off = format!("{run_id}-app-off");
        let guard = Teardown {
            backend: self,
            run: run_id.clone(),
            network: network.clone(),
            containers: vec![
                app.clone(),
                sidecar.clone(),
                mail_name.clone(),
                provider_name.clone(),
                browser_name.clone(),
                model_name.clone(),
                switched_off.clone(),
            ],
        };

        // 1. The fence. Without a gateway address when the daemon allows one of the ways; a daemon that
        //    refuses both gets the plain internal network, and the gateway check below decides.
        let mut made_with = None;
        for option in NO_GATEWAY {
            if self
                .docker(&["network", "create", "--internal", "-o", option, &network])
                .is_ok_and(|(code, _)| code == 0)
            {
                made_with = Some(*option);
                break;
            }
        }
        let created = match made_with {
            Some(_) => Ok((0, String::new())),
            None => self.docker(&["network", "create", "--internal", &network]),
        };
        created
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
        // 1b'. And that nothing on it can reach the host through the bridge's gateway, which
        //      `--internal` alone leaves open.
        self.verify_gateway_closed(&network).map_err(|e| match e {
            CannotRun::BackendFailed { detail } => CannotRun::BackendFailed {
                detail: format!(
                    "{detail} (the network was made {})",
                    made_with.map_or(
                        "plain internal: Docker refused both ways of leaving out a gateway"
                            .to_owned(),
                        |o| format!("with `{o}`")
                    )
                ),
            },
            other => other,
        })?;

        // 1c. A mail server, when a check needs to read what the app emails. Started before the app so
        //     it is there to be sent to, on the same fenced network, and nowhere else: mail sent to it
        //     goes no further. If it cannot be started the run goes on without it, and the checks
        //     that needed it say so.
        let wants_mail = plan
            .users
            .as_ref()
            .is_some_and(|u| u.reset.is_some() || u.email_code.is_some() || u.activation.is_some());
        let mail =
            (wants_mail && self.start_mail(&network, &mail_name)).then_some(mail_name.as_str());

        // 1d. A test OpenID Connect provider, when the app signs in through another service. Also
        //     before the app, which may read the provider's details as it starts. The secret is new
        //     every run and goes only to the provider and the app.
        let client_secret = crate::random_hex(16);
        // The access token the app's MCP server is told to accept, when it takes one fixed token.
        // New every run, and given only to the app and to the questions that send it.
        let mcp_token = plan
            .mcp_server
            .as_ref()
            .and_then(|m| m.token_env.as_ref())
            .map(|_| crate::random_hex(24));
        let provider = (plan.oidc.is_some()
            && self.start_provider(&network, &provider_name, &client_secret))
        .then_some(provider_name.as_str());

        // 1d½. A test model, when the app has an AI feature to ask. Before the app, which may read
        //      the model's address as it starts.
        // The test model's server also records what a feature that fetches addresses fetches, and
        // whether the app fetches the key a sign-in token names (V9.1.3): `sv` learns whether the
        // app's tokens are JWTs only after signing in, so any run that signs in starts it.
        let model = ((plan.ai.is_some() || plan.fetch.is_some() || plan.users.is_some())
            && self.start_model(&network, &model_name))
        .then_some(model_name.as_str());

        // 1e. A headless browser, when securevibe.toml asks for checks made in one. On the same
        //     fenced network, so the pages it draws can reach nothing the app could not. If it
        //     cannot be started the checks that needed it say so.
        let wants_browser = plan.users.as_ref().is_some_and(|u| u.browser.is_some());
        let browser = (wants_browser && self.start_browser(&network, &browser_name))
            .then_some(browser_name.as_str());

        // 2. The app, fenced and hardened like every helper (`app_args`).
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
        let mut args: Vec<&str> = app_args(&app, &network, &mount, &port_env);
        for pair in &mail_env {
            args.extend(["-e", pair.as_str()]);
        }
        let provider_env: Vec<String> = provider
            .map(|host| {
                vec![
                    format!("OIDC_ISSUER=http://{host}:{PROVIDER_PORT}"),
                    format!("OIDC_CLIENT_ID={PROVIDER_CLIENT_ID}"),
                    format!("OIDC_CLIENT_SECRET={client_secret}"),
                ]
            })
            .unwrap_or_default();
        for pair in &provider_env {
            args.extend(["-e", pair.as_str()]);
        }
        let model_env: Vec<String> = match (model, &plan.ai) {
            (Some(host), Some(section)) => {
                model_env(host, &section.base_url_env, section.mcp_url_env.as_deref())
            }
            _ => Vec::new(),
        };
        for pair in &model_env {
            args.extend(["-e", pair.as_str()]);
        }
        let mcp_env: Vec<String> = match (
            plan.mcp_server.as_ref().and_then(|m| m.token_env.as_ref()),
            &mcp_token,
        ) {
            (Some(name), Some(token)) if sv_manifest::is_variable_name(name) => {
                vec![format!("{name}={token}")]
            }
            _ => Vec::new(),
        };
        for pair in &mcp_env {
            args.extend(["-e", pair.as_str()]);
        }
        args.extend([plan.image.as_str(), "sh", "-c", command.as_str()]);
        // Kept for the copy of the app the kill-switch check starts, which differs only in its
        // name and one more setting.
        let app_args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
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
        let via = if self.start_sidecar(&network, &sidecar, plan) {
            Via::Sidecar(&sidecar)
        } else {
            Via::FreshContainer(&network)
        };
        let healthy = self.wait_until_ready(&via, &app, plan);
        // The browser reaches the app at http://localhost:<port>, as a person running it on their
        // own computer would: an app that trusts its own origin for forms trusts that one, and a
        // browser treats localhost as secure, so `Secure` cookies work without HTTPS. A forwarder
        // inside the browser's container carries it across. Without it there is no browser.
        let browser = browser.filter(|name| healthy && self.forward_browser(name, &app, plan.port));
        if !healthy {
            let logs = self
                .docker(&["logs", "--tail", "20", &app])
                .map(|(_, o)| o)
                .unwrap_or_default();
            // Whether the app had anything to start: the same folder, mounted the same way into a
            // container of the small image the probes already use, listed. Asked only here, so a
            // run that works pays nothing for it.
            let inside = self
                .docker(&[
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "-v",
                    &mount,
                    PROBE_IMAGE,
                    "ls",
                    "-A",
                    "/app",
                ])
                .ok()
                .filter(|(code, _)| *code == 0)
                .map(|(_, listed)| listed);
            drop(guard);
            if let Some(unseen) = crate::unseen_folder(&plan.app_dir, inside.as_deref()) {
                return Err(unseen);
            }
            let (detail, crashed) = never_ready_detail(&logs, plan.build.as_deref());
            return Err(CannotRun::NeverReady {
                waited_seconds: READY_TIMEOUT_SECONDS,
                detail,
                loopback: crate::loopback_named_in(&plan.start),
                crashed,
            });
        }

        // 4. The probes, while the app is up and the fence is in place. A request that gets no
        //    answer is left out rather than recorded as an empty response: "the app said nothing"
        //    and "the app has no Content-Security-Policy" are not the same sentence. So is one the
        //    app's rate limiter was still answering after waiting as it asked: its page is not the
        //    app's (`ask_anonymously`).
        let (probe_responses, probes_rate_limited) = sv_check::signed_in::ask_anonymously(
            &mut DockerHttp {
                backend: self,
                via: &via,
                app: &app,
                port: plan.port,
                mail: None,
                provider: None,
                browser: None,
                model: None,
            },
            probes,
        );
        let mut liveness = vec![self.liveness(
            &via,
            &app,
            plan,
            "the questions asked as somebody not signed in",
        )];

        // 4b. As signed-in users, when securevibe.toml says how. After the anonymous probes, so
        //     those see the app as a stranger first; before the tests, which may change its data.
        let accounts = plan.users.as_ref().map(|users| {
            crate::new_accounts(
                !users.admin.is_empty(),
                users.totp.is_some() && users.seed.is_some(),
            )
        });
        let signed_in = plan.users.as_ref().zip(accounts.as_ref()).map(|pair| {
            let model = model.filter(|host| self.model_ready(&via, host));
            self.signed_in(&via, &app, (mail, browser, model), plan, pair)
        });

        // 4c. Signing in through the test provider, when the app signs in through another service.
        //     A provider that never came up leaves `provider` empty, and the check says so.
        let oidc = plan.oidc.as_ref().map(|section| {
            let mut http = DockerHttp {
                backend: self,
                via: &via,
                app: &app,
                port: plan.port,
                mail: None,
                provider: provider.filter(|host| self.provider_ready(&via, host)),
                browser: None,
                model: None,
            };
            sv_check::oidc::run(&mut http, section)
        });

        // 4c'. The app as an MCP server, when securevibe.toml says where it answers.
        let mcp_server = plan.mcp_server.as_ref().map(|section| {
            let mut http = DockerHttp {
                backend: self,
                via: &via,
                app: &app,
                port: plan.port,
                mail: None,
                provider: None,
                browser: None,
                model: None,
            };
            sv_check::mcp_server::run(&mut http, section, mcp_token.as_deref())
        });

        // 4c''. A feature that fetches an address a person gives it, pointed at the test model's
        //      server, which records each fetch.
        let fetch = plan.fetch.as_ref().map(|section| {
            let ready = model.filter(|host| self.model_ready(&via, host));
            let canary = ready.map(|host| format!("http://{host}:{MODEL_PORT}"));
            let mut http = DockerHttp {
                backend: self,
                via: &via,
                app: &app,
                port: plan.port,
                mail: None,
                provider: None,
                browser: None,
                model: ready,
            };
            let context = sv_check::fetch::Context {
                signed_in: plan
                    .users
                    .as_ref()
                    .zip(accounts.as_ref())
                    .map(|(users, accounts)| (users, &accounts.b)),
                canary: canary.as_deref(),
            };
            sv_check::fetch::run(&mut http, section, &context)
        });

        // 4d. The AI feature, through the test model, when securevibe.toml says how to reach it.
        //     Last of the questions, as the second test user when it needs one: nothing after it
        //     depends on that user's session.
        let ai = plan.ai.as_ref().map(|section| {
            let mut http = DockerHttp {
                backend: self,
                via: &via,
                app: &app,
                port: plan.port,
                mail: None,
                provider: None,
                browser: None,
                model: model.filter(|host| self.model_ready(&via, host)),
            };
            let signed_in = plan
                .users
                .as_ref()
                .zip(accounts.as_ref())
                .map(|(users, accounts)| (users, &accounts.b));
            let context = sv_check::ai::Context {
                signed_in,
                policy: &plan.policy,
                health: &plan.health_path,
                seeded: plan.users.as_ref().is_some_and(|u| u.seed.is_some()),
                owner: accounts.as_ref().map(|accounts| &accounts.a),
            };
            let (mut outcome, markers) = sv_check::ai::run(&mut http, section, &context);
            // Then what the app wrote down about it, read after the questions, as the signed-in
            // suite reads its own markers.
            let log = self.app_log(&app);
            sv_check::ai::logged(&markers, &log, &mut outcome);

            // C9.6.1: a second copy of the app with the kill switch on, beside the first, so the
            // first and the declared tests are left as they were.
            let started = match &section.kill_switch {
                Some(switch) if markers.model_reached => {
                    self.start_switched_off(&app_args, &app, &switched_off, &plan.image, switch)
                        && self.wait_until_ready(&via, &switched_off, plan)
                        && match (section.signed_in, plan.users.as_ref(), accounts.as_ref()) {
                            (true, Some(users), Some(accounts)) => {
                                users.seed.as_ref().is_none_or(|seed| {
                                    self.seed(&switched_off, seed, accounts).is_ok()
                                })
                            }
                            _ => true,
                        }
                }
                _ => false,
            };
            let mut http = DockerHttp {
                backend: self,
                via: &via,
                app: &switched_off,
                port: plan.port,
                mail: None,
                provider: None,
                browser: None,
                model,
            };
            sv_check::ai::kill_switch(
                &mut http,
                section,
                &context,
                &markers,
                started,
                &mut outcome,
            );
            let _ = self.docker(&["rm", "-f", &switched_off]);
            outcome
        });

        // Still up after everything else it was asked, while the sidecar can still ask it.
        if signed_in.is_some()
            || oidc.is_some()
            || ai.is_some()
            || mcp_server.is_some()
            || fetch.is_some()
        {
            liveness.push(self.liveness(
                &via,
                &app,
                plan,
                "the signed-in, sign-in, and AI questions as well",
            ));
        }

        // Nothing after this point sends a request, so the sidecar goes now rather than waiting on
        // the tests, which can take as long as they like. The mail server with it: nothing reads it
        // after the probes.
        let _ = self.docker(&["rm", "-f", &sidecar]);
        if mail.is_some() {
            let _ = self.docker(&["rm", "-f", &mail_name]);
        }
        if provider.is_some() {
            let _ = self.docker(&["rm", "-f", &provider_name]);
        }
        if browser.is_some() {
            let _ = self.docker(&["rm", "-f", &browser_name]);
        }
        if model.is_some() {
            let _ = self.docker(&["rm", "-f", &model_name]);
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
            // At most `TEST_LIMIT`: a suite that hangs would otherwise hang the whole run. Stopping
            // the `docker exec` leaves the suite running in the app's container, which the
            // teardown then removes.
            let ran = crate::run_bounded(
                Command::new(&self.binary).args(["exec", &app, "sh", "-c", test_command]),
                plan.test_limit,
                false,
            )
            .ok()?;
            if ran.stopped {
                return Some(TestResult {
                    exit_code: ran.code,
                    output: ran.text,
                    report: None,
                    report_note: None,
                    stopped_after: Some(plan.test_limit),
                });
            }
            let (exit_code, output) = (ran.code, ran.text);
            let (report, report_note) = match (&report_path, removed_stale) {
                (None, _) => (
                    None,
                    Some(
                        "securevibe.toml declares no test-report, so only the exit code is known and a suite with one failing test credits nothing"
                            .to_owned(),
                    ),
                ),
                (Some(path), Some(false)) => (
                    None,
                    Some(format!(
                        "a report left over from an earlier run could not be removed from {path}, so anything found there now cannot be trusted to be this run's"
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
                stopped_after: None,
            })
        });

        drop(guard);
        Ok(RunOutcome {
            healthy,
            tests,
            fence: Fence::DockerInternalNetwork,
            probe_responses,
            probes_rate_limited,
            signed_in,
            oidc,
            ai,
            mcp_server,
            fetch,
            left_over_removed,
            liveness,
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
    /// The test provider's name on the fenced network, when the run has one that answered.
    provider: Option<&'a str>,
    /// The headless browser's container, when the run has one.
    browser: Option<&'a str>,
    /// The test model's name on the fenced network, when the run has one that answered.
    model: Option<&'a str>,
}

/// Now, in seconds since 1970, by this computer's clock.
fn host_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The containers' clock against this computer's, from a reading taken between `before` and `after`: the
/// difference from the middle of the two, and none when it is a second or less, which is the reading's
/// own uncertainty.
fn offset_from(before: u64, theirs: u64, after: u64) -> i64 {
    let middle = (i128::from(before) + i128::from(after)) / 2;
    let offset = i128::from(theirs) - middle;
    if offset.abs() <= 1 {
        0
    } else {
        i64::try_from(offset).unwrap_or(0)
    }
}

impl sv_check::signed_in::Http for DockerHttp<'_> {
    /// Now by the clock the app reads: this computer's, moved by how far the containers' differs, so a
    /// two-factor code is made for the time the app checks it against.
    fn now(&mut self) -> u64 {
        host_now().saturating_add_signed(self.backend.clock_offset(self.via))
    }

    /// The waits `--slow` makes can last an hour and a half, so they are taken in short steps that
    /// end at Ctrl-C, when the run goes on to remove its containers instead of waiting them out.
    fn wait(&mut self, seconds: u64) {
        let until = std::time::Instant::now() + Duration::from_secs(seconds);
        while !crate::interrupted() {
            let left = until.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(Duration::from_millis(200)));
        }
    }

    fn send(
        &mut self,
        request: &sv_check::probes::ProbeRequest,
    ) -> Option<sv_check::probes::ProbeResponse> {
        self.backend.probe(self.via, self.app, self.port, request)
    }

    fn send_together(
        &mut self,
        requests: &[sv_check::probes::ProbeRequest],
    ) -> Option<Vec<Option<sv_check::probes::ProbeResponse>>> {
        self.backend
            .probe_together(self.via, self.app, self.port, requests)
    }

    fn provider(
        &mut self,
        request: &sv_check::probes::ProbeRequest,
    ) -> Option<sv_check::probes::ProbeResponse> {
        let host = self.provider?;
        self.backend.probe(self.via, host, PROVIDER_PORT, request)
    }

    fn model(
        &mut self,
        request: &sv_check::probes::ProbeRequest,
    ) -> Option<sv_check::probes::ProbeResponse> {
        let host = self.model?;
        self.backend.probe(self.via, host, MODEL_PORT, request)
    }

    fn model_address(&mut self) -> Option<String> {
        self.model.map(|host| format!("http://{host}:{MODEL_PORT}"))
    }

    fn browser(&mut self, job: &sv_check::browser::Job) -> Option<Vec<serde_json::Value>> {
        let container = self.browser?;
        let job = serde_json::json!({
            "app": format!("http://localhost:{}", self.port),
            "actions": job.actions.iter().map(|a| a.to_json()).collect::<Vec<_>>(),
        });
        let env = format!("SV_JOB={}", base64(job.to_string().as_bytes()));
        let network = format!("container:{container}");
        let (code, out) = self.backend.docker(&driver_args(&network, &env)).ok()?;
        if code != 0 {
            return None;
        }
        // The driver prints one line of JSON last; anything Node said before it is not the answer.
        let line = out.lines().rev().find(|l| l.starts_with('['))?;
        serde_json::from_str::<Vec<serde_json::Value>>(line).ok()
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

/// What an app that never answered last said, and, when it had a build step, why such a step so
/// often fails here. The step runs inside the fence like the app, where nothing can be downloaded
/// and nothing outside `/tmp` written, so one that installs packages fails whatever it prints:
/// `pip install` says its package folder "is not writeable", and before the app ran read-only it
/// said the network was unreachable. Neither line names the cause, so this does.
fn never_ready_detail(logs: &str, build: Option<&str>) -> (String, bool) {
    // An app that crashed says what went wrong in its error line, which a Python traceback writes
    // last; one that is still running, or waiting, says the most in its last line (the review of
    // the loop's item 6, 6 October 2026: three crashes were quoted as "Traceback (most recent call
    // last):").
    let crash = crash_line(logs);
    let last = match &crash {
        Some(line) => format!("It stopped with an error: {line}"),
        None => format!("Its last output was: {}", last_line(logs)),
    };
    let crashed = crash.is_some();
    let detail = match build {
        Some(step) => format!(
            "{last} Its build step (`{step}`) ran inside the fence, where nothing can be \
             downloaded and the file system is read-only apart from /tmp, so a step that installs \
             packages cannot work there: install them into the image instead."
        ),
        None => last,
    };
    (detail, crashed)
}

/// The line that says why the app stopped, when its output shows it crashed: the last line that
/// names an error (`KeyError: 'PORT'`, `Error: Cannot find module 'express'`, `panic: …`,
/// `thread 'main' panicked at …`, Ruby's `… (NameError)`), read from the end past stack frames and
/// what a runtime prints after them. `None` when nothing in the output reads as a crash.
fn crash_line(logs: &str) -> Option<String> {
    logs.lines()
        .map(str::trim)
        .rev()
        .filter(|l| !l.is_empty())
        .find(|l| names_an_error(l))
        .map(str::to_owned)
}

/// Whether a line of output names an error: it starts with an error's name (`KeyError:`,
/// `sqlite3.OperationalError:`, `Error:`, `TypeError [ERR_…]:`), or with Go's or Rust's panic, or ends
/// with one in brackets, as Ruby writes it. An error's name ends in `Error`, `Exception`, or `Exit`, and
/// its last part is capitalized, so `server.onExit:` is not one. Read by hand rather than with a pattern library, which
/// `sv-run` does not otherwise need.
fn names_an_error(line: &str) -> bool {
    let is_error_name = |name: &str| {
        ["Error", "Exception", "Exit"]
            .iter()
            .any(|end| name.ends_with(end))
            && name
                .rsplit(['.', ':'])
                .next()
                .and_then(|last| last.chars().next())
                .is_some_and(|c| c.is_ascii_uppercase())
    };
    let first: String = line
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$'))
        .collect();
    let after = line[first.len()..].chars().next();
    if is_error_name(&first) && matches!(after, None | Some(':' | ' ' | '[')) {
        return true;
    }
    if line.starts_with("panic:")
        || (line.starts_with("thread '") && line.contains("' panicked"))
        || line.starts_with("Uncaught ")
        || line.to_ascii_lowercase().starts_with("fatal error")
    {
        return true;
    }
    line.strip_suffix(')')
        .and_then(|l| l.rsplit_once('('))
        .is_some_and(|(_, inner)| {
            inner
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_')
                && is_error_name(inner.rsplit("::").next().unwrap_or(inner))
        })
}

/// The last line of the app's output that says anything.
fn last_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .rev()
        .find(|l| !l.is_empty())
        .unwrap_or("no detail")
        .to_owned()
}

/// `args`, a `docker run` or `docker create`, with the limits every container is started under
/// inserted after the command.
fn limited(args: Vec<String>, cpus: Option<&str>) -> Vec<String> {
    let mut limits = vec![
        "--memory",
        MEMORY_LIMIT,
        "--memory-swap",
        MEMORY_LIMIT,
        "--pids-limit",
        PROCESS_LIMIT,
    ];
    if let Some(cpus) = cpus {
        limits.extend(["--cpus", cpus]);
    }
    let mut out = args;
    let at = 1.min(out.len());
    out.splice(at..at, limits.into_iter().map(str::to_owned));
    out
}

/// The processor limit for a Docker that says it has `ncpu` processors: `MOST_CPUS`, or all of them
/// when there are fewer. `None` when the answer is not a count.
fn cpus_for(ncpu: &str) -> Option<String> {
    let n: u64 = ncpu.trim().parse().ok().filter(|n| *n > 0)?;
    Some(n.min(MOST_CPUS).to_string())
}

/// The app's own `/tmp`: in memory, and with a size, so the app has somewhere to keep its data
/// while it runs (`sv init` tells it to use `/tmp`) and cannot fill the machine's memory through it.
const APP_TMP: &str = "/tmp:size=256m";

/// The folder a test runner writes its report to, at `REPORT_DIR`, in memory and with a size.
/// `/app` is read-only on purpose, so a test runner has nowhere to put its report unless something
/// is provided — which is how the first version of `test-report` failed: the runner could not
/// write the file and the report read as "no report", correctly but uselessly. Findings are still
/// only ever read out with `exec`.
const REPORT_TMPFS: &str = "/sv-reports:size=16m";

/// How the app itself is started: on the fenced network, and hardened like every helper — a
/// read-only file system, no capabilities, no way to gain any (ADR-019, "Later, 30 September
/// 2026"). Its writable places are two in-memory folders with a size each, `/tmp` and the report
/// folder. Its own folder is mounted read-only: `sv` reads code, it does not let the code it is
/// checking rewrite itself mid-check. No port is published — nothing on this computer could reach
/// it anyway, and saying so in the arguments keeps that honest. Separate so a test can read it.
fn app_args<'a>(
    name: &'a str,
    network: &'a str,
    mount: &'a str,
    port_env: &'a str,
) -> Vec<&'a str> {
    vec![
        "run",
        "-d",
        "--name",
        name,
        "--network",
        network,
        "--read-only",
        "--tmpfs",
        APP_TMP,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-v",
        mount,
        "--tmpfs",
        REPORT_TMPFS,
        "-w",
        "/app",
        "-e",
        port_env,
        // Nothing of the owner's reaches the app: no API keys, no home directory.
        "--env-file",
        "/dev/null",
    ]
}

/// How the test provider is started: fenced and hardened like the mail server, with its script
/// passed on the command line so nothing is written to the owner's disk.
fn provider_args<'a>(network: &'a str, name: &'a str, env: [&'a str; 4]) -> Vec<&'a str> {
    let mut args = vec![
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
    ];
    for pair in env {
        args.extend(["-e", pair]);
    }
    args.extend([
        PROVIDER_IMAGE,
        "node",
        "--input-type=module",
        "-e",
        PROVIDER_SCRIPT,
    ]);
    args
}

/// The first copy's `docker run` arguments, renamed, with one more setting before the image.
fn switched_off_args(
    app_args: &[String],
    app: &str,
    name: &str,
    image: &str,
    setting: &str,
) -> Option<Vec<String>> {
    let mut args: Vec<String> = app_args
        .iter()
        .map(|a| if a == app { name.to_owned() } else { a.clone() })
        .collect();
    let at = args.iter().rposition(|a| a == image)?;
    args.splice(at..at, ["-e".to_owned(), setting.to_owned()]);
    Some(args)
}

/// How the test model is started: fenced and hardened like the test provider.
fn model_args<'a>(network: &'a str, name: &'a str, env: [&'a str; 2]) -> Vec<&'a str> {
    let mut args = vec![
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
    ];
    for pair in env {
        args.extend(["-e", pair]);
    }
    args.extend([
        PROVIDER_IMAGE,
        "node",
        "--input-type=module",
        "-e",
        MODEL_SCRIPT,
    ]);
    args
}

/// What the app is told about the test model: the addresses the OpenAI and Anthropic libraries
/// read, a key for each that works nowhere else, and the OpenAI-style address in any other
/// variables securevibe.toml names.
fn model_env(host: &str, others: &[String], mcp: Option<&str>) -> Vec<String> {
    let openai = format!("http://{host}:{MODEL_PORT}/v1");
    let mut env = vec![
        format!("OPENAI_BASE_URL={openai}"),
        format!("OPENAI_API_KEY={MODEL_KEY}"),
        format!("ANTHROPIC_BASE_URL=http://{host}:{MODEL_PORT}"),
        format!("ANTHROPIC_API_KEY={MODEL_KEY}"),
    ];
    env.extend(others.iter().map(|name| format!("{name}={openai}")));
    // The test MCP server is the same container, at `/mcp`.
    env.extend(mcp.map(|name| format!("{name}=http://{host}:{MODEL_PORT}/mcp")));
    env
}

/// The browser's `/tmp`, where Chromium keeps its profile, and the mail server's, where Mailpit keeps
/// its messages: each in memory, and each with a size, as the app's is.
const BROWSER_TMP: &str = "/tmp:size=512m";
const MAIL_TMP: &str = "/tmp:size=64m";

/// How the browser is started. Hardened like the sidecar, with somewhere in memory to write, since
/// Chromium keeps its profile under `/tmp`; it runs with its own sandbox off, as it must in a
/// container, so the container is the sandbox and everything it may not do is taken away.
///
/// Chromium is started directly, not through the image's own script, which forwards port 9222 on
/// every address to DevTools and has Chromium listen on every address too: on the fenced network,
/// the app could reach DevTools and drive the browser that checks it (deep review S11). Here
/// DevTools listens on 127.0.0.1 alone, where only the driver, sharing the browser's network,
/// reaches it.
fn browser_args<'a>(network: &'a str, name: &'a str) -> Vec<&'a str> {
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
        BROWSER_TMP,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--entrypoint",
        "/headless-shell/headless-shell",
        BROWSER_IMAGE,
        "--no-sandbox",
        "--use-gl=angle",
        "--use-angle=swiftshader",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=9223",
    ]
}

/// How the driver is started: inside the browser's network, where the DevTools port is on
/// 127.0.0.1 and the app is reached by its name on the fenced network, and nothing else is.
fn driver_args<'a>(network: &'a str, job: &'a str) -> Vec<&'a str> {
    vec![
        "run",
        "--rm",
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-e",
        job,
        PROVIDER_IMAGE,
        "node",
        "--input-type=module",
        "-e",
        DRIVER_SCRIPT,
    ]
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
        MAIL_TMP,
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
        (mail, browser, model): (Option<&str>, Option<&str>, Option<&str>),
        plan: &RunPlan,
        (users, accounts): (&sv_manifest::UsersSection, &sv_check::signed_in::Accounts),
    ) -> sv_check::signed_in::Outcome {
        let mut http = DockerHttp {
            backend: self,
            via,
            app,
            port: plan.port,
            mail,
            provider: None,
            browser,
            model,
        };
        if !users.problems().is_empty() {
            // Nothing is run or asked; the suite says what is missing.
            return sv_check::signed_in::run(&mut http, users, accounts, true, &plan.policy);
        }
        let seeded = match &users.seed {
            Some(seed) => match self.seed(app, seed, accounts) {
                Ok(()) => true,
                Err(why) => {
                    return sv_check::signed_in::Outcome {
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
        let mut out = sv_check::signed_in::run_with(
            &mut http,
            users,
            accounts,
            seeded,
            &plan.policy,
            plan.slow,
        );

        // Last of all, and only after everything the probes do: whether the app wrote any of it
        // down. Reading the log earlier would be reading it before the events happened.
        let log = self.app_log(app);
        let logged = sv_check::logs::evaluate(&out.log_markers, &log);
        out.findings.extend(logged.findings);
        out.verified.extend(logged.verified);
        out.not_assessed.extend(logged.not_assessed);
        out.steps.extend(logged.steps);
        out
    }
}

impl DockerBackend {
    /// Runs the owner's `seed` command inside the app's container, with the run's accounts in its
    /// environment; or says, for the report, why it could not.
    fn seed(
        &self,
        app: &str,
        seed: &str,
        accounts: &sv_check::signed_in::Accounts,
    ) -> Result<(), String> {
        let env = seed_env(accounts);
        let names: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
        let args = seed_args(app, seed, &names);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        match self.docker_with_secrets(&args, &env) {
            Ok((0, _)) => Ok(()),
            Ok((code, out)) => Err(seed_failed(code, &out, accounts)),
            Err(e) => Err(format!("The seed command could not be started: {e}.")),
        }
    }

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

    /// Refuses the run when a container on the fenced network can reach the bridge's gateway, the
    /// host (or the virtual machine Docker runs in). Knocked on from a throwaway container: an answer
    /// of any kind, a connection or a refusal, is the host's stack answering. The control is the same
    /// knock on the container's own loopback, which must read as refused, so an `nc` that cannot tell
    /// one from the other stops the run rather than passing for a fence.
    pub fn verify_gateway_closed(&self, network: &str) -> Result<(), CannotRun> {
        let fail = |detail: String| Err(CannotRun::BackendFailed { detail });
        let config = match self.docker(&[
            "network",
            "inspect",
            "-f",
            "{{range .IPAM.Config}}{{.Gateway}}|{{.Subnet}} {{end}}",
            network,
        ]) {
            Ok((0, out)) => out,
            Ok((_, out)) => {
                return fail(format!(
                    "could not read the fence's gateway: {}",
                    first_line(&out)
                ));
            }
            Err(e) => return fail(format!("could not read the fence's gateway: {e}")),
        };
        // A network made without a gateway address may list none at all, so the address a gateway would
        // have, the subnet's first, is knocked on as well as any Docker names.
        let targets = gateway_targets(&config);
        if targets.is_empty() {
            return fail(format!(
                "Docker names no IPv4 gateway or subnet for the network `{network}` ({}), so whether the \
                 app could reach this computer through it cannot be checked",
                config.trim()
            ));
        }
        let gateway = targets.join(", ");
        // `-vv`, and not `-z`: busybox's netcat (`nc_bloaty.c`, 1.36) reports a refused connection only
        // at the second level of verbosity ("if we're scanning at a one -v verbosity level, don't print
        // refusals"), and a refusal kept quiet would read as silence, which must never pass for a fence.
        // CI found the first two tries silent. With nothing to send, a connection that opens ends at once.
        let mut script =
            format!("nc -vv -w 3 127.0.0.1 {GATEWAY_PORT} </dev/null 2>&1; echo \"sv-self=$?\"");
        // An address that is the knocking container's own is not knocked on: with no gateway, Docker
        // gives the subnet's first address to the first container, which is this one, and its own
        // refusal would read as the host answering. CI found exactly that.
        for target in &targets {
            script.push_str(&format!(
                "; case \" $(ip -4 -o addr show 2>/dev/null) \" in *\"inet {target}/\"*) echo \"sv-own={target}\";; \
                 *) nc -vv -w 3 {target} {GATEWAY_PORT} </dev/null 2>&1; echo \"sv-gateway=$?\";; esac"
            ));
        }
        let out = match self.docker(&[
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
            "sh",
            "-c",
            &script,
        ]) {
            Ok((_, out)) => out,
            Err(e) => return fail(format!("could not check the fence's gateway: {e}")),
        };
        match gateway_verdict(&out) {
            GatewayVerdict::Closed => Ok(()),
            GatewayVerdict::Reachable => fail(format!(
                "a container on the fenced network reached its gateway, {gateway}, which is this \
                 computer (or the virtual machine Docker runs in): the app could have reached anything \
                 listening there, so it was not started"
            )),
            GatewayVerdict::Unknown(why) => fail(format!(
                "could not tell whether the fence's gateway, {gateway}, is reachable ({why}), so the \
                 app was not started"
            )),
        }
    }

    /// Starts the container every request to the app is sent from, on the app's fenced network.
    ///
    /// It has nothing to be allowed and one thing to write, so it is given a read-only file system
    /// with one small folder in memory for the request it is about to send (`PROBE_TMPFS`), no
    /// capabilities, and no way to gain privileges. It runs `sleep` and nothing else until
    /// a request is `exec`ed into it. `--rm` and the time limit mean a run that dies without its
    /// teardown still leaves nothing behind for long.
    fn start_sidecar(&self, network: &str, name: &str, plan: &RunPlan) -> bool {
        let limit = sidecar_seconds(plan).to_string();
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
                "--tmpfs",
                PROBE_TMPFS,
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

    fn start_browser(&self, network: &str, name: &str) -> bool {
        matches!(self.docker(&browser_args(network, name)), Ok((0, _)))
    }

    /// Carries the browser's `localhost:<port>` to the app. Refused for the two ports Chromium's
    /// own DevTools use, where the forwarder would take the place of the thing it is driving.
    fn forward_browser(&self, name: &str, app: &str, port: u16) -> bool {
        if port == 9222 || port == 9223 {
            return false;
        }
        let listen = format!("TCP4-LISTEN:{port},fork,reuseaddr,bind=127.0.0.1");
        let to = format!("TCP4:{app}:{port}");
        matches!(
            self.docker(&["exec", "-d", name, "socat", &listen, &to]),
            Ok((0, _))
        )
    }

    fn start_provider(&self, network: &str, name: &str, secret: &str) -> bool {
        let (args, secrets) = provider_start(network, name, secret);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        matches!(self.docker_with_secrets(&args, &secrets), Ok((0, _)))
    }

    /// Starts a copy of the app under another name with one more setting in its environment: the
    /// same image, folder, network, and settings as the first, so the only difference between the
    /// two answers is the setting.
    fn start_switched_off(
        &self,
        app_args: &[String],
        app: &str,
        name: &str,
        image: &str,
        setting: &str,
    ) -> bool {
        let Some(args) = switched_off_args(app_args, app, name, image, setting) else {
            return false;
        };
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        matches!(self.docker(&args), Ok((0, _)))
    }

    fn start_model(&self, network: &str, name: &str) -> bool {
        let host = format!("HOST={name}");
        let port = format!("PORT={MODEL_PORT}");
        matches!(
            self.docker(&model_args(network, name, [&host, &port])),
            Ok((0, _))
        )
    }

    /// Whether the test model answers yet, for the same reason as the provider below.
    fn model_ready(&self, via: &Via, host: &str) -> bool {
        let health = sv_check::probes::ProbeRequest {
            id: "model-health".to_owned(),
            method: "GET".to_owned(),
            path: "/_sv/health".to_owned(),
            headers: Vec::new(),
            body: None,
        };
        (0..20).any(|_| {
            let up = self
                .probe(via, host, MODEL_PORT, &health)
                .is_some_and(|r| r.status == 200);
            if !up {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            up
        })
    }

    /// Whether the provider answers yet: Node takes a moment, and a check that starts before it
    /// is up would report the app's sign-in as broken when the provider was.
    fn provider_ready(&self, via: &Via, host: &str) -> bool {
        let health = sv_check::probes::ProbeRequest {
            id: "provider-health".to_owned(),
            method: "GET".to_owned(),
            path: "/_sv/health".to_owned(),
            headers: Vec::new(),
            body: None,
        };
        for _ in 0..20 {
            if self
                .probe(via, host, PROVIDER_PORT, &health)
                .is_some_and(|r| r.status == 200)
            {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        false
    }

    /// Runs a command where requests to the app are made from: in the sidecar, or in a throw-away
    /// container on the same internal network when there is no sidecar.
    fn inside_fence(&self, via: &Via, command: &[&str]) -> Result<(i32, String), String> {
        self.inside_fence_with_input(via, command, &[])
    }

    /// `inside_fence`, with `input` given to the command as what it reads. How a request reaches
    /// the container: an argument cannot carry one, since Linux refuses any single argument over
    /// 128 KiB, which an upload passes easily.
    fn inside_fence_with_input(
        &self,
        via: &Via,
        command: &[&str],
        input: &[u8],
    ) -> Result<(i32, String), String> {
        let mut args = self.fence_args(via);
        args.extend_from_slice(command);
        let mut c = Command::new(&self.binary);
        c.args(crate::cleanup::labeled(&args, &self.owner));
        crate::output_with_input(&mut c, input)
    }

    /// How a container that talks to the app is started, either way. Separate so the two paths can
    /// be compared without starting anything.
    fn fence_args<'a>(&self, via: &Via<'a>) -> Vec<&'a str> {
        match via {
            Via::Sidecar(name) => vec!["exec", "-i", name],
            // The same hardening as the sidecar. It had none of it: the flags were added where the
            // fast path was written and not where the fallback already lived, so a run that could
            // not start a sidecar quietly made every request from a container with its capabilities
            // and a writable file system — while the comment said the fallback was only slower.
            Via::FreshContainer(network) => vec![
                "run",
                "-i",
                "--rm",
                "--network",
                network,
                "--read-only",
                "--tmpfs",
                PROBE_TMPFS,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                PROBE_IMAGE,
            ],
        }
    }

    /// Whether the app is still running and answering, after `after`.
    ///
    /// Read from `docker inspect` and one request to the health path, tried three times two seconds
    /// apart so a moment of slowness is not taken for a stopped app.
    fn liveness(
        &self,
        via: &Via,
        app: &str,
        plan: &RunPlan,
        after: &str,
    ) -> sv_check::running::Liveness {
        let state = self
            .docker(&[
                "inspect",
                "-f",
                "{{.State.Status}} {{.RestartCount}} {{.State.ExitCode}} {{.State.OOMKilled}}",
                app,
            ])
            .ok()
            .filter(|(code, _)| *code == 0)
            .map(|(_, out)| out)
            .unwrap_or_default();
        let words: Vec<&str> = state.split_whitespace().collect();
        let (status, restarts, exit_code, out_of_memory) = match words.as_slice() {
            [status, restarts, exit_code, oom] => (
                (*status).to_owned(),
                restarts.parse().unwrap_or(0),
                exit_code.parse().unwrap_or(0),
                *oom == "true",
            ),
            _ => (String::new(), 0, 0, false),
        };
        let url = format!("http://{app}:{}{}", plan.port, plan.health_path);
        let answered = status == "running"
            && (0..3).any(|attempt| {
                if attempt > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
                matches!(
                    self.inside_fence(via, &["wget", "-q", "-T", "5", "-O", "/dev/null", &url]),
                    Ok((0, _))
                )
            });
        sv_check::running::Liveness {
            after: after.to_owned(),
            status,
            restarts,
            exit_code,
            out_of_memory,
            answered,
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

/// How long the sidecar may live: the usual limit, and with `--slow` long enough to wait out the
/// timeouts the owner states and the ten minutes an emailed sign-in code is kept.
fn sidecar_seconds(plan: &RunPlan) -> u64 {
    // The AI feature's rate check waits a minute before its burst, whether or not the run is slow.
    let rate = if plan.ai.is_some() && plan.policy.ai_requests_per_minute.is_some() {
        120
    } else {
        0
    };
    if !plan.slow {
        return SIDECAR_SECONDS + rate;
    }
    let minutes = plan.policy.idle_timeout_minutes.unwrap_or(0)
        + plan.policy.session_lifetime_minutes.unwrap_or(0);
    // An emailed sign-in code is kept ten minutes before it is used.
    let code_minutes = if plan.users.as_ref().is_some_and(|u| u.email_code.is_some()) {
        12
    } else {
        0
    };
    SIDECAR_SECONDS + u64::from(minutes.min(180) + code_minutes) * 60 + 120 + rate
}

/// Where requests to the app are sent from.
enum Via<'a> {
    /// The run's sidecar, by name: each request is an `exec` into it.
    Sidecar(&'a str),
    /// A container started for the one request, on this network, when there is no sidecar.
    FreshContainer(&'a str),
}

/// A run's name: `sv-<process>-<run in this process>-<random>`. The process id alone repeats
/// between two copies of `sv` in two containers sharing one Docker daemon (each is often process 1
/// or 7 in its own container), and then each run's teardown removed the other's containers by
/// name (S10). The random part makes the names, and so the label, this run's alone.
fn run_id(process: u32, number: u64, random: &str) -> String {
    format!("sv-{process}-{number}-{random}")
}

/// Removes the containers and the network however the run ended, including on an early return.
///
/// It removes what carries this run's label, by id, and nothing else. Only if Docker will not list
/// them does it fall back to the run's own names, which hold its random part.
struct Teardown<'a> {
    backend: &'a DockerBackend,
    run: String,
    network: String,
    containers: Vec<String>,
}

impl Drop for Teardown<'_> {
    fn drop(&mut self) {
        let filter = format!("label={RUN_LABEL}={}", self.run);
        let listed = |args: &[&str]| match self.backend.docker_cleanup(args) {
            Ok((0, out)) => Some(out),
            _ => None,
        };
        let containers = listed(&["ps", "-aq", "--filter", &filter]);
        for container in to_remove(containers.as_deref(), &self.containers) {
            let _ = self.backend.docker_cleanup(&["rm", "-f", &container]);
        }
        let networks = listed(&["network", "ls", "-q", "--filter", &filter]);
        for network in to_remove(networks.as_deref(), std::slice::from_ref(&self.network)) {
            let _ = self.backend.docker_cleanup(&["network", "rm", &network]);
        }
        if let Ok(mut run) = self.backend.run.lock()
            && run.as_deref() == Some(self.run.as_str())
        {
            *run = None;
        }
    }
}

/// What a teardown removes: the ids Docker listed under this run's label, or, when it would not
/// list them, the names this run gave.
fn to_remove(listed: Option<&str>, names: &[String]) -> Vec<String> {
    match listed {
        Some(listed) => listed
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .collect(),
        None => names.to_vec(),
    }
}

/// How the test provider is started, and the secret Docker hands it from its own environment: the
/// client secret by name only on the command line, as the seed's passwords are.
fn provider_start(
    network: &str,
    name: &str,
    secret: &str,
) -> (Vec<String>, Vec<(&'static str, String)>) {
    let issuer = format!("ISSUER=http://{name}:{PROVIDER_PORT}");
    let port = format!("PORT={PROVIDER_PORT}");
    let client = format!("CLIENT_ID={PROVIDER_CLIENT_ID}");
    let args = provider_args(network, name, [&issuer, &port, &client, "CLIENT_SECRET"])
        .into_iter()
        .map(str::to_owned)
        .collect();
    (args, vec![("CLIENT_SECRET", secret.to_owned())])
}

/// `docker exec` for the owner's `seed`, naming each of `names` with `-e` and no value, so the values
/// come from Docker's own environment (`docker_with_secrets`) and never stand on its command line.
fn seed_args(app: &str, seed: &str, names: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = vec!["exec".into()];
    for name in names {
        args.push("-e".into());
        args.push((*name).to_owned());
    }
    args.extend([
        app.to_owned(),
        "sh".into(),
        "-c".into(),
        format!("cd /app && {seed}"),
    ]);
    args
}

/// What `seed` is given: the run's accounts, their passwords, and the two-factor secrets in base32.
fn seed_env(accounts: &sv_check::signed_in::Accounts) -> Vec<(&'static str, String)> {
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
    if let Some(secret) = &accounts.admin_totp_secret {
        env.push(("SV_ADMIN_TOTP_SECRET", sv_check::totp::base32(secret)));
    }
    env
}

/// What the report says when `seed` failed: its exit code and the first line it wrote, with every
/// password and two-factor secret the run gave it taken out. A seed that echoes its environment, or
/// a stack trace that prints the value it choked on, would otherwise carry them into the report.
fn seed_failed(code: i32, out: &str, accounts: &sv_check::signed_in::Accounts) -> String {
    let mut line = first_line(out);
    let mut secrets: Vec<String> = [&accounts.a, &accounts.b]
        .into_iter()
        .chain(accounts.admin.as_ref())
        .chain(accounts.totp.as_ref().map(|t| &t.account))
        .map(|account| account.password.clone())
        .collect();
    for secret in accounts
        .totp
        .as_ref()
        .map(|t| &t.secret)
        .into_iter()
        .chain(accounts.admin_totp_secret.as_ref())
    {
        let encoded = sv_check::totp::base32(secret);
        secrets.push(encoded.to_lowercase());
        secrets.push(encoded);
    }
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        line = line.replace(secret.as_str(), "[a test secret, left out]");
    }
    format!(
        "The seed command in securevibe.toml failed (exit {code}): {line}. With no accounts there \
         is nobody to sign in as."
    )
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no detail")
        .to_owned()
}

/// The lines of `docker logs --timestamps`, each `2026-10-06T05:12:04.123456789Z text`, in the
/// order of their times and without them. The times are all UTC, written the same way, so they
/// sort as text; lines with the same time keep the order they came in. A line with no time (a note
/// that output was cut) stays after the line before it.
fn interleaved(text: &str) -> String {
    let mut lines: Vec<(String, usize, &str)> = Vec::new();
    let mut last = String::new();
    for (n, line) in text.lines().enumerate() {
        match line.split_once(' ') {
            Some((time, rest)) if is_docker_time(time) => {
                last = time.to_owned();
                lines.push((last.clone(), n, rest));
            }
            _ => lines.push((last.clone(), n, line)),
        }
    }
    lines.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut out = lines
        .into_iter()
        .map(|(_, _, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// `2026-10-06T05:12:04.123456789Z`: the form Docker stamps a log line with.
fn is_docker_time(word: &str) -> bool {
    let b = word.as_bytes();
    b.len() >= 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && word.ends_with('Z')
        && b[..4].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slow_run_gives_the_sidecar_time_for_an_emailed_codes_ten_minutes() {
        let mut m = sv_manifest::Manifest::default();
        m.stack.run.image = Some("busybox:1.36".to_owned());
        m.stack.run.start = Some("httpd -f".to_owned());
        let mut plan = RunPlan::from_manifest(&m, std::path::Path::new("/tmp/app")).unwrap();
        plan.slow = true;
        let without = sidecar_seconds(&plan);
        plan.users = Some(sv_manifest::UsersSection {
            email_code: Some(sv_manifest::ResetSection {
                request: Default::default(),
                use_code: Default::default(),
                code_pattern: None,
            }),
            ..Default::default()
        });
        assert!(sidecar_seconds(&plan) >= without + 10 * 60);
        plan.slow = false;
        assert_eq!(sidecar_seconds(&plan), SIDECAR_SECONDS);
        // The AI feature's rate check waits a minute, slow or not.
        plan.ai = Some(sv_manifest::AiSection::default());
        plan.policy.ai_requests_per_minute = Some(10);
        assert!(sidecar_seconds(&plan) >= SIDECAR_SECONDS + 60);
    }

    #[test]
    fn availability_is_judged_by_the_daemon_not_the_binary() {
        // `docker --version` prints happily with no daemon behind it. A backend that cannot run
        // anything must not report itself as available, or every app on such a machine is reported
        // as failing rather than as unrun.
        let backend = DockerBackend {
            binary: "definitely-not-a-real-binary-xyz".to_owned(),
            owner: crate::cleanup::owner(),
            cpus: OnceLock::new(),
            run: std::sync::Mutex::new(None),
            clock_offset: OnceLock::new(),
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
    fn the_containers_clock_is_read_against_the_middle_of_the_reading() {
        // The deep review's improvement 5: a Docker machine 47 seconds behind this computer.
        assert_eq!(offset_from(1_000, 953, 1_002), -48);
        assert_eq!(offset_from(1_000, 1_090, 1_000), 90);
        // A second either way is the reading's own uncertainty, not a clock that differs.
        for theirs in [999, 1_000, 1_001] {
            assert_eq!(offset_from(1_000, theirs, 1_001), 0, "{theirs}");
        }
    }

    #[test]
    fn the_fence_explains_itself_without_overstating() {
        let text = Fence::DockerInternalNetwork.explain();
        assert!(text.contains("could not reach the internet"));
        assert!(Fence::None.explain().contains("No network fence"));
    }

    #[test]
    fn no_password_or_secret_stands_on_docker_s_command_line() {
        // The deep review's improvement 5: `-e SV_PASSWORD_A=...` was readable by any user of the
        // computer while `docker exec` ran. Only the names are on the command line now.
        let accounts = crate::new_accounts(true, true);
        let env = seed_env(&accounts);
        let names: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
        let args = seed_args("app", "./seed.sh", &names);
        for (name, value) in &env {
            assert!(args.iter().any(|a| a == name), "{name} is not named");
            // Compared, never printed: the message names the variable only.
            assert!(
                !args.iter().any(|a| a.contains(value.as_str())),
                "{name}'s value is on the command line"
            );
        }
        let secret = crate::random_hex(16);
        let (provider, secrets) = provider_start("net", "idp", &secret);
        assert!(
            !provider.iter().any(|a| a.contains(&secret)),
            "the provider's secret is on the command line"
        );
        let at = provider
            .iter()
            .position(|a| a == "CLIENT_SECRET")
            .expect("named");
        assert_eq!(provider[at - 1], "-e");
        assert_eq!(secrets, vec![("CLIENT_SECRET", secret)]);
    }

    #[test]
    fn seed_is_given_the_admins_secret_only_when_there_is_a_two_factor_step() {
        let accounts = crate::new_accounts(true, true);
        let env = seed_env(&accounts);
        let given = |name: &str| env.iter().find(|(k, _)| *k == name).map(|(_, v)| v.clone());
        // Compared, never printed: the assertion messages name the variable only.
        assert!(
            given("SV_ADMIN_TOTP_SECRET")
                == Some(sv_check::totp::base32(
                    accounts.admin_totp_secret.as_ref().unwrap()
                )),
            "SV_ADMIN_TOTP_SECRET is the admin's secret, in base32"
        );
        assert!(
            given("SV_ADMIN_TOTP_SECRET") != given("SV_TOTP_SECRET"),
            "the admin's secret is its own"
        );
        let without = seed_env(&crate::new_accounts(true, false));
        assert!(without.iter().all(|(k, _)| *k != "SV_ADMIN_TOTP_SECRET"));
    }

    #[test]
    fn a_failed_seed_never_carries_a_secret_into_the_report() {
        let accounts = crate::new_accounts(true, true);
        let admin_secret = sv_check::totp::base32(accounts.admin_totp_secret.as_ref().unwrap());
        let user_secret = sv_check::totp::base32(&accounts.totp.as_ref().unwrap().secret);
        let admin_password = accounts.admin.as_ref().unwrap().password.clone();
        // A seed that prints its environment as it fails, in both cases a secret may be printed in.
        let echoed = format!(
            "SV_ADMIN_TOTP_SECRET={admin_secret} SV_TOTP_SECRET={} SV_ADMIN_PASSWORD={admin_password}",
            user_secret.to_lowercase()
        );
        // The setup: the line really carries them, so their absence below is the redaction's doing.
        assert!(first_line(&echoed).contains(&admin_secret));
        let said = seed_failed(1, &echoed, &accounts);
        for secret in [
            &admin_secret,
            &user_secret,
            &user_secret.to_lowercase(),
            &admin_password,
        ] {
            assert!(
                !said.contains(secret.as_str()),
                "a secret reached the report"
            );
        }
        assert!(said.contains("SV_ADMIN_TOTP_SECRET=[a test secret, left out]"));
        assert!(said.contains("failed (exit 1)"));
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
/// The shell that sends one request and reads the whole answer, run in the sidecar.
///
/// Until 26 September 2026 this was `echo … | nc`, and it lost every answer a Node server was
/// still working on. When `echo` finishes, BusyBox's `nc` half-closes the connection, and Node's
/// HTTP server drops a connection whose client has stopped sending before the reply is written —
/// so a route that waited on anything (a database, a fetch, OpenID Connect discovery) came back
/// as "no answer", while a route that replied at once worked. Found by the first real sign-in
/// through the test provider: the app answered `/` and never `/login/google`. `nc -e` hands the
/// connected socket to a small script that writes the request and then reads until the server
/// closes, so the sending side stays open. `timeout` stands in for `nc -w`, which no longer
/// applies once the script has the socket, so a server that never closes cannot stall the run.
fn exchange_script(host: &str, port: u16) -> String {
    // The request arrives as what the container reads, is written to a file in its memory, and is
    // read from there by the script `nc -e` runs. It once went in as an argument, as base64, and
    // every request over about 96 KB failed: Linux refuses a single argument over 128 KiB, and the
    // failure read as the app not answering. `nc -e` closes every file but the socket before it
    // starts the script, so the file is how the request gets there.
    format!(
        "f=$(mktemp) && cat > \"$f\" && timeout 15 nc -w 5 {host} {port} -e sh -c \"cat $f; cat 1>&2\" 2>&1; rm -f \"$f\""
    )
}

/// What starts each copy's answer in the output of `at_once_script`, before a part made fresh for each
/// call (`at_once_mark`). Printed on a line of its own before each, so an answer that never came still
/// has its place.
const AT_ONCE_MARK: &str = "@@sv-at-once-";

/// The marker for one call of `at_once_script`: `AT_ONCE_MARK` and a random part. With the marker
/// fixed, an app could print `@@sv-at-once-2@@` and an answer of its own inside its first answer, and
/// that would be read as the second copy's: a race check fooled into a pass (the deep review's
/// improvement 5). The app cannot know a marker made after it started.
fn at_once_mark() -> String {
    format!("{AT_ONCE_MARK}{}-", crate::random_hex(8))
}

/// What `at_once_script` reads for `requests`: each different request once, one after another;
/// their sizes; and, for each copy in the order given, which of them it is, counting from 1. Two
/// users' copies of one action are two requests, and sending each once keeps the input small.
fn together_input(
    requests: &[sv_check::probes::ProbeRequest],
    host: &str,
) -> Option<(Vec<u8>, Vec<usize>, Vec<usize>)> {
    let mut distinct: Vec<Vec<u8>> = Vec::new();
    let mut which = Vec::with_capacity(requests.len());
    for request in requests {
        let raw = request_bytes(request, host)?;
        let k = match distinct.iter().position(|d| *d == raw) {
            Some(k) => k,
            None => {
                distinct.push(raw);
                distinct.len() - 1
            }
        };
        which.push(k + 1);
    }
    let sizes = distinct.iter().map(Vec::len).collect();
    Some((distinct.concat(), sizes, which))
}

/// `exchange_script`, for requests sent together. The input, the requests of `sizes` one after
/// another, is cut into a file each; then every connection is started in the background before any
/// is waited for, so they reach the app together rather than one after another, copy `i` sending
/// request `which[i]`. Each answer is kept in its own file and printed in order after all have
/// finished. The cutting reads a file, not the pipe, so no request takes bytes of the next.
fn at_once_script(host: &str, port: u16, sizes: &[usize], which: &[usize], mark: &str) -> String {
    let mut offset = 0;
    let mut cut = String::new();
    for (k, size) in sizes.iter().enumerate() {
        cut.push_str(&format!(
            "tail -c +{} \"$d/all\" | head -c {size} > \"$d/r{}\" && ",
            offset + 1,
            k + 1
        ));
        offset += size;
    }
    let pairs: Vec<String> = which
        .iter()
        .enumerate()
        .map(|(i, k)| format!("{}:{k}", i + 1))
        .collect();
    let pairs = pairs.join(" ");
    let numbers: Vec<String> = (1..=which.len()).map(|i| i.to_string()).collect();
    let numbers = numbers.join(" ");
    format!(
        "d=$(mktemp -d) && cat > \"$d/all\" && {cut}\
         for p in {pairs}; do i=${{p%:*}}; k=${{p#*:}}; timeout 15 nc -w 5 {host} {port} -e sh -c \"cat $d/r$k; cat 1>&2\" > \"$d/$i\" 2>&1 & done; \
         wait; for i in {numbers}; do printf '\\n{mark}%s@@\\n' \"$i\"; cat \"$d/$i\"; done; rm -rf \"$d\""
    )
}

/// The answers in the output of `at_once_script`, in order, each under its request's id: `None`
/// for a copy that got none.
fn parse_at_once(
    ids: &[&str],
    out: &str,
    mark: &str,
) -> Vec<Option<sv_check::probes::ProbeResponse>> {
    (1..=ids.len())
        .map(|i| {
            let id = ids[i - 1];
            let start = format!("\n{mark}{i}@@\n");
            let next = format!("\n{mark}{}@@\n", i + 1);
            let from = out.find(&start)? + start.len();
            let to = out[from..].find(&next).map_or(out.len(), |n| from + n);
            let raw = &out[from..to];
            if raw.trim().is_empty() {
                return None;
            }
            parse_response(id, raw)
        })
        .collect()
}

/// What the gateway check saw. See `verify_gateway_closed`.
#[derive(Debug, PartialEq, Eq)]
enum GatewayVerdict {
    Closed,
    Reachable,
    Unknown(String),
}

/// The addresses to knock on for a network: every IPv4 gateway Docker names, and the first address of
/// every IPv4 subnet, where a gateway would be. Read from `Gateway|Subnet` pairs, space-separated.
fn gateway_targets(config: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pair in config.split_whitespace() {
        let (gateway, subnet) = pair.split_once('|').unwrap_or((pair, ""));
        if let Ok(ip) = gateway.parse::<std::net::Ipv4Addr>() {
            out.push(ip.to_string());
        }
        if let Some((base, bits)) = subnet.split_once('/')
            && let (Ok(base), Ok(bits)) = (base.parse::<std::net::Ipv4Addr>(), bits.parse::<u32>())
            && bits < 31
        {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            out.push(std::net::Ipv4Addr::from((u32::from(base) & mask) + 1).to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Reads the knocks: the container's own loopback (the control, which must be refused) and then each
/// gateway address. A connection or a refusal from any of them is the host answering; a timeout, no
/// route, or an unreachable network from every one is the fence holding. Anything else is not taken
/// for either.
fn gateway_verdict(out: &str) -> GatewayVerdict {
    // Each knock's output, and its exit status, in order.
    let mut sections: Vec<(String, String, Option<i32>)> = Vec::new();
    let mut text = String::new();
    for line in out.lines() {
        if let Some((mark, code)) = line.split_once('=').filter(|(m, _)| m.starts_with("sv-")) {
            sections.push((
                mark.to_owned(),
                std::mem::take(&mut text),
                code.trim().parse().ok(),
            ));
        } else {
            text.push_str(line);
            text.push('\n');
        }
    }
    let Some((_, own, Some(own_code))) = sections.iter().find(|(m, _, _)| m == "sv-self").cloned()
    else {
        return GatewayVerdict::Unknown("the check did not run".to_owned());
    };
    if own_code == 0 || !own.to_lowercase().contains("refused") {
        return GatewayVerdict::Unknown(format!(
            "the control, a knock on the container's own loopback, did not read as refused: {}",
            own.trim()
        ));
    }
    let knocks: Vec<&(String, String, Option<i32>)> = sections
        .iter()
        .filter(|(m, _, _)| m == "sv-gateway")
        .collect();
    if knocks.is_empty() {
        // Every address was the knocking container's own: nothing of the host's is on the network.
        if sections.iter().any(|(m, _, _)| m == "sv-own") {
            return GatewayVerdict::Closed;
        }
        return GatewayVerdict::Unknown("the knock on the gateway did not report back".to_owned());
    }
    let mut unknown = None;
    for (_, said, code) in knocks {
        let lower = said.to_lowercase();
        if *code == Some(0) || lower.contains("refused") {
            return GatewayVerdict::Reachable;
        }
        let closed = code.is_some()
            && (lower.contains("timed out")
                || lower.contains("timeout")
                || lower.contains("no route")
                || lower.contains("unreachable"));
        if !closed && unknown.is_none() {
            unknown = Some(format!("nc said: {}", said.trim()));
        }
    }
    match unknown {
        Some(why) => GatewayVerdict::Unknown(why),
        None => GatewayVerdict::Closed,
    }
}

fn request_bytes(request: &sv_check::probes::ProbeRequest, host: &str) -> Option<Vec<u8>> {
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
    // A request may name its own `Host`, to ask what the app does with a name that is not its
    // own; it then replaces this one rather than being sent beside it, since two would be refused
    // for being two.
    let own_host = request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"));
    let mut raw = if own_host {
        format!(
            "{} {} HTTP/1.0\r\nConnection: close\r\n",
            request.method, request.path
        )
    } else {
        format!(
            "{} {} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n",
            request.method, request.path
        )
    };
    for (name, value) in &request.headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    // A body is framed by its length, so nothing in it can be read as a second request: the server
    // stops at the byte count, whatever the body contains.
    let mut raw = raw.into_bytes();
    if let Some(body) = &request.body {
        raw.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        raw.extend_from_slice(body);
    } else {
        raw.extend_from_slice(b"\r\n");
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
        let script = exchange_script(host, port);
        let (_, out) = self
            .inside_fence_with_input(via, &["sh", "-c", &script], &raw)
            .ok()?;
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
        body: kept_body(body),
    })
}

/// How much of a body is kept: enough to recognize a stack trace, not enough to copy a page out of
/// somebody's app.
const KEPT_CHARS: usize = 4000;
/// How much is kept on each side of the reflection probes' value, when it comes back further down.
const AROUND_ECHO: usize = 200;
/// How many times it is kept further down.
const MOST_ECHOES: usize = 5;

/// The start of a body, and, when the reflection probes' value comes back past it, the text around
/// each time it does. A page often repeats a search term well down, past its head and navigation,
/// and the value is one only `sv` sends, so nothing else's answer keeps more than it did.
///
/// The same for the signs of a stack trace (`sv_check::probes::TRACE_MARKERS`): the whole answer is
/// searched, and the text around the first of each that comes past the cut is kept. Until 5 October
/// 2026 only the start was read, so an error page whose trace began below a long page of markup was
/// credited as saying nothing it should not (H17 of the deep review).
fn kept_body(body: &str) -> String {
    let mut kept: String = body.chars().take(KEPT_CHARS).collect();
    let from = kept.len();
    let mark = sv_check::probes::REFLECTION_MARK;
    // Searched from a little before the cut, so a value that starts inside the kept part and runs
    // past it is kept whole.
    let mut search = from.saturating_sub(mark.len() + AROUND_ECHO);
    while !body.is_char_boundary(search) {
        search += 1;
    }
    let mut after = from;
    for (at, _) in body[search..].match_indices(mark).take(MOST_ECHOES) {
        let at = search + at;
        if at + mark.len() + AROUND_ECHO <= from {
            continue;
        }
        let mut start = if at < after {
            at
        } else {
            at.saturating_sub(AROUND_ECHO).max(after)
        };
        while !body.is_char_boundary(start) {
            start += 1;
        }
        let mut end = (at + mark.len() + AROUND_ECHO).min(body.len());
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        kept.push_str("\n[…]\n");
        kept.push_str(&body[start..end]);
        after = end;
    }
    for marker in sv_check::probes::TRACE_MARKERS {
        let Some(at) = body.find(marker) else {
            continue;
        };
        if at + marker.len() <= from {
            continue;
        }
        let mut start = at.saturating_sub(AROUND_ECHO);
        while !body.is_char_boundary(start) {
            start += 1;
        }
        let mut end = (at + marker.len() + AROUND_ECHO).min(body.len());
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        kept.push_str("\n[…]\n");
        kept.push_str(&body[start..end]);
    }
    kept
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
        let script = exchange_script(app, port);
        let (code, out) = self
            .inside_fence_with_input(via, &["sh", "-c", &script], &raw)
            .ok()?;
        if code != 0 && out.trim().is_empty() {
            return None;
        }
        parse_response(&request.id, &out)
    }

    /// `probe`, for requests sent together. `None` when one of them cannot be sent at all or the
    /// container that sends them did not run.
    fn probe_together(
        &self,
        via: &Via,
        app: &str,
        port: u16,
        requests: &[sv_check::probes::ProbeRequest],
    ) -> Option<Vec<Option<sv_check::probes::ProbeResponse>>> {
        let (input, sizes, which) = together_input(requests, app)?;
        let mark = at_once_mark();
        let script = at_once_script(app, port, &sizes, &which, &mark);
        let (_, out) = self
            .inside_fence_with_input(via, &["sh", "-c", &script], &input)
            .ok()?;
        if !out.contains(&mark) {
            return None;
        }
        let ids: Vec<&str> = requests.iter().map(|r| r.id.as_str()).collect();
        Some(parse_at_once(&ids, &out, &mark))
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[test]
    fn a_stack_trace_below_the_cut_is_kept_and_found() {
        // H17: an error page whose trace starts below a long page of markup. Every marker is tried,
        // each past the cut, and each must survive the keeping and be found by the check itself.
        let missing = |body: String| sv_check::probes::ProbeResponse {
            id: "missing".to_owned(),
            status: 500,
            headers: Vec::new(),
            body,
        };
        for marker in sv_check::probes::TRACE_MARKERS {
            let body = format!(
                "{}<pre>{marker} detail</pre>{}",
                "<div>layout</div>".repeat(600),
                "b".repeat(2_000)
            );
            assert!(
                body.find(marker).unwrap() > KEPT_CHARS,
                "the setup: {marker:?} is past the cut"
            );
            let kept = kept_body(&body);
            assert!(kept.contains(marker), "{marker:?} was cut away");
            let found = sv_check::probes::evaluate(&[missing(kept.clone())]);
            assert!(
                found.iter().any(|f| f.rule_id == "probe.error-detail-leak"),
                "{marker:?}: {found:?}"
            );
            assert!(
                !sv_check::probes::verified(&[missing(kept)])
                    .iter()
                    .any(|v| v.check_id == "probe.error-detail-leak"),
                "{marker:?} was credited as saying nothing"
            );
        }
        // The control: the same long page with no trace keeps its start only and is credited.
        let plain = "<div>layout</div>".repeat(800);
        let kept = kept_body(&plain);
        assert_eq!(kept.chars().count(), KEPT_CHARS);
        assert!(
            sv_check::probes::verified(&[missing(kept)])
                .iter()
                .any(|v| v.check_id == "probe.error-detail-leak")
        );
    }

    #[test]
    fn a_body_is_kept_to_its_start_and_the_value_when_it_comes_back_further_down() {
        let mark = sv_check::probes::REFLECTION_MARK;
        let short = "<p>hello</p>";
        assert_eq!(kept_body(short), short);
        // A long page with nothing of the probes' in it: its start, and nothing more.
        let long = "a".repeat(10_000);
        assert_eq!(kept_body(&long), "a".repeat(KEPT_CHARS));
        // The value far down the page comes back with the text around it, and only that.
        let far = format!(
            "{}<p>You searched for {mark}<\"'end</p>{}",
            "a".repeat(9_000),
            "b".repeat(9_000)
        );
        let kept = kept_body(&far);
        assert!(kept.starts_with(&"a".repeat(KEPT_CHARS)));
        assert!(
            kept.contains(&format!("{mark}<\"'end")),
            "the value and what follows it"
        );
        assert!(
            kept.chars().count() < KEPT_CHARS + 2 * AROUND_ECHO + mark.len() + 10,
            "{}",
            kept.len()
        );
        // Asked once and repeated six times: five places kept.
        let many = format!(
            "{}{}",
            "a".repeat(5_000),
            format!("{mark}<x {}", "c".repeat(500)).repeat(6)
        );
        assert_eq!(kept_body(&many).matches(mark).count(), MOST_ECHOES);
    }

    #[test]
    fn an_echo_far_down_a_real_answer_reaches_the_judgment() {
        // From the bytes the app sends to the finding: an error page that repeats the path it was
        // asked for, after 6,000 characters of its own, the value cut short at the `<`.
        let mark = sv_check::probes::REFLECTION_MARK;
        let raw = format!(
            "HTTP/1.0 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html>{}<p>No page at /x-{mark}<\"'</p></html>",
            "<p>filler</p>".repeat(460)
        );
        let answer = parse_response("reflect-missing", &raw).expect("an answer");
        assert!(
            raw.find(mark).unwrap() > KEPT_CHARS,
            "the setup: past the cut"
        );
        let findings = sv_check::probes::evaluate(&[answer]);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "probe.reflected-unencoded"),
            "{:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_value_across_the_cut_is_kept_whole_and_no_character_is_split() {
        let mark = sv_check::probes::REFLECTION_MARK;
        // Starts ten characters before the cut, ends after it.
        let body = format!(
            "{}{mark}<\"'tail{}",
            "a".repeat(KEPT_CHARS - 10),
            "z".repeat(1_000)
        );
        assert!(kept_body(&body).contains(&format!("{mark}<\"'tail")));
        // Two- and three-byte characters on every side of every boundary.
        let body = format!("{}{mark}<{}", "é".repeat(KEPT_CHARS + 77), "日".repeat(300));
        let kept = kept_body(&body);
        assert!(kept.contains(&format!("{mark}<")));
        let body = format!("{}{mark}{}", "日".repeat(KEPT_CHARS - 3), "é".repeat(300));
        assert!(kept_body(&body).contains(mark));
    }

    /// The flags a container making requests to the app must carry, whichever path started it.
    const HARDENING: [&str; 4] = ["--read-only", "--cap-drop", "ALL", "no-new-privileges"];

    #[test]
    fn a_crash_at_start_is_quoted_by_its_error_line() {
        // The loop's item 6, 6 October 2026: three Haiku apps crashed, and each was quoted as
        // "Traceback (most recent call last):", the first line, where Python says what went wrong
        // on its last.
        for (logs, line) in [
            (
                "Traceback (most recent call last):\n  File \"/app/app.py\", line 3, in <module>\n    port = os.environ['PORT_NUMBER']\n  File \"<frozen os>\", line 714, in __getitem__\nKeyError: 'PORT_NUMBER'\n",
                "KeyError: 'PORT_NUMBER'",
            ),
            (
                "node:internal/modules/cjs/loader:1148\n  throw err;\n  ^\n\nError: Cannot find module 'express'\nRequire stack:\n- /app/server.js\n    at Module._resolveFilename (node:internal/modules/cjs/loader:1145:15)\n\nNode.js v20.11.0\n",
                "Error: Cannot find module 'express'",
            ),
            (
                "starting\npanic: listen tcp :abc: invalid port\n\ngoroutine 1 [running]:\nmain.main()\n",
                "panic: listen tcp :abc: invalid port",
            ),
            (
                "/app/app.rb:3:in `<main>': undefined local variable or method `sinatra' for main:Object (NameError)\n",
                "/app/app.rb:3:in `<main>': undefined local variable or method `sinatra' for main:Object (NameError)",
            ),
            (
                "sqlite3.OperationalError: unable to open database file\n",
                "sqlite3.OperationalError: unable to open database file",
            ),
        ] {
            let (detail, crashed) = never_ready_detail(logs, None);
            assert!(crashed, "{logs}");
            assert_eq!(detail, format!("It stopped with an error: {line}"));
        }
        // An error's name is capitalized: a handler or a variable that happens to end in one is not.
        for logs in [
            "listening on 8080\nserver.onExit: handler registered\n",
            "listening on 8080\nwaiting for a signal (onExit)\n",
        ] {
            let (detail, crashed) = never_ready_detail(logs, None);
            assert!(!crashed, "{detail}");
        }
        // The control: an app still running, or waiting, is quoted by its last line, and is not
        // said to have crashed.
        let (detail, crashed) = never_ready_detail(
            " * Serving Flask app 'app'\n * Debug mode: off\nWARNING: This is a development server.\n * Running on http://127.0.0.1:5000\n",
            None,
        );
        assert!(!crashed);
        assert_eq!(
            detail,
            "Its last output was: * Running on http://127.0.0.1:5000"
        );
    }

    #[test]
    fn an_app_with_a_build_step_is_told_why_the_step_cannot_install_here() {
        let pip = "Defaulting to user installation because normal site-packages is not writeable";
        let (with, _) = never_ready_detail(pip, Some("pip install -r requirements.txt"));
        assert!(
            with.starts_with(&format!("Its last output was: {pip}")),
            "{with}"
        );
        assert!(with.contains("`pip install -r requirements.txt`"), "{with}");
        assert!(
            with.contains("install them into the image instead"),
            "{with}"
        );
        // No build step, no sentence about one.
        let (without, _) = never_ready_detail("Listening on 8080", None);
        assert_eq!(without, "Its last output was: Listening on 8080");
    }

    #[test]
    fn the_app_is_hardened_like_every_helper() {
        let args = app_args("sv-1-app", "sv-1-net", "/apps/notes:/app:ro", "PORT=8080");
        for flag in HARDENING {
            assert!(args.contains(&flag), "{flag} missing: {args:?}");
        }
        let at = args.iter().position(|a| *a == "--network").unwrap();
        assert_eq!(args[at + 1], "sv-1-net");
        assert!(
            !args
                .iter()
                .any(|a| *a == "-p" || a.starts_with("--publish")),
            "nothing published: {args:?}"
        );
        assert!(
            args.contains(&"/apps/notes:/app:ro"),
            "the app's folder stays read-only: {args:?}"
        );
        // Its only writable places are in memory, and each has a size, so neither can be used to
        // fill the machine's memory.
        let tmpfs: Vec<&str> = args
            .windows(2)
            .filter(|w| w[0] == "--tmpfs")
            .map(|w| w[1])
            .collect();
        assert_eq!(tmpfs.len(), 2, "{tmpfs:?}");
        for mount in &tmpfs {
            assert!(mount.contains("size="), "{mount} has no size");
        }
        assert!(tmpfs.iter().any(|m| m.starts_with("/tmp:")), "{tmpfs:?}");
        assert!(
            tmpfs
                .iter()
                .any(|m| m.split(':').next() == Some(crate::REPORT_DIR)),
            "the report folder is where test runners are told to write: {tmpfs:?}"
        );
    }

    #[test]
    fn every_container_is_started_with_limits_and_nothing_else_is_changed() {
        let backend = DockerBackend::new();
        backend.cpus.set(Some("2".to_owned())).unwrap();
        let value = |args: &[String], flag: &str| {
            let at = args.iter().position(|a| a == flag)?;
            args.get(at + 1).cloned()
        };
        // Every way a container is started here: the app, each helper, and the plain `run`s.
        let mut started: Vec<Vec<&str>> = vec![
            app_args("sv-1-app", "sv-1-net", "/apps/notes:/app:ro", "PORT=8080"),
            browser_args("net", "b"),
            mail_args("net", "m"),
            driver_args("net", "JOB=1"),
            provider_args("net", "p", ["A=1", "B=2", "C=3", "D=4"]),
            model_args("net", "m", ["A=1", "B=2"]),
            backend.fence_args(&Via::FreshContainer("net")),
            vec!["create", "busybox"],
        ];
        started[0].extend(["busybox", "sh"]);
        for args in &started {
            let sent = backend.prepared(args);
            assert_eq!(sent[0], args[0], "{sent:?}");
            assert_eq!(
                value(&sent, "--memory").as_deref(),
                Some(MEMORY_LIMIT),
                "{sent:?}"
            );
            assert_eq!(
                value(&sent, "--memory-swap").as_deref(),
                Some(MEMORY_LIMIT),
                "{sent:?}"
            );
            assert_eq!(
                value(&sent, "--pids-limit").as_deref(),
                Some(PROCESS_LIMIT),
                "{sent:?}"
            );
            assert_eq!(value(&sent, "--cpus").as_deref(), Some("2"), "{sent:?}");
            // Still labeled, and everything that was asked for is still there, in order.
            assert!(
                sent.iter()
                    .any(|a| a.starts_with(crate::cleanup::OWNER_LABEL))
            );
            let asked: Vec<&String> = sent.iter().filter(|a| args.contains(&a.as_str())).collect();
            assert_eq!(asked.len(), args.len(), "{sent:?}");
            // Every in-memory folder has a size.
            for w in sent.windows(2).filter(|w| w[0] == "--tmpfs") {
                assert!(w[1].contains("size="), "{} has no size", w[1]);
            }
        }
        // A call that starts nothing is sent as it was, labels aside.
        for args in [
            vec!["exec", "-i", "sidecar", "wget", "-q"],
            vec!["rm", "-f", "app"],
            vec!["logs", "--tail", "20", "app"],
            vec!["network", "create", "--internal", "n"],
        ] {
            let sent = backend.prepared(&args);
            assert!(
                !sent.iter().any(|a| a == "--memory" || a == "--pids-limit"),
                "{sent:?}"
            );
        }
        // With no processor count from Docker, the other limits still hold.
        let sent = limited(vec!["run".to_owned(), "img".to_owned()], None);
        assert_eq!(
            sent,
            [
                "run",
                "--memory",
                MEMORY_LIMIT,
                "--memory-swap",
                MEMORY_LIMIT,
                "--pids-limit",
                PROCESS_LIMIT,
                "img"
            ]
        );
    }

    #[test]
    fn two_runs_never_share_a_name() {
        // Two copies of `sv`, each process 7 in its own container, on one Docker daemon: the
        // names differ by their random part, so neither run's teardown can name the other's.
        let a = run_id(7, 0, &crate::random_hex(4));
        let b = run_id(7, 0, &crate::random_hex(4));
        assert!(
            a.starts_with("sv-7-0-") && b.starts_with("sv-7-0-"),
            "{a} {b}"
        );
        assert_ne!(a, b);
        assert_eq!(a.len(), "sv-7-0-".len() + 8, "{a}");
    }

    #[test]
    fn everything_a_run_creates_carries_its_label_and_nothing_else_does() {
        let a = run_id(7, 0, "0badc0de");
        // While a run is under way, everything that creates a container or a network carries its
        // label; nothing else is changed, and with no run under way nothing carries one.
        let backend = DockerBackend::new();
        backend.cpus.set(None).unwrap();
        let label = |args: &[&str]| -> Option<String> {
            let sent = backend.prepared(args);
            sent.windows(2)
                .find(|w| w[0] == "--label" && w[1].starts_with(RUN_LABEL))
                .map(|w| w[1].clone())
        };
        assert_eq!(label(&["run", "-d", "busybox"]), None, "no run under way");
        *backend.run.lock().unwrap() = Some(a.clone());
        let mine = format!("{RUN_LABEL}={a}");
        for args in [
            &["run", "-d", "--name", "x", "busybox"][..],
            &["create", "busybox"][..],
            &["network", "create", "--internal", "n"][..],
        ] {
            assert_eq!(label(args).as_deref(), Some(mine.as_str()), "{args:?}");
        }
        for args in [
            &["exec", "-i", "x", "sh"][..],
            &["rm", "-f", "x"][..],
            &["logs", "x"][..],
        ] {
            assert_eq!(label(args), None, "{args:?}");
        }
        let sent = backend.prepared(&["network", "create", "--internal", "n"]);
        assert_eq!(sent.last().map(String::as_str), Some("n"), "{sent:?}");
    }

    #[test]
    fn a_teardown_removes_what_docker_lists_under_its_label() {
        let a = run_id(7, 0, "0badc0de");
        // The teardown removes the ids Docker listed under the label, and only when it would not
        // list them falls back to the run's own names.
        let names = vec![format!("{a}-app"), format!("{a}-probe")];
        assert_eq!(
            to_remove(Some("abc123\n\ndef456\n"), &names),
            ["abc123", "def456"]
        );
        assert!(
            to_remove(Some(""), &names).is_empty(),
            "nothing of this run's is left"
        );
        assert_eq!(to_remove(None, &names), names);
    }

    #[test]
    fn the_processor_limit_never_asks_for_more_than_docker_has() {
        assert_eq!(cpus_for("8\n").as_deref(), Some("2"));
        assert_eq!(cpus_for("2").as_deref(), Some("2"));
        assert_eq!(cpus_for("1").as_deref(), Some("1"));
        assert_eq!(cpus_for("0"), None);
        assert_eq!(cpus_for(""), None);
        assert_eq!(cpus_for("Cannot connect to the Docker daemon"), None);
    }

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
    fn the_test_provider_is_fenced_and_hardened_like_the_sidecar() {
        let args = provider_args("sv-1-net", "sv-1-idp", ["A=1", "B=2", "C=3", "D=4"]);
        for flag in HARDENING {
            assert!(args.contains(&flag), "{flag} missing: {args:?}");
        }
        let at = args.iter().position(|a| *a == "--network").unwrap();
        assert_eq!(args[at + 1], "sv-1-net");
        assert!(
            !args
                .iter()
                .any(|a| *a == "-p" || a.starts_with("--publish")),
            "nothing published: {args:?}"
        );
        assert_eq!(
            args.last(),
            Some(&PROVIDER_SCRIPT),
            "the script is passed in, not read from the owner's disk"
        );
    }

    #[test]
    fn the_switched_off_copy_differs_from_the_app_only_in_name_and_the_setting() {
        let first: Vec<String> = [
            "run",
            "-d",
            "--name",
            "sv-1-app",
            "--network",
            "sv-1-net",
            "-e",
            "PORT=8080",
            "python:3.12-slim",
            "sh",
            "-c",
            "cd /app && python app.py",
        ]
        .map(str::to_owned)
        .to_vec();
        let copy = switched_off_args(
            &first,
            "sv-1-app",
            "sv-1-app-off",
            "python:3.12-slim",
            "AI_DISABLED=1",
        )
        .unwrap();
        assert_eq!(
            copy,
            [
                "run",
                "-d",
                "--name",
                "sv-1-app-off",
                "--network",
                "sv-1-net",
                "-e",
                "PORT=8080",
                "-e",
                "AI_DISABLED=1",
                "python:3.12-slim",
                "sh",
                "-c",
                "cd /app && python app.py",
            ]
            .map(str::to_owned)
            .to_vec()
        );
        assert!(switched_off_args(&first, "sv-1-app", "x", "other-image", "A=1").is_none());
    }

    #[test]
    fn the_test_model_is_fenced_and_hardened_like_the_sidecar() {
        let args = model_args("sv-1-net", "sv-1-model", ["HOST=sv-1-model", "PORT=9100"]);
        for flag in HARDENING {
            assert!(args.contains(&flag), "{flag} missing: {args:?}");
        }
        let at = args.iter().position(|a| *a == "--network").unwrap();
        assert_eq!(args[at + 1], "sv-1-net");
        assert!(
            !args
                .iter()
                .any(|a| *a == "-p" || a.starts_with("--publish")),
            "nothing published: {args:?}"
        );
        assert_eq!(args.last(), Some(&MODEL_SCRIPT));
    }

    #[test]
    fn the_app_is_given_the_test_model_and_no_key_that_works_anywhere_else() {
        let env = model_env(
            "sv-1-model",
            &["LLM_BASE_URL".to_owned()],
            Some("MCP_SERVER_URL"),
        );
        for expected in [
            "OPENAI_BASE_URL=http://sv-1-model:9100/v1",
            "ANTHROPIC_BASE_URL=http://sv-1-model:9100",
            "LLM_BASE_URL=http://sv-1-model:9100/v1",
            "MCP_SERVER_URL=http://sv-1-model:9100/mcp",
        ] {
            assert!(env.iter().any(|e| e == expected), "{expected}: {env:?}");
        }
        for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
            assert!(
                env.iter().any(|e| *e == format!("{key}={MODEL_KEY}")),
                "{key}: {env:?}"
            );
        }
    }

    #[test]
    fn an_answer_a_node_server_takes_a_moment_over_still_arrives() {
        // The transport lost every answer a Node server was still working on: `echo | nc`
        // half-closed the connection and Node dropped it. This runs a server that waits 200ms
        // before replying and asks it through the same path the probes use. Where there is no
        // container backend it says so and stops, like the other tests that need one; where there
        // is one, a setup that fails is a failure, not a skip.
        let backend = DockerBackend::new();
        if backend.available().is_err() {
            println!("no container backend here; this needs one");
            return;
        }
        let network = format!("sv-slowtest-{}", std::process::id());
        let server = format!("{network}-app");
        let _ = backend.docker(&["network", "create", "--internal", &network]);
        let started = backend.docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &server,
            "--network",
            &network,
            PROVIDER_IMAGE,
            "node",
            "-e",
            "require('http').createServer(async (q, s) => { await new Promise(r => setTimeout(r, 200)); s.end('late but here') }).listen(8080)",
        ]);
        let answer = matches!(started, Ok((0, _))).then(|| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let request = sv_check::probes::ProbeRequest {
                id: "slow".to_owned(),
                method: "GET".to_owned(),
                path: "/".to_owned(),
                headers: Vec::new(),
                body: None,
            };
            backend.probe(&Via::FreshContainer(&network), &server, 8080, &request)
        });
        let _ = backend.docker(&["rm", "-f", &server]);
        let _ = backend.docker(&["network", "rm", &network]);
        let answer = answer.unwrap_or_else(|| panic!("the test server did not start: {started:?}"));
        let answer =
            answer.expect("no answer: the reply was dropped while the server worked on it");
        assert_eq!(answer.status, 200);
        assert!(answer.body.contains("late but here"), "{}", answer.body);
    }

    #[test]
    fn the_browser_and_its_driver_are_fenced_and_hardened_like_the_sidecar() {
        let browser = browser_args("sv-1-net", "sv-1-browser");
        let driver = driver_args("container:sv-1-browser", "SV_JOB=e30=");
        for args in [&browser, &driver] {
            for flag in HARDENING {
                assert!(args.contains(&flag), "{flag} missing: {args:?}");
            }
            assert!(
                !args
                    .iter()
                    .any(|a| *a == "-p" || a.starts_with("--publish") || *a == "-v"),
                "nothing published or mounted: {args:?}"
            );
        }
        let at = browser.iter().position(|a| *a == "--network").unwrap();
        assert_eq!(browser[at + 1], "sv-1-net");
        // DevTools on 127.0.0.1 alone, and Chromium started directly, not by the image's script,
        // which forwards it on every address (deep review S11).
        let at = browser.iter().position(|a| *a == "--entrypoint").unwrap();
        assert_eq!(browser[at + 1], "/headless-shell/headless-shell");
        assert_eq!(browser[at + 2], BROWSER_IMAGE);
        let after: Vec<&str> = browser[at + 3..].to_vec();
        assert!(
            after.contains(&"--remote-debugging-address=127.0.0.1"),
            "{after:?}"
        );
        assert!(after.contains(&"--remote-debugging-port=9223"), "{after:?}");
        assert!(!after.iter().any(|a| a.contains("0.0.0.0")), "{after:?}");
        // Every expression the driver runs goes through the world of its own, never the page's.
        let evaluations: Vec<&str> = DRIVER_SCRIPT
            .lines()
            .filter(|l| l.contains("Runtime.evaluate"))
            .collect();
        assert_eq!(evaluations.len(), 1, "{evaluations:?}");
        assert!(evaluations[0].contains("contextId"), "{evaluations:?}");
        // The driver has no network of its own: only the browser's, which is the fenced one.
        let at = driver.iter().position(|a| *a == "--network").unwrap();
        assert_eq!(driver[at + 1], "container:sv-1-browser");
        assert_eq!(driver.last(), Some(&DRIVER_SCRIPT));
        // One version of Chromium, named, so two runs draw pages the same way.
        let tag = BROWSER_IMAGE.rsplit(':').next().unwrap();
        assert!(
            tag.split('.').count() == 4 && tag.split('.').all(|p| p.parse::<u32>().is_ok()),
            "{BROWSER_IMAGE}"
        );
    }

    #[test]
    fn the_browser_signs_in_with_the_cookies_it_is_given_and_runs_the_page() {
        // The driver, the forwarder, and the browser together, against a small app on a fenced
        // network: the cookie opens a private page, the page's own script runs, and a form typed
        // into is posted and shown. Needs a container backend; with one, a failed setup fails.
        let backend = DockerBackend::new();
        if backend.available().is_err() {
            println!("no container backend here; this needs one");
            return;
        }
        let network = format!("sv-browsertest-{}", std::process::id());
        let server = format!("{network}-app");
        let browser = format!("{network}-browser");
        let _ = backend.docker(&["network", "create", "--internal", &network]);
        let app = r#"
const http = require('http');
http.createServer((q, s) => {
  s.setHeader('content-type', 'text/html');
  const signed = (q.headers.cookie || '').includes('sid=abc');
  if (q.url === '/private' && !signed) { s.writeHead(302, { location: '/login' }); return s.end(); }
  if (q.url === '/private') return s.end('<title>x</title><p>mine</p><a id=bye href=/bye>bye</a><script>document.title = "ran"</script>');
  if (q.url === '/form') return s.end('<form method=post action=/echo><textarea name=t></textarea><button>Go</button></form>');
  if (q.url === '/echo') {
    let b = ''; q.on('data', (c) => (b += c));
    return q.on('end', () => s.end('<p>' + new URLSearchParams(b).get('t').replace(/</g, '&lt;') + '</p>'));
  }
  if (q.url === '/rawform') return s.end('<form method=post action=/raw><textarea name=t></textarea><button>Go</button></form>');
  if (q.url === '/raw') {
    let b = ''; q.on('data', (c) => (b += c));
    return q.on('end', () => s.end('<p>' + new URLSearchParams(b).get('t') + '</p>'));
  }
  s.end('<p>login</p>');
}).listen(8080);"#;
        let started = backend.docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &server,
            "--network",
            &network,
            PROVIDER_IMAGE,
            "node",
            "-e",
            app,
        ]);
        let ready = matches!(started, Ok((0, _))) && backend.start_browser(&network, &browser) && {
            std::thread::sleep(std::time::Duration::from_secs(3));
            backend.forward_browser(&browser, &server, 8080)
        };
        let answers = ready.then(|| {
            let via = Via::FreshContainer(&network);
            let mut http = DockerHttp {
                backend: &backend,
                via: &via,
                app: &server,
                port: 8080,
                mail: None,
                provider: None,
                browser: Some(&browser),
                model: None,
            };
            use sv_check::browser::{Action, BrowserCookie, Job};
            use sv_check::signed_in::Http;
            http.browser(&Job {
                actions: vec![
                    Action::SetCookies(vec![BrowserCookie::plain("sid", "abc")]),
                    Action::Goto("/private".into()),
                    Action::Eval("document.title".into()),
                    Action::Fill {
                        page: "/form".into(),
                        text: "hi <b>".into(),
                    },
                    Action::Eval("document.body.innerText".into()),
                    Action::SetCookies(vec![BrowserCookie::plain("later", "1")]),
                    Action::Goto("/private".into()),
                    Action::Eval("document.cookie".into()),
                    Action::Act("document.getElementById('bye').click(); true".into()),
                    // The cross-site scripting check's own line and question, on a page that puts
                    // the text in as markup: the script runs, and the driver's own world must see it
                    // (the review of 6 October, item 10).
                    Action::Fill {
                        page: "/rawform".into(),
                        text: sv_check::browser::markup_line("feedc0de"),
                    },
                    Action::Eval(sv_check::browser::markup_question("feedc0de")),
                ],
            })
        });
        let _ = backend.docker(&["rm", "-f", &server, &browser]);
        let _ = backend.docker(&["network", "rm", &network]);
        assert!(
            ready,
            "the app, the browser, or the forwarder did not start: {started:?}"
        );
        let mut answers = answers.flatten().expect("the driver gave no answer");
        assert_eq!(answers.len(), 11, "{answers:?}");
        assert_eq!(answers.remove(0), serde_json::json!({ "refused": [] }));
        assert_eq!(answers[0]["status"], 200, "{answers:?}");
        assert_eq!(answers[0]["path"], "/private", "{answers:?}");
        assert_eq!(answers[1]["value"], "ran", "{answers:?}");
        assert_eq!(answers[2]["found"], true, "{answers:?}");
        assert_eq!(answers[2]["after"]["path"], "/echo", "{answers:?}");
        assert_eq!(answers[3]["value"], "hi <b>", "{answers:?}");
        // A cookie set partway through is sent from then on, and a click is followed to where it
        // leads.
        assert!(
            answers[6]["value"]
                .as_str()
                .is_some_and(|c| c.contains("later=1")),
            "{answers:?}"
        );
        assert_eq!(answers[7]["found"], true, "{answers:?}");
        assert_eq!(answers[7]["after"]["path"], "/bye", "{answers:?}");
        assert_eq!(answers[8]["after"]["path"], "/raw", "{answers:?}");
        assert_eq!(answers[9]["value"]["element"], true, "{answers:?}");
        assert_eq!(answers[9]["value"]["ran"], true, "{answers:?}");
    }

    #[test]
    fn two_factor_codes_are_made_for_the_time_the_containers_read() {
        // The deep review's improvement 5. The clock is read once, from the fence's container; here it
        // shares this computer's, as on Linux, and must be read as no different. Needs a container
        // backend; with one, a failed reading fails.
        let backend = DockerBackend::new();
        if backend.available().is_err() {
            println!("no container backend here; this needs one");
            return;
        }
        let network = format!("sv-clocktest-{}", std::process::id());
        let _ = backend.docker(&["network", "create", "--internal", &network]);
        let via = Via::FreshContainer(&network);
        let read = backend.read_clock_offset(&via);
        let _ = backend.docker(&["network", "rm", &network]);
        assert_eq!(
            read,
            Some(0),
            "the containers' clock was not read, or read wrong"
        );

        // And `now` is moved by what was measured: a machine 48 seconds behind.
        let behind = DockerBackend::new();
        behind.clock_offset.set(-48).unwrap();
        let via = Via::FreshContainer("unused");
        let mut http = DockerHttp {
            backend: &behind,
            via: &via,
            app: "app",
            port: 8080,
            mail: None,
            provider: None,
            browser: None,
            model: None,
        };
        use sv_check::signed_in::Http;
        let (ours, theirs) = (host_now(), http.now());
        assert!((ours - 48..=ours - 47).contains(&theirs), "{ours} {theirs}");
    }

    #[test]
    fn the_seed_command_is_given_the_passwords_though_they_are_not_on_the_command_line() {
        // The deep review's improvement 5: the passwords reach the seed from Docker's environment,
        // named with `-e` and no value. Needs a container backend; with one, a failed setup fails.
        let backend = DockerBackend::new();
        if backend.available().is_err() {
            println!("no container backend here; this needs one");
            return;
        }
        let name = format!("sv-seedtest-{}", std::process::id());
        let started = backend.docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            PROBE_IMAGE,
            "sh",
            "-c",
            "mkdir -p /app; sleep 120",
        ]);
        let accounts = crate::new_accounts(true, true);
        // The seed passes only if each value arrived whole; it compares, and prints nothing.
        let check = format!(
            "test \"$SV_PASSWORD_A\" = '{}' && test \"$SV_PASSWORD_B\" = '{}' && test -n \"$SV_TOTP_SECRET\"",
            accounts.a.password, accounts.b.password
        );
        let seeded = matches!(started, Ok((0, _))).then(|| backend.seed(&name, &check, &accounts));
        let refused = matches!(started, Ok((0, _)))
            .then(|| backend.seed(&name, "test \"$SV_PASSWORD_A\" = 'not it'", &accounts));
        let _ = backend.docker(&["rm", "-f", &name]);
        assert!(
            matches!(started, Ok((0, _))),
            "the container did not start: {started:?}"
        );
        assert!(
            seeded.unwrap().is_ok(),
            "the seed did not get the passwords"
        );
        assert!(refused.unwrap().is_err(), "the seed's check proves nothing");
    }

    #[test]
    fn the_test_provider_is_given_its_secret_though_it_is_not_on_the_command_line() {
        // As the seed's passwords: the client secret reaches the provider from Docker's environment.
        // Needs a container backend; with one, a failed setup fails.
        let backend = DockerBackend::new();
        if backend.available().is_err() {
            println!("no container backend here; this needs one");
            return;
        }
        let network = format!("sv-providertest-{}", std::process::id());
        let name = format!("{network}-idp");
        let _ = backend.docker(&["network", "create", "--internal", &network]);
        let secret = crate::random_hex(16);
        let started = backend.start_provider(&network, &name, &secret);
        let has = |value: &str| {
            let check = format!("test \"$CLIENT_SECRET\" = '{value}'");
            matches!(
                backend.docker(&["exec", &name, "sh", "-c", &check]),
                Ok((0, _))
            )
        };
        let (given, other) = (started && has(&secret), started && has("not it"));
        let _ = backend.docker(&["rm", "-f", &name]);
        let _ = backend.docker(&["network", "rm", &network]);
        assert!(started, "the provider did not start");
        assert!(given, "the provider did not get its secret");
        assert!(!other, "the check proves nothing");
    }

    #[test]
    fn the_app_cannot_reach_the_browser_s_devtools_or_hide_its_storage_from_the_driver() {
        // Deep review S11. The image's own script forwarded DevTools on every address, so the app,
        // on the same fenced network, could drive the browser that checks it; and the driver read
        // in the page's own world, where the app's scripts can redefine what it reads with. Needs
        // a container backend; with one, a failed setup fails.
        let backend = DockerBackend::new();
        if backend.available().is_err() {
            println!("no container backend here; this needs one");
            return;
        }
        let network = format!("sv-devtools-{}", std::process::id());
        let server = format!("{network}-app");
        let browser = format!("{network}-browser");
        let _ = backend.docker(&["network", "create", "--internal", &network]);
        // A page that keeps a token and then hides it from anything reading in its own world.
        let app = r#"
const http = require('http');
http.createServer((q, s) => {
  s.setHeader('content-type', 'text/html');
  s.end(`<script>
    localStorage.setItem('token', 'kept-after-sign-out');
    Storage.prototype.getItem = () => null;
    Object.keys = () => [];
    document.title = 'hidden';
  </script>`);
}).listen(8080);"#;
        let started = backend.docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &server,
            "--network",
            &network,
            PROVIDER_IMAGE,
            "node",
            "-e",
            app,
        ]);
        let ready = matches!(started, Ok((0, _))) && backend.start_browser(&network, &browser) && {
            std::thread::sleep(std::time::Duration::from_secs(3));
            backend.forward_browser(&browser, &server, 8080)
        };
        let address = backend
            .docker(&[
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                &browser,
            ])
            .map(|(_, out)| out.trim().to_owned())
            .unwrap_or_default();
        // From the app's own container, by the browser's address, as an app would ask: a name is
        // refused by DevTools itself, an address is not.
        let from_the_app: Vec<(u16, bool)> = [9222u16, 9223]
            .iter()
            .map(|port| {
                let script = format!(
                    "fetch('http://{address}:{port}/json/version', {{ signal: \
                     AbortSignal.timeout(3000) }}).then(() => process.exit(0), () => \
                     process.exit(1))"
                );
                let reached = matches!(
                    backend.docker(&["exec", &server, "node", "-e", &script]),
                    Ok((0, _))
                );
                (*port, reached)
            })
            .collect();
        // The control: from inside the browser's own network, where the driver is, it answers.
        let loopback = backend.docker(&[
            "run",
            "--rm",
            "--network",
            &format!("container:{browser}"),
            PROBE_IMAGE,
            "wget",
            "-q",
            "-O-",
            "-T",
            "3",
            "http://127.0.0.1:9223/json/version",
        ]);
        let answers = ready.then(|| {
            let via = Via::FreshContainer(&network);
            let mut http = DockerHttp {
                backend: &backend,
                via: &via,
                app: &server,
                port: 8080,
                mail: None,
                provider: None,
                browser: Some(&browser),
                model: None,
            };
            use sv_check::browser::{Action, Job};
            use sv_check::signed_in::Http;
            http.browser(&Job {
                actions: vec![
                    Action::Goto("/".into()),
                    Action::Eval("document.title".into()),
                    Action::Eval("localStorage.getItem('token')".into()),
                    Action::Eval("Object.keys(localStorage).join(',')".into()),
                ],
            })
        });
        let _ = backend.docker(&["rm", "-f", &server, &browser]);
        let _ = backend.docker(&["network", "rm", &network]);
        assert!(
            ready && !address.is_empty(),
            "the app, the browser, or the forwarder did not start: {started:?}"
        );
        assert!(
            matches!(&loopback, Ok((0, out)) if out.contains("Browser")),
            "DevTools did not answer the driver's side either, so nothing below means anything: \
             {loopback:?}"
        );
        assert_eq!(
            from_the_app,
            vec![(9222, false), (9223, false)],
            "the app reached the browser's DevTools"
        );
        let answers = answers.flatten().expect("the driver gave no answer");
        assert_eq!(answers.len(), 4, "{answers:?}");
        // The page's script ran, so what it redefined was redefined.
        assert_eq!(answers[1]["value"], "hidden", "{answers:?}");
        assert_eq!(answers[2]["value"], "kept-after-sign-out", "{answers:?}");
        assert_eq!(answers[3]["value"], "token", "{answers:?}");
    }

    #[test]
    fn what_a_page_sends_elsewhere_from_a_worker_or_over_a_websocket_is_recorded() {
        // Deep review, improvement 5: the driver watched the tab's own requests only, so a page
        // that sent an address elsewhere from a worker, or over a WebSocket, was not seen sending
        // it. Here a page does each, from a worker, a worker's own worker, a shared worker, and a
        // service worker, and a request from the page itself is the control. Needs a container backend; with one, a failed setup fails.
        let backend = DockerBackend::new();
        if backend.available().is_err() {
            println!("no container backend here; this needs one");
            return;
        }
        let network = format!("sv-wsworkers-{}", std::process::id());
        let server = format!("{network}-app");
        let browser = format!("{network}-browser");
        let _ = backend.docker(&["network", "create", "--internal", &network]);
        let app = r#"
const http = require('http');
const scripts = {
  '/worker.js': `fetch('http://collect.example/from-worker?em=a%40example.test').catch(() => {});
                 new Worker('/inner.js');`,
  '/inner.js': `fetch('http://collect.example/from-inner').catch(() => {});`,
  '/sw.js': `fetch('http://collect.example/from-service-worker').catch(() => {});`,
  '/shared.js': `fetch('http://collect.example/from-shared-worker').catch(() => {});`,
};
http.createServer((q, s) => {
  if (scripts[q.url]) {
    s.setHeader('content-type', 'text/javascript');
    return s.end(scripts[q.url]);
  }
  s.setHeader('content-type', 'text/html');
  s.end(`<script>
    fetch('http://collect.example/from-page').catch(() => {});
    new WebSocket('ws://socket.example/live?em=a%40example.test');
    new Worker('/worker.js');
    new SharedWorker('/shared.js');
    navigator.serviceWorker.register('/sw.js');
  </script>`);
}).listen(8080);"#;
        let started = backend.docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &server,
            "--network",
            &network,
            PROVIDER_IMAGE,
            "node",
            "-e",
            app,
        ]);
        let ready = matches!(started, Ok((0, _))) && backend.start_browser(&network, &browser) && {
            std::thread::sleep(std::time::Duration::from_secs(3));
            backend.forward_browser(&browser, &server, 8080)
        };
        let answers = ready.then(|| {
            let via = Via::FreshContainer(&network);
            let mut http = DockerHttp {
                backend: &backend,
                via: &via,
                app: &server,
                port: 8080,
                mail: None,
                provider: None,
                browser: Some(&browser),
                model: None,
            };
            use sv_check::browser::{Action, Job};
            use sv_check::signed_in::Http;
            http.browser(&Job {
                actions: vec![
                    Action::Goto("/account".into()),
                    Action::Wait(2000),
                    Action::Outside,
                ],
            })
        });
        let _ = backend.docker(&["rm", "-f", &server, &browser]);
        let _ = backend.docker(&["network", "rm", &network]);
        assert!(
            ready,
            "the app, the browser, or the forwarder did not start: {started:?}"
        );
        let answers = answers.flatten().expect("the driver gave no answer");
        let requests = answers[2]["requests"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let sent = |url: &str| requests.iter().find(|r| r["url"] == url).cloned();
        // Each is recorded once, though a service worker reaches the driver twice.
        let mut urls: Vec<&str> = requests.iter().filter_map(|r| r["url"].as_str()).collect();
        let all = urls.len();
        urls.sort_unstable();
        urls.dedup();
        assert_eq!(urls.len(), all, "{requests:#?}");
        // The control: the page's own request, as before.
        assert!(
            sent("http://collect.example/from-page").is_some(),
            "{answers:?}"
        );
        let socket = sent("ws://socket.example/live?em=a%40example.test")
            .unwrap_or_else(|| panic!("the WebSocket was not recorded: {requests:#?}"));
        assert_eq!(
            (&socket["type"], &socket["page"]),
            (&"WebSocket".into(), &"/account".into())
        );
        let worker = sent("http://collect.example/from-worker?em=a%40example.test")
            .unwrap_or_else(|| panic!("the worker's request was not recorded: {requests:#?}"));
        assert_eq!(worker["page"], "/worker.js", "{worker:?}");
        assert!(
            sent("http://collect.example/from-inner").is_some(),
            "the worker's own worker's request was not recorded: {requests:#?}"
        );
        assert!(
            sent("http://collect.example/from-service-worker").is_some(),
            "the service worker's request was not recorded: {requests:#?}"
        );
        assert!(
            sent("http://collect.example/from-shared-worker").is_some(),
            "the shared worker's request was not recorded: {requests:#?}"
        );
    }

    #[test]
    fn a_host_prefixed_cookie_signs_the_browser_in_and_a_refused_one_is_named() {
        // family-hub (3 October 2026): its session cookie was `__Host-fh_session`, `Secure`, and
        // the browser refused it when handed its name and value alone, so the browser checks said
        // the browser was not signed in. Here an app that opens /private only for `__Host-sid`,
        // in sv's own Chromium, through the real driver. Needs a container backend; with one, a
        // failed setup fails.
        let backend = DockerBackend::new();
        if backend.available().is_err() {
            println!("no container backend here; this needs one");
            return;
        }
        let network = format!("sv-hostcookie-{}", std::process::id());
        let server = format!("{network}-app");
        let browser = format!("{network}-browser");
        let _ = backend.docker(&["network", "create", "--internal", &network]);
        let app = r#"
const http = require('http');
http.createServer((q, s) => {
  s.setHeader('content-type', 'text/html');
  const cookies = q.headers.cookie || '';
  const signed = cookies.split('; ').includes('__Host-sid=abc');
  if (q.url === '/private' && !signed) { s.writeHead(302, { location: '/login' }); return s.end(); }
  if (q.url === '/private') return s.end('<p>mine</p>');
  if (q.url === '/sent') return s.end('<pre id=c>' + cookies.replace(/</g, '') + '</pre>');
  s.end('<p>login</p>');
}).listen(8080);"#;
        let started = backend.docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &server,
            "--network",
            &network,
            PROVIDER_IMAGE,
            "node",
            "-e",
            app,
        ]);
        let ready = matches!(started, Ok((0, _))) && backend.start_browser(&network, &browser) && {
            std::thread::sleep(std::time::Duration::from_secs(3));
            backend.forward_browser(&browser, &server, 8080)
        };
        use sv_check::browser::{Action, BrowserCookie, Job};
        use sv_check::signed_in::Http;
        // As family-hub set it: `Secure`, `HttpOnly`, `SameSite=Lax`, path `/`.
        let session = BrowserCookie {
            name: "__Host-sid".into(),
            value: "abc".into(),
            secure: true,
            http_only: true,
            path: Some("/".into()),
            same_site: Some("lax".into()),
        };
        // Larger than the 4,096 bytes a browser keeps of a cookie's name and value: plain
        // requests carry it, a browser does not.
        let big = BrowserCookie::plain("big", &"x".repeat(5000));
        let jobs = [
            // The session cookie and one the browser will refuse; the page opens, the refused one
            // is named, and what the browser sends back shows the one it kept.
            Job {
                actions: vec![
                    Action::SetCookies(vec![session.clone(), big]),
                    Action::Goto("/private".into()),
                    Action::Goto("/sent".into()),
                    Action::Eval("document.getElementById('c').textContent".into()),
                    // `HttpOnly` was carried: the page's own scripts cannot read it.
                    Action::Eval("document.cookie".into()),
                ],
            },
            // The prefix alone makes the cookie `Secure`, so an app that left `Secure` out of its
            // header still signs the browser in, as the owner decided on 4 October 2026.
            Job {
                actions: vec![
                    Action::SetCookies(vec![BrowserCookie::plain("__Host-sid", "abc")]),
                    Action::Goto("/private".into()),
                ],
            },
        ];
        let answers: Vec<Option<Vec<serde_json::Value>>> = if ready {
            let via = Via::FreshContainer(&network);
            let mut http = DockerHttp {
                backend: &backend,
                via: &via,
                app: &server,
                port: 8080,
                mail: None,
                provider: None,
                browser: Some(&browser),
                model: None,
            };
            jobs.iter().map(|job| http.browser(job)).collect()
        } else {
            Vec::new()
        };
        let _ = backend.docker(&["rm", "-f", &server, &browser]);
        let _ = backend.docker(&["network", "rm", &network]);
        assert!(
            ready,
            "the app, the browser, or the forwarder did not start: {started:?}"
        );
        let first = answers[0].clone().expect("the driver gave no answer");
        assert_eq!(first.len(), 5, "{first:?}");
        let refused = first[0]["refused"]
            .as_array()
            .expect("an answer about refusals");
        assert_eq!(refused.len(), 1, "{first:?}");
        assert_eq!(refused[0]["name"], "big", "{first:?}");
        assert!(
            refused[0]["why"].as_str().is_some_and(|w| !w.is_empty()),
            "{first:?}"
        );
        assert_eq!(first[1]["path"], "/private", "signed in: {first:?}");
        assert_eq!(first[1]["status"], 200, "{first:?}");
        // The setup worked: the app saw the cookie the browser kept, and not the refused one.
        assert_eq!(first[3]["value"], "__Host-sid=abc", "{first:?}");
        assert_eq!(first[4]["value"], "", "{first:?}");

        let second = answers[1].clone().expect("the driver gave no answer");
        assert_eq!(
            second[0],
            serde_json::json!({ "refused": [] }),
            "{second:?}"
        );
        assert_eq!(second[1]["path"], "/private", "signed in: {second:?}");
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
        let raw = String::from_utf8(raw).unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        assert_eq!(body, r.body_text());
    }

    #[test]
    fn a_body_that_is_not_text_goes_out_byte_for_byte() {
        // An archive is bytes of every value, most of them not text. Each must arrive as it was.
        let mut r = req("POST", "/upload", &[]);
        let bytes: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        r.body = Some(bytes.clone());
        let raw = request_bytes(&r, "app").unwrap();
        let at = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&raw[at..], &bytes[..]);
        let head = String::from_utf8(raw[..at].to_vec()).unwrap();
        assert!(head.contains("Content-Length: 1000\r\n"), "{head}");
    }

    #[test]
    fn a_request_naming_its_own_host_is_sent_with_that_one_only() {
        let raw = request_bytes(
            &req("POST", "/mcp", &[("Host", "sv-rebind.invalid")]),
            "app",
        )
        .expect("a Host header is allowed");
        let raw = String::from_utf8(raw).unwrap();
        let hosts: Vec<&str> = raw
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("host:"))
            .collect();
        assert_eq!(hosts, ["Host: sv-rebind.invalid"], "{raw}");
        // The control: without one, the app's own name is sent.
        let raw =
            String::from_utf8(request_bytes(&req("POST", "/mcp", &[]), "app").unwrap()).unwrap();
        assert!(raw.contains("\r\nHost: app\r\n"), "{raw}");
    }

    #[test]
    fn an_ordinary_request_is_written_out_in_full() {
        let raw = request_bytes(
            &req("GET", "/healthz", &[("Origin", "https://x.invalid")]),
            "app",
        )
        .expect("nothing wrong with this one");
        assert_eq!(
            String::from_utf8(raw).unwrap(),
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
    fn no_part_of_a_request_is_ever_in_the_shell_command() {
        // The request is what the container reads, never part of what its shell runs: the command
        // is built from the app's name and port alone, so nothing a request carries (a quote, a
        // `;`, a file name somebody chose) can become a command. And a request that would split
        // into two is refused before it is anything.
        let bad = req("GET", "/a\r\nX-Injected: 1", &[]);
        assert!(request_bytes(&bad, "app").is_none());
        let script = exchange_script("app", 8080);
        assert_eq!(
            script,
            "f=$(mktemp) && cat > \"$f\" && timeout 15 nc -w 5 app 8080 -e sh -c \"cat $f; cat 1>&2\" 2>&1; rm -f \"$f\""
        );
        let mut hostile = req("POST", "/upload", &[]);
        hostile.body = Some(b"name='quoted';$(echo x)`echo y`".to_vec());
        let raw = request_bytes(&hostile, "app").unwrap();
        assert!(
            raw.ends_with(b"`echo y`"),
            "the body is sent, as it is, as input"
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

#[cfg(test)]
mod gateway_tests {
    use super::*;

    const REFUSED_SELF: &str =
        "nc: can't connect to remote host (127.0.0.1): Connection refused\nsv-self=1\n";

    #[test]
    fn a_gateway_that_answers_in_any_way_is_reachable() {
        for gateway in [
            "nc: can't connect to remote host (172.20.0.1): Connection refused\nsv-gateway=1\n",
            "sv-gateway=0\n",
        ] {
            assert_eq!(
                gateway_verdict(&format!("{REFUSED_SELF}{gateway}")),
                GatewayVerdict::Reachable,
                "{gateway}"
            );
        }
    }

    #[test]
    fn a_gateway_that_cannot_be_reached_is_closed() {
        for gateway in [
            "nc: timed out\nsv-gateway=1\n",
            "nc: can't connect to remote host (172.20.0.1): No route to host\nsv-gateway=1\n",
            "nc: can't connect to remote host (172.20.0.1): Network is unreachable\nsv-gateway=1\n",
            "nc: can't connect to remote host (172.20.0.1): Connection timed out\nsv-gateway=1\n",
        ] {
            assert_eq!(
                gateway_verdict(&format!("{REFUSED_SELF}{gateway}")),
                GatewayVerdict::Closed,
                "{gateway}"
            );
        }
    }

    #[test]
    fn the_subnets_first_address_is_knocked_on_when_no_gateway_is_named() {
        // What GitHub's Docker said of a network made without a gateway address: no gateway listed.
        assert_eq!(gateway_targets("|172.18.0.0/16 "), vec!["172.18.0.1"]);
        assert_eq!(
            gateway_targets("172.20.0.1|172.20.0.0/16 "),
            vec!["172.20.0.1"]
        );
        assert_eq!(
            gateway_targets("10.9.0.254|10.9.0.0/24 |fd00::/64 "),
            vec!["10.9.0.1", "10.9.0.254"]
        );
        assert!(gateway_targets("").is_empty());
        assert!(gateway_targets("|fd00::/64 ").is_empty());
    }

    #[test]
    fn one_answering_address_of_several_is_reachable() {
        let out = format!(
            "{REFUSED_SELF}nc: timed out\nsv-gateway=1\nnc: can't connect to remote host (10.9.0.254): Connection refused\nsv-gateway=1\n"
        );
        assert_eq!(gateway_verdict(&out), GatewayVerdict::Reachable);
        let out =
            format!("{REFUSED_SELF}nc: timed out\nsv-gateway=1\nnc: timed out\nsv-gateway=1\n");
        assert_eq!(gateway_verdict(&out), GatewayVerdict::Closed);
    }

    #[test]
    fn the_knocking_containers_own_address_is_not_the_host() {
        // CI, 4 October 2026: with no gateway, the subnet's first address was the knocking container's
        // own, and its refusal read as the host answering.
        assert_eq!(
            gateway_verdict(&format!("{REFUSED_SELF}sv-own=172.18.0.1\n")),
            GatewayVerdict::Closed
        );
        // Its own address skipped, another that answers still stops the run.
        let out = format!(
            "{REFUSED_SELF}sv-own=172.18.0.1\nnc: 172.18.0.254 (172.18.0.254:9): Connection refused\nsv-gateway=1\n"
        );
        assert_eq!(gateway_verdict(&out), GatewayVerdict::Reachable);
    }

    #[test]
    fn a_check_that_cannot_tell_is_never_taken_for_a_fence() {
        let unknown = |out: &str| matches!(gateway_verdict(out), GatewayVerdict::Unknown(_));
        // The control did not read as refused: an nc that says nothing would pass any gateway.
        assert!(unknown("sv-self=1\nnc: timed out\nsv-gateway=1\n"));
        assert!(unknown("sv-self=0\nnc: timed out\nsv-gateway=1\n"));
        // Nothing ran, or the second knock never reported.
        assert!(unknown(""));
        assert!(unknown(REFUSED_SELF));
        // Something nobody has seen.
        assert!(unknown(&format!(
            "{REFUSED_SELF}sh: nc: not found\nsv-gateway=127\n"
        )));
    }
}

#[cfg(test)]
mod at_once_tests {
    use super::*;

    #[test]
    fn every_copy_is_started_before_any_is_waited_for() {
        let mark = at_once_mark();
        let script = at_once_script("app", 8080, &[40], &[1; 12], &mark);
        let (start, rest) = script
            .split_once("; wait;")
            .expect("one wait, after the starts");
        // Each connection is started in the background within the loop that comes before the
        // wait: one after another would show no race.
        assert!(
            start.contains("for p in 1:1 2:1 3:1 4:1 5:1 6:1 7:1 8:1 9:1 10:1 11:1 12:1; do"),
            "{start}"
        );
        assert!(
            start.contains("-e sh -c") && start.ends_with("2>&1 & done"),
            "{start}"
        );
        assert!(rest.contains(&mark) && rest.contains("rm -rf"), "{rest}");
    }

    #[test]
    fn each_answer_is_read_back_in_its_place() {
        let answer = |status: u16, body: &str| {
            format!(
                "HTTP/1.0 {status} X\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        // Twelve copies: the second got no answer, and the first and tenth must not be mixed up.
        let mark = at_once_mark();
        let mut out = String::from("noise before the first mark");
        for i in 1..=12 {
            out.push_str(&format!("\n{mark}{i}@@\n"));
            match i {
                2 => {}
                1 => out.push_str(&answer(200, "Booked")),
                _ => out.push_str(&answer(409, &format!("Sold out {i}"))),
            }
        }
        let answers = parse_at_once(&["once"; 12], &out, &mark);
        assert_eq!(answers.len(), 12);
        assert!(answers[1].is_none(), "{:?}", answers[1]);
        let first = answers[0].as_ref().expect("an answer");
        assert_eq!((first.status, first.body.as_str()), (200, "Booked"));
        let tenth = answers[9].as_ref().expect("an answer");
        assert_eq!((tenth.status, tenth.body.as_str()), (409, "Sold out 10"));
        assert_eq!(
            answers[11].as_ref().map(|r| r.body.as_str()),
            Some("Sold out 12")
        );
    }

    #[test]
    fn two_requests_are_cut_apart_and_each_copy_sends_its_own() {
        let request = |id: &str, cookie: &str| sv_check::probes::ProbeRequest {
            id: id.to_owned(),
            method: "POST".to_owned(),
            path: "/book".to_owned(),
            headers: vec![("Cookie".to_owned(), cookie.to_owned())],
            body: Some(b"seat=1".to_vec()),
        };
        let a = request("once-a", "s=aaaa");
        let b = request("once-b", "s=bbbbbbbb");
        let (input, sizes, which) =
            together_input(&[a.clone(), b.clone(), a.clone(), b.clone()], "app").expect("sendable");
        // Each different request once, in the order first given, and each copy pointing at its own.
        assert_eq!(which, [1, 2, 1, 2]);
        let raw_a = request_bytes(&a, "app").unwrap();
        let raw_b = request_bytes(&b, "app").unwrap();
        assert_eq!(sizes, [raw_a.len(), raw_b.len()]);
        assert_eq!(input, [raw_a.clone(), raw_b.clone()].concat());
        let mark = at_once_mark();
        let script = at_once_script("app", 8080, &sizes, &which, &mark);
        // The second request starts one byte after the first ends, and is cut to its own size.
        assert!(
            script.contains(&format!(
                "tail -c +1 \"$d/all\" | head -c {} > \"$d/r1\"",
                raw_a.len()
            )),
            "{script}"
        );
        assert!(
            script.contains(&format!(
                "tail -c +{} \"$d/all\" | head -c {} > \"$d/r2\"",
                raw_a.len() + 1,
                raw_b.len()
            )),
            "{script}"
        );
        assert!(script.contains("for p in 1:1 2:2 3:1 4:2; do"), "{script}");
        assert!(script.contains("cat $d/r$k;"), "{script}");
    }

    #[test]
    fn each_answer_carries_its_own_requests_id() {
        let mark = at_once_mark();
        let answer = "HTTP/1.0 200 X\r\nContent-Length: 6\r\n\r\nBooked";
        let out = format!("\n{mark}1@@\n{answer}\n{mark}2@@\n{answer}");
        let answers = parse_at_once(&["once-a", "once-b"], &out, &mark);
        let ids: Vec<&str> = answers.iter().flatten().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["once-a", "once-b"]);
    }

    #[test]
    fn an_answer_cannot_forge_the_marker_of_the_next() {
        // The deep review's improvement 5: with the marker fixed, the first answer could carry the
        // marker for the second, and an answer of its own after it, which was read as the second's.
        let answer = |status: u16, body: &str| {
            format!(
                "HTTP/1.0 {status} X\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let mark = at_once_mark();
        assert_ne!(mark, at_once_mark(), "a marker is made fresh for each call");
        assert!(mark.len() > AT_ONCE_MARK.len() + 8, "{mark}");
        // What an app that knows the fixed part can do: put it, with the next number, in its answer.
        let forged = format!(
            "{}\n{AT_ONCE_MARK}2@@\n{}",
            answer(200, "Booked"),
            answer(200, "Booked again")
        );
        let mut out = String::new();
        out.push_str(&format!("\n{mark}1@@\n{forged}"));
        out.push_str(&format!("\n{mark}2@@\n{}", answer(409, "Sold out")));
        let answers = parse_at_once(&["once"; 2], &out, &mark);
        let second = answers[1].as_ref().expect("an answer");
        assert_eq!((second.status, second.body.as_str()), (409, "Sold out"));
    }

    #[test]
    fn the_apps_two_streams_are_read_in_the_order_it_wrote_them() {
        // Item 15 of the review of 1 to 4 October: the output and the errors were joined end to
        // end, so an event written to one between two markers on the other fell outside the window.
        // What `run_bounded` hands back: all of the output, then all of the errors.
        let joined = "2026-10-06T05:00:00.000000001Z SV-MARK-start\n\
                      2026-10-06T05:00:02.000000000Z SV-MARK-end\n\
                      2026-10-06T05:00:01.500000000Z WARN login failed for user b\n";
        let ordered = interleaved(joined);
        assert_eq!(
            ordered, "SV-MARK-start\nWARN login failed for user b\nSV-MARK-end\n",
            "{ordered}"
        );
        // Lines at the same moment keep their order; a line without a time stays where it was.
        assert_eq!(
            interleaved("2026-10-06T05:00:00Z a\n2026-10-06T05:00:00Z b\n(output cut)\n"),
            "a\nb\n(output cut)\n"
        );
        // Text that is not Docker's stamped form is left as it came.
        assert_eq!(
            interleaved("plain line\nanother\n"),
            "plain line\nanother\n"
        );
        assert!(!is_docker_time("2026-10-06") && is_docker_time("2026-10-06T05:00:00.1Z"));
    }
}
