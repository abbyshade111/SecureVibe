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
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use sv_frameworks::paths::Canonical;
use sv_manifest::Manifest;

pub mod cleanup;
pub mod docker;
pub mod image_reference;
pub mod install;
pub mod stand_ins;

/// Why the app could not be run. Every one of these produces `not assessed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CannotRun {
    /// No container backend on this machine.
    NoBackend { checked: String },
    /// The manifest does not say how to start the app.
    NoRunCommand { missing: Vec<String> },
    /// `image` under `[stack.run]` is not a name Docker reads as one (`image_reference`), so it
    /// was never put on Docker's command line, where a value beginning with a dash is an option.
    BadImage { image: String, why: String },
    /// The backend is there but refused.
    BackendFailed { detail: String },
    /// The app was started and never became healthy. `loopback` is the loopback address its start
    /// command names, when it names one (`loopback_named_in`): the likeliest cause, said by name.
    NeverReady {
        waited_seconds: u64,
        detail: String,
        loopback: Option<&'static str>,
        /// Whether its output shows it stopped with an error, which `detail` quotes. Then the error
        /// is the cause, and a guess about where it listens would only crowd it.
        crashed: bool,
        /// How it ended, when it stopped of its own accord before answering: its exit code, and
        /// whether it was killed for using more memory than it was given (backlog 226, part 2,
        /// item 18). `waited_seconds` is then how long after it started that was.
        exited: Option<Exited>,
    },
    /// The app's folder has files on this computer and arrived empty in the container: the
    /// container backend cannot see it. Colima shares only the home folder by default, and Docker
    /// mounts a folder it cannot see as a new, empty one without complaint.
    AppFolderUnseen { folder: String },
    /// `install = true`, and the app's dependency files do not allow an install of exact versions:
    /// nothing was downloaded, and the app was not started.
    InstallRefused { why: String },
    /// The install step ran and did not finish. `detail` is the end of its output.
    InstallFailed {
        registry: &'static str,
        detail: String,
    },
}

impl CannotRun {
    /// What kind of failure this was, in a few words and without anything the app or the backend
    /// printed: for when what they printed cannot be shown.
    pub fn kind(&self) -> &'static str {
        match self {
            CannotRun::NoBackend { .. } => "no container backend",
            CannotRun::NoRunCommand { .. } => "stackvet.toml does not say how to run it",
            CannotRun::BadImage { .. } => "the image named is not one Docker reads",
            CannotRun::BackendFailed { .. } => "the container backend refused",
            CannotRun::NeverReady { .. } => "it started and never answered",
            CannotRun::AppFolderUnseen { .. } => "its folder arrived empty in the container",
            CannotRun::InstallRefused { .. } => "the install was refused",
            CannotRun::InstallFailed { .. } => "the install did not finish",
        }
    }

    /// Plain language, for the reports and the terminal.
    pub fn explain(&self) -> String {
        match self {
            CannotRun::NoBackend { checked } => format!(
                "No container backend on this computer ({checked}). Everything that needs the app \
                 running is reported as not assessed — not as passing, and not as failing. To have \
                 it checked, get Docker running with Linux containers (Docker Desktop, or \
                 `colima start` on a Mac), then run this again; `sv doctor` shows what it finds."
            ),
            CannotRun::NoRunCommand { missing } => format!(
                "stackvet.toml does not say how to run this app ({} not set under [stack.run]), \
                 so everything that needs it running is reported as not assessed.",
                missing.join(", ")
            ),
            CannotRun::BadImage { image, why } => format!(
                "stackvet.toml names an image under [stack.run] that is not a name Docker \
                 reads as one ({image:?}: {why}), so the app was not started and everything that \
                 needs it running is reported as not assessed. Name the image as Docker does, \
                 `python:3.12-slim` or `registry.example.com/team/app:1.0`."
            ),
            CannotRun::BackendFailed { detail } => format!(
                "The container backend refused: {detail}. Everything that needs the app running \
                 is reported as not assessed. If Docker or Colima has stopped, start it and run \
                 this again; `sv doctor` shows what it finds."
            ),
            CannotRun::NeverReady {
                waited_seconds,
                detail,
                loopback,
                crashed,
                exited,
            } => format!(
                "{} {detail} {} This is reported as not assessed rather than as a failure: an app \
                 that will not start under `sv` has not been shown to be insecure.",
                match exited {
                    Some(Exited {
                        code,
                        out_of_memory: true,
                    }) => format!(
                        "The app stopped {waited_seconds}s after it started, killed for using more \
                         memory than the container was given (exit code {code}), and never \
                         answered on its health path."
                    ),
                    Some(Exited { code, .. }) => format!(
                        "The app stopped {waited_seconds}s after it started, with exit code \
                         {code}, and never answered on its health path."
                    ),
                    None => format!(
                        "The app started but never answered on its health path within \
                         {waited_seconds}s."
                    ),
                },
                if detail.contains("Read-only file system") {
                    "The app tried to write outside the places it may: while `sv` runs it, its \
                     file system is read-only apart from /tmp, so keep its data under /tmp."
                        .to_owned()
                } else if *crashed {
                    "That error is why: fix it, and run this again.".to_owned()
                } else {
                    match loopback {
                        Some(name) => format!(
                            "Its start command names {name}, which is the likely cause: an app \
                             listening on {name} answers only from inside its own container, and \
                             `sv` asks it from a second container on the fenced network. Have it \
                             listen on 0.0.0.0 (every address) at the port in $PORT."
                        ),
                        None => "One common cause: an app listening on 127.0.0.1 or localhost \
                                 answers only from inside its own container, and `sv` asks it from \
                                 a second container on the fenced network. Have it listen on \
                                 0.0.0.0 (every address) at the port in $PORT."
                            .to_owned(),
                    }
                }
            ),
            CannotRun::AppFolderUnseen { folder } => format!(
                "The app's folder, {folder}, has files on this computer, and inside the container \
                 it was empty: the container backend cannot see that folder, so the app had nothing \
                 to start. On a Mac with Colima, only your home folder is shared by default: move \
                 the app under your home folder, or share its folder (`colima start --mount \
                 {folder}:w`, or `mounts` in ~/.colima/default/colima.yaml). With Docker Desktop, \
                 add it under Settings, Resources, File sharing. This is reported as not assessed: \
                 nothing about the app was seen."
            ),
            CannotRun::InstallRefused { why } => format!(
                "stackvet.toml asks for the app's packages to be installed before the run, and \
                 they were not: {why} Nothing was downloaded and the app was not started, so \
                 everything that needs it running is reported as not assessed."
            ),
            CannotRun::InstallFailed { registry, detail } => format!(
                "Installing the app's packages from {registry} before the run did not finish: \
                 {detail} The install takes only ready-made packages and runs none of their own \
                 install code, so a package that needs either cannot be installed this way: build \
                 an image with the packages in it and name it with `image` instead. The app was \
                 not started, so everything that needs it running is reported as not assessed."
            ),
        }
    }
}

/// How an app that stopped of its own accord ended (`CannotRun::NeverReady`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exited {
    pub code: i64,
    pub out_of_memory: bool,
}

/// What happened to a run's containers beyond the questions it asked (backlog 226, part 2, item
/// 18): how long the app took to answer, how its network was made, what could not be removed at the
/// end, and which download volumes were kept for the next run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerRecord {
    /// Seconds from the app's start to its first answer on the health path.
    pub ready_after_seconds: Option<u64>,
    /// How the fenced network was made, as "with `<option>`" or why it was made plain internal.
    pub network_made: Option<String>,
    /// What could not be removed when the run ended, each with what Docker said.
    pub not_removed: Vec<String>,
    /// The download volumes kept for the next run with the same files (ADR-052).
    pub volumes_kept: Vec<String>,
}

impl ContainerRecord {
    /// The record in sentences, for `sv run` and the report, or `None` when it holds nothing.
    pub fn sentences(&self) -> Option<String> {
        let mut said = Vec::new();
        if let Some(seconds) = self.ready_after_seconds {
            said.push(format!(
                "It answered on its health path {seconds}s after it started."
            ));
        }
        if let Some(made) = &self.network_made {
            said.push(format!("Its fenced network was made {made}."));
        }
        said.extend(not_removed_sentence(&self.not_removed));
        if !self.volumes_kept.is_empty() {
            let names = self.volumes_kept.join(" ");
            said.push(format!(
                "The packages it downloaded are kept in the Docker volume{} {}, so the next run \
                 with the same files reuses them: `docker volume rm {names}` removes {}, and \
                 `docker volume ls --filter label={}` lists every one `sv` keeps.",
                if self.volumes_kept.len() == 1 {
                    ""
                } else {
                    "s"
                },
                self.volumes_kept
                    .iter()
                    .map(|v| format!("`{v}`"))
                    .collect::<Vec<_>>()
                    .join(" and "),
                if self.volumes_kept.len() == 1 {
                    "it"
                } else {
                    "them"
                },
                install::VOLUME_LABEL
            ));
        }
        (!said.is_empty()).then(|| said.join(" "))
    }
}

/// What could not be removed when a run ended, each with what Docker said, and how to remove it, in
/// one sentence: `None` when everything went. A finished run and a failed one say it alike.
fn not_removed_sentence(not_removed: &[String]) -> Option<String> {
    (!not_removed.is_empty()).then(|| {
        format!(
            "When the run ended, these could not be removed: {}. `docker rm -f <name>` removes a \
             container, and `docker network rm <name>` a network.",
            not_removed.join("; ")
        )
    })
}

/// A run that could not be finished, and what it removed from this computer before it failed.
///
/// A run removes what an earlier, killed run left behind before it starts anything (`cleanup`).
/// That has happened whether or not the app then starts, so a failed run says so as well: removing
/// containers and a network from the owner's computer is never done without a word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunFailed {
    pub reason: CannotRun,
    /// As `RunOutcome::left_over_removed`.
    pub left_over_removed: Vec<String>,
    /// What the failed run's own teardown could not remove, as `ContainerRecord::not_removed`
    /// (backlog 226, part 2, item 18): until 10 October 2026 a failed run dropped it unsaid.
    pub not_removed: Vec<String>,
}

impl RunFailed {
    /// Why the run failed, then what it removed first, when it removed anything, and then what it
    /// could not remove of its own.
    pub fn explain(&self) -> String {
        std::iter::once(self.reason.explain())
            .chain(cleanup::removed_sentence(&self.left_over_removed))
            .chain(not_removed_sentence(&self.not_removed))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Whether the app never answering is the backend not seeing its folder: `inside` is what `ls -A`
/// listed in `/app` inside a container, or `None` when that could not be asked. Only an empty
/// listing of a folder that has something in it on this computer counts.
pub fn unseen_folder(app_dir: &Path, inside: Option<&str>) -> Option<CannotRun> {
    let empty_inside = inside.is_some_and(|listed| listed.trim().is_empty());
    let has_files = std::fs::read_dir(app_dir).is_ok_and(|mut entries| entries.next().is_some());
    (empty_inside && has_files).then(|| CannotRun::AppFolderUnseen {
        folder: app_dir.display().to_string(),
    })
}

/// The loopback address a start command names, if it names one: `127.0.0.1`, `localhost`, or
/// `::1`. An app told to listen there answers only from inside its own container, and `sv` asks it
/// from a second one (`docker`, the sidecar), so it never hears the question. Only the command line
/// is read: an app may listen somewhere other than its command suggests, in either direction, so
/// this is a reason to warn, never a reason to refuse.
pub fn loopback_named_in(start: &str) -> Option<&'static str> {
    let text = start.to_ascii_lowercase();
    // What may sit on either side of the name for it to be the name, and not part of a longer one:
    // `127.0.0.10` is not 127.0.0.1, `notlocalhost` is not localhost, and `fe80::1` is not ::1.
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let hex = |c: char| c.is_ascii_hexdigit() || c == ':';
    let dotted = |c: char| word(c) || c == '.';
    let digit = |c: char| c.is_ascii_digit();
    type Joined<'a> = &'a dyn Fn(char) -> bool;
    let names: [(&'static str, Joined, Joined); 3] = [
        ("127.0.0.1", &dotted, &digit),
        ("localhost", &word, &word),
        ("::1", &hex, &hex),
    ];
    for (name, joined_before, joined_after) in names {
        for (at, _) in text.match_indices(name) {
            let before = text[..at].chars().next_back();
            let after = text[at + name.len()..].chars().next();
            if !before.is_some_and(joined_before) && !after.is_some_and(joined_after) {
                return Some(name);
            }
        }
    }
    None
}

/// What to say before waiting for an app whose start command names a loopback address. A warning,
/// not a refusal: the app may listen elsewhere than its command line suggests, and the run goes on.
pub fn loopback_warning(start: &str) -> Option<String> {
    loopback_named_in(start).map(|name| {
        format!(
            "Warning: the start command in stackvet.toml names {name}. An app listening on \
             {name} answers only from inside its own container, and `sv` asks it from a second \
             one, so it may never answer. If this run waits and gives up, have the app listen on \
             0.0.0.0 (every address) at the port in $PORT. Starting it anyway: an app may listen \
             somewhere other than its command line suggests."
        )
    })
}

/// Names in a setting that speak to security, for `weakening_named_in`.
const SECURITY_WORDS: &[&str] = &[
    "auth",
    "csrf",
    "xsrf",
    "secure",
    "security",
    "ssl",
    "tls",
    "https",
    "hsts",
    "csp",
    "verify",
    "captcha",
    "mfa",
    "2fa",
    "totp",
    "ratelimit",
];

/// The settings in a start command that look like they make the app weaker for the run, as written
/// there (family-hub, 3 October 2026: `FAMILY_HUB_INSECURE_COOKIES=1`, added so the browser checks
/// could sign in, made them pass against a copy of the app with weaker cookies than the real one).
///
/// A setting is an environment variable (`NAME=value`) or a flag (`--name`, `--name=value`). Its
/// name is split into words at `_`, `-`, and `.`, in any case, and it is listed when:
/// 1. one of the words is `insecure` (`FAMILY_HUB_INSECURE_COOKIES=1`, `--insecure`);
/// 2. one word is `disable`, `disabled`, `skip`, `bypass`, or `no`, and another is one of
///    `SECURITY_WORDS` (`DISABLE_CSRF=1`, `AUTH_DISABLED=true`, `--no-verify`, `SKIP_AUTH=1`);
/// 3. one of the words is one of `SECURITY_WORDS` and the value is `0`, `false`, `no`, or `off`
///    (`SESSION_COOKIE_SECURE=False`, `CSRF_ENABLED=0`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).
///
/// `rate_limit` and `rate-limit` count as `ratelimit`. Nothing else is listed: `DISABLE_TELEMETRY`
/// and `--no-cache-dir` name nothing about security, and `DEBUG=1` is left alone, though it may
/// matter. Only the command line is read, so this is a reason to warn, never to refuse. A value is
/// shown only when it is one of the short words above, never anything that could be a key.
pub fn weakening_named_in(start: &str) -> Vec<String> {
    const OFF: &[&str] = &["0", "false", "no", "off"];
    const SHOWN: &[&str] = &["0", "1", "false", "true", "no", "yes", "off", "on"];
    let unquoted: String = start.chars().filter(|c| !matches!(c, '"' | '\'')).collect();
    let mut out: Vec<String> = Vec::new();
    for word in unquoted.split(|c: char| c.is_whitespace() || ";&|()`".contains(c)) {
        let (name, value) = match word.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (word, None),
        };
        let bare = name.trim_start_matches('-');
        if bare.is_empty()
            || !bare
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
        {
            continue;
        }
        let lower = bare.to_ascii_lowercase();
        let mut words: Vec<String> = lower
            .split(['_', '-', '.'])
            .filter(|w| !w.is_empty())
            .map(str::to_owned)
            .collect();
        if lower.replace(['_', '-', '.'], "").contains("ratelimit") {
            words.push("ratelimit".to_owned());
        }
        let has = |list: &[&str]| words.iter().any(|w| list.contains(&w.as_str()));
        let value_lower = value.map(str::to_ascii_lowercase);
        let off = value_lower.as_deref().is_some_and(|v| OFF.contains(&v));
        let security = has(SECURITY_WORDS);
        let weakens = has(&["insecure"])
            || (security && has(&["disable", "disabled", "skip", "bypass", "no"]))
            || (security && off);
        if !weakens {
            continue;
        }
        let shown = match (value, value_lower.as_deref()) {
            (Some(v), Some(l)) if SHOWN.contains(&l) => format!("{name}={v}"),
            _ => name.to_owned(),
        };
        if !out.contains(&shown) {
            out.push(shown);
        }
    }
    out
}

/// The settings `weakening_named_in` lists, joined for a sentence: "A", "A and B", "A, B, and C".
fn joined(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
    match quoted.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// What to say before starting an app whose start command looks like it weakens it for the run. A
/// warning, not a refusal (the owner's decision, 4 October 2026): the setting may be harmless, or
/// needed for the app to run here at all.
pub fn weakening_warning(start: &str) -> Option<String> {
    let names = weakening_named_in(start);
    (!names.is_empty()).then(|| {
        format!(
            "Warning: the start command in stackvet.toml sets {}, which looks like it makes the \
             app less secure for this run. What `sv` finds is then about that weaker copy, and a \
             check that passes may not pass for the app as it really runs. If it is not needed, \
             take it out of the start command. Starting it anyway.",
            joined(&names)
        )
    })
}

/// The same, as one sentence for the report's note about the run.
pub fn weakening_note(start: &str) -> Option<String> {
    let names = weakening_named_in(start);
    (!names.is_empty()).then(|| {
        format!(
            "Warning: its start command sets {}, which looks like it makes the app less secure \
             for the run, so what was found by running it is about that weaker copy and may not \
             hold for the app as it really runs.",
            joined(&names)
        )
    })
}

/// Where a run says each suite's name as it begins (`RunPlan::on_step`). How a run is watched is
/// not what it runs, so any two are equal, and two plans that differ only in it are the same plan.
#[derive(Clone, Copy)]
pub struct OnStep(pub fn(&str));

impl std::fmt::Debug for OnStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnStep")
    }
}

impl PartialEq for OnStep {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for OnStep {}

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
    /// How to sign in, when stackvet.toml says. Absent means the probes sign in as nobody.
    pub users: Option<sv_manifest::UsersSection>,
    /// The numbers the owner states as policy, for the probes that hold the app to them.
    pub policy: sv_manifest::PolicySection,
    /// How the app signs in through another service, when stackvet.toml says. The run then
    /// starts a test provider of `sv`'s own and points the app at it.
    pub oidc: Option<sv_manifest::OidcSection>,
    /// How to talk to the app's AI feature, when stackvet.toml says. The run then starts a test
    /// model of `sv`'s own and points the app at it.
    pub ai: Option<sv_manifest::AiSection>,
    /// Where the app answers as an MCP server, when stackvet.toml says.
    pub mcp_server: Option<sv_manifest::McpServerSection>,
    /// A feature that fetches an address a person gives it, when stackvet.toml says how to reach
    /// it. The run then starts the test model, whose server records each fetch.
    pub fetch: Option<sv_manifest::FetchSection>,
    /// Where the app answers GraphQL and WebSocket connections, when stackvet.toml says.
    pub graphql: Option<String>,
    pub websocket: Option<String>,
    /// Whether other programs are meant to use this app's API, as stackvet.toml claims it.
    /// Introspection is allowed for an API meant for others and not otherwise (V4.3.2), so the
    /// answer to that question depends on this one, and silence here leaves it unanswered.
    pub public_api: Option<bool>,
    /// Wait out the session timeouts the owner states (`sv run --slow`). Off unless asked for: it
    /// can take as long as the timeouts, up to an hour and a half.
    pub slow: bool,
    /// Told the name of each suite as it begins, for a person watching at a terminal (backlog
    /// 226, part 2, item 15). `None` says nothing.
    pub on_step: Option<OnStep>,
    /// The longest the test command may take: `TEST_LIMIT`, and shorter only in `sv`'s own tests.
    pub test_limit: Duration,
    /// Install the app's packages before the run (ADR-052). Off unless stackvet.toml says so.
    pub install: bool,
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
        let image = image.expect("checked above");
        if let Some(why) = image_reference::problem(&image) {
            return Err(CannotRun::BadImage { image, why });
        }
        Ok(RunPlan {
            image,
            build: non_empty(&run.build),
            start: start.expect("checked above"),
            test: non_empty(&run.test),
            test_report: non_empty(&run.test_report),
            health_path: non_empty(&run.health).unwrap_or_else(|| "/".to_owned()),
            // Absolute, always. Docker reads a relative path as the *name* of a named volume and
            // refuses it, which turns "sv was run from the wrong directory" into an error message
            // about invalid characters in a volume name.
            app_dir: app_dir
                .canonical()
                .unwrap_or_else(|_| app_dir.to_path_buf()),
            port: APP_PORT,
            users: run.users.clone(),
            policy: manifest.policy.clone(),
            oidc: run.oidc.clone(),
            ai: run.ai.clone(),
            mcp_server: run.mcp_server.clone(),
            fetch: run.fetch.clone(),
            graphql: run.graphql.clone(),
            websocket: run.websocket.clone(),
            public_api: manifest.capabilities.public_api,
            slow: false,
            on_step: None,
            test_limit: match run.test_time_limit {
                Some(seconds) if seconds > 0 => Duration::from_secs(seconds),
                _ => TEST_LIMIT,
            },
            install: run.install.unwrap_or(false),
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
    /// The anonymous questions the app's rate limiter was still answering after waiting as it asked,
    /// as "id (status)". Left out of `probe_responses`, since the limiter's page is not the app's.
    pub probes_rate_limited: Vec<String>,
    /// What asking as signed-in users showed, when stackvet.toml says how to sign in.
    pub signed_in: Option<sv_check::signed_in::Outcome>,
    /// What signing in through the test provider showed, when the app signs in through another
    /// service. Kept apart from `signed_in`: an app whose only sign-in is "Sign in with …" was not
    /// asked any of the signed-in questions, and folding the two together would say it was.
    pub oidc: Option<sv_check::signed_in::Outcome>,
    /// What asking the app's AI feature through the test model showed, when stackvet.toml says
    /// how to reach it.
    pub ai: Option<sv_check::signed_in::Outcome>,
    /// What asking the app as an MCP server showed, when stackvet.toml says where it answers.
    pub mcp_server: Option<sv_check::signed_in::Outcome>,
    /// What asking the feature that fetches an address showed, when stackvet.toml says how.
    pub fetch: Option<sv_check::signed_in::Outcome>,
    /// Containers and networks an earlier run on this machine left behind when its process was
    /// killed outright, removed before this run started. See `cleanup`.
    pub left_over_removed: Vec<String>,
    /// Whether the app was still running and answering after the anonymous questions, and again
    /// after the signed-in, sign-in-provider, and AI questions when any of those were asked (V16.5.4).
    pub liveness: Vec<sv_check::running::Liveness>,
    /// The first request that found the container the questions are sent from gone, when one did,
    /// and what Docker said: every request after it got no answer because nothing was there to
    /// ask, not because the app was silent (ADR-025, Later, 8 October 2026).
    pub sidecar_lost: Option<String>,
    /// The packages installed before the run (ADR-052), and whether each came from an earlier
    /// run's download. Empty when `install` was not asked for.
    pub installed: Vec<(install::Ecosystem, bool)>,
    /// What `sv`'s stand-in services received, read before they were removed (ADR-082).
    pub stand_ins: stand_ins::StandIns,
    /// What happened to the run's containers (backlog 226, part 2, item 18).
    pub container: ContainerRecord,
    /// How long each suite of questions took, and the app's own tests, in milliseconds, in the
    /// order run (backlog 226, part 2, item 13).
    pub suite_timings: Vec<(&'static str, u64)>,
}

impl RunOutcome {
    /// Every suite of questions asked beyond the anonymous ones, in the order they are asked, each
    /// with the words `sv run` puts before its steps. The one list the evidence, the report's steps,
    /// and the printout read, so none of them can leave a suite out: the MCP-server and fetch suites'
    /// steps once reached nobody (backlog 226, part 1, item 4). It names every field, so a suite
    /// added to `RunOutcome` does not build until it is placed here or said not to be one.
    pub fn asked(&self) -> Vec<(&'static str, &sv_check::signed_in::Outcome)> {
        let RunOutcome {
            signed_in,
            oidc,
            ai,
            mcp_server,
            fetch,
            healthy: _,
            tests: _,
            fence: _,
            probe_responses: _,
            probes_rate_limited: _,
            left_over_removed: _,
            liveness: _,
            sidecar_lost: _,
            installed: _,
            stand_ins: _,
            container: _,
            suite_timings: _,
        } = self;
        [
            ("as two test users", signed_in),
            (
                "through a test provider standing in for the one it signs in with",
                oidc,
            ),
            (
                "its AI feature, with a test model standing in for the real one",
                ai,
            ),
            ("its MCP server, asked as an MCP client would", mcp_server),
            (
                "its feature that fetches an address, given one it should not go to",
                fetch,
            ),
        ]
        .into_iter()
        .filter_map(|(lead, outcome)| Some((lead, outcome.as_ref()?)))
        .collect()
    }
}

#[cfg(test)]
mod asked_tests;

/// Two ordinary test accounts and, when asked for, an admin, each with a password made for this run.
///
/// Fresh every run and never written anywhere but the app's own container: they exist to be signed
/// in with once. The password carries every kind of character a password rule asks for, so an app
/// with a strict policy still accepts it.
/// The accounts a run makes for what stackvet.toml's users section asks: an admin when it lists
/// admin pages or admin actions, and a two-factor secret when it names `totp` and a `seed`.
pub fn accounts_for(users: &sv_manifest::UsersSection) -> sv_check::signed_in::Accounts {
    new_accounts(
        users.makes_an_admin(),
        users.totp.is_some() && users.seed.is_some(),
    )
}

pub fn new_accounts(with_admin: bool, with_totp: bool) -> sv_check::signed_in::Accounts {
    let account = |role: &str| {
        let tag = random_hex(6);
        sv_check::signed_in::Account {
            user: format!("sv-{role}-{tag}@example.test"),
            password: format!("Sv-{}-aZ9!", random_hex(12)),
        }
    };
    // Twenty random bytes: the secret length RFC 4226 recommends, and what authenticator apps make.
    // Taken from the same random hex, two characters to a byte.
    let secret = || -> Vec<u8> {
        random_hex(20)
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0)
            })
            .collect()
    };
    sv_check::signed_in::Accounts {
        a: account("a"),
        b: account("b"),
        admin: with_admin.then(|| account("admin")),
        spare: random_hex(16),
        totp: with_totp.then(|| sv_check::signed_in::TotpAccount {
            account: account("totp"),
            secret: secret(),
        }),
        // The admin's own, for an app that asks admins for a code: given to `seed` as
        // SV_ADMIN_TOTP_SECRET, like the two-factor account's, and never written anywhere else.
        admin_totp_secret: (with_admin && with_totp).then(secret),
    }
}

/// Random bytes as hex, from the operating system. A clock-based value would repeat between runs
/// started in the same instant, and a password is the one thing here that must not be guessable.
pub(crate) fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    // The operating system's own source on every system, Windows included (backlog 0120).
    let filled = getrandom::fill(&mut buf).is_ok();
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
    /// How long the tests ran before they were stopped for taking longer than `TEST_LIMIT`, or
    /// `None` when they finished. A suite cut short credits nothing, whatever it printed.
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
                 computer. Its file system was read-only apart from an in-memory `/tmp`, and it \
                 ran with no special privileges. The checks reached it from a second container on \
                 the same network."
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
    ) -> Result<RunOutcome, RunFailed>;
}

/// The backend to use, or why there is none.
pub fn detect() -> Result<Box<dyn Backend>, CannotRun> {
    let docker = docker::DockerBackend::new();
    match docker.available() {
        Ok(()) => Ok(Box::new(docker)),
        Err(e) => Err(e),
    }
}

/// The longest any one Docker command may take before it is stopped. Generous, because `docker run`
/// downloads an image it does not have, which on a slow connection takes minutes; the point is that a
/// run never waits forever, not that it hurries.
pub const DOCKER_CALL_LIMIT: Duration = Duration::from_secs(20 * 60);

/// The longest the app's own test command may take. A suite cut short credits nothing, and the report
/// says it was stopped and after how long.
pub const TEST_LIMIT: Duration = Duration::from_secs(10 * 60);

/// Set by Ctrl-C during a run. See `catch_interrupts`.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Whether Ctrl-C was pressed during a run. The run has returned by the time anybody asks, and its
/// containers and network have been removed.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// From here on, Ctrl-C (or a polite `kill`) stops the Docker command in progress and every one after
/// it, so the run returns and its teardown removes the containers and network, instead of ending
/// the process where it stands and leaving them behind: a signal ends a Rust process without
/// unwinding, so no `Drop` would run. A second Ctrl-C ends the process at once, for somebody who
/// would rather clean up by hand than wait.
pub fn catch_interrupts() {
    #[cfg(unix)]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        extern "C" fn on_signal(_: libc::c_int) {
            if INTERRUPTED.swap(true, Ordering::SeqCst) {
                // Only async-signal-safe calls in here: `_exit`, not `std::process::exit`.
                unsafe { libc::_exit(130) };
            }
        }
        ONCE.call_once(|| {
            let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            // SAFETY: the handler only touches an atomic and calls `_exit`.
            unsafe {
                libc::signal(libc::SIGINT, handler);
                libc::signal(libc::SIGTERM, handler);
            }
        });
    }
}

/// What a bounded command did.
#[derive(Debug)]
pub(crate) struct Bounded {
    pub code: i32,
    /// Standard output, then standard error.
    pub text: String,
    /// Stopped for taking longer than its limit; `code` is then not the command's own.
    pub stopped: bool,
    /// Printed more than `OUTPUT_LIMIT` on one stream, so `text` holds only the start of it.
    pub cut: bool,
}

/// The most `sv` reads of what one command prints on each of its two streams. Everything after it is
/// read and thrown away, so the command is never left waiting on a full pipe, but none of it is kept:
/// an app that answers with gigabytes, or a test suite that prints without end, could otherwise fill
/// this computer's memory (the deep review of 4 October 2026, S9). Far above any answer a check reads.
pub(crate) const OUTPUT_LIMIT: u64 = 32 * 1024 * 1024;

/// What is added to output that was cut, so nobody reads the start of it as the whole.
pub(crate) const CUT_NOTE: &str = "[sv stopped keeping this output here: it was longer than 32 MB]";

/// Reads `pipe` to its end, keeping at most `limit` bytes. The bytes kept, and whether any were not.
fn read_capped(pipe: &mut dyn std::io::Read, limit: u64) -> (Vec<u8>, bool) {
    use std::io::Read;
    let mut bytes = Vec::new();
    let _ = pipe.take(limit).read_to_end(&mut bytes);
    let rest = std::io::copy(pipe, &mut std::io::sink()).unwrap_or(0);
    (bytes, rest > 0)
}

/// Runs a command for at most `limit`, and hands back what it printed and its status, whether it was
/// stopped for time, or why it could not start. `cleanup` runs even after Ctrl-C, which is what
/// removing the containers needs; anything else is refused once Ctrl-C has been pressed.
pub(crate) fn run_bounded(
    command: &mut Command,
    limit: Duration,
    cleanup: bool,
) -> Result<Bounded, String> {
    run_bounded_with_input(command, limit, cleanup, &[])
}

/// `run_bounded`, with `input` written to what the command reads, from a thread of its own, so a
/// command that answers before it has read everything cannot leave both sides waiting.
pub(crate) fn run_bounded_with_input(
    command: &mut Command,
    limit: Duration,
    cleanup: bool,
    input: &[u8],
) -> Result<Bounded, String> {
    use std::io::{Read, Write};
    if !cleanup && interrupted() {
        return Err("not started: the run was stopped with Ctrl-C".to_owned());
    }
    // In a process group of its own, so stopping it stops what it started too: `sh -c` running a
    // suite, or anything else holding its output open, which would otherwise keep the output from
    // ending until it finished by itself. Ctrl-C at the terminal then reaches `sv` alone, whose
    // handler stops the group.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(command, 0);
    let mut child = command
        .stdin(if input.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    // Windows has no process groups. A job holds the command and everything it starts, so stopping
    // the job stops them all (`job::Job`).
    #[cfg(windows)]
    let job = job::Job::holding(&child);
    #[cfg(not(windows))]
    let job: Option<NoJob> = None;
    if let Some(mut stdin) = child.stdin.take() {
        let input = input.to_vec();
        // A command that stops reading early (a refusal sent before the upload has arrived) ends
        // the write with an error, which is not this function's to report: the answer is.
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    let read = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || read_capped(&mut pipe, OUTPUT_LIMIT))
    };
    let out = read(Box::new(child.stdout.take().expect("piped")));
    let err = read(Box::new(child.stderr.take().expect("piped")));
    let started = Instant::now();
    let mut pause = Duration::from_millis(1);
    let (status, stopped) = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => break (Some(status), false),
            None if started.elapsed() >= limit => {
                stop(&mut child, job.as_ref());
                break (None, true);
            }
            None if !cleanup && interrupted() => {
                stop(&mut child, job.as_ref());
                return Err("stopped: the run was stopped with Ctrl-C".to_owned());
            }
            None => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(50));
            }
        }
    };
    let (out, out_cut) = out.join().unwrap_or_default();
    let (err, err_cut) = err.join().unwrap_or_default();
    let mut text = String::from_utf8_lossy(&out).into_owned();
    if out_cut {
        text.push_str(&format!("\n{CUT_NOTE}\n"));
    }
    text.push_str(&String::from_utf8_lossy(&err));
    if err_cut {
        text.push_str(&format!("\n{CUT_NOTE}\n"));
    }
    Ok(Bounded {
        code: status.and_then(|s| s.code()).unwrap_or(-1),
        text,
        stopped,
        cut: out_cut || err_cut,
    })
}

/// Where there are process groups, the group stands in for a job, so there is none to hold.
#[cfg(not(windows))]
struct NoJob;

/// Stops a command started by `run_bounded`, and everything in its process group, or on Windows its
/// job.
#[cfg(not(windows))]
fn stop(child: &mut std::process::Child, _job: Option<&NoJob>) {
    #[cfg(unix)]
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: a plain system call; the group is the one `run_bounded` made for this child.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Windows has no process groups to stop at once, and stopping the command alone leaves what it
/// started running and holding its output open, so the reading waits until that ends by itself: 30
/// seconds for a `sleep 30`, or never for a suite that hangs (backlog 0120). `taskkill /T` was tried
/// first (9 October 2026) and left the child of Git's `sh` running, since it follows each process's
/// parent and a parent that has gone breaks the trail. The job is Windows' own way to stop a command
/// and everything it started; `taskkill /T` stays for a command no job could hold.
#[cfg(windows)]
fn stop(child: &mut std::process::Child, job: Option<&job::Job>) {
    match job {
        Some(job) => job.stop_all(),
        None => {
            let _ = Command::new("taskkill")
                .args(["/T", "/F", "/PID", &child.id().to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// A Windows job object: every process the command starts joins it, unless it asks to leave, and
/// stopping the job stops them all. Called through Windows' own `kernel32`, with no new dependency.
///
/// A process the command starts in the moment between its start and its joining the job is not held;
/// `sh -c` and a test runner take far longer than that to start anything.
#[cfg(windows)]
mod job {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    type Handle = *mut c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> Handle;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    pub(crate) struct Job(Handle);

    impl Job {
        /// A new job holding `child`, or `None` when Windows would not make one or put it in.
        pub(crate) fn holding(child: &std::process::Child) -> Option<Job> {
            // SAFETY: no attributes and no name: a new job only this process holds.
            let handle = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
            if handle.is_null() {
                return None;
            }
            let job = Job(handle);
            // SAFETY: both handles are open: the job's just made, the child's held by `child`.
            let joined = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) };
            (joined != 0).then_some(job)
        }

        /// Stops every process in the job.
        pub(crate) fn stop_all(&self) {
            // SAFETY: the job's handle is open until `drop`.
            unsafe { TerminateJobObject(self.0, 1) };
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // Closing the handle stops nothing: the job was not made to stop its processes on close,
            // so a command that ends normally leaves what it started as it would elsewhere.
            // SAFETY: the handle is open, and closed only here.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Runs a command and hands back stdout+stderr with the status, or the reason it could not start or
/// finish: every Docker call goes through here, and none may take longer than `DOCKER_CALL_LIMIT`.
pub(crate) fn output_of(command: &mut Command) -> Result<(i32, String), String> {
    bounded_output(command, DOCKER_CALL_LIMIT, false)
}

/// `output_of`, with `input` written to what the command reads.
pub(crate) fn output_with_input(
    command: &mut Command,
    input: &[u8],
) -> Result<(i32, String), String> {
    finished(
        run_bounded_with_input(command, DOCKER_CALL_LIMIT, false, input)?,
        DOCKER_CALL_LIMIT,
    )
}

/// `output_of` with a limit of its own, and for cleanup, which still runs after Ctrl-C.
pub(crate) fn bounded_output(
    command: &mut Command,
    limit: Duration,
    cleanup: bool,
) -> Result<(i32, String), String> {
    finished(run_bounded(command, limit, cleanup)?, limit)
}

/// A bounded command's status and output, or why neither can be used: it was stopped, or it printed
/// more than `OUTPUT_LIMIT`. Every Docker call ends here, and a check that read the start of an
/// answer as the whole of it could judge the app on half a page, so cut output is never handed on.
fn finished(done: Bounded, limit: Duration) -> Result<(i32, String), String> {
    if done.stopped {
        return Err(format!(
            "it had not finished after {}, and was stopped",
            minutes(limit)
        ));
    }
    if done.cut {
        return Err(
            "it printed more than 32 MB, and sv does not keep more than that of anything"
                .to_owned(),
        );
    }
    Ok((done.code, done.text))
}

/// "10 minutes", for a limit a person reads.
pub fn minutes(limit: Duration) -> String {
    let m = limit.as_secs() / 60;
    if m == 1 {
        "1 minute".to_owned()
    } else if m > 0 {
        format!("{m} minutes")
    } else {
        format!("{} seconds", limit.as_secs())
    }
}

#[cfg(test)]
mod image_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_app_that_writes_outside_tmp_is_told_where_it_may_write() {
        let refused = CannotRun::NeverReady {
            waited_seconds: 60,
            detail: "Its last output was: OSError: [Errno 30] Read-only file system: '/data'"
                .to_owned(),
            loopback: None,
            crashed: false,
            exited: None,
        }
        .explain();
        assert!(refused.contains("keep its data under /tmp"), "{refused}");
        // Any other reason a start fails says nothing about the file system.
        let other = CannotRun::NeverReady {
            waited_seconds: 60,
            detail: "Its last output was: ModuleNotFoundError: No module named 'flask'".to_owned(),
            loopback: None,
            crashed: false,
            exited: None,
        }
        .explain();
        assert!(!other.contains("/tmp"), "{other}");
    }

    #[test]
    fn an_app_that_never_answers_is_told_about_listening_on_loopback() {
        // family-hub, 3 October 2026: the app listened on 127.0.0.1 and the message gave no hint.
        let unnamed = CannotRun::NeverReady {
            waited_seconds: 60,
            detail: "Its last output was: WARNING: This is a development server.".to_owned(),
            loopback: None,
            crashed: false,
            exited: None,
        }
        .explain();
        assert!(unnamed.contains("127.0.0.1 or localhost"), "{unnamed}");
        assert!(unnamed.contains("0.0.0.0"), "{unnamed}");
        assert!(unnamed.contains("One common cause"), "{unnamed}");
        // When the start command names the address, the message names it as the likely cause.
        let named = CannotRun::NeverReady {
            waited_seconds: 60,
            detail: "Its last output was: WARNING: This is a development server.".to_owned(),
            loopback: Some("127.0.0.1"),
            crashed: false,
            exited: None,
        }
        .explain();
        assert!(
            named.contains("Its start command names 127.0.0.1, which is the likely cause"),
            "{named}"
        );
        assert!(named.contains("0.0.0.0"), "{named}");
        // A cause already known from the app's own output is not crowded by a guess.
        let read_only = CannotRun::NeverReady {
            waited_seconds: 60,
            detail: "Its last output was: OSError: [Errno 30] Read-only file system: '/data'"
                .to_owned(),
            loopback: None,
            crashed: false,
            exited: None,
        }
        .explain();
        assert!(!read_only.contains("0.0.0.0"), "{read_only}");
        // An app that crashed is told its error is why, and not given a guess about where it
        // listens, even when its start command names a loopback address (the loop's item 6).
        let crashed = CannotRun::NeverReady {
            waited_seconds: 60,
            detail: "It stopped with an error: KeyError: 'PORT_NUMBER'".to_owned(),
            loopback: Some("127.0.0.1"),
            crashed: true,
            exited: None,
        }
        .explain();
        assert!(crashed.contains("That error is why"), "{crashed}");
        assert!(!crashed.contains("0.0.0.0"), "{crashed}");
    }

    #[test]
    fn a_start_command_naming_loopback_is_recognized_and_nothing_else_is() {
        for (start, named) in [
            ("uvicorn app:app --host 127.0.0.1 --port $PORT", "127.0.0.1"),
            ("flask run --host=127.0.0.1 --port=$PORT", "127.0.0.1"),
            ("gunicorn -b 127.0.0.1:$PORT app:app", "127.0.0.1"),
            ("httpd -f -h /app -p 127.0.0.1:$PORT", "127.0.0.1"),
            ("next start -H localhost -p $PORT", "localhost"),
            ("HOST=LocalHost node server.js", "localhost"),
            ("php -S localhost:$PORT -t public", "localhost"),
            ("hypercorn app:app --bind [::1]:$PORT", "::1"),
        ] {
            assert_eq!(loopback_named_in(start), Some(named), "{start}");
            let warning = loopback_warning(start).expect("a warning for a named loopback address");
            assert!(
                warning.contains(named) && warning.contains("0.0.0.0"),
                "{warning}"
            );
            assert!(warning.contains("Starting it anyway"), "{warning}");
        }
        for start in [
            "uvicorn app:app --host 0.0.0.0 --port $PORT",
            "httpd -f -h /app -p $PORT",
            "python app.py",
            "gunicorn -b 127.0.0.10:$PORT app:app",
            "gunicorn -b 10.127.0.0.1:$PORT app:app",
            "node server.js --name notlocalhost",
            "LOCALHOST_ONLY=0 node server.js",
            "hypercorn app:app --bind [fe80::1]:$PORT",
            "hypercorn app:app --bind [::]:$PORT",
        ] {
            assert_eq!(loopback_named_in(start), None, "{start}");
            assert_eq!(loopback_warning(start), None, "{start}");
        }
    }

    #[test]
    fn the_starter_files_example_start_command_is_one_sv_can_reach() {
        // The example an AI tool copies (family-hub did). Read through the same test `sv` warns with,
        // after checking the example is really there to read.
        let line = sv_manifest::spec::STARTER_MANIFEST
            .lines()
            .find(|l| l.starts_with("start = "))
            .expect("the starter file has a start line");
        let example = line
            .split_once("e.g. \"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(example, _)| example)
            .expect("the start line gives an example command");
        assert!(example.contains("$PORT"), "{example}");
        assert!(example.contains("0.0.0.0"), "{example}");
        assert_eq!(loopback_named_in(example), None, "{example}");
        assert!(
            sv_manifest::spec::STARTER_MANIFEST.contains("not 127.0.0.1 or localhost"),
            "the starter file says why"
        );
    }

    /// The spec tells the AI tool when `seed` runs: after the app answers on its health path, in the
    /// app's own container. The third prompts trial's brief said "before the app starts", and three
    /// builds that made their tables only in the seed could not start (BACKLOG, "The specification
    /// does not say when `seed` runs"). This holds the sentence to the order in the code, so moving
    /// the seed earlier fails here and points at the sentence to change.
    #[test]
    fn the_spec_says_the_seed_runs_after_the_health_check_and_it_does() {
        let spec = sv_manifest::spec::STARTER_MANIFEST;
        assert!(
            spec.contains("after the") && spec.contains("app answers on `health`, never before"),
            "the spec says when the seed runs"
        );
        // The harness waits for the health path, then hands the app to the script (8 October
        // 2026, `sv_check::script`), whose signed-in stage is where the seed is run.
        let docker = include_str!("docker.rs");
        let healthy = docker
            .find("let ready = self.wait_until_ready(&via, &app, plan);")
            .expect("the run waits for the app's health path");
        let script = docker
            .find("sv_check::script::run(")
            .expect("the script, which runs the seed");
        assert!(healthy < script, "the script runs after the health check");
        let script = include_str!("../../sv-check/src/script.rs");
        let in_signed_in = &script[script.find("\nfn signed_in(").unwrap()..];
        let in_signed_in = &in_signed_in[..in_signed_in[1..]
            .find("\nfn ")
            .map_or(in_signed_in.len(), |n| n + 1)];
        assert!(
            in_signed_in.contains("services.seed(Target::App, seed, accounts)"),
            "the signed-in stage is where the seed is run"
        );
        // And the seed comes after the anonymous questions, which see the app as a stranger.
        let anonymous = script
            .find("ask_anonymously_within(")
            .expect("the anonymous questions");
        let seeded = script.find("services.seed(Target::App").unwrap();
        assert!(
            anonymous < seeded,
            "the seed runs after the anonymous questions"
        );
    }

    #[test]
    fn a_start_command_that_weakens_the_app_is_warned_about_and_nothing_else_is() {
        // Each rule, and what is shown for it: the name, and the value only when it is a short
        // on-or-off word.
        for (start, named) in [
            // family-hub's, 3 October 2026.
            (
                "FAMILY_HUB_INSECURE_COOKIES=1 python app.py",
                vec!["FAMILY_HUB_INSECURE_COOKIES=1"],
            ),
            ("node server.js --insecure", vec!["--insecure"]),
            ("DISABLE_CSRF=true npm start", vec!["DISABLE_CSRF=true"]),
            ("AUTH_DISABLED=1 ./run", vec!["AUTH_DISABLED=1"]),
            ("SKIP_AUTH=yes uvicorn app:app", vec!["SKIP_AUTH=yes"]),
            ("app --no-verify", vec!["--no-verify"]),
            ("app --disable-rate-limit", vec!["--disable-rate-limit"]),
            (
                "SESSION_COOKIE_SECURE=False gunicorn app:app",
                vec!["SESSION_COOKIE_SECURE=False"],
            ),
            ("export CSRF_ENABLED=0; node .", vec!["CSRF_ENABLED=0"]),
            (
                "NODE_TLS_REJECT_UNAUTHORIZED='0' node .",
                vec!["NODE_TLS_REJECT_UNAUTHORIZED=0"],
            ),
            ("RATELIMIT_ENABLED=off app", vec!["RATELIMIT_ENABLED=off"]),
            // A value that is not a short on-or-off word is never shown: it could be a key.
            ("ALLOW_INSECURE=s3cr3tvalue app", vec!["ALLOW_INSECURE"]),
            // Several, each once, in the order written.
            (
                "INSECURE=1 DISABLE_AUTH=1 app --insecure && INSECURE=1 app",
                vec!["INSECURE=1", "DISABLE_AUTH=1", "--insecure"],
            ),
        ] {
            assert_eq!(weakening_named_in(start), named, "{start}");
            let warning = weakening_warning(start).expect("a warning");
            assert!(warning.contains(&format!("`{}`", named[0])), "{warning}");
            assert!(warning.contains("Starting it anyway"), "{warning}");
            assert!(weakening_note(start).is_some(), "{start}");
        }
        assert!(
            weakening_warning("INSECURE=1 DISABLE_AUTH=1 app --insecure")
                .unwrap()
                .contains("`INSECURE=1`, `DISABLE_AUTH=1`, and `--insecure`")
        );
        assert!(
            !weakening_warning("ALLOW_INSECURE=s3cr3tvalue app")
                .unwrap()
                .contains("s3cr3t")
        );
        // Nothing about security switched off: no warning.
        for start in [
            "python app.py",
            "uvicorn app:app --host 0.0.0.0 --port $PORT",
            "NEXT_TELEMETRY_DISABLED=1 npm start",
            "pip install --no-cache-dir -r requirements.txt && python app.py",
            "node --disable-warning=ExperimentalWarning server.js",
            "AUTH_SECRET=abc123 SECURE_COOKIES=1 node .",
            "CSRF_ENABLED=true SESSION_COOKIE_SECURE=True gunicorn app:app",
            "DEBUG=1 flask run --host 0.0.0.0",
            "npm ci --no-audit && npm start",
            "RATE=0 LIMIT=0 app",
            "./secure-start.sh",
            "",
        ] {
            assert_eq!(weakening_named_in(start), Vec::<String>::new(), "{start}");
            assert_eq!(weakening_warning(start), None, "{start}");
            assert_eq!(weakening_note(start), None, "{start}");
        }
    }

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn a_command_that_takes_too_long_is_stopped_and_says_so() {
        let started = Instant::now();
        let done = run_bounded(
            &mut sh("echo begun; sleep 30"),
            Duration::from_millis(400),
            false,
        )
        .expect("it starts");
        assert!(done.stopped, "{done:?}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        // What it printed before it was stopped is kept: it is where a hung suite says how far it got.
        assert!(done.text.contains("begun"), "{done:?}");
        let said =
            bounded_output(&mut sh("sleep 30"), Duration::from_millis(300), false).unwrap_err();
        assert!(said.contains("had not finished after"), "{said}");
    }

    #[test]
    fn a_command_that_finishes_hands_back_both_streams_and_its_status() {
        // The control for the test above: the same machinery, not stopped.
        let done = run_bounded(
            &mut sh("echo out; echo err >&2; exit 3"),
            Duration::from_secs(20),
            false,
        )
        .unwrap();
        assert!(!done.stopped);
        assert_eq!(done.code, 3);
        assert!(
            done.text.contains("out") && done.text.contains("err"),
            "{done:?}"
        );
        // More than a pipe holds, on both streams at once: read while it runs, or it never ends.
        let done = run_bounded(
            &mut sh("head -c 3000000 /dev/zero | tr '\\0' a; head -c 3000000 /dev/zero | tr '\\0' b >&2"),
            Duration::from_secs(20),
            false,
        )
        .unwrap();
        assert!(!done.stopped, "it filled a pipe and hung");
        assert_eq!(done.text.len(), 6_000_000);
        assert!(!done.cut);
        assert!(bounded_output(&mut sh("exit 0"), Duration::from_secs(20), false).is_ok());
    }

    #[test]
    fn output_past_the_limit_is_read_and_not_kept() {
        // The limit itself, on something whose length is known.
        let mut long: &[u8] = &[b'a'; 100];
        assert_eq!(read_capped(&mut long, 40), (vec![b'a'; 40], true));
        let mut exact: &[u8] = &[b'a'; 40];
        assert_eq!(read_capped(&mut exact, 40), (vec![b'a'; 40], false));
        // A command that prints more than `OUTPUT_LIMIT`: it still ends (the rest is read and
        // thrown away), what is kept stops at the limit and says so, and nothing hands it on as an
        // answer.
        let over = OUTPUT_LIMIT + 5_000_000;
        let script = format!("head -c {over} /dev/zero | tr '\\0' a; echo err >&2");
        let done = run_bounded(&mut sh(&script), Duration::from_secs(60), false).unwrap();
        assert!(!done.stopped, "it filled a pipe and hung");
        assert!(done.cut, "{}", done.text.len());
        assert!(done.text.contains(CUT_NOTE));
        assert!(
            done.text.ends_with("err\n"),
            "the other stream is still read"
        );
        let kept = done.text.bytes().take_while(|b| *b == b'a').count() as u64;
        assert_eq!(kept, OUTPUT_LIMIT);
        let refused = bounded_output(&mut sh(&script), Duration::from_secs(60), false).unwrap_err();
        assert!(refused.contains("more than 32 MB"), "{refused}");
    }

    #[test]
    fn a_stopped_command_leaves_nothing_it_started_running() {
        let dir = std::env::temp_dir().join(format!("sv-bounded-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_file = dir.join("pid");
        // Its output sent elsewhere, so it is only the stopping that can end it, not the pipes. On
        // Windows the shell's own number for the child (`$!`) is not Windows' number, so the
        // shell's `/proc` gives Windows' instead, for Windows to be asked about (backlog 0120).
        let which = if cfg!(windows) {
            "cat /proc/$!/winpid"
        } else {
            "echo $!"
        };
        let script = format!(
            "sleep 30 >/dev/null 2>&1 & {which} > '{}'; wait",
            pid_file.display()
        );
        let done = run_bounded(&mut sh(&script), Duration::from_millis(500), false).unwrap();
        assert!(done.stopped);
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .to_owned();
        std::fs::remove_dir_all(&dir).ok();
        // The control is `pid` itself: it was written, so the child really was started.
        assert!(!pid.is_empty());
        std::thread::sleep(Duration::from_millis(200));
        // A killed process nobody has collected yet is a zombie: dead, and still answering `kill -0`.
        // Where `/proc` says, a zombie is not running; elsewhere, `kill -0` is the question.
        #[cfg(windows)]
        let alive = {
            let running = |pid: &str| {
                let listed = Command::new("tasklist")
                    .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
                    .output()
                    .unwrap();
                assert!(listed.status.success(), "tasklist did not answer");
                String::from_utf8_lossy(&listed.stdout).contains(&format!(",\"{pid}\","))
            };
            // The control: the question finds a process that is running, this test's own.
            assert!(running(&std::process::id().to_string()));
            running(&pid)
        };
        #[cfg(not(windows))]
        let alive = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat
                .rsplit_once(')')
                .is_some_and(|(_, rest)| !rest.trim_start().starts_with('Z')),
            Err(_) if std::path::Path::new("/proc/self").exists() => false,
            Err(_) => Command::new("kill")
                .args(["-0", &pid])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success(),
        };
        assert!(!alive, "the command's own child {pid} is still running");
    }

    #[test]
    fn a_command_that_cannot_start_says_why() {
        let said = run_bounded(
            &mut Command::new("/no/such/program"),
            Duration::from_secs(5),
            false,
        )
        .unwrap_err();
        assert!(!said.is_empty());
    }

    #[test]
    fn the_test_limit_is_ten_minutes_unless_securevibe_toml_says_otherwise() {
        let limit = |seconds: Option<u64>| {
            let mut m = Manifest::default();
            m.stack.run.image = Some("busybox:1.36".to_owned());
            m.stack.run.start = Some("true".to_owned());
            m.stack.run.test_time_limit = seconds;
            RunPlan::from_manifest(&m, Path::new("."))
                .unwrap()
                .test_limit
        };
        assert_eq!(limit(None), TEST_LIMIT);
        assert_eq!(limit(Some(0)), TEST_LIMIT, "no time at all is not a limit");
        assert_eq!(limit(Some(45)), Duration::from_secs(45));
        // And the setting is read under its written name.
        let m: Manifest = toml::from_str("[stack.run]\ntest-time-limit = 90\n").unwrap();
        assert_eq!(m.stack.run.test_time_limit, Some(90));
    }

    #[test]
    fn limits_are_written_for_a_person() {
        assert_eq!(minutes(TEST_LIMIT), "10 minutes");
        assert_eq!(minutes(DOCKER_CALL_LIMIT), "20 minutes");
        assert_eq!(minutes(Duration::from_secs(60)), "1 minute");
        assert_eq!(minutes(Duration::from_secs(3)), "3 seconds");
    }

    #[test]
    fn admin_actions_alone_make_an_admin_to_send_them_as() {
        // The documentation review of 6 October 2026, item 3: only admin pages made an admin, so
        // admin actions listed without them were never asked.
        let users = |extra: &str| -> sv_manifest::UsersSection {
            let m: Manifest = toml::from_str(&format!(
                "[stack.run.users]\nlogin = {{ path = \"/login\", form = {{ email = \"{{user}}\", \
                 password = \"{{password}}\" }} }}\nseed = \"python seed.py\"\nprivate = [\"/account\"]\n{extra}"
            ))
            .unwrap();
            m.stack.run.users.unwrap()
        };
        let actions = users(
            "[[stack.run.users.admin-actions]]\nmethod = \"POST\"\npath = \"/admin/notes/{marker}/delete\"\n",
        );
        assert!(!actions.admin_actions.is_empty() && actions.admin.is_empty());
        assert!(accounts_for(&actions).admin.is_some());
        assert!(
            accounts_for(&users("admin = [\"/admin\"]\n"))
                .admin
                .is_some()
        );
        // The control: neither, no admin.
        assert!(accounts_for(&users("")).admin.is_none());
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
        let admin_secret = one
            .admin_totp_secret
            .as_ref()
            .expect("the admin gets a two-factor secret when there is a two-factor step");
        assert_eq!(admin_secret.len(), 20);
        assert_ne!(
            admin_secret, &totp.secret,
            "the admin's secret is not the two-factor account's"
        );
        assert!(admin_secret.iter().any(|b| *b != 0));
        assert!(
            new_accounts(true, false).admin_totp_secret.is_none(),
            "no admin secret without a two-factor step"
        );
        assert!(
            new_accounts(false, true).admin_totp_secret.is_none(),
            "no admin secret without an admin"
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
    fn a_backend_that_is_missing_or_refuses_says_what_to_do() {
        // Backlog 226, part 2, item 16: what failed, what it means, and what to do.
        for reason in [
            CannotRun::NoBackend {
                checked: "`docker` could not be started".into(),
            },
            CannotRun::BackendFailed {
                detail: "Cannot connect to the Docker daemon".into(),
            },
        ] {
            let text = reason.explain();
            assert!(text.contains("not assessed"), "{text}");
            assert!(text.contains("run this again"), "{text}");
            assert!(text.contains("`sv doctor`"), "{text}");
            assert!(text.contains("Colima") || text.contains("colima"), "{text}");
        }
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
                loopback: None,
                crashed: false,
                exited: None,
            },
            CannotRun::NeverReady {
                waited_seconds: 30,
                detail: "no reply".into(),
                loopback: Some("localhost"),
                crashed: false,
                exited: None,
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

#[cfg(test)]
mod unseen_folder_tests {
    use super::*;

    fn scratch(name: &str, with_file: bool) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-unseen-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        if with_file {
            std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
        }
        dir
    }

    #[test]
    fn a_folder_with_files_that_is_empty_inside_is_named_as_unseen() {
        // On Linux every folder is shared, so the container's side is a stand-in: told empty.
        let dir = scratch("unseen", true);
        let unseen = unseen_folder(&dir, Some("")).expect("empty inside, files here");
        let said = unseen.explain();
        assert!(said.contains(&dir.display().to_string()), "{said}");
        assert!(
            said.contains("Colima") && said.contains("not assessed"),
            "{said}"
        );
        assert!(
            !said.contains("never answered"),
            "the app is not blamed: {said}"
        );

        // The controls: the files seen inside, the listing not asked, and an empty folder here.
        assert!(unseen_folder(&dir, Some("app.py\n")).is_none());
        assert!(
            unseen_folder(&dir, None).is_none(),
            "not knowing is not the same as empty"
        );
        let empty = scratch("empty", false);
        assert!(
            unseen_folder(&empty, Some("")).is_none(),
            "a folder with nothing in it is empty everywhere"
        );
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&empty).ok();
    }
}
