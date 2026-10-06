//! `sv preflight` and `securevibe_preflight`: what `sv run` will need, looked for in the code, with
//! nothing run (ADR-035).
//!
//! `sv run` can test an app only if the app gives it what `[stack.run]` says: a server listening on
//! every address at `$PORT`, a seed that makes the `SV_` accounts, the sign-in form at the path and
//! with the fields the settings give, and tables the app makes for itself. Each of these failed in
//! the prompts trials, and each was found only by running the app after the build was over. Here
//! they are looked for in the text of the app's files, so the AI tool that wrote them can fix them in
//! the same conversation, and the MCP server still never starts the app.
//!
//! It also hints at some of what `sv run` will test (a limit on wrong passwords, the security
//! headers, the session cookie's SameSite, an AI feature's screening, limit, and off switch), which the
//! code often shows before anything runs (`tested`).
//!
//! Every answer is a reading of text, and says so: "looks right" means the thing was found, not
//! that it works. Nothing here is evidence for any requirement, and nothing is credited.

use serde_json::{Value, json};
use std::path::Path;
use sv_manifest::Manifest;
use sv_report::fence::Fence;
use sv_scan::files::Listing;

/// What one look found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Answer {
    /// Something `sv run` needs, or will test for, appears to be missing or wrong.
    Look,
    /// The text could not settle it either way.
    Unknown,
    /// What `sv run` needs, or will test for, was found in the text. Not that it works.
    Looks,
}

impl Answer {
    pub fn id(self) -> &'static str {
        match self {
            Answer::Look => "look-at-this",
            Answer::Unknown => "could-not-tell",
            Answer::Looks => "looks-right",
        }
    }

    fn words(self) -> &'static str {
        match self {
            Answer::Look => "look at this",
            Answer::Unknown => "could not tell",
            Answer::Looks => "looks right",
        }
    }
}

/// A piece of what an item says: `sv`'s own words, or text from the app, which is fenced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Sv(String),
    App(String),
}

/// One thing `sv run` needs, and what was found about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// What was looked at: `start`, `listen`, `port`, `seed`, `accounts`, `tables`, `path`, `field`,
    /// `users` for what `sv run` needs; `TESTED` for what it will test.
    pub topic: &'static str,
    pub answer: Answer,
    pub says: Vec<Part>,
}

/// The topics that are what `sv run` will test, not what it needs to run.
const TESTED: &[&str] = &[
    "headers",
    "sign-in-limit",
    "cookie",
    "ai-screening",
    "ai-limit",
    "kill-switch",
];

impl Item {
    /// Whether this is something `sv run` will test, rather than something it needs to run.
    pub fn tested(&self) -> bool {
        TESTED.contains(&self.topic)
    }

    fn new(topic: &'static str, answer: Answer, says: Vec<Part>) -> Item {
        Item {
            topic,
            answer,
            says,
        }
    }

    fn text(&self, fence: &Fence) -> String {
        self.says
            .iter()
            .map(|part| match part {
                Part::Sv(text) => text.clone(),
                Part::App(text) => fence.wrap(text),
            })
            .collect()
    }
}

fn sv(text: impl Into<String>) -> Part {
    Part::Sv(text.into())
}

fn app(text: impl Into<String>) -> Part {
    Part::App(text.into())
}

/// The app's files that are read: text the app is made of, leaving out what only describes it
/// (`securevibe.toml`, the security notes, Markdown and plain text), where a path or a variable named
/// in prose would read as found.
pub struct Source {
    pub files: Vec<(String, String)>,
    /// Files not read, because they are too large or not text, by path.
    pub unread: Vec<String>,
}

const DESCRIBES: &[&str] = &["md", "markdown", "txt", "rst"];

impl Source {
    pub fn of(listing: &Listing) -> Source {
        let mut files = Vec::new();
        let mut unread = Vec::new();
        for entry in listing.app_files() {
            let name = entry.file_name();
            if name == "securevibe.toml"
                || entry
                    .extension
                    .as_deref()
                    .is_some_and(|ext| DESCRIBES.contains(&ext))
            {
                continue;
            }
            if entry.too_large() {
                unread.push(entry.relative.clone());
                continue;
            }
            // A file that is not text (an image, a database) holds no path or variable to find.
            if let Ok(text) = entry.read_text() {
                files.push((entry.relative.clone(), text));
            }
        }
        Source { files, unread }
    }

    /// The first file, other than `except`, whose text holds `needle` by `holds`.
    fn find(&self, except: Option<&str>, holds: impl Fn(&str) -> bool) -> Option<&str> {
        self.files
            .iter()
            .filter(|(name, _)| Some(name.as_str()) != except)
            .find(|(_, text)| holds(text))
            .map(|(name, _)| name.as_str())
    }

    /// The first file, lockfiles left out, whose squashed text holds one of `words` (`squash`).
    fn find_word(&self, words: &[&str]) -> Option<&str> {
        self.files
            .iter()
            .filter(|(name, _)| !lockfile(name))
            .find(|(_, text)| {
                let text = squash(text);
                words.iter().any(|word| text.contains(word))
            })
            .map(|(name, _)| name.as_str())
    }

    fn text_of(&self, relative: &str) -> Option<&str> {
        self.files
            .iter()
            .find(|(name, _)| name == relative)
            .map(|(_, text)| text.as_str())
    }
}

/// `text` holds `word` between quotes of any kind, as a route, a key, or a field name is written.
fn quoted(text: &str, word: &str) -> bool {
    ['"', '\'', '`']
        .iter()
        .any(|q| text.contains(&format!("{q}{word}{q}")))
}

/// A path as code names it: quoted whole, or, for a path with a trailing slash or a query, its stem.
fn names_path(text: &str, path: &str) -> bool {
    let stem = path.split(['?', '#']).next().unwrap_or(path);
    let trimmed = stem.trim_end_matches('/');
    quoted(text, stem) || (!trimmed.is_empty() && quoted(text, trimmed))
}

/// A form field as code or a template names it: quoted, or as an HTML `name=` without quotes.
fn names_field(text: &str, field: &str) -> bool {
    quoted(text, field)
        || text.contains(&format!("name={field} "))
        || text.contains(&format!("name={field}>"))
}

/// The files a command runs, as the command names them: words that end in a file name the folder
/// has, or look like one (`seed.py`, `scripts/seed.js`).
fn files_in_command(command: &str, source: &Source) -> (Vec<String>, Vec<String>) {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for word in command.split_whitespace() {
        let word = word.trim_matches(|c| c == '"' || c == '\'');
        let word = word.strip_prefix("./").unwrap_or(word);
        let looks_like_file = word.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty()
                && [
                    "py", "js", "mjs", "cjs", "ts", "rb", "php", "sh", "go", "java", "pl",
                ]
                .contains(&ext)
        });
        if source.text_of(word).is_some() {
            found.push(word.to_owned());
        } else if looks_like_file {
            missing.push(word.to_owned());
        }
    }
    (found, missing)
}

/// Looks for each thing `sv run` will need, and for what it will test that the code already shows,
/// in `source`, as `manifest` asks for it.
pub fn preflight(manifest: &Manifest, source: &Source) -> Vec<Item> {
    let mut items = needs(manifest, source);
    items.extend(tested(manifest, source));
    sorted(items)
}

/// What `sv run` needs from the app to start it and sign in.
fn needs(manifest: &Manifest, source: &Source) -> Vec<Item> {
    let run = &manifest.stack.run;
    let mut items = Vec::new();
    let set = |value: &Option<String>| {
        value
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };

    // Start.
    let start = set(&run.start);
    match (set(&run.image), &start) {
        (Some(_), Some(_)) => items.push(Item::new(
            "start",
            Answer::Looks,
            vec![sv("[stack.run] has an image and a start command.")],
        )),
        _ => items.push(Item::new(
            "start",
            Answer::Look,
            vec![sv(
                "[stack.run] needs both `image` and `start`. Without them `sv run` cannot start the app, and every check of the running app is reported as not assessed.",
            )],
        )),
    }
    let start = start.unwrap_or_default();
    // The file the start command runs, named the way the seed's is: two loop builds wrote
    // `start = "python app.py"` with no `app.py`, and `sv run` could not start them (6 October 2026).
    for file in files_in_command(&start, source).1 {
        let mut words = vec![
            sv("The start command names "),
            app(file),
            sv(", which is not in the app's folder."),
        ];
        if let Some(build) = set(&run.build) {
            words.push(sv(format!(
                " If the build step (`{build}`) makes it, ignore this."
            )));
        }
        items.push(Item::new("start", Answer::Look, words));
    }

    // Listening on every address.
    let everywhere =
        |text: &str| text.contains("0.0.0.0") || text.contains("\"::\"") || text.contains("'::'");
    let loopback = |text: &str| text.contains("127.0.0.1") || quoted(text, "localhost");
    if everywhere(&start) {
        items.push(Item::new(
            "listen",
            Answer::Looks,
            vec![sv("The start command listens on every address.")],
        ));
    } else if let Some(file) = source.find(None, everywhere) {
        items.push(Item::new(
            "listen",
            Answer::Looks,
            vec![
                sv("Every address (`0.0.0.0`) is named in "),
                app(file),
                sv("."),
            ],
        ));
    } else if let Some(file) = source
        .find(None, loopback)
        .map(str::to_owned)
        .or_else(|| loopback(&start).then(|| "the start command".to_owned()))
    {
        items.push(Item::new(
            "listen",
            Answer::Look,
            vec![
                sv("Only the loopback address (`127.0.0.1` or `localhost`) is named, in "),
                app(file),
                sv(", and not `0.0.0.0`. `sv` asks the app from a second container, so an app listening on loopback never answers. If it listens on every address another way, ignore this."),
            ],
        ));
    } else {
        items.push(Item::new(
            "listen",
            Answer::Unknown,
            vec![sv("No address the app listens on was found. It must listen on `0.0.0.0`, every address, for `sv` to reach it.")],
        ));
    }

    // The port.
    let port = |text: &str| {
        quoted(text, "PORT")
            || text.contains("$PORT")
            || text.contains("${PORT")
            || text.contains("env.PORT")
    };
    if port(&start) {
        items.push(Item::new(
            "port",
            Answer::Looks,
            vec![sv("The start command uses `$PORT`.")],
        ));
    } else if let Some(file) = source.find(None, port) {
        items.push(Item::new(
            "port",
            Answer::Looks,
            vec![sv("`PORT` is read in "), app(file), sv(".")],
        ));
    } else {
        items.push(Item::new(
            "port",
            Answer::Look,
            vec![sv("Nothing reads `PORT`. `sv` gives the app its port in the environment variable `PORT`, and asks it there.")],
        ));
    }

    // The health path.
    if let Some(health) = set(&run.health).filter(|h| h != "/") {
        items.push(path_item("health", &health, source));
    }

    let Some(users) = &run.users else {
        items.push(Item::new(
            "users",
            Answer::Unknown,
            vec![sv("There is no [stack.run.users], so nothing about signing in was looked for, and `sv run` will report what a signed-in user can reach as not assessed.")],
        ));
        return items;
    };

    // The seed: its file, the accounts it is given, and where the tables are made.
    if let Some(seed) = set(&users.seed) {
        let (found, missing) = files_in_command(&seed, source);
        for file in &missing {
            items.push(Item::new(
                "seed",
                Answer::Look,
                vec![
                    sv("The seed command names "),
                    app(file.clone()),
                    sv(", which is not in the app's folder."),
                ],
            ));
        }
        let seed_file = found.first().cloned();
        if seed_file.is_none() && missing.is_empty() {
            items.push(Item::new(
                "seed",
                Answer::Unknown,
                vec![sv("Could not tell which file the seed command runs, so the accounts it makes were looked for in every file.")],
            ));
        }
        let mut accounts = vec!["SV_USER_A", "SV_PASSWORD_A", "SV_USER_B", "SV_PASSWORD_B"];
        if !users.admin.is_empty() || !users.admin_actions.is_empty() {
            accounts.extend(["SV_ADMIN", "SV_ADMIN_PASSWORD"]);
        }
        let seed_text = seed_file.as_deref().and_then(|f| source.text_of(f));
        let unread: Vec<&str> = accounts
            .iter()
            .copied()
            .filter(|name| match seed_text {
                Some(text) => !names(text, name) && source.find(None, |t| names(t, name)).is_none(),
                None => source.find(None, |t| names(t, name)).is_none(),
            })
            .collect();
        if unread.is_empty() {
            items.push(Item::new(
                "accounts",
                Answer::Looks,
                vec![sv(format!(
                    "The seed's accounts are read: {}.",
                    accounts.join(", ")
                ))],
            ));
        } else {
            items.push(Item::new(
                "accounts",
                Answer::Look,
                vec![sv(format!(
                    "Nothing reads {}. `sv` gives the seed the accounts it signs in with in these variables, with fresh passwords each run; a seed that makes its own accounts makes ones `sv` cannot sign in to. If the names are built from parts, ignore this.",
                    unread.join(", ")
                ))],
            ));
        }
        let started = files_in_command(&start, source).0;
        if let (Some(file), Some(text)) = (seed_file.as_deref(), seed_text) {
            let makes = |t: &str| t.to_ascii_lowercase().contains("create table");
            if started.iter().any(|f| f == file) {
                // `python app.py seed`: the seed is the app's own file, so whether it makes its
                // tables when it starts or only when it seeds is not in the text.
                items.push(Item::new(
                    "tables",
                    Answer::Unknown,
                    vec![
                        sv("The seed runs "),
                        app(file),
                        sv(", the file the app starts from, so whether the app makes its tables when it starts, or only when it seeds, could not be told. `sv` runs the seed after the app answers on `health`: the tables must be there before."),
                    ],
                ));
            } else if makes(text) && source.find(Some(file), makes).is_none() {
                items.push(Item::new(
                    "tables",
                    Answer::Look,
                    vec![
                        sv("Tables are made in "),
                        app(file),
                        sv(" and in no other file. `sv` runs the seed after the app answers on `health`, so the app must make its own tables when it starts, or its first page fails."),
                    ],
                ));
            } else if let Some(other) = source.find(Some(file), makes) {
                items.push(Item::new(
                    "tables",
                    Answer::Looks,
                    vec![
                        sv("Tables are made in "),
                        app(other),
                        sv(", not only in the seed."),
                    ],
                ));
            }
        }
    } else if users.signup.is_none() {
        items.push(Item::new(
            "seed",
            Answer::Look,
            vec![sv("[stack.run.users] has neither `seed` nor `signup`, so `sv` has no way to make the accounts it signs in with.")],
        ));
    }

    // Every path the settings name, and the fields of the forms `sv` signs up and in with.
    let mut paths: Vec<(&'static str, String)> = Vec::new();
    for (what, template) in [
        ("sign-in", &users.login),
        ("sign-up", &users.signup),
        ("sign-out", &users.logout),
    ] {
        if let Some(t) = template {
            paths.push((what, t.path.clone()));
        }
    }
    paths.extend(users.private.iter().map(|p| ("private page", p.clone())));
    paths.extend(users.admin.iter().map(|p| ("admin page", p.clone())));
    for action in &users.admin_actions {
        paths.push(("admin action", action.path.clone()));
        if let Some(check) = &action.check {
            paths.push(("admin action's check", check.clone()));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for (what, path) in paths {
        if seen.insert(path.clone()) {
            items.push(path_item(what, &path, source));
        }
    }
    for (what, template) in [("sign-in", &users.login), ("sign-up", &users.signup)] {
        let Some(t) = template else { continue };
        let missing: Vec<&String> = t
            .form
            .keys()
            .chain(t.json.keys())
            .filter(|field| source.find(None, |text| names_field(text, field)).is_none())
            .collect();
        if missing.is_empty() {
            continue;
        }
        let mut says = vec![sv(format!("The {what} form's fields "))];
        for (i, field) in missing.iter().enumerate() {
            if i > 0 {
                says.push(sv(", "));
            }
            says.push(app((*field).clone()));
        }
        says.push(sv(" appear in no file. `sv` sends exactly the fields the settings list, so a field the app names differently is a sign-in that fails."));
        items.push(Item::new("field", Answer::Look, says));
    }
    items
}

/// What `sv run` will test that is often visible in the code before anything runs: a limit on wrong
/// passwords, the security headers, the session cookie's SameSite, and an AI feature's screening, limit,
/// and off switch. The loop trials' builders fixed nearly everything the check named in their code and
/// left their running apps with as many problems as every other arm's, because only the run looks for
/// these (BACKLOG, "Tell the builder, before it is done, what the code already shows about the running
/// app"). A word found is a hint that the thing is there, never that it works, and a word missing
/// is a hint it is not: the run is the evidence, and nothing here is credited.
fn tested(manifest: &Manifest, source: &Source) -> Vec<Item> {
    let run = &manifest.stack.run;
    let mut items = Vec::new();

    // The four headers `sv run` reads on the health path and the root page (`missing_headers` in
    // `sv-check/src/probes.rs`): each named by itself, or set by a library that sends it.
    const EVERY_HEADER: &[&str] = &["helmet", "talisman", "secureheaders"];
    const SPRING: &[&str] = &["springbootstartersecurity", "enablewebsecurity"];
    let headers: [(&str, Vec<&str>); 4] = [
        (
            "Content-Security-Policy",
            [
                &["contentsecuritypolicy", "cspdefaultsrc"][..],
                EVERY_HEADER,
            ]
            .concat(),
        ),
        (
            "X-Content-Type-Options",
            [
                &["xcontenttypeoptions", "nosniff", "securitymiddleware"][..],
                EVERY_HEADER,
                SPRING,
            ]
            .concat(),
        ),
        (
            "a rule against being framed (X-Frame-Options or frame-ancestors)",
            [
                &["xframeoptions", "frameancestors"][..],
                EVERY_HEADER,
                SPRING,
            ]
            .concat(),
        ),
        (
            "Referrer-Policy",
            [&["referrerpolicy", "securitymiddleware"][..], EVERY_HEADER].concat(),
        ),
    ];
    let mut named = Vec::new();
    let mut unnamed = Vec::new();
    for (header, words) in &headers {
        match source.find_word(words) {
            Some(file) => named.push((*header, file)),
            None => unnamed.push(*header),
        }
    }
    if unnamed.is_empty() {
        let mut says = vec![sv(
            "The four security headers `sv run` looks for are named in the code: ",
        )];
        for (i, (header, file)) in named.iter().enumerate() {
            if i > 0 {
                says.push(sv("; "));
            }
            says.push(sv(format!("{header} in ")));
            says.push(app(*file));
        }
        says.push(sv("."));
        items.push(Item::new("headers", Answer::Looks, says));
    } else {
        items.push(Item::new(
            "headers",
            Answer::Look,
            vec![sv(format!(
                "`sv run` asks the app's pages for four security headers, and the code names none of these, or a library that sends them: {}. If the framework or a server in front of the app sends them, ignore this.",
                unnamed.join("; ")
            ))],
        ));
    }

    // A limit on wrong passwords, and the session cookie's SameSite, only where `sv run` signs in.
    if run.users.as_ref().is_some_and(|u| u.login.is_some()) {
        let from = items.len();
        match source.find_word(LIMITS) {
            Some(file) => items.push(Item::new(
                "sign-in-limit",
                Answer::Looks,
                vec![
                    sv("A limit on requests is named in "),
                    app(file),
                    sv(". `sv run` sends more wrong passwords to the sign-in than `failed-sign-ins` under [policy] allows, and looks for the limit to start; whether this one covers the sign-in is not in the text."),
                ],
            )),
            None => items.push(Item::new(
                "sign-in-limit",
                Answer::Look,
                vec![sv("No limit on requests or on failed sign-ins is named in the code. `sv run` sends wrong passwords to the sign-in, and an app that answers every one the same way is a finding: count the failures per account and per address, and refuse for a while past the number `failed-sign-ins` under [policy] states.")],
            )),
        }
        if manifest.policy.failed_sign_ins.is_none() {
            unstated(&mut items[from..], "sign-in-limit", "failed-sign-ins");
        }
        if let Some(file) = source.find_word(&["samesite"]) {
            items.push(Item::new(
                "cookie",
                Answer::Looks,
                vec![sv("SameSite is set in "), app(file), sv(".")],
            ));
        } else if let Some(framework) = sets_same_site_itself(source) {
            items.push(Item::new(
                "cookie",
                Answer::Unknown,
                vec![sv(format!(
                    "SameSite is named nowhere, and {framework} sets it on its own session cookie unless told otherwise, so whether the cookie carries it could not be told from the text."
                ))],
            ));
        } else {
            items.push(Item::new(
                "cookie",
                Answer::Look,
                vec![sv("SameSite is named nowhere. `sv run` reads the cookies the app sets at sign-in and looks for HttpOnly and SameSite (Lax or Strict) on each; most frameworks set HttpOnly themselves, few set SameSite.")],
            ));
        }
    }

    // The AI feature: screening what people type, a limit of its own, and the off switch.
    if let Some(ai) = &run.ai {
        let ai_from = items.len();
        match source.find_word(SCREENS) {
            Some(file) => items.push(Item::new(
                "ai-screening",
                Answer::Looks,
                vec![
                    sv("Screening of what people send the model is named in "),
                    app(file),
                    sv(". `sv run` sends messages written to take the model over, and looks whether they reach it."),
                ],
            )),
            None => items.push(Item::new(
                "ai-screening",
                Answer::Look,
                vec![sv("Nothing that screens what people send the model (a prompt-injection check, a moderation call, a guardrail) is named in the code. `sv run` sends messages written to take the model over, and one that reaches the model untouched is a finding.")],
            )),
        }
        match source.find_word(LIMITS) {
            Some(file) => items.push(Item::new(
                "ai-limit",
                Answer::Unknown,
                vec![
                    sv("A limit on requests is named in "),
                    app(file),
                    sv(", and whether it limits the AI feature on its own, apart from the rest of the app, could not be told. `sv run` sends the feature more messages than `ai-requests-per-minute` under [policy] allows, and looks for a limit on the feature alone."),
                ],
            )),
            None => items.push(Item::new(
                "ai-limit",
                Answer::Look,
                vec![sv("No limit on requests is named in the code. `sv run` sends the AI feature more messages than `ai-requests-per-minute` under [policy] allows, and a feature that answers every one is a finding.")],
            )),
        }
        if manifest.policy.ai_requests_per_minute.is_none() {
            unstated(&mut items[ai_from..], "ai-limit", "ai-requests-per-minute");
        }
        if let Some(name) = ai
            .kill_switch
            .as_deref()
            .and_then(|s| s.split_once('=').map(|(n, _)| n.trim()))
            .filter(|n| !n.is_empty())
        {
            match source.find(None, |t| names(t, name)) {
                Some(file) => items.push(Item::new(
                    "kill-switch",
                    Answer::Looks,
                    vec![sv("The off switch "), app(name), sv(" is read in "), app(file), sv(".")],
                )),
                None => items.push(Item::new(
                    "kill-switch",
                    Answer::Look,
                    vec![
                        sv("Nothing reads "),
                        app(name),
                        sv(", the off switch the settings name. `sv run` starts a second copy of the app with it set, and that copy must answer without calling the model."),
                    ],
                )),
            }
        }
    }
    items
}

/// The number a limit is held to is the owner's to state, and with none `sv run` does not try the
/// limit at all: the item says so, whatever the code shows.
fn unstated(items: &mut [Item], topic: &str, setting: &str) {
    for item in items.iter_mut().filter(|i| i.topic == topic) {
        item.says.push(sv(format!(
            " `{setting}` under [policy] is not set, so `sv run` will not try this and will report it not assessed: the owner says the number."
        )));
    }
}

/// Words that name a limit on requests or on failed sign-ins, squashed as `squash` writes them:
/// the common libraries (`express-rate-limit`, `flask_limiter`, `slowapi`, `Rack::Attack`,
/// `django-axes`, Laravel's `throttle`), and the words a limit written by hand is named with.
const LIMITS: &[&str] = &[
    "ratelimit",
    "limiter",
    "throttl",
    "rack::attack",
    "djangoaxes",
    "bruteforce",
    "loginattempt",
    "failedattempt",
    "failedlogin",
    "failedsignin",
    "maxattempt",
    "lockout",
    "toomanyrequests",
    "toomanyattempts",
];

/// Words that name screening of what is sent to a model.
const SCREENS: &[&str] = &[
    "promptinjection",
    "jailbreak",
    "ignorepreviousinstructions",
    "ignoreallpreviousinstructions",
    "guardrail",
    "llmguard",
    "promptguard",
    "lakera",
    "rebuff",
    "moderation",
];

/// The framework, when the app is built on one that puts SameSite on its session cookie by default:
/// Django and Rails both send `SameSite=Lax` unless told otherwise.
fn sets_same_site_itself(source: &Source) -> Option<&'static str> {
    let has = |file: &str, word: &str| {
        source
            .files
            .iter()
            .any(|(name, text)| name.rsplit('/').next() == Some(file) && text.contains(word))
    };
    if source.find(None, |t| t.contains("django.")).is_some() {
        Some("Django")
    } else if has("Gemfile", "rails") {
        Some("Rails")
    } else {
        None
    }
}

/// Text lowered, with the `-`, `_`, and spaces that tell `X-Frame-Options` from `X_FRAME_OPTIONS`
/// and `XFrameOptionsMiddleware`, and `rate limit` from `rateLimit`, taken out.
fn squash(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '-' | '_' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// A lockfile lists every package installed, those the app never calls among them, so a word in
/// one says nothing about the app's own code.
fn lockfile(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    base.ends_with(".lock")
        || base.ends_with("-lock.json")
        || base.ends_with("-lock.yaml")
        || base == "go.sum"
}

fn path_item(what: &'static str, path: &str, source: &Source) -> Item {
    match source.find(None, |text| names_path(text, path)) {
        Some(file) => Item::new(
            "path",
            Answer::Looks,
            vec![
                sv(format!("The {what} path ")),
                app(path),
                sv(" is named in "),
                app(file),
                sv("."),
            ],
        ),
        None => Item::new(
            "path",
            Answer::Look,
            vec![
                sv(format!("The {what} path ")),
                app(path),
                sv(
                    " is named in no file. If the app builds its routes from parts, ignore this; if not, the settings and the app disagree, and `sv` will ask where nothing answers.",
                ),
            ],
        ),
    }
}

fn sorted(mut items: Vec<Item>) -> Vec<Item> {
    items.sort_by_key(|item| item.answer);
    items
}

/// The preflight of the app in `app_dir`.
pub fn of(app_dir: &Path) -> anyhow::Result<(Vec<Item>, Vec<String>)> {
    let manifest_path = app_dir.join("securevibe.toml");
    anyhow::ensure!(
        manifest_path.exists(),
        "no securevibe.toml in {}: write it first (`sv init` gives the spec), and the preflight reads what its [stack.run] asks for",
        app_dir.display()
    );
    let manifest = Manifest::load(&manifest_path)?;
    let source = Source::of(&Listing::of(app_dir));
    Ok((preflight(&manifest, &source), source.unread))
}

const OPENING: &str = "# Preflight: what `sv run` will need, and some of what it will test, looked for in the code\n\nNothing was run. Each answer is a reading of the app's files: \"looks right\" means what `sv run` needs was found in the text, not that it works, and \"look at this\" may be a route or a name built from parts. Nothing here is evidence for any requirement, and nothing is credited.\n";

const TESTED_HEADING: &str = "\n## What `sv run` will test, as the code shows it now\n\nThese do not stop the run. Each is something the run will look for in the running app, and the code already hints whether it is there; fixing it now saves a finding later. A hint either way is not the run's answer.\n\n";

pub fn markdown(items: &[Item], unread: &[String]) -> String {
    markdown_with(items, unread, &Fence::none())
}

pub(crate) fn markdown_with(items: &[Item], unread: &[String], fence: &Fence) -> String {
    let mut out = String::from(OPENING);
    // Each part counted on its own: the first says whether the run can start and sign in, and a
    // hint of what it will test must not read as a reason it cannot.
    let count = |tested: bool| {
        let of = |answer: Answer| {
            items
                .iter()
                .filter(|i| i.tested() == tested && i.answer == answer)
                .count()
        };
        format!(
            "{} to look at, {} could not tell, {} looks right.\n\n",
            of(Answer::Look),
            of(Answer::Unknown),
            of(Answer::Looks)
        )
    };
    out.push('\n');
    out.push_str(&count(false));
    let line = |item: &Item| {
        format!(
            "- **{}** ({}): {}\n",
            item.answer.words(),
            item.topic,
            item.text(fence)
        )
    };
    for item in items.iter().filter(|i| !i.tested()) {
        out.push_str(&line(item));
    }
    if items.iter().any(Item::tested) {
        out.push_str(TESTED_HEADING);
        out.push_str(&count(true));
        for item in items.iter().filter(|i| i.tested()) {
            out.push_str(&line(item));
        }
    }
    if !unread.is_empty() {
        out.push_str("\nNot read, because they are too large: ");
        out.push_str(
            &unread
                .iter()
                .map(|f| fence.wrap(f))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str(".\n");
    }
    out
}

pub fn to_json(items: &[Item], unread: &[String]) -> Value {
    json!({
        "ran": false,
        "credits": "nothing",
        "items": items.iter().map(|item| json!({
            "topic": item.topic,
            "for": if item.tested() { "tested" } else { "needed" },
            "answer": item.answer.id(),
            "says": item.text(&Fence::none()),
        })).collect::<Vec<_>>(),
        "notRead": unread,
    })
}

/// Whether `text` names the variable `name` as a whole: `SV_ADMIN` inside `SV_ADMIN_PASSWORD` is
/// not it, so a seed that reads only the password and makes up its own admin's name is not said to
/// read the admin account (the review of 6 October, item 14).
fn names(text: &str, name: &str) -> bool {
    let part = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(name).any(|(at, _)| {
        !text[..at].chars().next_back().is_some_and(part)
            && !text[at + name.len()..].chars().next().is_some_and(part)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(files: &[(&str, &str)]) -> Source {
        Source {
            files: files
                .iter()
                .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
                .collect(),
            unread: Vec::new(),
        }
    }

    fn manifest(run: &str) -> Manifest {
        let text = format!("manifest-version = 1\n[app]\nname = \"t\"\n{run}");
        Manifest::parse(&text, Path::new("securevibe.toml")).expect("the test's manifest parses")
    }

    const RUN: &str = "[stack.run]\nimage = \"python:3.12-slim\"\nstart = \"python app.py\"\nhealth = \"/health\"\n[stack.run.users]\nseed = \"python seed.py\"\nlogin = { path = \"/login\", form = { email = \"{user}\", password = \"{password}\", csrf_token = \"{csrf}\" } }\nprivate = [\"/account\"]\nadmin = [\"/admin\"]\n";

    const GOOD_APP: &str = "import os, sqlite3\nPORT = int(os.environ.get('PORT', 8080))\ndb.execute('CREATE TABLE IF NOT EXISTS users (id)')\nroutes = {'/health': h, '/login': login, '/account': acct, '/admin': admin}\nfields = ('email', 'password', 'csrf_token')\nserve(('0.0.0.0', PORT))\n";
    const GOOD_SEED: &str = "import os\nfor u, p in (('SV_USER_A','SV_PASSWORD_A'),('SV_USER_B','SV_PASSWORD_B'),('SV_ADMIN','SV_ADMIN_PASSWORD')):\n    add(os.environ[u], os.environ[p])\n";

    fn answers(items: &[Item], topic: &str) -> Vec<Answer> {
        items
            .iter()
            .filter(|i| i.topic == topic)
            .map(|i| i.answer)
            .collect()
    }

    /// Everything an item says, `sv`'s words and the app's names together.
    fn said(item: &Item) -> String {
        item.says
            .iter()
            .map(|p| match p {
                Part::Sv(t) | Part::App(t) => t.as_str(),
            })
            .collect()
    }

    #[test]
    fn a_start_command_naming_a_file_that_is_not_there_is_said() {
        // The loop's item 6, 6 October 2026: `start = "python app.py"` with no `app.py`.
        let items = preflight(
            &manifest(RUN),
            &source(&[("main.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        let start: Vec<&Item> = items
            .iter()
            .filter(|i| i.topic == "start" && i.answer == Answer::Look)
            .collect();
        assert_eq!(start.len(), 1, "{items:?}");
        assert!(
            said(start[0]).contains("app.py, which is not in the app's folder"),
            "{}",
            said(start[0])
        );
        // A build step may make it, and is named.
        let built = RUN.replace(
            "start = \"python app.py\"",
            "start = \"python app.py\"\nbuild = \"python make.py\"",
        );
        let items = preflight(
            &manifest(&built),
            &source(&[("main.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        assert!(
            items.iter().any(|i| i.topic == "start"
                && said(i).contains("If the build step (`python make.py`) makes it")),
            "{items:?}"
        );
        // The control: with the file there, nothing is said about it.
        let items = preflight(
            &manifest(RUN),
            &source(&[("app.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        assert!(
            !items
                .iter()
                .any(|i| i.topic == "start" && i.answer == Answer::Look),
            "{items:?}"
        );
    }

    #[test]
    fn an_app_that_gives_sv_run_everything_has_nothing_to_look_at() {
        let items = preflight(
            &manifest(RUN),
            &source(&[("app.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        // What the run will test is hinted at below, apart from what it needs.
        let look: Vec<String> = items
            .iter()
            .filter(|i| !i.tested() && i.answer != Answer::Looks)
            .map(|i| i.text(&Fence::none()))
            .collect();
        assert!(look.is_empty(), "{look:?}");
        // Each part was looked at, not skipped.
        for topic in ["start", "listen", "port", "accounts", "tables", "path"] {
            assert_eq!(
                answers(&items, topic).first(),
                Some(&Answer::Looks),
                "{topic}"
            );
        }
    }

    #[test]
    fn tables_made_only_by_the_seed_are_said() {
        let app = GOOD_APP.replace("db.execute('CREATE TABLE IF NOT EXISTS users (id)')\n", "");
        let seed = format!("{GOOD_SEED}db.execute('create table users (id)')\n");
        let items = preflight(
            &manifest(RUN),
            &source(&[("app.py", &app), ("seed.py", &seed)]),
        );
        assert_eq!(answers(&items, "tables"), vec![Answer::Look]);
    }

    #[test]
    fn a_seed_that_is_the_app_itself_cannot_say_where_the_tables_are_made() {
        // Found on the first loop builds: `seed = "python app.py seed"` was read as tables made
        // only by the seed, because the seed's file and the app's are the same file.
        let run = RUN.replace("seed = \"python seed.py\"", "seed = \"python app.py seed\"");
        let app = format!("{GOOD_APP}{GOOD_SEED}");
        let items = preflight(&manifest(&run), &source(&[("app.py", &app)]));
        assert_eq!(answers(&items, "tables"), vec![Answer::Unknown]);
        assert_eq!(answers(&items, "accounts"), vec![Answer::Looks]);
    }

    #[test]
    fn a_seed_that_ignores_the_sv_accounts_is_said_by_name() {
        let seed = "add('alice@example.com', 'hunter2')\n";
        let items = preflight(
            &manifest(RUN),
            &source(&[("app.py", GOOD_APP), ("seed.py", seed)]),
        );
        let accounts: Vec<&Item> = items.iter().filter(|i| i.topic == "accounts").collect();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].answer, Answer::Look);
        assert!(
            accounts[0]
                .text(&Fence::none())
                .contains("SV_ADMIN_PASSWORD")
        );
    }

    #[test]
    fn a_seed_that_reads_only_the_admin_password_does_not_read_the_admin_account() {
        // The review of 6 October, item 14: `SV_ADMIN` was found inside `SV_ADMIN_PASSWORD`.
        let seed = GOOD_SEED.replace(
            "('SV_ADMIN','SV_ADMIN_PASSWORD')",
            "('admin@x','SV_ADMIN_PASSWORD')",
        );
        assert_ne!(seed, GOOD_SEED, "the setup: the seed changed");
        let items = preflight(
            &manifest(RUN),
            &source(&[("app.py", GOOD_APP), ("seed.py", &seed)]),
        );
        let accounts: Vec<&Item> = items.iter().filter(|i| i.topic == "accounts").collect();
        assert_eq!(accounts[0].answer, Answer::Look);
        let said = accounts[0].text(&Fence::none());
        assert!(said.contains("Nothing reads SV_ADMIN."), "{said}");
        assert!(names("x = env['SV_ADMIN']", "SV_ADMIN"));
        assert!(!names("SV_ADMIN_PASSWORD", "SV_ADMIN"));
        assert!(!names("MY_SV_ADMIN", "SV_ADMIN"));
    }

    #[test]
    fn the_admin_account_is_asked_for_only_when_there_are_admin_pages() {
        let run = RUN.replace("admin = [\"/admin\"]\n", "");
        let seed = "add(env['SV_USER_A'], env['SV_PASSWORD_A']); add(env['SV_USER_B'], env['SV_PASSWORD_B'])\n";
        let items = preflight(
            &manifest(&run),
            &source(&[("app.py", GOOD_APP), ("seed.py", seed)]),
        );
        assert_eq!(answers(&items, "accounts"), vec![Answer::Looks]);
    }

    #[test]
    fn a_sign_in_path_the_app_does_not_have_is_said() {
        let run = RUN.replace("path = \"/login\"", "path = \"/signin\"");
        let items = preflight(
            &manifest(&run),
            &source(&[("app.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        let missing: Vec<String> = items
            .iter()
            .filter(|i| i.topic == "path" && i.answer == Answer::Look)
            .map(|i| i.text(&Fence::none()))
            .collect();
        assert_eq!(missing.len(), 1, "{missing:?}");
        assert!(missing[0].contains("/signin"));
    }

    #[test]
    fn a_form_field_the_app_names_differently_is_said() {
        let app = GOOD_APP.replace("'email', ", "'username', ");
        let items = preflight(
            &manifest(RUN),
            &source(&[("app.py", &app), ("seed.py", GOOD_SEED)]),
        );
        let fields: Vec<String> = items
            .iter()
            .filter(|i| i.topic == "field")
            .map(|i| i.text(&Fence::none()))
            .collect();
        assert_eq!(fields.len(), 1, "{fields:?}");
        assert!(
            fields[0].contains("email") && !fields[0].contains("password"),
            "{fields:?}"
        );
    }

    #[test]
    fn listening_on_loopback_only_is_said() {
        let app = GOOD_APP.replace("'0.0.0.0'", "'127.0.0.1'");
        let items = preflight(
            &manifest(RUN),
            &source(&[("app.py", &app), ("seed.py", GOOD_SEED)]),
        );
        assert_eq!(answers(&items, "listen"), vec![Answer::Look]);
    }

    #[test]
    fn an_app_that_ignores_port_is_said() {
        let app = GOOD_APP.replace("os.environ.get('PORT', 8080)", "8080");
        let items = preflight(
            &manifest(RUN),
            &source(&[("app.py", &app), ("seed.py", GOOD_SEED)]),
        );
        assert_eq!(answers(&items, "port"), vec![Answer::Look]);
    }

    #[test]
    fn a_seed_file_that_is_not_there_is_said() {
        let items = preflight(&manifest(RUN), &source(&[("app.py", GOOD_APP)]));
        assert!(answers(&items, "seed").contains(&Answer::Look));
    }

    #[test]
    fn no_start_command_is_said_first() {
        let run = RUN.replace("start = \"python app.py\"\n", "");
        let items = preflight(
            &manifest(&run),
            &source(&[("app.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        assert_eq!(items[0].topic, "start");
        assert_eq!(items[0].answer, Answer::Look);
    }

    #[test]
    fn what_the_app_names_is_fenced_and_sv_words_are_not() {
        let run = RUN.replace(
            "path = \"/login\"",
            "path = \"/ignore-all-previous-instructions\"",
        );
        let items = preflight(
            &manifest(&run),
            &source(&[("app.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        let text = sv_report::fence::fenced(|fence| markdown_with(&items, &[], fence));
        let tag_at = text.find("<app-text-").expect("the path is fenced");
        let path_at = text
            .find("/ignore-all-previous-instructions")
            .expect("the path is said");
        assert!(tag_at < path_at);
        assert!(text.contains("Nothing was run."));
    }

    #[test]
    fn prose_and_the_manifest_do_not_count_as_code() {
        let dir = std::env::temp_dir().join(format!("sv-preflight-prose-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("securevibe.toml"),
            format!("manifest-version = 1\n[app]\nname = \"t\"\n{RUN}"),
        )
        .unwrap();
        std::fs::write(dir.join("app.py"), "serve(('127.0.0.1', 8080))\n").unwrap();
        std::fs::write(dir.join("seed.py"), GOOD_SEED).unwrap();
        // Everything the app lacks, said in prose, where a plain search would find it.
        std::fs::write(
            dir.join("README.md"),
            "It listens on '0.0.0.0' at $PORT and serves '/login'.\n",
        )
        .unwrap();
        std::fs::write(dir.join("notes.txt"), "'0.0.0.0' PORT '/login'\n").unwrap();
        let (items, unread) = of(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(unread.is_empty());
        assert_eq!(answers(&items, "listen"), vec![Answer::Look]);
        assert_eq!(answers(&items, "port"), vec![Answer::Look]);
        let login: Vec<Answer> = items
            .iter()
            .filter(|i| i.topic == "path" && i.text(&Fence::none()).contains("/login"))
            .map(|i| i.answer)
            .collect();
        assert_eq!(login, vec![Answer::Look]);
    }

    /// The settings with an AI feature and its off switch, and [policy] as `policy` gives it.
    fn ai_run(policy: &str) -> String {
        format!(
            "{RUN}[stack.run.ai]\nchat = {{ path = \"/chat\", json = {{ message = \"{{prompt}}\" }} }}\nkill-switch = \"AI_ENABLED=false\"\n{policy}"
        )
    }

    const POLICY: &str = "[policy]\nfailed-sign-ins = 5\nai-requests-per-minute = 10\n";

    fn tested_answers(items: &[Item]) -> Vec<(&'static str, Answer)> {
        let mut out: Vec<_> = items
            .iter()
            .filter(|i| i.tested())
            .map(|i| (i.topic, i.answer))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn an_app_that_shows_none_of_what_the_run_will_test_is_told_each() {
        let items = preflight(
            &manifest(&ai_run("")),
            &source(&[("app.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        assert_eq!(
            tested_answers(&items),
            vec![
                ("ai-limit", Answer::Look),
                ("ai-screening", Answer::Look),
                ("cookie", Answer::Look),
                ("headers", Answer::Look),
                ("kill-switch", Answer::Look),
                ("sign-in-limit", Answer::Look),
            ]
        );
        let headers = items.iter().find(|i| i.topic == "headers").unwrap();
        for header in [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        ] {
            assert!(
                said(headers).contains(header),
                "{header}: {}",
                said(headers)
            );
        }
        // With no number stated, the run does not try the limits, and each says so.
        for topic in ["sign-in-limit", "ai-limit"] {
            let item = items.iter().find(|i| i.topic == topic).unwrap();
            assert!(said(item).contains("is not set"), "{topic}: {}", said(item));
        }
        let switch = items.iter().find(|i| i.topic == "kill-switch").unwrap();
        assert!(said(switch).contains("AI_ENABLED"), "{}", said(switch));
        // None of these is a reason the run cannot start: the needs above still have nothing.
        assert!(
            items
                .iter()
                .filter(|i| !i.tested())
                .all(|i| i.answer == Answer::Looks)
        );
    }

    const SHOWS_ALL: &str = "const helmet = require('helmet');\nconst rateLimit = require('express-rate-limit');\napp.use(session({ cookie: { sameSite: 'lax' } }));\nconst flagged = await openai.moderations.create({ input });\nif (process.env.AI_ENABLED === 'false') return off();\n";

    #[test]
    fn an_app_that_shows_each_is_told_where() {
        let items = preflight(
            &manifest(&ai_run(POLICY)),
            &source(&[
                ("app.py", GOOD_APP),
                ("seed.py", GOOD_SEED),
                ("server.js", SHOWS_ALL),
            ]),
        );
        assert_eq!(
            tested_answers(&items),
            vec![
                // A limit is there, and whether it is the AI feature's own is not in the text.
                ("ai-limit", Answer::Unknown),
                ("ai-screening", Answer::Looks),
                ("cookie", Answer::Looks),
                ("headers", Answer::Looks),
                ("kill-switch", Answer::Looks),
                ("sign-in-limit", Answer::Looks),
            ]
        );
        for item in items.iter().filter(|i| i.tested()) {
            assert!(!said(item).contains("is not set"), "{}", said(item));
            assert!(said(item).contains("server.js"), "{}", said(item));
        }
    }

    #[test]
    fn each_header_is_found_however_it_is_spelled_and_the_one_missing_is_named() {
        let manifest = manifest(RUN);
        let headers = |files: &[(&str, &str)]| {
            let items = preflight(&manifest, &source(files));
            let item = items.into_iter().find(|i| i.topic == "headers").unwrap();
            (item.answer, said(&item))
        };
        // Django's settings and middleware: every header but the policy.
        let (answer, text) = headers(&[(
            "settings.py",
            "MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.middleware.clickjacking.XFrameOptionsMiddleware']\n",
        )]);
        assert_eq!(answer, Answer::Look);
        assert!(text.contains("Content-Security-Policy"), "{text}");
        for other in ["X-Content-Type-Options", "framed", "Referrer-Policy"] {
            assert!(!text.contains(other), "{other}: {text}");
        }
        // Each named by hand, in four spellings.
        let (answer, _) = headers(&[(
            "app.go",
            "w.Header().Set(\"content-security-policy\", csp)\nres.setHeader('X-Content-Type-Options', 'nosniff')\nX_FRAME_OPTIONS = 'DENY'\nsetReferrerPolicy('no-referrer')\n",
        )]);
        assert_eq!(answer, Answer::Looks);
        // Spring Security sends the type and framing headers by itself, not the other two.
        let (answer, text) = headers(&[(
            "pom.xml",
            "<artifactId>spring-boot-starter-security</artifactId>\n",
        )]);
        assert_eq!(answer, Answer::Look);
        assert!(text.contains("Content-Security-Policy"), "{text}");
        assert!(text.contains("Referrer-Policy"), "{text}");
        assert!(!text.contains("X-Content-Type-Options"), "{text}");
        assert!(!text.contains("framed"), "{text}");
        // One library that sends them all.
        for library in [
            "Talisman(app)",
            "SecureHeaders::Configuration",
            "app.use(helmet())",
        ] {
            assert_eq!(headers(&[("app", library)]).0, Answer::Looks, "{library}");
        }
    }

    #[test]
    fn a_limit_is_found_in_the_ways_it_is_written() {
        let manifest = manifest(RUN);
        for limit in [
            "from flask_limiter import Limiter",
            "MAX_LOGIN_ATTEMPTS = 5",
            "return 'Too many attempts, try again later', 429",
            "Rack::Attack.throttle('logins/ip')",
            "const { RateLimiterMemory } = require('rate-limiter-flexible')",
            "failed_logins[email] += 1",
        ] {
            let items = preflight(
                &manifest,
                &source(&[("app.py", GOOD_APP), ("limit.py", limit)]),
            );
            assert_eq!(
                answers(&items, "sign-in-limit"),
                vec![Answer::Looks],
                "{limit}"
            );
        }
    }

    #[test]
    fn a_framework_that_sets_same_site_itself_could_not_be_told() {
        let manifest = manifest(RUN);
        for (file, text, framework) in [
            (
                "settings.py",
                "INSTALLED_APPS = ['django.contrib.auth']\n",
                "Django",
            ),
            ("Gemfile", "gem \"rails\", \"~> 7.1\"\n", "Rails"),
        ] {
            let items = preflight(&manifest, &source(&[("app.py", GOOD_APP), (file, text)]));
            let cookie = items.iter().find(|i| i.topic == "cookie").unwrap();
            assert_eq!(cookie.answer, Answer::Unknown, "{framework}");
            assert!(said(cookie).contains(framework), "{}", said(cookie));
        }
    }

    #[test]
    fn a_word_in_a_lockfile_is_not_the_app_using_it() {
        let items = preflight(
            &manifest(RUN),
            &source(&[
                ("app.py", GOOD_APP),
                (
                    "package-lock.json",
                    "{\"packages\": {\"node_modules/express-rate-limit\": {}, \"node_modules/helmet\": {}}}",
                ),
                ("yarn.lock", "helmet@^7:\nrate-limiter-flexible@^5:\n"),
            ]),
        );
        assert_eq!(answers(&items, "sign-in-limit"), vec![Answer::Look]);
        assert_eq!(answers(&items, "headers"), vec![Answer::Look]);
    }

    #[test]
    fn what_the_run_does_not_try_is_not_hinted_at() {
        // No sign-in, no AI feature: only the headers, which every run asks for.
        let run = "[stack.run]\nimage = \"python:3.12-slim\"\nstart = \"python app.py\"\n";
        let items = preflight(&manifest(run), &source(&[("app.py", GOOD_APP)]));
        assert_eq!(tested_answers(&items), vec![("headers", Answer::Look)]);
        // An AI feature with no off switch named: no off switch is looked for.
        let no_switch = ai_run(POLICY).replace("kill-switch = \"AI_ENABLED=false\"\n", "");
        let items = preflight(&manifest(&no_switch), &source(&[("app.py", GOOD_APP)]));
        assert!(answers(&items, "kill-switch").is_empty());
        assert_eq!(answers(&items, "ai-screening"), vec![Answer::Look]);
    }

    #[test]
    fn what_the_run_will_test_is_its_own_section_and_count() {
        let items = preflight(
            &manifest(&ai_run(POLICY)),
            &source(&[("app.py", GOOD_APP), ("seed.py", GOOD_SEED)]),
        );
        let text = markdown(&items, &[]);
        let (needs, tests) = text
            .split_once("## What `sv run` will test")
            .expect("the section is there");
        // What the run needs is all found, and its count says so; the hints are counted apart.
        assert!(
            needs.contains("\n0 to look at, 0 could not tell,"),
            "{needs}"
        );
        assert!(
            tests.contains("\n6 to look at, 0 could not tell, 0 looks right."),
            "{tests}"
        );
        for topic in TESTED {
            assert!(!needs.contains(&format!("({topic})")), "{topic}: {needs}");
        }
        assert!(tests.contains("(kill-switch)"), "{tests}");
        let json = to_json(&items, &[]);
        for item in json["items"].as_array().unwrap() {
            let topic = item["topic"].as_str().unwrap();
            let expected = if TESTED.contains(&topic) {
                "tested"
            } else {
                "needed"
            };
            assert_eq!(item["for"], expected, "{topic}");
        }
    }
}
