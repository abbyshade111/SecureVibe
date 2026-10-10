//! `sv doctor [PATH]`: is everything ready? (backlog 0217, part 3, narrowed as the owner chose on 9
//! October 2026).
//!
//! Setting up, a person finds out what is missing one failure at a time. This answers in plain
//! sentences, one line each: which `sv` this is and where its data is, whether the folder is in git,
//! whether `stackvet.toml` is there and reads, whether it says how to start the app, and whether
//! Docker can start it, which is what `sv report --run` needs.
//!
//! # What it cannot say
//!
//! Whether this copy is the newest: that would mean asking the internet, and `sv` opens no network
//! connection of its own. And, run inside StackVet's container, whether Docker on the computer can
//! start the app: the container cannot see that, and says so rather than guess.
//!
//! # What it is worth
//!
//! Nothing, as evidence: it credits nothing and writes nothing. Each answer is only as good as the
//! piece of `sv` it asks, which is the same piece the real run uses: the git guard (ADR-032), the
//! manifest reader, the run plan, and Docker's own `docker info`.

use sv_run::CannotRun;

/// How one answer came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Ready,
    NotReady,
    /// `sv` could not find out, and says why rather than guess.
    CannotTell,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            State::Ready => "ready",
            State::NotReady => "not ready",
            State::CannotTell => "can't tell",
        }
    }
}

/// One answer: what was asked, how it came out, and the sentence that says so.
#[derive(Debug, Clone)]
pub struct Line {
    pub topic: &'static str,
    pub state: State,
    pub said: String,
    /// Whether `said` can quote the app's own text (its stackvet.toml, read or not), which the MCP
    /// server fences as it fences every quote of the app (ADR-066).
    pub quotes_app: bool,
}

fn line(topic: &'static str, state: State, said: impl Into<String>) -> Line {
    Line {
        topic,
        state,
        said: said.into(),
        // The two answers read from stackvet.toml quote it: its parse error, the image it names.
        quotes_app: matches!(topic, "stackvet.toml" | "how to start the app"),
    }
}

/// `sv --version`'s first line: this copy's version and the commit it was built from.
pub fn version_line() -> String {
    format!(
        "sv {} (commit {})",
        env!("CARGO_PKG_VERSION"),
        env!("SV_GIT_COMMIT")
    )
}

/// What the answers depend on that is not the folder, given so a test can set each.
pub struct Asked<'a> {
    /// `sv --version`'s first line.
    pub version: &'a str,
    /// Where this copy reads its data, or why it found none.
    pub data: Result<std::path::PathBuf, String>,
    /// Whether `sv` is running inside a container (`/.dockerenv`).
    pub in_container: bool,
    /// Asks the container backend whether it can run anything (`docker info`).
    pub backend: &'a dyn Fn() -> Result<(), CannotRun>,
}

/// The answers for the app in `app_dir`, in the order a person sets things up.
pub fn answers(app_dir: &std::path::Path, asked: &Asked) -> Vec<Line> {
    let mut lines = Vec::new();
    lines.push(match &asked.data {
        Ok(dir) => line(
            "sv",
            State::Ready,
            format!(
                "This is {}, reading its data from {}. Whether a newer one is out is not \
                 asked: `sv` opens no network connection to find out.",
                asked.version,
                dir.display()
            ),
        ),
        Err(why) => line(
            "sv",
            State::NotReady,
            format!(
                "This is {}, and it found no data to read: {why}",
                asked.version
            ),
        ),
    });

    lines.push(match sv_check::git::ls_files(app_dir) {
        Some(files) => line(
            "git",
            State::Ready,
            format!(
                "The folder is in git, with {} file{} in it so far.",
                files.len(),
                if files.len() == 1 { "" } else { "s" }
            ),
        ),
        None => line(
            "git",
            State::NotReady,
            "git could not list the folder's files: either the folder is not in git yet, or git \
             is not installed. Some checks read the folder's history, which needs git: `git init` \
             in the folder starts it.",
        ),
    });

    let manifest = match sv_manifest::locate(app_dir) {
        Err(e) => {
            lines.push(line("stackvet.toml", State::NotReady, format!("{e:#}")));
            None
        }
        Ok(None) => {
            lines.push(line(
                "stackvet.toml",
                State::NotReady,
                "There is no stackvet.toml in the folder yet. It says what the app is and does; \
                 `sv init` prints the description of it to hand to your AI coding tool, which \
                 writes it.",
            ));
            None
        }
        Ok(Some(located)) => match sv_manifest::Manifest::load(&located.path) {
            Ok(manifest) => {
                let mut said = "stackvet.toml is there and reads.".to_owned();
                if let Some(note) = located.note() {
                    said.push(' ');
                    said.push_str(&note);
                }
                lines.push(line("stackvet.toml", State::Ready, said));
                Some(manifest)
            }
            Err(e) => {
                lines.push(line(
                    "stackvet.toml",
                    State::NotReady,
                    format!("stackvet.toml is there and does not read: {e:#}"),
                ));
                None
            }
        },
    };

    lines.push(match &manifest {
        None => line(
            "how to start the app",
            State::CannotTell,
            "Whether stackvet.toml says how to start the app can't be told until it reads.",
        ),
        Some(manifest) => match sv_run::RunPlan::from_manifest(manifest, app_dir) {
            Ok(_) => line(
                "how to start the app",
                State::Ready,
                "stackvet.toml says how to start the app ([stack.run] names an image and a start \
                 command). Whether the app really starts that way is only known by starting it.",
            ),
            Err(why) => line("how to start the app", State::NotReady, why.explain()),
        },
    });

    lines.push(if asked.in_container {
        line(
            "Docker",
            State::CannotTell,
            "This is `sv` inside StackVet's container, which cannot see whether Docker on your \
             computer can start the app. `sv report --run` needs StackVet installed on the \
             computer itself, not this container (the guide, \"Installing StackVet on your \
             computer, for `--run`\").",
        )
    } else {
        match (asked.backend)() {
            Ok(()) => line(
                "Docker",
                State::Ready,
                "Docker is running and runs Linux containers, so `sv report --run` can start the \
                 app.",
            ),
            Err(why) => line("Docker", State::NotReady, why.explain()),
        }
    });
    lines
}

/// The answers as the terminal prints them.
pub fn text(app_dir: &std::path::Path, lines: &[Line]) -> String {
    text_quoting(&app_dir.display().to_string(), lines, &|t| t.to_owned())
}

/// The answers, with each piece that can be the app's own text passed through `quote`: the folder's
/// name and the answers that read stackvet.toml. The MCP server fences them there.
pub fn text_quoting(folder: &str, lines: &[Line], quote: &dyn Fn(&str) -> String) -> String {
    let mut out = format!(
        "Is everything ready for {}? Nothing was written, and no network connection was opened.\n\n",
        quote(folder)
    );
    for l in lines {
        let said = if l.quotes_app {
            quote(&l.said)
        } else {
            l.said.clone()
        };
        out.push_str(&format!("  {:<11}{}: {said}\n", l.state.word(), l.topic));
    }
    let not_ready = lines.iter().filter(|l| l.state == State::NotReady).count();
    out.push('\n');
    out.push_str(&match not_ready {
        0 => "Nothing above is missing. That says the setup is in place; it says nothing about \
              whether the app is secure, which only a check and its report can speak to.\n"
            .to_owned(),
        1 => "1 thing above is not ready yet.\n".to_owned(),
        n => format!("{n} things above are not ready yet.\n"),
    });
    out
}

#[cfg(test)]
mod tests;
