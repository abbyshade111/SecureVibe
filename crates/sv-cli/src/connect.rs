//! `sv connect TOOL`: the settings block that connects an AI coding tool to `sv`, printed with the
//! paths already right (backlog 0217, part 1).
//!
//! Setting up by hand meant typing the app folder's full path into three places of a settings file,
//! and a wrong one fails without a word: the tool simply has no `stackvet_` tools. This prints the
//! block instead, for Claude (`.mcp.json`), VS Code (`.vscode/mcp.json`), or Cursor
//! (`.cursor/mcp.json`), with the folder it was started in. It prints and never writes: the AI coding
//! tool, or the person, puts it in the file, as with every other file in the app's folder.
//!
//! Two ways to run `sv`, two blocks:
//! - `--docker PATH`: through the container, as `docs/GETTING-STARTED.md` sets it up. `PATH` is where
//!   `docker` is on the person's computer (`which docker` prints it). A program inside the container
//!   cannot see that, so it is never guessed; the folder it can see, because the container is started
//!   with the folder mounted at its own path (`-v "$PWD":"$PWD" -w "$PWD"`).
//! - without it: this copy of `sv`, installed on the computer, by its real place. Inside the container
//!   that place means nothing outside it, so there it stops and asks for `--docker`.
//!
//! # What it is worth
//!
//! Nothing, as evidence: it reads no file of the app's and credits nothing. A block that is right is
//! shown to work only when the tool lists the `stackvet_` tools afterwards, which the guide and the
//! setup prompt both ask for.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use sv_frameworks::paths::Canonical;

/// The AI coding tools `sv connect` knows the settings file of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Claude,
    VsCode,
    Cursor,
}

impl Tool {
    pub const NAMES: &'static str = "claude, vscode, or cursor";

    pub fn named(name: &str) -> Option<Tool> {
        match name {
            "claude" => Some(Tool::Claude),
            "vscode" => Some(Tool::VsCode),
            "cursor" => Some(Tool::Cursor),
            _ => None,
        }
    }

    /// Where the block goes, from the app's folder.
    pub fn settings_file(self) -> &'static str {
        match self {
            Tool::Claude => ".mcp.json",
            Tool::VsCode => ".vscode/mcp.json",
            Tool::Cursor => ".cursor/mcp.json",
        }
    }
}

/// How the tool starts `sv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runner {
    /// Through the container: `docker` at this path on the person's computer, and, on Linux, the
    /// person's own user and group, so the files it writes are theirs.
    Docker {
        docker: String,
        user: Option<String>,
    },
    /// This copy of `sv`, at its real place.
    Installed(PathBuf),
}

/// The settings block for `tool`, starting `sv` for `folder`.
pub fn block(tool: Tool, runner: &Runner, folder: &Path) -> Value {
    let folder = folder.display().to_string();
    let (command, args) = match runner {
        Runner::Docker { docker, user } => {
            let mut args = vec![
                "run".to_owned(),
                "-i".to_owned(),
                "--rm".to_owned(),
                // The MCP server needs no network, and is given none (design entry 0043, "sv in a container").
                "--network".to_owned(),
                "none".to_owned(),
                "-v".to_owned(),
                format!("{folder}:{folder}"),
            ];
            if let Some(user) = user {
                args.push("--user".to_owned());
                args.push(user.clone());
            }
            args.push(sv_frameworks::names::IMAGE.to_owned());
            (docker.clone(), args)
        }
        Runner::Installed(program) => (program.display().to_string(), Vec::new()),
    };
    let mut args = args;
    args.extend(["mcp".to_owned(), "--root".to_owned(), folder]);
    match tool {
        Tool::Claude | Tool::Cursor => json!({
            "mcpServers": { "stackvet": { "command": command, "args": args } }
        }),
        Tool::VsCode => json!({
            "servers": { "stackvet": { "type": "stdio", "command": command, "args": args } }
        }),
    }
}

/// `sv connect TOOL [--docker PATH] [--user UID:GID] [--folder DIR]`.
pub fn command(args: &[String]) -> Result<String> {
    let mut tool = None;
    let mut docker = None;
    let mut user = None;
    let mut folder = None;
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        match arg.as_str() {
            "--docker" => docker = Some(words.next().context("--docker needs docker's full path")?),
            "--user" => user = Some(words.next().context("--user needs UID:GID")?),
            "--folder" => {
                folder = Some(PathBuf::from(
                    words.next().context("--folder needs a folder")?,
                ))
            }
            other if other.starts_with("--") => bail!("unknown option: {other}"),
            other => {
                tool = Some(Tool::named(other).with_context(|| {
                    format!(
                        "`{other}` is not a tool `sv connect` knows: give {}",
                        Tool::NAMES
                    )
                })?)
            }
        }
    }
    let tool = tool.with_context(|| format!("name the AI coding tool: {}", Tool::NAMES))?;
    let folder = folder.unwrap_or_else(|| PathBuf::from("."));
    let folder = folder
        .canonical()
        .with_context(|| format!("{} is not a folder `sv` can open", folder.display()))?;
    if !folder.is_dir() {
        bail!("{} is not a folder", folder.display());
    }
    let runner = match docker {
        Some(docker) => {
            if !docker.starts_with('/') {
                bail!(
                    "--docker needs docker's full path, such as /usr/local/bin/docker (`which docker` \
                     prints it), because an app started from the Dock often cannot find a bare `docker`"
                );
            }
            if let Some(user) = user {
                check_user(user)?;
            }
            Runner::Docker {
                docker: docker.clone(),
                user: user.cloned(),
            }
        }
        None => {
            if user.is_some() {
                bail!("--user is for the container: give it with --docker");
            }
            if in_a_container() {
                bail!(
                    "this `sv` is running inside its container, so its own path means nothing to your \
                     AI coding tool. Give --docker with docker's full path on your computer (`which \
                     docker` prints it), for example: sv connect {} --docker /usr/local/bin/docker",
                    tool_word(tool)
                );
            }
            let program = std::env::current_exe()
                .and_then(|p| p.canonical())
                .context("could not find where this copy of `sv` is")?;
            Runner::Installed(program)
        }
    };
    let text = serde_json::to_string_pretty(&block(tool, &runner, &folder))?;
    Ok(format!("{text}\n"))
}

/// The line that says where the block goes, for standard error, so standard output is the block alone.
pub fn where_it_goes(args: &[String]) -> Option<String> {
    let tool = args.iter().find_map(|a| Tool::named(a))?;
    Some(format!(
        "Put this in {} in the app's folder, then restart your AI coding tool and ask it to list the \
         `stackvet_` tools.",
        tool.settings_file()
    ))
}

fn tool_word(tool: Tool) -> &'static str {
    match tool {
        Tool::Claude => "claude",
        Tool::VsCode => "vscode",
        Tool::Cursor => "cursor",
    }
}

/// `UID:GID`, two numbers, as `id -u` and `id -g` print them.
fn check_user(user: &str) -> Result<()> {
    let numbers = user.split_once(':').filter(|(u, g)| {
        !u.is_empty()
            && !g.is_empty()
            && u.bytes().all(|b| b.is_ascii_digit())
            && g.bytes().all(|b| b.is_ascii_digit())
    });
    if numbers.is_none() {
        bail!(
            "--user needs UID:GID, two numbers, such as 1000:1000 (`id -u` and `id -g` print yours)"
        );
    }
    Ok(())
}

/// Docker marks every container with `/.dockerenv`.
pub fn in_a_container() -> bool {
    Path::new("/.dockerenv").exists() || std::env::var_os("SV_CONNECT_IN_CONTAINER").is_some()
}

#[cfg(test)]
mod tests;
