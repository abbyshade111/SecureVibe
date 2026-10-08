//! What a run leaves behind when it is stopped, and how it is removed.
//!
//! A run starts the app, a sidecar, and whatever stand-ins it needs, on a network of its own, and
//! `Teardown` removes them all on every way out of the run, Ctrl-C included (`catch_interrupts`).
//! A process killed outright (`kill -9`, a closed laptop, a crash) runs nothing at all, though, and
//! leaves them behind, one set per killed run. So everything a run starts is labeled with the
//! machine's name and the process's id, and each run first removes what carries this machine's name
//! and the id of a process that has ended. Anything else is left alone: another `sv` still running,
//! `sv` on another machine that shares the Docker daemon, and everything that is not `sv`'s.

/// The label on everything a run starts: `<machine>:<process id>`.
pub const OWNER_LABEL: &str = sv_frameworks::names::OWNER_LABEL;
/// The label before the rename (ADR-062): a container or network left by a run under the old name
/// is still this machine's leftover, and is still removed.
pub const OLD_OWNER_LABEL: &str = sv_frameworks::names::OLD_OWNER_LABEL;

/// This process, as what it starts is labeled.
pub fn owner() -> String {
    format!("{}:{}", host_name(), std::process::id())
}

/// This machine's name. `sv` in a container sees the container's name, which is what keeps two
/// copies of `sv` in two containers, each with its own process ids, from reading each other's.
fn host_name() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is valid for its length, and gethostname writes at most that much.
        let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
        if ok {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            let name = String::from_utf8_lossy(&buf[..end]).trim().to_owned();
            if !name.is_empty() {
                return name;
            }
        }
    }
    "unknown-machine".to_owned()
}

/// Whether a process with this id is running on this machine. Where that cannot be asked, every
/// process counts as running, so nothing is ever removed on a guess.
pub(crate) fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return true;
        };
        // SAFETY: signal 0 checks the process exists and sends nothing.
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Whether something labeled `label` was left by a run on this machine whose process has ended.
pub(crate) fn is_leftover(label: &str, host: &str, alive: impl Fn(u32) -> bool) -> bool {
    let Some((machine, pid)) = label.rsplit_once(':') else {
        return false;
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return false;
    };
    machine == host && pid != std::process::id() && !alive(pid)
}

/// The machine part of `owner()`.
pub(crate) fn this_machine() -> String {
    host_name()
}

/// A Docker command's arguments, with the owner label added to what creates a container or a
/// network, so that nothing a run starts is unlabeled.
pub(crate) fn labeled(args: &[&str], owner: &str) -> Vec<String> {
    let label = format!("{OWNER_LABEL}={owner}");
    let at = match args {
        ["run", ..] | ["create", ..] => Some(1),
        ["network", "create", ..] => Some(2),
        _ => None,
    };
    let mut out: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    if let Some(at) = at {
        out.insert(at, label);
        out.insert(at, "--label".to_owned());
    }
    out
}

/// What a person is told when a run removed leftovers first: `None` when there were none.
pub fn removed_sentence(removed: &[String]) -> Option<String> {
    if removed.is_empty() {
        return None;
    }
    Some(format!(
        "Before starting, `sv` removed {} left behind by an earlier run on this computer that was \
         stopped before it could clean up: {}.",
        if removed.len() == 1 {
            "one container or network".to_owned()
        } else {
            format!("{} containers and networks", removed.len())
        },
        removed.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_creates_a_container_or_a_network_is_labeled_and_nothing_else_is() {
        let owner = "laptop:42";
        assert_eq!(
            labeled(&["run", "-d", "--name", "x", "busybox"], owner),
            vec![
                "run",
                "--label",
                "org.stackvet.owner=laptop:42",
                "-d",
                "--name",
                "x",
                "busybox"
            ]
        );
        assert_eq!(
            labeled(&["network", "create", "--internal", "n"], owner),
            vec![
                "network",
                "create",
                "--label",
                "org.stackvet.owner=laptop:42",
                "--internal",
                "n"
            ]
        );
        assert_eq!(
            labeled(&["create", "busybox"], owner),
            vec![
                "create",
                "--label",
                "org.stackvet.owner=laptop:42",
                "busybox"
            ]
        );
        for untouched in [
            &["exec", "x", "run"][..],
            &["rm", "-f", "run"][..],
            &["network", "rm", "n"][..],
            &["info"][..],
        ] {
            assert_eq!(
                labeled(untouched, owner),
                untouched.to_vec(),
                "{untouched:?}"
            );
        }
    }

    #[test]
    fn only_what_this_machine_left_from_an_ended_process_is_a_leftover() {
        let me = std::process::id();
        let ended = |_: u32| false;
        let running = |_: u32| true;
        assert!(is_leftover("laptop:7", "laptop", ended));
        assert!(!is_leftover("laptop:7", "laptop", running), "still running");
        assert!(
            !is_leftover("other:7", "laptop", ended),
            "another machine's"
        );
        assert!(
            !is_leftover(&format!("laptop:{me}"), "laptop", ended),
            "this process's own"
        );
        for odd in ["laptop", "laptop:", "laptop:x", ""] {
            assert!(!is_leftover(odd, "laptop", ended), "{odd:?}");
        }
        // A machine name with a colon in it (an IPv6-looking name) keeps the last part as the id.
        assert!(is_leftover("fe80::1:7", "fe80::1", ended));
    }

    #[cfg(unix)]
    #[test]
    fn this_process_is_alive_and_one_that_ended_is_not() {
        assert!(alive(std::process::id()));
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("true runs");
        let pid = child.id();
        child.wait().expect("it ends");
        assert!(!alive(pid), "a process that has ended and been waited for");
    }
}
