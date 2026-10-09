//! What `sv` says when it panics (backlog 226, part 1, item 5): a fault in `sv`, where it was, and
//! that nothing was assessed, in place of Rust's own line. The hook only notes the panic on the
//! main thread; `main` says it once the unwinding has cleaned up. A panic on another thread keeps
//! Rust's own line: `sv mcp` survives a check thread that panics, and must not say `sv` failed.

use std::sync::Mutex;

static SEEN: Mutex<Option<(String, String)>> = Mutex::new(None);

/// Puts the hook in place, keeping Rust's own for every thread but the main one.
pub fn install() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().name() != Some("main") {
            default(info);
            return;
        }
        let what = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "no message".to_owned());
        let place = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "a place not recorded".to_owned());
        if let Ok(mut seen) = SEEN.lock() {
            *seen = Some((what, place));
        }
    }));
}

/// The lines `main` prints for the panic the hook noted.
pub fn said() -> String {
    let (what, place) = SEEN
        .lock()
        .ok()
        .and_then(|seen| seen.clone())
        .unwrap_or_else(|| ("no message".to_owned(), "a place not recorded".to_owned()));
    message(&what, &place)
}

fn message(what: &str, place: &str) -> String {
    format!(
        "sv itself failed: a fault in sv, not in your app ({what}, at {place}).\n\
         Nothing was assessed and no report was written by this run; anything it had started was \
         stopped. Please report it, with the command you ran and this message."
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_message_says_whose_fault_where_and_that_nothing_was_assessed() {
        let said = super::message("index out of bounds", "crates/x.rs:12");
        assert!(said.starts_with("sv itself failed: a fault in sv, not in your app"));
        assert!(said.contains("crates/x.rs:12") && said.contains("index out of bounds"));
        assert!(said.contains("Nothing was assessed"));
    }
}
