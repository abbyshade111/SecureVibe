//! A scratch folder no other test run can reach, removed when the test that made it ends.
//!
//! The folders used to be named after the test alone (`sv-clean-{name}`) in the shared temporary
//! folder, so two `cargo test --workspace` runs at once on one computer used the same one, and one
//! run's clean-up deleted the other's files in the middle of a test (5 October 2026: two
//! `clean_coverage` tests found nothing on their second scan). The name now carries the process id
//! and a count, so it is this run's and this call's alone.
//!
//! A folder whose test panicked is kept, so the files it failed on can be looked at; its name says
//! which run it came from.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static MADE: AtomicUsize = AtomicUsize::new(0);

pub struct Scratch(PathBuf);

impl Scratch {
    /// A new, empty folder whose name starts `sv-{prefix}-`.
    pub fn new(prefix: &str) -> Self {
        let n = MADE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sv-{prefix}-{}-{n}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }
}

impl Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
