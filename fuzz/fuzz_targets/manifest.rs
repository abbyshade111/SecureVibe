//! An app's `stackvet.toml`, which the app, or the AI coding tool building it, writes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = sv_manifest::Manifest::parse(text, std::path::Path::new("stackvet.toml"));
    }
});
