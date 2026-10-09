//! A report an outside tool writes, read by every adapter's reader: the tool reads the app, so what
//! it writes can quote anything the app holds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn adapters() -> &'static sv_check::adapters::Adapters {
    static ADAPTERS: OnceLock<sv_check::adapters::Adapters> = OnceLock::new();
    ADAPTERS.get_or_init(|| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../data/adapters.json");
        sv_check::adapters::Adapters::load(&path).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = sv_check::adapters::loaded_rules(text);
        for adapter in adapters().all() {
            let _ = sv_check::adapters::parse_sarif(adapter, text);
        }
    }
});
