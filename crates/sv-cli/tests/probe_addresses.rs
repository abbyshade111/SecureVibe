//! `sv probe` asks only public addresses, and holds curl to what it checked (the deep review of 4 October 2026,
//! S13).
//!
//! A `curl` of the test's own is put first on the path. It writes down what it was asked and answers like a site,
//! so the test sees every request `sv probe` would have made, and that none was made to an address it refused.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("sv-probe-addresses-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A `curl` that writes its arguments, one per line and each call ended by `--`, to `asked`.
fn fake_curl(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let asked = dir.join("asked");
    let script = format!(
        "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '{}'; done\necho -- >> '{}'\n\
         case \"$1\" in --version) echo 'curl 8.0.0 (x86_64-pc-linux-gnu) libcurl/8.0.0'; exit 0;; esac\n\
         printf 'HTTP/1.1 200 OK\\r\\ncontent-type: text/html\\r\\n\\r\\n'\n",
        asked.display(),
        asked.display()
    );
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let curl = bin.join("curl");
    std::fs::write(&curl, script).unwrap();
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn probe(dir: &Path, address: &str) -> std::process::Output {
    let bin = fake_curl(dir);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["probe", address])
        .env("PATH", path)
        .output()
        .unwrap()
}

/// What the fake curl was asked, one call per entry, leaving out `curl --version`.
fn requests(dir: &Path) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(dir.join("asked")).unwrap_or_default();
    text.split("--\n")
        .map(|call| call.lines().map(str::to_owned).collect::<Vec<_>>())
        .filter(|call| !call.is_empty() && call[0] != "--version")
        .collect()
}

#[test]
fn an_internal_address_is_refused_before_anything_is_asked() {
    for address in [
        "https://10.0.0.1",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]:8443",
        "https://[::ffff:192.168.1.1]",
    ] {
        let dir = scratch("refused");
        let out = probe(&dir, address);
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{address}: {said}");
        assert!(
            said.contains("not an address on the public internet"),
            "{address}: {said}"
        );
        assert!(requests(&dir).is_empty(), "{address}: {:?}", requests(&dir));
    }
}

#[test]
fn a_public_address_is_asked_with_no_config_no_globbing_and_web_addresses_only() {
    // The control: the fake curl is really on the path and really asked, so the test above
    // passing is not the fake curl failing to run.
    let dir = scratch("public");
    let out = probe(&dir, "https://93.184.215.14");
    let asked = requests(&dir);
    assert!(
        !asked.is_empty(),
        "the fake curl was never asked: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(asked.len() <= 4, "{asked:?}");
    for call in &asked {
        assert_eq!(call[0], "--disable", "{call:?}");
        assert!(call.iter().any(|a| a == "--globoff"), "{call:?}");
        assert!(
            call.windows(2).any(|w| w == ["--proto", "=http,https"]),
            "{call:?}"
        );
        assert!(
            call.last().unwrap().contains("93.184.215.14"),
            "only the address typed: {call:?}"
        );
    }
}
