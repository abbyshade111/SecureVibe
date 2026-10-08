//! An app whose session cookie is named `__Host-...` signs the real browser in, a cookie the browser
//! will not keep is named in the report, and a start command that switches the app's cookies to a
//! weaker setting for the run is warned about (family-hub, 3 October 2026: the browser refused its
//! `__Host-fh_session`, handed over by name and value alone, and the AI tool added
//! `FAMILY_HUB_INSECURE_COOKIES=1` to the start command to get past it).
//!
//! `examples/notes-with-users`, copied and changed to name its session cookie `__Host-sid` (`Secure`,
//! path `/`, as the prefix requires) and to set one more cookie, larger than a browser keeps, at
//! sign-in. Real containers, sv's own Chromium, and the real binary. With no container backend, the
//! report must say the app was not started, and that is what is checked instead.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// One more cookie set beside the session at sign-in, larger than the 4,096 bytes a browser keeps of
/// a cookie's name and value. Plain requests carry it; the browser refuses it.
const BIG_COOKIE: &str = "fh_prefs";

fn replace(text: &mut String, from: &str, to: &str) {
    // The setup has to have worked: each change is made exactly where it was meant to be.
    let count = text.matches(from).count();
    assert!(count >= 1, "the example no longer has {from:?}");
    *text = text.replace(from, to);
}

/// The example, copied into Cargo's scratch folder beside the build, which every Mac backend shares
/// (see `killed_run.rs`), with its cookies changed.
fn app() -> PathBuf {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/notes-with-users");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sv-host-cookie-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    for file in [
        "app.py",
        "seed.py",
        "common-passwords.txt",
        "securevibe.toml",
    ] {
        std::fs::copy(example.join(file), dir.join(file)).unwrap();
    }

    let mut code = std::fs::read_to_string(dir.join("app.py")).unwrap();
    replace(
        &mut code,
        r#"cookie["sid"].value if "sid" in cookie"#,
        r#"cookie["__Host-sid"].value if "__Host-sid" in cookie"#,
    );
    replace(
        &mut code,
        r#"f"sid={sid}; Path=/; HttpOnly; SameSite=Lax""#,
        r#"f"__Host-sid={sid}; Path=/; Secure; HttpOnly; SameSite=Lax""#,
    );
    replace(
        &mut code,
        r#""sid=; Max-Age=0""#,
        r#""__Host-sid=; Path=/; Secure; Max-Age=0""#,
    );
    // Wherever the session cookie is set, the large one is set beside it.
    replace(
        &mut code,
        "        for name, value in headers:\n            self.send_header(name, value)\n",
        &format!(
            "        for name, value in headers:\n            self.send_header(name, value)\n\
             \x20       if any(n == \"Set-Cookie\" and v.startswith(\"__Host-sid=\") and not \
             v.startswith(\"__Host-sid=;\") for n, v in headers):\n\
             \x20           self.send_header(\"Set-Cookie\", \"{BIG_COOKIE}=\" + \"x\" * 5000 + \"; Path=/\")\n"
        ),
    );
    assert!(
        !code.contains("\"sid\""),
        "every use of the old name changed"
    );
    std::fs::write(dir.join("app.py"), code).unwrap();

    let mut manifest = std::fs::read_to_string(dir.join("securevibe.toml")).unwrap();
    replace(
        &mut manifest,
        "start = \"python app.py\"",
        "start = \"FAMILY_HUB_INSECURE_COOKIES=1 python app.py\"",
    );
    std::fs::write(dir.join("securevibe.toml"), manifest).unwrap();
    dir
}

fn docker_ok() -> bool {
    Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn a_host_prefixed_cookie_signs_the_browser_in_and_a_weakened_start_is_warned_about() {
    let app = app();
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .arg("--run")
        .output()
        .expect("sv runs");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let report = std::fs::read_to_string(
        app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)
            .join("compliance.md"),
    )
    .unwrap_or_else(|e| panic!("no report ({e}): {stderr}"));
    if !docker_ok() {
        println!("no container backend here; checking the honest-absence path instead");
        assert!(!report.contains("signed in a real browser"), "{report}");
        return;
    }
    println!("container backend present; running the app for real");

    // Before the run, and in the report's note about it: the warning, which does not stop the run.
    assert!(
        stderr.contains(
            "Warning: the start command in securevibe.toml sets `FAMILY_HUB_INSECURE_COOKIES=1`"
        ),
        "{stderr}"
    );
    let first = report
        .split("## Read this first")
        .nth(1)
        .expect("the report has its first section");
    assert!(
        first.contains(
            "Warning: its start command sets `FAMILY_HUB_INSECURE_COOKIES=1`, which looks like it \
             makes the app less secure for the run"
        ),
        "{report}"
    );

    // The setup worked: the plain requests signed in with the `__Host-` cookie, the only one the
    // app reads.
    assert!(
        report.contains("signed in as A and opened /account (200)"),
        "{report}"
    );
    // The browser was signed in with it, and the cookie it refused is named.
    assert!(
        report.contains(&format!(
            "signed in a real browser with the first user's cookies: 1 private page opened in it, \
             though the browser refused the cookie {BIG_COOKIE} ("
        )),
        "{report}"
    );
    assert!(!report.contains("not really signed in"), "{report}");
    assert!(
        !report.contains("did not open in the browser after signing in"),
        "{report}"
    );
    std::fs::remove_dir_all(&app).ok();
}
