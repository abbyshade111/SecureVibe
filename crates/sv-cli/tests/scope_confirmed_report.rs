//! The level line says whose word the level rests on: the answers confirmed through `sv review`,
//! changed since, or a confirmation that does not count here (gap analysis of 7 October 2026,
//! finding 17; ADR-024, Later, 9 October 2026), end to end through the binary.

use std::path::PathBuf;
use std::process::Command;
use sv_check::seal::App;
use sv_check::signed::{SigningKey, trust_here};
use sv_frameworks::names::CONFIG_DIR;

const APP: &str = "manifest-version = 1\n\n[app]\nname = \"Notes\"\ndescription = \"Notes.\"\naudience = \"just-me\"\n\n[stack]\nlanguages = [\"python\"]\n\n[data]\ncategories = [\"contact\"]\n";

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("sv-scope-report-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("app")).unwrap();
        std::fs::write(dir.join("app/app.py"), "print('hello')\n").unwrap();
        Scratch(dir)
    }
    fn app(&self) -> PathBuf {
        self.0.join("app")
    }
    fn config(&self) -> PathBuf {
        self.0.join("config")
    }
    /// A signing key made and trusted for the app, as `sv review` makes it.
    fn key(&self) -> SigningKey {
        let folder = self.config().join(CONFIG_DIR);
        let key = SigningKey::make_in(&folder, None).unwrap();
        let app = App::of(&self.app()).unwrap();
        assert!(trust_here(&folder, &key, &app).unwrap());
        key
    }
    /// `manifest`, with `[scope-review]` confirming these answers, sealed with `key` when given.
    fn write(&self, manifest: &str, confirmed: Option<(&str, &str, Option<&SigningKey>)>) {
        let mut text = manifest.to_owned();
        if let Some((audience, categories, key)) = confirmed {
            let mut entry = sv_manifest::ScopeReview {
                audience: audience.to_owned(),
                categories: Some(vec![categories.to_owned()]),
                by: "owner".to_owned(),
                on: "2026-10-09".to_owned(),
                seal: None,
            };
            if let Some(key) = key {
                let fields = sv_check::seal::scope_review_fields(&entry);
                let app = App::of(&self.app()).unwrap();
                entry.seal = Some(
                    key.for_app(&app)
                        .seal(&sv_check::seal::as_strs(&fields))
                        .unwrap(),
                );
            }
            text.push_str(&format!(
                "\n[scope-review]\naudience = \"{}\"\ncategories = [\"{categories}\"]\nby = \"owner\"\non = \"2026-10-09\"\n{}",
                entry.audience,
                entry
                    .seal
                    .map(|s| format!("seal = \"{s}\"\n"))
                    .unwrap_or_default()
            ));
        }
        std::fs::write(self.app().join("stackvet.toml"), text).unwrap();
    }
    /// The report's JSON and its compliance page, made on this computer, or on one given only
    /// `list` as SV_TRUSTED_SEALS and no key folder.
    fn report(&self, list: Option<&str>) -> (serde_json::Value, String) {
        let out = self.0.join("report");
        std::fs::remove_dir_all(&out).ok();
        let mut sv = Command::new(env!("CARGO_BIN_EXE_sv"));
        sv.env_remove("RUST_BACKTRACE")
            .env_remove(sv_check::signed::TRUSTED_VARIABLE);
        match list {
            None => sv.env("XDG_CONFIG_HOME", self.config()),
            Some(list) => sv
                .env("XDG_CONFIG_HOME", self.0.join("elsewhere"))
                .env(sv_check::signed::TRUSTED_VARIABLE, list),
        };
        let ran = sv
            .args([
                "report",
                self.app().to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ])
            .output()
            .expect("sv runs");
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        let json = serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap())
            .unwrap();
        let page = std::fs::read_to_string(out.join("compliance.md")).unwrap();
        (json, page)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn level_line(page: &str) -> &str {
    page.lines()
        .find(|l| l.contains("Level 1 because"))
        .unwrap_or_else(|| panic!("no level line in:\n{page}"))
}

#[test]
fn unconfirmed_answers_say_so_and_name_the_command() {
    let s = Scratch::new("none");
    s.write(APP, None);
    let (json, page) = s.report(None);
    assert!(json["level_why"].get("confirmed").is_none(), "{json}");
    let line = level_line(&page);
    assert!(
        line.contains("nobody has confirmed, so check them, and confirm them with `sv review`"),
        "{line}"
    );
}

#[test]
fn confirmed_answers_say_who_when_and_with_which_key() {
    let s = Scratch::new("confirmed");
    let key = s.key();
    s.write(APP, Some(("just-me", "contact", Some(&key))));
    let (json, page) = s.report(None);
    assert_eq!(
        json["level_why"]["confirmed"]["state"], "confirmed",
        "{json}"
    );
    let line = level_line(&page);
    assert!(
        line.contains("answers in stackvet.toml that the owner confirmed through `sv review` on 2026-10-09, signed with key SHA256:"),
        "{line}"
    );
    assert!(
        line.contains("(a key on this computer with no passphrase"),
        "{line}"
    );
    assert!(!line.contains("nobody has confirmed"), "{line}");
    // The level is the answers', confirmed or not.
    assert_eq!(json["target_level"], 1);
}

#[test]
fn an_answer_changed_since_is_unconfirmed_again() {
    let s = Scratch::new("changed");
    let key = s.key();
    // Confirmed with the data list as it was; the file now lists another category.
    s.write(
        &APP.replace("[\"contact\"]", "[\"contact\", \"location\"]"),
        Some(("just-me", "contact", Some(&key))),
    );
    let (json, page) = s.report(None);
    assert_eq!(json["level_why"]["confirmed"]["state"], "changed", "{json}");
    let line = level_line(&page);
    assert!(
        line.contains("have changed since the owner confirmed them on 2026-10-09, so they are unconfirmed again"),
        "{line}"
    );
}

#[test]
fn a_confirmation_with_no_seal_does_not_count() {
    let s = Scratch::new("unsealed");
    s.key();
    s.write(APP, Some(("just-me", "contact", None)));
    let (json, page) = s.report(None);
    assert_eq!(
        json["level_why"]["confirmed"]["state"], "not-counted",
        "{json}"
    );
    let line = level_line(&page);
    assert!(
        line.contains(
            "whose confirmation does not count here: it was not recorded through `sv review`"
        ),
        "{line}"
    );
}

#[test]
fn ci_given_the_list_counts_the_confirmation_and_cannot_tell_the_passphrase() {
    let s = Scratch::new("ci");
    let key = s.key();
    s.write(APP, Some(("just-me", "contact", Some(&key))));
    let line = key.trusted_line(&App::of(&s.app()).unwrap()).unwrap();
    let (json, page) = s.report(Some(&line));
    assert_eq!(
        json["level_why"]["confirmed"]["state"], "confirmed",
        "{json}"
    );
    let level = level_line(&page);
    assert!(
        level.contains("which the list of trusted keys in SV_TRUSTED_SEALS trusts for this app"),
        "{level}"
    );
    assert!(level.contains("cannot be told here"), "{level}");
}

/// `manifest`, with `[scope-review]` written from `entry`, sealed with `key` over `sealed_as`
/// (the same entry, unless the test wants a seal made for other answers).
fn write_entry(
    s: &Scratch,
    manifest: &str,
    entry: &sv_manifest::ScopeReview,
    sealed_as: &sv_manifest::ScopeReview,
    key: &SigningKey,
) {
    let app = App::of(&s.app()).unwrap();
    let seal = key
        .for_app(&app)
        .seal(&sv_check::seal::as_strs(
            &sv_check::seal::scope_review_fields(sealed_as),
        ))
        .unwrap();
    let categories = match &entry.categories {
        None => String::new(),
        Some(listed) => format!(
            "categories = [{}]\n",
            listed
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    std::fs::write(
        s.app().join("stackvet.toml"),
        format!(
            "{manifest}\n[scope-review]\naudience = \"{}\"\n{categories}by = \"owner\"\non = \"2026-10-09\"\nseal = \"{seal}\"\n",
            entry.audience
        ),
    )
    .unwrap();
}

fn entry(audience: &str, categories: Option<&[&str]>) -> sv_manifest::ScopeReview {
    sv_manifest::ScopeReview {
        audience: audience.to_owned(),
        categories: categories.map(|l| l.iter().map(|c| (*c).to_owned()).collect()),
        by: "owner".to_owned(),
        on: "2026-10-09".to_owned(),
        seal: None,
    }
}

fn state(s: &Scratch) -> String {
    let (json, _) = s.report(None);
    json["level_why"]["confirmed"]["state"]
        .as_str()
        .unwrap_or_else(|| panic!("no confirmation state: {json}"))
        .to_owned()
}

#[test]
fn the_audience_changed_since_is_unconfirmed_again() {
    let s = Scratch::new("audience");
    let key = s.key();
    let confirmed = entry("just-me", Some(&["contact"]));
    write_entry(&s, APP, &confirmed, &confirmed, &key);
    assert_eq!(state(&s), "confirmed", "the setup");
    write_entry(
        &s,
        &APP.replace("\"just-me\"", "\"my-team\""),
        &confirmed,
        &confirmed,
        &key,
    );
    assert_eq!(state(&s), "changed");
}

#[test]
fn a_category_in_other_capitals_is_the_same_answer() {
    let s = Scratch::new("capitals");
    let key = s.key();
    let confirmed = entry("just-me", Some(&["Contact"]));
    write_entry(&s, APP, &confirmed, &confirmed, &key);
    assert_eq!(state(&s), "confirmed");
}

#[test]
fn an_unanswered_list_confirmed_is_not_an_empty_one() {
    // Confirmed while the list was unanswered; the file now says the app holds nothing.
    let s = Scratch::new("unanswered");
    let key = s.key();
    let confirmed = entry("just-me", None);
    write_entry(
        &s,
        &APP.replace("categories = [\"contact\"]", "categories = []"),
        &confirmed,
        &confirmed,
        &key,
    );
    assert_eq!(state(&s), "changed");
    // The control: confirmed unanswered and still unanswered is the same answer.
    write_entry(
        &s,
        &APP.replace("categories = [\"contact\"]\n", ""),
        &confirmed,
        &confirmed,
        &key,
    );
    assert_eq!(state(&s), "confirmed");
}

#[test]
fn a_seal_made_for_other_answers_does_not_count() {
    // The answers in the file and in `[scope-review]` agree, but the seal was made over another
    // audience: copied, or the entry edited after it was sealed.
    let s = Scratch::new("copied");
    let key = s.key();
    let public = APP.replace("\"just-me\"", "\"public\"");
    write_entry(
        &s,
        &public,
        &entry("public", Some(&["contact"])),
        &entry("just-me", Some(&["contact"])),
        &key,
    );
    let (json, page) = s.report(None);
    assert_eq!(
        json["level_why"]["confirmed"]["state"], "not-counted",
        "{json}"
    );
    assert!(
        page.contains("whose confirmation does not count here"),
        "{page}"
    );
}
