//! The tests of `secrets.rs` that were `mod tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

#[test]
fn sv_init_s_own_template_raises_no_credential_finding() {
    let found = scan_text(
        &rules(),
        "stackvet.toml",
        sv_manifest::spec::STARTER_MANIFEST,
    );
    assert!(
        found.is_empty(),
        "{:?}",
        found
            .iter()
            .map(|f| (&f.rule_id, f.location.line))
            .collect::<Vec<_>>()
    );
    // The setup: the template really has the line that tripped it.
    assert!(sv_manifest::spec::STARTER_MANIFEST.contains(r#"password = "{new_password}""#));
}

#[test]
fn a_blank_in_sv_s_own_braces_is_a_placeholder_and_a_value_around_one_is_not() {
    let judged =
        |line: &str| !assignment_findings("stackvet.toml", line, 1, &(0..usize::MAX)).is_empty();
    assert!(!judged(r#"password = "{new_password}""#));
    assert!(!judged(r#"token = "{code}""#));
    // The control: the same blank with text of its own is still reported. Named, not printed.
    let with_text = ["{new_password}", "x9Q2vL7kP"].concat();
    assert!(
        judged(&format!(r#"password = "{with_text}""#)),
        "a value around a blank was passed over"
    );
}

#[test]
fn a_template_filling_in_its_own_token_is_not_a_credential() {
    // The line from the start-of-build test, in a Python f-string, and its relatives.
    let judged =
        |file: &str, line: &str| !assignment_findings(file, line, 1, &(0..usize::MAX)).is_empty();
    // The setup: the rule reads each name in this shape, so silence below is the expression.
    let real = ["Qv7rT2mX", "9kLp4WzN", "c8Ha"].concat();
    for name in ["csrf_token", "api_token"] {
        assert!(judged(
            "app.py",
            &format!(r#"f'<input type=hidden name={name} value="{real}">'"#)
        ));
    }
    for line in [
        r#"f'<input type=hidden name=csrf_token value="{html.escape(csrf_token)}">'"#,
        r#"f'<input name=csrf_token value="{session.csrf_token}">'"#,
        r#"f'<input name=api_token value="{tokens[0]}">'"#,
        r#"f'<input name=csrf_token value="{escape(make_token(request, 32))}">'"#,
    ] {
        assert!(!judged("app.py", line), "{line}");
    }
    // Text of its own beside the braces, or a quoted literal inside them, is still judged.
    for line in [
        format!(r#"f'<input name=csrf_token value="{{html.escape(t)}}{real}">'"#),
        format!(r#"<input name=csrf_token value="{{str('{real}')}}">"#),
        // And a key in braces is not a name: it starts with a digit.
        format!(r#"<input name=csrf_token value="{{7{real}}}">"#),
    ] {
        assert!(judged("app.py", &line), "{line}");
    }
}

#[test]
fn a_value_that_is_wholly_a_reference_is_not_a_credential_and_one_that_contains_one_is() {
    let judged = |line: &str| !assignment_findings("run.sh", line, 1, &(0..usize::MAX)).is_empty();
    // Built from pieces, so no line here reads as a key to anything scanning this file.
    let suffix = ["4f9a", "2c7b"].concat();
    let password = ["pa$$w0rd", "Q7xZ9k2L"].concat();
    for line in [
        r#"export CF_ZONE_API_TOKEN="$CF_DNS_API_TOKEN""#.to_owned(),
        r#"TOKEN="$(cat /run/secrets/token)""#.to_owned(),
        r#"API_KEY="%API_KEY%""#.to_owned(),
        r#"$Password = "$env:DB_PASSWORD""#.to_owned(),
        "SECRET=\"`vault read -field=value secret/app`\"".to_owned(),
    ] {
        assert!(!judged(&line), "a reference was reported: {line}");
    }
    // The controls: a value with text of its own is still reported, so the lines above were
    // passed over for being references and not for the shape of the line.
    // Named rather than printed on failure: even a made-up credential is not written to output.
    for (case, line) in [
        (
            "a reference with text after it",
            format!(r#"API_KEY="$CF_DNS_API_TOKEN-extra-{suffix}""#),
        ),
        (
            "a password with dollar signs in it",
            format!(r#"PASSWORD="{password}""#),
        ),
    ] {
        assert!(judged(&line), "not reported: {case}");
    }
}

use super::*;

/// Builds a credential-shaped string at run time, from pieces.
///
/// Written this way because a literal here that looks like a real key is one GitHub's push protection
/// blocks — it blocked this branch once already, on this crate's own test data. The alternative is
/// clicking "allow this secret" on a repository whose subject is not leaking secrets, which teaches
/// exactly the reflex this scanner exists to make unnecessary. The rules still see a whole key: it is
/// assembled before it is scanned.
fn credential_shaped(parts: &[&str], separator: &str) -> String {
    parts.join(separator)
}

#[test]
fn redacting_cuts_a_known_key_anywhere_and_a_value_by_its_name() {
    let key = credential_shaped(&["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb"], "-");
    let text = format!(
        "Authorization failed for {key} at /v1/messages\n\
             password: 'S3cr3t-Value-99'\n\
             SECRET_KEY=changeme\n"
    );
    let (out, n) = redact_text(&rules(), &text);
    assert_eq!(n, 2);
    // No message prints `out`: were a cut missed, it would hold the credential.
    assert!(!out.contains(&key), "the key was not cut short");
    assert!(
        !out.contains("S3cr3t-Value-99"),
        "the password was not cut short"
    );
    assert!(out.contains("Authorization failed for [redacted: sk-a…"));
    assert!(out.contains("password: '[redacted: S3cr…"));
    // A placeholder is not a credential, and cutting it would hide the mistake it points at.
    assert!(out.contains("SECRET_KEY=changeme"));
}

fn rules() -> SecretRules {
    SecretRules::load(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"),
    )
    .expect("rules load")
}

#[test]
fn every_pattern_in_the_data_file_compiles() {
    // A pattern Rust cannot compile would otherwise be a rule that silently never fires.
    let r = rules();
    assert!(r.len() >= 8, "only {} rules loaded", r.len());
}

#[test]
fn it_finds_a_key_and_does_not_repeat_it() {
    let key = credential_shaped(&["sk", "ant", "api03", "REALLOOKINGKEYVALUE123456"], "-");
    let text = format!("ANTHROPIC = '{key}'\n");
    let text = text.as_str();
    let found = scan_text(&rules(), "src/app.py", text);
    let key = found
        .iter()
        .find(|f| f.rule_id == "secrets.anthropic-key")
        .expect("key found");
    assert_eq!(key.location.line, 1);
    assert!(key.requirement_ids.contains(&"V13.3.1".to_string()));
    let rendered = serde_json::to_string(&found).unwrap();
    assert!(
        !rendered.contains("REALLOOKINGKEYVALUE"),
        "the key reached the finding"
    );
}

/// `n` characters from `alphabet`, in a fixed order, for building key-shaped test values. Fixed
/// so a failing test fails the same way twice; built at run time so no file holds a key.
fn filler(n: usize, alphabet: &str) -> String {
    alphabet.chars().cycle().take(n).collect()
}

const MIXED: &str = "Qm7Rz2Kv9Lp4Wn8Hs3Jd6Tf1Gb5Yc0";
const LETTERS: &str = "QmRzKvLpWnHsJdTfGbYcAeBi";

/// The key formats of the providers AI-built apps use, each as its published pattern has it
/// (gitleaks for SendGrid, Twilio, and Perplexity; TruffleHog for the rest, read 7 October 2026).
/// Each is built from pieces at run time, found once under its own rule, and kept out of the
/// finding; one character short, it is not a key of that format and is not reported.
#[test]
fn the_ai_app_providers_keys_are_found_by_their_own_formats() {
    const HEX: &str = "0123456789abcdef";
    const BASE58: &str = "QmRzKvLpWnHsJdTfGbYcAeBi123456789";
    const LOWER: &str = "qmrzkvlpwnhsjdtf0123456789";
    let cases: [(&str, String, String); 10] = [
        (
            "secrets.sendgrid-key",
            credential_shaped(&["SG", &filler(22, MIXED), &filler(43, MIXED)], "."),
            credential_shaped(&["SG", &filler(22, MIXED), &filler(42, MIXED)], "."),
        ),
        (
            "secrets.twilio-key",
            credential_shaped(&["SK", &filler(32, HEX)], ""),
            credential_shaped(&["SK", &filler(31, HEX)], ""),
        ),
        (
            "secrets.groq-key",
            credential_shaped(&["gsk", &filler(52, MIXED)], "_"),
            credential_shaped(&["gsk", &filler(51, MIXED)], "_"),
        ),
        (
            "secrets.replicate-token",
            credential_shaped(&["r8", &filler(37, MIXED)], "_"),
            credential_shaped(&["r8", &filler(36, MIXED)], "_"),
        ),
        (
            "secrets.resend-key",
            credential_shaped(&["re", &filler(8, BASE58), &filler(24, BASE58)], "_"),
            credential_shaped(&["re", &filler(8, BASE58), &filler(23, BASE58)], "_"),
        ),
        (
            "secrets.supabase-token",
            credential_shaped(&["sbp", &filler(40, LOWER)], "_"),
            credential_shaped(&["sbp", &filler(39, LOWER)], "_"),
        ),
        (
            "secrets.openrouter-key",
            credential_shaped(&["sk", "or", "v1", &filler(64, HEX)], "-"),
            credential_shaped(&["sk", "or", "v1", &filler(63, HEX)], "-"),
        ),
        (
            "secrets.pinecone-key",
            credential_shaped(&["pcsk", &filler(5, MIXED), &filler(63, MIXED)], "_"),
            credential_shaped(&["pcsk", &filler(5, MIXED), &filler(62, MIXED)], "_"),
        ),
        (
            "secrets.perplexity-key",
            credential_shaped(&["pplx", &filler(48, MIXED)], "-"),
            credential_shaped(&["pplx", &filler(47, MIXED)], "-"),
        ),
        (
            "secrets.xai-key",
            credential_shaped(&["xai", &filler(80, MIXED)], "-"),
            credential_shaped(&["xai", &filler(79, MIXED)], "-"),
        ),
    ];
    let rules = rules();
    for (rule, key, short) in &cases {
        // Not under a name that says it is a credential, so only the format can find it.
        let text = format!("client = make_client(\"{key}\")\n");
        let found = scan_text(&rules, "src/clients.py", &text);
        let hits: Vec<_> = found.iter().filter(|f| f.rule_id == *rule).collect();
        assert_eq!(hits.len(), 1, "{rule}: {found:?}");
        assert!(hits[0].requirement_ids.contains(&"V13.3.1".to_string()));
        let rendered = serde_json::to_string(&found).unwrap();
        assert!(
            !rendered.contains(&key[key.len() - 12..]),
            "{rule}: the key reached the finding"
        );
        let text = format!("client = make_client(\"{short}\")\n");
        assert!(
            scan_text(&rules, "src/clients.py", &text)
                .iter()
                .all(|f| f.rule_id != *rule),
            "{rule}: one character short was reported"
        );
    }
}

#[test]
fn a_password_in_a_web_address_is_found_and_never_shown() {
    // Built from pieces, so no file holds an address with a password in it.
    let password = filler(16, MIXED);
    let address = |scheme: &str, user: &str, pw: &str| {
        format!("{scheme}://{user}:{pw}@db.internal.example:5432/app")
    };
    let rules = rules();
    for scheme in ["postgresql", "mysql", "mongodb+srv", "redis", "amqp"] {
        let text = format!(
            "engine = create_engine(\"{}\")\n",
            address(scheme, "app_owner", &password)
        );
        let found: Vec<_> = scan_text(&rules, "src/db.py", &text)
            .into_iter()
            .filter(|f| f.rule_id == URL_PASSWORD_RULE)
            .collect();
        assert_eq!(found.len(), 1, "{scheme}");
        assert_eq!(found[0].requirement_ids, vec!["V13.3.1", "SBD-AC-05"]);
        let rendered = serde_json::to_string(&found).unwrap();
        assert!(
            !rendered.contains(&password[4..]),
            "{scheme}: the password reached the finding"
        );
        let (out, n) = redact_text(&rules, &text);
        assert_eq!(n, 1, "{scheme}");
        assert!(
            !out.contains(&password),
            "{scheme}: the password was not cut"
        );
    }
    // Not reported: a reference to a setting, a placeholder, a stock password, the user name
    // again, an address with no password, and the same address in a .env file.
    for (case, pw_or_text, file) in [
        (
            "a reference to a setting",
            address("postgresql", "app", "${DB_PASSWORD}"),
            "src/db.py",
        ),
        (
            "a placeholder",
            address("postgresql", "app", "<password>"),
            "src/db.py",
        ),
        (
            "a format blank",
            address("postgresql", "app", "%(password)s"),
            "src/db.py",
        ),
        (
            "the user name again, a stock one",
            address("postgresql", "postgres", "postgres"),
            "docker-compose.yml",
        ),
        (
            "a stock placeholder",
            address("postgresql", "app", "changeme"),
            "src/db.py",
        ),
        (
            "an example password",
            address("postgresql", "myuser", "mypassword"),
            "README.md",
        ),
        (
            "the user name again",
            address("postgresql", "appuser", "appuser"),
            "src/db.py",
        ),
        (
            "a stock password",
            address("mysql", "app", "root"),
            "src/db.py",
        ),
        (
            "a row of x's",
            address("postgresql", "app", "xxxxxxxx"),
            "src/db.py",
        ),
        (
            "no password",
            "postgresql://app@db.internal.example:5432/app".to_owned(),
            "src/db.py",
        ),
        (
            "a path with a colon",
            "https://example.com/a:b@c".to_owned(),
            "src/db.py",
        ),
        (
            "a .env file",
            address("postgresql", "app_owner", &password),
            ".env",
        ),
    ] {
        let text = format!("url = \"{pw_or_text}\"\n");
        // The case's name only: the text may hold the test's password, and a message is output.
        assert!(
            scan_text(&rules, file, &text)
                .iter()
                .all(|f| f.rule_id != URL_PASSWORD_RULE),
            "reported: {case} in {file}"
        );
    }
}

/// OpenAI's middle marker, in two pieces, so this file does not hold a key's shape whole.
fn openai_marker() -> String {
    ["T3Bl", "bkFJ"].concat()
}

/// A project key ending in `-`, which a trailing word boundary would have missed, and a
/// legacy key: the two shapes in gitleaks' rule that a person is likely to have.
fn openai_keys() -> Vec<String> {
    let tail = format!("{}-", filler(73, MIXED));
    vec![
        credential_shaped(
            &[
                "sk",
                "proj",
                &format!("{}{}{tail}", filler(74, MIXED), openai_marker()),
            ],
            "-",
        ),
        credential_shaped(
            &[
                "sk",
                &format!(
                    "{}{}{}",
                    filler(20, MIXED),
                    openai_marker(),
                    filler(20, MIXED)
                ),
            ],
            "-",
        ),
    ]
}

fn huggingface_tokens() -> Vec<String> {
    vec![
        credential_shaped(&["hf", &filler(34, LETTERS)], "_"),
        credential_shaped(&["api", "org", &filler(34, LETTERS)], "_"),
    ]
}

#[test]
fn openai_and_hugging_face_keys_are_found_where_nothing_found_them_before() {
    // Where the generic assignment rule does not reach: an env file other than .env itself,
    // which it skips on purpose, and a shell line with no quotes. Before these rules an OpenAI
    // key in `.env.production` or a Dockerfile's ENV line was reported by nothing.
    let cases: Vec<(String, &str)> = openai_keys()
        .into_iter()
        .map(|k| (k, "secrets.openai-key"))
        .chain(
            huggingface_tokens()
                .into_iter()
                .map(|k| (k, "secrets.huggingface-token")),
        )
        .collect();
    for (key, rule) in &cases {
        for (file, text) in [
            (".env.production", format!("OPENAI_API_KEY={key}\n")),
            ("deploy.sh", format!("export TOKEN={key}\n")),
            (
                "Dockerfile",
                format!("FROM python:3.12\nENV HF_TOKEN {key}\n"),
            ),
        ] {
            let found = scan_text(&rules(), file, &text);
            let hits: Vec<&Finding> = found.iter().filter(|f| f.rule_id == *rule).collect();
            assert_eq!(
                hits.len(),
                1,
                "{rule} in {file}: {:?}",
                found.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
            );
            let hit = hits[0];
            assert!(hit.requirement_ids.contains(&"V13.3.1".to_string()));
            // Four characters and the length, never the key.
            let rendered = serde_json::to_string(&found).unwrap();
            assert!(
                !rendered.contains(key.as_str()),
                "{rule}: the key reached the finding"
            );
            assert_eq!(
                hit.secret.as_ref().map(|s| s.length()),
                Some(key.len()),
                "{rule} in {file}: the whole key, and only the key, was matched"
            );
        }
    }
}

#[test]
fn redaction_cuts_openai_and_hugging_face_keys_from_output() {
    // What a failing test suite printed goes into the report; a key in it must not.
    for key in openai_keys().into_iter().chain(huggingface_tokens()) {
        let text = format!("request failed: Bearer {key} was refused\n");
        let (out, n) = redact_text(&rules(), &text);
        assert_eq!(n, 1, "one credential in the line");
        assert!(!out.contains(key.as_str()), "the key was not cut short");
    }
}

#[test]
fn each_ai_vendors_key_is_reported_by_its_own_rule_alone() {
    // Anthropic's keys start sk-ant-, OpenAI's sk-proj- or sk-: a pattern for one that
    // forgot its marker would claim the other's keys too, and one key would read as two.
    let anthropic = credential_shaped(&["sk", "ant", "api03", &filler(40, MIXED)], "-");
    let cases: Vec<(String, &str)> = std::iter::once((anthropic, "secrets.anthropic-key"))
        .chain(openai_keys().into_iter().map(|k| (k, "secrets.openai-key")))
        .chain(
            huggingface_tokens()
                .into_iter()
                .map(|k| (k, "secrets.huggingface-token")),
        )
        .collect();
    for (key, rule) in &cases {
        let text = format!("key: {key}\n");
        let found = scan_text(&rules(), "notes.txt", &text);
        let ids: Vec<&str> = found.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, [*rule], "{}…: {ids:?}", &key[..8]);
    }
}

#[test]
fn near_misses_are_not_openai_or_hugging_face_keys() {
    // Shapes close to the rules that are not keys: a Hugging Face identifier, a token one
    // letter short or long, and an sk- string with no marker in it.
    for text in [
        "from huggingface_hub import hf_hub_download\n".to_owned(),
        format!("x = 'hf_{}'\n", filler(33, LETTERS)),
        format!("x = 'hf_{}'\n", filler(35, LETTERS)),
        format!("x = 'sk-{}'\n", filler(48, MIXED)),
    ] {
        let found = scan_text(&rules(), "src/app.py", &text);
        assert!(
            !found
                .iter()
                .any(|f| f.rule_id == "secrets.openai-key"
                    || f.rule_id == "secrets.huggingface-token"),
            "{text:?}: {:?}",
            found.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }
}

fn big_scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-secrets-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn aws_key(tail: &str) -> String {
    credential_shaped(&["AKIA", tail], "")
}

#[test]
fn a_key_in_utf16_or_latin1_text_is_found() {
    // Text saved by Windows tools, or by an editor set to Latin-1, was not read at all.
    let dir = big_scratch("encodings");
    let key = aws_key("Q7RZ2KV9LP4WN8HE");
    let mut utf16 = vec![0xFF, 0xFE];
    for unit in format!("AWS_KEY={key}\n").encode_utf16() {
        utf16.extend(unit.to_le_bytes());
    }
    std::fs::write(dir.join("config.ps1"), utf16).unwrap();
    let mut latin1 = b"# Gr\xfc\xdfe\n".to_vec();
    latin1.extend(format!("aws = {key}\n").as_bytes());
    std::fs::write(dir.join("notes.txt"), latin1).unwrap();
    let scan = scan_dir(&rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        scan.coverage.skipped.is_empty(),
        "{:?}",
        scan.coverage.skipped
    );
    let mut files: Vec<&str> = scan
        .findings
        .iter()
        .filter(|f| f.rule_id.contains("aws"))
        .map(|f| f.location.file.as_str())
        .collect();
    files.sort_unstable();
    // The files are named, never the key.
    assert_eq!(files, vec!["config.ps1", "notes.txt"]);
}

#[test]
fn an_image_or_ds_store_is_named_and_leaves_the_scan_whole() {
    let dir = big_scratch("no-written-text");
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join(".DS_Store"),
        b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00",
    )
    .unwrap();
    std::fs::write(dir.join("logo.png"), b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR").unwrap();
    let clean = scan_dir(&rules(), &dir);
    // The control: an unknown binary file is still a gap, and there is no clean claim.
    std::fs::write(
        dir.join("data.bin"),
        b"\x7fELF\x02\x01\x01\x00\x00\xff\x80\x9c",
    )
    .unwrap();
    let gap = scan_dir(&rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        clean.coverage.skipped.is_empty(),
        "{:?}",
        clean.coverage.skipped
    );
    let named: Vec<&str> = clean
        .coverage
        .no_written_text
        .iter()
        .map(|(f, _)| f.as_str())
        .collect();
    assert_eq!(named, vec![".DS_Store", "logo.png"]);
    assert_eq!(clean.verified.len(), 1, "{clean:?}");
    assert!(
        clean.verified[0].scope.contains("2 more not read"),
        "{:?}",
        clean.verified[0].scope
    );

    assert_eq!(
        gap.coverage.skipped,
        vec![("data.bin".to_owned(), "not a text file".to_owned())]
    );
    assert!(gap.verified.is_empty(), "{gap:?}");
}

#[test]
fn keys_in_a_large_one_line_file_are_found_once_each_wherever_the_pieces_fall() {
    // cato-pipeline's case: a vendored catalog of several MB, on one line as JSON often is. Three
    // keys: one across the boundary where the first piece's own part ends (1 MB less 64 KB), one
    // across the first piece's physical end (1 MB), and one past the 2 MB mark.
    let keys = [
        aws_key("Q7RZ2KV9LP4WN8HA"),
        aws_key("Q7RZ2KV9LP4WN8HB"),
        aws_key("Q7RZ2KV9LP4WN8HC"),
    ];
    let mib = 1024 * 1024;
    let snippets: [(usize, &str); 3] = [
        (mib - 64 * 1024 - 5, keys[0].as_str()),
        (mib - 10, keys[1].as_str()),
        (2 * mib + mib / 2, keys[2].as_str()),
    ];
    let mut line = String::from("{\"text\": \"");
    for (offset, snippet) in snippets {
        line.push_str(&"y".repeat(offset - line.len()));
        line.push(' ');
        line.push_str(snippet);
        line.push(' ');
    }
    line.push_str(&"y".repeat(3 * mib - line.len()));
    line.push_str("\"}\n");
    let dir = big_scratch("one-line");
    std::fs::write(dir.join("catalog.json"), &line).unwrap();
    let listing = sv_scan::files::Listing::of(&dir);
    assert!(listing.files[0].too_large(), "the setup: over 2 MB");
    let scan = scan_listing(&rules(), &listing);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        scan.coverage.skipped.is_empty(),
        "{:?}",
        scan.coverage.skipped
    );
    assert_eq!(scan.coverage.read_in_pieces, ["catalog.json"]);
    let aws: Vec<&Finding> = scan
        .findings
        .iter()
        .filter(|f| f.rule_id == "secrets.aws-access-key")
        .collect();
    assert_eq!(aws.len(), 3, "each key once, none twice, none cut in half");
    for f in &aws {
        assert_eq!(f.location.line, 1);
        assert_eq!(
            f.secret.as_ref().map(|s| s.length()),
            Some(20),
            "a whole key"
        );
        assert_eq!(
            f.confidence,
            Confidence::High,
            "a vendor shape keeps its confidence"
        );
    }
    let rendered = serde_json::to_string(&scan.findings).unwrap();
    for key in &keys {
        assert!(
            !rendered.contains(key.as_str()),
            "a key reached the finding"
        );
    }
}

#[test]
fn a_piece_reports_only_what_starts_in_its_own_part() {
    // One piece, three lines: the first is look-behind, the last look-ahead, and only the
    // middle is the piece's own. A key or an assignment outside the middle belongs to the piece
    // before or after, and is reported there; here it must not be, or it is reported twice.
    let key = aws_key("Q7RZ2KV9LP4WN8HE");
    let value = credential_shaped(&["Zq8", "Lm2", "Vx7", "Rt4", "Wp9", "Kd3"], "");
    let behind = format!("aws = {key}\npassword = \"{value}\"\n");
    let own = format!("aws = {key}\npassword = \"{value}\"\n");
    let ahead = format!("aws = {key}\npassword = \"{value}\"\n");
    let text = format!("{behind}{own}{ahead}");
    let keep = behind.len()..behind.len() + own.len();
    let found = scan_piece(&rules(), "dump.txt", &text, 100, keep, true);
    let mut got: Vec<(&str, usize)> = found
        .iter()
        .map(|f| (f.rule_id.as_str(), f.location.line))
        .collect();
    got.sort();
    // `text` starts on line 100, so its own part is lines 102 and 103.
    assert_eq!(
        got,
        [
            ("secrets.aws-access-key", 102),
            ("secrets.credential-assignment", 103)
        ]
    );
}

#[test]
fn a_piece_sees_the_character_before_its_own_part() {
    // `AKIA…` glued to the letter before it is not a key: the rule asks for a word boundary.
    // Placed so that `AKIA` is the first byte of the second piece's own part, a piece with no
    // look-behind would see a boundary that the file does not have, and report it.
    let mib = 1024 * 1024;
    let own_starts = mib - 64 * 1024;
    let glued = format!("y{}", aws_key("Q7RZ2KV9LP4WN8HF"));
    let mut line = "y".repeat(own_starts - 1);
    line.push_str(&glued);
    line.push_str(&" y".repeat(mib));
    line.push('\n');
    assert_eq!(
        &line[own_starts..own_starts + 4],
        "AKIA",
        "the setup: at the boundary"
    );
    let dir = big_scratch("glued");
    std::fs::write(dir.join("catalog.txt"), &line).unwrap();
    let scan = scan_dir(&rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        scan.coverage.read_in_pieces,
        ["catalog.txt"],
        "the setup: read in pieces"
    );
    assert!(
        !scan
            .findings
            .iter()
            .any(|f| f.rule_id == "secrets.aws-access-key"),
        "a key the file does not have: {:?}",
        scan.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn a_large_file_gives_the_line_an_editor_shows_and_a_weaker_assignment() {
    // Many short lines, so the pieces start mid-file on counted lines. A key on line 45,000 must
    // say 45,000. An assignment in a large file is reported with low confidence: a long
    // random-looking value in generated data is as likely a hash as a key.
    let key = aws_key("Q7RZ2KV9LP4WN8HD");
    let value = credential_shaped(&["Zq8", "Lm2", "Vx7", "Rt4", "Wp9", "Kd3"], "");
    let mut text = String::new();
    for i in 1..=60_000 {
        match i {
            45_000 => text.push_str(&format!("aws = {key}\n")),
            50_000 => text.push_str(&format!("password = \"{value}\"\n")),
            _ => text.push_str(&format!("{i:>8} a line of generated data, nothing in it\n")),
        }
    }
    let dir = big_scratch("many-lines");
    std::fs::write(dir.join("dump.txt"), &text).unwrap();
    let listing = sv_scan::files::Listing::of(&dir);
    assert!(listing.files[0].too_large(), "the setup: over 2 MB");
    let scan = scan_listing(&rules(), &listing);
    std::fs::remove_dir_all(&dir).ok();
    let aws = scan
        .findings
        .iter()
        .find(|f| f.rule_id == "secrets.aws-access-key")
        .expect("the key is found");
    assert_eq!(aws.location.line, 45_000);
    let assigned = scan
        .findings
        .iter()
        .find(|f| f.rule_id == "secrets.credential-assignment")
        .expect("the assignment is found");
    assert_eq!(assigned.location.line, 50_000);
    assert_eq!(assigned.confidence, Confidence::Low);
    // The same line in an ordinary file keeps the rule's usual confidence.
    let small = scan_text(&rules(), "src/app.py", &format!("password = \"{value}\"\n"));
    assert_eq!(small[0].confidence, Confidence::Medium);
}

#[test]
fn an_assignment_in_the_overlap_is_reported_once_and_weaker() {
    // Alone on its line, since the assignment rule stands aside for a vendor key on the same
    // line. Inside the overlap: the first piece reads it as look-ahead and the second owns it,
    // so it is reported once, and with low confidence, as a large file's assignment is.
    let value = credential_shaped(&["Zq8", "Lm2", "Vx7", "Rt4", "Wp9", "Kd3"], "");
    let mib = 1024 * 1024;
    let mut line = String::from("{\"text\": \"");
    line.push_str(&"y".repeat(mib - 30_000 - line.len()));
    line.push_str(&format!(" password = '{value}' "));
    line.push_str(&"y".repeat(3 * mib - line.len()));
    line.push_str("\"}\n");
    let dir = big_scratch("overlap-assignment");
    std::fs::write(dir.join("catalog.json"), &line).unwrap();
    let scan = scan_dir(&rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        scan.coverage.read_in_pieces,
        ["catalog.json"],
        "the setup: read in pieces"
    );
    let assigned: Vec<&Finding> = scan
        .findings
        .iter()
        .filter(|f| f.rule_id == "secrets.credential-assignment")
        .collect();
    assert_eq!(assigned.len(), 1, "the assignment in the overlap, once");
    assert_eq!(assigned[0].confidence, Confidence::Low);
    let rendered = serde_json::to_string(&scan.findings).unwrap();
    assert!(
        !rendered.contains(value.as_str()),
        "the value reached the finding"
    );
}

#[test]
fn a_large_file_of_accented_text_is_read_and_not_called_binary() {
    // Two- and four-byte characters throughout, so pieces end in the middle of one: the scan
    // must read on, and find the key past the 2 MB mark, rather than refuse the file.
    let key = aws_key("Q7RZ2KV9LP4WN8HG");
    let mut text = "Détails 🔑 réglementés ü\n".repeat(100_000);
    text.push_str(&format!("aws = {key}\n"));
    let dir = big_scratch("accented");
    std::fs::write(dir.join("catalogue.txt"), &text).unwrap();
    let scan = scan_dir(&rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        text.len() as u64 > sv_scan::files::MAX_FILE_BYTES,
        "the setup: over 2 MB"
    );
    assert!(
        scan.coverage.skipped.is_empty(),
        "{:?}",
        scan.coverage.skipped
    );
    let aws = scan
        .findings
        .iter()
        .find(|f| f.rule_id == "secrets.aws-access-key")
        .expect("the key past 2 MB is found");
    assert_eq!(aws.location.line, 100_001);
}

#[test]
fn a_large_file_with_nothing_in_it_leaves_the_scan_clean_and_says_how_it_was_read() {
    let dir = big_scratch("clean");
    std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
    std::fs::write(
        dir.join("catalog.json"),
        format!("{{\"text\": \"{}\"}}\n", "y".repeat(3 * 1024 * 1024)),
    )
    .unwrap();
    let scan = scan_dir(&rules(), &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(scan.coverage.files_read, 2);
    assert!(scan.coverage.skipped.is_empty());
    let clean = scan
        .verified
        .first()
        .expect("a clean scan, not an unfinished one");
    assert!(
        clean
            .scope
            .contains("2 files (1 over 2 MB, read in pieces)"),
        "{}",
        clean.scope
    );
}

#[test]
fn a_placeholder_word_counts_only_as_a_word_of_its_own() {
    // A4: the markers matched anywhere, so a real key with `xxx` or `todo` among its random
    // characters was taken for a placeholder.
    for value in [
        "your-api-key-here",
        "YOUR_API_KEY",
        "sk-ant-changeme",
        "changeme123",
        "TODO",
        "todo: put the key here",
        "xxx-xxx-xxx",
        "https://api.example.com/v1",
        "replace_me",
        "insert-token",
        "dummy",
        "AKIAEXAMPLEEXAMPLE12",
        "todo1",
    ] {
        assert!(looks_like_placeholder(value), "{value}");
    }
    for value in [
        "aB3xXxQ9",
        "kTodoZ7q",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eHgifQ.abcXXXdef",
    ] {
        assert!(!looks_like_placeholder(value), "{value}");
    }
    // How often random JWTs are taken for placeholders now: none in twenty thousand, made the
    // same way each run so a failure can be looked at again.
    let mut seed: u64 = 0x5eed_cafe_f00d_d00d;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut part = |n: usize| -> String {
        (0..n)
            .map(|_| B64URL[(next() % 64) as usize] as char)
            .collect()
    };
    let mut dropped = 0;
    for _ in 0..20_000 {
        let jwt = format!("eyJhbGciOiJIUzI1NiJ9.{}.{}", part(60), part(43));
        if looks_like_placeholder(&jwt) {
            dropped += 1;
        }
    }
    assert_eq!(
        dropped, 0,
        "{dropped} of 20,000 random JWTs taken for placeholders"
    );
}

#[test]
fn sv_s_own_redaction_marker_is_read_as_one_escaped_or_not() {
    // R13 escapes brackets in Markdown, and `sv bundle` reads the report back (S8).
    for marker in [
        "[redacted: Qv7r… (16 more characters)]",
        "\\[redacted: Qv7r… (16 more characters)\\]",
        "\\[redacted: a\\[b… (9 more characters)\\]",
        "[redacted: abc]",
    ] {
        assert!(looks_like_placeholder(marker), "{marker}");
    }
    // A real value written beside the words is still one.
    let key = credential_shaped(&["Qv7rXk2", "Lp9Wm4", "Tz8Yb"], "");
    assert!(!looks_like_placeholder(&format!("\\[redacted: {key}\\]")));
    assert!(!looks_like_placeholder(&key));
}

#[test]
fn a_placeholder_is_not_reported() {
    // The rule that decides whether anybody keeps using the scanner.
    for value in [
        "your-api-key-here",
        "sk-ant-changeme",
        "${ANTHROPIC_API_KEY}",
        "<your key>",
        "",
    ] {
        let text = format!("api_key = \"{value}\"\n");
        let found = scan_text(&rules(), "src/app.py", &text);
        assert!(
            found.is_empty(),
            "reported a placeholder {value:?}: {found:?}"
        );
    }
}

#[test]
fn a_credential_assignment_is_found_by_name_and_entropy_together() {
    let text = "db_password = \"Xk7#mQ92vLpR4sTz\"\n";
    let found = scan_text(&rules(), "src/config.py", text);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].rule_id, "secrets.credential-assignment");
}

/// The deep review's H3: the shapes a credential is written in that only `name = "v"` and
/// `name: "v"` were read in until 4 October 2026. `{v}` is replaced by a made-up value built at
/// run time; findings are named, never printed, on failure.
const SHAPES_CAUGHT: &[(&str, &str, &str)] = &[
    ("a JSON key", "config.json", r#"{ "password": "{v}" }"#),
    (
        "a Python dict key",
        "app.py",
        r#"CONFIG = {"api_key": "{v}"}"#,
    ),
    ("PHP's =>", "config.php", r#"'password' => '{v}',"#),
    ("Ruby's =>", "config.rb", r#"{ :secret_key => "{v}" }"#),
    ("Go's :=", "main.go", r#"	dbPassword := "{v}""#),
    (
        "Go's var with a type",
        "main.go",
        r#"var dbPassword string = "{v}""#,
    ),
    (
        "TypeScript's typed const",
        "app.ts",
        r#"const apiKey: string = "{v}";"#,
    ),
    // Read twice, once with the type as the name: reported once.
    (
        "a TypeScript type named like a key",
        "app.ts",
        r#"const apiKey: ApiKey = "{v}";"#,
    ),
    (
        "Kotlin's typed val",
        "App.kt",
        r#"val password: String = "{v}""#,
    ),
    (
        "Rust's typed const",
        "main.rs",
        r#"const API_KEY: &'static str = "{v}";"#,
    ),
    (
        "Java's typed field",
        "App.java",
        r#"private static final String DB_PASSWORD = "{v}";"#,
    ),
    (
        "unquoted YAML",
        "config.yml",
        "database:\n  password: {v}\n",
    ),
    (
        "unquoted YAML in a list",
        "compose.yaml",
        "  - token: {v}  # prod\n",
    ),
    ("a .properties line", "app.properties", "db.password={v}\n"),
    (
        "Python's getenv default",
        "app.py",
        r#"os.getenv("DB_PASSWORD", "{v}")"#,
    ),
    (
        "Python's environ.get default",
        "app.py",
        r#"os.environ.get('SECRET_KEY', '{v}')"#,
    ),
    (
        "Python's or default",
        "app.py",
        r#"os.environ.get("SECRET_KEY") or "{v}""#,
    ),
    (
        "Ruby's ENV.fetch default",
        "app.rb",
        r#"ENV.fetch("API_KEY", "{v}")"#,
    ),
    (
        "Ruby's ENV[] || default",
        "app.rb",
        r#"ENV["API_KEY"] || "{v}""#,
    ),
    (
        "Node's || default",
        "app.js",
        r#"const s = process.env.JWT_SECRET || "{v}";"#,
    ),
    (
        "Node's ?? default",
        "app.ts",
        r#"process.env["JWT_SECRET"] ?? '{v}'"#,
    ),
    (
        "Laravel's env default",
        "config.php",
        r#"'password' => env('DB_PASSWORD', '{v}'),"#,
    ),
    (
        "PHP's getenv ?: default",
        "db.php",
        r#"$p = getenv('DB_PASSWORD') ?: '{v}';"#,
    ),
    // Shell scripts and Dockerfiles, unquoted (H3's leftovers, 5 October 2026).
    ("a shell variable", "deploy.sh", "DB_PASSWORD={v}"),
    // Quoted, read by the first shape alone: once, not again as unquoted.
    (
        "a quoted shell export",
        "deploy.sh",
        r#"export API_KEY="{v}""#,
    ),
    (
        "a quoted Dockerfile ENV",
        "Dockerfile",
        r#"ENV API_KEY="{v}""#,
    ),
    ("a shell export", "run.bash", "  export API_KEY={v}  # prod"),
    (
        "a shell variable before a command",
        "migrate.sh",
        "DB_PASSWORD={v} ./manage.py migrate",
    ),
    (
        "a declared shell variable",
        "env.zsh",
        "declare -x SECRET_KEY={v}",
    ),
    (
        "a Dockerfile ENV with =",
        "Dockerfile",
        "ENV DB_PASSWORD={v}",
    ),
    (
        "a Dockerfile ENV with a space",
        "Dockerfile",
        "ENV DB_PASSWORD {v}",
    ),
    (
        "a Dockerfile ARG default",
        "api.Dockerfile",
        "ARG API_TOKEN={v}",
    ),
    (
        "a lower-case env line",
        "Dockerfile.prod",
        "env SECRET_KEY={v}",
    ),
];

/// A made-up credential: mixed case and digits, no quote, `#`, or space, so every shape can hold it.
fn made_up_value() -> String {
    ["Xk7mQ92v", "LpR4sTzW"].concat()
}

#[test]
fn a_credential_is_found_in_every_shape_it_is_commonly_written_in() {
    let value = made_up_value();
    let mut missed = Vec::new();
    for (case, file, template) in SHAPES_CAUGHT {
        let text = template.replace("{v}", &value);
        let found = scan_text(&rules(), file, &format!("{text}\n"));
        let assigned: Vec<&Finding> = found
            .iter()
            .filter(|f| f.rule_id == "secrets.credential-assignment")
            .collect();
        if assigned.len() != 1 {
            missed.push(format!("{case}: {} findings", assigned.len()));
            continue;
        }
        let rendered = serde_json::to_string(&found).unwrap();
        assert!(
            !rendered.contains(&value),
            "{case}: the value reached the finding"
        );
    }
    assert!(missed.is_empty(), "not found exactly once: {missed:?}");
}

#[test]
fn the_new_shapes_pass_over_what_is_not_a_credential_in_the_clear() {
    let value = made_up_value();
    // The setup: the made-up value is one the rule reports, so each line below is passed over for
    // what it is and not for the value.
    assert!(!scan_text(&rules(), "app.py", &format!("password = \"{value}\"\n")).is_empty());
    for (case, file, text) in [
        (
            "a getenv with no default",
            "app.py",
            r#"os.getenv("DB_PASSWORD")"#.to_owned(),
        ),
        (
            "a getenv default that is a placeholder",
            "app.py",
            r#"os.getenv("DB_PASSWORD", "changeme-please")"#.to_owned(),
        ),
        (
            "a default under a harmless name",
            "app.py",
            format!(r#"os.getenv("LOG_LEVEL", "{value}")"#),
        ),
        (
            "a typed value under a harmless name",
            "app.ts",
            format!(r#"const greeting: string = "{value}";"#),
        ),
        (
            "a Go value under a harmless name",
            "main.go",
            format!(r#"var greeting string = "{value}""#),
        ),
        (
            "a JSON key with a harmless name",
            "package.json",
            format!(r#"{{ "version": "{value}" }}"#),
        ),
        (
            "YAML read from a reference",
            "config.yml",
            "password: ${DB_PASSWORD}\n".to_owned(),
        ),
        (
            "a Home Assistant secret",
            "configuration.yaml",
            "password: !secret db_password\n".to_owned(),
        ),
        (
            "a YAML alias",
            "config.yml",
            "password: *db_password_value\n".to_owned(),
        ),
        (
            "a SOPS-encrypted value",
            "secrets.yaml",
            format!("password: ENC[AES256_GCM,data:{value},iv:{value},type:str]\n"),
        ),
        (
            "an unquoted value in code, which is a call",
            "app.py",
            "password = read_password_from_vault()\n".to_owned(),
        ),
        (
            "an unquoted value in a file that is not configuration",
            "notes.md",
            format!("password: {value}\n"),
        ),
        (
            "a shell variable read from a command",
            "deploy.sh",
            "DB_PASSWORD=$(cat /run/secrets/db_password)\n".to_owned(),
        ),
        (
            "a shell variable from a command with no space in it",
            "deploy.sh",
            "export SECRET_KEY=$(generate_secret_key_now)\n".to_owned(),
        ),
        (
            "a shell variable that is wholly another",
            "deploy.sh",
            "export API_KEY=$API_KEY_FROM_CI_SECRETS\n".to_owned(),
        ),
        (
            "a shell variable read from another",
            "deploy.sh",
            "export API_KEY=${API_KEY_FROM_CI}\n".to_owned(),
        ),
        (
            "a shell variable under a harmless name",
            "deploy.sh",
            format!("export RELEASE_TAG={value}\n"),
        ),
        (
            "a Dockerfile ENV from a build argument",
            "Dockerfile",
            "ARG API_TOKEN\nENV API_TOKEN=$API_TOKEN\n".to_owned(),
        ),
        (
            "a Dockerfile ENV under a harmless name",
            "Dockerfile",
            format!("ENV BUILD_ID {value}\n"),
        ),
        (
            "a shell line in a file that is not a script",
            "README.txt",
            format!("export API_KEY={value}\n"),
        ),
    ] {
        let found = scan_text(&rules(), file, &format!("{text}\n"));
        assert!(
            found.is_empty(),
            "reported {case}: {} findings",
            found.len()
        );
    }
}

#[test]
fn what_only_the_new_shapes_find_is_passed_over_when_it_is_text_or_a_name() {
    // The false alarms reading JSON and dict keys first brought in, each from v1's code or its
    // `node_modules` on 4 October 2026.
    for (case, file, line) in [
        (
            "a message catalog",
            "diagnosticMessages.generated.json",
            r#""Unexpected_token_1012": "Unexpected token. A constructor, method, accessor, or property was expected.","#,
        ),
        (
            "a message catalog with no spaces between words",
            "diagnosticMessages.generated.json",
            "\"Unexpected_token_1012\": \"\u{4e88}\u{671f}\u{3057}\u{306a}\u{3044}\u{30c8}\u{30fc}\u{30af}\u{30f3}\u{3067}\u{3059}\u{3002}\",",
        ),
        (
            "a package's export map",
            "package.json",
            r#""./lib/tokenize": "./lib/tokenize.js","#,
        ),
        (
            "a rule id in a typed constant",
            "workflows.rs",
            r#"pub const FORK_SECRETS: &str = "config.workflow-fork-secrets";"#,
        ),
        (
            "a sentence under a quoted key",
            "metrics.ts",
            r#"'auth_token_issued': 'Sign-in tokens issued today',"#,
        ),
    ] {
        let found = scan_text(&rules(), file, &format!("{line}\n"));
        assert!(
            found.is_empty(),
            "reported {case}: {} findings",
            found.len()
        );
    }
    // The controls. The shape read before 4 October 2026 is judged as it was, so a passphrase it
    // found is still found; written as a JSON value, it is the stated cost, and not found.
    let passphrase = ["Tr0ub4dor", "and 3 horses"].join(" ");
    assert!(
        !scan_text(
            &rules(),
            "app.py",
            &format!("password = \"{passphrase}\"\n")
        )
        .is_empty(),
        "the shape read before lost a passphrase"
    );
    assert!(
        scan_text(
            &rules(),
            "config.json",
            &format!("{{\"password\": \"{passphrase}\"}}\n")
        )
        .is_empty()
    );
    // An assignment inside a JSON string, as a report's example holds one. A wider first shape
    // read `"example": "// Before\nconst apiKey = '` as one name and value, and the regex went on
    // past the real assignment: found in v1's self-assessment report before, lost by that version.
    let in_a_string = format!(
        r#""example": "// Before\nconst apiKey = '{}';\n// After","#,
        made_up_value()
    );
    assert_eq!(
        scan_text(&rules(), "report.json", &format!("{in_a_string}\n")).len(),
        1,
        "an assignment inside a JSON string"
    );
    // A default given to a secret setting is a value whatever it reads like: lower case and
    // hyphens is how a made-up fallback secret is written (v1's planted fixture is one).
    let fallback = ["dev", "session", "secret", "for", "local"].join("-");
    assert_eq!(
        scan_text(
            &rules(),
            "app.js",
            &format!("const s = process.env.SESSION_SECRET || '{fallback}';\n"),
        )
        .len(),
        1,
        "a lower-case default for a secret setting"
    );
    assert_eq!(
        scan_text(
            &rules(),
            "app.py",
            &format!("os.getenv('SESSION_SECRET', '{fallback}')\n")
        )
        .len(),
        1,
        "a lower-case default given to getenv"
    );
    // And a credential with no space, path, or lower-case-only shape is still found in a JSON key.
    let value = made_up_value();
    assert!(
        !scan_text(
            &rules(),
            "config.json",
            &format!("{{\"password\": \"{value}\"}}\n")
        )
        .is_empty()
    );
}

#[test]
fn redacting_cuts_a_value_in_the_new_shapes_too() {
    let value = made_up_value();
    for template in [
        r#"dbPassword := "{v}""#,
        r#"'password' => '{v}'"#,
        r#"os.getenv("DB_PASSWORD", "{v}")"#,
        r#"const apiKey: string = "{v}";"#,
    ] {
        let (out, n) = redact_text(&rules(), &template.replace("{v}", &value));
        // No message prints `out`: were a cut missed, it would hold the value.
        assert!(!out.contains(&value), "not cut: {template}");
        assert!(n >= 1, "{template}: nothing cut");
        // The older pattern reads the `=` of `:=` and the `>` of `=>` as a value; cutting those
        // tells the reader nothing.
        assert!(
            !out.contains("[redacted: =") && !out.contains("[redacted: >"),
            "{template}: punctuation cut as a value"
        );
    }
}

/// The one assignment finding on `line`, which must be there: a control that is not reported
/// at all would pass "keeps its severity" for the wrong reason.
fn the_assignment(line: &str) -> Finding {
    let found = assignment_findings("app/views.py", line, 1, &(0..usize::MAX));
    assert_eq!(
        found.len(),
        1,
        "expected one finding on a line of {} characters",
        line.len()
    );
    found.into_iter().next().expect("one finding")
}

#[test]
fn a_message_under_a_password_name_is_reported_low_and_says_it_reads_like_a_sentence() {
    // family-hub, 3 October 2026: this line was rated high, with advice to change the credential.
    let message = "Your current password isn't right.";
    let line = format!(r#"WRONG_PASSWORD = "{message}""#);
    let f = the_assignment(&line);
    assert_eq!(f.severity, Severity::Low);
    assert_eq!(f.certainty(), "possible");
    assert!(f.title.contains("reads like a sentence"), "{}", f.title);
    assert!(f.description.contains("reads like a sentence"));
    assert!(f.fix.contains("reads like a sentence"));
    assert!(!f.fix.starts_with("Move the value"), "{}", f.fix);
    // The whole message was judged, not the part before the apostrophe, and it is still
    // redacted: a passphrase can be a sentence, so the report holds four characters of it.
    let secret = f.secret.as_ref().expect("the value is recorded, redacted");
    assert_eq!(secret.length(), message.chars().count());
    assert_eq!(secret.as_str(), "Your… (30 more characters)");
    let rendered = serde_json::to_string(&f).unwrap();
    assert!(
        !rendered.contains("current password isn"),
        "the value reached the finding"
    );

    // Other messages an app shows, under names of every kind the rule reads. Each must clear
    // the entropy gate first, or "not reported high" would say nothing.
    for line in [
        r#"PASSWORD_MISMATCH = "Passwords do not match!""#,
        r#"token_prompt: 'Is this the token you were sent?'"#,
        r#"API_KEY_HELP = "Please paste your key here, then press save.""#,
        r#"secret_hint = "We'll never share your secret.""#,
        r#"RESET_PASSWORD = "Check your email for a sign-in link.""#,
    ] {
        let f = the_assignment(line);
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Low, Confidence::Low),
            "{line}"
        );
    }
}

#[test]
fn passphrases_keys_and_tokens_that_are_not_sentences_keep_their_severity() {
    // Built at run time, so this file holds no key-shaped literal.
    let key = filler(32, MIXED);
    let token = credential_shaped(&[&filler(12, MIXED), &filler(20, LETTERS)], ".");
    for (case, value) in [
        // A passphrase is words too; without the closing mark it is not a sentence.
        (
            "a passphrase without closing punctuation",
            "violet harbor quickly juggles nine lanterns".to_owned(),
        ),
        (
            "a capitalized passphrase without closing punctuation",
            "Violet Harbor Quickly Juggles Nine Lanterns".to_owned(),
        ),
        (
            "a passphrase with a digit in it",
            "violet harbor juggles 9 lanterns.".to_owned(),
        ),
        (
            "a passphrase with a digit inside a word",
            "violet harb0r quickly juggles lanterns.".to_owned(),
        ),
        (
            "a passphrase with symbols for letters",
            "v1olet h@rbor jugg!es lanterns.".to_owned(),
        ),
        (
            "a passphrase joined by hyphens",
            "violet-harbor-quickly-juggles.".to_owned(),
        ),
        (
            "words whose letter case is mixed",
            "vIoLeT harBOR juggles lanterns.".to_owned(),
        ),
        (
            "words two spaces apart",
            "violet  harbor juggles lanterns.".to_owned(),
        ),
        ("two words only", "Wrong password.".to_owned()),
        ("a key", key.clone()),
        ("a key ending in a period", format!("{key}.")),
        ("a token with a dot in it", token),
    ] {
        let f = the_assignment(&format!(r#"db_password = "{value}""#));
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::High, Confidence::Medium),
            "{case}"
        );
        assert!(!f.description.contains("sentence"), "{case}");
    }
}

#[test]
fn what_reads_like_a_sentence_is_narrow() {
    for yes in [
        "Your current password isn't right.",
        "Your current password isn\u{2019}t right.",
        "Is this your password?",
        "Passwords do not match!",
        "Sorry, that sign-in link has expired.",
        "The API key is missing.",
        "Ce mot de passe est trop court.",
    ] {
        assert!(reads_like_sentence(yes), "{yes:?}");
    }
    for no in [
        "Your current password isn't right",
        "Your password.",
        "Your password .",
        " Your current password is wrong.",
        "Your current password is wrong. ",
        "Your current password is wrong..",
        "Your current password, is wrong,.",
        "Your current passw0rd is wrong.",
        "Your current pass_word is wrong.",
        "Your current 'password' is wrong.",
        "Your current password is - wrong.",
        "Your current password is wrong\t.",
        "Your cuRRent password is wrong.",
    ] {
        assert!(!reads_like_sentence(no), "{no:?}");
    }
}

#[test]
fn a_value_runs_to_the_quote_that_opened_it() {
    // Until 4 October 2026 either quote ended a value, so an apostrophe cut a message short and
    // the rule judged a fragment. Each quote now ends only a value it opened.
    let quoted = r#"She said "keep it" twice"#;
    let f = the_assignment(&format!("secret_note = '{quoted}'"));
    assert_eq!(
        f.secret.as_ref().map(Secret::length),
        Some(quoted.chars().count())
    );
    // A sentence redacted when `sv` passes text on, whatever its severity as a finding.
    let message = "Your current password isn't right.";
    let (out, n) = redact_text(&rules(), &format!(r#"WRONG_PASSWORD = "{message}""#));
    assert_eq!(n, 1);
    assert!(!out.contains(message));
}

#[test]
fn a_tool_s_quoted_value_with_an_apostrophe_in_it_is_redacted_whole() {
    // Bandit's B105, as it read in a real report on 4 October 2026: the value is a message, and
    // the redaction stopped at `You'`, leaving the rest of it showing (deep review S8).
    let value = [
        "Pass",
        "word changed. You've been ",
        "signed out everywhere else.",
    ]
    .concat();
    let (out, n) = redact_text(&rules(), &format!("Possible hardcoded password: '{value}'"));
    assert_eq!(n, 1, "{out}");
    assert_eq!(
        out,
        format!(
            "Possible hardcoded password: '[redacted: Pass… ({} more characters)]'",
            value.chars().count() - 4
        )
    );
    // Two values side by side are still two: a quote with no letter after it ends the first.
    let (out, n) = redact_text(&rules(), "{'password': 'Qv7rLm2x', 'token': 'Tz9kWp4n'}");
    assert_eq!(n, 2, "{out}");
    // Eight characters show two: never more than a third of a value (the review of 8 October, item 6).
    assert!(out.contains("'token': '[redacted: Tz… (6 more"), "{out}");
}

#[test]
fn sv_s_own_redaction_read_back_is_not_a_credential() {
    // A report holding what `redact_text` wrote, scanned again as `sv bundle` scans its own
    // report: the marker is not a value, so finding it would refuse every such bundle.
    let password = ["Qv7r", "Lm2x", "Tz9k"].concat();
    let (redacted, n) = redact_text(
        &rules(),
        &format!("Possible hardcoded password: '{password}'"),
    );
    assert_eq!(n, 1);
    for text in [
        redacted.clone(),
        format!("password = \"{}\"", redacted.split('\'').nth(1).unwrap()),
        "PASSWORD: \"[redacted: abc]\"".to_owned(),
    ] {
        let found = scan_text(&rules(), "report/security.md", &format!("{text}\n"));
        assert!(found.is_empty(), "{text}: {found:?}");
    }
    // The control: the value itself is found there, and a marker with text of its own is a value.
    for text in [
        format!("Possible hardcoded password: '{password}'"),
        format!("password = \"[redacted: Qv7r… (8 more characters)]{password}\""),
    ] {
        assert!(
            !scan_text(&rules(), "report/security.md", &format!("{text}\n")).is_empty(),
            "not found: the scan does not read this shape, so the test proves nothing"
        );
    }
}

#[test]
fn an_ordinary_string_with_a_harmless_name_is_left_alone() {
    for line in [
        "greeting = \"hello there friend\"",
        "path = \"/usr/local/share/app\"",
        "endpoint = \"https://api.example.com/v1\"",
        "title = \"Client's habit tracker\"",
    ] {
        let found = scan_text(&rules(), "src/app.py", &format!("{line}\n"));
        assert!(found.is_empty(), "reported {line:?}: {found:?}");
    }
}

#[test]
fn a_secret_name_with_a_low_entropy_value_is_not_reported() {
    // "password = 'password'" is a bad password, not a leaked credential, and calling it one would
    // bury the findings that are.
    let found = scan_text(&rules(), "src/app.py", "password = \"aaaaaaaaaaaa\"\n");
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn dot_env_is_not_scanned_for_assignments_because_that_is_what_it_is_for() {
    let text = "SESSION_SECRET=\"Xk7#mQ92vLpR4sTzAAbb\"\n";
    assert!(scan_text(&rules(), ".env", text).is_empty());
    // The same line anywhere else is a finding.
    assert!(!scan_text(&rules(), "src/config.ts", text).is_empty());
}

#[test]
fn a_known_format_is_still_reported_inside_dot_env() {
    // A vendor key in .env is expected. A vendor key is also the thing most worth knowing about when
    // the file turns out to be committed, so the pattern rules still run there.
    let key = credential_shaped(&["sk", "ant", "api03", "REALLOOKINGKEYVALUE123456"], "-");
    let text = format!("ANTHROPIC_API_KEY={key}\n");
    let text = text.as_str();
    let found = scan_text(&rules(), ".env", text);
    assert!(
        found.iter().any(|f| f.rule_id == "secrets.anthropic-key"),
        "{found:?}"
    );
}

#[test]
fn the_rule_data_finds_what_it_promises_and_grades_a_test_key_below_a_live_one() {
    // A5 of the deep review. Every value is put together here, so the file holds no key.
    let found = |text: &str| scan_text(&rules(), "src/config.txt", text);
    let rule_of = |text: &str| {
        let f = found(text);
        assert_eq!(f.len(), 1, "{f:?}");
        (f[0].rule_id.clone(), f[0].severity)
    };
    // Slack's app-level token, which the rule's own description named and its pattern missed.
    let xapp = credential_shaped(
        &[
            "xapp",
            "1",
            "A0123456789",
            "1234567890123",
            "0a1b2c3d4e5f6a7b8c9d",
        ],
        "-",
    );
    assert_eq!(
        rule_of(&format!("SLACK_APP_TOKEN={xapp}\n")).0,
        "secrets.slack-token"
    );
    // A PGP private key block, beside the PEM ones it already found.
    let pgp = format!("-----BEGIN PGP {} KEY BLOCK-----\nlQOYBF\n", "PRIVATE");
    assert_eq!(rule_of(&pgp).0, "secrets.private-key-block");
    let pem = format!("-----BEGIN {} KEY-----\nMIIE\n", "PRIVATE");
    assert_eq!(rule_of(&pem).0, "secrets.private-key-block");
    // A public PGP block is not a secret.
    let public = format!("-----BEGIN PGP {} KEY BLOCK-----\nmQIN\n", "PUBLIC");
    assert!(found(&public).is_empty(), "{:?}", found(&public));
    // Stripe's test key cannot move money; its live key can.
    let live = credential_shaped(&["sk", "live", "51HxaMpLeKeyV4lu3Abcdefghijk"], "_");
    let test = credential_shaped(&["sk", "test", "51HxaMpLeKeyV4lu3Abcdefghijk"], "_");
    assert_eq!(
        rule_of(&format!("STRIPE_KEY={live}\n")),
        ("secrets.stripe-key".to_owned(), Severity::Critical)
    );
    assert_eq!(
        rule_of(&format!("STRIPE_KEY={test}\n")),
        ("secrets.stripe-test-key".to_owned(), Severity::Medium)
    );
    // The private key rule says what it found, not only why it matters.
    let block = rules()
        .rules()
        .find(|r| r.id == "secrets.private-key-block")
        .map(|r| r.description.clone())
        .unwrap();
    assert!(block.starts_with("A private key"), "{block}");
}

#[test]
fn one_secret_produces_one_finding() {
    // A vendor key assigned to a well-named variable matches both the vendor rule and the generic
    // assignment rule. Reporting it twice doubles the apparent problem and halves the attention each
    // finding gets; the vendor rule wins because it can say how to revoke the thing.
    let key = credential_shaped(&["sk", "live", "51HxaMpLeKeyV4lu3Abcdefghijk"], "_");
    let text = format!("STRIPE_SECRET_KEY = \"{key}\"\n");
    let text = text.as_str();
    let found = scan_text(&rules(), "src/config.py", text);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].rule_id, "secrets.stripe-key");
}

#[test]
fn two_different_secrets_on_two_lines_are_two_findings() {
    // The other side of it: de-duplication must not swallow a real second finding.
    let key = credential_shaped(&["sk", "live", "51HxaMpLeKeyV4lu3Abcdefghijk"], "_");
    let text =
        format!("STRIPE_SECRET_KEY = \"{key}\"\nsession_secret = \"Xk7#mQ92vLpR4sTzWwYy\"\n");
    let text = text.as_str();
    let found = scan_text(&rules(), "src/config.py", text);
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn a_whole_example_env_file_is_silent() {
    // The file every project ships to show what to fill in. If the scanner shouts at this, an owner
    // learns on their first run that its findings are noise — which costs more than the rule is worth.
    // A different shape from the single-value placeholder test: several rules, several lines, at once.
    let example = "\
# Copy to .env and fill in.
ANTHROPIC_API_KEY=sk-ant-your-key-here
AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE12
STRIPE_SECRET_KEY=sk_test_replace_me
DATABASE_PASSWORD=changeme
SESSION_SECRET=${SESSION_SECRET}
GITHUB_TOKEN=<your token>
SIGNING_KEY=generate_with_openssl_rand
";
    let found = scan_text(&rules(), "README.env.example", example);
    assert!(
        found.is_empty(),
        "an example file produced findings: {found:?}"
    );
}

#[test]
fn repetitive_values_under_credential_names_are_not_credentials() {
    // Low entropy, not placeholders: the entropy gate is the only thing standing between these and a
    // wall of false findings. Deliberately different values from the single-case test above.
    for line in [
        "auth_token = \"abcabcabcabcabcabc\"",
        "client_secret = \"111111111111111111\"",
        "signing_key = \"aaaaaaaaaaaaaaaaaaaa\"",
        "encryption_key = \"abababababababababab\"",
    ] {
        let found = scan_text(&rules(), "src/settings.rb", &format!("{line}\n"));
        assert!(found.is_empty(), "reported {line:?}: {found:?}");
    }
}

#[test]
fn entropy_tells_a_random_string_from_a_word() {
    assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
    assert!(shannon_entropy("password") < 3.5);
    assert!(shannon_entropy("Xk7#mQ92vLpR4sTz") > 3.5);
}

#[test]
fn line_numbers_are_what_an_editor_shows() {
    let text = "one\ntwo\napi_key = \"Xk7#mQ92vLpR4sTz\"\n";
    let found = scan_text(&rules(), "src/app.py", text);
    assert_eq!(found[0].location.line, 3);
}

#[test]
fn a_committed_credential_is_a_finding_against_no_secrets_in_code() {
    // SBD-AC-05 asks, among other things, for no secrets in code. A key in a file is that failing,
    // from the data file's rules and from the assignment rule alike.
    let rules = SecretRules::load(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"),
    )
    .unwrap();
    for rule in rules.rules() {
        assert!(
            rule.requirement_ids.iter().any(|r| r == "SBD-AC-05"),
            "{} does not cite SBD-AC-05",
            rule.id
        );
    }
    assert!(ASSIGNMENT_REQUIREMENTS.contains(&"SBD-AC-05"));
    assert!(
        rules.requirement_ids().contains(&"SBD-AC-05"),
        "a clean scan has to offer itself as supporting evidence for it"
    );
}

/// A hex digest of `n` digits, built at run time so no file holds one.
fn hex(n: usize) -> String {
    filler(n, "9f3a0c7e5b18d246")
}

/// A bcrypt hash's shape (`$2b$12$` and 53 more), built at run time so no file holds one.
fn bcrypt() -> String {
    format!(
        "${}${}${}",
        "2b",
        "12",
        filler(53, "Qm7Rz2Kv9Lp4./Wn8Hs3Jd6Tf1Gb5Yc0")
    )
}

fn reported(relative: &str, line: &str) -> Vec<Finding> {
    scan_text(&rules(), relative, &format!("{line}\n"))
}

#[test]
fn a_stored_password_hash_is_not_a_credential_and_a_hexy_password_still_is() {
    // Follow-up 4 of the Semgrep false-alarm measurement: a hex digest or bcrypt hash written
    // under a name that says it is one is what an app keeps instead of a password.
    let (b, h32, h40, h64, h128) = (bcrypt(), hex(32), hex(40), hex(64), hex(128));
    let stored = [
        ("app.py", format!("password_hash = \"{b}\"")),
        ("seed.js", format!("{{ \"password\": \"{b}\" }}")),
        ("users.rb", format!("'encrypted_password' => '{b}'")),
        ("app.py", format!("hashed_password = \"{h64}\"")),
        ("settings.py", format!("ADMIN_PASSWORD_DIGEST = \"{h40}\"")),
        (
            "user.ts",
            format!("const passwordHash: string = \"{h32}\";"),
        ),
        ("main.go", format!("passwordHash := \"{h128}\"")),
        ("config.yml", format!("password_hash: {h64}")),
    ];
    for (file, line) in &stored {
        // The setup: the same value under a plain credential name is reported, so silence
        // below is the exception and not a value the rule cannot see.
        let value = line
            .rsplit(['"', '\'', ' '])
            .find(|p| p.len() >= 32)
            .unwrap();
        assert!(
            !reported(file, &format!("api_key = \"{value}\"")).is_empty(),
            "the value in {line:?} is not findable at all, so the test proves nothing"
        );
        let found = reported(file, line);
        assert!(found.is_empty(), "{line:?} was reported: {found:?}");
    }

    // Still reported, high: a password made of hex digits is still a password; a key for
    // hashing is a key; a value that is not exactly a digest or a bcrypt hash is judged as before.
    let still = [
        ("app.py", format!("password = \"{h32}\"")),
        ("app.py", format!("ADMIN_PASSWORD = \"{h64}\"")),
        ("seed.js", format!("{{ \"password\": \"{h64}\" }}")),
        (
            "User.cs",
            format!("public const string TokenSecret = \"{h64}\";"),
        ),
        ("app.py", format!("PASSWORD_HASH_KEY = \"{h64}\"")),
        ("app.py", format!("password_hash_salt = \"{h32}\"")),
        ("app.py", format!("hmac_digest_secret = \"{h64}\"")),
        ("app.py", format!("api_token = \"{b}\"")),
        ("app.py", format!("password_hash = \"{}\"", hex(31))),
        ("app.py", format!("password_hash = \"{}\"", hex(33))),
        ("app.py", format!("password_hash = \"{}\"", &b[..59])),
        (
            "app.py",
            format!("password_hash = \"{}\"", filler(64, MIXED)),
        ),
    ];
    for (file, line) in &still {
        let found = reported(file, line);
        assert!(
            found
                .iter()
                .any(|f| f.rule_id == "secrets.credential-assignment"
                    && f.severity == Severity::High),
            "{line:?} was not reported high: {found:?}"
        );
        // And never shown whole.
        assert!(!serde_json::to_string(&found).unwrap().contains(&h32[..20]));
    }
}

#[test]
fn a_line_with_a_stored_hash_and_nothing_else_is_all_another_tool_s_secret_rule_is_spared() {
    let (b, h64) = (bcrypt(), hex(64));
    let rules = rules();
    let spared = [
        ("app.py", format!("password_hash = \"{b}\"")),
        // NodeGoat's seed script, as the measurement found it: a commented-out hash.
        (
            "db-reset.js",
            format!("//\"password\" : \"{b}\", // Admin_123"),
        ),
        (
            "models.py",
            format!("User(name=\"ann\", password_hash=\"{h64}\")"),
        ),
    ];
    for (file, line) in &spared {
        assert!(
            holds_only_stored_hashes(&rules, file, line),
            "{line:?} was not spared"
        );
    }
    let key = credential_shaped(&["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb"], "-");
    let kept = [
        // A hexy plaintext password.
        ("app.py", format!("password = \"{h64}\"")),
        // A hash beside a key the vendor rules know, beside a named key, and beside a token
        // in a shape nobody listed.
        ("app.py", format!("password_hash = \"{b}\"; k = \"{key}\"")),
        (
            "seed.js",
            format!(
                "{{ \"password_hash\": \"{h64}\", \"api_key\": \"{}\" }}",
                filler(24, MIXED)
            ),
        ),
        (
            "seed.js",
            format!(
                "{{ \"password_hash\": \"{h64}\" }} // {}",
                filler(24, MIXED)
            ),
        ),
        // A key for hashing, under a name that says hash.
        ("app.py", format!("password_hash_key = \"{h64}\"")),
        // Nothing named at all.
        ("app.py", format!("check(\"{h64}\")")),
        ("app.py", String::new()),
    ];
    for (file, line) in &kept {
        assert!(
            !holds_only_stored_hashes(&rules, file, line),
            "{line:?} was spared"
        );
    }
}

#[test]
fn the_measured_corpus_s_secret_rule_lines_keep_every_true_finding() {
    // The secret-rule findings outside test code in `docs/semgrep-false-alarms.csv`, each line
    // rebuilt in its shape with values made here: the measurement's verdict, and whether the
    // exception spares it. Test-code findings are listed apart instead (follow-up 2).
    let (b, h32, h64) = (bcrypt(), hex(32), hex(64));
    let jwt = format!(
        "{}.{}.{}",
        filler(36, "eyJhbGciOiJIUzI1NiJ9"),
        filler(40, MIXED),
        filler(43, MIXED)
    );
    let rows = [
        // pygoat introduction/views.py 866, 870, 872: MD5 digests under `password`.
        (
            false,
            "views.py",
            format!("sql_instance = sql_lab_table(id=\"admin\", password=\"{h32}\")"),
        ),
        (
            false,
            "views.py",
            format!("sql_instance = sql_lab_table(id=\"slinky\", password=\"{h32}\")"),
        ),
        (
            false,
            "views.py",
            format!("sql_instance = sql_lab_table(id=\"bloke\", password=\"{h32}\")"),
        ),
        // pygoat introduction/views.py 1164 to 1167: SHA-256 digests under `password`.
        (
            false,
            "views.py",
            format!(
                "    \"User1\":{{\"userid\":\"1\", \"username\":\"User1\", \"password\": \"{h64}\"}},"
            ),
        ),
        (
            false,
            "views.py",
            format!(
                "    \"User2\":{{\"userid\":\"2\", \"username\":\"User2\", \"password\": \"{h64}\"}},"
            ),
        ),
        (
            false,
            "views.py",
            format!(
                "    \"User3\":{{\"userid\":\"3\", \"username\":\"User3\", \"password\": \"{h64}\"}},"
            ),
        ),
        (
            false,
            "views.py",
            format!(
                "    \"User4\":{{\"userid\":\"4\", \"username\":\"User4\", \"password\": \"{h64}\"}}"
            ),
        ),
        // NodeGoat artifacts/db-reset.js 19, 28, 36: commented-out bcrypt hashes.
        (
            false,
            "db-reset.js",
            format!("        //\"password\" : \"{b}\", // Admin_123"),
        ),
        (
            false,
            "db-reset.js",
            format!("        // \"password\" : \"{b}\",// User1_123"),
        ),
        (
            false,
            "db-reset.js",
            format!("        //\"password\" : \"{b}\", // User2_123"),
        ),
        // DVWA's help page: an example token.
        (false, "help.php", format!("user-token: {h32}")),
        // True: dvcsharp's token secret, NodeGoat's ZAP key, pygoat's pasted session token,
        // and juice-shop's expected password (unsure, counted with the true ones).
        (
            true,
            "User.cs",
            format!("      public const string TokenSecret = \"{h64}\";"),
        ),
        (
            true,
            "development.js",
            format!("   zapApiKey: \"{}\",", filler(26, MIXED)),
        ),
        (
            true,
            "a7.js",
            format!("// document.cookie = \"sessionid={jwt}\";"),
        ),
        (
            true,
            "login.ts",
            format!(
                "    return req.body.email === 'bjoern@example.org' && req.body.password === '{}'",
                filler(36, MIXED)
            ),
        ),
    ];
    let rules = rules();
    let mut spared_false = 0;
    for (true_finding, file, line) in &rows {
        let spared = holds_only_stored_hashes(&rules, file, line);
        assert!(
            !(spared && *true_finding),
            "a true finding was spared: {line:?}"
        );
        spared_false += usize::from(spared);
    }
    // The three bcrypt hashes. The seven digests under a name that says only `password` are
    // still reported: that is the price of never sparing a hex plaintext password.
    assert_eq!(spared_false, 3);
}

#[test]
fn a_value_is_masked_as_far_as_it_is_found_in_its_file() {
    // Item 17 of the review of 1 to 4 October: in these files the scan finds the whole value,
    // and masking, which did not know the file, stopped at the `&` or `,`, or masked nothing.
    let value = ["Xk7mQ92v", "&LpR4sTz"].concat();
    let comma = ["Xk7mQ92v", ",LpR4sTz"].concat();
    for (file, line, secret) in [
        (
            "config.yml",
            format!("db_password: {value}"),
            value.as_str(),
        ),
        (
            "app.properties",
            format!("api.secret={comma}"),
            comma.as_str(),
        ),
        (
            "Dockerfile",
            format!("ENV DB_PASSWORD {value}"),
            value.as_str(),
        ),
        (
            "deploy.sh",
            format!("export API_TOKEN={value}"),
            value.as_str(),
        ),
    ] {
        // The setup: the scan really finds it in that file. No message here names the value or
        // the line holding it, so a failure prints nothing that looks like a credential.
        assert!(
            !scan_text(&rules(), file, &line).is_empty(),
            "the setup: the value in {file} is found"
        );
        let (out, n) = redact_text_in(&rules(), file, &line);
        assert!(n >= 1, "{file}: nothing was masked");
        // Not one part of the value is left, before or after the `&` or `,`.
        for (which, part) in [("first", &secret[..8]), ("last", &secret[9..])] {
            assert!(
                !out.contains(part),
                "{file}: the {which} part of the value was left"
            );
        }
    }
}
