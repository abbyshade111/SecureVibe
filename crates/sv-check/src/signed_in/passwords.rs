use super::*;

/// A password from the top 3000 most common that meets an 8-character rule: line 1,238 of
/// `data/knowledge/common-passwords.txt`.
pub(super) const COMMON: &str = "123qweasdzxc";

/// Two more from the top 3000, of the same shape as `COMMON` (12 characters of digits and lowercase
/// letters), so the one random control of that shape still shows a refusal is about the word: lines
/// 2,018 and 2,744 of `data/knowledge/common-passwords.txt`. One word alone was a matter of whether a list
/// held it, so the credit needs all three refused (ADR-055).
pub(super) const COMMON_MORE: [&str; 2] = ["1q2w3e4r5t6y", "qwerty123456"];

/// A password far down the common list, at line 12,393 of `data/knowledge/common-passwords.txt`:
/// well past the top 3000 that V6.2.4 asks about, so an app that checks only those accepts it, and
/// 16 characters, so a length rule of up to 16 does not refuse it first. That it is breached is
/// not taken from the list, whose source is recorded nowhere: it is Have I Been Pwned's count, in
/// `data/breached-password-evidence.json`, and `breached_seen_in` below says it in the finding. A test
/// holds the password to that file, so it cannot change without new evidence.
pub(super) const BREACHED: &str = "1qaz2wsx3edc4rfv";

/// `data/breached-password-evidence.json`, compiled in: `sv` reads it and fetches nothing.
/// `tools/pwned_passwords.py` rewrites it, and the wording below follows without an edit here.
const BREACHED_EVIDENCE: &str = include_str!("../../../../data/breached-password-evidence.json");

/// How often Pwned Passwords has seen `BREACHED`, and when that was last checked, from the
/// evidence file: "133,732 times when last checked, on 26 September 2026". What is wrong with the
/// file, rather than a panic: a source build with the file edited badly would otherwise stop the
/// whole run.
fn breached_seen_in(evidence: &str) -> Result<String, String> {
    let evidence: serde_json::Value =
        serde_json::from_str(evidence).map_err(|e| format!("it is not readable JSON ({e})"))?;
    if evidence["password"].as_str() != Some(BREACHED) {
        return Err(format!(
            "it is evidence for another password, not `{BREACHED}`"
        ));
    }
    let seen = evidence["seen"]
        .as_u64()
        .ok_or("it has no count of how often the password was seen")?;
    let checked = evidence["checked"]
        .as_str()
        .and_then(long_date)
        .ok_or("it has no date written YYYY-MM-DD for when it was checked")?;
    Ok(format!(
        "{} times when last checked, on {checked}",
        with_commas(seen)
    ))
}

/// 133732 as "133,732".
fn with_commas(n: u64) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(|c| std::str::from_utf8(c).expect("digits"))
        .collect::<Vec<_>>()
        .join(",")
}

/// "2026-09-26" as "26 September 2026"; `None` for anything else.
fn long_date(iso: &str) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let mut parts = iso.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    let ok = parts.next().is_none()
        && year.len() == 4
        && month.len() == 2
        && day.len() == 2
        && [year, month, day]
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_digit()));
    let month = MONTHS.get(month.parse::<usize>().ok()?.checked_sub(1)?)?;
    let day: u8 = day.parse().ok()?;
    (ok && (1..=31).contains(&day)).then(|| format!("{day} {month} {year}"))
}

/// A password with the same shape as `template` — each lowercase letter, capital, and digit
/// replaced by a random one of the same kind, everything else kept — made from `spare`, the random
/// material every run has. The control that says a refusal was about *these* characters and not
/// about their length or kinds.
fn random_like(template: &str, spare: &str) -> String {
    let nibbles: Vec<u8> = spare
        .chars()
        .filter_map(|c| c.to_digit(16))
        .map(|d| d as u8)
        .collect();
    template
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let n = nibbles[i % nibbles.len()];
            match c {
                'a'..='z' => (b'a' + n) as char,
                'A'..='Z' => (b'A' + n) as char,
                '0'..='9' => (b'0' + n % 10) as char,
                other => other,
            }
        })
        .collect()
}

/// The password tried for V6.2.11: the first word of at least four letters or digits in the
/// owner's list, lowercased and repeated to at least 16 characters, so no length rule refuses it
/// first. `None` when no word on the list is long enough to mean anything.
fn context_password(words: &[String]) -> Option<(String, String)> {
    let word = words.iter().find_map(|w| {
        let kept: String = w
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        (4..=32).contains(&kept.len()).then_some((w.clone(), kept))
    })?;
    let (named, kept) = word;
    let mut password = kept.clone();
    while password.len() < 16 {
        password.push_str(&kept);
    }
    Some((named, password))
}

/// Makes an account through `signup`, and nothing else.
pub(super) fn sign_up_only(
    http: &mut dyn Http,
    signup: &RequestTemplate,
    who: &str,
    account: &Account,
) -> Option<ProbeResponse> {
    let values = Values {
        user: &account.user,
        password: &account.password,
        ..Default::default()
    };
    let mut session = Session::default();
    send_template(
        http,
        &format!("signup-{who}"),
        signup,
        &values,
        &mut session,
        &[],
    )
    .0
}

/// Whether this account can sign in and open the private page: the only test of a password that
/// does not depend on how the app words its refusals.
pub(super) fn account_works(
    http: &mut dyn Http,
    users: &UsersSection,
    who: &str,
    account: &Account,
    confirm: &str,
    steps: &mut Vec<String>,
) -> bool {
    let mut quiet = Vec::new();
    let Some(signed_in) = sign_in(http, users, who, account, &mut quiet) else {
        return false;
    };
    let works = ok(&http.send(&get(&format!("private-{who}"), confirm, &signed_in.session)));
    steps.push(format!(
        "signed in as {} with {}: {}",
        account.user,
        describe_password(&account.password),
        if works { "opened" } else { "refused" }
    ));
    works
}

fn describe_password(p: &str) -> String {
    if p == COMMON {
        return format!("the common password `{COMMON}`");
    }
    let kinds = [
        (p.chars().any(|c| c.is_ascii_lowercase()), "lowercase"),
        (p.chars().any(|c| c.is_ascii_uppercase()), "uppercase"),
        (p.chars().any(|c| c.is_ascii_digit()), "digits"),
        (p.chars().any(|c| !c.is_ascii_alphanumeric()), "symbols"),
    ];
    let kinds: Vec<&str> = kinds.iter().filter(|(k, _)| *k).map(|(_, n)| *n).collect();
    format!("a {}-character password of {}", p.len(), kinds.join(", "))
}

/// V6.2.12 from sign-up's answers to `BREACHED` and to a random password of the same shape, and the
/// evidence that `BREACHED` is breached. In the same shape as V6.2.4: refused beside a random password
/// of the same shape that was accepted is evidence; refused beside a refused control is evidence of
/// nothing.
fn judge_breached(accepted: bool, control_accepted: bool, evidence: &str, out: &mut Outcome) {
    let seen = breached_seen_in(evidence);
    match (accepted, control_accepted, seen) {
        // Without the evidence that the password is breached, neither outcome says anything.
        (_, _, Err(wrong)) => out.not_assessed.push((
            "V6.2.12".to_owned(),
            format!(
                "`sv`'s own record that `{BREACHED}` is a breached password, \
                 data/breached-password-evidence.json, could not be used: {wrong}. Without it, \
                 whether the app accepts that password says nothing about breached passwords. \
                 Restore the file from StackVet's repository and build `sv` again."
            ),
        )),
        (true, _, Ok(seen)) => out.findings.push(finding(
            &BREACHED_PASSWORD,
            "A password known from data breaches is accepted",
            Severity::Low,
            format!(
                "The app let an account sign up with `{BREACHED}`, and sign in with it. Have I Been \
                 Pwned has seen that password in breaches {seen}, though it is not among \
                 the 3000 most common, so a check against a large set of breached passwords would \
                 have refused it."
            ),
        )),
        (false, true, Ok(seen)) => out.verified.push(crate::Verified::new(
            BREACHED_PASSWORD.rule_id,
            BREACHED_PASSWORD.requirement_ids,
            format!(
                "`{BREACHED}`, seen in breaches {seen} and not among the 3000 most \
                 common, refused at sign-up where a random password of the same shape was accepted"
            ),
        )),
        (false, false, Ok(_)) => out.not_assessed.push((
            "V6.2.12".to_owned(),
            format!(
                "The app refused `{BREACHED}`, and also a random password of the same length and \
                 kinds of character, so the refusal cannot be told apart from another rule."
            ),
        )),
    }
}

/// The password rules, asked through the app's own sign-up and answered by signing in.
///
/// A control goes first: an account signed up with an ordinary strong password, 32 characters of
/// every kind, which has to be able to sign in or nothing here can be told. Each password after it
/// differs from the control in one thing only, so a refusal is about that thing: seven characters;
/// lowercase letters alone; a common password, beside a random one of the same length and kinds of
/// character. The test users may have been made by `seed`; these never are.
pub(super) fn password_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    policy: &sv_manifest::PolicySection,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.2.1, V6.2.4, V6.2.5, V6.2.8, V6.2.9, V6.2.11, V6.2.12";
    let Some(signup) = &users.signup else {
        out.not_assessed.push((
            IDS.to_owned(),
            "The password rules are asked through the app's own sign-up, and stackvet.toml sets \
             no `signup` under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether a password was accepted is told by signing in with it and opening a private \
             page, and no private page was shown to open for a signed-in user alone."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 || !spare.chars().all(|c| c.is_ascii_hexdigit()) {
        out.not_assessed.push((
            IDS.to_owned(),
            "There was no random material to make test passwords from.".to_owned(),
        ));
        return;
    }
    let account = |label: &str, password: String| Account {
        user: format!("{label}.{}", accounts.a.user),
        password,
    };
    let lowercase: String = spare
        .chars()
        .map(|c| (b'g' + c.to_digit(16).unwrap_or(0) as u8) as char)
        .collect();
    let control = account("control", format!("Sv-{}-aZ9!", &spare[8..32]));
    sign_up(http, users, signup, "control", &control);
    if !account_works(http, users, "control", &control, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            "An account signed up with an ordinary strong password could not then sign in, so \
             nothing can be told from the passwords the app refuses."
                .to_owned(),
        ));
        return;
    }
    let tries = [
        ("short", account("short", format!("S{}aZ9!", &spare[..2]))),
        ("lower", account("lower", lowercase)),
        ("common", account("common", COMMON.to_owned())),
        ("common-b", account("common-b", COMMON_MORE[0].to_owned())),
        ("common-c", account("common-c", COMMON_MORE[1].to_owned())),
        (
            "like-common",
            account("like-common", spare[2..14].to_owned()),
        ),
        ("breached", account("breached", BREACHED.to_owned())),
        (
            "like-breached",
            account("like-breached", random_like(BREACHED, &spare[14..32])),
        ),
    ];
    let context = context_password(&policy.context_words);
    let context_tries: Vec<(&str, Account)> = match &context {
        Some((_, password)) => vec![
            ("context", account("context", password.clone())),
            (
                "like-context",
                account("like-context", random_like(password, &spare[4..28])),
            ),
        ],
        None => Vec::new(),
    };
    let tries: Vec<(&str, Account)> = tries.into_iter().chain(context_tries).collect();
    let mut works = std::collections::BTreeMap::new();
    for (label, try_account) in &tries {
        sign_up(http, users, signup, label, try_account);
        works.insert(
            *label,
            account_works(http, users, label, try_account, confirm, &mut out.steps),
        );
    }

    if works["short"] {
        out.findings.push(finding(
            &SHORT_PASSWORD,
            "A password shorter than 8 characters is accepted",
            Severity::Medium,
            format!(
                "The app let an account sign up with the 7-character password `{}` and sign in \
                 with it.",
                tries[0].1.password
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            SHORT_PASSWORD.rule_id,
            SHORT_PASSWORD.requirement_ids,
            "a 7-character password at sign-up, refused where a 32-character one of the same kinds \
             of character was accepted"
                .to_owned(),
        ));
    }

    if works["lower"] {
        out.verified.push(crate::Verified::new(
            COMPOSITION_RULES.rule_id,
            COMPOSITION_RULES.requirement_ids,
            "a 32-character password of lowercase letters alone, accepted at sign-up".to_owned(),
        ));
    } else {
        out.findings.push(finding(
            &COMPOSITION_RULES,
            "Passwords must contain certain kinds of character",
            Severity::Low,
            "The app refused a 32-character password of lowercase letters alone, where it \
             accepted one of the same length with capitals, digits and symbols."
                .to_owned(),
        ));
    }

    // Three common words of one shape (ADR-055): any accepted is a finding naming it; the credit needs
    // all three refused, with the random control of the same shape accepted.
    let words = [
        ("common", COMMON),
        ("common-b", COMMON_MORE[0]),
        ("common-c", COMMON_MORE[1]),
    ];
    let named = |ws: &[&str]| {
        ws.iter()
            .map(|w| format!("`{w}`"))
            .collect::<Vec<_>>()
            .join(" and ")
    };
    let accepted: Vec<&str> = words
        .iter()
        .filter(|(label, _)| works[label])
        .map(|(_, word)| *word)
        .collect();
    let all: Vec<&str> = words.iter().map(|(_, word)| *word).collect();
    match (!accepted.is_empty(), works["like-common"]) {
        (true, _) => out.findings.push(finding(
            &COMMON_PASSWORD,
            "A common password is accepted",
            Severity::Medium,
            format!(
                "The app let an account sign up with {}, {} among the 3000 most common passwords, \
                 and sign in with {}.",
                named(&accepted),
                if accepted.len() == 1 { "which is" } else { "which are" },
                if accepted.len() == 1 { "it" } else { "each" }
            ),
        )),
        (false, true) => out.verified.push(crate::Verified::new(
            COMMON_PASSWORD.rule_id,
            COMMON_PASSWORD.requirement_ids,
            format!(
                "{}, three of the 3000 most common passwords, at sign-up, each refused where a random \
                 password of the same length and kinds of character was accepted",
                named(&all)
            ),
        )),
        (false, false) => out.not_assessed.push((
            "V6.2.4".to_owned(),
            format!(
                "The app refused {}, and also a random password of the same length and kinds of \
                 character, so the refusals cannot be told apart from another rule.",
                named(&all)
            ),
        )),
    }

    judge_breached(
        works["breached"],
        works["like-breached"],
        BREACHED_EVIDENCE,
        out,
    );

    // V6.2.11 asks that the *documented* list is used, so without the owner's list there is
    // nothing to hold the app to, and guessing at words would be testing a list nobody wrote.
    match &context {
        None => out.not_assessed.push((
            "V6.2.11".to_owned(),
            if policy.context_words.is_empty() {
                "stackvet.toml lists no context-specific words. Add your app's and your \
                 organization's names under [policy] as `context-words`, and sign-up is asked to \
                 refuse a password made from one."
                    .to_owned()
            } else {
                "No word under `context-words` in stackvet.toml has between 4 and 32 letters or \
                 digits, so none could be made into a password worth trying."
                    .to_owned()
            },
        )),
        Some((word, password)) => match (works["context"], works["like-context"]) {
            (true, _) => out.findings.push(finding(
                &CONTEXT_WORD_PASSWORD,
                "A password made from one of your context-specific words is accepted",
                Severity::Low,
                format!(
                    "The app let an account sign up with `{password}`, which is \"{word}\" from \
                     `context-words` in stackvet.toml, repeated, and sign in with it."
                ),
            )),
            (false, true) => out.verified.push(crate::Verified::new(
                CONTEXT_WORD_PASSWORD.rule_id,
                CONTEXT_WORD_PASSWORD.requirement_ids,
                format!(
                    "a password made from \"{word}\", the first usable word in `context-words`, \
                     refused at sign-up where a random password of the same shape was accepted"
                ),
            )),
            (false, false) => out.not_assessed.push((
                "V6.2.11".to_owned(),
                format!(
                    "The app refused a password made from \"{word}\", and also a random password \
                     of the same length and kinds of character, so the refusal cannot be told \
                     apart from another rule."
                ),
            )),
        },
    }

    exact_password_checks(http, users, signup, &control, spare, confirm, out);
}

/// Whether the password is checked exactly as typed (V6.2.8), and whether a long one is allowed at
/// all (V6.2.9).
///
/// Two ways an app alters a password before comparing it, each asked against an account that is
/// shown to work with its real password first. Its capitals swapped, on the control account: an app
/// that lowercases passwords lets it in. And an 83-character password cut to its first 72: an app
/// that hashes with bcrypt, which stops reading at 72 bytes, lets that in too. Signing that account
/// up at all is the V6.2.9 question.
fn exact_password_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    signup: &RequestTemplate,
    control: &Account,
    spare: &str,
    confirm: &str,
    out: &mut Outcome,
) {
    let swapped = Account {
        user: control.user.clone(),
        password: control
            .password
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect(),
    };
    let case_works = account_works(http, users, "case", &swapped, confirm, &mut out.steps);

    let long = Account {
        user: format!("long.{}", control.user.trim_start_matches("control.")),
        password: format!("Lg-{0}{0}{1}-aZ9!", &spare[..32], &spare[..11]),
    };
    sign_up(http, users, signup, "long", &long);
    let long_works = account_works(http, users, "long", &long, confirm, &mut out.steps);
    let cut = Account {
        user: long.user.clone(),
        password: long.password.chars().take(72).collect(),
    };
    let cut_works = long_works && account_works(http, users, "cut", &cut, confirm, &mut out.steps);

    if long_works {
        out.verified.push(crate::Verified::new(
            LONG_PASSWORD.rule_id,
            LONG_PASSWORD.requirement_ids,
            format!(
                "a {}-character password, accepted at sign-up and signed in with",
                long.password.len()
            ),
        ));
    } else {
        out.findings.push(finding(
            &LONG_PASSWORD,
            "A long password is refused",
            Severity::Low,
            format!(
                "The app did not let an account sign up with a {}-character password and sign in \
                 with it, where it accepted one of 32 characters of the same kinds.",
                long.password.len()
            ),
        ));
    }

    let mut altered = Vec::new();
    if case_works {
        altered.push("with the capitals in the password swapped".to_owned());
    }
    if cut_works {
        altered.push(format!(
            "with only the first 72 of its {} characters",
            long.password.len()
        ));
    }
    if !altered.is_empty() {
        out.findings.push(finding(
            &ALTERED_PASSWORD,
            "The password is not checked exactly as typed",
            Severity::Medium,
            format!("Signing in worked {}.", altered.join(", and ")),
        ));
    } else if long_works {
        out.verified.push(crate::Verified::new(
            ALTERED_PASSWORD.rule_id,
            ALTERED_PASSWORD.requirement_ids,
            format!(
                "the password with its capitals swapped, and an {}-character one cut to 72, both \
                 refused where the exact passwords signed in",
                long.password.len()
            ),
        ));
    } else {
        out.not_assessed.push((
            "V6.2.8".to_owned(),
            "Whether a password is cut short before it is checked: the app would not take a long \
             password to begin with. A password with its capitals swapped was refused."
                .to_owned(),
        ));
    }
}

/// The password field on the sign-in and sign-up pages: masked (V6.2.6), and not refusing a paste
/// (V6.2.7).
///
/// Read from the page's HTML, which is what a browser is given. The field is the one stackvet.toml
/// sends `{password}` in, so what is looked at is the field the app reads, not any input that
/// happens to say "password". A page that builds its form with script has no such field in its HTML,
/// and says so rather than passing. Pasting blocked by a script attached after the page loads cannot
/// be seen here, so V6.2.7 is only ever a finding.
pub(super) fn password_field_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    signed_in: Option<&Session>,
    out: &mut Outcome,
) {
    let anonymous = Session::default();
    // The password-change page is asked for as a signed-in user, since it is only shown to one.
    let forms: Vec<(&str, &RequestTemplate, &Session)> = [
        ("sign-in", &users.login, &anonymous),
        ("sign-up", &users.signup, &anonymous),
        (
            "password-change",
            &users.change_password,
            signed_in.unwrap_or(&anonymous),
        ),
    ]
    .into_iter()
    .filter_map(|(label, t, session)| t.as_ref().map(|t| (label, t, session)))
    .collect();
    let mut masked = Vec::new();
    let mut unmasked = Vec::new();
    let mut pasting = Vec::new();
    let mut missing = Vec::new();
    let mut hints = Vec::new();
    for (label, template, session) in forms {
        // Every field a password is sent in: the one of a sign-in, both of a password change.
        let fields: Vec<&String> = template
            .form
            .iter()
            .filter(|(_, v)| v.contains("{password}") || v.contains("{new_password}"))
            .map(|(k, _)| k)
            .collect();
        if fields.is_empty() {
            continue;
        }
        let page = http.send(&get(
            &format!("password-field-{label}"),
            &template.path,
            session,
        ));
        if let Some(what) = page
            .as_ref()
            .filter(|p| p.status == 200)
            .and_then(|p| password_hint(&p.body))
        {
            hints.push(format!("the {label} page {} ({what})", template.path));
        }
        let inputs: Vec<String> = page
            .as_ref()
            .filter(|p| p.status == 200)
            .map(|p| tags(&p.body, "input"))
            .unwrap_or_default()
            .into_iter()
            .filter(|tag| {
                attribute(tag, "name").is_some_and(|name| fields.iter().any(|f| **f == name))
            })
            .collect();
        if inputs.is_empty() {
            missing.push(format!("{} ({})", template.path, status(&page)));
            continue;
        }
        let where_ = format!("the {label} page {}", template.path);
        if inputs
            .iter()
            .all(|tag| attribute(tag, "type").is_some_and(|t| t.eq_ignore_ascii_case("password")))
        {
            masked.push(where_.clone());
        } else {
            unmasked.push(where_.clone());
        }
        if inputs.iter().any(|tag| attribute(tag, "onpaste").is_some()) {
            pasting.push(where_);
        }
    }
    if !unmasked.is_empty() {
        out.findings.push(finding(
            &UNMASKED_PASSWORD,
            "A password field shows what is typed",
            Severity::Medium,
            format!(
                "The password field on {} is not `type=\"password\"`.",
                unmasked.join(" and on ")
            ),
        ));
    } else if !masked.is_empty() {
        out.verified.push(crate::Verified::new(
            UNMASKED_PASSWORD.rule_id,
            UNMASKED_PASSWORD.requirement_ids,
            format!(
                "the password field stackvet.toml names, on {}, served as type=password",
                masked.join(" and ")
            ),
        ));
    }
    if !hints.is_empty() {
        out.findings.push(finding(
            &PASSWORD_HINTS,
            "A password hint or secret question is offered",
            Severity::Medium,
            format!("Found on {}.", hints.join(" and on ")),
        ));
    }
    if !pasting.is_empty() {
        out.findings.push(finding(
            &PASTE_BLOCKED,
            "Pasting into a password field is blocked",
            Severity::Low,
            format!(
                "The password field on {} has an `onpaste` handler.",
                pasting.join(" and on ")
            ),
        ));
    }
    if masked.is_empty() && unmasked.is_empty() {
        out.not_assessed.push((
            "V6.2.6".to_owned(),
            if missing.is_empty() {
                "Whether password fields are masked: stackvet.toml names no form with a \
                 `{password}` field."
                    .to_owned()
            } else {
                format!(
                    "Whether password fields are masked: the field stackvet.toml names was not in \
                     the HTML of {}. A page that builds its form with script cannot be read here.",
                    missing.join(" or ")
                )
            },
        ));
    }
}

/// Whether a password can be changed (V6.2.2), and whether changing it needs the current one
/// (V6.2.3), through `change-password`.
///
/// The wrong current password first, then the right one, each told by signing in afterwards. If the
/// change with a wrong current password takes, that is the finding, and it has also shown a
/// password can be changed. If it does not, the same change with the right current password has to
/// take, the new password signing in and the old one no longer, or the refusal before it cannot be
/// told apart from a change that never works.
pub(super) fn change_password_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    // V7.4.3 and V6.3.7 are asked about the same change, so they are not assessed whenever it is not.
    const IDS: &str = "V6.2.2, V6.2.3, V7.4.3, V6.3.7";
    let Some(change) = &users.change_password else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether a password can be changed, and whether that needs the current one: \
             stackvet.toml sets no `change-password` under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether a password can be changed: telling needs a private page a signed-in user alone \
             can open, and none was shown."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let account = match &users.signup {
        Some(signup) => {
            let account = Account {
                user: format!("change.{}", accounts.a.user),
                password: format!("Ch-{}-aZ9!", &spare[4..28]),
            };
            sign_up(http, users, signup, "change", &account);
            account
        }
        None => accounts.a.clone(),
    };
    if !account_works(http, users, "change", &account, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Whether a password can be changed: the account made for it, {}, could not sign in \
                 to begin with.",
                account.user
            ),
        ));
        return;
    }
    let wrong = format!("Wr-{}-aZ9!", &spare[6..30]);
    let first = format!("N1-{}-aZ9!", &spare[8..32]);
    let second = format!("N2-{}-aZ9!", &spare[2..26]);

    let changed = |http: &mut dyn Http, current: &str, new: &str, label: &str| {
        let mut quiet = Vec::new();
        let signed_in = sign_in(http, users, label, &account, &mut quiet)?;
        let mut session = signed_in.session;
        let values = Values {
            user: &account.user,
            password: current,
            new_password: new,
            ..Default::default()
        };
        // As for deletion: the form may be on the account page rather than at the address it posts
        // to.
        let pages: Vec<String> = users.private.clone();
        send_template(
            http,
            &format!("change-password-{label}"),
            change,
            &values,
            &mut session,
            &pages,
        )
        .0
    };
    let as_with = |password: &str| Account {
        user: account.user.clone(),
        password: password.to_owned(),
    };

    let answer = changed(http, &wrong, &first, "wrong-current");
    out.steps.push(format!(
        "asked to change the password giving a wrong current one ({})",
        status(&answer)
    ));
    if account_works(
        http,
        users,
        "changed",
        &as_with(&first),
        confirm,
        &mut out.steps,
    ) {
        out.findings.push(finding(
            &CHANGE_WITHOUT_CURRENT,
            "The password can be changed without the current one",
            Severity::High,
            format!(
                "A request to {} giving a wrong current password changed it: the new password then \
                 signed in.",
                change.path
            ),
        ));
        out.verified.push(crate::Verified::new(
            CHANGE_PASSWORD.rule_id,
            CHANGE_PASSWORD.requirement_ids,
            format!(
                "a password change through {}, after which the new password signed in",
                change.path
            ),
        ));
        out.not_assessed.push((
            "V7.4.3, V6.3.7".to_owned(),
            "What a password change does to the account's other sessions, and whether it emails the \
             account holder: the change was taken with a wrong current password, so the account's \
             password was no longer the one known here to try it again."
                .to_owned(),
        ));
        return;
    }

    // Before the change that should take: a second session of the same account (V7.4.3), and how
    // many emails the account has had (V6.3.7).
    let mut quiet = Vec::new();
    let bystander = sign_in(http, users, "bystander", &account, &mut quiet).map(|s| s.session);
    let mail_before = http.mail(&account.user, 0).map(|m| m.len());
    // The change, by hand rather than through `changed`, so the second session can be shown to
    // work after the changing session signed in: an app that keeps one session per account would
    // otherwise end it at that sign-in, and the change would be credited with it.
    let (answer, bystander_open_before) =
        match sign_in(http, users, "right-current", &account, &mut quiet) {
            None => (None, false),
            Some(signed_in) => {
                let open_before = bystander
                    .as_ref()
                    .is_some_and(|b| ok(&http.send(&get("bystander-before", confirm, b))));
                let mut session = signed_in.session;
                let values = Values {
                    user: &account.user,
                    password: &account.password,
                    new_password: &second,
                    ..Default::default()
                };
                let pages: Vec<String> = users.private.clone();
                let answer = send_template(
                    http,
                    "change-password-right-current",
                    change,
                    &values,
                    &mut session,
                    &pages,
                )
                .0;
                (answer, open_before)
            }
        };
    let bystander_open_after = bystander
        .as_ref()
        .filter(|_| bystander_open_before)
        .map(|b| ok(&http.send(&get("bystander-after", confirm, b))));
    let mail_after = mail_before.and_then(|before| {
        http.mail(&account.user, before + 1)
            .map(|m| (before, m.len()))
    });
    out.steps.push(format!(
        "asked to change the password giving the right current one ({})",
        status(&answer)
    ));
    let new_works = account_works(
        http,
        users,
        "changed",
        &as_with(&second),
        confirm,
        &mut out.steps,
    );
    if !new_works {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "A change of password through {} with the right current password did not take: \
                 the new password did not sign in. Check `change-password` in stackvet.toml. With \
                 no change that works, a refused one shows nothing.",
                change.path
            ),
        ));
        return;
    }
    let old_works = account_works(http, users, "old", &account, confirm, &mut out.steps);
    if old_works {
        out.findings.push(finding(
            &CHANGE_PASSWORD,
            "The old password still works after a change",
            Severity::High,
            format!(
                "After changing the password through {}, both the new password and the old one \
                 signed in.",
                change.path
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            CHANGE_PASSWORD.rule_id,
            CHANGE_PASSWORD.requirement_ids,
            format!(
                "a password change through {}, after which the new password signed in and the old \
                 one was refused",
                change.path
            ),
        ));
    }
    out.verified.push(crate::Verified::new(
        CHANGE_WITHOUT_CURRENT.rule_id,
        CHANGE_WITHOUT_CURRENT.requirement_ids,
        format!(
            "a change through {} giving a wrong current password, refused where the same change \
             with the right one took",
            change.path
        ),
    ));
    sessions_after_change(bystander_open_after, &change.path, out);
    email_after_change(mail_after, &change.path, out);
}

/// V7.5.1: whether the email address can be changed without the password. Only ever asked of an
/// account made for it through `signup`, since A and B have to keep signing in by their addresses.
///
/// A change counts as taken when the new address signs in with the account's password. That is
/// all it rests on: a page showing the new address could be one saying a change is waiting to be
/// confirmed, which is no change at all. So an app that signs in by user name, or that holds the
/// change until the new address is confirmed, leaves this not assessed rather than credited.
pub(super) fn change_email_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V7.5.1";
    let Some(change) = &users.change_email else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether changing the email address needs the password again: stackvet.toml sets no \
             `change-email` under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(signup) = &users.signup else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether changing the email address needs the password again: it is only ever done to \
             an account made for it, and stackvet.toml sets no `signup` to make one."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether changing the email address needs the password again: telling needs a private \
             page a signed-in user alone can open, and none was shown."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let account = Account {
        user: format!("email.{}", accounts.a.user),
        password: format!("Em-{}-aZ9!", &spare[3..27]),
    };
    sign_up(http, users, signup, "email", &account);
    if !account_works(http, users, "email", &account, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Whether changing the email address needs the password again: the account made \
                 for it, {}, could not sign in to begin with.",
                account.user
            ),
        ));
        return;
    }
    let wrong = format!("Wr-{}-aZ9!", &spare[5..29]);
    let moved = |label: &str| Account {
        user: format!("{label}.{}", account.user),
        password: account.password.clone(),
    };
    let (by_wrong, by_right) = (moved("moved-wrong"), moved("moved-right"));

    let changed = |http: &mut dyn Http, password: &str, to: &Account, label: &str| {
        let mut quiet = Vec::new();
        let signed_in = sign_in(http, users, &format!("email-{label}"), &account, &mut quiet)?;
        let mut session = signed_in.session;
        let values = Values {
            user: &account.user,
            password,
            new_email: &to.user,
            ..Default::default()
        };
        let pages: Vec<String> = users.private.clone();
        send_template(
            http,
            &format!("change-email-{label}"),
            change,
            &values,
            &mut session,
            &pages,
        )
        .0
    };

    let answer = changed(http, &wrong, &by_wrong, "wrong-password");
    out.steps.push(format!(
        "asked to change the email address giving a wrong password ({})",
        status(&answer)
    ));
    if account_works(
        http,
        users,
        "email-moved-wrong",
        &by_wrong,
        confirm,
        &mut out.steps,
    ) {
        out.findings.push(finding(
            &EMAIL_CHANGE_WITHOUT_PASSWORD,
            "The email address can be changed without the password",
            Severity::High,
            format!(
                "A request to {} giving a wrong password changed the account's email address: \
                 the new address then signed in.",
                change.path
            ),
        ));
        return;
    }

    let answer = changed(http, &account.password, &by_right, "right-password");
    out.steps.push(format!(
        "asked to change the email address giving the right password ({})",
        status(&answer)
    ));
    if !account_works(
        http,
        users,
        "email-moved-right",
        &by_right,
        confirm,
        &mut out.steps,
    ) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "A change of email address through {} with the right password did not take: the \
                 new address did not sign in. That happens when sign-in is by user name rather \
                 than email address, or when the app waits for the new address to be confirmed \
                 first; otherwise check `change-email` in stackvet.toml. With no change that \
                 works, a refused one shows nothing.",
                change.path
            ),
        ));
        return;
    }
    out.verified.push(crate::Verified::new(
        EMAIL_CHANGE_WITHOUT_PASSWORD.rule_id,
        EMAIL_CHANGE_WITHOUT_PASSWORD.requirement_ids,
        format!(
            "a change of email address through {} giving a wrong password, refused where the same \
             change with the right one took",
            change.path
        ),
    ));
}

/// V7.4.3: whether a second session of the account still opened a private page after the password
/// was changed in another. `None` when that second session could not be shown working just before
/// the change.
fn sessions_after_change(open_after: Option<bool>, path: &str, out: &mut Outcome) {
    match open_after {
        Some(false) => out.verified.push(crate::Verified::new(
            CHANGE_ENDS_SESSIONS.rule_id,
            CHANGE_ENDS_SESSIONS.requirement_ids,
            format!(
                "a second session of the account, open just before the password was changed \
                 through {path}, and shut just after"
            ),
        )),
        Some(true) => out.not_assessed.push((
            "V7.4.3".to_owned(),
            format!(
                "Another session of the account kept working after the password was changed \
                 through {path}. That meets V7.4.3 only if the app offers to end the other \
                 sessions when the password changes; check whether it does. Not a finding: an \
                 offer on the page cannot be seen from here."
            ),
        )),
        None => out.not_assessed.push((
            "V7.4.3".to_owned(),
            "Whether a password change ends the account's other sessions: a second session could \
             not be shown opening a private page just before the change, so its being shut \
             afterwards would show nothing."
                .to_owned(),
        )),
    }
    crate::verified::unless_credited(CHANGE_ENDS_SESSIONS.rule_id, &out.verified);
}

/// V6.3.7: whether an email reached the account holder after the password was changed, as
/// (emails before, emails after), or `None` when the run has no mail server to read.
fn email_after_change(mail: Option<(usize, usize)>, path: &str, out: &mut Outcome) {
    match mail {
        Some((before, after)) if after > before => out.verified.push(crate::Verified::new(
            CHANGE_NOTIFIED.rule_id,
            CHANGE_NOTIFIED.requirement_ids,
            format!("an email to the account holder after a password change through {path}"),
        )),
        Some(_) => out.not_assessed.push((
            "V6.3.7".to_owned(),
            format!(
                "No email reached the account holder after the password was changed through \
                 {path}. If the app tells people about a changed password some other way, such as \
                 a message in the app, say so; if not, it should email them. Not a finding: \
                 another way cannot be seen from here."
            ),
        )),
        None => out.not_assessed.push((
            "V6.3.7".to_owned(),
            "Whether the account holder is emailed when the password changes: this run has no \
             mail server to read, so no email could have been seen."
                .to_owned(),
        )),
    }
    crate::verified::unless_credited(CHANGE_NOTIFIED.rule_id, &out.verified);
}

/// What a request that may tell an address with an account from one without is, for the finding:
/// the rule it raises, its title, and how the request is named in its description.
pub(super) struct AskedAbout<'a> {
    pub(super) rule: &'a Rule,
    pub(super) title: &'a str,
    pub(super) what: &'a str,
}

/// The reset request, as `reveals_account_check` names it.
pub(super) const RESET_REQUEST: AskedAbout<'static> = AskedAbout {
    rule: &RESET_REVEALS_ACCOUNT,
    title: "Password reset tells anyone whether an address has an account",
    what: "A reset request",
};

/// Whether a second sign-up with an address that has an account takes that account (V6.2.3).
///
/// An account is made for it, never A's or B's, and shown to work: its password opens the private
/// page. Then the same address signs up again with another password, and both passwords are tried.
/// The new one opening the page is the finding: the second sign-up changed the account's password
/// without the current one, which is what a password change must ask for. Only ever a finding: the
/// old password still working, and the new one refused, shows nothing about the app's own password
/// change. Without a sign-up, or a private page to tell a working sign-in by, it does not run.
pub(super) fn signup_replaces_account_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let (Some(signup), Some(confirm)) = (users.signup.as_ref(), confirm) else {
        return;
    };
    let spare: String = accounts.b.password.chars().take(12).collect();
    let first = Account {
        user: format!("resignup.{}", accounts.a.user),
        password: format!("R1-{spare}-1aZ!"),
    };
    let second = Account {
        user: first.user.clone(),
        password: format!("R2-{spare}-1aZ!"),
    };
    sign_up(http, users, signup, "resignup-1", &first);
    if !account_works(http, users, "resignup-1", &first, confirm, &mut out.steps) {
        out.steps.push(format!(
            "made an account, {}, to sign up with again: it did not sign in, so the second sign-up \
             was not tried",
            first.user
        ));
        return;
    }
    let answer = sign_up(http, users, signup, "resignup-2", &second);
    let status = answer.as_ref().map_or(0, |r| r.status);
    let new_works = account_works(
        http,
        users,
        "resignup-new",
        &second,
        confirm,
        &mut out.steps,
    );
    let old_works = account_works(http, users, "resignup-old", &first, confirm, &mut out.steps);
    out.steps.push(format!(
        "signed up again with {}, which has an account, and another password ({status}): the new \
         password {}, the old one {}",
        first.user,
        if new_works {
            "signed in"
        } else {
            "was refused"
        },
        if old_works {
            "still signed in"
        } else {
            "was refused"
        },
    ));
    if new_works {
        out.findings.push(finding(
            &SIGNUP_REPLACES_ACCOUNT,
            "Signing up again with a taken address takes the account",
            Severity::Critical,
            format!(
                "After an account was made through {} and shown to sign in, a second sign-up with the \
                 same address and another password was answered {status}, and that other password then \
                 signed in to the account{}.",
                signup.path,
                if old_works {
                    ", beside the old one"
                } else {
                    " in place of the old one"
                }
            ),
        ));
    }
}

/// The sign-up a run asked, as `reveals_account_check` names it.
const SIGN_UP_WITH_A_TAKEN_ADDRESS: AskedAbout<'static> = AskedAbout {
    rule: &SIGNUP_REVEALS_ACCOUNT,
    title: "Sign-up tells anyone whether an address has an account",
    what: "A sign-up",
};

/// Whether a sign-up tells an address that has an account from one that has none (V6.3.8).
///
/// An account is made for it first, never A's or B's: an app that lets a second sign-up replace an
/// account would otherwise change a password the other checks rely on. Then two sign-ups with that
/// address and one with an address nobody has, all with the same password, compared by
/// `reveals_account_check`: the pair shows what varies between identical sign-ups, and only a
/// status, words, or a redirect that differ beyond that count. A limit refusing a sign-up (429), or
/// no answer, leaves them uncompared; a crash is set aside through `RAISED_ON_A_REFUSAL`. Only ever a
/// finding: answers alike can still differ in how long they take, or in the email sent afterwards.
pub(super) fn signup_reveals_account_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    out: &mut Outcome,
) {
    let Some(signup) = users.signup.as_ref() else {
        return;
    };
    let password = format!(
        "Su-{}-1aZ!",
        accounts.b.password.chars().take(12).collect::<String>()
    );
    let taken = Account {
        user: format!("taken.{}", accounts.a.user),
        password: password.clone(),
    };
    let fresh = Account {
        user: format!("nobody.taken.{}", accounts.a.user),
        password,
    };
    sign_up_only(http, signup, "reveal-made", &taken);
    let first = sign_up_only(http, signup, "reveal-1", &taken);
    let second = sign_up_only(http, signup, "reveal-2", &taken);
    let stranger = sign_up_only(http, signup, "reveal-nobody", &fresh);
    let status = |r: &Option<ProbeResponse>| r.as_ref().map_or(0, |r| r.status);
    let statuses = [status(&first), status(&second), status(&stranger)];
    let limited = statuses.iter().any(|s| *s == 429 || *s == 0);
    out.steps.push(format!(
        "signed up with an address that has an account, {}, twice ({}, {}) and with one that has none \
         ({}){}",
        taken.user,
        statuses[0],
        statuses[1],
        statuses[2],
        if limited {
            ": not compared, since a sign-up was refused as too many or not answered"
        } else {
            ""
        }
    ));
    if limited {
        return;
    }
    reveals_account_check(
        [&first, &second, &stranger],
        &taken.user,
        &fresh.user,
        &signup.path,
        &SIGN_UP_WITH_A_TAKEN_ADDRESS,
        out,
    );
}

/// Whether the answer to a request tells an address with an account from one without.
///
/// Two requests for the same account show what changes between identical requests — a token in
/// a hidden field, a time — and all of that is set aside first; the address itself is replaced
/// in each answer, since echoing it back is no leak. Only a difference left over after that is a
/// finding, and a pair that differs from itself leaves the wording unjudged, never faulted.
pub(super) fn reveals_account_check(
    answers: [&Option<ProbeResponse>; 3],
    user: &str,
    nobody: &str,
    path: &str,
    asked: &AskedAbout,
    out: &mut Outcome,
) {
    let [Some(first), Some(second), Some(stranger)] = answers else {
        return;
    };
    let what = asked.what;
    if first.status == second.status && stranger.status != first.status {
        out.findings.push(finding(
            asked.rule,
            asked.title,
            Severity::Medium,
            format!(
                "{what} to {path} was answered {} for an address with an account and {} for one \
                 without.",
                first.status, stranger.status
            ),
        ));
        return;
    }
    let shape = |r: &ProbeResponse, address: &str| {
        let location = r
            .headers
            .iter()
            .find(|(k, _)| k == "location")
            .map_or("", |(_, v)| v.as_str());
        same_shape(&format!("{location}\n{}", r.body), address)
    };
    let (a, b, c) = (
        shape(first, user),
        shape(second, user),
        shape(stranger, nobody),
    );
    if a == b && c != a && first.status == stranger.status {
        out.findings.push(finding(
            asked.rule,
            asked.title,
            Severity::Medium,
            format!(
                "{what} to {path} was answered in different words, or sent somewhere different, \
                 for an address with an account than for one without, where two requests for the \
                 same account were answered alike."
            ),
        ));
    }
}

/// An answer with what legitimately differs between requests taken out: the address it was about,
/// however it was written, the values of fields, and long random-looking runs.
fn same_shape(text: &str, address: &str) -> String {
    let mut text = text.to_owned();
    for written in [
        address.to_owned(),
        address.replace('@', "%40"),
        address.replace('@', "&#64;"),
        address.replace('@', "&#x40;"),
    ] {
        text = text.replace(&written, "{user}");
    }
    static VALUES: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)value\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)"#).expect("a fixed pattern")
    });
    static LONG: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z0-9_-]{16,}").expect("a fixed pattern"));
    let text = VALUES.replace_all(&text, "value");
    LONG.replace_all(&text, "#").into_owned()
}

/// A password hint or a secret question on a page, in the page's words or a field's name.
///
/// Only ever a finding: a page with none of these words can still ask for one in a way no list of
/// phrases foresees, and the same page may be one step of several.
fn password_hint(body: &str) -> Option<String> {
    static WORDS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)\b(security question|secret question|password hint|mother'?s maiden name|name of your first pet|first pet'?s name|what city were you born)\b",
        )
        .expect("a fixed pattern")
    });
    static NAMES: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)^(password_?hint|hint|security_?question|secret_?question|security_?answer|secret_?answer)$",
        )
        .expect("a fixed pattern")
    });
    if let Some(m) = WORDS.find(body) {
        return Some(format!("\"{}\"", m.as_str()));
    }
    ["input", "select", "textarea"]
        .iter()
        .flat_map(|t| tags(body, t))
        .filter_map(|tag| attribute(&tag, "name"))
        .find(|name| NAMES.is_match(name))
        .map(|name| format!("a field named `{name}`"))
}

/// Whether deleting an account ends every session it had (V7.4.2), through `delete-account`.
///
/// Only ever on an account made for it through `signup`; A and B are never deleted. It is signed in
/// twice, as two browsers would be, and both sessions are shown to open the private page. The
/// account is deleted from the first; then the second is asked for the private page again. The
/// deletion itself is shown first: the account's password must no longer sign in, or a surviving
/// session says nothing about deletion.
pub(super) fn delete_account_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V7.4.2";
    let Some(delete) = &users.delete_account else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether deleting an account ends its sessions: stackvet.toml sets no \
             `delete-account` under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(signup) = &users.signup else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether deleting an account ends its sessions: only an account made for the purpose is \
             ever deleted, and stackvet.toml sets no `signup` to make one."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        // Said, not skipped (the architecture assessment of 8 October 2026, item 8).
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether deleting an account ends its sessions: no private page opened for a \
             signed-in user, so whether a deleted account's session still opens one cannot be \
             tried."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let account = Account {
        user: format!("delete.{}", accounts.a.user),
        password: format!("De-{}-aZ9!", &spare[3..27]),
    };
    sign_up(http, users, signup, "delete", &account);
    let mut quiet = Vec::new();
    let (Some(first), Some(second)) = (
        sign_in(http, users, "delete-1", &account, &mut quiet),
        sign_in(http, users, "delete-2", &account, &mut quiet),
    ) else {
        return;
    };
    let opens = |http: &mut dyn Http, s: &Session, id: &str| ok(&http.send(&get(id, confirm, s)));
    if !(opens(http, &first.session, "delete-before-1")
        && opens(http, &second.session, "delete-before-2"))
    {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether deleting an account ends its sessions: the account made for it could not be \
             signed in twice to begin with."
                .to_owned(),
        ));
        return;
    }
    let mut session = first.session.clone();
    let values = Values {
        user: &account.user,
        password: &account.password,
        ..Default::default()
    };
    // The token is looked for where sign-out looks for it: the delete button is usually on a page
    // of its own account, not at the address it posts to.
    let pages: Vec<String> = users
        .private
        .iter()
        .cloned()
        .chain(users.owned.as_ref().map(|o| o.create.path.clone()))
        .collect();
    let (answer, _) = send_template(
        http,
        "delete-account",
        delete,
        &values,
        &mut session,
        &pages,
    );
    out.steps.push(format!(
        "deleted an account made for it, signed in twice ({})",
        status(&answer)
    ));
    if account_works(http, users, "deleted", &account, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Whether deleting an account ends its sessions: after the request to {}, the \
                 account still signed in, so it was not deleted. Check `delete-account` in \
                 stackvet.toml.",
                delete.path
            ),
        ));
        return;
    }
    if opens(http, &second.session, "delete-after") {
        out.findings.push(finding(
            &SESSIONS_SURVIVE_DELETION,
            "A deleted account's other sessions keep working",
            Severity::High,
            format!(
                "After the account was deleted through {}, a second session signed in to it earlier \
                 still opened {confirm}.",
                delete.path
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            SESSIONS_SURVIVE_DELETION.rule_id,
            SESSIONS_SURVIVE_DELETION.requirement_ids,
            format!(
                "an account signed in twice and deleted through {} from one session: the other was \
                 refused afterwards, and the account's password no longer signed in",
                delete.path
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::{run_signing_up, run_signing_up_with, with_signup, with_words};
    use super::*;

    #[test]
    fn a_correct_sign_up_confirms_the_password_rules_and_raises_nothing() {
        let o = run_signing_up(Flaws::default());
        assert!(o.findings.is_empty(), "{:#?}\n{:?}", o.findings, o.steps);
        for id in [
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
            COMPOSITION_RULES.rule_id,
            ALTERED_PASSWORD.rule_id,
            LONG_PASSWORD.rule_id,
            UNMASKED_PASSWORD.rule_id,
            BREACHED_PASSWORD.rule_id,
            CONTEXT_WORD_PASSWORD.rule_id,
        ] {
            assert!(verified_ids(&o).contains(&id), "{id}: {:?}", o.steps);
        }
        // These can only ever find something; a clean answer is credited with nothing.
        for id in [
            DEFAULT_ACCOUNT.rule_id,
            PASSWORD_IN_URL.rule_id,
            WEAK_SESSION_ID.rule_id,
            PASTE_BLOCKED.rule_id,
            SIGN_OUT_ON_GET.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&id), "{id} was credited");
        }
        assert!(
            o.steps.iter().any(|s| s.contains("7-character password")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn three_common_words_of_one_shape_and_a_list_holding_one_of_them_is_found() {
        // ADR-055. The three are where they say in the list, in its top 3000, and of the one shape the
        // random control has, so a refusal of any of them is about the word.
        let list = include_str!("../../../../data/knowledge/common-passwords.txt");
        let lines: Vec<&str> = list.lines().collect();
        for (word, line) in [
            (COMMON, 1238),
            (COMMON_MORE[0], 2018),
            (COMMON_MORE[1], 2744),
        ] {
            assert_eq!(lines[line - 1], word, "line {line}");
            assert!(line <= 3000, "{word}");
            assert_eq!(word.len(), 12, "{word}");
            assert!(
                word.chars()
                    .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
            );
        }
        let u = with_signup();
        // A list written from memory that holds the first word and not the others: found, naming them.
        let o = run_against(
            Flaws {
                common_list_short: true,
                ..Default::default()
            },
            &u,
        );
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == COMMON_PASSWORD.rule_id)
            .expect("found");
        assert!(
            found
                .description
                .contains("`1q2w3e4r5t6y` and `qwerty123456`")
                && !found.description.contains(COMMON),
            "{}",
            found.description
        );
        assert!(!verified_ids(&o).contains(&COMMON_PASSWORD.rule_id));
        // All three refused: credited, the line naming all three.
        let o = run_against(Flaws::default(), &u);
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == COMMON_PASSWORD.rule_id)
            .expect("credited");
        for word in [COMMON, COMMON_MORE[0], COMMON_MORE[1]] {
            assert!(credit.scope.contains(word), "{}", credit.scope);
        }
    }

    #[test]
    fn each_password_flaw_is_found_by_its_own_rule_and_by_no_other() {
        for (flaw, rule) in [
            (
                Flaws {
                    short_password_ok: true,
                    ..Default::default()
                },
                SHORT_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    common_password_ok: true,
                    ..Default::default()
                },
                COMMON_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    common_list_short: true,
                    ..Default::default()
                },
                COMMON_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    composition_rules: true,
                    ..Default::default()
                },
                COMPOSITION_RULES.rule_id,
            ),
            (
                Flaws {
                    breached_password_ok: true,
                    ..Default::default()
                },
                BREACHED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    context_word_ok: true,
                    ..Default::default()
                },
                CONTEXT_WORD_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    default_admin: true,
                    ..Default::default()
                },
                DEFAULT_ACCOUNT.rule_id,
            ),
            (
                Flaws {
                    password_in_url: true,
                    ..Default::default()
                },
                PASSWORD_IN_URL.rule_id,
            ),
            (
                Flaws {
                    short_session_ids: true,
                    ..Default::default()
                },
                WEAK_SESSION_ID.rule_id,
            ),
            (
                Flaws {
                    same_session_id: true,
                    ..Default::default()
                },
                WEAK_SESSION_ID.rule_id,
            ),
            (
                Flaws {
                    case_folded: true,
                    ..Default::default()
                },
                ALTERED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    cut_at_72: true,
                    ..Default::default()
                },
                ALTERED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    longest_64: true,
                    ..Default::default()
                },
                LONG_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    password_shown: true,
                    ..Default::default()
                },
                UNMASKED_PASSWORD.rule_id,
            ),
            (
                Flaws {
                    paste_blocked: true,
                    ..Default::default()
                },
                PASTE_BLOCKED.rule_id,
            ),
            (
                Flaws {
                    logout_on_get: true,
                    ..Default::default()
                },
                SIGN_OUT_ON_GET.rule_id,
            ),
            (
                Flaws {
                    deletion_keeps_sessions: true,
                    ..Default::default()
                },
                SESSIONS_SURVIVE_DELETION.rule_id,
            ),
            (
                Flaws {
                    secret_question: true,
                    ..Default::default()
                },
                PASSWORD_HINTS.rule_id,
            ),
        ] {
            let o = run_signing_up(flaw);
            let found = rule_ids(&o);
            assert_eq!(found, vec![rule], "{:?}\n{:?}", o.steps, o.not_assessed);
            assert!(
                !verified_ids(&o).contains(&rule),
                "{rule} both found and confirmed"
            );
        }
    }

    #[test]
    fn a_correct_password_change_confirms_both_questions() {
        for (how, o) in [
            ("signing up", run_signing_up(Flaws::default())),
            ("seeded, with A", run_against(Flaws::default(), &users())),
        ] {
            assert!(o.findings.is_empty(), "{how}: {:#?}", o.findings);
            for id in [CHANGE_PASSWORD.rule_id, CHANGE_WITHOUT_CURRENT.rule_id] {
                assert!(verified_ids(&o).contains(&id), "{how}: {id}: {:?}", o.steps);
            }
        }
    }

    #[test]
    fn each_password_change_flaw_is_found_by_its_own_rule() {
        for (flaw, rule, credited) in [
            (
                Flaws {
                    change_without_current: true,
                    ..Default::default()
                },
                CHANGE_WITHOUT_CURRENT.rule_id,
                // A change that took has shown the password can be changed.
                Some(CHANGE_PASSWORD.rule_id),
            ),
            (
                Flaws {
                    change_keeps_old: true,
                    ..Default::default()
                },
                CHANGE_PASSWORD.rule_id,
                Some(CHANGE_WITHOUT_CURRENT.rule_id),
            ),
        ] {
            for o in [run_signing_up(flaw), run_against(flaw, &users())] {
                assert_eq!(rule_ids(&o), vec![rule], "{:?}", o.steps);
                assert!(
                    !verified_ids(&o).contains(&rule),
                    "{rule} both found and credited"
                );
                if let Some(other) = credited {
                    assert!(verified_ids(&o).contains(&other), "{other}: {:?}", o.steps);
                }
            }
        }
    }

    #[test]
    fn an_email_change_that_needs_the_password_is_credited() {
        let o = run_signing_up(Flaws::default());
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        assert!(
            verified_ids(&o).contains(&EMAIL_CHANGE_WITHOUT_PASSWORD.rule_id),
            "{:?}",
            o.steps
        );
        // The control really ran: the new address signed in.
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("signed in as moved-right.") && s.ends_with("opened")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn an_email_change_without_the_password_is_found() {
        let o = run_signing_up(Flaws {
            email_change_without_password: true,
            ..Default::default()
        });
        assert_eq!(
            rule_ids(&o),
            vec![EMAIL_CHANGE_WITHOUT_PASSWORD.rule_id],
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&EMAIL_CHANGE_WITHOUT_PASSWORD.rule_id));
    }

    #[test]
    fn an_email_change_that_never_takes_is_not_assessed() {
        // Refusing the wrong password means nothing if the right one changes nothing either.
        let o = run_signing_up(Flaws {
            email_change_does_nothing: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(!verified_ids(&o).contains(&EMAIL_CHANGE_WITHOUT_PASSWORD.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V7.5.1")
            .expect("named as not assessed");
        assert!(why.contains("did not take"), "{why}");
    }

    #[test]
    fn an_email_change_is_never_made_to_a_seeded_account() {
        // Without `signup` there is only A and B, which every other question signs in as.
        let o = run_against(Flaws::default(), &users());
        assert!(!verified_ids(&o).contains(&EMAIL_CHANGE_WITHOUT_PASSWORD.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V7.5.1" && why.contains("no `signup`")),
            "{:?}",
            o.not_assessed
        );
        assert!(
            !o.steps.iter().any(|s| s.contains("email address")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_change_that_never_takes_answers_neither_question() {
        // Refusing the wrong current password means nothing if the right one is refused too.
        let o = run_signing_up(Flaws {
            change_does_nothing: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        for id in [CHANGE_PASSWORD.rule_id, CHANGE_WITHOUT_CURRENT.rule_id] {
            assert!(!verified_ids(&o).contains(&id), "{id} credited");
        }
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.2, V6.2.3, V7.4.3, V6.3.7")
            .expect("both are named as not assessed");
        assert!(why.contains("did not take"), "{why}");
    }

    #[test]
    fn with_no_change_password_entry_both_are_not_assessed() {
        let mut u = with_signup();
        u.change_password = None;
        let mut app = FakeApp::new(Flaws::default());
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(&mut app, &u, &acc, false, &Default::default());
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.2, V6.2.3, V7.4.3, V6.3.7")
            .expect("named as not assessed");
        assert!(why.contains("`change-password`"), "{why}");
    }

    #[test]
    fn the_password_change_page_is_read_signed_in_and_both_its_fields_are_judged() {
        // The change page sends anybody not signed in to /login; only a signed-in read sees it.
        let o = run_signing_up(Flaws {
            password_shown: true,
            ..Default::default()
        });
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == UNMASKED_PASSWORD.rule_id)
            .expect("found");
        assert!(
            found.description.contains("password-change page /password"),
            "{}",
            found.description
        );
    }

    #[test]
    fn the_new_password_field_is_judged_as_well_as_the_current_one() {
        let o = run_signing_up(Flaws {
            new_field_shown: true,
            ..Default::default()
        });
        assert_eq!(
            rule_ids(&o),
            vec![UNMASKED_PASSWORD.rule_id],
            "{:?}",
            o.steps
        );
        assert!(o.findings[0].description.contains("/password"));
    }

    #[test]
    fn deleting_an_account_ends_its_other_sessions_and_says_so() {
        let o = run_signing_up(Flaws::default());
        assert!(
            verified_ids(&o).contains(&SESSIONS_SURVIVE_DELETION.rule_id),
            "{:?}\n{:?}",
            o.steps,
            o.not_assessed
        );
        let o = run_signing_up(Flaws {
            deletion_keeps_sessions: true,
            ..Default::default()
        });
        assert_eq!(
            rule_ids(&o),
            vec![SESSIONS_SURVIVE_DELETION.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_deletion_that_did_not_happen_answers_nothing() {
        // The account still signing in means nothing was deleted, and a live session afterwards
        // would otherwise be blamed on the sessions.
        let o = run_signing_up(Flaws {
            delete_does_nothing: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(!verified_ids(&o).contains(&SESSIONS_SURVIVE_DELETION.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V7.4.2")
            .expect("named as not assessed");
        assert!(why.contains("was not deleted"), "{why}");
    }

    #[test]
    fn without_sign_up_no_account_is_ever_deleted() {
        // A and B are the accounts every other question stands on; deleting one is never done.
        let o = run_against(Flaws::default(), &users());
        assert!(!verified_ids(&o).contains(&SESSIONS_SURVIVE_DELETION.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V7.4.2")
            .expect("named as not assessed");
        assert!(why.contains("`signup`"), "{why}");
        assert!(
            !o.steps.iter().any(|s| s.contains("deleted")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_secret_question_is_found_by_its_field_and_by_its_words() {
        let o = run_signing_up(Flaws {
            secret_question: true,
            ..Default::default()
        });
        assert_eq!(rule_ids(&o), vec![PASSWORD_HINTS.rule_id], "{:?}", o.steps);
        assert!(o.findings[0].description.contains("security_answer"));
        assert_eq!(
            password_hint("<p>Choose a security question.</p>").as_deref(),
            Some("\"security question\"")
        );
        assert_eq!(
            password_hint("<input name=hint>").as_deref(),
            Some("a field named `hint`")
        );
        // Ordinary words that are not a hint: "hints" in prose, a "question" field of a form.
        assert_eq!(
            password_hint("<p>Some hints for a strong password</p><input name=question>"),
            None
        );
    }

    #[test]
    fn a_password_both_case_folded_and_cut_short_is_one_finding_naming_both() {
        let o = run_signing_up(Flaws {
            case_folded: true,
            cut_at_72: true,
            ..Default::default()
        });
        let altered: Vec<&Finding> = o
            .findings
            .iter()
            .filter(|f| f.rule_id == ALTERED_PASSWORD.rule_id)
            .collect();
        assert_eq!(altered.len(), 1, "{:?}", o.findings);
        let said = &altered[0].description;
        assert!(
            said.contains("capitals") && said.contains("first 72"),
            "{said}"
        );
    }

    #[test]
    fn a_long_password_refused_leaves_the_cut_short_question_unanswered() {
        // Nothing can be cut short if nothing long was taken. The case question still ran.
        let o = run_signing_up(Flaws {
            longest_64: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&ALTERED_PASSWORD.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.8")
            .expect("V6.2.8 is named as not assessed");
        assert!(why.contains("capitals swapped was refused"), "{why}");
    }

    #[test]
    fn a_form_built_by_script_is_not_assessed_rather_than_passed() {
        let o = run_signing_up(Flaws {
            no_form_in_html: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&UNMASKED_PASSWORD.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.6")
            .expect("V6.2.6 is named as not assessed");
        assert!(why.contains("/login") && why.contains("/signup"), "{why}");
    }

    #[test]
    fn the_password_field_is_the_one_the_form_sends_not_any_input() {
        // A search box that happens to be a text field is not the password field: only the input
        // named by the template's `{password}` is judged.
        let mut app = FakeApp::new(Flaws::default());
        let mut out = Outcome::default();
        struct Page<'a>(&'a mut FakeApp);
        impl Http for Page<'_> {
            fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
                let mut response = self.0.send(r)?;
                if r.path == "/login" && r.method == "GET" {
                    response.body.push_str("<input type=\"text\" name=\"q\">");
                }
                Some(response)
            }
        }
        password_field_checks(&mut Page(&mut app), &with_signup(), None, &mut out);
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert_eq!(verified_ids(&out), [UNMASKED_PASSWORD.rule_id]);
    }

    #[test]
    fn composition_rules_leave_the_common_password_check_unanswerable_rather_than_passed() {
        // The common password has no capital, so an app that wants one refuses it for that; the
        // random password of the same kinds is refused too, which is what shows it.
        let o = run_signing_up(Flaws {
            composition_rules: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&COMMON_PASSWORD.rule_id));
        assert!(
            o.not_assessed.iter().any(|(ids, _)| ids == "V6.2.4"),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn with_no_sign_up_the_password_rules_are_not_assessed() {
        let o = run_against(Flaws::default(), &users());
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids.contains("V6.2.1"))
            .expect("the password rules are named as not assessed");
        assert!(why.contains("`signup`"), "{why}");
        for id in [
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
            COMPOSITION_RULES.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&id));
        }
    }

    #[test]
    fn a_sign_up_that_refuses_everybody_asks_no_password_question() {
        // The control is refused too, so no refusal can be put down to the password.
        let mut u = with_signup();
        u.seed = Some("seed".into());
        let o = run_against(
            Flaws {
                signup_closed: true,
                ..Default::default()
            },
            &u,
        );
        for id in [
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
            COMPOSITION_RULES.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&id), "{id} credited");
            assert!(!rule_ids(&o).contains(&id), "{id} found");
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.2.1") && why.contains("strong password")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn with_no_context_words_listed_v6_2_11_is_not_assessed_and_says_how_to_list_them() {
        // V6.2.11 asks that the *documented* list is used. Guessing at words would be testing a
        // list nobody wrote, so no list means nothing to hold the app to.
        let o = run_signing_up_with(
            Flaws {
                context_word_ok: true,
                ..Default::default()
            },
            &Default::default(),
        );
        assert!(
            !rule_ids(&o).contains(&CONTEXT_WORD_PASSWORD.rule_id),
            "found a fault against a list nobody wrote"
        );
        assert!(!verified_ids(&o).contains(&CONTEXT_WORD_PASSWORD.rule_id));
        let (_, why) = o
            .not_assessed
            .iter()
            .find(|(ids, _)| ids == "V6.2.11")
            .expect("V6.2.11 is named as not assessed");
        assert!(why.contains("context-words"), "{why}");
    }

    #[test]
    fn a_list_of_words_too_short_to_try_is_not_assessed_rather_than_padded() {
        let o = run_signing_up_with(Flaws::default(), &with_words(&["ab", "x!y"]));
        assert!(!verified_ids(&o).contains(&CONTEXT_WORD_PASSWORD.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V6.2.11" && why.contains("between 4 and 32")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_refusal_that_also_refuses_the_control_credits_neither_new_rule() {
        // Composition rules refuse both the listed password and its random twin, since neither
        // has a capital. A refusal the control shares is about the shape, not the password.
        let o = run_signing_up(Flaws {
            composition_rules: true,
            ..Default::default()
        });
        for (id, rule) in [
            ("V6.2.12", BREACHED_PASSWORD.rule_id),
            ("V6.2.11", CONTEXT_WORD_PASSWORD.rule_id),
        ] {
            assert!(!verified_ids(&o).contains(&rule), "{rule} credited");
            assert!(!rule_ids(&o).contains(&rule), "{rule} found");
            assert!(
                o.not_assessed.iter().any(|(ids, _)| ids == id),
                "{id} not named: {:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn the_breached_password_and_its_count_are_the_ones_the_evidence_records() {
        // The finding calls this password breached on the strength of one recorded check. Changing
        // the password without new evidence must fail here, and the wording must quote the file.
        let evidence: serde_json::Value =
            serde_json::from_str(BREACHED_EVIDENCE).expect("the evidence file parses");
        assert_eq!(
            evidence["password"], BREACHED,
            "a different password than the one checked"
        );
        let seen = evidence["seen"].as_u64().expect("a count");
        let sha1 = evidence["sha1"].as_str().expect("a hash");
        let own: String = {
            use sha1::Digest;
            sha1::Sha1::digest(BREACHED.as_bytes())
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect()
        };
        assert_eq!(sha1, own, "the recorded hash is not this password's");
        assert_eq!(
            evidence["range"].as_str(),
            Some(format!("https://api.pwnedpasswords.com/range/{}", &sha1[..5]).as_str()),
            "the recorded range is not the one for this hash"
        );
        assert_eq!(
            evidence["line"].as_str(),
            Some(format!("{}:{seen}", &sha1[5..]).as_str()),
            "the recorded line is not the one for this hash"
        );
        let checked = long_date(evidence["checked"].as_str().expect("a date")).expect("a date");
        assert_eq!(
            breached_seen_in(BREACHED_EVIDENCE).expect("the evidence file is sound"),
            format!(
                "{} times when last checked, on {checked}",
                with_commas(seen)
            )
        );
    }

    #[test]
    fn a_broken_breached_password_record_leaves_v6_2_12_not_assessed_and_does_not_stop_the_run() {
        // The control: with the file as shipped, each answer is judged.
        let judged = |accepted, control, evidence: &str| {
            let mut out = Outcome::default();
            judge_breached(accepted, control, evidence, &mut out);
            out
        };
        let sound = judged(true, true, BREACHED_EVIDENCE);
        assert_eq!(sound.findings.len(), 1, "{sound:?}");
        assert!(
            sound.findings[0]
                .description
                .contains("times when last checked"),
            "{sound:?}"
        );
        assert_eq!(judged(false, true, BREACHED_EVIDENCE).verified.len(), 1);
        assert_eq!(
            judged(false, false, BREACHED_EVIDENCE).not_assessed.len(),
            1
        );

        let good: serde_json::Value = serde_json::from_str(BREACHED_EVIDENCE).unwrap();
        let with = |key: &str, value: serde_json::Value| {
            let mut broken = good.clone();
            broken[key] = value;
            broken.to_string()
        };
        for (broken, says) in [
            ("{ not json".to_owned(), "not readable JSON"),
            (with("password", "hunter2".into()), "another password"),
            (with("seen", "many".into()), "no count"),
            (with("checked", "26/09/2026".into()), "no date"),
        ] {
            for (accepted, control) in [(true, true), (true, false), (false, true), (false, false)]
            {
                let out = judged(accepted, control, &broken);
                assert!(
                    out.findings.is_empty() && out.verified.is_empty(),
                    "{says}: {out:?}"
                );
                assert_eq!(out.not_assessed.len(), 1, "{says}: {out:?}");
                let (id, why) = &out.not_assessed[0];
                assert_eq!(id, "V6.2.12");
                assert!(
                    why.contains(says) && why.contains("breached-password-evidence.json"),
                    "{says}: {why}"
                );
            }
        }
    }

    #[test]
    fn the_evidence_reader_says_what_is_wrong_with_the_file() {
        assert!(breached_seen_in(BREACHED_EVIDENCE).is_ok());
        let sound =
            format!(r#"{{"password": "{BREACHED}", "seen": 1234567, "checked": "2027-01-05"}}"#);
        assert_eq!(
            breached_seen_in(&sound).as_deref(),
            Ok("1,234,567 times when last checked, on 5 January 2027")
        );
        for (broken, says) in [
            (sound.replace(BREACHED, "letmein"), "another password"),
            (sound.replace("1234567", "-4"), "no count"),
            (sound.replace("\"seen\"", "\"count\""), "no count"),
            (sound.replace("2027-01-05", "yesterday"), "no date"),
            (sound.replace('}', ""), "not readable JSON"),
        ] {
            let wrong = breached_seen_in(&broken).expect_err(&broken);
            assert!(wrong.contains(says), "{broken}: {wrong}");
        }
    }

    #[test]
    fn dates_and_counts_are_written_out_for_a_person() {
        assert_eq!(
            long_date("2026-09-26").as_deref(),
            Some("26 September 2026")
        );
        assert_eq!(long_date("2027-01-05").as_deref(), Some("5 January 2027"));
        for bad in [
            "2026-13-01",
            "2026-00-10",
            "2026-09-32",
            "26-09-2026",
            "2026-9-26",
            "",
        ] {
            assert_eq!(long_date(bad), None, "{bad:?}");
        }
        assert_eq!(with_commas(133_732), "133,732");
        assert_eq!(with_commas(1_000), "1,000");
        assert_eq!(with_commas(999), "999");
    }

    #[test]
    fn the_control_has_the_same_shape_and_none_of_the_characters() {
        let spare = "0123456789abcdef0123456789abcdef";
        let twin = random_like(BREACHED, spare);
        assert_eq!(twin.len(), BREACHED.len());
        for (a, b) in BREACHED.chars().zip(twin.chars()) {
            assert_eq!(
                a.is_ascii_digit(),
                b.is_ascii_digit(),
                "{BREACHED} / {twin}"
            );
            assert_eq!(
                a.is_ascii_lowercase(),
                b.is_ascii_lowercase(),
                "{BREACHED} / {twin}"
            );
        }
        assert_ne!(twin, BREACHED);
        assert!(!twin.contains(CONTEXT_WORD));
    }

    #[test]
    fn the_context_password_is_the_word_repeated_past_any_length_rule() {
        let (word, password) = context_password(&["Hi".into(), "Acme Notes".into()]).unwrap();
        assert_eq!(word, "Acme Notes", "the first word long enough, as written");
        assert_eq!(password, "acmenotesacmenotes");
        assert!(password.len() >= 16);
        assert_eq!(context_password(&["ab".into()]), None);
        assert_eq!(context_password(&[]), None);
    }

    #[test]
    fn a_long_minimum_leaves_the_common_password_check_unanswerable_too() {
        // A second way the random password beside the common one is refused: it is shorter than
        // the app allows. The common one's refusal then says nothing about a list of passwords.
        let o = run_signing_up(Flaws {
            long_minimum: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        assert!(!verified_ids(&o).contains(&COMMON_PASSWORD.rule_id));
        assert!(o.not_assessed.iter().any(|(ids, _)| ids == "V6.2.4"));
        // The rules it can answer, it still does.
        assert!(verified_ids(&o).contains(&SHORT_PASSWORD.rule_id));
    }

    #[test]
    fn a_sign_up_that_makes_no_account_asks_no_password_question_either() {
        // It answers as if it worked. Only signing in shows it did not.
        let mut u = with_signup();
        u.seed = Some("seed".into());
        let o = run_against(
            Flaws {
                signup_does_nothing: true,
                ..Default::default()
            },
            &u,
        );
        for id in [
            SHORT_PASSWORD.rule_id,
            COMMON_PASSWORD.rule_id,
            COMPOSITION_RULES.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&id), "{id} credited");
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.2.1") && why.contains("strong password"))
        );
    }

    #[test]
    fn beside_seed_a_common_password_accepted_is_found() {
        let mut u = with_signup();
        u.seed = Some("seed".into());
        let o = run_against(
            Flaws {
                common_password_ok: true,
                ..Default::default()
            },
            &u,
        );
        assert_eq!(rule_ids(&o), vec![COMMON_PASSWORD.rule_id], "{:?}", o.steps);
    }

    #[test]
    fn two_answers_differing_only_in_what_every_answer_changes_are_the_same_shape() {
        let a = same_shape(
            "<input value=\"9f86d081884c7d659a2f\">If a@x.test has an account",
            "a@x.test",
        );
        let b = same_shape(
            "<input value='0c55ad0159f86d081884'>If nobody@x.test has an account",
            "nobody@x.test",
        );
        assert_eq!(a, b);
        let c = same_shape("There is no account for nobody%40x.test", "nobody@x.test");
        let d = same_shape("There is no account for a@x.test", "a@x.test");
        assert_eq!(c, d);
        assert_ne!(a, c);
    }

    #[test]
    fn a_status_is_judged_only_when_two_requests_for_the_same_account_agree() {
        let answer = |status: u16| {
            Some(ProbeResponse {
                id: String::new(),
                status,
                headers: Vec::new(),
                body: "no".to_owned(),
            })
        };
        let judged = |first: u16, second: u16, stranger: u16| {
            let mut out = Outcome::default();
            reveals_account_check(
                [&answer(first), &answer(second), &answer(stranger)],
                "a@x.test",
                "n@x.test",
                "/login",
                &RESET_REQUEST,
                &mut out,
            );
            out.findings.len()
        };
        // The pair agrees and the address with no account is answered otherwise: told apart.
        assert_eq!(judged(403, 403, 404), 1);
        // The pair disagrees with itself, so a third status that differs shows nothing.
        assert_eq!(judged(403, 401, 404), 0);
    }

    #[test]
    fn wording_is_judged_only_when_two_requests_for_the_same_account_agree() {
        let answer = |status: u16, body: &str| {
            Some(ProbeResponse {
                id: String::new(),
                status,
                headers: Vec::new(),
                body: body.to_owned(),
            })
        };
        let judged = |first: &Option<ProbeResponse>, second: &Option<ProbeResponse>| {
            let stranger = answer(200, "Sent. Ticket 9.");
            let mut out = Outcome::default();
            reveals_account_check(
                [first, second, &stranger],
                "a@x.test",
                "n@x.test",
                "/forgot",
                &RESET_REQUEST,
                &mut out,
            );
            out.findings.len()
        };
        // The pair disagrees with itself, so a third answer that differs shows nothing.
        assert_eq!(
            judged(
                &answer(200, "Sent. Ticket 7."),
                &answer(200, "Sent. Ticket 8.")
            ),
            0
        );
        // The pair agrees, and the third answer does not.
        assert_eq!(
            judged(
                &answer(200, "Sent. Ticket 7."),
                &answer(200, "Sent. Ticket 7.")
            ),
            1
        );
    }

    /// The account's sign-up run against `app`, which may have settings of its own.
    fn run_app(http: &mut dyn Http) -> Outcome {
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        run(http, &with_signup(), &acc, false, &Default::default())
    }

    fn not_assessed_for<'a>(o: &'a Outcome, ids: &str) -> Vec<&'a str> {
        o.not_assessed
            .iter()
            .filter(|(i, _)| i == ids)
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn a_correct_change_ends_the_other_sessions_and_emails_the_account_holder() {
        let o = run_signing_up(Flaws::default());
        for rule in [&CHANGE_ENDS_SESSIONS, &CHANGE_NOTIFIED] {
            assert!(
                verified_ids(&o).contains(&rule.rule_id),
                "{}: {:?}",
                rule.rule_id,
                o.steps
            );
            assert!(!rule_ids(&o).contains(&rule.rule_id));
        }
        assert!(
            not_assessed_for(&o, "V7.4.3").is_empty(),
            "{:?}",
            o.not_assessed
        );
        assert!(
            not_assessed_for(&o, "V6.3.7").is_empty(),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn other_sessions_left_open_are_asked_about_never_found_or_credited() {
        // V7.4.3 lets the app offer to end them instead, and an offer cannot be seen from here.
        let o = run_signing_up(Flaws {
            change_keeps_sessions: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&CHANGE_ENDS_SESSIONS.rule_id));
        assert!(!rule_ids(&o).contains(&CHANGE_ENDS_SESSIONS.rule_id));
        let why = not_assessed_for(&o, "V7.4.3");
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(why[0].contains("kept working"), "{}", why[0]);
        assert!(
            why[0].contains("offers to end the other sessions"),
            "{}",
            why[0]
        );
        // The email is its own question, answered as before.
        assert!(verified_ids(&o).contains(&CHANGE_NOTIFIED.rule_id));
    }

    #[test]
    fn no_email_after_a_change_is_asked_about_never_found_or_credited() {
        let o = run_signing_up(Flaws {
            change_sends_no_email: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&CHANGE_NOTIFIED.rule_id));
        assert!(!rule_ids(&o).contains(&CHANGE_NOTIFIED.rule_id));
        let why = not_assessed_for(&o, "V6.3.7");
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(why[0].contains("No email reached"), "{}", why[0]);
        assert!(verified_ids(&o).contains(&CHANGE_ENDS_SESSIONS.rule_id));
    }

    /// The fake app with no mail server to read.
    struct NoMail(FakeApp);

    impl Http for NoMail {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            self.0.send(r)
        }
        fn now(&mut self) -> u64 {
            self.0.now()
        }
        fn wait(&mut self, seconds: u64) {
            self.0.wait(seconds);
        }
    }

    #[test]
    fn with_no_mail_server_the_email_is_not_assessed() {
        let mut http = NoMail(FakeApp::new(Flaws::default()));
        let o = run_app(&mut http);
        // The change itself was checked: the rest of it is credited.
        assert!(
            verified_ids(&o).contains(&CHANGE_ENDS_SESSIONS.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&CHANGE_NOTIFIED.rule_id));
        let why = not_assessed_for(&o, "V6.3.7");
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(why[0].contains("no mail server"), "{}", why[0]);
        // The app did send it: only the reading was missing.
        assert!(
            http.0
                .outbox
                .iter()
                .any(|(_, text)| text.contains("Your password was changed")),
            "{:?}",
            http.0.outbox
        );
    }

    #[test]
    fn an_app_with_one_session_per_account_is_not_credited_for_ending_them_on_a_change() {
        // Signing in to make the change already ends the second session, so its being shut
        // afterwards says nothing about the change.
        let mut app = FakeApp::new(Flaws {
            change_keeps_sessions: true,
            ..Default::default()
        });
        app.one_session_per_user = true;
        let o = run_app(&mut app);
        assert!(
            app.clock_log.iter().any(|(id, _)| id == "bystander-before"),
            "the second session was asked about"
        );
        assert!(!verified_ids(&o).contains(&CHANGE_ENDS_SESSIONS.rule_id));
        let why = not_assessed_for(&o, "V7.4.3");
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(why[0].contains("could not be shown"), "{}", why[0]);
    }

    #[test]
    fn a_change_taken_with_a_wrong_current_password_leaves_both_questions_open() {
        let o = run_signing_up(Flaws {
            change_without_current: true,
            ..Default::default()
        });
        for rule in [&CHANGE_ENDS_SESSIONS, &CHANGE_NOTIFIED] {
            assert!(!verified_ids(&o).contains(&rule.rule_id));
        }
        let why = not_assessed_for(&o, "V7.4.3, V6.3.7");
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(why[0].contains("wrong current password"), "{}", why[0]);
    }

    // -------------------------------------------------------------------------------------------
    // A sign-up that tells which accounts exist (V6.3.8)
    // -------------------------------------------------------------------------------------------

    fn reveals(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| id.ends_with("-reveals-account"))
            .collect()
    }

    #[test]
    fn a_sign_up_that_answers_alike_is_compared_and_not_reported() {
        let o = run_signing_up(Flaws::default());
        assert_eq!(reveals(&o), Vec::<&str>::new(), "{:?}", o.steps);
        assert!(!verified_ids(&o).contains(&SIGNUP_REVEALS_ACCOUNT.rule_id));
        // Setup: the account was made and the three sign-ups answered, so the quiet means something.
        assert!(
            o.steps.iter().any(|s| s
                == "signed up with an address that has an account, taken.a@example.test, twice \
                    (303, 303) and with one that has none (303)"),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_sign_up_that_tells_which_accounts_exist_is_found_either_way_it_does() {
        for flaws in [
            Flaws {
                signup_reveals_by_status: true,
                ..Default::default()
            },
            Flaws {
                signup_reveals_by_words: true,
                ..Default::default()
            },
        ] {
            let o = run_signing_up(flaws);
            assert_eq!(
                reveals(&o),
                vec![SIGNUP_REVEALS_ACCOUNT.rule_id],
                "{:?}",
                o.steps
            );
            let f = o
                .findings
                .iter()
                .find(|f| f.rule_id == SIGNUP_REVEALS_ACCOUNT.rule_id)
                .unwrap();
            assert!(
                f.description.starts_with("A sign-up to /signup"),
                "{}",
                f.description
            );
        }
    }

    #[test]
    fn with_no_sign_up_the_check_does_not_run() {
        let o = run_against(
            Flaws {
                signup_reveals_by_status: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            !o.steps
                .iter()
                .any(|s| s.starts_with("signed up with an address"))
        );
        assert!(!rule_ids(&o).contains(&SIGNUP_REVEALS_ACCOUNT.rule_id));
    }

    /// The fake app, with the one request named answered as a limit refusing it (429).
    struct LimitedOnce {
        app: FakeApp,
        refuse: &'static str,
    }

    impl Http for LimitedOnce {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            if r.id == self.refuse {
                return Some(ProbeResponse {
                    id: r.id.clone(),
                    status: 429,
                    headers: Vec::new(),
                    body: "too many sign-ups".into(),
                });
            }
            self.app.send(r)
        }
        fn now(&mut self) -> u64 {
            self.app.now()
        }
        fn wait(&mut self, seconds: u64) {
            self.app.wait(seconds);
        }
    }

    #[test]
    fn one_sign_up_refused_as_too_many_is_not_read_as_an_account_told_apart() {
        let mut http = LimitedOnce {
            app: FakeApp::new(Flaws::default()),
            refuse: "signup-reveal-nobody",
        };
        let mut out = Outcome::default();
        signup_reveals_account_check(&mut http, &with_signup(), &accounts(), &mut out);
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert_eq!(
            out.steps,
            vec![
                "signed up with an address that has an account, taken.a@example.test, twice (303, \
                 303) and with one that has none (429): not compared, since a sign-up was refused as \
                 too many or not answered"
                    .to_owned()
            ]
        );
    }
}
