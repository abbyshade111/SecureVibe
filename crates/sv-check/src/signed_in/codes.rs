use super::*;

/// A forgotten-password reset, followed through the email it sends (V6.4.3, V6.3.8).
///
/// The run gives the app a mail server that keeps what it is sent, and this reads it as the
/// account's owner would. The setup is shown to work before anything is judged: the email has to
/// arrive, a code has to be found in it, and using that code has to set a password that then signs
/// in. Only then is the same code tried again, the old password tried, and the code's length read.
///
/// Only ever findings. V6.4.3 also asks that a reset does not get round two-factor sign-in, and a
/// safe reset expires; neither is tried here, so a clean run credits nothing and says so.
pub(super) fn reset_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.4.3, V6.3.8";
    let Some(reset) = &users.reset else {
        out.not_assessed.push((
            IDS.to_owned(),
            "How a forgotten password is reset: securevibe.toml sets no `reset` under \
             [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let patterns = match code_patterns(reset.code_pattern.as_deref(), "reset") {
        Ok(p) => p,
        Err(e) => {
            out.not_assessed.push((
                IDS.to_owned(),
                format!("`reset.code-pattern` in securevibe.toml cannot be used: {e}."),
            ));
            return;
        }
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "How a forgotten password is reset: telling whether a reset worked needs a private page \
             a signed-in user alone can open, and none was shown."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    // Never A, whose password the checks before this rely on. B when there is no sign-up: nothing
    // after this signs B in.
    let account = match &users.signup {
        Some(signup) => {
            let account = Account {
                user: format!("reset.{}", accounts.a.user),
                password: format!("Re-{}-aZ9!", &spare[5..29]),
            };
            sign_up(http, users, signup, "reset", &account);
            account
        }
        None => accounts.b.clone(),
    };
    let Some(before) = http.mail(&account.user, 0) else {
        out.not_assessed.push((
            IDS.to_owned(),
            "How a forgotten password is reset: the run had no mail server for the app to send to, \
             so there was no email to follow."
                .to_owned(),
        ));
        return;
    };
    if !account_works(http, users, "reset", &account, confirm, &mut out.steps) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "How a forgotten password is reset: the account used for it, {}, could not sign in \
                 to begin with.",
                account.user
            ),
        ));
        return;
    }

    // Two requests for the account and one for an address nobody has: the pair shows what varies
    // between two identical requests, so that only a difference beyond it is held against the app.
    let ask = |http: &mut dyn Http, user: &str, label: &str| {
        let values = Values {
            user,
            ..Default::default()
        };
        let mut session = Session::default();
        send_template(
            http,
            &format!("reset-request-{label}"),
            &reset.request,
            &values,
            &mut session,
            &[],
        )
        .0
    };
    let first = ask(http, &account.user, "1");
    let second = ask(http, &account.user, "2");
    let nobody = format!("nobody-{}@example.test", &spare[..12]);
    let stranger = ask(http, &nobody, "nobody");
    out.steps.push(format!(
        "asked for a password reset for {} twice ({}, {}) and for an address with no account ({})",
        account.user,
        status(&first),
        status(&second),
        status(&stranger)
    ));
    reveals_account_check(
        [&first, &second, &stranger],
        &account.user,
        &nobody,
        &reset.request.path,
        out,
    );

    let mail = http
        .mail(&account.user, before.len() + 2)
        .unwrap_or_default();
    let arrived: Vec<&String> = mail.iter().skip(before.len()).collect();
    out.steps.push(format!(
        "{} email{} arrived for {}",
        arrived.len(),
        if arrived.len() == 1 { "" } else { "s" },
        account.user
    ));
    if arrived.is_empty() {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Asked for a password reset, the app sent no email to {} at the run's mail server. \
                 The app is told where that is in SMTP_HOST and SMTP_PORT; check that it reads them, \
                 and check `reset.request` in securevibe.toml.",
                account.user
            ),
        ));
        return;
    }
    let codes: Vec<String> = arrived
        .iter()
        .filter_map(|m| reset_code(m, &patterns))
        .collect();
    // The newest: an app that cancels an earlier code when a new one is asked for is right to.
    let Some(code) = codes.last().cloned() else {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "The reset email arrived and no code was found in it{}. Set `reset.code-pattern` in \
                 securevibe.toml to a pattern whose first group is the code.",
                if reset.code_pattern.is_some() {
                    " with `reset.code-pattern`"
                } else {
                    " as a link's `token`, `code`, or `key`"
                }
            ),
        ));
        return;
    };
    reset_code_check(&codes, out);

    let set = |http: &mut dyn Http, new: &str, label: &str| {
        let values = Values {
            user: &account.user,
            code: &code,
            new_password: new,
            ..Default::default()
        };
        let mut session = Session::default();
        send_template(
            http,
            &format!("reset-use-{label}"),
            &reset.use_code,
            &values,
            &mut session,
            &[],
        )
        .0
    };
    let with = |password: &str| Account {
        user: account.user.clone(),
        password: password.to_owned(),
    };
    let first_new = format!("R1-{}-aZ9!", &spare[7..31]);
    let second_new = format!("R2-{}-aZ9!", &spare[1..25]);

    let answer = set(http, &first_new, "1");
    out.steps.push(format!(
        "used the code from the email to set a new password ({})",
        status(&answer)
    ));
    let reset_worked = account_works(
        http,
        users,
        "reset-new",
        &with(&first_new),
        confirm,
        &mut out.steps,
    );
    out.steps.push(format!(
        "the password the reset set {}",
        if reset_worked {
            "signed in"
        } else {
            "did not sign in"
        }
    ));
    if !reset_worked {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Using the code from the reset email through {} did not change the password: the \
                 new password did not sign in. Check `reset.use` and `reset.code-pattern` in \
                 securevibe.toml. With no reset that works, a refused one shows nothing.",
                reset.use_code.path
            ),
        ));
        return;
    }
    let old_works = account_works(http, users, "reset-old", &account, confirm, &mut out.steps);
    out.steps.push(format!(
        "the password from before the reset {}",
        if old_works {
            "still signed in"
        } else {
            "was refused"
        }
    ));
    if old_works {
        out.findings.push(finding(
            &RESET_KEEPS_OLD,
            "The old password still works after a reset",
            Severity::High,
            format!(
                "After a reset through {}, both the new password and the old one signed in.",
                reset.use_code.path
            ),
        ));
    }
    let again = set(http, &second_new, "2");
    out.steps.push(format!(
        "used the same code from the email a second time ({})",
        status(&again)
    ));
    let reused = account_works(
        http,
        users,
        "reset-again",
        &with(&second_new),
        confirm,
        &mut out.steps,
    );
    out.steps.push(format!(
        "the password the used code tried to set {}",
        if reused { "signed in" } else { "was refused" }
    ));
    if reused {
        out.findings.push(finding(
            &RESET_REUSABLE,
            "A password reset link works more than once",
            Severity::High,
            format!(
                "The code from one reset email set the password twice through {}: after it had \
                 been used, it set another new password, which then signed in.",
                reset.use_code.path
            ),
        ));
    }
    out.not_assessed.push((
        "V6.4.3".to_owned(),
        "Two parts of a safe password reset were not tried: whether a reset code stops working \
         after a while, which would mean waiting, and whether a reset gets round two-factor \
         sign-in, which needs an account that has it."
            .to_owned(),
    ));
}

/// Signing in with a code the app emails, followed through the mail server (V6.5.1, V6.5.4,
/// V6.6.2). V6.6.3, guessing, is `email_code_guessing`, which runs last of all.
///
/// Every code is asked for and used in a session of its own, as a browser would, since a code tied
/// to the session that asked for it is exactly what V6.6.2 wants. The setup is shown to work first:
/// a code used where it was asked for signs in, which the private page confirms.
pub(super) fn email_code_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.5.1, V6.5.4, V6.6.2, V6.6.3";
    let Some(flow) = EmailCode::start(http, users, accounts, confirm, IDS, out) else {
        return;
    };

    // 1. A code, used where it was asked for: the setup proof.
    let mut first = Session::default();
    let code = match flow.ask(http, &mut first, "1", out) {
        Ok(code) => code,
        Err(why) => {
            out.not_assessed.push((IDS.to_owned(), why));
            return;
        }
    };
    if !flow.signs_in(http, &code, &mut first, "1", out) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Using the emailed code through {} in the session that asked for it did not open \
                 {}: check `email-code` in securevibe.toml. With no code that works, a refused one \
                 shows nothing.",
                flow.entry.use_code.path, flow.confirm
            ),
        ));
        return;
    }
    let mut codes = vec![code.clone()];

    // 2. Two sessions each ask for a code; the first session's code is used in the second
    //    (V6.6.2). Then the second session's own code, so a refusal is known to be about the code.
    //    Before the second use of a code, because what a refused second use means depends on it.
    let mut asked_one = Session::default();
    let mut asked_two = Session::default();
    let (one, two) = match (
        flow.ask(http, &mut asked_one, "2", out),
        flow.ask(http, &mut asked_two, "3", out),
    ) {
        (Ok(one), Ok(two)) => (one, two),
        (Err(why), _) | (_, Err(why)) => {
            email_code_short_check(&codes, out);
            out.not_assessed.push(("V6.6.2, V6.5.1".to_owned(), why));
            return;
        }
    };
    codes.extend([one.clone(), two.clone()]);
    email_code_short_check(&codes, out);
    let crossed = flow.signs_in(http, &one, &mut asked_two, "crossed", out);
    let bound = if crossed {
        out.findings.push(finding(
            &EMAIL_CODE_UNBOUND,
            "An emailed sign-in code works for a sign-in it was not sent for",
            Severity::Medium,
            format!(
                "Two sign-ins were started in separate sessions. The code sent for the first, used \
                 through {} in the second, signed the second one in.",
                flow.entry.use_code.path
            ),
        ));
        Some(false)
    } else if flow.signs_in(http, &two, &mut asked_two, "own", out) {
        out.verified.push(crate::Verified::new(
            EMAIL_CODE_UNBOUND.rule_id,
            EMAIL_CODE_UNBOUND.requirement_ids,
            format!(
                "a code sent for one sign-in, refused through {} in another session, where that \
                 session's own code then signed in",
                flow.entry.use_code.path
            ),
        ));
        Some(true)
    } else {
        out.not_assessed.push((
            "V6.6.2".to_owned(),
            "A code used in a session that did not ask for it was refused, and so was that \
             session's own code afterwards, so the refusal cannot be said to be about the code."
                .to_owned(),
        ));
        None
    };

    // 3. The first code again, already used, from a new session (V6.5.1). Signing in is a finding
    //    whatever else is true. A refusal is credited only where codes were shown to work outside
    //    the session that asked: a code tied to its session would be refused in a new one used or
    //    not, and the session it belonged to is the one its first use signed in.
    let mut again = Session::default();
    if flow.signs_in(http, &code, &mut again, "again", out) {
        out.findings.push(finding(
            &EMAIL_CODE_REUSABLE,
            "An emailed sign-in code works more than once",
            Severity::High,
            format!(
                "The code from one sign-in email signed in twice through {}: once where it was \
                 asked for, and again in a new session after it had been used.",
                flow.entry.use_code.path
            ),
        ));
    } else if bound == Some(false) {
        out.verified.push(crate::Verified::new(
            EMAIL_CODE_REUSABLE.rule_id,
            EMAIL_CODE_REUSABLE.requirement_ids,
            format!(
                "an emailed sign-in code through {}, which signed in once and was refused the \
                 second time, where an unused code worked from any session",
                flow.entry.use_code.path
            ),
        ));
    } else {
        out.not_assessed.push((
            "V6.5.1".to_owned(),
            "Whether an emailed code works twice: a used code was refused in a new session, but \
             codes here are tied to the session that asked for them, so it would have been \
             refused there unused too, and the session it belonged to is already signed in."
                .to_owned(),
        ));
    }
}

/// How long an emailed sign-in code lasts (V6.5.5): at most ten minutes. Only with `--slow`.
///
/// A code is asked for, and its session kept busy while ten minutes pass — a code tied to a session
/// that ended for being idle would be refused for that, not for its age. Then the code is used
/// there. Signing in is a finding. A refusal is credited only when a code asked for then, in a new
/// session, signs in at once: that is what shows the old one was refused for being old.
pub(super) fn email_code_lifetime(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    slow: bool,
    out: &mut Outcome,
) {
    const ID: &str = "V6.5.5";
    /// Ten minutes, the most V6.5.5 allows, and a few seconds more.
    const LATE: u64 = 10 * 60 + 5;
    if users.email_code.is_none() {
        return;
    }
    if !slow {
        out.not_assessed.push((
            ID.to_owned(),
            "How long an emailed sign-in code keeps working: that means waiting ten minutes, so it \
             is asked only by `sv run --slow`."
                .to_owned(),
        ));
        return;
    }
    // Quietly: the checks above already said why, if the flow cannot be started.
    let mut quiet = Outcome::default();
    let Some(flow) = EmailCode::start(http, users, accounts, confirm, ID, &mut quiet) else {
        out.not_assessed.push((
            ID.to_owned(),
            "How long an emailed sign-in code keeps working: the sign-in by emailed code could not \
             be started, as said above."
                .to_owned(),
        ));
        return;
    };
    let mut asked = Session::default();
    let asked_at = http.now();
    let code = match flow.ask(http, &mut asked, "old", out) {
        Ok(code) => code,
        Err(why) => {
            out.not_assessed.push((ID.to_owned(), why));
            return;
        }
    };
    // Kept busy, a page request every two minutes, so the session outlives the wait.
    while http.now() < asked_at + LATE {
        let left = asked_at + LATE - http.now();
        http.wait(left.min(120));
        http.send(&get(
            "email-code-keep-busy",
            &flow.entry.use_code.path,
            &asked,
        ));
    }
    let late = flow.signs_in(http, &code, &mut asked, "late", out);
    let waited = http.now().saturating_sub(asked_at);
    let after = format!("{} minutes {} seconds", waited / 60, waited % 60);
    if late {
        out.findings.push(finding(
            &EMAIL_CODE_LONG_LIVED,
            "An emailed sign-in code still works after ten minutes",
            Severity::Medium,
            format!(
                "A code asked for through {} was used through {} {after} later, in the session \
                 that asked for it, and signed in.",
                flow.entry.request.path, flow.entry.use_code.path
            ),
        ));
        return;
    }
    let mut fresh = Session::default();
    let control = match flow.ask(http, &mut fresh, "fresh", out) {
        Ok(new) => flow.signs_in(http, &new, &mut fresh, "fresh", out),
        Err(_) => false,
    };
    out.steps.push(format!(
        "an emailed code used {after} after it was asked for: refused; a code asked for then {}",
        if control {
            "signed in"
        } else {
            "did not sign in either"
        }
    ));
    if control {
        out.verified.push(crate::Verified::new(
            EMAIL_CODE_LONG_LIVED.rule_id,
            EMAIL_CODE_LONG_LIVED.requirement_ids,
            format!(
                "an emailed sign-in code refused through {} {after} after it was asked for, in a \
                 session kept in use, where a code asked for then signed in",
                flow.entry.use_code.path
            ),
        ));
    } else {
        out.not_assessed.push((
            ID.to_owned(),
            format!(
                "How long an emailed sign-in code keeps working: a code used {after} after it was \
                 asked for was refused, and so was one asked for and used straight away then, so \
                 the refusal cannot be said to be about its age."
            ),
        ));
    }
}

/// Wrong emailed codes, one more than the owner says the app allows, then the right one (V6.6.3).
///
/// Run after everything else, the password guessing included, for the same reason: it sets out to
/// make the app refuse requests. The app is held to pushing back in any way — refusing the right
/// code afterwards, or answering the wrong ones differently or slowly — as the password check does.
pub(super) fn email_code_guessing(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    policy: &sv_manifest::PolicySection,
    out: &mut Outcome,
) {
    const MOST_ATTEMPTS: u32 = 25;
    if users.email_code.is_none() {
        return;
    }
    let Some(allowed) = policy
        .failed_codes
        .filter(|n| (1..MOST_ATTEMPTS).contains(n))
    else {
        out.not_assessed.push((
            "V6.6.3".to_owned(),
            match policy.failed_codes {
                None => {
                    "Whether emailed sign-in codes can be guessed: say how many wrong codes in \
                         a row the app should allow, as `failed-codes` under [policy] in \
                         securevibe.toml, and this will make one more attempt than that."
                        .to_owned()
                }
                Some(n) => format!(
                    "[policy] failed-codes is {n}; this check makes between 2 and {MOST_ATTEMPTS} \
                     attempts, so it cannot hold the app to that number."
                ),
            },
        ));
        return;
    };
    // Quietly: the checks above already said why, if the flow cannot be started.
    let mut quiet = Outcome::default();
    let Some(flow) = EmailCode::start(http, users, accounts, confirm, "V6.6.3", &mut quiet) else {
        out.not_assessed.push((
            "V6.6.3".to_owned(),
            "Whether emailed sign-in codes can be guessed: the sign-in by emailed code could not \
             be started, as said above."
                .to_owned(),
        ));
        return;
    };
    // First, that a code works at all here, in a session of its own. Otherwise the right code
    // refused after the guesses — the strongest sign of pushing back — would be credited for an
    // app whose codes never sign anybody in. Found by the seeded fixture's witness.
    let mut proof = Session::default();
    let works = match flow.ask(http, &mut proof, "guess-proof", out) {
        Ok(code) => flow.signs_in(http, &code, &mut proof, "guess-proof", out),
        Err(_) => false,
    };
    if !works {
        out.not_assessed.push((
            "V6.6.3".to_owned(),
            "Whether emailed sign-in codes can be guessed: a code asked for and used in the same \
             session did not sign in, so a right code refused after wrong ones would show nothing."
                .to_owned(),
        ));
        return;
    }
    let mut session = Session::default();
    let code = match flow.ask(http, &mut session, "guessed", out) {
        Ok(code) => code,
        Err(why) => {
            out.not_assessed.push(("V6.6.3".to_owned(), why));
            return;
        }
    };
    let attempts = allowed + 1;
    let mut answers: Vec<(u16, u128)> = Vec::new();
    for n in 0..attempts {
        let wrong = wrong_code(&code, n);
        let started = std::time::Instant::now();
        let response = flow.send_use(http, &wrong, &mut session, &format!("guess-{n}"));
        let elapsed = started.elapsed().as_millis();
        answers.push((response.map_or(0, |r| r.status), elapsed));
    }
    let Some(&(first_status, first_ms)) = answers.first() else {
        return;
    };
    if matches!(first_status, 0 | 423 | 429) {
        out.not_assessed.push((
            "V6.6.3".to_owned(),
            format!(
                "The app was already refusing ({first_status}) before this check made its first \
                 wrong code, most likely because of a limit an earlier check tripped, so nothing \
                 here can say whether it pushes back at {allowed}."
            ),
        ));
        return;
    }
    let last = answers.last().copied().unwrap_or((0, 0));
    let right_still_works = flow.signs_in(http, &code, &mut session, "after-guesses", out);
    let status_changed = last.0 != first_status;
    let refused = matches!(last.0, 0 | 423 | 429);
    let slowed = last.1 >= first_ms.saturating_mul(4).max(first_ms + 900);
    let how = if !right_still_works {
        "then refused the right code".to_owned()
    } else if refused {
        format!("refused the last wrong code outright ({})", last.0)
    } else if status_changed {
        format!(
            "answered the last wrong code {} where the first got {first_status}",
            last.0
        )
    } else if slowed {
        format!(
            "took {}ms over the last wrong code against {first_ms}ms",
            last.1
        )
    } else {
        String::new()
    };
    out.steps.push(format!(
        "sent {attempts} wrong emailed codes in a row, then the right one; the app {}",
        if how.is_empty() {
            "did not push back"
        } else {
            &how
        }
    ));
    if how.is_empty() {
        out.findings.push(finding(
            &EMAIL_CODE_GUESSING,
            "Emailed sign-in codes can be guessed without limit",
            Severity::High,
            format!(
                "securevibe.toml says the app should allow {allowed} wrong codes in a row. After \
                 {attempts} wrong codes through {}, each answered {first_status}, the right code \
                 still signed in.",
                flow.entry.use_code.path
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            EMAIL_CODE_GUESSING.rule_id,
            EMAIL_CODE_GUESSING.requirement_ids,
            format!(
                "{attempts} wrong emailed codes in a row, the number you stated plus one: the app \
                 {how}"
            ),
        ));
    }
}

/// A code that is certainly wrong and looks like the real one: the same length and kind of
/// character, each position moved along by a different amount.
fn wrong_code(code: &str, n: u32) -> String {
    code.chars()
        .enumerate()
        .map(|(i, c)| {
            let step = (n as usize + i) % 8 + 1;
            if c.is_ascii_digit() {
                char::from(b'0' + ((c as u8 - b'0') as usize + step) as u8 % 10)
            } else if c.is_ascii_lowercase() {
                char::from(b'a' + ((c as u8 - b'a') as usize + step) as u8 % 26)
            } else if c.is_ascii_uppercase() {
                char::from(b'A' + ((c as u8 - b'A') as usize + step) as u8 % 26)
            } else {
                c
            }
        })
        .collect()
}

/// Whether an emailed sign-in code could be guessed: too short to hold 20 bits (V6.5.4).
///
/// Only ever a finding, by `most_bits`, an upper bound: a code this calls too short is too short
/// however it was made, and a long one may still be predictable.
fn email_code_short_check(codes: &[String], out: &mut Outcome) {
    let Some(shortest) = codes.iter().min_by_key(|c| c.chars().count()) else {
        return;
    };
    let bits = most_bits(shortest);
    if bits < 19.9 {
        out.findings.push(finding(
            &EMAIL_CODE_SHORT,
            "The emailed sign-in code is short enough to guess",
            Severity::High,
            format!(
                "The code in the sign-in email is {} characters long and can hold at most {bits:.0} \
                 bits, fewer than the 20 of six random digits that ASVS asks for.",
                shortest.chars().count()
            ),
        ));
    }
}

/// The pieces every emailed-code check needs, found once.
struct EmailCode<'a> {
    entry: &'a sv_manifest::ResetSection,
    patterns: Vec<regex::Regex>,
    account: Account,
    confirm: &'a str,
}

impl<'a> EmailCode<'a> {
    /// Everything up to the first code, or `None` having said why not.
    fn start(
        http: &mut dyn Http,
        users: &'a UsersSection,
        accounts: &Accounts,
        confirm: Option<&'a str>,
        ids: &str,
        out: &mut Outcome,
    ) -> Option<Self> {
        let Some(entry) = &users.email_code else {
            out.not_assessed.push((
                ids.to_owned(),
                "Signing in with an emailed code: securevibe.toml sets no `email-code` under \
                 [stack.run.users]."
                    .to_owned(),
            ));
            return None;
        };
        let patterns = match code_patterns(
            entry.code_pattern.as_deref(),
            "login|log-in|signin|sign-in|magic|verify|auth",
        ) {
            Ok(p) => p,
            Err(e) => {
                out.not_assessed.push((
                    ids.to_owned(),
                    format!("`email-code.code-pattern` in securevibe.toml cannot be used: {e}."),
                ));
                return None;
            }
        };
        let Some(confirm) = confirm else {
            out.not_assessed.push((
                ids.to_owned(),
                "Signing in with an emailed code: telling whether it worked needs a private page a \
                 signed-in user alone can open, and none was shown."
                    .to_owned(),
            ));
            return None;
        };
        // A sign-in by code changes nothing about an account, so A will do when there is no
        // sign-up; with one, an account of its own keeps its mail apart from everything else.
        let account = match &users.signup {
            Some(signup) => {
                let spare = &accounts.spare;
                let account = Account {
                    user: format!("code.{}", accounts.a.user),
                    password: format!(
                        "Co-{}-aZ9!",
                        spare.chars().skip(4).take(24).collect::<String>()
                    ),
                };
                sign_up(http, users, signup, "code", &account);
                account
            }
            None => accounts.a.clone(),
        };
        if http.mail(&account.user, 0).is_none() {
            out.not_assessed.push((
                ids.to_owned(),
                "Signing in with an emailed code: the run had no mail server for the app to send \
                 to, so there was no email to read."
                    .to_owned(),
            ));
            return None;
        }
        Some(EmailCode {
            entry,
            patterns,
            account,
            confirm,
        })
    }

    /// Asks for a code in this session and reads it from the newest email; or says why there is
    /// none, for the caller to report against the requirements it was needed for.
    fn ask(
        &self,
        http: &mut dyn Http,
        session: &mut Session,
        label: &str,
        out: &mut Outcome,
    ) -> Result<String, String> {
        let no_sink = || "The run's mail server stopped answering.".to_owned();
        let before = http.mail(&self.account.user, 0).ok_or_else(no_sink)?.len();
        self.open_form(http, &self.entry.request.path, session, label);
        let values = Values {
            user: &self.account.user,
            ..Default::default()
        };
        let (response, _) = send_template(
            http,
            &format!("email-code-request-{label}"),
            &self.entry.request,
            &values,
            session,
            &[],
        );
        let mail = http
            .mail(&self.account.user, before + 1)
            .ok_or_else(no_sink)?;
        let code = mail
            .get(before..)
            .and_then(|new| new.last())
            .and_then(|m| reset_code(m, &self.patterns));
        out.steps.push(format!(
            "asked for a sign-in code for {} ({}): {}",
            self.account.user,
            status(&response),
            match (&code, mail.len() > before) {
                (Some(_), _) => "the email arrived with a code in it",
                (None, true) => "the email arrived with no code found in it",
                (None, false) => "no email arrived",
            }
        ));
        match (code, mail.len() > before) {
            (Some(code), _) => Ok(code),
            (None, true) => Err(
                "The sign-in email arrived and no code was found in it. Set \
                                 `email-code.code-pattern` in securevibe.toml to a pattern whose \
                                 first group is the code."
                    .to_owned(),
            ),
            (None, false) => Err(format!(
                "Asked for a sign-in code, the app sent no email to {} at the run's mail server. \
                 The app is told where that is in SMTP_HOST and SMTP_PORT; check that it reads \
                 them, and check `email-code.request` in securevibe.toml.",
                self.account.user
            )),
        }
    }

    /// Opens the form's page first in a session that has nothing yet, as a browser would. A
    /// template with no `{csrf}` sends no page request of its own, and a code asked for with no
    /// session at all cannot be tied to one: that is how the first run against a real app reported
    /// a correct one for codes that work anywhere.
    fn open_form(&self, http: &mut dyn Http, path: &str, session: &mut Session, label: &str) {
        if session.cookies.is_empty()
            && session.bearer.is_none()
            && let Some(page) = http.send(&get(&format!("email-code-page-{label}"), path, session))
        {
            session.absorb(&page);
        }
    }

    fn send_use(
        &self,
        http: &mut dyn Http,
        code: &str,
        session: &mut Session,
        label: &str,
    ) -> Option<ProbeResponse> {
        let values = Values {
            user: &self.account.user,
            code,
            ..Default::default()
        };
        send_template(
            http,
            &format!("email-code-use-{label}"),
            &self.entry.use_code,
            &values,
            session,
            &[],
        )
        .0
    }

    /// Uses a code in this session and says whether the session then opens the private page.
    fn signs_in(
        &self,
        http: &mut dyn Http,
        code: &str,
        session: &mut Session,
        label: &str,
        out: &mut Outcome,
    ) -> bool {
        self.open_form(http, &self.entry.use_code.path, session, label);
        let answer = self.send_use(http, code, session, label);
        let opened = ok(&http.send(&get(
            &format!("email-code-private-{label}"),
            self.confirm,
            session,
        )));
        out.steps.push(format!(
            "used an emailed code ({label}, {}): {}",
            status(&answer),
            if opened { "signed in" } else { "not signed in" }
        ));
        opened
    }
}

/// The activation code emailed at sign-up (V6.4.1), followed through the mail server.
///
/// Two accounts are made through `signup`, so there are two codes to compare. The setup is shown
/// to work first: the email arrives and a code is found in it; where the app refuses a sign-in
/// before activation, the code has to lift that. Then two findings are possible: a code short
/// enough to guess, or two that count up; and an activation link that signs the account in and
/// then does so again. Only ever findings: V6.4.1 also asks that a code expire after a while and
/// that an initial password never become the lasting one, which this does not try.
pub(super) fn activation_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const ID: &str = "V6.4.1";
    let Some(entry) = &users.activation else {
        return;
    };
    let say = |why: String, out: &mut Outcome| out.not_assessed.push((ID.to_owned(), why));
    let Some(signup) = &users.signup else {
        say(
            "The activation code emailed at sign-up: securevibe.toml sets `activation` and no \
             `signup`, so no account is made that would be sent one."
                .to_owned(),
            out,
        );
        return;
    };
    let Some(confirm) = confirm else {
        say(
            "The activation code emailed at sign-up: telling whether it worked needs a private \
             page a signed-in user alone can open, and none was shown."
                .to_owned(),
            out,
        );
        return;
    };
    let patterns = match code_patterns(
        entry.code_pattern.as_deref(),
        "activate|activation|verify|confirm|welcome",
    ) {
        Ok(p) => p,
        Err(e) => {
            say(
                format!("`activation.code-pattern` in securevibe.toml cannot be used: {e}."),
                out,
            );
            return;
        }
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let made: Vec<Account> = (1..=2)
        .map(|n| Account {
            user: format!("activate{n}.{}", accounts.a.user),
            password: format!("Ac{n}-{}-aZ9!", &spare[n..n + 24]),
        })
        .collect();
    if http.mail(&made[0].user, 0).is_none() {
        say(
            "The activation code emailed at sign-up: the run had no mail server for the app to \
             send to, so there was no email to read."
                .to_owned(),
            out,
        );
        return;
    }

    // Each account: signed up, its email read. Whether it could sign in before activation is
    // asked of the first only; it decides what the code has to show.
    let mut codes = Vec::new();
    let mut gated = false;
    for (n, account) in made.iter().enumerate() {
        let before = http.mail(&account.user, 0).map_or(0, |m| m.len());
        let answer = sign_up_only(http, signup, &format!("activate-{n}"), account);
        let mail = http.mail(&account.user, before + 1).unwrap_or_default();
        let code = mail
            .get(before..)
            .and_then(|new| new.last())
            .and_then(|m| reset_code(m, &patterns));
        out.steps.push(format!(
            "signed up {} ({}): {}",
            account.user,
            status(&answer),
            match (&code, mail.len() > before) {
                (Some(_), _) => "an email arrived with an activation code in it",
                (None, true) => "an email arrived with no code found in it",
                (None, false) => "no email arrived",
            }
        ));
        let Some(code) = code else {
            say(
                if mail.len() > before {
                    "The sign-up email arrived and no activation code was found in it. Set \
                     `activation.code-pattern` in securevibe.toml to a pattern whose first group \
                     is the code."
                        .to_owned()
                } else {
                    format!(
                        "Signing up {} sent no email to the run's mail server. The app is told \
                         where that is in SMTP_HOST and SMTP_PORT; check that it reads them.",
                        account.user
                    )
                },
                out,
            );
            return;
        };
        if n == 0 {
            gated = !account_works(
                http,
                users,
                "activate-before",
                account,
                confirm,
                &mut out.steps,
            );
        }
        codes.push(code);
    }

    // The code, used once in a new session: whether it activated, and whether it signed in.
    let use_code = |http: &mut dyn Http, code: &str, label: &str, session: &mut Session| {
        let values = Values {
            user: &made[0].user,
            code,
            ..Default::default()
        };
        send_template(
            http,
            &format!("activation-{label}"),
            &entry.use_code,
            &values,
            session,
            &[],
        )
        .0
    };
    let mut first = Session::default();
    let answer = use_code(http, &codes[0], "first", &mut first);
    let signed_in_by_link = ok(&http.send(&get("activation-first-private", confirm, &first)));
    let works = account_works(
        http,
        users,
        "activate-after",
        &made[0],
        confirm,
        &mut out.steps,
    );
    out.steps.push(format!(
        "used the activation code ({}): the account {}{}",
        status(&answer),
        if works {
            "then signed in"
        } else {
            "still could not sign in"
        },
        if signed_in_by_link {
            ", and the link itself signed it in"
        } else {
            ""
        }
    ));
    if gated && !works {
        say(
            format!(
                "The account could not sign in before activation and still could not after its \
                 code was used through {}: check `activation` in securevibe.toml. With no \
                 activation that works, nothing about the code can be told.",
                entry.use_code.path
            ),
            out,
        );
        return;
    }
    if !gated {
        out.steps.push(
            "the account could sign in before it was activated, so activation guards nothing \
             here that a password does not"
                .to_owned(),
        );
    }

    // Guessable: from the two codes.
    activation_code_check(&codes, out);

    // Used again: only tellable when the link signs the account in.
    if signed_in_by_link {
        let mut again = Session::default();
        use_code(http, &codes[0], "again", &mut again);
        let reused = ok(&http.send(&get("activation-again-private", confirm, &again)));
        out.steps.push(format!(
            "used the same activation code again in a new session: {}",
            if reused { "signed in" } else { "not signed in" }
        ));
        if reused {
            out.findings.push(finding(
                &ACTIVATION_REUSABLE,
                "An activation link signs its account in more than once",
                Severity::High,
                format!(
                    "The activation code sent at sign-up signed the account in through {}, and \
                     then did so again from a new session after it had been used.",
                    entry.use_code.path
                ),
            ));
        }
    }
    say(
        if signed_in_by_link {
            "Two parts of V6.4.1 were not tried: whether an activation code stops working after a \
             while, which would mean waiting, and whether a system-made initial password can \
             become the lasting one."
                .to_owned()
        } else {
            "Whether an activation code works twice: using it did not sign anybody in, so a second \
             use could not be told from the first. Not tried either: whether a code stops working \
             after a while, and whether a system-made initial password can become the lasting one."
                .to_owned()
        },
        out,
    );
}

/// Whether activation codes could be guessed: too short to hold 20 bits, or counting up.
fn activation_code_check(codes: &[String], out: &mut Outcome) {
    let Some(shortest) = codes.iter().min_by_key(|c| c.chars().count()) else {
        return;
    };
    let bits = most_bits(shortest);
    if bits < 19.9 {
        out.findings.push(finding(
            &ACTIVATION_GUESSABLE,
            "The activation code is short enough to guess",
            Severity::High,
            format!(
                "The code in the sign-up email is {} characters long and can hold at most {bits:.0} \
                 bits, fewer than the 20 of six random digits.",
                shortest.chars().count()
            ),
        ));
        return;
    }
    let numbers: Vec<u128> = codes.iter().filter_map(|c| c.parse().ok()).collect();
    if numbers.len() == codes.len()
        && let [.., earlier, later] = numbers.as_slice()
        && (1..=1000).contains(&later.abs_diff(*earlier))
    {
        out.findings.push(finding(
            &ACTIVATION_GUESSABLE,
            "Activation codes count up",
            Severity::High,
            format!(
                "Two sign-ups one after the other were sent codes {} apart: whoever has one code \
                 can work out the next.",
                later.abs_diff(*earlier)
            ),
        ));
    }
}

/// Where a code is looked for in an email: the owner's pattern, or a link's usual places, with
/// `under` naming the words a link's path goes through (`reset`, or the sign-in words).
pub(super) fn code_patterns(
    custom: Option<&str>,
    under: &str,
) -> Result<Vec<regex::Regex>, String> {
    if let Some(custom) = custom {
        let pattern = regex::Regex::new(custom).map_err(|e| e.to_string())?;
        if pattern.captures_len() < 2 {
            return Err("it has no group, `( … )`, to say which part is the code".to_owned());
        }
        return Ok(vec![pattern]);
    }
    // `;` as well as `&` before a parameter: in an HTML email a link's `&` is written `&amp;`.
    [
        r"(?i)[?&;](?:reset[_-]?|login[_-]?)?(?:token|code|key)=([A-Za-z0-9._~%-]+)".to_owned(),
        format!(
            r#"(?i)https?://[^\s"'<>]*(?:{under})[^\s"'<>?]*/([A-Za-z0-9._~-]{{8,}})(?:[\s"'<>?#]|$)"#
        ),
        // A code written out on its own: "your code is 482913", "Code: X7K2Q9".
        r"(?i)\bcode(?:\s+is)?\s*:?\s*([A-Za-z0-9]{4,12})\b".to_owned(),
    ]
    .iter()
    .map(|p| regex::Regex::new(p).map_err(|e| e.to_string()))
    .collect()
}

pub(super) fn reset_code(mail: &str, patterns: &[regex::Regex]) -> Option<String> {
    let found = patterns
        .iter()
        .find_map(|p| p.captures(mail).and_then(|c| c.get(1)))?;
    let code = percent_decode(found.as_str());
    (!code.is_empty()).then_some(code)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(b) = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a reset code could be guessed: too short to hold 20 bits, or counting up.
///
/// The floor is the one ASVS sets for codes sent out of band (V6.5.4), which names six random
/// digits as enough; a code is compared against it by `most_bits`, an upper bound, so a code this
/// calls too short is too short however it was made. A long code is credited with nothing.
fn reset_code_check(codes: &[String], out: &mut Outcome) {
    let Some(shortest) = codes.iter().min_by_key(|c| c.chars().count()) else {
        return;
    };
    let bits = most_bits(shortest);
    if bits < 19.9 {
        out.findings.push(finding(
            &RESET_CODE_GUESSABLE,
            "The password reset code is short enough to guess",
            Severity::High,
            format!(
                "The code in the reset email is {} characters long and can hold at most {bits:.0} \
                 bits, fewer than the 20 of six random digits, the least ASVS accepts for a code \
                 sent by email.",
                shortest.chars().count()
            ),
        ));
        return;
    }
    let numbers: Vec<u128> = codes.iter().filter_map(|c| c.parse().ok()).collect();
    if numbers.len() == codes.len()
        && let [.., earlier, later] = numbers.as_slice()
        && (1..=1000).contains(&later.abs_diff(*earlier))
    {
        out.findings.push(finding(
            &RESET_CODE_GUESSABLE,
            "Password reset codes count up",
            Severity::High,
            format!(
                "Two reset emails asked for one after the other carried codes {} apart: whoever has \
                 one code can work out the next.",
                later.abs_diff(*earlier)
            ),
        ));
    }
}

/// What every two-factor sign-in attempt shares: where to send the code, as whom, and the private
/// page that says whether it worked.
struct TotpSignIn<'a> {
    users: &'a UsersSection,
    entry: &'a RequestTemplate,
    account: &'a Account,
    confirm: &'a str,
}

impl TotpSignIn<'_> {
    /// Signs in with the password, then gives `code`, and says whether the private page then
    /// opened. `gate` first asks the private page between the two steps, and answers `None` when it
    /// already opened there: then the code is not what let anybody in, and nothing about codes can
    /// be told.
    fn attempt(&self, http: &mut dyn Http, code: &str, who: &str, gate: bool) -> Option<bool> {
        let mut quiet = Vec::new();
        let mut session = sign_in(http, self.users, who, self.account, &mut quiet)?.session;
        if gate && ok(&http.send(&get(&format!("totp-gate-{who}"), self.confirm, &session))) {
            return None;
        }
        let values = Values {
            user: &self.account.user,
            password: &self.account.password,
            code,
            ..Default::default()
        };
        send_template(
            http,
            &format!("totp-{who}"),
            self.entry,
            &values,
            &mut session,
            &self.users.private,
        );
        Some(ok(&http.send(&get(
            &format!("totp-confirm-{who}"),
            self.confirm,
            &session,
        ))))
    }
}

/// Whether a two-factor code works once only (V6.5.1) and only while it is current (V6.5.5).
///
/// `seed` enrolled a third account with a secret this run made, so the codes an authenticator app
/// would show are computed here. The order is the substance:
///
/// 1. **The code from five steps ago, first**, two and a half minutes old, which no clock drift
///    explains — and before any code has been used. Many apps refuse a code for any step not later
///    than the last one used, which is how they stop a code being used twice; ask for an old code
///    after a current one and that rule refuses it whatever the app thinks of its age, and an app
///    that takes ten-minute-old codes would be credited. The private page has to stay shut between
///    the password and this code, or nothing about codes can be told.
/// 2. **The current code**, which has to sign in: the control.
/// 3. **The same code again**, in a new sign-in.
/// 4. **A fresh code**, once the next step has begun, which has to sign in too. Without it, two
///    refusals in a row could be the account locking rather than the codes being refused, and
///    neither is credited.
pub(super) fn totp_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.5.1, V6.5.5";
    let Some(entry) = &users.totp else {
        return;
    };
    let Some(totp) = &accounts.totp else {
        out.not_assessed.push((
            IDS.to_owned(),
            "`totp` is set in securevibe.toml, but only `seed` can enroll an account in two-factor \
             sign-in, and there is no `seed`."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether a code signed in is told by opening a private page, and no private page was \
             shown to open for a signed-in user alone."
                .to_owned(),
        ));
        return;
    };
    let secret = &totp.secret;
    let signing = TotpSignIn {
        users,
        entry,
        account: &totp.account,
        confirm,
    };
    // Clear of the end of a step: with ten seconds or fewer left, the step can end between a code
    // being worked out and being given, and a code refused for going stale reads as a code refused
    // for being used. The rest of that risk is handled below, by looking at the clock again.
    let into = http.now() % crate::totp::STEP;
    if into + 10 >= crate::totp::STEP {
        http.wait(crate::totp::STEP - into + 1);
    }
    let step = http.now() / crate::totp::STEP;
    let current = crate::totp::code_at_step(secret, step);
    let old = crate::totp::code_at_step(secret, step.saturating_sub(5));

    // 1. The old code, before any code has been used.
    let Some(stale) = signing.attempt(http, &old, "1", true) else {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "The two-factor account opened {confirm} with its password alone, before any code \
                 was given, so what the app does with a code cannot be seen. Check that `seed` \
                 enrolled it with SV_TOTP_SECRET."
            ),
        ));
        return;
    };

    // 2. The control: the current code, then 3. the same code again, in a new sign-in. A refusal of
    //    the second is evidence only when the step it was worked out for has not ended: an app that
    //    takes the current step alone refuses a code whose step is over, used or not. So when the
    //    step has moved on and the code was refused, the pair is tried once more with the new
    //    step's code; if the step ends again, nothing is said about reuse.
    let mut current = current;
    let mut step = step;
    let mut reused = false;
    let mut unsure = false;
    for round in 0..2 {
        if !signing
            .attempt(http, &current, &format!("2-{round}"), false)
            .unwrap_or(false)
        {
            let ended = http.now() / crate::totp::STEP != step;
            out.not_assessed.push((
                IDS.to_owned(),
                if ended {
                    format!(
                        "The 30-second step ended while the current code was being given through \
                         {}, so its refusal shows nothing about the code or the setup. Run it \
                         again.",
                        entry.path
                    )
                } else {
                    format!(
                        "The current code for the secret `seed` was given did not sign the \
                         two-factor account in through {}, so a refused code shows nothing. Check \
                         `totp` in securevibe.toml, and that `seed` enrolled the account with \
                         SV_TOTP_SECRET.",
                        entry.path
                    )
                },
            ));
            return;
        }
        reused = signing.attempt(http, &current, &format!("3-{round}"), false) == Some(true);
        let now_step = http.now() / crate::totp::STEP;
        if reused || now_step == step {
            unsure = false;
            break;
        }
        unsure = true;
        step = now_step;
        current = crate::totp::code_at_step(secret, step);
    }
    out.steps.push(format!(
        "the two-factor account's code from 2½ minutes ago: {}; the current code: opened; the \
         same code again: {}",
        if stale { "opened" } else { "refused" },
        if reused { "opened" } else { "refused" }
    ));

    // 4. A fresh code, once the next step has begun.
    let into_next = crate::totp::STEP - http.now() % crate::totp::STEP + 1;
    http.wait(into_next);
    let fresh = crate::totp::code_at_step(secret, http.now() / crate::totp::STEP);
    let works = signing.attempt(http, &fresh, "4", false) == Some(true);
    out.steps.push(format!(
        "waited {into_next}s for the next step; its code: {}",
        if works { "opened" } else { "refused" }
    ));

    for (worked, rule, id, title, severity, what) in [
        (
            reused,
            &TOTP_REUSED,
            "V6.5.1",
            "A two-factor code works more than once",
            Severity::Medium,
            "the code that had just signed the account in, used again in a new sign-in",
        ),
        (
            stale,
            &TOTP_OLD_CODE,
            "V6.5.5",
            "A two-factor code still works minutes after it was shown",
            Severity::Low,
            "the code from five 30-second steps earlier, two and a half minutes old, before any \
             code had been used",
        ),
    ] {
        if worked {
            out.findings.push(finding(
                rule,
                title,
                severity,
                format!("The app signed the two-factor account in with {what}."),
            ));
        } else if id == "V6.5.1" && unsure {
            out.not_assessed.push((
                id.to_owned(),
                "The 30-second step ended between the two uses of a code, twice, so its refusal \
                 may be the code going stale rather than the app refusing a code used before."
                    .to_owned(),
            ));
        } else if works {
            out.verified.push(crate::Verified::new(
                rule.rule_id,
                rule.requirement_ids,
                if id == "V6.5.5" {
                    // What was shown is the first clause of V6.5.5, a defined lifetime; the second,
                    // at most 30 seconds, would take refusing the code from one step back, which a
                    // sensible allowance for clock drift accepts.
                    format!(
                        "{what}, refused, where a fresh code afterwards signed in: codes have a \
                         defined lifetime, shorter than two and a half minutes; that it is at most \
                         30 seconds was not shown"
                    )
                } else {
                    format!("{what}, refused, where a fresh code afterwards signed in")
                },
            ));
        } else {
            out.not_assessed.push((
                id.to_owned(),
                format!(
                    "The app refused {what}, but then refused a fresh code as well, so the refusal \
                     may be the account locking rather than the code."
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::{run_signing_up, run_with, seeded_with, with_signup};
    use super::*;

    /// Every reason given for not assessing `id`. V6.5.1 is also the emailed-code check's, whose
    /// reasons are not about two-factor codes, so a test looks through them all.
    fn totp_named(o: &Outcome, id: &str) -> Vec<String> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.split(", ").any(|i| i == id))
            // V6.5.5 is asked of emailed codes too, and those are said apart.
            .filter(|(_, why)| !why.contains("emailed sign-in code"))
            .map(|(_, why)| why.clone())
            .collect()
    }

    #[test]
    fn a_code_used_once_and_only_while_current_is_credited_for_both() {
        let o = run_against(Flaws::default(), &users());
        for rule in [&TOTP_REUSED, &TOTP_OLD_CODE] {
            assert!(!rule_ids(&o).contains(&rule.rule_id), "{:?}", o.steps);
            assert!(
                verified_ids(&o).contains(&rule.rule_id),
                "{} not credited: {:?}\n{:?}",
                rule.rule_id,
                o.steps,
                o.not_assessed
            );
        }
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("waited ") && s.ends_with("opened")),
            "the fresh code after the wait is the control, and it is not in the steps: {:?}",
            o.steps
        );
    }

    #[test]
    fn each_code_flaw_is_found_by_its_own_rule_and_the_other_is_still_credited() {
        for (flaws, found, credited) in [
            (
                Flaws {
                    totp_reusable: true,
                    ..Default::default()
                },
                &TOTP_REUSED,
                &TOTP_OLD_CODE,
            ),
            (
                Flaws {
                    totp_any_age: true,
                    ..Default::default()
                },
                &TOTP_OLD_CODE,
                &TOTP_REUSED,
            ),
        ] {
            let o = run_against(flaws, &users());
            assert!(
                rule_ids(&o).contains(&found.rule_id),
                "{}: {:?}",
                found.rule_id,
                o.steps
            );
            assert!(
                !verified_ids(&o).contains(&found.rule_id),
                "{} credited as well",
                found.rule_id
            );
            assert!(
                !rule_ids(&o).contains(&credited.rule_id),
                "{}",
                credited.rule_id
            );
            assert!(
                verified_ids(&o).contains(&credited.rule_id),
                "{}",
                credited.rule_id
            );
        }
    }

    #[test]
    fn nothing_about_codes_is_said_when_the_setup_does_not_hold() {
        // Three ways the control fails: the password alone lets the account in, no code ever
        // works, and the account locks after the first wrong code so the fresh one is refused.
        for (flaws, says) in [
            (
                Flaws {
                    totp_not_required: true,
                    ..Default::default()
                },
                "password alone",
            ),
            (
                Flaws {
                    totp_broken: true,
                    ..Default::default()
                },
                "did not sign the two-factor account in",
            ),
            (
                Flaws {
                    totp_locks: true,
                    ..Default::default()
                },
                "refused a fresh code as well",
            ),
            (
                Flaws {
                    totp_locks_at_once: true,
                    ..Default::default()
                },
                "did not sign the two-factor account in",
            ),
        ] {
            let o = run_against(flaws, &users());
            for (id, rule) in [("V6.5.1", &TOTP_REUSED), ("V6.5.5", &TOTP_OLD_CODE)] {
                assert!(
                    !verified_ids(&o).contains(&rule.rule_id),
                    "{says}: {id} credited"
                );
                assert!(!rule_ids(&o).contains(&rule.rule_id), "{says}: {id} found");
                let why = totp_named(&o, id);
                assert!(
                    why.iter().any(|w| w.contains(says)),
                    "{says}: {id}: {why:?}"
                );
            }
        }
    }

    #[test]
    fn without_seed_there_is_no_two_factor_account_and_it_says_so() {
        // Only `seed` can enroll an account, so a sign-up run has none, as the real runner does.
        let mut u = with_signup();
        u.totp = users().totp;
        let mut app = FakeApp::new(Flaws::default());
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(&mut app, &u, &acc, false, &Default::default());
        let why = totp_named(&o, "V6.5.5");
        assert!(why.iter().any(|w| w.contains("`seed`")), "{why:?}");
    }

    #[test]
    fn with_no_totp_entry_nothing_is_said_about_codes() {
        let mut u = users();
        u.totp = None;
        let o = run_against(Flaws::default(), &u);
        assert!(totp_named(&o, "V6.5.5").is_empty());
        for rule in [&TOTP_REUSED, &TOTP_OLD_CODE] {
            assert!(!verified_ids(&o).contains(&rule.rule_id));
            assert!(!rule_ids(&o).contains(&rule.rule_id));
        }
    }

    // --------------------------------------------------------------------------------------------
    // Password reset, through the mail sink

    const RESET_RULES: [&str; 4] = [
        RESET_REUSABLE.rule_id,
        RESET_KEEPS_OLD.rule_id,
        RESET_CODE_GUESSABLE.rule_id,
        RESET_REVEALS_ACCOUNT.rule_id,
    ];

    fn reset_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| RESET_RULES.contains(id))
            .collect()
    }

    fn reset_not_assessed(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.contains("V6.4.3"))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn a_reset_that_works_once_is_followed_through_and_faults_nothing() {
        let o = run_against(Flaws::default(), &users());
        assert!(reset_findings(&o).is_empty(), "{:#?}", o.findings);
        // The setup was really shown to work: the email arrived, and its code set a password
        // that then signed in. Without these the quiet above would mean nothing.
        let steps = o.steps.join("\n");
        assert!(
            steps.contains("2 emails arrived for b@example.test"),
            "{steps}"
        );
        for step in [
            "the password the reset set signed in",
            "the password from before the reset was refused",
            "the password the used code tried to set was refused",
        ] {
            assert!(steps.contains(step), "{step}:\n{steps}");
        }
        // And it credits nothing, saying what it did not try.
        assert!(!verified_ids(&o).iter().any(|id| RESET_RULES.contains(id)));
        let why = reset_not_assessed(&o);
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(why[0].contains("two-factor"), "{why:?}");
    }

    #[test]
    fn each_fault_in_a_reset_is_found_by_its_own_rule() {
        let cases: [(Flaws, &str); 6] = [
            (
                Flaws {
                    reset_reusable: true,
                    ..Default::default()
                },
                RESET_REUSABLE.rule_id,
            ),
            (
                Flaws {
                    reset_keeps_old: true,
                    ..Default::default()
                },
                RESET_KEEPS_OLD.rule_id,
            ),
            (
                Flaws {
                    reset_short_code: true,
                    ..Default::default()
                },
                RESET_CODE_GUESSABLE.rule_id,
            ),
            (
                Flaws {
                    reset_counting_codes: true,
                    ..Default::default()
                },
                RESET_CODE_GUESSABLE.rule_id,
            ),
            (
                Flaws {
                    reset_reveals_by_status: true,
                    ..Default::default()
                },
                RESET_REVEALS_ACCOUNT.rule_id,
            ),
            (
                Flaws {
                    reset_reveals_by_words: true,
                    ..Default::default()
                },
                RESET_REVEALS_ACCOUNT.rule_id,
            ),
        ];
        for (flaws, rule) in cases {
            let o = run_against(flaws, &users());
            assert_eq!(
                reset_findings(&o),
                vec![rule],
                "{rule}: {:#?}\n{:?}",
                o.findings,
                o.steps
            );
        }
    }

    #[test]
    fn a_reset_that_changes_nothing_is_not_assessed_however_else_it_is_broken() {
        // Reusable and keeping the old password, in an app whose reset does nothing at all: the
        // old password "still works" and a second use "does nothing new" for a reason that has
        // nothing to do with either, and neither may be reported off the back of it.
        let o = run_against(
            Flaws {
                reset_does_nothing: true,
                reset_reusable: true,
                reset_keeps_old: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(reset_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            reset_not_assessed(&o)
                .iter()
                .any(|w| w.contains("did not change the password")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn with_no_email_to_read_a_reset_is_not_assessed_and_says_why() {
        for (flaws, why) in [
            (
                Flaws {
                    no_mail_sink: true,
                    reset_reusable: true,
                    ..Default::default()
                },
                "no mail server",
            ),
            (
                Flaws {
                    reset_sends_nothing: true,
                    reset_reusable: true,
                    ..Default::default()
                },
                "sent no email",
            ),
            (
                Flaws {
                    reset_code_elsewhere: true,
                    reset_reusable: true,
                    ..Default::default()
                },
                "no code was found",
            ),
        ] {
            let o = run_against(flaws, &users());
            assert!(
                !reset_findings(&o).contains(&RESET_REUSABLE.rule_id),
                "{why}: {:#?}",
                o.findings
            );
            assert!(
                reset_not_assessed(&o).iter().any(|w| w.contains(why)),
                "{why}: {:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_code_pattern_finds_a_code_the_defaults_miss_and_a_broken_one_is_refused() {
        let mut u = users();
        u.reset.as_mut().unwrap().code_pattern = Some(r"reset number is ([0-9a-f]+)".into());
        let flaws = Flaws {
            reset_code_elsewhere: true,
            reset_reusable: true,
            ..Default::default()
        };
        let o = run_against(flaws, &u);
        assert_eq!(
            reset_findings(&o),
            vec![RESET_REUSABLE.rule_id],
            "{:?}",
            o.steps
        );

        u.reset.as_mut().unwrap().code_pattern = Some(r"reset number is [0-9a-f]+".into());
        let o = run_against(flaws, &u);
        assert!(reset_findings(&o).is_empty());
        assert!(
            reset_not_assessed(&o)
                .iter()
                .any(|w| w.contains("code-pattern") && w.contains("no group")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn with_a_sign_up_the_reset_uses_an_account_of_its_own() {
        let mut app = FakeApp::new(Flaws {
            reset_reusable: true,
            ..Default::default()
        });
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(&mut app, &with_signup(), &acc, false, &Default::default());
        assert_eq!(reset_findings(&o), vec![RESET_REUSABLE.rule_id]);
        assert!(
            app.outbox
                .iter()
                .filter(|(_, text)| text.contains("Reset"))
                .all(|(to, _)| to == "reset.a@example.test"),
            "only the account made for it is ever sent a reset: {:?}",
            app.outbox
        );
        // A and B keep the passwords they started with.
        assert_eq!(app.users[&acc.a.user].0, acc.a.password);
        assert_eq!(app.users[&acc.b.user].0, acc.b.password);
    }

    #[test]
    fn a_code_is_found_in_a_link_however_the_email_writes_it() {
        let p = code_patterns(None, "reset").unwrap();
        for (mail, code) in [
            ("Go to http://app/reset?token=abc123XYZ now", "abc123XYZ"),
            (
                "<a href=\"http://app/reset?uid=4&amp;token=k9%2Dz_Q\">Reset</a>",
                "k9-z_Q",
            ),
            (
                "https://app.test/password/reset/9f8e7d6c5b4a3210\r\n",
                "9f8e7d6c5b4a3210",
            ),
            ("http://app/forgot?reset_code=77aa99bb", "77aa99bb"),
        ] {
            assert_eq!(reset_code(mail, &p).as_deref(), Some(code), "{mail}");
        }
        assert_eq!(reset_code("Thanks for signing up. http://app/", &p), None);
    }

    #[test]
    fn six_random_digits_pass_and_fewer_or_counting_do_not() {
        let judged = |codes: &[&str]| {
            let mut out = Outcome::default();
            let codes: Vec<String> = codes.iter().map(|c| (*c).to_owned()).collect();
            reset_code_check(&codes, &mut out);
            out.findings.len()
        };
        assert_eq!(judged(&["482913", "117204"]), 0);
        assert_eq!(judged(&["9f86d081884c7d659a2feaa0c55ad015"]), 0);
        assert_eq!(judged(&["4829", "1172"]), 1);
        assert_eq!(judged(&["482913", "482914"]), 1);
        assert_eq!(judged(&["482913", "483913"]), 1);
        assert_eq!(judged(&["482913", "483914"]), 0);
    }

    #[test]
    fn the_same_faults_are_found_with_an_account_made_for_the_reset() {
        // The same rules through the other way of getting an account, so no rule rests on the
        // seeded fixture alone.
        for (flaws, rule) in [
            (
                Flaws {
                    reset_keeps_old: true,
                    ..Default::default()
                },
                RESET_KEEPS_OLD.rule_id,
            ),
            (
                Flaws {
                    reset_reveals_by_status: true,
                    ..Default::default()
                },
                RESET_REVEALS_ACCOUNT.rule_id,
            ),
            (
                Flaws {
                    reset_reveals_by_words: true,
                    ..Default::default()
                },
                RESET_REVEALS_ACCOUNT.rule_id,
            ),
        ] {
            let o = run_signing_up(flaws);
            assert_eq!(reset_findings(&o), vec![rule], "{rule}: {:?}", o.steps);
        }
        let o = run_signing_up(Flaws {
            no_mail_sink: true,
            reset_reusable: true,
            ..Default::default()
        });
        assert!(reset_findings(&o).is_empty());
        assert!(
            reset_not_assessed(&o)
                .iter()
                .any(|w| w.contains("no mail server")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn answers_that_differ_between_identical_requests_are_not_held_against_the_app() {
        for users in [users(), with_signup()] {
            let mut app = FakeApp::new(Flaws {
                reset_answer_counts: true,
                ..Default::default()
            });
            let mut acc = accounts();
            let seeded = users.seed.is_some();
            if seeded {
                for account in [&acc.a, &acc.b] {
                    app.users
                        .insert(account.user.clone(), (account.password.clone(), false));
                }
            }
            if !seeded {
                acc.admin = None;
                acc.totp = None;
                acc.totp = None;
            } else {
                let admin = acc.admin.clone().unwrap();
                app.users.insert(admin.user, (admin.password, true));
            }
            let o = run(&mut app, &users, &acc, seeded, &Default::default());
            assert!(reset_findings(&o).is_empty(), "{:#?}", o.findings);
            // And the comparison really ran: all three requests were answered.
            assert!(
                o.steps
                    .iter()
                    .any(|s| s.contains("twice (200, 200)") && s.contains("no account (200)")),
                "{:?}",
                o.steps
            );
        }
    }

    #[test]
    fn a_reset_that_changes_nothing_through_sign_up_is_not_assessed_either() {
        let o = run_signing_up(Flaws {
            reset_does_nothing: true,
            reset_reusable: true,
            reset_keeps_old: true,
            ..Default::default()
        });
        assert!(reset_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            reset_not_assessed(&o)
                .iter()
                .any(|w| w.contains("did not change the password")),
            "{:?}",
            o.not_assessed
        );
    }

    // --------------------------------------------------------------------------------------------
    // How long an emailed code lasts, waited out with --slow

    fn lifetime_why(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(id, why)| id == "V6.5.5" && why.contains("emailed sign-in code"))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    /// The seeded fixture with `--slow` and no timeouts stated, so the only waiting is the code's.
    fn code_slow_run(flaws: Flaws, tune: impl FnOnce(&mut FakeApp)) -> Outcome {
        let mut app = FakeApp::new(flaws);
        tune(&mut app);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        super::run_with(&mut app, &users(), &acc, true, &Default::default(), true)
    }

    #[test]
    fn a_code_refused_after_ten_minutes_is_credited_when_a_fresh_one_works() {
        let o = code_slow_run(Flaws::default(), |_| {});
        assert!(
            !rule_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
            "{:#?}",
            o.findings
        );
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == EMAIL_CODE_LONG_LIVED.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(credit.scope.contains("10 minutes"), "{}", credit.scope);
        assert!(lifetime_why(&o).is_empty(), "{:?}", lifetime_why(&o));
    }

    #[test]
    fn a_code_that_never_expires_is_found() {
        for o in [
            code_slow_run(
                Flaws {
                    code_long_lived: true,
                    ..Default::default()
                },
                |_| {},
            ),
            // With sessions that end after five idle minutes: the one that asked is kept in use,
            // so the old code is judged on its age and not on a session that ended.
            code_slow_run(
                Flaws {
                    code_long_lived: true,
                    ..Default::default()
                },
                |app| {
                    app.idle_limit = Some(5 * 60);
                    app.anonymous_sessions_time_out = true;
                },
            ),
        ] {
            assert!(
                rule_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
                "{:?}",
                o.steps
            );
            assert!(!verified_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        }
    }

    #[test]
    fn a_session_kept_in_use_outlives_the_wait_so_a_good_app_is_still_credited() {
        let o = code_slow_run(Flaws::default(), |app| {
            app.idle_limit = Some(5 * 60);
            app.anonymous_sessions_time_out = true;
        });
        assert!(
            verified_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_refusal_with_no_working_code_to_compare_is_not_assessed() {
        let o = code_slow_run(
            Flaws {
                code_does_nothing: true,
                ..Default::default()
            },
            |_| {},
        );
        assert!(!rule_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(!verified_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(
            lifetime_why(&o)
                .iter()
                .any(|w| w.contains("cannot be said to be about its age")),
            "{:?}",
            lifetime_why(&o)
        );
    }

    /// The sign-up fixture with `--slow`, in an app whose sessions end after five idle minutes,
    /// signed in or not: the lifetime check's account is made through sign-up there.
    fn code_slow_signup_run(flaws: Flaws) -> Outcome {
        let mut app = FakeApp::new(flaws);
        app.idle_limit = Some(5 * 60);
        app.anonymous_sessions_time_out = true;
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        super::run_with(
            &mut app,
            &with_signup(),
            &acc,
            false,
            &Default::default(),
            true,
        )
    }

    #[test]
    fn through_sign_up_each_lifetime_outcome_is_reached() {
        let long_lived = code_slow_signup_run(Flaws {
            code_long_lived: true,
            ..Default::default()
        });
        assert!(
            rule_ids(&long_lived).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
            "{:?}",
            long_lived.steps
        );
        assert!(!verified_ids(&long_lived).contains(&EMAIL_CODE_LONG_LIVED.rule_id));

        let correct = code_slow_signup_run(Flaws::default());
        assert!(
            verified_ids(&correct).contains(&EMAIL_CODE_LONG_LIVED.rule_id),
            "{:?}",
            correct.steps
        );

        let broken = code_slow_signup_run(Flaws {
            code_does_nothing: true,
            ..Default::default()
        });
        assert!(!verified_ids(&broken).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(!rule_ids(&broken).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(
            lifetime_why(&broken)
                .iter()
                .any(|w| w.contains("cannot be said to be about its age")),
            "{:?}",
            lifetime_why(&broken)
        );
    }

    #[test]
    fn without_slow_nothing_is_waited_for_and_it_says_so() {
        let mut app = FakeApp::new(Flaws {
            code_long_lived: true,
            ..Default::default()
        });
        let start = app.clock;
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(&mut app, &users(), &acc, true, &Default::default());
        assert!(!rule_ids(&o).contains(&EMAIL_CODE_LONG_LIVED.rule_id));
        assert!(
            lifetime_why(&o).iter().any(|w| w.contains("--slow")),
            "{:?}",
            lifetime_why(&o)
        );
        assert!(app.clock - start < 5 * 60, "it waited without --slow");
    }

    #[test]
    fn with_no_email_code_entry_the_lifetime_is_not_mentioned() {
        let mut u = users();
        u.email_code = None;
        let o = run_against(Flaws::default(), &u);
        assert!(lifetime_why(&o).is_empty(), "{:?}", lifetime_why(&o));
    }

    // --------------------------------------------------------------------------------------------
    // Signing in with an emailed code

    const CODE_RULES: [&str; 4] = [
        EMAIL_CODE_REUSABLE.rule_id,
        EMAIL_CODE_UNBOUND.rule_id,
        EMAIL_CODE_SHORT.rule_id,
        EMAIL_CODE_GUESSING.rule_id,
    ];

    fn code_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| CODE_RULES.contains(id))
            .collect()
    }

    fn code_credits(o: &Outcome) -> Vec<&str> {
        verified_ids(o)
            .into_iter()
            .filter(|id| CODE_RULES.contains(id))
            .collect()
    }

    fn code_not_assessed(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.contains("V6.5.1") || ids.contains("V6.6."))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    fn codes_policy(n: u32) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            failed_codes: Some(n),
            ..Default::default()
        }
    }

    #[test]
    fn a_code_that_works_once_where_it_was_asked_for_is_credited() {
        for o in [
            run_against(Flaws::default(), &users()),
            run_signing_up(Flaws::default()),
        ] {
            assert!(code_findings(&o).is_empty(), "{:#?}", o.findings);
            assert_eq!(
                code_credits(&o),
                vec![EMAIL_CODE_UNBOUND.rule_id],
                "{:?}",
                o.steps
            );
            // A code tied to its session cannot be tried twice from another, so single use is
            // not credited on a refusal there.
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(ids, why)| ids == "V6.5.1" && why.contains("tied to the session")),
                "{:?}",
                o.not_assessed
            );
            // Guessing is held to a stated number, and none was stated.
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(ids, why)| ids == "V6.6.3" && why.contains("failed-codes")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn each_fault_in_a_sign_in_code_is_found_by_its_own_rule() {
        for (flaws, found) in [
            (
                Flaws {
                    code_reusable: true,
                    code_unbound: true,
                    ..Default::default()
                },
                vec![EMAIL_CODE_UNBOUND.rule_id, EMAIL_CODE_REUSABLE.rule_id],
            ),
            (
                Flaws {
                    code_unbound: true,
                    ..Default::default()
                },
                vec![EMAIL_CODE_UNBOUND.rule_id],
            ),
            (
                Flaws {
                    code_short: true,
                    ..Default::default()
                },
                vec![EMAIL_CODE_SHORT.rule_id],
            ),
        ] {
            for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
                assert_eq!(code_findings(&o), found, "{found:?}: {:?}", o.steps);
                for rule in &found {
                    assert!(
                        !code_credits(&o).contains(rule),
                        "{rule} both found and credited"
                    );
                }
            }
        }
        // A code that works from any session but only once: the one case where a refused second
        // use is credited.
        let flaws = Flaws {
            code_unbound: true,
            ..Default::default()
        };
        for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
            assert_eq!(
                code_credits(&o),
                vec![EMAIL_CODE_REUSABLE.rule_id],
                "{:?}",
                o.steps
            );
        }
    }

    #[test]
    fn guessing_is_held_to_the_stated_number_of_wrong_codes() {
        let o = run_with(Flaws::default(), &codes_policy(3));
        assert!(
            code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
            "{:?}\n{:?}",
            o.steps,
            o.not_assessed
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));

        let o = run_with(
            Flaws {
                code_guessing_unlimited: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert_eq!(
            code_findings(&o),
            vec![EMAIL_CODE_GUESSING.rule_id],
            "{:?}",
            o.steps
        );
        // And through the seeded fixture, with A's own address.
        let mut app = FakeApp::new(Flaws {
            code_guessing_unlimited: true,
            ..Default::default()
        });
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(&mut app, &users(), &acc, true, &codes_policy(3));
        assert_eq!(code_findings(&o), vec![EMAIL_CODE_GUESSING.rule_id]);
    }

    #[test]
    fn guessing_is_not_judged_on_a_number_it_cannot_reach() {
        for n in [0, 25, 400] {
            let o = run_with(
                Flaws {
                    code_guessing_unlimited: true,
                    ..Default::default()
                },
                &codes_policy(n),
            );
            assert!(
                !code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
                "{n}"
            );
            assert!(
                !code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
                "{n}"
            );
        }
    }

    #[test]
    fn a_sign_in_code_that_signs_nobody_in_is_not_assessed_however_else_it_is_broken() {
        let flaws = Flaws {
            code_does_nothing: true,
            code_reusable: true,
            code_unbound: true,
            ..Default::default()
        };
        for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
            assert!(code_findings(&o).is_empty(), "{:#?}", o.findings);
            assert!(code_credits(&o).is_empty(), "{:?}", code_credits(&o));
            assert!(
                code_not_assessed(&o)
                    .iter()
                    .any(|w| w.contains("did not open")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn with_no_sign_in_email_to_read_nothing_is_judged_and_it_says_why() {
        for (flaws, why) in [
            (
                Flaws {
                    no_mail_sink: true,
                    code_reusable: true,
                    ..Default::default()
                },
                "no mail server",
            ),
            (
                Flaws {
                    code_sends_nothing: true,
                    code_reusable: true,
                    ..Default::default()
                },
                "sent no email",
            ),
        ] {
            for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
                assert!(code_findings(&o).is_empty(), "{why}: {:#?}", o.findings);
                assert!(code_credits(&o).is_empty(), "{why}");
                assert!(
                    code_not_assessed(&o).iter().any(|w| w.contains(why)),
                    "{why}: {:?}",
                    o.not_assessed
                );
            }
        }
    }

    #[test]
    fn a_refusal_is_credited_only_when_the_sessions_own_code_then_works() {
        // The session is locked by its first wrong code, so the code from elsewhere is refused and
        // so is its own afterwards: the refusal says nothing about where the code came from.
        let flaws = Flaws {
            code_locks_after_one: true,
            ..Default::default()
        };
        for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
            // Nor is single use: with binding unknown, a refused second use shows nothing.
            assert!(!code_credits(&o).contains(&EMAIL_CODE_REUSABLE.rule_id));
            assert!(!code_credits(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
            assert!(!code_findings(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(ids, why)| ids == "V6.6.2" && why.contains("own code")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_wrong_code_is_wrong_everywhere_and_looks_like_the_right_one() {
        for code in ["482913", "X7k2Q9", "000000", "9f86d081884c7d659a2f"] {
            let guesses: Vec<String> = (0..25).map(|n| wrong_code(code, n)).collect();
            for g in &guesses {
                assert_eq!(g.len(), code.len());
                assert!(
                    g.chars().zip(code.chars()).all(|(a, b)| a != b
                        && a.is_ascii_digit() == b.is_ascii_digit()
                        && a.is_ascii_lowercase() == b.is_ascii_lowercase()),
                    "{code} -> {g}"
                );
            }
        }
    }

    #[test]
    fn pushing_back_by_cancelling_the_code_counts_and_refusing_from_the_start_is_not_judged() {
        // Wrong codes answered the same all the way through: the right code refused afterwards is
        // the only sign, and it is enough.
        let flaws = Flaws {
            code_cancels_quietly: true,
            ..Default::default()
        };
        let o = run_with(flaws, &codes_policy(3));
        assert!(
            code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));

        let flaws = Flaws {
            code_already_refusing: true,
            code_guessing_unlimited: true,
            ..Default::default()
        };
        let o = run_with(flaws, &codes_policy(3));
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(!code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V6.6.3" && why.contains("already refusing")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_short_code_that_works_anywhere_and_twice_is_three_findings_and_no_credit() {
        let flaws = Flaws {
            code_reusable: true,
            code_unbound: true,
            code_short: true,
            ..Default::default()
        };
        let o = run_with(flaws, &codes_policy(3));
        let mut found = code_findings(&o);
        found.sort_unstable();
        let mut want = vec![
            EMAIL_CODE_REUSABLE.rule_id,
            EMAIL_CODE_UNBOUND.rule_id,
            EMAIL_CODE_SHORT.rule_id,
        ];
        want.sort_unstable();
        assert_eq!(found, want, "{:?}", o.steps);
        assert_eq!(code_credits(&o), vec![EMAIL_CODE_GUESSING.rule_id]);
    }

    #[test]
    fn seeded_a_locked_session_leaves_binding_unjudged() {
        let o = seeded_with(
            Flaws {
                code_locks_after_one: true,
                ..Default::default()
            },
            &Default::default(),
        );
        assert!(!code_credits(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
        assert!(!code_findings(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
    }

    #[test]
    fn seeded_guessing_is_credited_when_pushed_back_and_found_when_not() {
        let o = seeded_with(Flaws::default(), &codes_policy(3));
        assert!(code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        let o = seeded_with(
            Flaws {
                code_cancels_quietly: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert!(
            code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
    }

    #[test]
    fn seeded_guessing_without_limit_is_found() {
        let o = seeded_with(
            Flaws {
                code_guessing_unlimited: true,
                ..Default::default()
            },
            &codes_policy(5),
        );
        assert_eq!(
            code_findings(&o),
            vec![EMAIL_CODE_GUESSING.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn seeded_an_app_refusing_from_the_first_wrong_code_is_not_judged() {
        let o = seeded_with(
            Flaws {
                code_already_refusing: true,
                code_guessing_unlimited: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(!code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
    }

    #[test]
    fn seeded_a_code_that_signs_nobody_in_is_not_assessed() {
        let o = seeded_with(
            Flaws {
                code_does_nothing: true,
                code_reusable: true,
                code_unbound: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert!(code_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(code_credits(&o).is_empty());
        assert!(
            code_not_assessed(&o)
                .iter()
                .any(|w| w.contains("did not open")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_code_that_signs_nobody_in_is_never_credited_for_resisting_guesses() {
        let o = run_with(
            Flaws {
                code_does_nothing: true,
                ..Default::default()
            },
            &codes_policy(3),
        );
        assert!(!code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V6.6.3" && why.contains("did not sign in")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn seeded_no_mail_server_is_said_as_such() {
        let o = seeded_with(
            Flaws {
                no_mail_sink: true,
                ..Default::default()
            },
            &Default::default(),
        );
        assert!(
            code_not_assessed(&o)
                .iter()
                .any(|w| w.contains("no mail server")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn seeded_a_number_too_large_to_reach_is_not_judged() {
        let o = seeded_with(
            Flaws {
                code_guessing_unlimited: true,
                ..Default::default()
            },
            &codes_policy(400),
        );
        assert!(!code_findings(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V6.6.3" && why.contains("400")),
            "{:?}",
            o.not_assessed
        );
    }

    /// The fixtures with the emailed-code forms carrying no `{csrf}`.
    fn without_code_csrf(mut u: UsersSection) -> UsersSection {
        let entry = u.email_code.as_mut().unwrap();
        for t in [&mut entry.request, &mut entry.use_code] {
            t.form.remove("csrf_token");
        }
        u
    }

    #[test]
    fn a_form_with_no_token_is_still_opened_first_so_the_code_has_a_session_to_belong_to() {
        let flaws = Flaws {
            code_no_csrf: true,
            ..Default::default()
        };
        let mut app = FakeApp::new(flaws);
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let o = run(
            &mut app,
            &without_code_csrf(with_signup()),
            &acc,
            false,
            &Default::default(),
        );
        assert!(
            code_findings(&o).is_empty(),
            "{:#?}\n{:?}",
            o.findings,
            o.steps
        );
        assert_eq!(code_credits(&o), vec![EMAIL_CODE_UNBOUND.rule_id]);
    }

    #[test]
    fn seeded_a_form_with_no_token_is_still_opened_first() {
        let mut app = FakeApp::new(Flaws {
            code_no_csrf: true,
            ..Default::default()
        });
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(
            &mut app,
            &without_code_csrf(users()),
            &acc,
            true,
            &codes_policy(3),
        );
        assert!(code_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(code_credits(&o).contains(&EMAIL_CODE_UNBOUND.rule_id));
        assert!(code_credits(&o).contains(&EMAIL_CODE_GUESSING.rule_id));
    }

    /// The seeded suite, starting `before` seconds ahead of a 30-second boundary, with the clock
    /// moving `per_request` seconds with every request, as it does against a real app.
    fn totp_ticking(flaws: Flaws, before: u64, per_request: u64) -> Outcome {
        let mut app = FakeApp::new(flaws);
        let step = crate::totp::STEP;
        app.clock = (app.clock / step + 10) * step - before;
        app.seconds_per_request = per_request;
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        if let Some(admin) = acc.admin.clone() {
            app.users.insert(admin.user, (admin.password, true));
        }
        let totp = acc.totp.clone().unwrap();
        app.users.insert(
            totp.account.user.clone(),
            (totp.account.password.clone(), false),
        );
        app.totp
            .insert(totp.account.user.clone(), totp.secret.clone());
        run(&mut app, &users(), &acc, true, &Default::default())
    }

    #[test]
    fn a_code_that_works_twice_is_never_credited_whenever_the_step_ends() {
        // From the review: an app that takes a code twice, and accepts only the current step, with
        // the step ending partway through the check. Every combination must end in the finding or
        // in not assessed — never in V6.5.1 credited.
        for before in [2, 4, 6, 9, 15, 25] {
            for per_request in [0, 1, 2, 3] {
                let o = totp_ticking(
                    Flaws {
                        totp_reusable: true,
                        totp_current_only: true,
                        ..Default::default()
                    },
                    before,
                    per_request,
                );
                assert!(
                    !verified_ids(&o).contains(&TOTP_REUSED.rule_id),
                    "credited, {before}s before a boundary, {per_request}s a request: {:?}",
                    o.steps
                );
            }
        }
    }

    #[test]
    fn a_correct_app_is_still_credited_with_the_clock_moving() {
        // The fix must not just stop crediting: with a step ending in the middle, the pair is
        // tried again in the new step and the refusal counts.
        // One or two seconds a request: a sign-in and a second use fit in one step. Slower than
        // that they cannot, and `a_step_that_keeps_ending_leaves_reuse_unjudged_and_says_so` holds.
        for (before, per_request) in [(25, 1), (15, 1), (9, 2), (4, 0)] {
            let o = totp_ticking(
                Flaws {
                    totp_current_only: true,
                    ..Default::default()
                },
                before,
                per_request,
            );
            assert!(
                verified_ids(&o).contains(&TOTP_REUSED.rule_id),
                "{before}s before a boundary, {per_request}s a request: {:?}\n{:?}",
                o.steps,
                totp_named(&o, "V6.5.1")
            );
        }
    }

    #[test]
    fn an_app_that_takes_a_code_twice_is_still_found_with_the_clock_moving() {
        // One or two seconds a request: a sign-in and a second use fit in one step. Slower than
        // that they cannot, and `a_step_that_keeps_ending_leaves_reuse_unjudged_and_says_so` holds.
        for (before, per_request) in [(25, 1), (15, 1), (9, 2), (4, 0)] {
            let o = totp_ticking(
                Flaws {
                    totp_reusable: true,
                    totp_current_only: true,
                    ..Default::default()
                },
                before,
                per_request,
            );
            assert!(
                rule_ids(&o).contains(&TOTP_REUSED.rule_id),
                "{before}s before a boundary, {per_request}s a request: {:?}",
                o.steps
            );
        }
    }

    #[test]
    fn a_step_that_keeps_ending_leaves_reuse_unjudged_and_says_so() {
        // Eight seconds a request: every pair of sign-ins straddles a boundary.
        let o = totp_ticking(
            Flaws {
                totp_current_only: true,
                ..Default::default()
            },
            25,
            8,
        );
        assert!(
            !verified_ids(&o).contains(&TOTP_REUSED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!rule_ids(&o).contains(&TOTP_REUSED.rule_id));
        assert!(
            totp_named(&o, "V6.5.1")
                .iter()
                .any(|w| w.contains("step ended")),
            "{:?}",
            totp_named(&o, "V6.5.1")
        );
    }

    #[test]
    fn the_lifetime_credit_says_the_thirty_second_bound_was_not_shown() {
        let o = run_against(Flaws::default(), &users());
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == TOTP_OLD_CODE.rule_id)
            .expect("credited");
        assert!(
            credit.scope.contains("at most 30 seconds was not shown"),
            "{}",
            credit.scope
        );
    }

    #[test]
    fn the_case_from_review_is_not_credited() {
        // 15 seconds before a boundary, 3 seconds a request, an app that takes a code twice and
        // only the current step's: credited as verified before the fix.
        let o = totp_ticking(
            Flaws {
                totp_reusable: true,
                totp_current_only: true,
                ..Default::default()
            },
            15,
            3,
        );
        assert!(
            !verified_ids(&o).contains(&TOTP_REUSED.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_control_code_refused_as_its_step_ended_does_not_blame_the_setup() {
        let o = totp_ticking(
            Flaws {
                totp_current_only: true,
                ..Default::default()
            },
            25,
            5,
        );
        let why = totp_named(&o, "V6.5.1");
        assert!(why.iter().any(|w| w.contains("step ended")), "{why:?}");
        assert!(
            !why.iter().any(|w| w.contains("Check `totp`")),
            "a clock problem blamed on the manifest: {why:?}"
        );
    }

    #[test]
    fn the_lifetime_credit_is_worded_the_same_with_the_clock_moving() {
        let o = totp_ticking(Flaws::default(), 25, 1);
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == TOTP_OLD_CODE.rule_id)
            .expect("credited");
        assert!(credit.scope.contains("not shown"), "{}", credit.scope);
    }

    // --------------------------------------------------------------------------------------------
    // Activation codes emailed at sign-up (V6.4.1)

    const ACTIVATION_RULES: [&str; 2] = [ACTIVATION_GUESSABLE.rule_id, ACTIVATION_REUSABLE.rule_id];

    fn activation_users() -> UsersSection {
        let mut u = with_signup();
        u.activation = Some(sv_manifest::ActivationSection {
            use_code: RequestTemplate {
                method: "POST".into(),
                path: "/activate".into(),
                form: [("code", "{code}"), ("csrf_token", "{csrf}")]
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                json: BTreeMap::new(),
            },
            code_pattern: None,
        });
        u
    }

    fn run_activation(flaws: Flaws) -> Outcome {
        let mut app = FakeApp::new(flaws);
        app.activation = true;
        let mut acc = accounts();
        acc.admin = None;
        // A and B are seeded, so every activation fixture reaches the check however broken sign-up is.
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let mut u = activation_users();
        u.seed = Some("seed".into());
        run(&mut app, &u, &acc, true, &Default::default())
    }

    /// The same app with every account, A and B included, made through sign-up.
    fn run_activation_signed_up(flaws: Flaws) -> Outcome {
        let mut app = FakeApp::new(flaws);
        app.activation = true;
        let mut acc = accounts();
        acc.admin = None;
        run(
            &mut app,
            &activation_users(),
            &acc,
            false,
            &Default::default(),
        )
    }

    fn activation_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| ACTIVATION_RULES.contains(id))
            .collect()
    }

    fn activation_why(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(id, _)| id == "V6.4.1")
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn a_correct_activation_is_followed_through_and_credits_nothing() {
        let o = run_activation(Flaws::default());
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            !verified_ids(&o)
                .iter()
                .any(|id| ACTIVATION_RULES.contains(id))
        );
        let steps = o.steps.join("\n");
        for step in [
            "an email arrived with an activation code in it",
            "the account then signed in, and the link itself signed it in",
            "used the same activation code again in a new session: not signed in",
        ] {
            assert!(steps.contains(step), "{step}:\n{steps}");
        }
        assert!(
            activation_why(&o).iter().any(|w| w.contains("not tried")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn each_activation_fault_is_found_by_its_own_rule() {
        for (flaws, rule) in [
            (
                Flaws {
                    activation_reusable: true,
                    ..Default::default()
                },
                ACTIVATION_REUSABLE.rule_id,
            ),
            (
                Flaws {
                    activation_short: true,
                    ..Default::default()
                },
                ACTIVATION_GUESSABLE.rule_id,
            ),
            (
                Flaws {
                    activation_counting: true,
                    ..Default::default()
                },
                ACTIVATION_GUESSABLE.rule_id,
            ),
        ] {
            let o = run_activation(flaws);
            assert_eq!(activation_findings(&o), vec![rule], "{rule}: {:?}", o.steps);
        }
    }

    #[test]
    fn an_activation_that_activates_nothing_is_not_assessed_however_else_it_is_broken() {
        let o = run_activation(Flaws {
            activation_does_nothing: true,
            activation_reusable: true,
            ..Default::default()
        });
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("still could not after")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn a_link_that_does_not_sign_in_leaves_reuse_unjudged() {
        let o = run_activation(Flaws {
            activation_link_does_not_sign_in: true,
            activation_reusable: true,
            ..Default::default()
        });
        assert!(
            !activation_findings(&o).contains(&ACTIVATION_REUSABLE.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            !o.steps
                .iter()
                .any(|s| s.contains("used the same activation code again")),
            "{:?}",
            o.steps
        );
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("did not sign anybody in")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn sign_in_that_does_not_wait_for_activation_is_said_and_still_judged() {
        let o = run_activation(Flaws {
            activation_not_gating: true,
            activation_short: true,
            ..Default::default()
        });
        assert_eq!(activation_findings(&o), vec![ACTIVATION_GUESSABLE.rule_id]);
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("could sign in before it was activated")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn accounts_made_through_sign_up_are_activated_so_the_suite_can_sign_in() {
        let o = run_activation_signed_up(Flaws::default());
        let steps = o.steps.join("\n");
        assert!(
            steps.contains("signed in as A and opened /account (200)"),
            "{steps}"
        );
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            steps.contains("used the same activation code again in a new session: not signed in"),
            "{steps}"
        );
    }

    #[test]
    fn the_accounts_other_checks_sign_up_are_activated_too() {
        let o = run_activation_signed_up(Flaws::default());
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("signed in as control.") && s.contains("opened")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn the_faults_are_found_when_every_account_is_signed_up_too() {
        for (flaws, rule) in [
            (
                Flaws {
                    activation_reusable: true,
                    ..Default::default()
                },
                ACTIVATION_REUSABLE.rule_id,
            ),
            (
                Flaws {
                    activation_counting: true,
                    ..Default::default()
                },
                ACTIVATION_GUESSABLE.rule_id,
            ),
        ] {
            let o = run_activation_signed_up(flaws);
            assert_eq!(activation_findings(&o), vec![rule], "{rule}: {:?}", o.steps);
        }
    }

    #[test]
    fn a_short_code_is_not_judged_when_activation_activates_nothing() {
        let o = run_activation(Flaws {
            activation_does_nothing: true,
            activation_short: true,
            ..Default::default()
        });
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("With no activation that works")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn reuse_is_not_tried_when_the_link_signs_nobody_in() {
        let o = run_activation(Flaws {
            activation_link_does_not_sign_in: true,
            ..Default::default()
        });
        assert!(activation_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            !o.steps
                .iter()
                .any(|s| s.contains("used the same activation code again")),
            "{:?}",
            o.steps
        );
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.starts_with("Whether an activation code works twice")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn an_ungated_sign_in_is_said_beside_a_reuse_finding() {
        let o = run_activation(Flaws {
            activation_not_gating: true,
            activation_reusable: true,
            ..Default::default()
        });
        assert_eq!(activation_findings(&o), vec![ACTIVATION_REUSABLE.rule_id]);
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("could sign in before it was activated")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn with_no_mail_server_no_activation_account_is_even_signed_up() {
        let o = run_activation(Flaws {
            no_mail_sink: true,
            ..Default::default()
        });
        assert!(
            !o.steps.iter().any(|s| s.starts_with("signed up activate")),
            "{:?}",
            o.steps
        );
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("had no mail server for the app")),
            "{:?}",
            activation_why(&o)
        );
    }

    #[test]
    fn without_a_mail_server_or_a_sign_up_nothing_is_judged_and_it_says_why() {
        let o = run_activation(Flaws {
            no_mail_sink: true,
            activation_reusable: true,
            ..Default::default()
        });
        assert!(activation_findings(&o).is_empty());
        assert!(
            activation_why(&o)
                .iter()
                .any(|w| w.contains("no mail server"))
        );

        let mut app = FakeApp::new(Flaws {
            activation_reusable: true,
            ..Default::default()
        });
        app.activation = true;
        let mut u = activation_users();
        u.signup = None;
        u.seed = Some("seed".into());
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let o = run(&mut app, &u, &acc, true, &Default::default());
        assert!(activation_findings(&o).is_empty());
        assert!(activation_why(&o).iter().any(|w| w.contains("no `signup`")));
    }
}
