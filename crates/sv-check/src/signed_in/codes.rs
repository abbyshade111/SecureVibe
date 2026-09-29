use super::*;

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

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::{run_signing_up, run_with, seeded_with, with_signup};
    use super::*;

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
}
