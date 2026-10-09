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
    let mut mailed = None;
    reset_flow(http, users, accounts, confirm, &mut mailed, out);
    // Last, after the whole reset: a new request may cancel the code the flow above was using.
    match (&users.reset, mailed) {
        (Some(reset), Some(account)) => {
            mail_header_check(http, reset, &account, &accounts.spare, out);
        }
        _ => out.not_assessed.push((
            "V1.3.11".to_owned(),
            "Whether a header typed into an email address reaches the app's email: it is asked of \
             the password reset, once its email has been seen to arrive, and it was not."
                .to_owned(),
        )),
    }
}

/// V1.3.11 (ADR-069): the reset requested twice more for the account, its address followed by a
/// line break and a `Bcc` header naming an address of `sv`'s own, once with `\r\n` and once with
/// `\n`. Asked only once the reset email has been seen to arrive for that account.
fn mail_header_check(
    http: &mut dyn Http,
    reset: &sv_manifest::ResetSection,
    account: &Account,
    spare: &str,
    out: &mut Outcome,
) {
    let theirs = format!("sv-bcc-{}@example.test", &spare[12..24]);
    let before = http.mail(&account.user, 0).map_or(0, |m| m.len());
    let mut answers = Vec::new();
    for (label, line_break) in [("crlf", "\r\n"), ("lf", "\n")] {
        let user = format!("{}{line_break}Bcc: {theirs}", account.user);
        let values = Values {
            user: &user,
            ..Default::default()
        };
        let mut session = Session::default();
        let answer = send_template(
            http,
            &format!("reset-header-{label}"),
            &reset.request,
            &values,
            &mut session,
            &[],
        )
        .0;
        answers.push(status(&answer));
    }
    // The account's own email first, waited for: by the time it has come, so has anything sent
    // with it.
    let to_account = http
        .mail(&account.user, before + 1)
        .map_or(0, |m| m.len().saturating_sub(before));
    let to_theirs = http
        .mail(&theirs, usize::from(to_account == 0))
        .map_or(0, |m| m.len());
    out.steps.push(format!(
        "asked for a reset twice more for {} with a line break and a `Bcc` header after the address \
         ({}): {to_account} email{} came to the account and {to_theirs} to the address in the header",
        account.user,
        answers.join(", "),
        if to_account == 1 { "" } else { "s" }
    ));
    if to_theirs > 0 {
        out.findings.push(finding(
            &MAIL_HEADER_INJECTED,
            "A header typed into the email address is added to the app's email",
            Severity::High,
            format!(
                "Asked for a password reset through {} with `Bcc: {theirs}` after a line break in \
                 the address, the app's email reached {theirs} as well.",
                reset.request.path
            ),
        ));
    } else if to_account > 0 {
        out.verified.push(
            crate::Verified::new(
                MAIL_HEADER_INJECTED.rule_id,
                MAIL_HEADER_INJECTED.requirement_ids,
                format!(
                    "the address field of the password reset request ({}), sent with a line break \
                     and a `Bcc` header after the address: the account's reset email came, and \
                     nothing reached the address in the header; one field and one kind of mail",
                    reset.request.path
                ),
            )
            .in_part(),
        );
    } else {
        out.not_assessed.push((
            "V1.3.11".to_owned(),
            format!(
                "Whether a header typed into an email address reaches the app's email: a reset asked \
                 for with a line break and a `Bcc` header after the address sent no email at all \
                 ({}), which an app that finds the account by the exact address it was given does, \
                 so it shows nothing either way.",
                answers.join(", ")
            ),
        ));
    }
    crate::verified::unless_credited(MAIL_HEADER_INJECTED.rule_id, &out.verified);
}

fn reset_flow(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    mailed: &mut Option<Account>,
    out: &mut Outcome,
) {
    const IDS: &str = "V6.4.3, V6.3.8";
    let Some(reset) = &users.reset else {
        out.not_assessed.push((
            IDS.to_owned(),
            "How a forgotten password is reset: stackvet.toml sets no `reset` under \
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
                format!("`reset.code-pattern` in stackvet.toml cannot be used: {e}."),
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
        &RESET_REQUEST,
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
                 and check `reset.request` in stackvet.toml.",
                account.user
            ),
        ));
        return;
    }
    *mailed = Some(account.clone());
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
                 stackvet.toml to a pattern whose first group is the code.",
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
    code_in_answer_check([&first, &second], &codes, &reset.request.path, out);

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
                 stackvet.toml. With no reset that works, a refused one shows nothing.",
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

/// The shortest code looked for in an answer. A shorter one could turn up in a page by chance (a
/// year, a count), and is reported as guessable whatever the answer says.
const SHORTEST_CODE_LOOKED_FOR: usize = 6;

/// Whether the answer to a reset request carries a code the email did (V6.4.3): in its body, as
/// far as the run keeps of it, or in a header such as `Location`. Only a code standing on its own
/// counts, not one inside a longer run of letters and digits. Never credit: the run keeps only the
/// start of each answer, so a code further on would not be seen.
fn code_in_answer_check(
    answers: [&Option<ProbeResponse>; 2],
    codes: &[String],
    path: &str,
    out: &mut Outcome,
) {
    let stands_alone = |text: &str, code: &str| {
        text.match_indices(code).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let after = text[at + code.len()..].chars().next();
            !before.is_some_and(|c| c.is_ascii_alphanumeric())
                && !after.is_some_and(|c| c.is_ascii_alphanumeric())
        })
    };
    let found = answers
        .iter()
        .filter_map(|a| a.as_ref())
        .find_map(|answer| {
            codes
                .iter()
                .filter(|code| code.chars().count() >= SHORTEST_CODE_LOOKED_FOR)
                .find_map(|code| {
                    if stands_alone(&answer.body, code) {
                        Some("its body".to_owned())
                    } else {
                        answer
                            .headers
                            .iter()
                            .find(|(_, value)| stands_alone(value, code))
                            .map(|(name, _)| format!("its `{name}` header"))
                    }
                })
        });
    out.steps.push(format!(
        "looked for the code from the email in the answers to the reset requests: {}",
        match &found {
            Some(place) => format!("found, in {place}"),
            None => "not found".to_owned(),
        }
    ));
    if let Some(place) = found {
        out.findings.push(finding(
            &RESET_CODE_IN_ANSWER,
            "A password reset hands its code to whoever asked",
            Severity::Critical,
            format!(
                "The answer to a password reset request through {path} carried, in {place}, the same \
                 code the reset email sent to the account. Whoever asks for a reset can read it there."
            ),
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::{run_signing_up, with_signup};
    use super::*;

    // --------------------------------------------------------------------------------------------
    // Password reset, through the mail sink

    const RESET_RULES: [&str; 5] = [
        RESET_REUSABLE.rule_id,
        RESET_KEEPS_OLD.rule_id,
        RESET_CODE_GUESSABLE.rule_id,
        RESET_REVEALS_ACCOUNT.rule_id,
        RESET_CODE_IN_ANSWER.rule_id,
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
    fn a_header_typed_into_the_reset_address_is_found_or_credited_or_said() {
        // ADR-069, V1.3.11. Found: the app mails the address as typed, `Bcc:` line and all.
        let o = run_against(
            Flaws {
                reset_mails_typed_address: true,
                ..Default::default()
            },
            &users(),
        );
        let f = o
            .findings
            .iter()
            .find(|f| f.rule_id == MAIL_HEADER_INJECTED.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(f.description.contains("sv-bcc-"), "{}", f.description);
        assert!(!verified_ids(&o).contains(&MAIL_HEADER_INJECTED.rule_id));
        // The reset flow before it still ran in full, so the check came after it.
        assert!(
            o.steps
                .iter()
                .any(|s| s == "the password the used code tried to set was refused"),
            "{:?}",
            o.steps
        );
        // Credited in part: the app cuts the address at the line break and mails the account.
        let o = run_against(
            Flaws {
                reset_cuts_line_breaks: true,
                ..Default::default()
            },
            &users(),
        );
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == MAIL_HEADER_INJECTED.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(credit.in_part, "{credit:?}");
        assert!(!rule_ids(&o).contains(&MAIL_HEADER_INJECTED.rule_id));
        // Said, neither found nor credited: the app finds the account by the exact address, so
        // nothing is sent (the fake app's way by default).
        let o = run_against(Flaws::default(), &users());
        assert!(!rule_ids(&o).contains(&MAIL_HEADER_INJECTED.rule_id));
        assert!(!verified_ids(&o).contains(&MAIL_HEADER_INJECTED.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V1.3.11" && why.contains("sent no email at all")),
            "{:?}",
            o.not_assessed
        );
        // Not asked at all when the reset email never arrived.
        let o = run_against(
            Flaws {
                reset_sends_nothing: true,
                reset_mails_typed_address: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            !o.steps.iter().any(|s| s.contains("`Bcc` header")),
            "{:?}",
            o.steps
        );
        assert!(!rule_ids(&o).contains(&MAIL_HEADER_INJECTED.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V1.3.11" && why.contains("it was not")),
            "{:?}",
            o.not_assessed
        );
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
            "looked for the code from the email in the answers to the reset requests: not found",
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

    #[test]
    fn a_code_in_the_answer_is_found_whichever_way_the_account_was_made() {
        // Only the first answer carries the code, so the two answers for the account differ
        // between themselves, and the account check rightly sets that difference aside.
        let flaws = Flaws {
            reset_code_in_answer: true,
            ..Default::default()
        };
        for o in [run_against(flaws, &users()), run_signing_up(flaws)] {
            assert_eq!(
                reset_findings(&o),
                vec![RESET_CODE_IN_ANSWER.rule_id],
                "{:?}",
                o.steps
            );
        }
    }

    #[test]
    fn a_code_in_the_answer_is_reported_without_printing_it() {
        let o = run_against(
            Flaws {
                reset_code_in_answer: true,
                ..Default::default()
            },
            &users(),
        );
        let found: Vec<&Finding> = o
            .findings
            .iter()
            .filter(|f| f.rule_id == RESET_CODE_IN_ANSWER.rule_id)
            .collect();
        assert_eq!(found.len(), 1, "{:?}", o.steps);
        assert!(
            found[0].description.contains("in its body"),
            "{}",
            found[0].description
        );
        assert!(!verified_ids(&o).contains(&RESET_CODE_IN_ANSWER.rule_id));
        // The code the email carried is in no finding and no step: setup first, that a code was
        // read from the email at all.
        let steps = o.steps.join("\n");
        assert!(steps.contains("2 emails arrived"), "{steps}");
        let said = format!("{:?}{steps}", o.findings);
        assert!(!said.contains("reset_token="), "{said}");
        assert!(
            !said
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w.len() == 32 && w.chars().all(|c| c.is_ascii_hexdigit())),
            "a code-shaped word was printed: {said}"
        );
    }

    #[test]
    fn a_code_is_found_on_its_own_in_a_body_or_a_header_and_not_inside_a_longer_word() {
        let answer = |body: &str, headers: &[(&str, &str)]| {
            Some(ProbeResponse {
                id: "reset-request-1".to_owned(),
                status: 200,
                headers: headers
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect(),
                body: body.to_owned(),
            })
        };
        let code = vec!["a1b2c3d4e5".to_owned()];
        let check = |a: Option<ProbeResponse>, codes: &[String]| {
            let mut out = Outcome::default();
            code_in_answer_check([&a, &None], codes, "/forgot", &mut out);
            (
                rule_ids(&out).len(),
                out.findings.first().map(|f| f.description.clone()),
            )
        };
        let (n, said) = check(answer(r#"{"ok":true,"token":"a1b2c3d4e5"}"#, &[]), &code);
        assert_eq!(n, 1);
        assert!(said.unwrap().contains("in its body"));
        let (n, said) = check(
            answer("", &[("location", "/reset?token=a1b2c3d4e5")]),
            &code,
        );
        assert_eq!(n, 1);
        assert!(said.unwrap().contains("`location` header"));
        // Inside a longer run of letters and digits is not the code standing alone.
        assert_eq!(check(answer("xa1b2c3d4e5", &[]), &code).0, 0);
        assert_eq!(check(answer("a1b2c3d4e59", &[]), &code).0, 0);
        // A code shorter than six characters is not looked for: it could be there by chance.
        let short = vec!["4821".to_owned()];
        assert_eq!(check(answer("Request 4821 today.", &[]), &short).0, 0);
        // A crashed request has no answer to read.
        assert_eq!(check(None, &code).0, 0);
    }
}
