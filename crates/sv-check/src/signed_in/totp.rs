use super::*;

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
            "`totp` is set in stackvet.toml, but only `seed` can enroll an account in two-factor \
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
                         `totp` in stackvet.toml, and that `seed` enrolled the account with \
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
    use super::super::tests::with_signup;
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

    /// The seeded suite, with the two-factor check starting `before` seconds ahead of a 30-second
    /// boundary, and the clock moving `per_request` seconds with every request, as it does against
    /// a real app. Where the check starts depends on how many requests the checks before it send,
    /// so a first run finds that moment, and the second starts its clock so the moment lands where
    /// the test wants it.
    fn totp_ticking(flaws: Flaws, before: u64, per_request: u64) -> Outcome {
        let step = crate::totp::STEP;
        let (_, first, started) = totp_ticking_from(flaws, None, per_request);
        let target = (started / step + 10) * step - before;
        let (o, _, again) = totp_ticking_from(flaws, Some(first + target - started), per_request);
        assert_eq!(
            again % step,
            target % step,
            "the two-factor check did not start where the test put it"
        );
        o
    }

    /// One seeded run from `clock`, or the app's own start: the outcome, the clock it started at,
    /// and the clock when the two-factor check began (just after the request before its first).
    fn totp_ticking_from(
        flaws: Flaws,
        clock: Option<u64>,
        per_request: u64,
    ) -> (Outcome, u64, u64) {
        let mut app = FakeApp::new(flaws);
        if let Some(clock) = clock {
            app.clock = clock;
        }
        let first = app.clock;
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
        let o = run(&mut app, &users(), &acc, true, &Default::default());
        let at = app
            .clock_log
            .iter()
            .position(|(id, _)| id == "login-page-1")
            .expect("the two-factor check ran");
        assert!(at > 0, "a request came before the two-factor check");
        (o, first, app.clock_log[at - 1].1)
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
}
