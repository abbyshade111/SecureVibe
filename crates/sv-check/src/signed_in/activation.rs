use super::*;

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

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::with_signup;
    use super::*;

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
