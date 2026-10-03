//! An action that should go through only once, sent many times at the same instant (V2.3.4).
//!
//! The owner names it in `once`: booking the last seat, redeeming a one-time code. A reads the
//! page's token once, and then the same request goes out `AT_ONCE` times together, each over its
//! own connection. An app that reads "is one left?" and then writes "taken" without holding a lock
//! in between lets several through; one that does it in a single step lets one through.

use super::*;

/// How many copies are sent together. Enough that a gap between reading and writing of a few
/// milliseconds is likely to be hit, and few enough to be gentle on a small app.
pub(super) const AT_ONCE: usize = 20;

pub(super) fn once_check(
    http: &mut dyn Http,
    users: &UsersSection,
    account: &Account,
    out: &mut Outcome,
) {
    const IDS: &str = "V2.3.4";
    let Some(once) = &users.once else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether an action can go through twice when sent twice at the same instant: \
             securevibe.toml names no `once` action under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(signed_in) = sign_in(http, users, "once", account, &mut out.steps) else {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Whether {} can go through twice: the first user could not sign in to send it.",
                once.path
            ),
        ));
        return;
    };
    let mut session = signed_in.session;
    let values = Values {
        user: &account.user,
        password: &account.password,
        marker: "sv-probe-once-7d1a",
        ..Default::default()
    };
    let request = prepared(
        http,
        "once",
        &once.request(),
        &values,
        &mut session,
        &users.private,
    );
    let Some(answers) = http.send_at_once(&request, AT_ONCE) else {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Whether {} can go through twice: this run cannot send requests at the same \
                 instant, and requests sent one after another cannot show a race.",
                once.path
            ),
        ));
        return;
    };
    let went_through = answers
        .iter()
        .filter(|a| super::flows::finished(a, &once.completed))
        .count();
    // A crash, or no answer, is not a refusal: one success beside it does not show the others were
    // turned away.
    let unanswered = answers
        .iter()
        .filter(|a| a.as_ref().is_none_or(|r| r.status >= 500))
        .count();
    // Nor is a limiter's answer: a copy it turned away never reached the action, so the race was
    // run between fewer copies than were sent.
    let limited = answers.iter().flatten().filter(|r| r.status == 429).count();
    out.steps.push(format!(
        "sent {} to {} {AT_ONCE} times at the same instant: {went_through} went through, {unanswered} \
         crashed or did not answer, {limited} were turned away by a rate limit",
        once.method, once.path
    ));
    if went_through >= 2 {
        out.findings.push(finding(
            &DONE_TWICE,
            "An action that should go through once went through more than once",
            Severity::High,
            format!(
                "Sent {AT_ONCE} times at the same instant, {} {} went through {went_through} times \
                 (the answer said \"{}\"). Securevibe.toml names it as an action that should go \
                 through only once.",
                once.method, once.path, once.completed
            ),
        ));
    } else if went_through == 0 {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "None of the {AT_ONCE} copies of {} {} sent at the same instant went through (no \
                 answer said \"{}\"). Check `once` in securevibe.toml, and that the app starts the \
                 run with one of the thing to take. With nothing taken, a refusal shows nothing.",
                once.method, once.path, once.completed
            ),
        ));
    } else if limited > 0 {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "One of the {AT_ONCE} copies of {} {} sent at the same instant went through, and a \
                 rate limit turned {limited} away (429) before they reached the action. The race was \
                 not run between them, so this is not credited. A limit is not a lock: copies under \
                 it can still race.",
                once.method, once.path
            ),
        ));
    } else if unanswered > 0 {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "One of the {AT_ONCE} copies of {} {} sent at the same instant went through, and \
                 {unanswered} crashed or did not answer rather than being refused. A crash is not \
                 an answer to whether it would have gone through too, so this is not credited.",
                once.method, once.path
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            DONE_TWICE.rule_id,
            DONE_TWICE.requirement_ids,
            format!(
                "{} {} sent {AT_ONCE} times at the same instant: one went through and the rest were \
                 refused. One race, tried once",
                once.method, once.path
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::*;

    fn run(flaws: Flaws) -> Outcome {
        run_against(flaws, &users())
    }

    fn why_not(o: &Outcome) -> &str {
        o.not_assessed
            .iter()
            .find(|(ids, _)| ids == "V2.3.4")
            .map_or("", |(_, why)| why.as_str())
    }

    #[test]
    fn one_booking_out_of_twenty_sent_together_is_credited() {
        let o = run(Flaws::default());
        assert!(
            !rule_ids(&o).contains(&DONE_TWICE.rule_id),
            "{:?}",
            o.findings
        );
        assert!(
            verified_ids(&o).contains(&DONE_TWICE.rule_id),
            "{:?}\n{}",
            o.steps,
            why_not(&o)
        );
        // The twenty really went, together, and one went through.
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("20 times at the same instant: 1 went through")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_booking_that_races_is_found() {
        let o = run(Flaws {
            booking_races: true,
            ..Default::default()
        });
        assert_eq!(rule_ids(&o), vec![DONE_TWICE.rule_id], "{:?}", o.steps);
        assert!(!verified_ids(&o).contains(&DONE_TWICE.rule_id));
        assert!(
            o.findings[0].description.contains("went through 20 times"),
            "{}",
            o.findings[0].description
        );
    }

    #[test]
    fn a_booking_that_never_works_is_not_assessed() {
        let o = run(Flaws {
            booking_broken: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(!verified_ids(&o).contains(&DONE_TWICE.rule_id));
        assert!(why_not(&o).contains("None of the 20"), "{}", why_not(&o));
    }

    #[test]
    fn copies_a_rate_limit_turned_away_are_not_credited_as_refused() {
        let o = run(Flaws {
            booking_rate_limited: true,
            ..Default::default()
        });
        assert!(!verified_ids(&o).contains(&DONE_TWICE.rule_id));
        assert!(
            why_not(&o).contains("rate limit turned 19 away"),
            "{}",
            why_not(&o)
        );
    }

    #[test]
    fn a_way_of_reaching_the_app_that_cannot_send_together_is_not_assessed() {
        /// The fake app reached one request at a time, as a runner without `send_at_once` is.
        struct OneAtATime(FakeApp);
        impl Http for OneAtATime {
            fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
                self.0.send(r)
            }
        }
        let acc = accounts();
        let mut app = OneAtATime(FakeApp::new(Flaws::default()));
        app.0
            .users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        let o = super::super::run(&mut app, &users(), &acc, true, &Default::default());
        // A really signed in, so the reason below is the runner's and not a failed sign-in.
        assert!(
            o.steps.iter().any(|s| s.starts_with("signed in as ONCE")),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&DONE_TWICE.rule_id));
        assert!(
            why_not(&o).contains("cannot send requests at the same"),
            "{}",
            why_not(&o)
        );
        assert_eq!(app.0.bookings, 0, "nothing was sent one at a time instead");
    }

    #[test]
    fn a_copy_that_crashed_beside_the_one_that_went_through_is_not_credited() {
        /// A correct app, with the last copy of those sent together crashing instead of refused.
        struct LastCrashes(FakeApp);
        impl Http for LastCrashes {
            fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
                self.0.send(r)
            }
            fn send_at_once(
                &mut self,
                r: &ProbeRequest,
                times: usize,
            ) -> Option<Vec<Option<ProbeResponse>>> {
                let mut answers = self.0.send_at_once(r, times)?;
                if let Some(last) = answers.last_mut() {
                    *last = None;
                }
                Some(answers)
            }
        }
        let acc = accounts();
        let mut app = LastCrashes(FakeApp::new(Flaws::default()));
        app.0
            .users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        let o = super::super::run(&mut app, &users(), &acc, true, &Default::default());
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("1 went through, 1 crashed or did not answer")),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&DONE_TWICE.rule_id));
    }

    #[test]
    fn without_a_once_action_it_is_not_assessed() {
        let mut u = users();
        u.once = None;
        let o = run_against(Flaws::default(), &u);
        assert!(why_not(&o).contains("names no `once`"), "{}", why_not(&o));
    }
}
