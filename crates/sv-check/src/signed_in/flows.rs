use super::*;

/// Whether an answer says the flow finished: `completed` in its page, or in the address it sends
/// the browser on to. Only an answer the app accepted counts, so an error page that happens to
/// mention the words does not.
pub(super) fn finished(response: &Option<ProbeResponse>, completed: &str) -> bool {
    response.as_ref().is_some_and(|r| {
        (200..400).contains(&r.status)
            && (r.body.contains(completed)
                || r.headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("location") && v.contains(completed)))
    })
}

/// Sends the steps given, in the order given, in one session; the last answer.
fn take_steps(
    http: &mut dyn Http,
    who: &str,
    steps: &[&RequestTemplate],
    values: &Values,
    session: &mut Session,
    pages: &[String],
) -> Option<ProbeResponse> {
    let mut last = None;
    for (i, step) in steps.iter().enumerate() {
        last = send_template(
            http,
            &format!("flow-{who}-{i}"),
            step,
            values,
            session,
            pages,
        )
        .0;
    }
    last
}

/// Whether a flow of several steps can be skipped through (V2.3.1).
///
/// A goes through every step in order first. That has to end in the owner's `completed`, or
/// nothing can be told: a skip refused by an app whose flow does not work as described is not a
/// skip refused. Then B, signed in afresh so nothing of A's carries over, goes straight to the last
/// step, and — when there is a middle to leave out — signs in afresh again and does the first step
/// and then the last. With a middle, B also tries two wrong orders that leave nothing out by count
/// or by name: the first step done once for every step before the last, and then the last (an app
/// that counts steps rather than knowing which were done); and the steps between first and last,
/// then the first, then the last (an app that asks only whether each step was ever done). Any of
/// them ending in `completed` is a finding. All refused is support for V2.3.1 and no more: it is on
/// the manual-only list, because a few orders refused is not every order refused.
///
/// The last step sent again after the flow finished is not tried: an app's answer cannot tell an
/// order placed again from the same order shown again, the false alarm `probe.action-done-twice`
/// had (DESIGN, "Later, 5 October 2026: two users, not one"). B has finished no flow, so a wrong
/// order ending in `completed` cannot be that.
pub(super) fn flow_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    a: &SignedIn,
    out: &mut Outcome,
) {
    const ID: &str = "V2.3.1";
    let Some(flow) = &users.flow else {
        return;
    };
    if flow.steps.len() < 2 {
        out.not_assessed.push((
            ID.to_owned(),
            "The `flow` in stackvet.toml has fewer than two steps, so there is no step to skip."
                .to_owned(),
        ));
        return;
    }
    if flow.completed.trim().is_empty() {
        out.not_assessed.push((
            ID.to_owned(),
            "The `flow` in stackvet.toml does not say what the last step shows when the flow \
             finished (`completed`), so a skip that worked cannot be told from one that was refused."
                .to_owned(),
        ));
        return;
    }
    let steps: Vec<&RequestTemplate> = flow.steps.iter().collect();
    let last = steps[steps.len() - 1];
    let marker = format!("sv-flow-{}", accounts.spare.get(..8).unwrap_or("0"));
    fn values<'v>(account: &'v Account, marker: &'v str) -> Values<'v> {
        Values {
            user: &account.user,
            password: &account.password,
            marker,
            ..Default::default()
        }
    }

    // The control: every step, in order, as A.
    let mut session = a.session.clone();
    let done = take_steps(
        http,
        "a",
        &steps,
        &values(&accounts.a, &marker),
        &mut session,
        &users.private,
    );
    if !finished(&done, &flow.completed) {
        out.not_assessed.push((
            ID.to_owned(),
            format!(
                "Going through the {} steps in order as A ended in {}, without \"{}\", so the flow \
                 does not finish as stackvet.toml describes and nothing can be told from skipping \
                 a step.",
                steps.len(),
                status(&done),
                flow.completed
            ),
        ));
        return;
    }
    out.steps.push(format!(
        "went through the {} steps of the flow in order as A: finished",
        steps.len()
    ));

    let mut tries: Vec<(&str, Vec<&RequestTemplate>)> = vec![(
        "straight to the last step, with none of the steps before it",
        vec![last],
    )];
    // Each of these is the steps in order when there is no middle, so a two-step flow has only the
    // one skip. The order of the tries matters, because an app may keep where each person is in
    // the flow against the account rather than the session, and then B's fresh session does not
    // start B afresh. Every try with the first step in it can leave B at the second step, after
    // which the steps between first and last, sent first, are no longer the wrong order. So that
    // try goes straight after the one that sends only the last step, which leaves a correct app
    // where it found it; the repeated first step and the skip past the middle follow.
    let middle = &steps[1..steps.len() - 1];
    if !middle.is_empty() {
        tries.push((
            "the steps between the first and the last, then the first, then the last",
            middle.iter().copied().chain([steps[0], last]).collect(),
        ));
        tries.push((
            "the first step once for each step before the last, and then the last",
            std::iter::repeat_n(steps[0], steps.len() - 1)
                .chain([last])
                .collect(),
        ));
        tries.push((
            "the first step and then the last, leaving out the ones between",
            vec![steps[0], last],
        ));
    }
    let mut skipped = Vec::new();
    for (i, (how, these)) in tries.iter().enumerate() {
        let who = format!("flow-b{i}");
        let Some(b) = sign_in(http, users, &who, &accounts.b, &mut out.steps) else {
            out.not_assessed.push((
                ID.to_owned(),
                "B could not sign in again to try skipping a step in a fresh session.".to_owned(),
            ));
            return;
        };
        let mut session = b.session.clone();
        let answer = take_steps(
            http,
            &who,
            these,
            &values(&accounts.b, &marker),
            &mut session,
            &users.private,
        );
        let worked = finished(&answer, &flow.completed);
        out.steps.push(format!(
            "as B, {how}: {}",
            if worked { "finished" } else { "refused" }
        ));
        if worked {
            skipped.push(*how);
        }
    }

    if skipped.is_empty() {
        out.verified.push(crate::Verified::new(
            STEP_SKIPPED.rule_id,
            STEP_SKIPPED.requirement_ids,
            format!(
                "a {}-step flow tried {} way{} out of order, refused each time, where the steps in \
                 order finished",
                steps.len(),
                tries.len(),
                if tries.len() == 1 { "" } else { "s" }
            ),
        )
        // The one flow stackvet.toml names, not every flow the app has (ADR-053, Later).
        .in_part());
    } else {
        out.findings.push(finding(
            &STEP_SKIPPED,
            "The flow can be finished without its steps in order",
            Severity::High,
            format!(
                "The flow ended in \"{}\" for B, going {}. Only going through every step in order \
                 should get there.",
                flow.completed,
                skipped.join(", and also ")
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::*;

    fn run_flow(flaws: Flaws, users: &UsersSection) -> Outcome {
        run_against(flaws, users)
    }

    fn flow_not_assessed(o: &Outcome) -> Option<&str> {
        o.not_assessed
            .iter()
            .find(|(ids, _)| ids == "V2.3.1")
            .map(|(_, why)| why.as_str())
    }

    #[test]
    fn a_flow_that_refuses_both_skips_is_supported_and_found_nothing() {
        let o = run_flow(Flaws::default(), &users());
        assert!(
            !rule_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.steps
        );
        // The one flow stackvet.toml names (ADR-053, Later).
        assert!(credited_in_part(&o, STEP_SKIPPED.rule_id));
        assert!(
            verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}\n{:?}",
            o.steps,
            o.not_assessed
        );
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("in order as A: finished")),
            "the control is not in the steps: {:?}",
            o.steps
        );
        assert_eq!(
            o.steps
                .iter()
                .filter(|s| s.starts_with("as B,") && s.ends_with("refused"))
                .count(),
            4,
            "both skips, the repeated first step, and the middle first: {:?}",
            o.steps
        );
    }

    #[test]
    fn a_step_that_can_be_skipped_is_found_whichever_way_it_is_skipped() {
        for (flaws, how) in [
            (
                Flaws {
                    flow_unguarded: true,
                    ..Default::default()
                },
                "straight to the last step",
            ),
            (
                Flaws {
                    flow_checks_first_only: true,
                    ..Default::default()
                },
                "the first step and then the last",
            ),
        ] {
            let o = run_flow(flaws, &users());
            let f = o
                .findings
                .iter()
                .find(|f| f.rule_id == STEP_SKIPPED.rule_id)
                .unwrap_or_else(|| panic!("{how}: not found: {:?}", o.steps));
            assert!(f.description.contains(how), "{how}: {}", f.description);
            assert!(
                !verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
                "{how}: credited as well"
            );
        }
    }

    #[test]
    fn a_flow_finished_in_the_wrong_order_is_found_by_the_order_that_does_it() {
        // Neither app lets a step be left out, so neither skip finds anything: only the repeated
        // first step finds the app that counts steps, and only the middle first finds the app that
        // asks whether each step was ever done.
        for (flaws, how, not) in [
            (
                Flaws {
                    flow_counts_steps: true,
                    ..Default::default()
                },
                "the first step once for each step before the last",
                "the steps between the first and the last",
            ),
            (
                Flaws {
                    flow_any_order: true,
                    ..Default::default()
                },
                "the steps between the first and the last",
                "the first step once for each step before the last",
            ),
        ] {
            let o = run_flow(flaws, &users());
            let f = o
                .findings
                .iter()
                .find(|f| f.rule_id == STEP_SKIPPED.rule_id)
                .unwrap_or_else(|| panic!("{how}: not found: {:?}", o.steps));
            assert!(f.description.contains(how), "{how}: {}", f.description);
            assert!(!f.description.contains(not), "{how}: {}", f.description);
            assert!(
                !f.description.contains("leaving out") && !f.description.contains("straight to"),
                "{how}: a skip worked too, so this is not the order's own finding: {}",
                f.description
            );
            assert!(
                !verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
                "{how}: credited as well"
            );
        }
    }

    #[test]
    fn each_try_sends_the_steps_it_names_and_no_others() {
        // What each try sends is what makes it the order it says. Read from the app's own record
        // of requests, because an app that keeps its progress against the account can make a try
        // one step short finish anyway, with a step left over from the try before.
        let (o, app) = run_against_keeping(Flaws::default(), &users());
        let sent = |who: &str| -> Vec<String> {
            app.clock_log
                .iter()
                .filter_map(|(id, _)| id.strip_prefix(&format!("flow-{who}-")))
                // The page each step's anti-forgery token is read from is asked for too.
                .filter(|step| step.chars().all(|c| c.is_ascii_digit()))
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(sent("a"), ["0", "1", "2"], "{:?}", o.steps);
        for (who, how_many, how) in [
            ("flow-b0", 1, "straight to the last step"),
            ("flow-b1", 3, "the steps between the first and the last"),
            (
                "flow-b2",
                3,
                "the first step once for each step before the last",
            ),
            ("flow-b3", 2, "the first step and then the last"),
        ] {
            assert_eq!(sent(who).len(), how_many, "{who}: {:?}", sent(who));
            let said = format!("as B, {how}");
            assert!(
                o.steps.iter().any(|s| s.starts_with(&said)),
                "{who} is not {how}: {:?}",
                o.steps
            );
        }
        assert!(sent("flow-b4").is_empty(), "a fifth try: {:?}", o.steps);
    }

    #[test]
    fn a_refusal_that_mentions_the_finishing_words_is_still_a_refusal() {
        // The owner's words can turn up on an error page ("an order is placed only after…"). An
        // answer counts as finished only when the app accepted it.
        let mut u = users();
        u.flow.as_mut().unwrap().completed = "placed".into();
        let o = run_flow(
            Flaws {
                flow_refusal_says_placed: true,
                ..Default::default()
            },
            &u,
        );
        assert!(
            !rule_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_refusal_that_sends_the_browser_back_to_the_start_is_a_refusal() {
        // 303 is an accepted status. Only the owner's words tell a redirect to the finished order
        // from a redirect back to step one.
        let o = run_flow(
            Flaws {
                flow_refusal_redirects: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            !rule_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_flow_that_does_not_finish_in_order_says_so_and_credits_nothing() {
        // Every skip is refused by an app whose flow never finishes. That is not a guarded flow.
        let o = run_flow(
            Flaws {
                flow_broken: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            !verified_ids(&o).contains(&STEP_SKIPPED.rule_id),
            "credited a broken flow"
        );
        assert!(!rule_ids(&o).contains(&STEP_SKIPPED.rule_id));
        let why = flow_not_assessed(&o).expect("V2.3.1 is named as not assessed");
        assert!(why.contains("in order as A"), "{why}");
    }

    #[test]
    fn a_two_step_flow_is_skipped_the_one_way_it_can_be() {
        let mut u = users();
        let flow = u.flow.as_mut().unwrap();
        flow.steps.remove(1);
        flow.steps[1].path = "/checkout/2".into();
        flow.completed = "next step".into();
        let o = run_flow(Flaws::default(), &u);
        let v = o
            .verified
            .iter()
            .find(|v| v.check_id == STEP_SKIPPED.rule_id)
            .unwrap_or_else(|| panic!("{:?}\n{:?}", o.steps, o.not_assessed));
        assert!(v.scope.contains("1 way out of order"), "{}", v.scope);
        assert_eq!(
            o.steps.iter().filter(|s| s.starts_with("as B,")).count(),
            1,
            "with no middle, a repeated first step or the middle first is the flow in order: {:?}",
            o.steps
        );
    }

    #[test]
    fn a_flow_described_too_thinly_to_try_is_not_assessed() {
        let mut one = users();
        one.flow.as_mut().unwrap().steps.truncate(1);
        let mut silent = users();
        silent.flow.as_mut().unwrap().completed = "  ".into();
        for (u, says) in [(one, "fewer than two"), (silent, "completed")] {
            let o = run_flow(Flaws::default(), &u);
            let why = flow_not_assessed(&o).unwrap_or_else(|| panic!("{says}: not named"));
            assert!(why.contains(says), "{why}");
            assert!(!verified_ids(&o).contains(&STEP_SKIPPED.rule_id));
        }
    }

    #[test]
    fn with_no_flow_nothing_is_said_about_v2_3_1() {
        let mut u = users();
        u.flow = None;
        let o = run_flow(Flaws::default(), &u);
        assert!(flow_not_assessed(&o).is_none());
        assert!(!verified_ids(&o).contains(&STEP_SKIPPED.rule_id));
        assert!(!rule_ids(&o).contains(&STEP_SKIPPED.rule_id));
    }
}
