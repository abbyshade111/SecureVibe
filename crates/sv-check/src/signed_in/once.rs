//! An action that should go through only once, sent many times at the same instant (V2.3.4).
//!
//! The owner names it in `once`: booking the last seat, redeeming a one-time code. Two test users,
//! A and B, each read the page's token once, and then the request goes out `AT_ONCE` times
//! together, half as A and half as B, taking turns, each over its own connection. An app that reads
//! "is one left?" and then writes "taken" without holding a lock in between lets both through; one
//! that does it in a single step lets one of them through.
//!
//! Two users, since 5 October 2026 (the owner's decision): with every copy sent as one user, an app
//! that answers a repeat from the person who already holds the seat with "Booked" again, changing
//! nothing, was counted as booking it twenty times. An app's answer cannot tell "taken now" from
//! "already yours", but two different people cannot both have the one thing there was.

use super::*;

/// How many copies are sent together, half from each user. Enough that a gap between reading and
/// writing of a few milliseconds is likely to be hit, and few enough to be gentle on a small app.
pub(super) const AT_ONCE: usize = 20;

pub(super) fn once_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
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
    let mut copies = Vec::new();
    let mut sessions = Vec::new();
    for (who, account) in [("once", &accounts.a), ("once-b", &accounts.b)] {
        let which = if who == "once" { "first" } else { "second" };
        let Some(signed_in) = sign_in(http, users, who, account, &mut out.steps) else {
            out.not_assessed.push((
                IDS.to_owned(),
                format!(
                    "Whether {} can go through twice: the {} user could not sign in to send it, \
                     and copies sent by one user cannot tell a second booking from a repeat of \
                     their own.",
                    once.path, which
                ),
            ));
            return;
        };
        let mut session = signed_in.session;
        // `sign_in` gives back a session whatever the app answered; this shows it is signed in.
        if let Some(why) = signed_in_now(http, users, &session) {
            out.not_assessed.push((
                IDS.to_owned(),
                format!(
                    "Whether {} can go through twice: the {which} user could not be shown signed \
                     in ({why}), and copies sent by one user cannot tell a second booking from a \
                     repeat of their own.",
                    once.path
                ),
            ));
            return;
        }
        let values = Values {
            user: &account.user,
            password: &account.password,
            marker: "sv-probe-once-7d1a",
            ..Default::default()
        };
        let id = if who == "once" { "once-a" } else { who };
        let template = once.request();
        let values = with_token(http, id, &template, &values, &mut session, &users.private);
        // Without the token it asks for, every copy would be refused for that, and a refusal of
        // the other user's copies would show nothing about the seat.
        if uses_csrf(&template) && values.csrf.is_none() {
            out.not_assessed.push((
                IDS.to_owned(),
                format!(
                    "Whether {} can go through twice: the page's anti-forgery token could not be \
                     read for the {which} user, so a refusal of their copies would show nothing.",
                    once.path
                ),
            ));
            return;
        }
        copies.push(request(id, &template, &values, &session));
        sessions.push(session);
    }
    // A's and B's copies take turns, so neither user's all leave first.
    let requests: Vec<ProbeRequest> = (0..AT_ONCE).map(|i| copies[i % 2].clone()).collect();
    let Some(answers) = http.send_together(&requests) else {
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
    let went_through = |user: usize| {
        answers
            .iter()
            .skip(user)
            .step_by(2)
            .filter(|a| super::flows::finished(a, &once.completed))
            .count()
    };
    let (by_a, by_b) = (went_through(0), went_through(1));
    let each = AT_ONCE / 2;
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
        "sent {} to {} {AT_ONCE} times at the same instant, {each} as A and {each} as B: {by_a} of \
         A's went through and {by_b} of B's, {unanswered} crashed or did not answer, {limited} were \
         turned away by a rate limit",
        once.method, once.path
    ));
    if by_a > 0 && by_b > 0 {
        out.findings.push(finding(
            &DONE_TWICE,
            "An action that should go through once went through for two people",
            Severity::High,
            format!(
                "Sent {AT_ONCE} times at the same instant, {each} copies as each of two test users, \
                 {} {} went through for both of them: {by_a} of the first user's copies and {by_b} \
                 of the second's (the answer said \"{}\"). Securevibe.toml names it as an action \
                 that should go through only once.",
                once.method, once.path, once.completed
            ),
        ));
        return;
    }
    let (holder, got) = if by_a > 0 {
        ("first", by_a)
    } else {
        ("second", by_b)
    };
    if got == 0 {
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
                "Of the {AT_ONCE} copies of {} {} sent at the same instant, only the {holder} \
                 user's went through, and a rate limit turned {limited} away (429) before they \
                 reached the action. The race was not run between them, so this is not credited. A \
                 limit is not a lock: copies under it can still race.",
                once.method, once.path
            ),
        ));
    } else if unanswered > 0 {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Of the {AT_ONCE} copies of {} {} sent at the same instant, only the {holder} \
                 user's went through, and {unanswered} crashed or did not answer rather than being \
                 refused. A crash is not an answer to whether it would have gone through too, so \
                 this is not credited.",
                once.method, once.path
            ),
        ));
    } else if let Some(why) = signed_in_now(http, users, &sessions[usize::from(by_a > 0)]) {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "Of the {AT_ONCE} copies of {} {} sent at the same instant, only the {holder} \
                 user's went through, but the other user's session no longer showed signed in \
                 afterwards ({why}), so their copies may have been refused \
                 for not being signed in rather than because the thing was taken. This is not \
                 credited.",
                once.method, once.path
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            DONE_TWICE.rule_id,
            DONE_TWICE.requirement_ids,
            format!(
                "{} {} sent {AT_ONCE} times at the same instant, {each} copies as each of two test \
                 users: it went through for the {holder} user only ({got} of their copies said so, \
                 repeats of their own taking it), and every copy from the other was refused. One \
                 race, tried once",
                once.method, once.path
            ),
        ));
    }
}

/// Why a session cannot be shown signed in: `None` when it opens the first private page, the reason
/// otherwise. Asked of each user before the copies go, and of the user whose copies were refused
/// afterwards, so a refusal for not being signed in is never read as the thing being taken.
fn signed_in_now(http: &mut dyn Http, users: &UsersSection, session: &Session) -> Option<String> {
    let Some(page) = users.private.first() else {
        return Some("securevibe.toml names no `private` page to show it by".to_owned());
    };
    (!ok(&http.send(&get("private-once", page, session)))).then(|| format!("{page} did not open"))
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
        // The twenty really went, together, half from each user, and one went through.
        assert!(
            o.steps.iter().any(|s| s.contains(
                "20 times at the same instant, 10 as A and 10 as B: 1 of A's went through and 0 \
                 of B's"
            )),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_repeat_the_holder_is_told_went_through_is_not_a_second_booking() {
        // The false alarm of 4 October 2026: a correct app answers a repeat from the person who
        // already holds the seat with "Booked" again, and every copy came from that person.
        let o = run(Flaws {
            booking_repeat_says_booked: true,
            ..Default::default()
        });
        assert!(
            !rule_ids(&o).contains(&DONE_TWICE.rule_id),
            "{:?}\n{:?}",
            o.findings,
            o.steps
        );
        assert!(
            verified_ids(&o).contains(&DONE_TWICE.rule_id),
            "{:?}\n{}",
            o.steps,
            why_not(&o)
        );
        // The setup: the holder really was told so more than once, and the other user never was.
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("10 of A's went through and 0 of B's")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_booking_that_races_is_found_even_when_repeats_say_booked() {
        let o = run(Flaws {
            booking_races: true,
            booking_repeat_says_booked: true,
            ..Default::default()
        });
        assert_eq!(rule_ids(&o), vec![DONE_TWICE.rule_id], "{:?}", o.steps);
    }

    #[test]
    fn without_the_second_user_it_is_not_assessed_rather_than_counted_as_one() {
        let acc = accounts();
        let mut app = FakeApp::new(Flaws {
            booking_repeat_says_booked: true,
            ..Default::default()
        });
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        let o = super::super::run(&mut app, &users(), &acc, true, &Default::default());
        assert!(o.findings.iter().all(|f| f.rule_id != DONE_TWICE.rule_id));
        assert!(!verified_ids(&o).contains(&DONE_TWICE.rule_id));
        assert!(
            why_not(&o).contains("the second user could not be shown signed in"),
            "{}",
            why_not(&o)
        );
        assert_eq!(app.bookings, 0, "nothing was sent as one user instead");
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
            o.findings[0]
                .description
                .contains("went through for both of them: 10 of the first user's copies and 10"),
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
        /// The fake app reached one request at a time, as a runner without `send_together` is.
        struct OneAtATime(FakeApp);
        impl Http for OneAtATime {
            fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
                self.0.send(r)
            }
        }
        let acc = accounts();
        let mut app = OneAtATime(FakeApp::new(Flaws::default()));
        for account in [&acc.a, &acc.b] {
            app.0
                .users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
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
            fn send_together(&mut self, rs: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
                let mut answers = self.0.send_together(rs)?;
                if let Some(last) = answers.last_mut() {
                    *last = None;
                }
                Some(answers)
            }
        }
        let acc = accounts();
        let mut app = LastCrashes(FakeApp::new(Flaws::default()));
        for account in [&acc.a, &acc.b] {
            app.0
                .users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let o = super::super::run(&mut app, &users(), &acc, true, &Default::default());
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("0 of B's, 1 crashed or did not answer")),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&DONE_TWICE.rule_id));
    }

    #[test]
    fn the_refused_user_must_still_be_signed_in_after_the_race() {
        /// A correct app, where B's session stops opening the private page once the copies have
        /// gone. A sends first and takes the seat, so B's refusals may have been for being signed
        /// out. The private page is asked as A, then as B, before the copies go.
        struct SignedOutAfter {
            app: FakeApp,
            raced: bool,
            seen: Vec<String>,
        }
        impl Http for SignedOutAfter {
            fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
                if r.id == "private-once" {
                    let cookie = r
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                        .map_or(String::new(), |(_, v)| v.clone());
                    if !self.raced {
                        self.seen.push(cookie);
                    } else if self.seen.get(1) == Some(&cookie) {
                        return Some(ProbeResponse {
                            id: r.id.clone(),
                            status: 302,
                            headers: vec![("Location".into(), "/login".into())],
                            body: String::new(),
                        });
                    }
                }
                self.app.send(r)
            }
            fn send_together(&mut self, rs: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
                self.raced = true;
                self.app.send_together(rs)
            }
        }
        let acc = accounts();
        let mut http = SignedOutAfter {
            app: FakeApp::new(Flaws::default()),
            raced: false,
            seen: Vec::new(),
        };
        for account in [&acc.a, &acc.b] {
            http.app
                .users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let o = super::super::run(&mut http, &users(), &acc, true, &Default::default());
        // The setup: both users were shown signed in, the race ran, and A got the seat.
        assert_eq!(http.seen.len(), 2, "{:?}", o.steps);
        assert_ne!(http.seen[0], http.seen[1], "two sessions, not one");
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("1 of A's went through and 0 of B's")),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&DONE_TWICE.rule_id));
        assert!(
            why_not(&o).contains("no longer showed signed in afterwards"),
            "{}",
            why_not(&o)
        );
    }

    #[test]
    fn without_a_once_action_it_is_not_assessed() {
        let mut u = users();
        u.once = None;
        let o = run_against(Flaws::default(), &u);
        assert!(why_not(&o).contains("names no `once`"), "{}", why_not(&o));
    }
}
