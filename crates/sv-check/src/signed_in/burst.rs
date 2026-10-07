//! A burst of creations by one user, held to the number the owner states (V2.4.1).
//!
//! The same shape as the AI feature's limit (C11.2.2): one more than `[policy] requests-per-minute`
//! records are created through `owned` as B, inside a minute. It runs before the password questions,
//! which can change both A's and B's passwords, and waits a minute afterwards so the limit it set
//! off no longer refuses the checks that follow. Each record carries a marker of its own, so none is
//! refused for repeating a value. All of them going through is the finding; the first going
//! through and the last refused the way a limit refuses (429, or 503 with `Retry-After`) is credit
//! for that one action. A refusal of any other kind is not assessed: a token taken once, a quota,
//! or a value kept unique is refused the same way. Without a
//! stated number nothing is judged: a limit kept by a proxy in production is not in the fenced run,
//! so "no limit seen here" alone would accuse apps that have one.

use super::*;

/// The requirement every burst is about.
const IDS: &str = "V2.4.1";

/// The most a burst sends: a stated limit above this is not tested.
pub(super) const MOST_IN_A_BURST: u32 = 100;

/// Whether the session opens the first private page.
fn still_in(http: &mut dyn Http, users: &UsersSection, when: &str, session: &Session) -> bool {
    users
        .private
        .first()
        .is_some_and(|page| ok(&http.send(&get(&format!("private-burst-{when}"), page, session))))
}

/// Whether an answer is how a limit refuses: 429 Too Many Requests, or 503 Service Unavailable with
/// a `Retry-After` saying when to come back.
fn limit_answer(answer: &Option<ProbeResponse>) -> bool {
    answer.as_ref().is_some_and(|r| {
        r.status == 429
            || (r.status == 503
                && r.headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("retry-after")))
    })
}

pub(super) fn burst_check(
    http: &mut dyn Http,
    users: &UsersSection,
    account: &Account,
    policy: &sv_manifest::PolicySection,
    out: &mut Outcome,
) {
    // `owned`'s create first, then each request `creates` names (the owner's decision, 6 October
    // 2026): each is its own action, judged on its own.
    let creates: Vec<&RequestTemplate> = users
        .owned
        .iter()
        .map(|o| &o.create)
        .chain(users.creates.iter())
        .collect();
    if creates.is_empty() {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether creating records is limited: securevibe.toml lists no `owned` record to \
             create, and no request under `creates`."
                .to_owned(),
        ));
        return;
    }
    let n = match policy.requests_per_minute {
        None => {
            out.not_assessed.push((
                IDS.to_owned(),
                "Whether creating records is limited: say how many records a minute one user \
                 should be able to create, as `requests-per-minute` under [policy] in \
                 securevibe.toml, and this will send one more than that."
                    .to_owned(),
            ));
            return;
        }
        Some(n) if n == 0 || n >= MOST_IN_A_BURST => {
            out.not_assessed.push((
                IDS.to_owned(),
                format!(
                    "[policy] requests-per-minute is {n}; this check sends between 2 and \
                     {MOST_IN_A_BURST} requests, so it cannot hold the app to that number."
                ),
            ));
            return;
        }
        Some(n) => n,
    };
    // Signed in, and shown to be: an app answers a request from nobody with a redirect to its
    // sign-in page, which would read as each record going through.
    let signed_in = sign_in(http, users, "burst", account, &mut out.steps)
        .map(|s| s.session)
        .filter(|session| still_in(http, users, "before", session));
    let Some(mut session) = signed_in else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether creating records is limited: the second user could not sign in, or was not \
             shown a private page once signed in."
                .to_owned(),
        ));
        return;
    };
    for create in creates {
        burst_one(http, users, &mut session, create, n, out);
    }
}

/// One burst through `create`, signed in as `session`, against the `n` a minute securevibe.toml
/// states: the finding, the credit, or why neither, for this action alone.
fn burst_one(
    http: &mut dyn Http,
    users: &UsersSection,
    session: &mut Session,
    create: &RequestTemplate,
    n: u32,
    out: &mut Outcome,
) {
    // A minute's pause first, so the records the checks above created no longer count against a
    // limit per minute.
    http.wait(61);
    // Each record carries a marker of its own: one repeated would be refused by an app that keeps
    // the value unique, and that refusal would read as a limit.
    let values = with_token(
        http,
        "burst-create",
        create,
        &Values::default(),
        session,
        &users.private,
    );
    let markers: Vec<String> = (1..=n + 1)
        .map(|i| format!("sv-probe-burst-5e2b-{i}"))
        .collect();
    let began = http.now();
    let answers: Vec<Option<ProbeResponse>> = markers
        .iter()
        .enumerate()
        .map(|(i, marker)| {
            let v = Values {
                marker,
                ..values.clone()
            };
            http.send(&request(&format!("burst-{}", i + 1), create, &v, session))
        })
        .collect();
    let took = http.now().saturating_sub(began);
    let still = still_in(http, users, "after", session);
    // The limit this set off, left to lapse before anything else is asked.
    http.wait(61);
    let through = answers.iter().filter(|a| accepted(a)).count();
    let crashed = answers
        .iter()
        .filter(|a| a.as_ref().is_none_or(|r| r.status >= 500) && !limit_answer(a))
        .count();
    let first = answers.first().is_some_and(accepted);
    let last = answers.last().is_some_and(accepted);
    let sent = n as usize + 1;
    out.steps.push(format!(
        "created {sent} records through {} in {took} second{}: {through} went through, {crashed} \
         crashed or did not answer",
        create.path,
        if took == 1 { "" } else { "s" }
    ));
    let say = |why: String, out: &mut Outcome| out.not_assessed.push((IDS.to_owned(), why));
    if !still {
        say(
            "Whether creating records is limited: after the burst the session no longer opened a \
             private page, so the answers may be the app sending somebody signed out to its \
             sign-in page rather than records going through."
                .to_owned(),
            out,
        );
    } else if !first {
        say(
            format!(
                "Whether creating records is limited: the first of the burst through {} was \
                 refused ({}), so a refusal later on shows nothing.",
                create.path,
                status(&answers[0])
            ),
            out,
        );
    } else if took > 55 {
        say(
            format!(
                "Whether creating records is limited: sending {sent} took {took} seconds, longer \
                 than the minute a limit per minute counts over."
            ),
            out,
        );
    } else if through == sent {
        out.findings.push(finding(
            &CREATE_UNLIMITED,
            "One user can create records without limit",
            Severity::Medium,
            format!(
                "securevibe.toml says one user should be able to create at most {n} records a \
                 minute. All {sent} sent through {} within {took} seconds went through.",
                create.path
            ),
        ));
    } else if crashed > 0 {
        say(
            format!(
                "Whether creating records is limited: {crashed} of the {sent} sent through {} \
                 crashed or got no answer rather than being refused, and a crash is not a limit.",
                create.path
            ),
            out,
        );
    } else if !last && !answers.last().is_some_and(limit_answer) {
        say(
            format!(
                "Whether creating records is limited: the last of the {sent} sent through {} was \
                 refused with {}, which is not how a limit answers (429 Too Many Requests, or 503 \
                 with Retry-After). A value the app keeps unique, a token used up, or a quota \
                 reached is refused the same way.",
                create.path,
                status(answers.last().unwrap_or(&None))
            ),
            out,
        );
    } else if last {
        say(
            format!(
                "Whether creating records is limited: {through} of {sent} went through, the last \
                 among them, so what refused the others was not a limit that stayed shut."
            ),
            out,
        );
    } else {
        out.verified.push(crate::Verified::new(
            CREATE_UNLIMITED.rule_id,
            CREATE_UNLIMITED.requirement_ids,
            format!(
                "{sent} records created through {} within {took} seconds by one user: the first \
                 went through and the last was refused, against the {n} a minute securevibe.toml \
                 states. One action, not every function V2.4.1 names",
                create.path
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::*;

    /// The scripted app, with `limit` notes a minute or none, against a stated `per_minute`.
    fn run_with_limit(limit: Option<u32>, per_minute: Option<u32>) -> (Outcome, FakeApp) {
        run_with(limit, per_minute, false)
    }

    fn run_with(limit: Option<u32>, per_minute: Option<u32>, leaks: bool) -> (Outcome, FakeApp) {
        let acc = accounts();
        let mut app = FakeApp::new(Flaws::default());
        app.notes_per_minute = limit;
        app.notes_limit_leaks = leaks;
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let policy = sv_manifest::PolicySection {
            requests_per_minute: per_minute,
            ..Default::default()
        };
        let o = super::super::run(&mut app, &users(), &acc, true, &policy);
        (o, app)
    }

    /// The scripted app, changed by `adjust`, against 10 a minute stated.
    fn run_adjusted(adjust: impl FnOnce(&mut FakeApp)) -> Outcome {
        let acc = accounts();
        let mut app = FakeApp::new(Flaws::default());
        adjust(&mut app);
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let policy = sv_manifest::PolicySection {
            requests_per_minute: Some(10),
            ..Default::default()
        };
        super::super::run(&mut app, &users(), &acc, true, &policy)
    }

    #[test]
    fn a_refusal_that_is_not_a_limit_is_not_credited_as_one() {
        // No limit at all, and each refuses the second record on for another reason: a value it
        // keeps unique, or a token it takes once.
        for (what, adjust) in [
            (
                "repeats",
                (|a: &mut FakeApp| a.refuses_repeats = true) as fn(&mut FakeApp),
            ),
            ("single-use tokens", |a: &mut FakeApp| {
                a.single_use_tokens = true
            }),
        ] {
            let o = run_adjusted(adjust);
            assert!(
                !verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
                "{what}: credited\n{:#?}",
                o.steps
            );
            if what == "repeats" {
                // Each record its own marker: all eleven go through, and that is the finding.
                assert!(
                    rule_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
                    "{what}: {:#?}",
                    o.steps
                );
            } else {
                assert!(
                    why_not(&o).contains("not how a limit answers"),
                    "{what}: {}",
                    why_not(&o)
                );
            }
        }
        // The control: an app that refuses repeats and keeps a limit at the stated number is
        // credited, since every record now differs.
        let o = run_adjusted(|a| {
            a.refuses_repeats = true;
            a.notes_per_minute = Some(10);
        });
        assert!(
            verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
            "{}\n{:#?}",
            why_not(&o),
            o.steps
        );
        // A token taken once refuses the second record before a limit could: not assessed, never
        // credited, whatever the limit.
        let o = run_adjusted(|a| {
            a.single_use_tokens = true;
            a.notes_per_minute = Some(10);
        });
        assert!(!verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id));
        assert!(
            why_not(&o).contains("not how a limit answers"),
            "{}",
            why_not(&o)
        );
    }

    #[test]
    fn only_429_or_503_with_retry_after_is_a_limit() {
        for (answer, credited) in [
            ((429, true), true),
            ((429, false), true),
            ((503, true), true),
            ((503, false), false),
            ((403, true), false),
            ((409, false), false),
            ((400, false), false),
        ] {
            let o = run_adjusted(|a| {
                a.notes_per_minute = Some(10);
                a.notes_limit_answer = Some(answer);
            });
            assert_eq!(
                verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
                credited,
                "{answer:?}: {}\n{:#?}",
                why_not(&o),
                o.steps
            );
            assert!(
                !rule_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
                "{answer:?}"
            );
            if !credited {
                assert!(!why_not(&o).is_empty(), "{answer:?}: nothing said");
            }
        }
    }

    fn why_not(o: &Outcome) -> &str {
        o.not_assessed
            .iter()
            .find(|(ids, _)| ids == "V2.4.1")
            .map_or("", |(_, why)| why.as_str())
    }

    #[test]
    fn a_limit_at_the_stated_number_is_credited() {
        let (o, _) = run_with_limit(Some(10), Some(10));
        assert!(
            !rule_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
            "{:?}",
            o.findings
        );
        assert!(
            verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
            "{:?}\n{}",
            o.steps,
            why_not(&o)
        );
        // Eleven sent, ten through: the limiter's 429 was read, not waited out and sent again.
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("created 11 records") && s.contains("10 went through")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn no_limit_against_a_stated_number_is_found() {
        let (o, _) = run_with_limit(None, Some(10));
        assert_eq!(
            rule_ids(&o),
            vec![CREATE_UNLIMITED.rule_id],
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id));
        assert!(
            o.findings[0].description.contains("All 11 sent"),
            "{}",
            o.findings[0].description
        );
    }

    #[test]
    fn a_limit_above_the_stated_number_is_found() {
        // The app lets 30 through where the owner says 10: the eleventh is still taken.
        let (o, _) = run_with_limit(Some(30), Some(10));
        assert_eq!(
            rule_ids(&o),
            vec![CREATE_UNLIMITED.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn without_a_stated_number_nothing_is_sent_or_judged() {
        let (o, app) = run_with_limit(None, None);
        assert!(!rule_ids(&o).contains(&CREATE_UNLIMITED.rule_id));
        assert!(!verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id));
        assert!(
            why_not(&o).contains("requests-per-minute"),
            "{}",
            why_not(&o)
        );
        assert!(
            !app.clock_log.iter().any(|(id, _)| id.starts_with("burst-")),
            "no burst was sent"
        );
    }

    #[test]
    fn a_limit_that_shuts_before_the_first_is_not_credited() {
        // A limit that refuses every record: the burst's first is refused too.
        let (o, _) = run_with_limit(Some(0), Some(10));
        assert!(!verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id));
        assert!(
            why_not(&o).contains("the first of the burst"),
            "{}",
            why_not(&o)
        );
    }

    #[test]
    fn a_session_lost_during_the_burst_is_not_read_as_records_going_through() {
        /// From the burst's third record on, the app has forgotten the session: it sends the
        /// browser to sign in, as an app does for somebody signed out.
        struct Forgets(FakeApp);
        impl Http for Forgets {
            fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
                let forgotten = r.id == "private-burst-after"
                    || r.id
                        .strip_prefix("burst-")
                        .and_then(|n| n.parse::<u32>().ok())
                        .is_some_and(|n| n >= 3);
                if forgotten {
                    return Some(ProbeResponse {
                        id: r.id.clone(),
                        status: 302,
                        headers: vec![("location".into(), "/login".into())],
                        body: String::new(),
                    });
                }
                self.0.send(r)
            }
            fn now(&mut self) -> u64 {
                self.0.now()
            }
            fn wait(&mut self, seconds: u64) {
                self.0.wait(seconds);
            }
        }
        let acc = accounts();
        let mut app = Forgets(FakeApp::new(Flaws::default()));
        for who in [&acc.a, &acc.b] {
            app.0
                .users
                .insert(who.user.clone(), (who.password.clone(), false));
        }
        let policy = sv_manifest::PolicySection {
            requests_per_minute: Some(10),
            ..Default::default()
        };
        let o = super::super::run(&mut app, &users(), &acc, true, &policy);
        assert!(
            o.steps.iter().any(|s| s.contains("created 11 records")),
            "{:?}",
            o.steps
        );
        assert!(
            !rule_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
            "{:?}",
            o.findings
        );
        assert!(why_not(&o).contains("no longer opened"), "{}", why_not(&o));
    }

    #[test]
    fn a_limit_that_lets_the_last_through_is_not_credited() {
        // Nine through, the tenth refused, the eleventh through again.
        let (o, _) = run_with(Some(9), Some(10), true);
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("created 11 records") && s.contains("10 went through")),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&CREATE_UNLIMITED.rule_id));
        assert!(
            why_not(&o).contains("the last among them"),
            "{}",
            why_not(&o)
        );
    }

    #[test]
    fn a_stated_number_out_of_range_is_not_tested() {
        let (o, _) = run_with_limit(None, Some(MOST_IN_A_BURST));
        assert!(!rule_ids(&o).contains(&CREATE_UNLIMITED.rule_id));
        assert!(
            why_not(&o).contains("cannot hold the app"),
            "{}",
            why_not(&o)
        );
    }

    /// The scripted app with notes held to `notes` a minute and comments to `comments`, against 10 a
    /// minute stated, with `users` adjusted by `adjust`.
    fn run_both(
        notes: Option<u32>,
        comments: Option<u32>,
        adjust: impl FnOnce(&mut UsersSection),
    ) -> Outcome {
        let acc = accounts();
        let mut app = FakeApp::new(Flaws::default());
        app.notes_per_minute = notes;
        app.comments_per_minute = comments;
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let policy = sv_manifest::PolicySection {
            requests_per_minute: Some(10),
            ..Default::default()
        };
        let mut u = users();
        adjust(&mut u);
        super::super::run(&mut app, &u, &acc, true, &policy)
    }

    fn comments() -> RequestTemplate {
        RequestTemplate {
            method: "POST".into(),
            path: "/comments".into(),
            form: [("text", "{marker}")]
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            json: BTreeMap::new(),
        }
    }

    #[test]
    fn each_request_creates_names_is_held_to_the_stated_limit_on_its_own() {
        // The owner's decision, 6 October 2026: functions other than `owned`, through `creates`.
        // Notes are limited and comments are not: one credit for notes, one finding for comments.
        let o = run_both(Some(10), None, |u| u.creates = vec![comments()]);
        let findings: Vec<&Finding> = o
            .findings
            .iter()
            .filter(|f| f.rule_id == CREATE_UNLIMITED.rule_id)
            .collect();
        assert_eq!(findings.len(), 1, "{:?}", o.findings);
        assert!(
            findings[0].description.contains("/comments"),
            "{}",
            findings[0].description
        );
        let credits: Vec<&crate::Verified> = o
            .verified
            .iter()
            .filter(|v| v.check_id == CREATE_UNLIMITED.rule_id)
            .collect();
        assert_eq!(credits.len(), 1, "{:?}", o.verified);
        assert!(credits[0].scope.contains("/notes"), "{}", credits[0].scope);
        // The control: comments limited too, and both are credited, each for itself.
        let o = run_both(Some(10), Some(10), |u| u.creates = vec![comments()]);
        assert!(
            !rule_ids(&o).contains(&CREATE_UNLIMITED.rule_id),
            "{:?}",
            o.findings
        );
        let scopes: Vec<&str> = o
            .verified
            .iter()
            .filter(|v| v.check_id == CREATE_UNLIMITED.rule_id)
            .map(|v| v.scope.as_str())
            .collect();
        assert_eq!(scopes.len(), 2, "{scopes:?}");
        assert!(scopes[1].contains("/comments"), "{scopes:?}");
    }

    #[test]
    fn creates_alone_is_enough_and_neither_is_said() {
        // With no `owned`, a request under `creates` is still asked.
        let o = run_both(None, None, |u| {
            u.owned = None;
            u.creates = vec![comments()];
        });
        assert!(
            o.findings
                .iter()
                .any(|f| f.rule_id == CREATE_UNLIMITED.rule_id
                    && f.description.contains("/comments")),
            "{:?}",
            o.findings
        );
        // With neither, the report says what to list.
        let o = run_both(None, None, |u| u.owned = None);
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V2.4.1" && why.contains("no request under `creates`")),
            "{:?}",
            o.not_assessed
        );
    }
}
