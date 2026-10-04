//! Whether part of a web address the app reads goes into a database query as code (V1.2.4).
//!
//! Only requests that read (GET), with A's session, and only ever in the run `sv` starts itself,
//! on its own copy of the app with its throwaway data: the owner's decision of 4 October 2026, so
//! that an always-true condition can never reach a request that changes data. Only ever a finding.

use super::*;

/// The conditions added: how the value is read, then the always-true and the always-false
/// ending. Each pair is the same length, so an app that only repeats what it was sent answers
/// both alike.
const NUMBER: (&str, &str, &str) = ("a number", " AND 1=1", " AND 1=2");
const QUOTED: (&str, &str, &str) = ("quoted text", "' AND '1'='1", "' AND '1'='2");
const QUOTED_OR: (&str, &str, &str) = ("quoted text, as either-or", "' OR '1'='1", "' OR '1'='2");

/// One place in an address a value can be changed: the address with `{}` where the value goes,
/// the value as it was, and where it is, in words.
struct Spot {
    template: String,
    value: String,
    place: String,
}

/// The last part of a record's address (`/notes/12`: the `12`), when it has one.
fn record_spot(path: &str) -> Option<Spot> {
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let (before, last) = path.rsplit_once('/')?;
    if last.is_empty() {
        return None;
    }
    Some(Spot {
        template: format!(
            "{before}/{{}}{}",
            query.map(|q| format!("?{q}")).unwrap_or_default()
        ),
        value: decode_value(last),
        place: format!("the last part of {path}"),
    })
}

/// Each value in an address's query string (`/search?q=test`: the `test`).
fn query_spots(path: &str) -> Vec<Spot> {
    let Some((base, query)) = path.split_once('?') else {
        return Vec::new();
    };
    let pairs: Vec<&str> = query.split('&').collect();
    pairs
        .iter()
        .enumerate()
        .filter_map(|(i, pair)| {
            let (name, value) = pair.split_once('=')?;
            let mut changed = pairs.clone();
            let slot = format!("{name}={{}}");
            changed[i] = &slot;
            Some(Spot {
                template: format!("{base}?{}", changed.join("&")),
                value: decode_value(value),
                place: format!("`{name}` in {base}"),
            })
        })
        .collect()
}

/// A value from an address, read back from its percent-encoding.
fn decode_value(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A value percent-encoded for any part of an address: everything but letters, digits, and
/// `-._~`.
pub(super) fn encode_value(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// What is compared between two answers: the status and the length. Not the text, which may
/// repeat the condition; the two conditions are the same length, so the length does not change
/// with them.
fn shape(response: &Option<ProbeResponse>) -> Option<(u16, usize)> {
    response
        .as_ref()
        .filter(|r| r.status < 500)
        .map(|r| (r.status, r.body.len()))
}

/// Sends the always-true and always-false versions of one condition at one spot, each twice and
/// in turn. The two answers when each version was answered alike both times, without a crash,
/// and the always-true one was a success; `None` otherwise, as an answer that says nothing.
fn ask(
    http: &mut dyn Http,
    session: &Session,
    spot: &Spot,
    (id, true_end, false_end): (&str, &str, &str),
) -> Option<((u16, usize), (u16, usize))> {
    let at = |end: &str| {
        spot.template
            .replacen("{}", &encode_value(&format!("{}{end}", spot.value)), 1)
    };
    let (true_path, false_path) = (at(true_end), at(false_end));
    let mut answers = Vec::new();
    for round in 1..=2 {
        for (version, path) in [("true", &true_path), ("false", &false_path)] {
            let response = http.send(&get(&format!("sql-{id}-{version}-{round}"), path, session));
            answers.push(shape(&response));
        }
    }
    let [Some(t1), Some(f1), Some(t2), Some(f2)] = answers[..] else {
        return None;
    };
    (t1 == t2 && f1 == f2 && (200..300).contains(&t1.0)).then_some((t1, f1))
}

/// Whether an always-true and an always-false condition, added to a value the app reads from the
/// address, are answered differently: the database reading the input as part of its query.
///
/// The spots are the last part of the address of the record A made, when there is one, and each
/// value in the query string of each private page; a search page listed among the private pages
/// as `/search?q=test` is how its search is asked. A record's last part is tried as a number and
/// as quoted text; a value in a query string as quoted text, as quoted text either-or (which
/// makes a search that found nothing find everything), and as a number when it is one.
pub(super) fn sql_injection_check(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &SignedIn,
    record: Option<&str>,
    out: &mut Outcome,
) {
    let mut asked = Vec::new();
    if let Some(spot) = record.and_then(record_spot) {
        asked.push((spot, vec![NUMBER, QUOTED]));
    }
    for path in &users.private {
        for spot in query_spots(path) {
            let mut forms = vec![QUOTED, QUOTED_OR];
            if !spot.value.is_empty() && spot.value.bytes().all(|b| b.is_ascii_digit()) {
                forms.insert(0, NUMBER);
            }
            asked.push((spot, forms));
        }
    }
    if asked.is_empty() {
        out.steps.push(
            "no address with a value to put a database condition in: neither a record of A's nor \
             a private page with a query string"
                .to_owned(),
        );
        return;
    }
    let mut n = 0;
    for (spot, forms) in &asked {
        let mut differed = None;
        for (words, true_end, false_end) in forms {
            n += 1;
            if let Some(answers) = ask(
                http,
                &a.session,
                spot,
                (&n.to_string(), true_end, false_end),
            ) && answers.0 != answers.1
            {
                differed = Some((*words, *true_end, *false_end, answers));
                break;
            }
        }
        out.steps.push(format!(
            "added an always-true and an always-false database condition to {}: {}",
            spot.place,
            if differed.is_some() {
                "answered differently"
            } else {
                "nothing told apart"
            }
        ));
        if let Some((words, true_end, false_end, ((ts, tl), (fs, fl)))) = differed {
            out.findings.push(finding(
                &SQL_INJECTION,
                "A value in a web address is read into a database query",
                Severity::Critical,
                format!(
                    "Read as {words}, {} with `{true_end}` added was answered {ts} with \
                     {tl} characters, and with `{false_end}` added {fs} with {fl} characters, the \
                     same each of the two times asked. Only a database reading the value as part \
                     of its query tells those apart.",
                    spot.place
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::*;

    /// The fake app, with each answer to one of this check's requests passed through `twist`, and
    /// every request's id, method, and address kept.
    struct Twisting {
        app: FakeApp,
        twist: fn(&ProbeRequest, ProbeResponse, usize) -> Option<ProbeResponse>,
        sent: Vec<(String, String, String)>,
    }

    impl Http for Twisting {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            self.sent
                .push((r.id.clone(), r.method.clone(), r.path.clone()));
            let answer = self.app.send(r)?;
            if r.id.starts_with("sql-") {
                (self.twist)(r, answer, self.sent.len())
            } else {
                Some(answer)
            }
        }
        fn now(&mut self) -> u64 {
            self.app.now()
        }
        fn wait(&mut self, seconds: u64) {
            self.app.wait(seconds);
        }
    }

    /// securevibe.toml with a search page and a record by query string among the private pages.
    fn sql_users() -> UsersSection {
        let mut u = users();
        u.private.push("/search?q=zz".into());
        u.private.push("/note?id=1".into());
        u
    }

    fn run_twisted(
        flaws: Flaws,
        u: &UsersSection,
        twist: fn(&ProbeRequest, ProbeResponse, usize) -> Option<ProbeResponse>,
    ) -> (Outcome, Vec<(String, String, String)>) {
        let mut app = FakeApp::new(flaws);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let mut http = Twisting {
            app,
            twist,
            sent: Vec::new(),
        };
        let out = run(&mut http, u, &acc, true, &Default::default());
        (out, http.sent)
    }

    /// A run against an app already set up.
    fn run_app(mut app: FakeApp, u: &UsersSection) -> Outcome {
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        run(&mut app, u, &acc, true, &Default::default())
    }

    fn plain(flaws: Flaws, u: &UsersSection) -> (Outcome, Vec<(String, String, String)>) {
        run_twisted(flaws, u, |_, answer, _| Some(answer))
    }

    fn sql_findings(o: &Outcome) -> Vec<&Finding> {
        o.findings
            .iter()
            .filter(|f| f.rule_id == SQL_INJECTION.rule_id)
            .collect()
    }

    #[test]
    fn a_correct_app_is_not_accused_and_nothing_is_credited() {
        let (o, sent) = plain(Flaws::default(), &sql_users());
        assert!(sql_findings(&o).is_empty(), "{:?}", sql_findings(&o));
        // Never credit: the check is a finding or nothing.
        assert!(
            !o.verified
                .iter()
                .any(|v| v.check_id == SQL_INJECTION.rule_id)
        );
        // Setup: the record was read back, and every spot was asked.
        assert!(
            o.steps.iter().any(|s| s.starts_with("A created a record")),
            "{:?}",
            o.steps
        );
        let asked: Vec<&String> = o
            .steps
            .iter()
            .filter(|s| s.starts_with("added an always-true"))
            .collect();
        assert_eq!(asked.len(), 3, "{asked:?}");
        assert!(
            asked.iter().all(|s| s.ends_with("nothing told apart")),
            "{asked:?}"
        );
        // Only ever requests that read.
        let ours: Vec<_> = sent
            .iter()
            .filter(|(id, _, _)| id.starts_with("sql-"))
            .collect();
        assert!(!ours.is_empty());
        assert!(
            ours.iter().all(|(_, method, _)| method == "GET"),
            "{ours:?}"
        );
        // Each address as a request line can carry it: the condition percent-encoded.
        assert!(
            ours.iter()
                .all(|(_, _, path)| !path.contains([' ', '\'']) && path.contains("%20")),
            "{ours:?}"
        );
    }

    #[test]
    fn a_value_joined_into_a_query_is_found_wherever_it_is() {
        let cases = [
            (
                "record",
                Flaws {
                    sql_in_record: true,
                    ..Default::default()
                },
                // The record's own address, and the same record by query string, read as a
                // number.
                vec!["the last part of /notes/1", "`id` in /note"],
            ),
            (
                "search",
                Flaws {
                    sql_in_search: true,
                    ..Default::default()
                },
                vec!["`q` in /search"],
            ),
        ];
        for (name, flaws, places) in cases {
            let (o, _) = plain(flaws, &sql_users());
            let found = sql_findings(&o);
            assert_eq!(found.len(), places.len(), "{name}: {found:?}");
            for (finding, place) in found.iter().zip(&places) {
                assert!(
                    finding.description.contains(place),
                    "{name}: {}",
                    finding.description
                );
            }
        }
        // Where the ids are text, the quoted form: in the record's address and in the query
        // string alike.
        let mut app = FakeApp::new(Flaws {
            sql_in_record: true,
            ..Default::default()
        });
        app.ids_are_text = true;
        let found = run_app(app, &sql_users());
        let found = sql_findings(&found);
        assert_eq!(found.len(), 2, "{found:?}");
        for (finding, place) in found
            .iter()
            .zip(["the last part of /notes/1", "`id` in /note"])
        {
            assert!(
                finding.description.contains(place),
                "{}",
                finding.description
            );
            assert!(
                finding.description.contains("as quoted text,"),
                "{}",
                finding.description
            );
        }
    }

    #[test]
    fn a_page_that_changes_by_itself_is_not_told_apart() {
        // Every answer a character longer than the last: nothing is the same twice, so nothing
        // can be told apart, flaw or not.
        let (o, _) = run_twisted(
            Flaws {
                sql_in_search: true,
                sql_in_record: true,
                ..Default::default()
            },
            &sql_users(),
            |_, mut answer, n| {
                answer.body.push_str(&"x".repeat(n));
                Some(answer)
            },
        );
        assert!(sql_findings(&o).is_empty(), "{:?}", sql_findings(&o));
    }

    #[test]
    fn a_crash_or_no_answer_raises_nothing() {
        for silent in [false, true] {
            let twist = if silent {
                (|r: &ProbeRequest, answer: ProbeResponse, _| {
                    (!r.id.contains("-false-")).then_some(answer)
                })
                    as fn(&ProbeRequest, ProbeResponse, usize) -> Option<ProbeResponse>
            } else {
                |r: &ProbeRequest, mut answer: ProbeResponse, _| {
                    if r.id.contains("-false-") {
                        answer.status = 500;
                    }
                    Some(answer)
                }
            };
            let (o, _) = run_twisted(Flaws::default(), &sql_users(), twist);
            assert!(
                sql_findings(&o).is_empty(),
                "silent {silent}: {:?}",
                sql_findings(&o)
            );
        }
    }

    #[test]
    fn two_refusals_told_apart_are_not_a_finding() {
        // The always-true answered 404 and the always-false 403: different, but neither shows a
        // record or a result, so neither says the database read the condition.
        let (o, _) = run_twisted(Flaws::default(), &sql_users(), |r, mut answer, _| {
            answer.status = if r.id.contains("-true-") { 404 } else { 403 };
            Some(answer)
        });
        assert!(sql_findings(&o).is_empty(), "{:?}", sql_findings(&o));
    }

    #[test]
    fn with_nowhere_to_put_a_condition_it_says_so() {
        let mut u = users();
        u.owned = None;
        let (o, sent) = plain(Flaws::default(), &u);
        assert!(!sent.iter().any(|(id, _, _)| id.starts_with("sql-")));
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("no address with a value")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn spots_are_found_in_a_records_address_and_in_query_strings() {
        let spot = record_spot("/notes/12").unwrap();
        assert_eq!(
            (spot.template.as_str(), spot.value.as_str()),
            ("/notes/{}", "12")
        );
        let spot = record_spot("/a/b%20c?x=1").unwrap();
        assert_eq!(
            (spot.template.as_str(), spot.value.as_str()),
            ("/a/{}?x=1", "b c")
        );
        assert!(record_spot("/notes/").is_none());
        assert!(record_spot("notes").is_none());
        let spots = query_spots("/s?q=a+b&page=2&flag");
        let got: Vec<(&str, &str)> = spots
            .iter()
            .map(|s| (s.template.as_str(), s.value.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("/s?q={}&page=2&flag", "a b"),
                ("/s?q=a+b&page={}&flag", "2")
            ]
        );
        assert!(query_spots("/s").is_empty());
        assert_eq!(encode_value("1' AND '1'='1"), "1%27%20AND%20%271%27%3D%271");
        assert_eq!(decode_value("%27%2"), "'%2");
    }

    #[test]
    fn each_pair_of_conditions_is_the_same_length() {
        for (_, t, f) in [NUMBER, QUOTED, QUOTED_OR] {
            assert_eq!(t.len(), f.len(), "{t} {f}");
        }
    }
}
