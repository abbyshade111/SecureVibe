//! The checks on the sign-in token the app issues itself, when it is a JSON Web Token (a JWT):
//! three parts separated by dots, the first two being JSON that anybody can read and the third a
//! signature over them made with the app's key.
//!
//! Each check sends a token with one thing changed, carried exactly as the real one was and with
//! nothing else, to the private page the sign-in was shown to open. The real token, carried the
//! same way and alone, is sent first as the control: when it does not open the page by itself, the
//! app needs more than the token, a refusal of the changed ones would show nothing, and the checks
//! are not assessed.
//!
//! None of these forges a token the app would have made: that needs the app's key, which `sv`
//! never has. They ask whether the app checks what it should before believing one.

use super::*;

/// The most a run waits for the app's token to run out without `--slow`: a token due to expire
/// within this many seconds is waited for.
const SHORT_WAIT: u64 = 60;
/// How long past its expiry a token is sent again. Many token libraries accept one up to a minute
/// late, to allow for clocks that disagree, which is common practice rather than a fault; asking
/// sooner would accuse every app that allows it.
const LEEWAY: u64 = 65;

/// Where the token travels: the `Authorization` header, or a cookie of this name.
#[derive(Clone, Debug, PartialEq)]
enum Carried {
    Bearer,
    Cookie(String),
}

/// A token read from a sign-in: its two readable parts, and how it travels.
struct Jwt {
    header: serde_json::Map<String, serde_json::Value>,
    payload: serde_json::Map<String, serde_json::Value>,
    signature: String,
    raw: String,
    carried: Carried,
}

impl Jwt {
    /// The token a session carries, the bearer before any cookie, when it is a JWT.
    fn find(session: &Session) -> Option<Jwt> {
        let bearer = session.bearer.iter().map(|t| (Carried::Bearer, t));
        let cookies = session
            .cookies
            .iter()
            .map(|(name, value)| (Carried::Cookie(name.clone()), value));
        bearer
            .chain(cookies)
            .find_map(|(carried, value)| Jwt::read(value, carried))
    }

    /// A value read as a JWT: three parts, the first two JSON objects in base64 for web addresses,
    /// the first naming its signing method (`alg`).
    fn read(value: &str, carried: Carried) -> Option<Jwt> {
        let mut parts = value.split('.');
        let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || signature.is_empty() {
            return None;
        }
        let object = |part: &str| match serde_json::from_slice(&unbase64(part)?) {
            Ok(serde_json::Value::Object(map)) => Some(map),
            _ => None,
        };
        let header = object(header)?;
        header.get("alg")?.as_str()?;
        Some(Jwt {
            header,
            payload: object(payload)?,
            signature: signature.to_owned(),
            raw: value.to_owned(),
            carried,
        })
    }

    /// A session carrying `token` the way this one travels, and nothing else.
    fn session_with(&self, token: String) -> Session {
        let mut session = Session::default();
        match &self.carried {
            Carried::Bearer => session.bearer = Some(token),
            Carried::Cookie(name) => session.cookies.push((name.clone(), token)),
        }
        session
    }

    /// How the token travels, in words.
    fn where_carried(&self) -> String {
        match &self.carried {
            Carried::Bearer => "the `Authorization` header".to_owned(),
            Carried::Cookie(name) => format!("the cookie `{name}`"),
        }
    }

    /// The expiry written in the token, in seconds since 1970.
    fn expiry(&self) -> Option<u64> {
        let exp = self.payload.get("exp")?;
        exp.as_u64()
            .or_else(|| exp.as_f64().filter(|e| *e >= 0.0).map(|e| e as u64))
    }
}

/// One part of a token, written back.
fn part(map: &serde_json::Map<String, serde_json::Value>) -> String {
    crate::browser::base64(&serde_json::to_vec(map).unwrap_or_default(), true)
}

/// Base64 for web addresses, without padding, read back; `None` for anything else.
pub(super) fn unbase64(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut bits: u32 = 0;
    let mut held = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
        }
    }
    Some(out)
}

/// The control: whether the real token, carried alone, opens `confirm`. Says why not when it
/// does not.
fn opens_alone(
    http: &mut dyn Http,
    jwt: &Jwt,
    id: &str,
    confirm: &str,
    ids: &str,
    out: &mut Outcome,
) -> bool {
    let response = http.send(&get(id, confirm, &jwt.session_with(jwt.raw.clone())));
    let opened = ok(&response);
    out.steps.push(format!(
        "asked for {confirm} with the app's own sign-in token alone, in {}: {}",
        jwt.where_carried(),
        if opened { "opened" } else { "refused" }
    ));
    if !opened {
        out.not_assessed.push((
            ids.to_owned(),
            format!(
                "Whether the app checks its own sign-in token: the token alone, in {}, did not \
                 open {confirm} ({}), so the app needs more than the token and a refusal of a \
                 changed one would show nothing.",
                jwt.where_carried(),
                status(&response)
            ),
        ));
    }
    opened
}

/// Sends one changed token: a finding when it opens `confirm`, credit when it is refused.
fn changed_token(
    http: &mut dyn Http,
    jwt: &Jwt,
    (id, token): (&str, String),
    confirm: &str,
    rule: &Rule,
    (what, title): (&str, &str),
    out: &mut Outcome,
) {
    let response = http.send(&get(id, confirm, &jwt.session_with(token)));
    let opened = ok(&response);
    out.steps.push(format!(
        "asked for {confirm} with the app's own sign-in token {what}: {}",
        if opened { "opened" } else { "refused" }
    ));
    if opened {
        out.findings.push(finding(
            rule,
            title,
            Severity::Critical,
            format!(
                "The app's own sign-in token, {what}, opened {confirm} when sent in {}.",
                jwt.where_carried()
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            rule.rule_id,
            rule.requirement_ids,
            format!(
                "the app's own sign-in token, {what}, was refused {confirm} where the real one \
                 opened it"
            ),
        ));
    }
}

/// Whether the app checks its own token's signature (V9.1.1), and refuses one that says it needs
/// none (V9.1.2). With A's session, which these leave as it was.
///
/// The first adds a field (`sv_probe`) to what the token says and keeps the signature: the
/// signature no longer matches, and only an app that checks it notices. The second keeps what the
/// token says, marks it as needing no signature (`alg: none`), and sends none.
pub(super) fn app_token_checks(
    http: &mut dyn Http,
    signed_in: &SignedIn,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V9.1.1, V9.1.2";
    let Some(jwt) = Jwt::find(&signed_in.session) else {
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "Whether the app checks its own sign-in token: telling needs a private page a \
             signed-in user alone can open, and none was shown."
                .to_owned(),
        ));
        return;
    };
    if !opens_alone(http, &jwt, "token-real", confirm, IDS, out) {
        return;
    }
    let header = jwt.raw.split('.').next().unwrap_or_default();
    let mut altered = jwt.payload.clone();
    altered.insert("sv_probe".to_owned(), "altered".into());
    changed_token(
        http,
        &jwt,
        (
            "token-altered",
            format!("{header}.{}.{}", part(&altered), jwt.signature),
        ),
        confirm,
        &APP_TOKEN_UNSIGNED,
        (
            "with a field added to what it says and the signature left as it was",
            "The app believes its sign-in token without checking the signature",
        ),
        out,
    );
    let mut unsigned = jwt.header.clone();
    unsigned.insert("alg".to_owned(), "none".into());
    let payload = jwt.raw.split('.').nth(1).unwrap_or_default();
    changed_token(
        http,
        &jwt,
        ("token-alg-none", format!("{}.{payload}.", part(&unsigned))),
        confirm,
        &APP_TOKEN_ALG_NONE,
        (
            "marked `alg: none` and sent with no signature",
            "The app takes a sign-in token that says it needs no signature",
        ),
        out,
    );
}

/// Whether the app refuses its own token once it has expired (V9.2.1), with a sign-in of its own.
///
/// An expired token cannot be made without the app's key, since the expiry is inside what is
/// signed, so this waits for a real one to run out: the token is shown to open the page, then sent
/// again a little over a minute after its expiry. Only a token due to run out within a minute is
/// waited for, or within 90 minutes with `--slow`; otherwise this is not assessed, saying how long
/// the token lasts. A refusal is credited only when a sign-in begun afterwards still works, so it
/// is not an app that stopped answering.
pub(super) fn app_token_expiry_check(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &Account,
    confirm: Option<&str>,
    slow: bool,
    out: &mut Outcome,
) {
    const ID: &str = "V9.2.1";
    let say = |why: String, out: &mut Outcome| out.not_assessed.push((ID.to_owned(), why));
    let Some(jwt) = sign_in(http, users, "a-token", a, &mut out.steps)
        .and_then(|signed_in| Jwt::find(&signed_in.session))
    else {
        return;
    };
    let Some(confirm) = confirm else {
        say(
            "Whether the app refuses its own sign-in token once it has expired: telling needs a \
             private page a signed-in user alone can open, and none was shown."
                .to_owned(),
            out,
        );
        return;
    };
    if !opens_alone(http, &jwt, "token-before-expiry", confirm, ID, out) {
        return;
    }
    let Some(expiry) = jwt.expiry() else {
        say(
            "Whether the app refuses its own sign-in token once it has expired: the token carries \
             no expiry time (`exp`), so there is nothing to wait for. Unless the app keeps a list \
             of the tokens it has issued, one copied once works for good."
                .to_owned(),
            out,
        );
        return;
    };
    let now = http.now();
    let wait = (expiry + LEEWAY).saturating_sub(now);
    let most = if slow {
        u64::from(MOST_WAIT_MINUTES) * 60
    } else {
        SHORT_WAIT + LEEWAY
    };
    if wait > most {
        say(
            format!(
                "Whether the app refuses its own sign-in token once it has expired: the token \
                 lasts {} more, and this waits for one only when it runs out within a minute{}.",
                duration_text(expiry.saturating_sub(now)),
                if slow {
                    format!(", or within {MOST_WAIT_MINUTES} minutes with `sv run --slow`")
                } else {
                    format!(
                        " (within {MOST_WAIT_MINUTES} minutes with `sv run --slow`, which waits \
                         longer)"
                    )
                }
            ),
            out,
        );
        return;
    }
    if wait > 0 {
        out.steps.push(format!(
            "waited {} for the app's own sign-in token to expire, and a minute more",
            duration_text(wait)
        ));
        http.wait(wait);
    }
    let late = http.now().saturating_sub(expiry);
    let response = http.send(&get(
        "token-expired",
        confirm,
        &jwt.session_with(jwt.raw.clone()),
    ));
    let opened = ok(&response);
    out.steps.push(format!(
        "asked for {confirm} with the app's own sign-in token, {} after its expiry: {}",
        duration_text(late),
        if opened { "opened" } else { "refused" }
    ));
    if opened {
        out.findings.push(finding(
            &APP_TOKEN_EXPIRED,
            "The app still takes its sign-in token after it has expired",
            Severity::High,
            format!(
                "The app's own sign-in token opened {confirm} {} after the expiry written in it.",
                duration_text(late)
            ),
        ));
        return;
    }
    let fresh = sign_in(http, users, "a-token-fresh", a, &mut out.steps)
        .and_then(|signed_in| Jwt::find(&signed_in.session));
    let works = fresh.is_some_and(|fresh| {
        ok(&http.send(&get(
            "token-fresh",
            confirm,
            &fresh.session_with(fresh.raw.clone()),
        )))
    });
    out.steps.push(format!(
        "signed in again and opened {confirm} with the new token: {}",
        if works { "opened" } else { "refused" }
    ));
    if works {
        out.verified.push(crate::Verified::new(
            APP_TOKEN_EXPIRED.rule_id,
            APP_TOKEN_EXPIRED.requirement_ids,
            format!(
                "the app's own sign-in token, which opened {confirm}, was refused {} after its \
                 expiry, while a new sign-in's token still opened it",
                duration_text(late)
            ),
        ));
    } else {
        say(
            "Whether the app refuses its own sign-in token once it has expired: the expired token \
             was refused, but a new sign-in's token then did not open the page either, so the \
             refusal cannot be said to be the expiry."
                .to_owned(),
            out,
        );
    }
}

/// "1 second", "2 minutes 5 seconds".
fn duration_text(seconds: u64) -> String {
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    match (seconds / 60, seconds % 60) {
        (0, s) => plural(s, "second"),
        (m, 0) => plural(m, "minute"),
        (m, s) => format!("{} {}", plural(m, "minute"), plural(s, "second")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::*;

    /// The fake app with its tokens switched on, reached through this, which refuses the one
    /// request named, as an app needing more than the token would, and counts what is sent.
    struct Refusing {
        app: FakeApp,
        refuse: Option<&'static str>,
        sent: Vec<String>,
        /// The names of the headers each request sent, by id.
        headers: Vec<(String, Vec<String>)>,
    }

    impl Http for Refusing {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            self.sent.push(r.id.clone());
            self.headers.push((
                r.id.clone(),
                r.headers.iter().map(|(k, _)| k.clone()).collect(),
            ));
            if self.refuse == Some(r.id.as_str()) {
                return Some(ProbeResponse {
                    id: r.id.clone(),
                    status: 401,
                    headers: Vec::new(),
                    body: "sign in first".into(),
                });
            }
            self.app.send(r)
        }
        fn now(&mut self) -> u64 {
            self.app.now()
        }
        fn wait(&mut self, seconds: u64) {
            self.app.wait(seconds);
        }
    }

    /// securevibe.toml for an app that signs in through JSON and answers with a token.
    fn bearer_users() -> UsersSection {
        let mut u = users();
        u.login = Some(RequestTemplate {
            method: "POST".into(),
            path: "/api/login".into(),
            form: BTreeMap::new(),
            json: [("email", "{user}"), ("password", "{password}")]
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        });
        u.token_field = Some("token".into());
        u.logout = None;
        u.owned = None;
        u
    }

    /// How a run is made: the flaws, whether the token travels as a bearer (or in the cookie),
    /// what else the app does, `--slow`, and the request to refuse.
    struct Run {
        flaws: Flaws,
        bearer: bool,
        setup: fn(&mut FakeApp),
        slow: bool,
        refuse: Option<&'static str>,
    }

    impl Default for Run {
        fn default() -> Self {
            Run {
                flaws: Flaws::default(),
                bearer: true,
                setup: |app| app.jwt_lifetime = Some(30),
                slow: false,
                refuse: None,
            }
        }
    }

    impl Run {
        fn go(&self) -> (Outcome, Vec<String>) {
            let (out, http) = self.go_with();
            (out, http.sent)
        }

        fn go_with(&self) -> (Outcome, Refusing) {
            let mut app = FakeApp::new(self.flaws);
            (self.setup)(&mut app);
            let acc = accounts();
            for (account, admin) in [(&acc.a, false), (&acc.b, false)] {
                app.users
                    .insert(account.user.clone(), (account.password.clone(), admin));
            }
            let admin = acc.admin.clone().unwrap();
            app.users.insert(admin.user, (admin.password, true));
            let mut http = Refusing {
                app,
                refuse: self.refuse,
                sent: Vec::new(),
                headers: Vec::new(),
            };
            let u = if self.bearer { bearer_users() } else { users() };
            let out = run_with(&mut http, &u, &acc, true, &Default::default(), self.slow);
            (out, http)
        }
    }

    const TOKEN_RULES: [&Rule; 3] = [&APP_TOKEN_UNSIGNED, &APP_TOKEN_ALG_NONE, &APP_TOKEN_EXPIRED];

    fn found(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| TOKEN_RULES.iter().any(|r| r.rule_id == *id))
            .collect()
    }

    fn credited(o: &Outcome) -> Vec<&str> {
        verified_ids(o)
            .into_iter()
            .filter(|id| TOKEN_RULES.iter().any(|r| r.rule_id == *id))
            .collect()
    }

    fn not_assessed<'a>(o: &'a Outcome, id: &str) -> Vec<&'a str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.split(", ").any(|i| i == id))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn a_correct_apps_token_passes_each_check_carried_either_way() {
        for bearer in [true, false] {
            let (o, http) = Run {
                bearer,
                ..Default::default()
            }
            .go_with();
            let sent = http.sent;
            // Each token is carried as the real one was, and with nothing else.
            let token_requests: Vec<_> = http
                .headers
                .iter()
                .filter(|(id, _)| id.starts_with("token-"))
                .collect();
            assert_eq!(token_requests.len(), 6, "{token_requests:?}");
            for (id, names) in token_requests {
                let expected = if bearer { "Authorization" } else { "Cookie" };
                assert_eq!(names, &[expected.to_owned()], "bearer {bearer}, {id}");
            }
            assert_eq!(
                found(&o),
                Vec::<&str>::new(),
                "bearer {bearer}: {:?}",
                o.steps
            );
            assert_eq!(
                credited(&o),
                TOKEN_RULES.map(|r| r.rule_id).to_vec(),
                "bearer {bearer}: {:?} {:?}",
                o.not_assessed,
                o.steps
            );
            // Setup: the control was sent and opened, and the token was really waited out.
            assert!(sent.contains(&"token-real".to_owned()), "{sent:?}");
            assert!(
                o.steps
                    .iter()
                    .any(|s| s.contains("token alone") && s.ends_with("opened")),
                "{:?}",
                o.steps
            );
            assert!(
                o.steps
                    .iter()
                    .any(|s| s.contains("1 minute 5 seconds after its expiry")),
                "{:?}",
                o.steps
            );
        }
    }

    #[test]
    fn each_fault_in_checking_the_token_is_found_carried_either_way() {
        let cases: [(&str, Flaws, &[&Rule]); 3] = [
            (
                "signature not checked",
                Flaws {
                    jwt_signature_ignored: true,
                    ..Default::default()
                },
                // Not checking the signature at all takes an unsigned token too.
                &[&APP_TOKEN_UNSIGNED, &APP_TOKEN_ALG_NONE],
            ),
            (
                "alg none taken",
                Flaws {
                    jwt_alg_none_accepted: true,
                    ..Default::default()
                },
                &[&APP_TOKEN_ALG_NONE],
            ),
            (
                "expiry not checked",
                Flaws {
                    jwt_expiry_ignored: true,
                    ..Default::default()
                },
                &[&APP_TOKEN_EXPIRED],
            ),
        ];
        for (name, flaws, expected) in cases {
            for bearer in [true, false] {
                let (o, _) = Run {
                    flaws,
                    bearer,
                    ..Default::default()
                }
                .go();
                let expected: Vec<&str> = expected.iter().map(|r| r.rule_id).collect();
                assert_eq!(
                    found(&o),
                    expected,
                    "{name}, bearer {bearer}: {:?}",
                    o.steps
                );
                // The others are still credited: one fault does not hide the rest.
                assert_eq!(
                    credited(&o).len() + expected.len(),
                    TOKEN_RULES.len(),
                    "{name}, bearer {bearer}: {:?}",
                    o.not_assessed
                );
            }
        }
    }

    #[test]
    fn a_token_taken_within_a_minute_of_its_expiry_is_not_a_fault() {
        // Token libraries commonly allow a minute for clocks that disagree. Asking sooner than
        // that would accuse every app that allows it.
        let (o, _) = Run {
            setup: |app| {
                app.jwt_lifetime = Some(30);
                app.jwt_leeway = 60;
            },
            ..Default::default()
        }
        .go();
        assert_eq!(found(&o), Vec::<&str>::new(), "{:?}", o.steps);
        assert!(
            credited(&o).contains(&APP_TOKEN_EXPIRED.rule_id),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_token_lasting_longer_is_waited_for_only_with_slow_and_only_so_long() {
        let hour = |app: &mut FakeApp| app.jwt_lifetime = Some(3600);
        let (o, sent) = Run {
            setup: hour,
            ..Default::default()
        }
        .go();
        assert!(!sent.contains(&"token-expired".to_owned()), "{sent:?}");
        assert!(!credited(&o).contains(&APP_TOKEN_EXPIRED.rule_id));
        let why = not_assessed(&o, "V9.2.1");
        assert!(
            why.iter()
                .any(|w| w.contains("lasts 60 minutes more") && w.contains("--slow")),
            "{why:?}"
        );
        // The other two do not wait, and are credited all the same.
        assert_eq!(credited(&o).len(), 2, "{:?}", o.not_assessed);

        let (o, _) = Run {
            setup: hour,
            slow: true,
            ..Default::default()
        }
        .go();
        assert!(
            credited(&o).contains(&APP_TOKEN_EXPIRED.rule_id),
            "{:?}",
            o.not_assessed
        );
        let (o, _) = Run {
            setup: hour,
            slow: true,
            flaws: Flaws {
                jwt_expiry_ignored: true,
                ..Default::default()
            },
            ..Default::default()
        }
        .go();
        assert_eq!(found(&o), vec![APP_TOKEN_EXPIRED.rule_id]);

        let (o, sent) = Run {
            setup: |app| app.jwt_lifetime = Some(2 * 3600),
            slow: true,
            ..Default::default()
        }
        .go();
        assert!(!sent.contains(&"token-expired".to_owned()), "{sent:?}");
        let why = not_assessed(&o, "V9.2.1");
        assert!(
            why.iter().any(|w| w.contains("within 90 minutes")),
            "{why:?}"
        );
    }

    #[test]
    fn a_token_with_no_expiry_is_not_assessed_saying_so() {
        let (o, sent) = Run {
            setup: |app| {
                app.jwt_lifetime = Some(30);
                app.jwt_without_expiry = true;
            },
            ..Default::default()
        }
        .go();
        assert!(!sent.contains(&"token-expired".to_owned()), "{sent:?}");
        let why = not_assessed(&o, "V9.2.1");
        assert!(why.iter().any(|w| w.contains("no expiry time")), "{why:?}");
        assert_eq!(credited(&o).len(), 2, "{:?}", o.not_assessed);
    }

    #[test]
    fn a_token_that_does_not_open_the_page_alone_leaves_the_checks_not_assessed() {
        // The control. With it refused, a fault the app really has is not reported either: a
        // refusal of the changed tokens would have shown nothing.
        let flaws = Flaws {
            jwt_signature_ignored: true,
            jwt_expiry_ignored: true,
            ..Default::default()
        };
        let (o, sent) = Run {
            flaws,
            refuse: Some("token-real"),
            ..Default::default()
        }
        .go();
        assert!(sent.contains(&"token-real".to_owned()));
        assert!(!sent.contains(&"token-altered".to_owned()), "{sent:?}");
        assert!(!sent.contains(&"token-alg-none".to_owned()), "{sent:?}");
        assert!(!found(&o).contains(&APP_TOKEN_UNSIGNED.rule_id));
        assert!(!found(&o).contains(&APP_TOKEN_ALG_NONE.rule_id));
        for id in ["V9.1.1", "V9.1.2"] {
            assert!(
                not_assessed(&o, id)
                    .iter()
                    .any(|w| w.contains("needs more than the token")),
                "{id}: {:?}",
                o.not_assessed
            );
        }
        let (o, sent) = Run {
            flaws,
            refuse: Some("token-before-expiry"),
            ..Default::default()
        }
        .go();
        assert!(!sent.contains(&"token-expired".to_owned()), "{sent:?}");
        assert!(!found(&o).contains(&APP_TOKEN_EXPIRED.rule_id));
        assert!(
            not_assessed(&o, "V9.2.1")
                .iter()
                .any(|w| w.contains("needs more than the token")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_expired_token_refused_counts_only_when_a_new_sign_in_still_works() {
        let (o, _) = Run {
            refuse: Some("token-fresh"),
            ..Default::default()
        }
        .go();
        assert!(!credited(&o).contains(&APP_TOKEN_EXPIRED.rule_id));
        assert!(
            not_assessed(&o, "V9.2.1")
                .iter()
                .any(|w| w.contains("cannot be said to be the expiry")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn session_ids_that_are_not_tokens_are_left_alone() {
        for bearer in [true, false] {
            let (o, sent) = Run {
                bearer,
                setup: |_| {},
                ..Default::default()
            }
            .go();
            assert!(!sent.iter().any(|id| id.starts_with("token-")), "{sent:?}");
            assert!(credited(&o).is_empty() && found(&o).is_empty());
            for id in ["V9.1.1", "V9.1.2", "V9.2.1"] {
                assert!(
                    not_assessed(&o, id).is_empty(),
                    "{id}: {:?}",
                    o.not_assessed
                );
            }
        }
    }

    #[test]
    fn a_token_is_read_only_when_it_has_the_shape_of_one() {
        let part = |text: &str| crate::browser::base64(text.as_bytes(), true);
        let (h, p) = (part(r#"{"alg":"HS256"}"#), part(r#"{"sub":"a"}"#));
        assert!(Jwt::read(&format!("{h}.{p}.c2ln"), Carried::Bearer).is_some());
        for not_one in [
            format!("{h}.{p}"),
            format!("{h}.{p}."),
            format!("{h}.{p}.c2ln.more"),
            format!("{}.{p}.c2ln", part(r#"{"typ":"JWT"}"#)),
            format!("{}.{p}.c2ln", part("[1]")),
            format!("{h}.{}.c2ln", part("\"text\"")),
            format!("{h}.{p}!.c2ln"),
            "0123456789abcdef0123456789abcdef".to_owned(),
        ] {
            assert!(Jwt::read(&not_one, Carried::Bearer).is_none(), "{not_one}");
        }
        assert_eq!(
            unbase64(&part("any bytes at all?")).unwrap(),
            b"any bytes at all?"
        );
        assert_eq!(unbase64("YQ==").unwrap(), b"a");
    }

    #[test]
    fn an_expiry_is_read_whole_or_with_a_fraction() {
        // RFC 7519 lets the time be a number with a fraction, and some libraries write one.
        let part = |text: &str| crate::browser::base64(text.as_bytes(), true);
        let h = part(r#"{"alg":"HS256"}"#);
        let expiry = |claims: &str| {
            Jwt::read(&format!("{h}.{}.c2ln", part(claims)), Carried::Bearer)
                .unwrap()
                .expiry()
        };
        assert_eq!(expiry(r#"{"exp":1700000040}"#), Some(1_700_000_040));
        assert_eq!(expiry(r#"{"exp":1700000040.5}"#), Some(1_700_000_040));
        assert_eq!(expiry(r#"{"exp":"soon"}"#), None);
        assert_eq!(expiry(r#"{"exp":-1.5}"#), None);
        assert_eq!(expiry(r#"{"sub":"a"}"#), None);
    }

    #[test]
    fn with_no_private_page_to_ask_the_token_checks_say_so() {
        let mut u = bearer_users();
        u.private.clear();
        let mut app = FakeApp::new(Flaws::default());
        app.jwt_lifetime = Some(30);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let o = run_with(&mut app, &u, &acc, true, &Default::default(), false);
        assert!(credited(&o).is_empty() && found(&o).is_empty());
        for id in ["V9.1.1", "V9.1.2", "V9.2.1"] {
            assert!(
                not_assessed(&o, id)
                    .iter()
                    .any(|w| w.contains("none was shown")),
                "{id}: {:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn durations_are_said_in_words() {
        assert_eq!(duration_text(1), "1 second");
        assert_eq!(duration_text(60), "1 minute");
        assert_eq!(duration_text(125), "2 minutes 5 seconds");
    }
}
