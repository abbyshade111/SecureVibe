use super::*;

/// The most `sv run --slow` waits, in all. A lifetime stated longer is not waited out.
pub(super) const MOST_WAIT_MINUTES: u32 = 90;

/// Whether sessions end when the owner says they should (V7.3.1, V7.3.2), which means waiting.
///
/// Two sessions of A's, both shown open first. One is left alone; the other is kept busy, a request
/// every so often. After the idle timeout and a minute more, the idle one must be refused and the
/// busy one must still work — the busy one is what shows the idle one was refused for being idle,
/// rather than because every session died or the app stopped answering. After the lifetime and a
/// minute more, the busy one must be refused too, and a sign-in begun then must still work.
///
/// The numbers are the owner's (`idle-timeout-minutes`, `session-lifetime-minutes`), as
/// `failed-sign-ins` is: the requirements ask for timeouts "according to documented security
/// decisions", and a number can be held to where prose cannot. Only with `--slow`.
///
/// Says whether it waited. Every session made before the wait sat unused through it, A's main one
/// included, so a caller that waited signs A in again before anything else uses that session.
pub(super) fn session_timeout_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &Account,
    confirm: Option<&str>,
    policy: &sv_manifest::PolicySection,
    slow: bool,
    out: &mut Outcome,
) -> bool {
    let idle = policy.idle_timeout_minutes;
    let lifetime = policy.session_lifetime_minutes;
    let say = |id: &str, why: String, out: &mut Outcome| {
        out.not_assessed.push((id.to_owned(), why));
    };
    if idle.is_none() && lifetime.is_none() {
        say(
            "V7.3.1, V7.3.2",
            "Whether sessions time out: say after how long, as `idle-timeout-minutes` and \
             `session-lifetime-minutes` under [policy] in securevibe.toml, and run `sv run --slow`, \
             which waits that long and then asks."
                .to_owned(),
            out,
        );
        return false;
    }
    if !slow {
        say(
            "V7.3.1, V7.3.2",
            "Whether sessions time out when securevibe.toml says they should: that means waiting, \
             so it is asked only by `sv run --slow`."
                .to_owned(),
            out,
        );
        return false;
    }
    let Some(confirm) = confirm else {
        say(
            "V7.3.1, V7.3.2",
            "Whether sessions time out: telling needs a private page a signed-in user alone can \
             open, and none was shown."
                .to_owned(),
            out,
        );
        return false;
    };
    // What will be waited out, within the most this waits.
    let lifetime = match lifetime {
        Some(0) | None => None,
        Some(l) if l > MOST_WAIT_MINUTES => {
            say(
                "V7.3.2",
                format!(
                    "A session lifetime of {l} minutes is longer than the {MOST_WAIT_MINUTES} this \
                     waits, so it was not waited out."
                ),
                out,
            );
            None
        }
        Some(l) => Some(l),
    };
    let idle = match idle {
        Some(0) | None => None,
        Some(i) if i + 1 > MOST_WAIT_MINUTES => {
            say(
                "V7.3.1",
                format!(
                    "An idle timeout of {i} minutes is longer than the {MOST_WAIT_MINUTES} this \
                     waits, so it was not waited out."
                ),
                out,
            );
            None
        }
        // A session that must end within the idle timeout anyway cannot show idleness is what
        // ended it: the busy one would end too.
        Some(i) if lifetime.is_some_and(|l| l <= i) => {
            say(
                "V7.3.1",
                format!(
                    "The idle timeout, {i} minutes, is no shorter than the session lifetime, so a \
                     session refused after it cannot be told to have ended for being idle."
                ),
                out,
            );
            None
        }
        Some(i) => Some(i),
    };
    if idle.is_none() && lifetime.is_none() {
        return false;
    }

    let opens = |http: &mut dyn Http, session: &Session, label: &str| {
        ok(&http.send(&get(&format!("timeout-{label}"), confirm, session)))
    };
    let mut quiet = Vec::new();
    let (Some(left), Some(busy)) = (
        sign_in(http, users, "idle", a, &mut quiet),
        sign_in(http, users, "busy", a, &mut quiet),
    ) else {
        return false;
    };
    let (left, busy) = (left.session, busy.session);
    if !(opens(http, &left, "idle-start") && opens(http, &busy, "busy-start")) {
        say(
            "V7.3.1, V7.3.2",
            "Whether sessions time out: two new sessions of the first test user did not both open \
             the private page to begin with."
                .to_owned(),
            out,
        );
        return false;
    }
    let began = http.now();
    // Kept busy well inside the shortest timeout, and never idle for more than two minutes.
    let every = idle.map_or(120, |i| (u64::from(i) * 60 / 3).clamp(10, 120));
    let wait_until = |http: &mut dyn Http, until: u64| {
        while http.now() < until {
            let left = until - http.now();
            http.wait(every.min(left));
            ok(&http.send(&get("timeout-keep-busy", confirm, &busy)));
        }
    };

    if let Some(minutes) = idle {
        wait_until(http, began + u64::from(minutes) * 60 + 60);
        let left_open = opens(http, &left, "idle-after");
        let busy_open = opens(http, &busy, "busy-after-idle");
        out.steps.push(format!(
            "after {} minutes, a session left alone {} and one kept busy {}",
            minutes + 1,
            if left_open {
                "still opened the private page"
            } else {
                "was refused"
            },
            if busy_open {
                "still opened it"
            } else {
                "was refused"
            },
        ));
        if left_open {
            out.findings.push(finding(
                &NO_IDLE_TIMEOUT,
                "A session left unused does not time out",
                Severity::Medium,
                format!(
                    "securevibe.toml says a session should end after {} unused. A \
                     session left alone for {} minutes still opened {confirm}.",
                    minutes_text(minutes),
                    minutes + 1
                ),
            ));
        } else if busy_open {
            out.verified.push(crate::Verified::new(
                NO_IDLE_TIMEOUT.rule_id,
                NO_IDLE_TIMEOUT.requirement_ids,
                format!(
                    "a session left unused for {} minutes, refused, where one kept busy for the \
                     same time still opened the private page; the timeout you stated is {}",
                    minutes + 1,
                    minutes_text(minutes)
                ),
            ));
        } else {
            say(
                "V7.3.1",
                "A session left unused was refused, but so was one kept busy, so it cannot be \
                 said to have ended for being idle."
                    .to_owned(),
                out,
            );
        }
    }

    if let Some(minutes) = lifetime {
        wait_until(http, began + u64::from(minutes) * 60 + 60);
        let busy_open = opens(http, &busy, "busy-after-lifetime");
        let fresh = sign_in(http, users, "after-lifetime", a, &mut quiet)
            .is_some_and(|s| opens(http, &s.session, "fresh-after-lifetime"));
        out.steps.push(format!(
            "after {} minutes, the session kept busy {}, and a new sign-in {}",
            minutes + 1,
            if busy_open {
                "still opened the private page"
            } else {
                "was refused"
            },
            if fresh { "worked" } else { "did not" },
        ));
        if busy_open {
            out.findings.push(finding(
                &NO_SESSION_LIFETIME,
                "A session kept busy never has to sign in again",
                Severity::Medium,
                format!(
                    "securevibe.toml says a session should last at most {}. One \
                     used every {every} seconds still opened {confirm} after {} minutes.",
                    minutes_text(minutes),
                    minutes + 1
                ),
            ));
        } else if fresh {
            out.verified.push(crate::Verified::new(
                NO_SESSION_LIFETIME.rule_id,
                NO_SESSION_LIFETIME.requirement_ids,
                format!(
                    "a session used every {every} seconds, refused after {} minutes, where a new \
                     sign-in then worked; the lifetime you stated is {}",
                    minutes + 1,
                    minutes_text(minutes)
                ),
            ));
        } else {
            say(
                "V7.3.2",
                "The busy session was refused at the end of its lifetime, but a new sign-in then \
                 did not work either, so the refusal cannot be said to be the lifetime."
                    .to_owned(),
                out,
            );
        }
    }
    true
}

/// "1 minute", "15 minutes".
fn minutes_text(n: u32) -> String {
    format!("{n} minute{}", if n == 1 { "" } else { "s" })
}

/// Whether the cookies set at sign-in are what carries the signed-in session: the private page asked
/// with them left out and every other cookie kept. `Some(true)` when it was refused, `Some(false)`
/// when it still opened (the session lives in a cookie from before sign-in), `None` when there is
/// no page to ask, nothing was set at sign-in, a token may carry the session, or the answer was a
/// crash or a limiter's, which says neither. Until 6 October 2026 this was assumed, which gave a
/// made-up value of an unrelated cookie set at sign-in as "the session" (the review of 1 to 4
/// October, item 13).
pub(super) fn sign_in_cookies_carry_session(
    http: &mut dyn Http,
    a: &SignedIn,
    confirm: Option<&str>,
) -> Option<bool> {
    let confirm = confirm?;
    if a.set_at_login.is_empty() || a.session.bearer.is_some() {
        return None;
    }
    let mut without = a.session.clone();
    without
        .cookies
        .retain(|(name, _)| !a.set_at_login.iter().any(|c| c.name == *name));
    let answer = http.send(&get("session-without-sign-in-cookies", confirm, &without));
    let answer = super::answer_of(answer.as_ref()).answered()?;
    Some(!(200..300).contains(&answer.status))
}

/// Whether a session value this check invented is refused (V7.2.1).
///
/// The cookies the app set at sign-in are the session; every other cookie it gave (an anti-forgery
/// cookie from the sign-in page, a preference) is not. Each sign-in cookie is given a value of the
/// same length that no session store could have issued, and every other cookie is sent as it was,
/// so the request differs from the real one in the session alone. A private page that opens for it
/// is an app taking the cookie's word rather than checking it. The real session is sent first, as
/// the control: a refusal is credited only when that just opened the same page.
///
/// Different from V7.2.3, which asks whether a real session id could be *guessed*. This asks
/// whether anything is checked at all, which is the more basic failure and the cheaper one to make.
pub(super) fn invented_session_check(
    http: &mut dyn Http,
    signed_in: &SignedIn,
    confirm: Option<&str>,
    carried: Option<bool>,
    out: &mut Outcome,
) {
    let say = |why: String, out: &mut Outcome| out.not_assessed.push(("V7.2.1".to_owned(), why));
    let Some(confirm) = confirm else {
        // Said, not skipped: until 8 October 2026 this returned with nothing in `out`, and the
        // requirement went unmentioned (the architecture assessment of that day, item 8).
        say(
            "Whether a session value the app never issued is refused: no private page opened for \
             a signed-in user, so there is nothing to try an invented session against."
                .to_owned(),
            out,
        );
        return;
    };
    if signed_in.set_at_login.is_empty() {
        say(
            "Whether a made-up session value is refused: signing in set no cookie, so there is no \
             session cookie of the app's own to alter."
                .to_owned(),
            out,
        );
        return;
    }
    if signed_in.session.bearer.is_some() {
        say(
            "Whether a made-up session value is refused: signing in also gave a token, which may be \
             what carries the session, so altering the cookies alone would show nothing."
                .to_owned(),
            out,
        );
        return;
    }
    let mut session = signed_in.session.clone();
    let mut altered = Vec::new();
    // Whether a cookie was shorter than the made-up value's least length, for the evidence to say
    // so rather than call every value "the same length" (item 16 of the review of 1 to 4 October).
    let mut lengthened = false;
    for (name, value) in &mut session.cookies {
        if !signed_in.set_at_login.iter().any(|c| c.name == *name) {
            continue;
        }
        // The same length, so nothing is refused merely for being the wrong shape.
        lengthened |= value.chars().count() < 16;
        let invented: String = "sv0probe0invented0session0value0"
            .chars()
            .cycle()
            .take(value.chars().count().max(16))
            .collect();
        if invented != *value {
            *value = invented;
            altered.push(format!("`{name}`"));
        }
    }
    if altered.is_empty() {
        return;
    }
    let altered = altered.join(", ");
    let same_length = if lengthened {
        "of the same length (16 characters where the real one was shorter)"
    } else {
        "of the same length"
    };
    let control = ok(&http.send(&get(
        "invented-session-control",
        confirm,
        &signed_in.session,
    )));
    if !control {
        out.steps.push(format!(
            "asked for {confirm} with the real session, before making one up: refused"
        ));
        say(
            format!(
                "Whether a made-up session value is refused: the real session did not open \
                 {confirm} just before, so a refusal of a made-up one would show nothing."
            ),
            out,
        );
        return;
    }
    let opened = ok(&http.send(&get("invented-session", confirm, &session)));
    out.steps.push(format!(
        "asked for {confirm} with the real session (opened), then with a session value this \
         check invented in {altered} and every other cookie kept: {}",
        if opened { "opened" } else { "refused" }
    ));
    if opened && carried != Some(true) {
        // The page opening with a made-up value says the app took it only when the cookies changed
        // are what carries the session; without them it may never have looked at them.
        say(
            format!(
                "Whether a made-up session value is refused: {confirm} opened with {altered} made \
                 up, but nothing showed those cookies carry the session ({}), so that it opened \
                 says nothing about whether the session is checked.",
                match carried {
                    Some(false) => "the page opened without them too",
                    _ => "the page could not be asked without them",
                }
            ),
            out,
        );
    } else if opened {
        out.findings.push(finding(
            &SESSION_TOKEN_UNVERIFIED,
            "A made-up session value opens a private page",
            Severity::High,
            format!(
                "With {altered}, the cookies set at sign-in, given values {same_length} that \
                 this check made up, and the app's other cookies as they were, {confirm} still \
                 opened."
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            SESSION_TOKEN_UNVERIFIED.rule_id,
            SESSION_TOKEN_UNVERIFIED.requirement_ids,
            format!(
                "{altered}, set at sign-in, given made-up values {same_length} with the app's \
                 other cookies kept, refused {confirm}, where the real session had just opened it"
            ),
        ));
    }
}

/// A WebSocket handshake, carrying whatever session it is given.
fn ws_handshake(id: &str, path: &str, session: &Session) -> ProbeRequest {
    let mut request = get(id, path, session);
    request.headers.extend(
        [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "c3YtcHJvYmUtd3Mta2V5LTE2Yg=="),
            ("Sec-WebSocket-Version", "13"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned())),
    );
    request
}

/// Whether a WebSocket meant for signed-in users needs a real session (V4.4.4), and whether signing
/// out ends it (V4.4.3).
///
/// A sign-in of its own, so the socket is asked with a session nothing else is using. That session's
/// handshake has to be accepted first: an app that refuses every handshake, or a path that is not a
/// WebSocket, would refuse the others too and show nothing. Then the same handshake with no session
/// and with a session value this check made up, each of which must be refused. Refusing both is
/// credited for V4.4.4: the channel opens only through the signed-in session. Then the session is
/// signed out and its old cookie sent again, which is only ever a finding: V4.4.3 asks that a
/// socket's own tokens meet every session requirement, and ending with sign-out is one of them.
pub(super) fn websocket_session_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &Account,
    out: &mut Outcome,
) {
    let Some(path) = &users.private_websocket else {
        return;
    };
    let say =
        |id: &str, why: String, out: &mut Outcome| out.not_assessed.push((id.to_owned(), why));
    let Some(signed_in) = sign_in(http, users, "a-websocket", a, &mut out.steps) else {
        say(
            "V4.4.3, V4.4.4",
            "Whether the private WebSocket needs a session: signing in as the first test user got \
             no answer."
                .to_owned(),
            out,
        );
        return;
    };
    let session = signed_in.session;
    let upgraded = |http: &mut dyn Http, label: &str, session: &Session| {
        http.send(&ws_handshake(&format!("websocket-{label}"), path, session))
            .is_some_and(|r| r.status == 101)
    };
    if !upgraded(http, "signed-in", &session) {
        out.steps
            .push(format!("opened the WebSocket at {path} signed in: refused"));
        say(
            "V4.4.3, V4.4.4",
            format!(
                "A WebSocket handshake to {path} with the first test user's session was not \
                 accepted, so either `private-websocket` is not where the socket is or it refuses \
                 everybody; either way a refusal without a session would show nothing."
            ),
            out,
        );
        return;
    }
    let anonymous = upgraded(http, "no-session", &Session::default());
    let invented = session.cookies.first().map(|(name, real)| {
        let value: String = "sv0probe0invented0session0value0"
            .chars()
            .cycle()
            .take(real.chars().count().max(16))
            .collect();
        let mut made_up = Session::default();
        made_up.cookies.push((name.clone(), value));
        upgraded(http, "invented-session", &made_up)
    });
    out.steps.push(format!(
        "opened the WebSocket at {path} signed in: accepted; with no session: {}{}",
        if anonymous { "accepted" } else { "refused" },
        match invented {
            Some(true) => "; with a session value this check made up: accepted",
            Some(false) => "; with a session value this check made up: refused",
            None => "",
        }
    ));
    if anonymous || invented == Some(true) {
        out.findings.push(finding(
            &WS_WITHOUT_SESSION,
            "A private WebSocket opens without a real session",
            Severity::High,
            format!(
                "securevibe.toml names {path} as a WebSocket for signed-in users. A handshake {} \
                 was accepted (101).",
                match (anonymous, invented == Some(true)) {
                    (true, true) => "with no session, and one with a made-up session value,",
                    (true, false) => "with no session at all",
                    _ => "with a session value this check made up",
                }
            ),
        ));
    } else if invented == Some(false) {
        out.verified.push(crate::Verified::new(
            WS_WITHOUT_SESSION.rule_id,
            WS_WITHOUT_SESSION.requirement_ids,
            format!(
                "WebSocket handshakes to {path} with no session and with a made-up one, refused \
                 where the signed-in session's was accepted"
            ),
        ));
    } else {
        // A session carried some other way than a cookie cannot be made up here, and a refusal
        // with none at all is half the answer.
        say(
            "V4.4.4",
            format!(
                "A handshake to {path} with no session was refused, but the session was not a \
                 cookie, so one with a made-up value could not be tried."
            ),
            out,
        );
    }

    // V4.4.2, which the anonymous probe cannot ask of a socket that needs a sign-in: the same signed-in
    // handshake, from a site the app has never heard of. The plain one upgraded above, so a refusal
    // is about the origin.
    let mut foreign = ws_handshake("websocket-foreign-origin", path, &session);
    foreign
        .headers
        .push(("Origin".to_owned(), STRANGER.to_owned()));
    let foreign_status = http.send(&foreign).map(|r| r.status);
    out.steps.push(format!(
        "opened the WebSocket at {path} signed in, from another site: {}",
        match foreign_status {
            Some(101) => "accepted".to_owned(),
            Some(status) => format!("refused ({status})"),
            None => "no answer".to_owned(),
        }
    ));
    match foreign_status {
        Some(101) => out.findings.push(finding(
            &WS_FOREIGN_ORIGIN,
            "A private WebSocket is accepted from any website",
            Severity::Medium,
            format!(
                "A handshake to {path} carrying the signed-in session and `Origin: {STRANGER}` was \
                 accepted (101). A page on any site can open this connection as a signed-in visitor."
            ),
        )),
        Some(status) => out.verified.push(crate::Verified::new(
            WS_FOREIGN_ORIGIN.rule_id,
            WS_FOREIGN_ORIGIN.requirement_ids,
            format!(
                "a signed-in WebSocket handshake to {path} from a site the app has never heard of, \
                 refused ({status}) where the same handshake with no Origin was accepted"
            ),
        )),
        None => say(
            "V4.4.2",
            format!(
                "Whether the private WebSocket checks where a handshake comes from: the signed-in \
                 handshake from another site to {path} got no answer."
            ),
            out,
        ),
    }

    // Signed out, then the old session again. Only when a real session was shown to be needed: a
    // socket that opens without one opens after sign-out too, and that shows nothing more.
    if anonymous || invented != Some(false) {
        say(
            "V4.4.3",
            "Whether signing out closes the private WebSocket: it was not shown to need a real \
             session in the first place, so opening after sign-out would show nothing more."
                .to_owned(),
            out,
        );
        return;
    }
    let Some(logout) = &users.logout else {
        say(
            "V4.4.3",
            "Whether signing out closes the private WebSocket: securevibe.toml lists no `logout`."
                .to_owned(),
            out,
        );
        return;
    };
    let before = session.clone();
    let mut ending = session;
    let (response, _) = send_template(
        http,
        "logout-websocket",
        logout,
        &Values::default(),
        &mut ending,
        &users.private,
    );
    if !accepted(&response) {
        say(
            "V4.4.3",
            format!(
                "Whether signing out closes the private WebSocket: the sign-out itself was refused \
                 ({}).",
                status(&response)
            ),
            out,
        );
        return;
    }
    let after = upgraded(http, "after-sign-out", &before);
    out.steps.push(format!(
        "signed that session out, then opened the WebSocket with its old cookie: {}",
        if after { "accepted" } else { "refused" }
    ));
    if after {
        out.findings.push(finding(
            &WS_AFTER_SIGN_OUT,
            "A private WebSocket still opens after signing out",
            Severity::Medium,
            format!(
                "After the session was signed out, a handshake to {path} carrying its old cookie \
                 was accepted (101)."
            ),
        ));
    }
    say(
        "V4.4.3",
        "Only one part of a WebSocket's own session management was tried: that signing out ends \
         it. Whether its tokens meet the rest of the session requirements was not."
            .to_owned(),
        out,
    );
}

/// Field names that should never leave the server, whatever the app calls its columns.
const SECRET_FIELD_NAMES: &[&str] = &[
    "password",
    "passwd",
    "password_hash",
    "pwhash",
    "hashed_password",
    "salt",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "session_token",
    "csrf_secret",
];

/// Whether a record handed back carries fields nobody outside the server should see (V15.3.1).
///
/// Only ever a finding. Not seeing these names proves nothing: this app may have no such column,
/// may call it something else, or may return the record somewhere this never looked.
pub(super) fn record_fields_check(body: &str, path: &str, out: &mut Outcome) {
    let lower = body.to_lowercase();
    // A name has to appear as a field, not as a word in a sentence: `"password":` in JSON, or
    // `password=` / `password":` in whatever the app writes. Otherwise a page saying "change your
    // password" is a finding.
    let found: Vec<&str> = SECRET_FIELD_NAMES
        .iter()
        .filter(|name| {
            [
                format!("\"{name}\""),
                format!("'{name}'"),
                format!("{name}="),
            ]
            .iter()
            .any(|shape| lower.contains(shape.as_str()))
        })
        .copied()
        .collect();
    if found.is_empty() {
        return;
    }
    out.findings.push(finding(
        &RECORD_LEAKS_FIELDS,
        "A record is handed back with fields that should stay on the server",
        Severity::Medium,
        format!(
            "Reading back the record at {path} produced {}, named as {} field{}.",
            found.join(", "),
            if found.len() == 1 { "a" } else { "" },
            if found.len() == 1 { "" } else { "s" }
        ),
    ));
}

/// Whether signing out tells the browser to throw away what it kept (V14.3.1).
///
/// Credit on presence only, and this is the reason: `Clear-Site-Data` is one way to meet V14.3.1
/// and the requirement names it as something that "may be able to help". An app whose own script
/// clears storage when the session ends has met it without the header, so not finding one is not a
/// failure — it is simply not something this saw.
pub(super) fn clear_site_data_check(
    response: Option<&ProbeResponse>,
    path: &str,
    out: &mut Outcome,
) {
    let Some(response) = response else {
        return;
    };
    let header = response
        .header("clear-site-data")
        .unwrap_or_default()
        .to_lowercase();
    // `"*"` covers everything; otherwise storage is the part that holds signed-in data. Cookies
    // alone are not it: the session ending already does that.
    let clears = header.contains('*') || header.contains("storage");
    out.steps.push(format!(
        "signing out sent Clear-Site-Data: {}",
        if clears {
            "yes"
        } else if header.is_empty() {
            "no"
        } else {
            "not covering storage"
        }
    ));
    if clears {
        out.verified.push(crate::Verified::new(
            "probe.clear-site-data",
            &["V14.3.1"],
            format!(
                "signing out at {path} answered with `Clear-Site-Data: {}`, telling the browser to \
                 throw away what it had kept",
                header.trim()
            ),
        ));
    } else {
        out.not_assessed.push((
            "V14.3.1".to_owned(),
            format!(
                "Whether data is cleared from the browser when the session ends: signing out sent \
                 {}. That is not a failure — an app whose own script clears storage has met this \
                 without the header — but nothing here saw it happen.",
                if header.is_empty() {
                    "no `Clear-Site-Data` header".to_owned()
                } else {
                    format!(
                        "`Clear-Site-Data: {}`, which does not cover storage",
                        header.trim()
                    )
                }
            ),
        ));
    }
    crate::verified::unless_credited("probe.clear-site-data", &out.verified);
}

/// Whether signing out also happens on a plain page visit (V3.5.3).
///
/// A fresh sign-in, shown to open the private page; a GET to the sign-out address; then the private
/// page again. Only ever a finding: one address refusing a GET says nothing about the others.
/// Two questions about the private pages themselves, asked with the session that opened them.
///
/// Both are read off the same responses, because both need the same thing shown first: that the
/// page really opened for a signed-in user. A page that answered 302 to the sign-in screen has no
/// caching headers worth reading and no sign-out link worth looking for, and counting it either way
/// would be judging the sign-in page instead.
pub(super) fn private_page_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    signed_in: &SignedIn,
    out: &mut Outcome,
) {
    if users.private.is_empty() {
        out.not_assessed.push((
            "V14.3.2, V7.4.4".to_owned(),
            "[stack.run.users] lists no `private` pages, so there is no signed-in page to read \
             caching headers from or to look for a sign-out link on."
                .to_owned(),
        ));
        return;
    }
    let logout_path = users.logout.as_ref().map(|l| l.path.as_str());

    let mut opened = Vec::new();
    let mut not_stored = Vec::new();
    let mut stored = Vec::new();
    let mut shared = Vec::new();
    let mut with_link = Vec::new();
    let mut without_link = Vec::new();
    let mut without_headers = Vec::new();

    for path in &users.private {
        let Some(response) = http.send(&get("private-page-headers", path, &signed_in.session))
        else {
            continue;
        };
        if !(200..300).contains(&response.status) {
            continue;
        }
        opened.push(path.clone());
        let missing = crate::probes::missing_headers(&response);
        if !missing.is_empty() {
            without_headers.push(format!(
                "{path} came back without {}",
                missing.join("; without ")
            ));
        }

        // `no-store` is the only value that means "do not keep a copy". `no-cache` permits the copy
        // and asks for it to be revalidated, and `private` only says not to keep it in a shared
        // cache, so neither answers this requirement.
        let cache_control = response
            .header("cache-control")
            .unwrap_or_default()
            .to_lowercase();
        let parts: Vec<&str> = cache_control.split(',').map(str::trim).collect();
        if parts.contains(&"no-store") {
            not_stored.push(path.clone());
        } else {
            stored.push(path.clone());
        }
        // Shared caches may keep a response marked `public` or given an `s-maxage`, unless
        // `private` or `no-store` says otherwise, which each overrides.
        if (parts.contains(&"public") || parts.iter().any(|p| p.starts_with("s-maxage")))
            && !parts.contains(&"private")
            && !parts.contains(&"no-store")
        {
            shared.push(path.clone());
        }

        if logout_path.is_some_and(|logout| points_at(&response.body, logout)) {
            with_link.push(path.clone());
        } else {
            without_link.push(path.clone());
        }
    }

    if opened.is_empty() {
        out.not_assessed.push((
            "V14.3.2, V7.4.4".to_owned(),
            "No private page opened for the signed-in test user, so nothing here could read what \
             it sends or look for its sign-out link."
                .to_owned(),
        ));
        return;
    }

    // ---- V14.3.2: Cache-Control: no-store
    out.steps.push(format!(
        "{} of {} private page{} sent Cache-Control: no-store",
        not_stored.len(),
        opened.len(),
        if opened.len() == 1 { "" } else { "s" }
    ));
    if stored.is_empty() {
        out.verified.push(crate::Verified::new(
            PRIVATE_PAGE_CACHING.rule_id,
            PRIVATE_PAGE_CACHING.requirement_ids,
            format!(
                "{} private page{}, each sending Cache-Control: no-store to a signed-in user",
                opened.len(),
                if opened.len() == 1 { "" } else { "s" }
            ),
        ));
    } else {
        out.findings.push(finding(
            &PRIVATE_PAGE_CACHING,
            "A private page may be kept in the browser's cache",
            Severity::Medium,
            format!(
                "Opened by a signed-in user, {} came back without `Cache-Control: no-store`.",
                stored.join(", ")
            ),
        ));
    }

    // ---- V3.4.3 to V3.4.6: the headers a browser relies on, on every private page that opened
    out.steps.push(format!(
        "{} of {} private page{} sent the headers a browser relies on",
        opened.len() - without_headers.len(),
        opened.len(),
        if opened.len() == 1 { "" } else { "s" }
    ));
    if without_headers.is_empty() {
        out.verified.push(crate::Verified::new(
            PRIVATE_PAGE_HEADERS.rule_id,
            PRIVATE_PAGE_HEADERS.requirement_ids,
            format!(
                "{} private page{}, each sending the four headers to a signed-in user",
                opened.len(),
                if opened.len() == 1 { "" } else { "s" }
            ),
        ));
    } else {
        out.findings.push(finding(
            &PRIVATE_PAGE_HEADERS,
            "A private page is missing headers a browser relies on",
            Severity::Medium,
            format!(
                "Opened by a signed-in user, {}.",
                without_headers.join("; ")
            ),
        ));
    }

    // ---- V14.2.2: a private page shared caches are told they may keep. Only ever a finding.
    out.steps.push(format!(
        "{} of {} private page{} told shared caches they may keep {}",
        shared.len(),
        opened.len(),
        if opened.len() == 1 { "" } else { "s" },
        if opened.len() == 1 { "it" } else { "them" }
    ));
    if !shared.is_empty() {
        out.findings.push(finding(
            &PRIVATE_PAGE_SHARED_CACHE,
            "A private page tells shared caches they may keep it",
            Severity::Medium,
            format!(
                "Opened by a signed-in user, {} came back marked `public` or with an `s-maxage`, \
                 which lets a load balancer or content delivery network keep it and serve it to \
                 someone else.",
                shared.join(", ")
            ),
        ));
    }

    // ---- V7.4.4: a visible way to sign out
    //
    // Only asked when securevibe.toml says where signing out happens. Without that there is no
    // address to look for, and "no sign-out link" would be a statement about the manifest.
    let Some(logout) = logout_path else {
        out.not_assessed.push((
            "V7.4.4".to_owned(),
            "[stack.run.users] has no `logout`, so there is no sign-out address to look for on the \
             private pages."
                .to_owned(),
        ));
        return;
    };
    out.steps.push(format!(
        "{} of {} private page{} showed a way to reach {logout}",
        with_link.len(),
        opened.len(),
        if opened.len() == 1 { "" } else { "s" }
    ));
    if without_link.is_empty() {
        out.verified.push(crate::Verified::new(
            SIGN_OUT_LINK.rule_id,
            SIGN_OUT_LINK.requirement_ids,
            format!(
                "{} private page{}, each carrying a link or form pointing at {logout}",
                opened.len(),
                if opened.len() == 1 { "" } else { "s" }
            ),
        ));
    } else {
        out.findings.push(finding(
            &SIGN_OUT_LINK,
            "A private page offers no visible way to sign out",
            Severity::Low,
            format!(
                "Opened by a signed-in user, {} carried no link or form pointing at {logout}.",
                without_link.join(", ")
            ),
        ));
    }
}

/// Whether a page offers a way to reach `target`: a link to it, or a form that posts to it.
///
/// Reads the `href` and `action` attributes rather than searching the whole page for the text, so a
/// sign-out address mentioned in a comment or a script string is not mistaken for a control the
/// person can see. What it cannot tell is whether the control is *visible* — a link inside a
/// collapsed menu counts here — which is why finding one is worth no more than this.
fn points_at(body: &str, target: &str) -> bool {
    let matches = |value: &str| {
        let value = value.trim();
        value == target
            || value.trim_end_matches('/') == target.trim_end_matches('/')
            || value.split('?').next().is_some_and(|v| v == target)
    };
    tags(body, "a")
        .iter()
        .filter_map(|t| attribute(t, "href"))
        .any(|href| matches(&href))
        || tags(body, "form")
            .iter()
            .filter_map(|t| attribute(t, "action"))
            .any(|action| matches(&action))
}

/// At most how many bits of randomness a value could hold, from its length and the kinds of
/// character in it.
///
/// An upper bound, and meant as one: hex counted as letters and digits is credited with more than
/// it has. It can show an id too short to be unguessable; it can never show one is random.
pub(super) fn most_bits(value: &str) -> f64 {
    let kinds = [
        (value.chars().any(|c| c.is_ascii_digit()), 10.0),
        (value.chars().any(|c| c.is_ascii_lowercase()), 26.0),
        (value.chars().any(|c| c.is_ascii_uppercase()), 26.0),
        (value.chars().any(|c| !c.is_ascii_alphanumeric()), 4.0),
    ];
    let alphabet: f64 = kinds.iter().filter(|(k, _)| *k).map(|(_, n)| n).sum();
    if alphabet < 2.0 {
        return 0.0;
    }
    value.chars().count() as f64 * alphabet.log2()
}

/// Whether the session id could be guessed: too short to hold 128 bits, or the same twice.
///
/// Only ever a finding. Length is necessary and far from sufficient; whether an id came from a
/// secure generator is not something its value shows, so a long one is credited with nothing.
pub(super) fn session_id_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    a: &SignedIn,
    signed_in_works: bool,
    out: &mut Outcome,
) {
    if !signed_in_works || a.set_at_login.is_empty() {
        return;
    }
    let mut quiet = Vec::new();
    let Some(again) = sign_in(http, users, "a-again", &accounts.a, &mut quiet) else {
        return;
    };
    let mut problems = Vec::new();
    for first in &a.set_at_login {
        let bits = most_bits(&first.value);
        if bits < 128.0 {
            problems.push(format!(
                "`{}` is {} characters, room for at most {bits:.0} bits",
                first.name,
                first.value.chars().count()
            ));
        }
        if again
            .set_at_login
            .iter()
            .any(|c| c.name == first.name && c.value == first.value)
        {
            problems.push(format!(
                "`{}` had the same value at two separate sign-ins",
                first.name
            ));
        }
    }
    out.steps.push(format!(
        "compared the session cookies of two sign-ins: {}",
        if problems.is_empty() {
            "long enough and different"
        } else {
            "too short or repeated"
        }
    ));
    if !problems.is_empty() {
        out.findings.push(finding(
            &WEAK_SESSION_ID,
            "The session id could be guessed",
            Severity::High,
            problems.join("; "),
        ));
    }
}

pub(super) fn session_checks(
    a: &SignedIn,
    signed_in_works: bool,
    carried: Option<bool>,
    out: &mut Outcome,
) {
    if a.session.bearer.is_some() && a.set_at_login.is_empty() {
        out.not_assessed.push((
            "V3.3.2, V3.3.4, V7.2.4".to_owned(),
            "Sign-in answered with a token rather than a cookie, so there is no session cookie to \
             judge."
                .to_owned(),
        ));
        return;
    }
    if !signed_in_works {
        out.not_assessed.push((
            "V3.3.2, V3.3.4, V7.2.4".to_owned(),
            "Nothing showed the signed-in session working — no private page opened for the signed-in \
             user alone, and no record was created and read back — so which cookie is the session \
             cannot be told."
                .to_owned(),
        ));
        return;
    }
    if a.set_at_login.is_empty() {
        if a.before_login.is_empty() {
            out.not_assessed.push((
                "V3.3.2, V3.3.4, V7.2.4".to_owned(),
                "Signing in set no cookie and none was set before it, so the session is carried \
                 some way this probe does not see."
                    .to_owned(),
            ));
        } else {
            // The session works and sign-in issued nothing: the cookie from before sign-in is now
            // the signed-in session. That is session fixation, whatever else is true.
            let names: Vec<&str> = a.before_login.iter().map(|(n, _)| n.as_str()).collect();
            out.findings.push(finding(
                &SESSION_RENEWAL,
                "Signing in does not issue a new session",
                Severity::High,
                format!(
                    "The app set {} before sign-in and nothing new at sign-in, and the old value \
                     then opened a signed-in page.",
                    names.join(", ")
                ),
            ));
        }
        return;
    }

    // What sign-in set is the session only when the page was refused without it. Opened without it,
    // the signed-in session is a cookie from before sign-in, which is the fixation V7.2.4 asks
    // about; not shown either way, nothing here is judged on the guess (the review of 1 to 4
    // October, item 13).
    match carried {
        Some(true) => {}
        Some(false) => {
            let names: Vec<&str> = a.before_login.iter().map(|(n, _)| n.as_str()).collect();
            out.findings.push(finding(
                &SESSION_RENEWAL,
                "Signing in does not issue a new session",
                Severity::High,
                format!(
                    "With the cookies sign-in set left out, the cookies from before sign-in ({}) \
                     still opened a signed-in page: the session from before sign-in is the \
                     signed-in session.",
                    names.join(", ")
                ),
            ));
            out.not_assessed.push((
                "V3.3.2, V3.3.4".to_owned(),
                "The signed-in session is carried by a cookie from before sign-in, so the cookies \
                 set at sign-in are not the session and their attributes say nothing about it."
                    .to_owned(),
            ));
            return;
        }
        None => {
            out.not_assessed.push((
                "V3.3.2, V3.3.4, V7.2.4".to_owned(),
                "Which cookie carries the session could not be shown: no private page could be \
                 asked with the cookies set at sign-in left out, so nothing here is judged on a \
                 guess."
                    .to_owned(),
            ));
            return;
        }
    }

    let mut problems = Vec::new();
    for c in &a.set_at_login {
        if !c.http_only {
            problems.push(format!(
                "`{}` can be read by any script on the page (no HttpOnly)",
                c.name
            ));
        }
        if c.same_site.is_none() {
            problems.push(format!(
                "`{}` does not say when it may travel to other sites (no SameSite)",
                c.name
            ));
        }
    }
    if problems.is_empty() {
        out.verified.push(crate::Verified::new(
            SESSION_COOKIE.rule_id,
            SESSION_COOKIE.requirement_ids,
            "every cookie the app set when a test user signed in".to_owned(),
        ));
    } else {
        out.findings.push(finding(
            &SESSION_COOKIE,
            "The session cookie is set without the attributes that protect it",
            Severity::High,
            problems.join("; "),
        ));
    }

    let kept: Vec<&str> = a
        .set_at_login
        .iter()
        .filter(|c| {
            a.before_login
                .iter()
                .any(|(n, v)| *n == c.name && *v == c.value)
        })
        .map(|c| c.name.as_str())
        .collect();
    if kept.is_empty() {
        out.verified.push(crate::Verified::new(
            SESSION_RENEWAL.rule_id,
            SESSION_RENEWAL.requirement_ids,
            "a sign-in by a test user, compared with the cookies given before it".to_owned(),
        ));
    } else {
        out.findings.push(finding(
            &SESSION_RENEWAL,
            "Signing in does not issue a new session",
            Severity::High,
            format!(
                "Sign-in set {} to the same value it had before sign-in.",
                kept.join(", ")
            ),
        ));
    }
}

/// The headers a proxy in front of an app adds to say who the user is, each with the value it would
/// carry for the first test user.
const IDENTITY_HEADERS: [&str; 8] = [
    "X-User-ID",
    "X-User",
    "X-Forwarded-User",
    "X-Remote-User",
    "Remote-User",
    "X-Auth-Request-User",
    "X-Auth-Request-Email",
    "X-Forwarded-Email",
];

/// V4.1.3: a private page asked for by somebody not signed in, carrying in turn each header a proxy
/// uses to say who the user is. An app that lets the request in takes the header's word for who is
/// asking, so anybody can be anybody. Only pages that refused a stranger, on a run where signing in
/// was shown to open them, are asked, so an opened page is the header's doing. Only ever a finding:
/// refusing these eight says nothing about a header not tried.
pub(super) fn identity_header_check(
    http: &mut dyn Http,
    user: &str,
    private: &[String],
    out: &mut Outcome,
) {
    let mut opened = Vec::new();
    let mut asked = 0;
    for path in private {
        for (n, header) in IDENTITY_HEADERS.iter().enumerate() {
            let value = if *header == "X-User-ID" { "1" } else { user };
            let mut request = get(&format!("identity-header-{n}"), path, &Session::default());
            request
                .headers
                .push(((*header).to_owned(), value.to_owned()));
            asked += 1;
            if ok(&http.send(&request)) {
                opened.push(format!("{path} with {header}: {value}"));
            }
        }
    }
    out.steps.push(format!(
        "asked for {} private page{} without signing in, carrying {} header{} that name a user: {} \
         let in",
        private.len(),
        if private.len() == 1 { "" } else { "s" },
        asked,
        if asked == 1 { "" } else { "s" },
        opened.len()
    ));
    if !opened.is_empty() {
        out.findings.push(finding(
            &IDENTITY_HEADER,
            "A header that names a user opens a private page without signing in",
            Severity::High,
            format!(
                "Asked for without a session, a page that refused somebody not signed in opened \
                 when the request named the test user in a header: {}.",
                opened.join("; ")
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::{bearer_ws_users, timeouts, with_signup, ws_findings, ws_run};
    use super::*;

    #[test]
    fn the_run_note_names_a_clear_site_data_that_falls_short() {
        // The second witness for the storage rule, on the run note rather than on the verdict.
        // "sent a header" and "sent a header that does the job" are different things, and the
        // note is where the owner can see which one happened.
        let mut app = FakeApp::new(Flaws {
            clears_site_data: true,
            ..Default::default()
        });
        app.clear_site_data_value = Some("\"cookies\"".to_string());
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(&mut app, &users(), &acc, true, &Default::default());
        let note = o.steps.join(" | ");
        assert!(
            note.contains("Clear-Site-Data: not covering storage"),
            "a cookies-only header was noted as if it did the job: {note}"
        );
    }

    #[test]
    fn a_secret_name_has_to_be_a_field_not_a_word() {
        // The failure this check would otherwise have: almost every app has a page saying "change
        // your password" or "forgot your password". Matching the bare word makes a finding out of
        // every one of them, and a check that cries wolf is one people learn to skip.
        for prose in [
            "<p>Change your password</p>",
            "Forgot your password? We never store your password in plain text.",
            "<label>Current password</label>",
            "<p>Your secret is safe with us</p>",
        ] {
            let mut out = Outcome::default();
            record_fields_check(prose, "/notes/1", &mut out);
            assert!(
                out.findings.is_empty(),
                "prose was read as a leaked field: {prose}"
            );
        }
        // And the shapes that really are fields, so this cannot pass by never finding anything.
        for record in [
            r#"{"id":1,"password_hash":"$2b$12$abc"}"#,
            "{'salt': 'xyz', 'id': 2}",
            "id=1&api_key=sk-live-abc",
        ] {
            let mut out = Outcome::default();
            record_fields_check(record, "/notes/1", &mut out);
            assert_eq!(
                out.findings.len(),
                1,
                "a field was not recognized: {record}"
            );
            assert!(
                out.findings[0]
                    .requirement_ids
                    .iter()
                    .any(|r| r == "V15.3.1")
            );
            // The reading half of field-level access (BOPLA), and only ever a finding.
            assert!(
                out.findings[0]
                    .requirement_ids
                    .iter()
                    .any(|r| r == "V8.2.3")
            );
            assert!(out.verified.is_empty());
        }
    }

    #[test]
    fn clear_site_data_credits_on_presence_and_never_faults() {
        // The shape of this check, in one test. Sending the header is credited; not sending it is
        // *not assessed*, because an app whose own script clears storage has met V14.3.1 without
        // it. A finding here would be accusing apps of something this cannot see.
        let with = run_against(
            Flaws {
                clears_site_data: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            verified_ids(&with).contains(&"probe.clear-site-data"),
            "{:?}",
            with.not_assessed
        );

        let without = run_against(Flaws::default(), &users());
        assert!(!verified_ids(&without).contains(&"probe.clear-site-data"));
        assert!(
            !rule_ids(&without).contains(&"probe.clear-site-data"),
            "not sending the header must never be a finding"
        );
        assert!(
            without
                .not_assessed
                .iter()
                .any(|(id, why)| id == "V14.3.1" && why.contains("not a failure")),
            "{:?}",
            without.not_assessed
        );
    }

    #[test]
    fn a_header_that_does_not_cover_storage_is_not_enough() {
        // `Clear-Site-Data: "cookies"` clears the cookie the session already ended with, and
        // leaves everything the page kept. Crediting it would be crediting the wrong thing.
        let mut app = FakeApp::new(Flaws {
            clears_site_data: true,
            ..Default::default()
        });
        app.clear_site_data_value = Some("\"cookies\"".to_string());
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let o = run(&mut app, &users(), &acc, true, &Default::default());
        assert!(!verified_ids(&o).contains(&"probe.clear-site-data"));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V14.3.1" && why.contains("does not cover storage")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_app_that_believes_any_session_cookie_is_found() {
        // Deliberately not in the table below, and the reason is worth writing down: an app that
        // takes any session id at its word does not fail *one* check. Default accounts sign in,
        // sign-out does not end anything, a password change needs no current password — because
        // every one of those is asked with a cookie the app now believes. Putting it in a table
        // that asserts "this flaw and no other" would be asserting something untrue about it.
        let o = run_against(
            Flaws {
                session_not_verified: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            rule_ids(&o).contains(&SESSION_TOKEN_UNVERIFIED.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(!verified_ids(&o).contains(&SESSION_TOKEN_UNVERIFIED.rule_id));
        // And a correct app is not accused of it, which is the half that could quietly rot.
        let correct = run_against(Flaws::default(), &users());
        assert!(!rule_ids(&correct).contains(&SESSION_TOKEN_UNVERIFIED.rule_id));
        assert!(verified_ids(&correct).contains(&SESSION_TOKEN_UNVERIFIED.rule_id));
    }

    #[test]
    fn a_made_up_session_value_is_called_the_same_length_only_when_it_is() {
        // Item 16 of the review of 1 to 4 October: a made-up value is at least 16 characters, and
        // the evidence called it "the same length" when the real one was shorter.
        let scope = |o: &Outcome| {
            o.verified
                .iter()
                .find(|v| v.check_id == SESSION_TOKEN_UNVERIFIED.rule_id)
                .map(|v| v.scope.clone())
                .unwrap_or_else(|| panic!("credited: {:?}", verified_ids(o)))
        };
        let long = scope(&run_against(Flaws::default(), &users()));
        assert!(long.contains("of the same length with"), "{long}");
        assert!(!long.contains("16 characters"), "{long}");
        let short = scope(&run_against(
            Flaws {
                short_session_ids: true,
                ..Default::default()
            },
            &users(),
        ));
        assert!(
            short.contains("16 characters where the real one was shorter"),
            "{short}"
        );
    }

    /// A run against the scripted app with a cookie set on the sign-in page before the session
    /// cookie, and, when `needed`, an app that treats a request without it as signed out.
    fn run_with_pre_login_cookie(believes_any: bool, needed: bool) -> Outcome {
        let mut app = FakeApp::new(Flaws {
            session_not_verified: believes_any,
            ..Default::default()
        });
        app.pre_login_cookie = true;
        app.needs_pre_login_cookie = needed;
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        run(&mut app, &users(), &acc, true, &Default::default())
    }

    #[test]
    fn the_cookie_set_at_sign_in_is_the_one_made_up_and_the_rest_are_kept() {
        // The anti-forgery cookie comes first. Making that one up, and sending it alone, is refused
        // by any app for want of a session at all, which is how an app believing any session id
        // was credited.
        for needed in [false, true] {
            let believing = run_with_pre_login_cookie(true, needed);
            assert!(
                believing
                    .steps
                    .iter()
                    .any(|s| s.contains("session value this check invented in `sid` and")),
                "the setup: the session cookie is the one altered: {:#?}",
                believing.steps
            );
            assert!(
                rule_ids(&believing).contains(&SESSION_TOKEN_UNVERIFIED.rule_id),
                "needed {needed}: {:?}",
                rule_ids(&believing)
            );
            assert!(!verified_ids(&believing).contains(&SESSION_TOKEN_UNVERIFIED.rule_id));
            // The control: an app that checks its sessions is credited, with the other cookie
            // kept where the app refuses requests without it.
            let correct = run_with_pre_login_cookie(false, needed);
            assert!(
                !rule_ids(&correct).contains(&SESSION_TOKEN_UNVERIFIED.rule_id),
                "needed {needed}: {:?}",
                rule_ids(&correct)
            );
            assert!(
                verified_ids(&correct).contains(&SESSION_TOKEN_UNVERIFIED.rule_id),
                "needed {needed}: {:?}\n{:#?}",
                verified_ids(&correct),
                correct.not_assessed
            );
        }
    }

    /// An app that answers each request id from a list, and records what it was sent.
    struct Scripted {
        open: Vec<&'static str>,
        sent: Vec<ProbeRequest>,
    }

    impl Http for Scripted {
        fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
            self.sent.push(request.clone());
            Some(ProbeResponse {
                id: request.id.clone(),
                status: if self.open.contains(&request.id.as_str()) {
                    200
                } else {
                    403
                },
                headers: Vec::new(),
                body: String::new(),
            })
        }
    }

    fn signed_in_with(bearer: Option<&str>, set_at_login: &[&str]) -> SignedIn {
        let mut session = Session::default();
        session
            .cookies
            .push(("csrftoken".into(), "pre-login-value".into()));
        session
            .cookies
            .push(("sid".into(), "0123456789abcdef0123".into()));
        session.bearer = bearer.map(str::to_owned);
        SignedIn {
            session,
            set_at_login: set_at_login
                .iter()
                .map(|n| Cookie {
                    name: (*n).to_owned(),
                    value: String::new(),
                    http_only: true,
                    same_site: None,
                    secure: false,
                    path: None,
                })
                .collect(),
            before_login: Vec::new(),
            landed: String::new(),
            limited: false,
        }
    }

    #[test]
    fn a_made_up_value_that_opens_the_page_is_a_finding_only_where_those_cookies_carry_the_session()
    {
        // The review of 1 to 4 October, item 13: an app whose session is the cookie from before
        // sign-in, which sets another cookie at sign-in, was found to take a made-up session.
        for carried in [Some(false), None] {
            let mut app = Scripted {
                open: vec!["invented-session-control", "invented-session"],
                sent: Vec::new(),
            };
            let mut out = Outcome::default();
            invented_session_check(
                &mut app,
                &signed_in_with(None, &["sid"]),
                Some("/account"),
                carried,
                &mut out,
            );
            assert!(rule_ids(&out).is_empty(), "{carried:?}: {out:#?}");
            assert!(out.verified.is_empty(), "{carried:?}: {out:#?}");
            assert!(
                out.not_assessed
                    .iter()
                    .any(|(id, why)| id == "V7.2.1" && why.contains("carry the session")),
                "{carried:?}: {out:#?}"
            );
        }
        // Shown to carry it: the finding stands.
        let mut app = Scripted {
            open: vec!["invented-session-control", "invented-session"],
            sent: Vec::new(),
        };
        let mut out = Outcome::default();
        invented_session_check(
            &mut app,
            &signed_in_with(None, &["sid"]),
            Some("/account"),
            Some(true),
            &mut out,
        );
        assert_eq!(rule_ids(&out), vec![SESSION_TOKEN_UNVERIFIED.rule_id]);
    }

    #[test]
    fn a_refusal_is_credited_only_after_the_real_session_opened_the_page() {
        // The control opens, the made-up session does not: credited, and the request differed
        // from the real one in `sid` alone.
        let mut app = Scripted {
            open: vec!["invented-session-control"],
            sent: Vec::new(),
        };
        let mut out = Outcome::default();
        invented_session_check(
            &mut app,
            &signed_in_with(None, &["sid"]),
            Some("/account"),
            Some(true),
            &mut out,
        );
        assert!(
            verified_ids(&out).contains(&SESSION_TOKEN_UNVERIFIED.rule_id),
            "{out:#?}"
        );
        let invented = app
            .sent
            .iter()
            .find(|r| r.id == "invented-session")
            .expect("sent");
        let cookie = &invented
            .headers
            .iter()
            .find(|(k, _)| k == "Cookie")
            .expect("cookies")
            .1;
        assert!(cookie.contains("csrftoken=pre-login-value"), "{cookie}");
        assert!(!cookie.contains("0123456789abcdef0123"), "{cookie}");
        assert!(cookie.contains("sid=sv0probe0invented0s"), "{cookie}");

        // Everything refused, the real session included: nothing is shown, so nothing credited.
        let mut app = Scripted {
            open: Vec::new(),
            sent: Vec::new(),
        };
        let mut out = Outcome::default();
        invented_session_check(
            &mut app,
            &signed_in_with(None, &["sid"]),
            Some("/account"),
            Some(true),
            &mut out,
        );
        assert!(
            !verified_ids(&out).contains(&SESSION_TOKEN_UNVERIFIED.rule_id),
            "{out:#?}"
        );
        assert!(rule_ids(&out).is_empty(), "{out:#?}");
        assert!(
            out.not_assessed
                .iter()
                .any(|(id, why)| id == "V7.2.1" && why.contains("real session"))
        );

        // No cookie set at sign-in, or a token beside the cookies: not assessed, nothing sent.
        for signed_in in [
            signed_in_with(None, &[]),
            signed_in_with(Some("token"), &["sid"]),
        ] {
            let mut app = Scripted {
                open: vec!["invented-session-control", "invented-session"],
                sent: Vec::new(),
            };
            let mut out = Outcome::default();
            invented_session_check(&mut app, &signed_in, Some("/account"), Some(true), &mut out);
            assert!(app.sent.is_empty(), "{:?}", app.sent);
            assert!(
                out.verified.is_empty() && out.findings.is_empty(),
                "{out:#?}"
            );
            assert!(
                out.not_assessed.iter().any(|(id, _)| id == "V7.2.1"),
                "{out:#?}"
            );
        }
    }

    #[test]
    fn a_session_id_is_measured_by_its_length_and_kinds_of_character() {
        assert!(most_bits("s7919x1") < 128.0);
        assert!(most_bits("0123456789abcdef0123456789abcdef") >= 128.0);
        // Twenty-two base64 characters hold 128 bits and no more.
        assert!(most_bits("aB3dE5fG7hI9jK1lM3nO5p") >= 128.0);
        // An upper bound: a long run of one letter passes. It can only ever show an id too short.
        assert!(most_bits("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") >= 128.0);
        assert_eq!(most_bits(""), 0.0);
    }

    // ---- The private pages themselves: what they let a browser keep (V14.3.2), and whether they
    // show a way out (V7.4.4).

    #[test]
    fn no_cache_is_not_no_store() {
        // The distinction the whole check turns on, and the one an app is most likely to get
        // half-right. `no-cache` permits the browser to keep the copy and asks it to revalidate;
        // `private` only says not to keep it in a shared cache. Neither is what V14.3.2 asks for,
        // and a substring search for "no-store" inside "no-cache, private" would find nothing
        // anyway — what would pass wrongly is a looser reading of the header.
        for value in [
            "no-cache",
            "private",
            "max-age=0",
            "no-cache, private, max-age=0",
            "private, s-maxage=60",
        ] {
            let mut app = FakeApp::new(Flaws::default());
            app.cache_control = Some(value.to_string());
            let acc = accounts();
            app.users
                .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
            app.users
                .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
            let admin = acc.admin.clone().unwrap();
            app.users.insert(admin.user, (admin.password, true));
            let o = run(&mut app, &users(), &acc, true, &Default::default());
            assert!(
                rule_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
                "`{value}` was accepted as no-store: {:?}",
                rule_ids(&o)
            );
            assert!(
                !verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
                "`{value}` was credited as no-store"
            );
            // None of these tells a shared cache it may keep the page.
            assert!(
                !rule_ids(&o).contains(&PRIVATE_PAGE_SHARED_CACHE.rule_id),
                "`{value}` was read as open to shared caches"
            );
        }
    }

    #[test]
    fn an_app_whose_private_pages_are_public_is_found_in_a_full_run() {
        let o = run_against(
            Flaws {
                private_page_shared_cache: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            rule_ids(&o).contains(&PRIVATE_PAGE_SHARED_CACHE.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(!verified_ids(&o).contains(&PRIVATE_PAGE_SHARED_CACHE.rule_id));
    }

    #[test]
    fn private_pages_without_the_browser_headers_are_found_and_with_them_credited() {
        let bare = run_against(
            Flaws {
                private_page_no_headers: true,
                ..Default::default()
            },
            &users(),
        );
        let found = bare
            .findings
            .iter()
            .find(|f| f.rule_id == PRIVATE_PAGE_HEADERS.rule_id)
            .unwrap_or_else(|| panic!("{:?}", rule_ids(&bare)));
        assert!(
            found
                .description
                .contains("/account came back without Content-Security-Policy"),
            "{}",
            found.description
        );
        assert!(!verified_ids(&bare).contains(&PRIVATE_PAGE_HEADERS.rule_id));

        // A policy short of what V3.4.3 names is found on a private page too (ADR-047).
        let short = run_against(
            Flaws {
                private_page_policy_without_base_uri: true,
                ..Default::default()
            },
            &users(),
        );
        let found = short
            .findings
            .iter()
            .find(|f| f.rule_id == PRIVATE_PAGE_HEADERS.rule_id)
            .unwrap_or_else(|| panic!("{:?}", rule_ids(&short)));
        assert!(
            found.description.contains("without `base-uri 'none'`"),
            "{}",
            found.description
        );
        assert!(!verified_ids(&short).contains(&PRIVATE_PAGE_HEADERS.rule_id));

        // The control: the same app with the headers, where the page really opened.
        let correct = run_against(Flaws::default(), &users());
        assert!(!rule_ids(&correct).contains(&PRIVATE_PAGE_HEADERS.rule_id));
        assert!(verified_ids(&correct).contains(&PRIVATE_PAGE_HEADERS.rule_id));
        assert!(
            correct
                .steps
                .iter()
                .any(|s| s == "1 of 1 private page sent the headers a browser relies on"),
            "{:?}",
            correct.steps
        );
    }

    /// A signed-in run against a fake app whose private pages send exactly `cache_control`.
    fn run_with_cache_control(cache_control: &str) -> Outcome {
        let mut app = FakeApp::new(Flaws::default());
        app.cache_control = Some(cache_control.to_string());
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        run(&mut app, &users(), &acc, true, &Default::default())
    }

    #[test]
    fn a_private_page_shared_caches_may_keep_is_found_against_v14_2_2() {
        for value in [
            "public, max-age=60",
            "s-maxage=300",
            "Public",
            "max-age=0, s-maxage=60",
        ] {
            let o = run_with_cache_control(value);
            let f = o
                .findings
                .iter()
                .find(|f| f.rule_id == PRIVATE_PAGE_SHARED_CACHE.rule_id)
                .unwrap_or_else(|| panic!("`{value}` was not found: {:?}", rule_ids(&o)));
            assert_eq!(f.requirement_ids, vec!["V14.2.2"]);
            assert!(
                o.steps
                    .join(" | ")
                    .contains("1 of 1 private page told shared caches they may keep it"),
                "{:?}",
                o.steps
            );
        }
        // The controls: `private` or `no-store` keeps it out of shared caches whatever else is
        // there, and a page that says nothing about shared caches is not found either. None is
        // ever credited: a server cache this cannot see may still keep the page.
        for value in [
            "private, s-maxage=60",
            "public, no-store",
            "no-cache",
            "no-store",
            "max-age=60",
        ] {
            let o = run_with_cache_control(value);
            assert!(
                !rule_ids(&o).contains(&PRIVATE_PAGE_SHARED_CACHE.rule_id),
                "`{value}` was found"
            );
            assert!(!verified_ids(&o).contains(&PRIVATE_PAGE_SHARED_CACHE.rule_id));
            assert!(
                o.steps
                    .join(" | ")
                    .contains("0 of 1 private page told shared caches they may keep it"),
                "the page was not really opened for `{value}`: {:?}",
                o.steps
            );
        }
    }

    #[test]
    fn the_run_note_counts_the_pages_that_answered_each_question() {
        // A second reading of the same two checks, on the surface the owner actually sees. The
        // findings list says something is wrong; this line says how much of the app was looked at,
        // and a check that silently examined nothing would still print a reassuring "0 of 0".
        let correct = run_against(Flaws::default(), &users());
        let steps = correct.steps.join(" | ");
        assert!(
            steps.contains("1 of 1 private page sent Cache-Control: no-store"),
            "{steps}"
        );
        assert!(
            steps.contains("1 of 1 private page showed a way to reach /logout"),
            "{steps}"
        );

        let mut app = FakeApp::new(Flaws::default());
        app.cache_control = Some("no-cache, private".to_string());
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let loose = run(&mut app, &users(), &acc, true, &Default::default());
        assert!(
            loose
                .steps
                .join(" | ")
                .contains("0 of 1 private page sent Cache-Control: no-store"),
            "`no-cache, private` was counted as no-store in the run note: {:?}",
            loose.steps
        );
    }

    #[test]
    fn no_store_among_other_directives_is_still_no_store() {
        // The other direction: a real app writes `no-store, max-age=0` or
        // `private, no-store, must-revalidate`, and refusing those would be a finding for every
        // app that gets this right.
        for value in [
            "no-store",
            "no-store, max-age=0",
            "private, no-store, must-revalidate",
            "No-Store",
        ] {
            let mut app = FakeApp::new(Flaws::default());
            app.cache_control = Some(value.to_string());
            let acc = accounts();
            app.users
                .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
            app.users
                .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
            let admin = acc.admin.clone().unwrap();
            app.users.insert(admin.user, (admin.password, true));
            let o = run(&mut app, &users(), &acc, true, &Default::default());
            assert!(
                !rule_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
                "`{value}` was refused as no-store"
            );
            assert!(
                verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
                "`{value}` was not credited"
            );
        }
    }

    #[test]
    fn a_sign_out_address_only_mentioned_in_a_script_is_not_a_visible_way_out() {
        // `points_at` reads href and action attributes rather than searching the page for the
        // text. A page that names the sign-out address in a script string or a comment offers the
        // person nothing, and a substring search would have credited it.
        assert!(!points_at(
            "<script>const LOGOUT = '/logout';</script><!-- /logout -->",
            "/logout"
        ));
        assert!(!points_at("you can sign out at /logout one day", "/logout"));
        assert!(points_at("<a href='/logout'>Sign out</a>", "/logout"));
        assert!(points_at(
            "<form method='post' action='/logout'><button>out</button></form>",
            "/logout"
        ));
        // Spellings a real page uses, which must not cost an app the credit.
        assert!(points_at("<a href=\"/logout/\">out</a>", "/logout"));
        assert!(points_at("<a href=\"/logout?next=/\">out</a>", "/logout"));
        assert!(!points_at("<a href='/logout-help'>help</a>", "/logout"));
    }

    #[test]
    fn a_private_page_that_never_opened_answers_neither_question() {
        // The setup-first rule. If the signed-in session cannot open the private page, there are no
        // headers worth reading and no link worth looking for, and both requirements must come back
        // not assessed rather than as a pass or a finding.
        //
        // A page that never opens also stops the run before these checks are reached at all, so
        // what this really pins is that the bail-out names them: a requirement nothing asked about
        // has to be said out loud wherever the asking stopped.
        let mut broken = users();
        broken.private = vec!["/nowhere".into()];
        let o = run_against(Flaws::default(), &broken);
        assert!(
            !rule_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id)
                && !rule_ids(&o).contains(&SIGN_OUT_LINK.rule_id),
            "a page that never opened produced a finding: {:?}",
            rule_ids(&o)
        );
        assert!(
            !verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id)
                && !verified_ids(&o).contains(&SIGN_OUT_LINK.rule_id),
            "a page that never opened was credited"
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, _)| ids.contains("V14.3.2") && ids.contains("V7.4.4")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_app_with_no_private_pages_listed_answers_neither_question() {
        // The other way to have nowhere to look. `private = []` reaches the checks rather than
        // bailing out before them, so this is the branch inside `private_page_checks` itself.
        let mut none = users();
        none.private = Vec::new();
        let o = run_against(Flaws::default(), &none);
        assert!(
            !rule_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id)
                && !rule_ids(&o).contains(&SIGN_OUT_LINK.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(
            !verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id)
                && !verified_ids(&o).contains(&SIGN_OUT_LINK.rule_id),
            "nothing was read, so nothing may be credited"
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, _)| ids.contains("V14.3.2") && ids.contains("V7.4.4")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn without_a_sign_out_address_the_link_question_is_not_asked() {
        // V7.4.4 needs somewhere to look for. With no `logout` in securevibe.toml, "no sign-out
        // link" would be a statement about the manifest rather than about the app — but the caching
        // question does not depend on it and must still be answered.
        let mut no_logout = users();
        no_logout.logout = None;
        let o = run_against(Flaws::default(), &no_logout);
        assert!(!rule_ids(&o).contains(&SIGN_OUT_LINK.rule_id));
        assert!(!verified_ids(&o).contains(&SIGN_OUT_LINK.rule_id));
        assert!(
            o.not_assessed.iter().any(|(ids, _)| ids.contains("V7.4.4")),
            "{:?}",
            o.not_assessed
        );
        assert!(
            verified_ids(&o).contains(&PRIVATE_PAGE_CACHING.rule_id),
            "the caching question does not depend on the sign-out address"
        );
    }

    // --------------------------------------------------------------------------------------------
    // Session timeouts, waited out with --slow

    const TIMEOUT_RULES: [&str; 2] = [NO_IDLE_TIMEOUT.rule_id, NO_SESSION_LIFETIME.rule_id];

    fn timeout_findings(o: &Outcome) -> Vec<&str> {
        rule_ids(o)
            .into_iter()
            .filter(|id| TIMEOUT_RULES.contains(id))
            .collect()
    }

    fn timeout_credits(o: &Outcome) -> Vec<&str> {
        verified_ids(o)
            .into_iter()
            .filter(|id| TIMEOUT_RULES.contains(id))
            .collect()
    }

    fn timeout_why(o: &Outcome, id: &str) -> Vec<String> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.contains(id))
            .map(|(_, why)| why.clone())
            .collect()
    }

    /// The seeded fixture, with the app's own timeouts in minutes, the owner's stated ones, and
    /// `slow` on.
    fn slow_run(
        app_idle: Option<u64>,
        app_lifetime: Option<u64>,
        policy: &sv_manifest::PolicySection,
        tune: impl FnOnce(&mut FakeApp),
    ) -> Outcome {
        let mut app = FakeApp::new(Flaws::default());
        app.idle_limit = app_idle.map(|m| m * 60);
        app.lifetime_limit = app_lifetime.map(|m| m * 60);
        tune(&mut app);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        super::run_with(&mut app, &users(), &acc, true, policy, true)
    }

    /// The same through sign-up rather than seeding.
    fn slow_signup_run(
        app_idle: Option<u64>,
        app_lifetime: Option<u64>,
        policy: &sv_manifest::PolicySection,
    ) -> Outcome {
        let mut app = FakeApp::new(Flaws::default());
        app.idle_limit = app_idle.map(|m| m * 60);
        app.lifetime_limit = app_lifetime.map(|m| m * 60);
        let mut acc = accounts();
        acc.admin = None;
        super::run_with(&mut app, &with_signup(), &acc, false, policy, true)
    }

    #[test]
    fn sessions_that_end_when_stated_are_credited_for_both() {
        let policy = timeouts(Some(15), Some(60));
        for o in [
            slow_run(Some(15), Some(60), &policy, |_| {}),
            slow_signup_run(Some(15), Some(60), &policy),
        ] {
            assert!(timeout_findings(&o).is_empty(), "{:#?}", o.findings);
            assert_eq!(
                timeout_credits(&o),
                vec![NO_IDLE_TIMEOUT.rule_id, NO_SESSION_LIFETIME.rule_id],
                "{:?}\n{:?}",
                o.steps,
                o.not_assessed
            );
        }
    }

    /// The same seeded app and accounts as `slow_run`, without `--slow`: nothing is waited for.
    fn fast_run(app_idle: Option<u64>, app_lifetime: Option<u64>) -> Outcome {
        let mut app = FakeApp::new(Flaws::default());
        app.idle_limit = app_idle.map(|m| m * 60);
        app.lifetime_limit = app_lifetime.map(|m| m * 60);
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let start = app.clock;
        let o = super::run_with(
            &mut app,
            &users(),
            &acc,
            true,
            &timeouts(Some(15), Some(60)),
            false,
        );
        assert!(app.clock - start < 5 * 60, "the run without --slow waited");
        o
    }

    #[test]
    fn after_the_wait_every_later_check_asks_with_a_session_signed_in_afresh() {
        // An app whose sessions end after 15 idle minutes and live at most 60, as stated: the
        // first sign-in's session is dead by the time the waiting is over. Through sign-up too,
        // where the record and form checks make their own requests with A's session.
        let policy = timeouts(Some(15), Some(60));
        for (how, slow, fast) in [
            (
                "seeded",
                slow_run(Some(15), Some(60), &policy, |_| {}),
                fast_run(Some(15), Some(60)),
            ),
            ("signed up", slow_signup_run(Some(15), Some(60), &policy), {
                let mut app = FakeApp::new(Flaws::default());
                app.idle_limit = Some(15 * 60);
                app.lifetime_limit = Some(60 * 60);
                let mut acc = accounts();
                acc.admin = None;
                super::run_with(&mut app, &with_signup(), &acc, false, &policy, false)
            }),
        ] {
            // The setup: the wait really ended idle sessions (the idle check saw one refused
            // beside a busy one that was not).
            assert_eq!(
                timeout_credits(&slow),
                vec![NO_IDLE_TIMEOUT.rule_id, NO_SESSION_LIFETIME.rule_id],
                "{how}: {:?}",
                slow.steps
            );
            // A correct app: nothing found with the slow run, and everything the fast run credits
            // the slow run credits too. Before the fix, the checks after the wait asked with A's
            // dead session.
            assert!(slow.findings.is_empty(), "{how}: {:#?}", slow.findings);
            let slow_credits = verified_ids(&slow);
            let fast_credits = verified_ids(&fast);
            assert!(
                fast_credits.len() > 5,
                "{how}: the fast run credits little: {fast_credits:?}"
            );
            let missing: Vec<&&str> = fast_credits
                .iter()
                .filter(|id| !slow_credits.contains(id))
                .collect();
            assert!(
                missing.is_empty(),
                "{how}: credited without --slow, not with it: {missing:?}\n{:?}",
                slow.not_assessed
            );
            // And it was the new sign-in that made the difference.
            assert!(
                slow.steps
                    .iter()
                    .any(|s| s.starts_with("signed in as A again after the wait")
                        && s.ends_with("(200)")),
                "{how}: {:?}",
                slow.steps
            );
            assert!(
                !slow
                    .not_assessed
                    .iter()
                    .any(|(_, why)| why.contains("signed in again")),
                "{how}: {:?}",
                slow.not_assessed
            );
        }
    }

    #[test]
    fn a_sign_in_that_fails_after_the_wait_leaves_the_rest_not_assessed_and_says_why() {
        // Sign-ins work for the first ten minutes, long enough for the timeout check's two
        // sessions, and are refused by the time the 16-minute wait is over.
        let o = slow_run(Some(15), None, &timeouts(Some(15), None), |app| {
            app.sign_ins_refused_from = Some(app.clock + 10 * 60);
        });
        // The idle timeout itself is still judged, with the sessions made before the refusals.
        assert_eq!(
            timeout_credits(&o),
            vec![NO_IDLE_TIMEOUT.rule_id],
            "{:?}",
            o.steps
        );
        // Nothing after the wait was asked, so nothing after it was found or credited.
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        for rule in [&LOGOUT, &OTHER_USERS_DATA, &FORGERY] {
            assert!(
                !verified_ids(&o).contains(&rule.rule_id),
                "{} credited with no working session: {:?}",
                rule.rule_id,
                o.steps
            );
        }
        assert!(
            !o.steps.iter().any(|s| s.contains("signed out")),
            "{:?}",
            o.steps
        );
        // And the owner is told why.
        let why = timeout_why(&o, "V8.2.1");
        assert!(
            why.iter()
                .any(|w| w.contains("signed in again") && w.contains("did not open")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_session_that_never_idles_out_is_found() {
        let policy = timeouts(Some(15), Some(60));
        for o in [
            slow_run(None, Some(60), &policy, |_| {}),
            slow_signup_run(None, Some(60), &policy),
        ] {
            assert_eq!(
                timeout_findings(&o),
                vec![NO_IDLE_TIMEOUT.rule_id],
                "{:?}",
                o.steps
            );
            assert_eq!(timeout_credits(&o), vec![NO_SESSION_LIFETIME.rule_id]);
        }
    }

    #[test]
    fn a_session_that_lasts_forever_when_busy_is_found() {
        let policy = timeouts(Some(15), Some(60));
        for o in [
            slow_run(Some(15), None, &policy, |_| {}),
            slow_signup_run(Some(15), None, &policy),
        ] {
            assert_eq!(
                timeout_findings(&o),
                vec![NO_SESSION_LIFETIME.rule_id],
                "{:?}",
                o.steps
            );
            assert_eq!(timeout_credits(&o), vec![NO_IDLE_TIMEOUT.rule_id]);
        }
    }

    #[test]
    fn a_timeout_longer_than_stated_is_found() {
        // Idle sessions do end, at 30 minutes: not at the 15 stated.
        let o = slow_run(Some(30), Some(60), &timeouts(Some(15), Some(60)), |_| {});
        assert_eq!(
            timeout_findings(&o),
            vec![NO_IDLE_TIMEOUT.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn an_idle_session_refused_beside_a_busy_one_refused_too_is_not_credited() {
        // Every session dies after ten minutes, busy or not: the idle one's refusal at sixteen
        // says nothing about idleness.
        for o in [
            slow_run(None, Some(10), &timeouts(Some(15), Some(60)), |_| {}),
            slow_signup_run(None, Some(10), &timeouts(Some(15), Some(60))),
        ] {
            assert!(!timeout_credits(&o).contains(&NO_IDLE_TIMEOUT.rule_id));
            assert!(!timeout_findings(&o).contains(&NO_IDLE_TIMEOUT.rule_id));
            assert!(
                timeout_why(&o, "V7.3.1")
                    .iter()
                    .any(|w| w.contains("kept busy")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_busy_session_refused_when_no_sign_in_works_is_not_credited() {
        // The app refuses every sign-in from 40 minutes in: the busy session's refusal at the
        // lifetime cannot be told from the app no longer letting anyone in.
        let policy = timeouts(None, Some(60));
        let o = slow_run(Some(15), Some(60), &policy, |app| {
            app.sign_ins_refused_from = Some(app.clock + 40 * 60);
        });
        assert!(
            !timeout_credits(&o).contains(&NO_SESSION_LIFETIME.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("new sign-in")),
            "{:?}",
            o.not_assessed
        );
        let o = slow_run(None, Some(30), &timeouts(None, Some(45)), |app| {
            app.sign_ins_refused_from = Some(app.clock + 40 * 60);
        });
        assert!(
            !timeout_credits(&o).contains(&NO_SESSION_LIFETIME.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn nothing_is_waited_for_without_slow_or_without_numbers() {
        let mut app = FakeApp::new(Flaws::default());
        let acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let start = app.clock;
        let o = super::run_with(
            &mut app,
            &users(),
            &acc,
            true,
            &timeouts(Some(15), Some(60)),
            false,
        );
        assert!(timeout_credits(&o).is_empty() && timeout_findings(&o).is_empty());
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("--slow"))
        );
        assert!(app.clock - start < 5 * 60, "it waited without --slow");

        let o = slow_run(None, None, &timeouts(None, None), |_| {});
        assert!(timeout_findings(&o).is_empty());
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("idle-timeout-minutes")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn numbers_that_cannot_be_waited_out_or_told_apart_are_said_so() {
        // A day is not waited for; the idle timeout is still judged.
        let o = slow_run(Some(15), None, &timeouts(Some(15), Some(24 * 60)), |_| {});
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("longer than"))
        );
        assert_eq!(timeout_credits(&o), vec![NO_IDLE_TIMEOUT.rule_id]);
        // An idle timeout no shorter than the lifetime cannot be told apart from it.
        let o = slow_run(Some(30), Some(30), &timeouts(Some(30), Some(30)), |_| {});
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("no shorter")),
            "{:?}",
            o.not_assessed
        );
        assert_eq!(timeout_credits(&o), vec![NO_SESSION_LIFETIME.rule_id]);
    }

    #[test]
    fn two_sessions_that_do_not_both_open_are_not_judged() {
        // One session per user: signing the busy one in ends the idle one at once. Its refusal at
        // the end would otherwise read as an idle timeout.
        let o = slow_run(None, None, &timeouts(Some(15), None), |app| {
            app.one_session_per_user = true;
        });
        assert!(timeout_credits(&o).is_empty(), "{:?}", o.steps);
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("did not both open")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn seeded_an_idle_refusal_with_the_busy_one_refused_too_is_not_credited() {
        let o = slow_run(Some(15), Some(10), &timeouts(Some(15), None), |_| {});
        assert!(
            !timeout_credits(&o).contains(&NO_IDLE_TIMEOUT.rule_id),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn through_sign_up_a_session_that_lasts_forever_is_found() {
        let o = slow_signup_run(None, None, &timeouts(None, Some(45)));
        assert_eq!(
            timeout_findings(&o),
            vec![NO_SESSION_LIFETIME.rule_id],
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_lifetime_refusal_when_sign_in_stopped_working_is_not_credited_through_a_short_lifetime() {
        let o = slow_run(None, Some(30), &timeouts(None, Some(45)), |app| {
            app.sign_ins_refused_from = Some(app.clock + 40 * 60);
        });
        assert!(
            !timeout_credits(&o).contains(&NO_SESSION_LIFETIME.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("new sign-in"))
        );
    }

    #[test]
    fn through_sign_up_nothing_is_waited_for_without_slow() {
        let mut app = FakeApp::new(Flaws::default());
        app.idle_limit = Some(15 * 60);
        let mut acc = accounts();
        acc.admin = None;
        let start = app.clock;
        let o = super::run_with(
            &mut app,
            &with_signup(),
            &acc,
            false,
            &timeouts(Some(15), None),
            false,
        );
        assert!(timeout_credits(&o).is_empty());
        assert!(app.clock - start < 5 * 60, "it waited without --slow");
    }

    #[test]
    fn through_sign_up_no_numbers_are_said_to_be_needed() {
        let o = slow_signup_run(Some(15), None, &timeouts(None, None));
        assert!(timeout_credits(&o).is_empty());
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("session-lifetime-minutes"))
        );
    }

    #[test]
    fn a_lifetime_of_two_hours_is_not_waited_for() {
        let o = slow_run(None, None, &timeouts(None, Some(120)), |_| {});
        assert!(timeout_findings(&o).is_empty(), "{:?}", o.steps);
        assert!(
            timeout_why(&o, "V7.3.2")
                .iter()
                .any(|w| w.contains("longer than"))
        );
    }

    #[test]
    fn an_idle_timeout_longer_than_the_lifetime_is_not_judged() {
        let o = slow_run(None, Some(30), &timeouts(Some(45), Some(30)), |_| {});
        assert!(
            !timeout_findings(&o).contains(&NO_IDLE_TIMEOUT.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            timeout_why(&o, "V7.3.1")
                .iter()
                .any(|w| w.contains("no shorter"))
        );
    }

    fn ws_why<'o>(o: &'o Outcome, id: &str) -> Vec<&'o str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.split(", ").any(|i| i == id))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn a_socket_that_needs_a_real_session_is_credited_and_sign_out_said_as_partial() {
        let o = ws_run(Flaws::default());
        assert!(ws_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(
            verified_ids(&o).contains(&WS_WITHOUT_SESSION.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&WS_AFTER_SIGN_OUT.rule_id));
        let steps = o.steps.join("\n");
        for step in [
            "opened the WebSocket at /ws signed in: accepted; with no session: refused; with a session value this check made up: refused",
            "signed that session out, then opened the WebSocket with its old cookie: refused",
        ] {
            assert!(steps.contains(step), "{step}:\n{steps}");
        }
        assert!(
            ws_why(&o, "V4.4.3")
                .iter()
                .any(|w| w.contains("Only one part")),
            "{:?}",
            ws_why(&o, "V4.4.3")
        );
    }

    #[test]
    fn each_way_a_private_socket_opens_is_found() {
        for (flaws, found) in [
            (
                Flaws {
                    ws_open: true,
                    ..Default::default()
                },
                vec![WS_WITHOUT_SESSION.rule_id],
            ),
            (
                Flaws {
                    ws_any_cookie: true,
                    ..Default::default()
                },
                vec![WS_WITHOUT_SESSION.rule_id],
            ),
            (
                Flaws {
                    ws_guest: true,
                    ..Default::default()
                },
                vec![WS_WITHOUT_SESSION.rule_id],
            ),
            (
                Flaws {
                    ws_survives_sign_out: true,
                    ..Default::default()
                },
                vec![WS_AFTER_SIGN_OUT.rule_id],
            ),
        ] {
            let o = ws_run(flaws);
            assert_eq!(ws_findings(&o), found, "{found:?}: {:?}", o.steps);
            if found == vec![WS_WITHOUT_SESSION.rule_id] {
                assert!(
                    ws_why(&o, "V4.4.3")
                        .iter()
                        .any(|w| w.contains("not shown to need a real session")),
                    "{:?}",
                    o.not_assessed
                );
            }
            for rule in &found {
                assert!(
                    !verified_ids(&o).contains(rule),
                    "{rule} found and credited"
                );
            }
        }
    }

    #[test]
    fn a_made_up_cookie_alone_is_enough_for_the_finding() {
        // The anonymous handshake is refused here; only the invented value gets in.
        let o = ws_run(Flaws {
            ws_any_cookie: true,
            ..Default::default()
        });
        assert!(
            o.steps.iter().any(|s| s.contains(
                "with no session: refused; with a session value this check made up: accepted"
            )),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&WS_WITHOUT_SESSION.rule_id));
        assert_eq!(ws_findings(&o), vec![WS_WITHOUT_SESSION.rule_id]);
    }

    #[test]
    fn a_socket_that_refuses_everybody_shows_nothing() {
        let o = ws_run(Flaws {
            ws_refuses_all: true,
            ..Default::default()
        });
        assert!(ws_findings(&o).is_empty());
        assert!(!verified_ids(&o).contains(&WS_WITHOUT_SESSION.rule_id));
        assert!(
            ws_why(&o, "V4.4.4")
                .iter()
                .any(|w| w.contains("was not accepted")),
            "{:?}",
            o.not_assessed
        );
        assert!(
            !o.steps.iter().any(|s| s.contains("with no session")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_sign_out_that_ends_nothing_leaves_the_socket_unjudged_after_it() {
        // The session outlives sign-out everywhere, so the socket opening afterwards says nothing
        // the logout check has not already said; it is still a finding, the socket's own.
        let o = ws_run(Flaws {
            logout_keeps_session: true,
            ..Default::default()
        });
        assert!(
            ws_findings(&o).contains(&WS_AFTER_SIGN_OUT.rule_id),
            "{:?}",
            o.steps
        );
        // And a sign-out the app refuses is said, not judged.
        let mut u = users();
        u.private_websocket = Some("/ws".into());
        if let Some(logout) = u.logout.as_mut() {
            logout.form.remove("csrf_token");
        }
        let o = run_against(Flaws::default(), &u);
        assert!(!ws_findings(&o).contains(&WS_AFTER_SIGN_OUT.rule_id));
        assert!(
            ws_why(&o, "V4.4.3")
                .iter()
                .any(|w| w.contains("sign-out itself was refused")),
            "{:?}",
            ws_why(&o, "V4.4.3")
        );
    }

    #[test]
    fn with_no_private_websocket_nothing_is_asked_or_said() {
        let o = run_against(Flaws::default(), &users());
        assert!(!o.steps.iter().any(|s| s.contains("WebSocket")));
        assert!(ws_why(&o, "V4.4.4").is_empty());
        assert!(ws_why(&o, "V4.4.3").is_empty());
    }

    #[test]
    fn a_private_websocket_that_is_not_a_path_is_a_manifest_problem() {
        let mut u = users();
        u.private_websocket = Some("ws".into());
        assert!(u.problems().iter().any(|p| p.contains("private-websocket")));
    }

    #[test]
    fn a_socket_that_lets_in_a_handshake_with_no_cookie_is_found() {
        let o = ws_run(Flaws {
            ws_guest: true,
            ..Default::default()
        });
        assert_eq!(
            ws_findings(&o),
            vec![WS_WITHOUT_SESSION.rule_id],
            "{:?}",
            o.steps
        );
        let finding = o
            .findings
            .iter()
            .find(|f| f.rule_id == WS_WITHOUT_SESSION.rule_id)
            .unwrap();
        assert!(finding.description.contains("with no session at all"));
        // And sign-out is not asked of a socket that never needed a session.
        assert!(
            ws_why(&o, "V4.4.3")
                .iter()
                .any(|w| w.contains("not shown to need a real session")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_session_that_is_not_a_cookie_cannot_be_made_up_so_nothing_is_credited() {
        let o = run_against(Flaws::default(), &bearer_ws_users());
        assert!(ws_findings(&o).is_empty(), "{:#?}", o.findings);
        assert!(!verified_ids(&o).contains(&WS_WITHOUT_SESSION.rule_id));
        assert!(
            ws_why(&o, "V4.4.4")
                .iter()
                .any(|w| w.contains("was not a cookie")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_bearer_socket_refusing_a_bare_handshake_still_earns_no_credit() {
        let o = run_against(
            Flaws {
                ws_survives_sign_out: true,
                ..Default::default()
            },
            &bearer_ws_users(),
        );
        assert!(!verified_ids(&o).contains(&WS_WITHOUT_SESSION.rule_id));
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("signed in: accepted; with no session: refused")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_path_that_is_not_the_socket_is_said_and_nothing_judged() {
        let mut u = users();
        u.private_websocket = Some("/account".into());
        let o = run_against(Flaws::default(), &u);
        assert!(ws_findings(&o).is_empty());
        assert!(!verified_ids(&o).contains(&WS_WITHOUT_SESSION.rule_id));
        assert!(
            ws_why(&o, "V4.4.3")
                .iter()
                .any(|w| w.contains("`private-websocket` is not where")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_sign_out_sent_nowhere_is_said_and_not_judged() {
        let mut u = users();
        u.private_websocket = Some("/ws".into());
        if let Some(logout) = u.logout.as_mut() {
            logout.path = "/nowhere".into();
        }
        let o = run_against(
            Flaws {
                ws_survives_sign_out: true,
                ..Default::default()
            },
            &u,
        );
        assert!(!ws_findings(&o).contains(&WS_AFTER_SIGN_OUT.rule_id));
        assert!(
            ws_why(&o, "V4.4.3")
                .iter()
                .any(|w| w.contains("sign-out itself was refused")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_header_that_names_a_user_and_opens_a_private_page_is_found() {
        let o = run_against(
            Flaws {
                trusts_identity_header: true,
                ..Default::default()
            },
            &users(),
        );
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == IDENTITY_HEADER.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(
            found.description.contains("X-Remote-User"),
            "{}",
            found.description
        );
        // Only the header the app trusts is named.
        assert!(
            !found.description.contains("X-Forwarded-User"),
            "{}",
            found.description
        );
        assert!(!verified_ids(&o).contains(&IDENTITY_HEADER.rule_id));
    }

    #[test]
    fn an_app_that_ignores_identity_headers_raises_nothing_and_says_it_asked() {
        let o = run_against(Flaws::default(), &users());
        assert!(!rule_ids(&o).contains(&IDENTITY_HEADER.rule_id));
        // Never credited either: eight header names are not every header a proxy may use.
        assert!(!verified_ids(&o).contains(&IDENTITY_HEADER.rule_id));
        let step = o
            .steps
            .iter()
            .find(|s| s.contains("headers that name a user"))
            .unwrap_or_else(|| panic!("the check ran: {:?}", o.steps));
        assert!(step.ends_with(": 0 let in"), "{step}");
    }

    #[test]
    fn a_private_page_open_to_anybody_is_not_blamed_on_a_header() {
        // Of two pages listed as private, one is open without any header; that is the
        // private-page finding, and only the other is asked with one.
        let mut u = users();
        u.private.push("/notes".into());
        let o = run_against(
            Flaws {
                trusts_identity_header: true,
                ..Default::default()
            },
            &u,
        );
        assert!(
            rule_ids(&o).contains(&PRIVATE_PAGE.rule_id),
            "{:?}",
            o.steps
        );
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == IDENTITY_HEADER.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(
            !found.description.contains("/notes"),
            "{}",
            found.description
        );
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("asked for 1 private page without signing in")),
            "{:?}",
            o.steps
        );
    }
}
