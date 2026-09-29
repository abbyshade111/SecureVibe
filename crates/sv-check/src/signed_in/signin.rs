use super::*;

/// Accounts somebody might leave in place, tried with their name as the password and with
/// `password`.
const DEFAULT_ACCOUNTS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("administrator", "administrator"),
];

/// One wrong sign-in attempt, carrying `extra` headers, in a fresh session; the status it got, 0 for
/// no answer.
fn guess_once(
    http: &mut dyn Http,
    login: &RequestTemplate,
    wrong: &Account,
    id: &str,
    extra: &[(&str, &str)],
) -> u16 {
    let mut session = Session::default();
    let mut csrf = None;
    if let Some(page) = http.send(&get(&format!("{id}-page"), &login.path, &session)) {
        session.absorb(&page);
        csrf = csrf_token(&page, &session);
    }
    let values = Values {
        user: &wrong.user,
        password: &wrong.password,
        csrf,
        ..Default::default()
    };
    let mut req = request(id, login, &values, &session);
    for (k, v) in extra {
        req.headers.push(((*k).to_owned(), (*v).to_owned()));
    }
    http.send(&req).map_or(0, |r| r.status)
}

/// Whether the limit on guessing believes an address the client made up (V15.3.4).
///
/// Called once the brute-force check has seen the app refuse. Two more wrong attempts, each
/// claiming a different new address from the range set aside for documentation, in every header an
/// app might take one from; then two more claiming nothing. Both claimed attempts answered as the
/// very first attempt was, while both plain ones are still refused, is a limiter that let a header
/// the client wrote lift it. The plain pair is the control: a limit that lifted by itself lifts for
/// them too.
///
/// Two of each, not one: a limiter that lets one attempt through for every one it refuses — a token
/// bucket, a sliding window, `nginx limit_req` — answers one claimed and one plain attempt in exactly
/// the pattern of a limit that believes the header, and reported a correct app for it. Found in
/// review with a fake limiter that leaks (`lockout_leaks`). Alternating the attempts does not help:
/// such a limiter produces exactly that alternation. The remaining blind spot is the other
/// direction — a leaky limiter can still hide an app that does trust the header — which is the safe
/// one, since this is only ever a finding.
///
/// Only ever a finding. An app whose limit counts by account is not moved by the header at all,
/// and that shows nothing about how it treats addresses.
fn forwarded_check(
    http: &mut dyn Http,
    login: &RequestTemplate,
    wrong: &Account,
    first_status: u16,
    out: &mut Outcome,
) {
    const ADDRESSES: [&str; 2] = ["203.0.113.77", "203.0.113.78"];
    let spoofed: Vec<u16> = ADDRESSES
        .iter()
        .enumerate()
        .map(|(n, address)| {
            let forwarded = format!("for={address}");
            guess_once(
                http,
                login,
                wrong,
                &format!("guess-forwarded-{n}"),
                &[
                    ("X-Forwarded-For", address),
                    ("X-Real-IP", address),
                    ("Forwarded", &forwarded),
                ],
            )
        })
        .collect();
    let plain: Vec<u16> = (0..2)
        .map(|n| {
            guess_once(
                http,
                login,
                wrong,
                &format!("guess-after-forwarded-{n}"),
                &[],
            )
        })
        .collect();
    let lifted = spoofed.iter().all(|s| *s == first_status);
    let still_refused = plain.iter().all(|p| *p != first_status);
    let said = |answers: &[u16]| {
        let all_first = answers.iter().all(|a| *a == first_status);
        let none_first = answers.iter().all(|a| *a != first_status);
        let list = answers
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if all_first {
            format!("answered {list}, as the first attempt was")
        } else if none_first {
            format!("still refused ({list})")
        } else {
            format!("answered {list}, one as the first attempt was and one refused")
        }
    };
    out.steps.push(format!(
        "two more wrong attempts claiming to come from {} and {}: {}; two more claiming nothing: {}",
        ADDRESSES[0],
        ADDRESSES[1],
        said(&spoofed),
        said(&plain)
    ));
    if lifted && still_refused {
        out.findings.push(finding(
            &FORWARDED_TRUSTED,
            "The limit on guessing passwords can be lifted by claiming another address",
            Severity::Medium,
            format!(
                "After the app started refusing wrong passwords, two more attempts, carrying \
                 `X-Forwarded-For: {}` and then `{}`, were both answered as the very first attempt \
                 was, while the two after them, claiming nothing, were both still refused. Nothing \
                 sits in front of the app here, so the addresses came from the requests \
                 themselves.",
                ADDRESSES[0], ADDRESSES[1]
            ),
        ));
    }
}

/// Whether the app pushes back after the number of wrong passwords the owner said it would (V6.3.1).
///
/// V6.3.1 asks that brute-force controls are implemented *according to the application's security
/// documentation*, which nothing can check against prose. A number can be checked: `failed-sign-ins`
/// in securevibe.toml is the owner stating the policy, and the probe holds the app to it by making
/// one more wrong attempt than that and watching what changes.
///
/// What counts as pushing back is deliberately broad — a different status, a refusal, a lockout or
/// an error page, or an attempt that takes markedly longer than the first. Narrowing it would make
/// the check report apps that defend themselves in a way this did not anticipate, and a check that
/// cries wolf is one people learn to skip.
///
/// Three things it does not do. It never uses A or B, whose sessions the checks above depend on,
/// and never the admin: it makes its own account through `signup`, or uses a name no account can
/// have. It does not test `within-minutes`, because every attempt here lands within a few seconds,
/// which is inside any window worth stating — the count is the testable half and the report says so.
/// And a clean result is *checked* rather than a pass: it shows the app pushed back at the stated
/// number on one run, not that the control is correct.
pub(super) fn brute_force_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    policy: &sv_manifest::PolicySection,
    out: &mut Outcome,
) {
    let Some(login) = users.login.as_ref() else {
        return;
    };
    let Some(allowed) = policy.failed_sign_ins else {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            "Whether the app resists password guessing: say how many wrong passwords in a row it \
             should allow, as `failed-sign-ins` under [policy] in securevibe.toml, and this will \
             make one more attempt than that and watch what the app does."
                .to_owned(),
        ));
        return;
    };
    // Zero would mean the first attempt is already too many, which no app can implement and no
    // owner means. Said rather than silently treated as one.
    if allowed == 0 {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            "[policy] failed-sign-ins is 0, which would mean refusing the first attempt anybody \
             makes. Set it to the number of wrong passwords in a row the app should allow."
                .to_owned(),
        ));
        return;
    }
    // A cap, so a large number cannot turn one check into thousands of requests against somebody's
    // app. Above it the check says what it did rather than pretending to have tested the policy.
    const MOST_ATTEMPTS: u32 = 25;
    if allowed >= MOST_ATTEMPTS {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            format!(
                "[policy] failed-sign-ins is {allowed}. This check makes at most {MOST_ATTEMPTS} \
                 attempts, so it cannot reach that number; a limit that high is worth reconsidering \
                 on its own."
            ),
        ));
        return;
    }

    // An account whose password this check knows, so a wrong one is certainly wrong: its own,
    // through sign-up, and failing that a name no account can have. The second only exercises a
    // limiter that counts by address; the report says which was used.
    let target = match &users.signup {
        Some(signup) => {
            let account = Account {
                user: format!("guessed.{}", accounts.a.user),
                password: format!(
                    "Gx-{}-1aZ!",
                    accounts.b.password.chars().take(12).collect::<String>()
                ),
            };
            sign_up(http, users, signup, "guessed", &account);
            account
        }
        None => Account {
            user: format!("nobody.{}", accounts.a.user),
            password: "this-account-does-not-exist".to_owned(),
        },
    };
    let real_account = users.signup.is_some();

    let wrong = Account {
        user: target.user.clone(),
        password: "Wrong-Password-For-This-Probe-1!".to_owned(),
    };
    let attempts = allowed + 1;
    let mut answers: Vec<(u16, u128)> = Vec::new();
    for n in 0..attempts {
        let mut session = Session::default();
        let mut csrf = None;
        if let Some(page) = http.send(&get(&format!("guess-page-{n}"), &login.path, &session)) {
            session.absorb(&page);
            csrf = csrf_token(&page, &session);
        }
        let values = Values {
            user: &wrong.user,
            password: &wrong.password,
            csrf,
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let (response, _) = send_template(
            http,
            &format!("guess-{n}"),
            login,
            &values,
            &mut session,
            &[],
        );
        let elapsed = started.elapsed().as_millis();
        match response {
            Some(r) => answers.push((r.status, elapsed)),
            // No answer at all is the app refusing to talk, which is pushing back.
            None => answers.push((0, elapsed)),
        }
    }

    let Some(&(first_status, first_ms)) = answers.first() else {
        return;
    };
    // The app was already pushing back before this check made its first attempt, so whatever it is
    // refusing, it is not refusing because of the number the owner stated. Found by session
    // securevibe-e9 reviewing this after it merged: the test below is the witness. Reachable
    // exactly where this check is most careful — it runs last *because* it provokes refusals, and
    // by then the suite has made dozens of sign-in attempts from one address, so a limiter counting
    // by address is already tripped. Crediting here would be a false *checked* on no evidence.
    if matches!(first_status, 0 | 423 | 429) {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            format!(
                "The app was already refusing sign-in attempts ({first_status}) before this check \
                 made its first one, so nothing here can say whether it pushes back at {allowed}. \
                 Something earlier in the run has most likely tripped a limit that counts by \
                 address rather than by account."
            ),
        ));
        return;
    }
    let last = answers.last().copied().unwrap_or((0, 0));
    // Pushing back is any of: a different status on the last attempt than the first, a status that
    // says refused outright, or an attempt that took markedly longer than the first.
    let status_changed = last.0 != first_status;
    let refused = matches!(last.0, 0 | 423 | 429) || (last.0 >= 400 && first_status < 400);
    // No `first_ms >= 1` guard: the `+ 900` floor already covers a zero measurement, and the guard
    // only stopped an app whose first answer came back inside a millisecond — realistic in a local
    // container — from ever being found to have slowed.
    let slowed = last.1 >= first_ms.saturating_mul(4).max(first_ms + 900);
    let pushed_back = status_changed || refused || slowed;

    let how = if refused {
        format!("refused it outright ({})", last.0)
    } else if status_changed {
        format!("answered {} where the first got {first_status}", last.0)
    } else {
        format!("took {}ms against {first_ms}ms for the first", last.1)
    };
    let against = if real_account {
        "an account this check made for it"
    } else {
        "a user name no account has, since securevibe.toml declares no sign-up"
    };

    out.steps.push(format!(
        "made {attempts} wrong sign-in attempts against {against}; the app {}",
        if pushed_back {
            "pushed back"
        } else {
            "did not push back"
        }
    ));

    // V15.3.4, only where the app pushed back with a different answer: a delay is too noisy to
    // tell apart from a delay the next attempt happens to get.
    if refused || status_changed {
        forwarded_check(http, login, &wrong, first_status, out);
    }

    if pushed_back {
        out.verified.push(crate::Verified::new(
            NO_BRUTE_FORCE_LIMIT.rule_id,
            NO_BRUTE_FORCE_LIMIT.requirement_ids,
            format!(
                "{attempts} wrong passwords in a row against {against}, the number you stated plus \
                 one: the app {how}. The count is what was tested; `within-minutes` was not, \
                 because every attempt landed within a few seconds"
            ),
        ));
    } else {
        out.findings.push(finding(
            &NO_BRUTE_FORCE_LIMIT,
            "Wrong passwords can be tried without limit",
            Severity::High,
            format!(
                "securevibe.toml says the app should allow {allowed} wrong passwords in a row. \
                 Asked {attempts} times in a row with a wrong password, against {against}, the app \
                 answered {} every time and the last attempt took {}ms against {first_ms}ms for \
                 the first: nothing about it changed.",
                first_status, last.1
            ),
        ));
    }
}

/// Does three things no other traffic could have done, each carrying a string nothing else
/// contains, so the container's log can be read for them afterwards (V16.3.1, V16.3.2).
///
/// None of this asserts anything on its own: `logs::evaluate` reads what the app wrote. The point
/// of planting rather than searching for ordinary words is that "the log mentions `admin`" says
/// nothing at all — every log mentions `admin`.
pub(super) fn plant_log_markers(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    signed_in_works: bool,
    out: &mut Outcome,
) {
    // A unique run-scoped tag, taken from the account names the run already made unique.
    let tag: String = accounts
        .a
        .user
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(16)
        .collect();

    // 1. A sign-in for an account that does not exist. Its name can only reach the log because a
    //    failed authentication was written down.
    if let Some(login) = &users.login {
        let nobody = Account {
            user: format!("sv-log-nobody-{tag}@example.test"),
            password: "Sv-Log-Marker-Not-A-Real-Password-1!".to_owned(),
        };
        let mut session = Session::default();
        let mut csrf = None;
        if let Some(page) = http.send(&get("log-marker-page", &login.path, &session)) {
            session.absorb(&page);
            csrf = csrf_token(&page, &session);
        }
        let values = Values {
            user: &nobody.user,
            password: &nobody.password,
            csrf,
            ..Default::default()
        };
        send_template(http, "log-marker-failed", login, &values, &mut session, &[]);
        out.log_markers.failed_sign_in = Some(nobody.user);
    }

    // 2. A sign-in that works, by an account used for nothing else. Needs `signup`: A and B sign in
    //    and fail elsewhere in the run, so neither of their names could tell the two apart.
    if let Some(signup) = &users.signup {
        let only = Account {
            user: format!("sv-log-ok-{tag}@example.test"),
            password: format!("Sv-Log-{tag}-aZ9!"),
        };
        sign_up(http, users, signup, "log-marker", &only);
        if sign_in(http, users, "log-marker-ok", &only, &mut Vec::new()).is_some() {
            out.log_markers.successful_sign_in = Some(only.user);
        }
    }

    // 3. A private page asked for by nobody, with a marker in the address, which the app should
    //    refuse. Only planted once the page is known to be private at all.
    if signed_in_works && let Some(path) = users.private.first() {
        let marker = format!("sv-log-refused-{tag}");
        let joiner = if path.contains('?') { '&' } else { '?' };
        let asked = format!("{path}{joiner}{marker}=1");
        let response = http.send(&get("log-marker-refused", &asked, &Session::default()));
        // Only a marker the app actually refused is evidence about a refusal being recorded, and
        // the status it refused with travels with it: a redirect to the sign-in page is a refusal
        // too, and no fixed list of "refused" codes would have contained it.
        if let Some(status) = response.map(|r| r.status).filter(|s| *s >= 300) {
            out.log_markers.refused_request = Some((marker, status));
        }
    }
}

pub(super) fn sign_out_on_get_check(
    http: &mut dyn Http,
    users: &UsersSection,
    account: &Account,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let (Some(confirm), Some(logout)) = (confirm, &users.logout) else {
        return;
    };
    let mut quiet = Vec::new();
    let Some(signed_in) = sign_in(http, users, "get-logout", account, &mut quiet) else {
        return;
    };
    if !ok(&http.send(&get(
        "private-before-get-logout",
        confirm,
        &signed_in.session,
    ))) {
        return;
    }
    let mut session = signed_in.session.clone();
    if let Some(response) = http.send(&get("logout-by-get", &logout.path, &session)) {
        session.absorb(&response);
    }
    // The session as it was, so a cookie the answer cleared in the browser does not count as the
    // session ending on the server.
    let ended = !ok(&http.send(&get(
        "private-after-get-logout",
        confirm,
        &signed_in.session,
    )));
    out.steps.push(format!(
        "visited {} as a plain page: {}",
        logout.path,
        if ended {
            "signed out"
        } else {
            "still signed in"
        }
    ));
    if ended {
        out.findings.push(finding(
            &SIGN_OUT_ON_GET,
            "Signing out happens on a plain page visit",
            Severity::Low,
            format!(
                "A GET to {}, with no form and no token, ended the session: afterwards {confirm} \
                 was refused.",
                logout.path
            ),
        ));
    }
}

/// Signing in with a few names and passwords somebody might leave in place.
///
/// Only ever a finding. Four tries show four accounts are not there, which is not the same as there
/// being none, so nothing is credited when they all fail.
pub(super) fn default_account_check(
    http: &mut dyn Http,
    users: &UsersSection,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let Some(confirm) = confirm else {
        return;
    };
    let mut opened = Vec::new();
    for (user, password) in DEFAULT_ACCOUNTS {
        let account = Account {
            user: (*user).to_owned(),
            password: (*password).to_owned(),
        };
        let mut quiet = Vec::new();
        if let Some(signed_in) = sign_in(http, users, "default", &account, &mut quiet)
            && ok(&http.send(&get("private-default", confirm, &signed_in.session)))
        {
            opened.push(format!("{user} / {password}"));
        }
    }
    out.steps.push(format!(
        "tried {} default accounts: {}",
        DEFAULT_ACCOUNTS.len(),
        if opened.is_empty() {
            "none signed in".to_owned()
        } else {
            opened.join(", ")
        }
    ));
    if !opened.is_empty() {
        out.findings.push(finding(
            &DEFAULT_ACCOUNT,
            "A default account can sign in",
            Severity::Critical,
            format!(
                "Signing in as {} worked and opened {confirm}.",
                opened.join(" and as ")
            ),
        ));
    }
}

/// Signing in with the password in the address rather than the body.
///
/// Only ever a finding: an app that refuses this has shown one address refuses it.
pub(super) fn password_in_url_check(
    http: &mut dyn Http,
    users: &UsersSection,
    account: &Account,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let (Some(confirm), Some(login)) = (confirm, &users.login) else {
        return;
    };
    if login.form.is_empty() || !login.method.eq_ignore_ascii_case("POST") {
        return;
    }
    let mut session = Session::default();
    let mut csrf = None;
    if let Some(page) = http.send(&get("login-page-url", &login.path, &session)) {
        session.absorb(&page);
        csrf = csrf_token(&page, &session);
    }
    let values = Values {
        user: &account.user,
        password: &account.password,
        csrf,
        ..Default::default()
    };
    let query: Vec<String> = login
        .form
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode(k), form_encode(&fill(v, &values))))
        .collect();
    let path = format!(
        "{}{}{}",
        fill(&login.path, &values),
        if login.path.contains('?') { "&" } else { "?" },
        query.join("&")
    );
    let mut request = get("login-in-url", &path, &session);
    request.headers = session.headers();
    if let Some(response) = http.send(&request) {
        session.absorb(&response);
    }
    let works = ok(&http.send(&get("private-url", confirm, &session)));
    out.steps.push(format!(
        "signed in with the password in the address: {}",
        if works { "opened" } else { "refused" }
    ));
    if works {
        out.findings.push(finding(
            &PASSWORD_IN_URL,
            "The app accepts a password in the address",
            Severity::Medium,
            format!(
                "Sending the sign-in fields as a GET to {} signed the user in, so a password can \
                 arrive in the query string.",
                login.path
            ),
        ));
    }
}

pub(super) fn logout_check(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &SignedIn,
    confirm: Option<String>,
    out: &mut Outcome,
) {
    let Some(logout) = &users.logout else {
        out.not_assessed.push((
            "V7.4.1".to_owned(),
            "Whether signing out ends the session: securevibe.toml lists no `logout`.".to_owned(),
        ));
        return;
    };
    let Some(path) = confirm else {
        out.not_assessed.push((
            "V7.4.1".to_owned(),
            "Whether signing out ends the session: nothing showed the session working in the first \
             place, so its ending would show nothing."
                .to_owned(),
        ));
        return;
    };
    let before = a.session.clone();
    let mut session = a.session.clone();
    let pages: Vec<String> = users
        .private
        .iter()
        .cloned()
        .chain(users.owned.as_ref().map(|o| o.create.path.clone()))
        .collect();
    let (response, _) = send_template(
        http,
        "logout",
        logout,
        &Values::default(),
        &mut session,
        &pages,
    );
    out.steps
        .push(format!("A signed out ({})", status(&response)));
    clear_site_data_check(response.as_ref(), &logout.path, out);
    // A sign-out the app refused has ended nothing, and the session still working afterwards would
    // then be blamed on the app. The same setup rule as everywhere else: show the thing happened.
    if !accepted(&response) {
        out.not_assessed.push((
            "V7.4.1".to_owned(),
            format!(
                "Whether signing out ends the session: the sign-out request itself was refused ({}), \
                 so there was no sign-out to test. Check `logout` in securevibe.toml.",
                status(&response)
            ),
        ));
        return;
    }
    // The copy kept from before logout, as somebody who had copied the cookie would use it.
    let replay = http.send(&get("after-logout", &path, &before));
    if ok(&replay) {
        out.findings.push(finding(
            &LOGOUT,
            "Signing out does not end the session",
            Severity::High,
            format!("After signing out, the old session still opened {path}."),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            LOGOUT.rule_id,
            LOGOUT.requirement_ids,
            format!("the session from before sign-out, sent again to {path} and refused"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::{run_keeping_app, run_with, seeded_with};
    use super::*;

    #[test]
    fn a_refused_sign_out_is_not_blamed_on_the_app() {
        // Found against the first real app: the sign-out was refused for want of a token, the
        // session carried on, and the suite reported that signing out does not end sessions. A
        // sign-out that did not happen proves nothing, whatever the app does with real ones.
        let mut u = users();
        u.logout.as_mut().unwrap().form.clear(); // no token field, so the app refuses it
        for flaws in [
            Flaws::default(),
            Flaws {
                logout_keeps_session: true,
                ..Default::default()
            },
        ] {
            let o = run_against(flaws, &u);
            assert!(
                !rule_ids(&o).contains(&LOGOUT.rule_id),
                "{:?}",
                rule_ids(&o)
            );
            assert!(!verified_ids(&o).contains(&LOGOUT.rule_id));
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(ids, why)| ids == "V7.4.1" && why.contains("refused")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_sign_out_sent_to_the_wrong_address_is_not_blamed_on_the_app_either() {
        // The second shape: not a missing token but a path the app does not have. A 404 ended no
        // session, so the session carrying on says nothing about sign-out.
        let mut u = users();
        u.logout.as_mut().unwrap().path = "/sign-out".into();
        let o = run_against(Flaws::default(), &u);
        assert!(
            !rule_ids(&o).contains(&LOGOUT.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V7.4.1" && why.contains("404")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn the_sign_out_token_is_found_on_another_page() {
        // `/logout` shows nothing; the token is on the note form, as a sign-out button's would be
        // on whatever page it sits. Without looking there, every correct app would fail to sign out.
        let o = run_against(Flaws::default(), &users());
        assert!(
            verified_ids(&o).contains(&LOGOUT.rule_id),
            "{:?}",
            o.not_assessed
        );
    }

    // -------------------------------------------------------------------------------------------
    // Holding the app to the number of wrong passwords the owner said it would allow (V6.3.1)
    // -------------------------------------------------------------------------------------------

    fn policy(failed: Option<u32>) -> sv_manifest::PolicySection {
        sv_manifest::PolicySection {
            failed_sign_ins: failed,
            within_minutes: Some(15),
            ..Default::default()
        }
    }

    fn finding_ids(out: &Outcome) -> Vec<&str> {
        out.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn an_app_that_never_pushes_back_is_a_finding() {
        let out = run_with(Flaws::default(), &policy(Some(3)));
        assert!(
            finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"),
            "got {:?}",
            finding_ids(&out)
        );
    }

    #[test]
    fn an_app_that_locks_out_at_the_stated_number_is_checked() {
        let flaws = Flaws {
            locks_out_after: Some(3),
            ..Flaws::default()
        };
        let out = run_with(flaws, &policy(Some(3)));
        assert!(
            !finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"),
            "an app that pushed back was reported anyway: {:?}",
            finding_ids(&out)
        );
        assert!(
            out.verified
                .iter()
                .any(|v| v.check_id == "probe.failed-sign-ins-unlimited"
                    && v.requirement_ids.iter().any(|r| r == "V6.3.1")),
            "and it must be credited: {:?}",
            out.verified
                .iter()
                .map(|v| v.check_id.as_str())
                .collect::<Vec<_>>()
        );
    }

    // The limits below are six, not three: a limit counting by address trips during the suite
    // itself, whose default-account check alone makes four wrong sign-ins in a row, and then the
    // brute-force check rightly finds the app already refusing and asks nothing, this included.
    fn forwarded_steps(out: &Outcome) -> Vec<&String> {
        out.steps
            .iter()
            .filter(|s| s.contains("claiming to come from"))
            .collect()
    }

    #[test]
    fn a_limit_that_believes_a_made_up_address_is_found() {
        let out = run_with(
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                trusts_forwarded_for: true,
                ..Flaws::default()
            },
            &policy(Some(6)),
        );
        assert!(
            finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}\n{:?}",
            finding_ids(&out),
            out.steps
        );
        assert!(
            finding_ids(&out).len() == 1,
            "found only by its own rule: {:?}",
            finding_ids(&out)
        );
    }

    #[test]
    fn a_limit_that_ignores_the_header_is_not_found() {
        // By address and not trusting the header, and by account, which the header cannot touch.
        for flaws in [
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                ..Flaws::default()
            },
            Flaws {
                locks_out_after: Some(6),
                trusts_forwarded_for: true,
                ..Flaws::default()
            },
        ] {
            let out = run_with(flaws, &policy(Some(6)));
            assert!(
                !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
                "{:?}",
                out.steps
            );
            let steps = forwarded_steps(&out);
            assert_eq!(steps.len(), 1, "the attempt was made: {:?}", out.steps);
            assert!(steps[0].contains("still refused"), "{}", steps[0]);
        }
    }

    #[test]
    fn a_limit_that_lifts_by_itself_is_not_blamed_on_the_header() {
        // The control. The attempt claiming another address is answered normally, but so is the
        // one after it, claiming nothing: the limit lifted on its own. Counted by account, so the
        // suite's earlier wrong sign-ins cannot make it lift partway through the guessing.
        let out = run_with(
            Flaws {
                locks_out_after: Some(6),
                lockout_forgets: true,
                ..Flaws::default()
            },
            &policy(Some(6)),
        );
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            out.steps
        );
        let steps = forwarded_steps(&out);
        assert_eq!(steps.len(), 1, "{:?}", out.steps);
        assert!(
            steps[0].contains("claiming nothing: answered"),
            "the control must have run and lifted: {}",
            steps[0]
        );
    }

    #[test]
    fn with_no_limit_to_lift_no_address_is_claimed() {
        let out = run_with(Flaws::default(), &policy(Some(6)));
        assert!(forwarded_steps(&out).is_empty(), "{:?}", out.steps);
        assert!(!finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id));
    }

    #[test]
    fn an_app_that_pushes_back_too_late_is_still_a_finding() {
        // The number is the owner's claim, and the point of stating it is that the app is held to
        // it. An app that only gives way after twenty attempts has not implemented the policy that
        // says three, and a check that accepted any limiter at all would not be checking the claim.
        let flaws = Flaws {
            locks_out_after: Some(20),
            ..Flaws::default()
        };
        let out = run_with(flaws, &policy(Some(3)));
        assert!(
            finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"),
            "got {:?}",
            finding_ids(&out)
        );
    }

    #[test]
    fn without_a_stated_number_nothing_is_claimed_either_way() {
        // The honest default. An app nobody has stated a policy for is not thereby failing, and it
        // is certainly not passing: the report says which question would settle it.
        let out = run_with(Flaws::default(), &policy(None));
        assert!(!finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"));
        assert!(
            !out.verified
                .iter()
                .any(|v| v.check_id == "probe.failed-sign-ins-unlimited")
        );
        let said = out
            .not_assessed
            .iter()
            .find(|(ids, _)| ids.contains("V6.3.1"))
            .unwrap_or_else(|| {
                panic!(
                    "V6.3.1 must be named as not assessed: {:?}",
                    out.not_assessed
                )
            });
        assert!(
            said.1.contains("failed-sign-ins") && said.1.contains("[policy]"),
            "and it must say what to write: {}",
            said.1
        );
    }

    #[test]
    fn a_number_this_check_will_not_make_that_many_attempts_for_is_refused() {
        // A cap, so one check cannot turn into thousands of requests against somebody's app.
        let out = run_with(Flaws::default(), &policy(Some(500)));
        assert!(!finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"));
        assert!(
            out.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.3.1") && why.contains("500")),
            "{:?}",
            out.not_assessed
        );
    }

    #[test]
    fn zero_is_refused_rather_than_read_as_one() {
        // Nobody means "refuse the first attempt anybody makes", and guessing that they meant one
        // would hold the app to a policy the owner did not state.
        let out = run_with(Flaws::default(), &policy(Some(0)));
        assert!(!finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"));
        assert!(
            out.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V6.3.1") && why.contains("first attempt")),
            "{:?}",
            out.not_assessed
        );
    }

    #[test]
    fn an_app_already_refusing_before_the_first_attempt_is_not_credited() {
        // Found by session securevibe-e9 reviewing #104, after it had merged. `refused` read only
        // the last attempt, so an app answering 429 from the very first one satisfied it and
        // V6.3.1 was credited having tested nothing at all — a false *checked*, which is the one
        // outcome this report exists to prevent.
        //
        // Reachable exactly where the check is most careful: it runs last precisely because it
        // provokes refusals, and by then the suite has made dozens of sign-in attempts from one
        // address. A limiter counting by address is already tripped when this begins.
        //
        // Every refusal the guard names gets a case. With 429 alone, narrowing the guard to 429
        // was caught by nothing, and 423 and a dropped connection would have gone on being
        // credited.
        for status in [429, 423, 0] {
            let flaws = Flaws {
                already_refusing: Some(status),
                ..Flaws::default()
            };
            let out = run_with(flaws, &policy(Some(3)));
            assert!(
                !out.verified
                    .iter()
                    .any(|v| v.check_id == "probe.failed-sign-ins-unlimited"),
                "answering {status} from the first attempt proves nothing about the stated \
                 number, but it was credited"
            );
            assert!(
                !finding_ids(&out).contains(&"probe.failed-sign-ins-unlimited"),
                "and {status} is not a finding either: nothing was established"
            );
            let said = out
                .not_assessed
                .iter()
                .find(|(ids, _)| ids.contains("V6.3.1"))
                .unwrap_or_else(|| panic!("V6.3.1 must be named for {status}"));
            assert!(
                said.1.contains("already refusing"),
                "and the reason is worth telling the owner, because something earlier tripped a \
                 limiter: {}",
                said.1
            );
        }
    }

    #[test]
    fn the_guessing_never_touches_the_accounts_the_other_checks_need() {
        // The hazard this check has and no other does: it provokes the app into refusing requests.
        // If it guessed at A, an app that locks an account out would end the session every check
        // above depends on, and the run would start reporting faults of this check's own making.
        //
        // The first version of this test looped over `out.steps` looking for A's name — and no step
        // carries it, so the assertion could never fail. Deleting the safeguard was caught by
        // nothing. The promise is about which account is attacked, so the app records that.
        let flaws = Flaws {
            locks_out_after: Some(2),
            ..Flaws::default()
        };
        let (_out, app, acc) = run_keeping_app(flaws, &policy(Some(2)));
        assert!(
            !app.guessed_at.is_empty(),
            "no wrong password reached the app at all, so this proves nothing"
        );
        // Counted and labeled rather than printed. The accounts these come from carry generated
        // passwords, and a failure message is a log line like any other: nothing built from an
        // `Accounts` belongs in one, whatever the particular field happens to hold.
        for (label, who) in [("A", &acc.a.user), ("B", &acc.b.user)] {
            assert!(
                !app.guessed_at.contains(who),
                "the guessing attacked {label}, whose session the checks above depend on \
                 ({} accounts were guessed at)",
                app.guessed_at.len()
            );
        }
    }

    /// The four rows found in review: steady and leaky limits by address, reading the header or not.
    fn forwarded_case(leaks: bool, trusts: bool) -> Outcome {
        run_with(
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                trusts_forwarded_for: trusts,
                lockout_leaks: leaks,
                ..Flaws::default()
            },
            &policy(Some(6)),
        )
    }

    #[test]
    fn a_leaky_limit_that_ignores_the_header_is_not_accused_of_trusting_it() {
        // The false positive: the leak let exactly one claimed attempt through, which is what a
        // single claimed attempt beside a single plain one could not tell from a trusted header.
        let out = forwarded_case(true, false);
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            out.steps
        );
        let steps = forwarded_steps(&out);
        assert_eq!(steps.len(), 1, "the attempts were made: {:?}", out.steps);
        assert!(
            steps[0].contains("one as the first attempt was and one refused"),
            "{}",
            steps[0]
        );
    }

    #[test]
    fn the_four_rows_from_review_come_out_as_they_should() {
        for (leaks, trusts, found) in [
            (false, false, false),
            (false, true, true),
            (true, false, false),
            // A leaky limit still hides an app that trusts the header: the safe direction.
            (true, true, false),
        ] {
            let out = forwarded_case(leaks, trusts);
            assert_eq!(
                finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
                found,
                "leaks {leaks}, trusts {trusts}: {:?}",
                forwarded_steps(&out)
            );
        }
    }

    fn forwarded_once(trusts: bool) -> Outcome {
        run_with(
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                trusts_forwarded_for: trusts,
                window_rolls_over_at_first_claim: true,
                ..Flaws::default()
            },
            &policy(Some(6)),
        )
    }

    #[test]
    fn a_limit_that_lets_one_attempt_through_once_is_not_accused() {
        // One claimed attempt gets through and everything after is refused: only the second
        // claimed attempt, from its own address, tells this apart from a trusted header.
        let out = forwarded_once(false);
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            forwarded_steps(&out)
        );
    }

    #[test]
    fn a_limit_that_leaked_once_and_trusts_the_header_is_still_found() {
        let out = forwarded_once(true);
        assert!(
            finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            forwarded_steps(&out)
        );
    }

    #[test]
    fn a_leaky_limit_hides_a_trusted_header_rather_than_inventing_one() {
        let out = forwarded_case(true, true);
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{:?}",
            forwarded_steps(&out)
        );
    }

    #[test]
    fn seeded_a_limit_that_lets_one_attempt_through_once_is_not_accused() {
        let out = seeded_with(
            Flaws {
                locks_out_after: Some(6),
                limits_by_address: true,
                window_rolls_over_at_first_claim: true,
                ..Flaws::default()
            },
            &policy(Some(6)),
        );
        let steps = forwarded_steps(&out);
        assert_eq!(steps.len(), 1, "the attempts were made: {:?}", out.steps);
        assert!(
            !finding_ids(&out).contains(&FORWARDED_TRUSTED.rule_id),
            "{steps:?}"
        );
    }
}
