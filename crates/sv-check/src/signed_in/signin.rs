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
             make two more attempts than that and watch what the app does."
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
    const MOST_ATTEMPTS: u32 = 26;
    if allowed + 2 > MOST_ATTEMPTS {
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            format!(
                "[policy] failed-sign-ins is {allowed}. This check makes at most {MOST_ATTEMPTS} \
                 attempts, the number allowed plus two, so it cannot reach that number; a limit that high is worth reconsidering \
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
    // One past the limit, and one more to confirm a delay (`slowing`).
    let attempts = allowed + 2;
    let mut answers: Vec<(u16, u128)> = Vec::new();
    // How long the sign-in page took before each attempt: the same way in, `docker exec` included,
    // to a page no limit on wrong passwords slows.
    let mut pages: Vec<u128> = Vec::new();
    for n in 0..attempts {
        let mut session = Session::default();
        let mut csrf = None;
        let started = std::time::Instant::now();
        if let Some(page) = http.send(&get(&format!("guess-page-{n}"), &login.path, &session)) {
            session.absorb(&page);
            csrf = csrf_token(&page, &session);
        }
        pages.push(started.elapsed().as_millis());
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
    // The first attempt past the limit, whose answer says whether the app pushed back.
    let last = answers[allowed as usize];
    // Pushing back is any of: a different status past the limit than the first, a status that
    // says refused outright, or both attempts past the limit markedly slower than any before it.
    let status_changed = last.0 != first_status;
    let refused = matches!(last.0, 0 | 423 | 429) || (last.0 >= 400 && first_status < 400);
    // The second attempt past the limit is read too. An app that answers it differently, having
    // answered the first past the limit as it answered the first of all, let one more through than
    // was stated; saying it "answered the same every time" would be untrue (the review of 6 October,
    // item 13).
    let next = answers[allowed as usize + 1].0;
    // Only from real answers, every one up to the limit the same: a crash or no answer anywhere in
    // the run is not the app pushing back, and must not read as a status that changed.
    let real = |status: u16| status != 0 && status < 500;
    let alike = answers[..=allowed as usize]
        .iter()
        .all(|a| a.0 == first_status);
    if !(status_changed || refused)
        && alike
        && real(first_status)
        && real(next)
        && next != first_status
    {
        out.steps.push(format!(
            "made {attempts} wrong sign-in attempts; the app answered {first_status} to the first \
             {}, and {next} only to the last",
            allowed + 1
        ));
        out.findings.push(finding(
            &NO_BRUTE_FORCE_LIMIT,
            "One more wrong password than stated is let through",
            Severity::Medium,
            format!(
                "securevibe.toml says the app should allow {allowed} wrong passwords in a row. \
                 Asked {attempts} times in a row with a wrong password, the app answered \
                 {first_status} to the first {}, the one past the limit included, and pushed back \
                 ({next}) only at the attempt after it.",
                allowed + 1
            ),
        ));
        return;
    }
    let times: Vec<u128> = answers.iter().map(|a| a.1).collect();
    let (within, past) = times.split_at(allowed as usize);
    let slowing = slowing(within, past, &pages[allowed as usize..]);
    if !(status_changed || refused)
        && let Slowing::Unclear(why) = &slowing
    {
        out.steps.push(format!(
            "made {attempts} wrong sign-in attempts; the app answered {first_status} to each, \
             and the times could not say whether it slowed"
        ));
        out.not_assessed.push((
            "V6.3.1".to_owned(),
            format!(
                "Whether the app resists password guessing: it answered {first_status} to all \
                 {attempts} wrong passwords, and {why}."
            ),
        ));
        return;
    }
    let slowed = slowing == Slowing::Slowed;
    let pushed_back = status_changed || refused || slowed;
    let quickest = within.iter().copied().min().unwrap_or(first_ms);

    let how = if refused {
        format!("refused it outright ({})", last.0)
    } else if status_changed {
        format!("answered {} where the first got {first_status}", last.0)
    } else {
        format!(
            "took {}ms and {}ms over the two attempts past the limit, against {quickest}ms at \
             the quickest before it",
            past[0], past[1]
        )
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
                 two: the app {how}. The count is what was tested; `within-minutes` was not, \
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
                 answered {first_status} every time, and the two attempts past the limit took {}ms \
                 and {}ms against {quickest}ms at the quickest before it: nothing about it changed.",
                past[0], past[1]
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
///
/// Every marker is also put somewhere an app that keeps personal data out of its log still writes
/// down: a request's path. The two sign-ins are each bracketed by a request for a page nobody has
/// (`/sv-log-before-…`, `/sv-log-after-…`), and the refused request is asked a second time with
/// the marker as the last part of its path. `logs.rs` says why each keeps its meaning.
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
    // A request for a page nobody has, carrying a marker and nothing else: nobody's session, no
    // form, no personal data. Whatever the app answers, it is only ever read as a place in the log.
    let mark = |http: &mut dyn Http, marker: &str| {
        http.send(&get(
            &format!("log-marker-{marker}"),
            &format!("/{marker}"),
            &Session::default(),
        ));
    };
    let window = |login: &RequestTemplate, which: &str| crate::logs::Window {
        open: format!("sv-log-before-{which}-{tag}"),
        close: format!("sv-log-after-{which}-{tag}"),
        login_path: login.path.split('?').next().unwrap_or_default().to_owned(),
    };

    // 1. A sign-in for an account that does not exist. Its name can only reach the log because a
    //    failed authentication was written down; and a sign-in event written between the two
    //    marked requests around it can only be this one.
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
        let around = window(login, "failed");
        mark(http, &around.open);
        send_template(http, "log-marker-failed", login, &values, &mut session, &[]);
        mark(http, &around.close);
        out.log_markers.failed_sign_in = Some(nobody.user);
        out.log_markers.failed_window = Some(around);
    }

    // 2. A sign-in that works, by an account used for nothing else. Needs `signup`: A and B sign in
    //    and fail elsewhere in the run, so neither of their names could tell the two apart.
    if let (Some(signup), Some(login)) = (&users.signup, &users.login) {
        let only = Account {
            user: format!("sv-log-ok-{tag}@example.test"),
            password: format!("Sv-Log-{tag}-aZ9!"),
        };
        sign_up(http, users, signup, "log-marker", &only);
        let around = window(login, "ok");
        mark(http, &around.open);
        let signed = sign_in(http, users, "log-marker-ok", &only, &mut Vec::new());
        mark(http, &around.close);
        // The window is read for a sign-in event that does not say it failed, so the sign-in has
        // to be shown to have worked, by the private page opening with its session: an app that
        // logs `{"event":"login","ok":false}` would otherwise be credited with a success.
        let worked = signed_in_works
            && signed.as_ref().is_some_and(|s| {
                users
                    .private
                    .first()
                    .is_some_and(|p| ok(&http.send(&get("log-marker-ok-confirm", p, &s.session))))
            });
        if worked {
            out.log_markers.successful_window = Some(around);
        }
        if worked || (!signed_in_works && signed.is_some()) {
            out.log_markers.successful_sign_in = Some(only.user);
        }
    }

    // 3. A private page asked for by nobody, with a marker in the address, which the app should
    //    refuse. Only planted once the page is known to be private at all.
    if signed_in_works && let Some(path) = users.private.first() {
        let (bare, query) = match path.split_once('?') {
            Some((bare, query)) => (bare, Some(query)),
            None => (path.as_str(), None),
        };
        // a. After `?`, on the private page itself, so the request means exactly what it did.
        let marker = format!("sv-log-refused-{tag}");
        let asked = match query {
            Some(q) => format!("{bare}?{q}&{marker}=1"),
            None => format!("{bare}?{marker}=1"),
        };
        let refused = http
            .send(&get("log-marker-refused", &asked, &Session::default()))
            .map(|r| r.status);
        // Only a marker the app actually refused is evidence about a refusal being recorded, and
        // the status it refused with travels with it: a redirect to the sign-in page is a refusal
        // too, and no fixed list of "refused" codes would have contained it.
        if let Some(status) = refused.filter(|s| *s >= 300) {
            out.log_markers.refused_requests.push((marker, status));
        }
        // b. As the last part of the path, which an app that strips query strings still logs.
        //    That address is not the private page, so its answer only counts as an authorization
        //    refusal when it is the very refusal the private page got, and not a 404: "no such
        //    page" answers a different question, and so does an app that hides private pages
        //    behind a 404 (then the two cannot be told apart, and only `a` is planted).
        let marker = format!("sv-log-denied-{tag}");
        let asked = format!(
            "{}/{marker}{}",
            bare.trim_end_matches('/'),
            query.map(|q| format!("?{q}")).unwrap_or_default()
        );
        let answered = http
            .send(&get("log-marker-denied", &asked, &Session::default()))
            .map(|r| r.status);
        if let Some(status) = refused.filter(|s| *s >= 300 && *s != 404)
            && answered == Some(status)
        {
            out.log_markers.refused_requests.push((marker, status));
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

/// What the times of wrong attempts say about whether the app slowed down past the limit.
#[derive(Debug, PartialEq)]
pub(super) enum Slowing {
    Slowed,
    Not,
    /// The times disagree, and why, in a clause that follows "and".
    Unclear(String),
}

/// Whether the attempts `past` the limit were slowed, against those `within` it, read from times
/// that include `docker exec`'s own (deep review H16). That time is added to every request and
/// never taken away, so the quickest attempt within the limit is the baseline, and a delay counts
/// only when every attempt past the limit is markedly slower than it: four times as long, and at
/// least 900ms longer. One slow attempt and one not, or a request a limit would not slow
/// (`controls`, such as the sign-in page) as slow as they were, is unclear, never a pass or a fail.
pub(super) fn slowing(within: &[u128], past: &[u128], controls: &[u128]) -> Slowing {
    let Some(quickest) = within.iter().copied().min() else {
        return Slowing::Unclear(
            "no attempt within the limit was timed to compare with".to_owned(),
        );
    };
    let markedly = quickest.saturating_mul(4).max(quickest + 900);
    let slow = past.iter().filter(|&&ms| ms >= markedly).count();
    if past.is_empty() || slow == 0 {
        return Slowing::Not;
    }
    let shown = |ms: &[u128]| {
        ms.iter()
            .map(|m| format!("{m}ms"))
            .collect::<Vec<_>>()
            .join(" and ")
    };
    if slow < past.len() {
        return Slowing::Unclear(format!(
            "the attempts past the limit took {} against {quickest}ms at the quickest before it: \
             one slow attempt cannot be told apart from a slow start of the container that sends it",
            shown(past)
        ));
    }
    if let Some(&page) = controls.iter().find(|&&ms| ms >= markedly) {
        return Slowing::Unclear(format!(
            "the attempts past the limit took {}, but a request no limit would slow took {page}ms \
             beside them, so the delay was not the sign-in's own",
            shown(past)
        ));
    }
    Slowing::Slowed
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::{run_keeping_app, run_with, seeded_with, with_signup};
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

    #[test]
    fn an_app_that_pushes_back_one_attempt_late_is_said_to_and_not_said_to_answer_the_same() {
        // The review of 6 October, item 13: three allowed, the fourth answered as the first, the
        // fifth refused. The second attempt past the limit was sent and never read.
        let flaws = Flaws {
            locks_out_after: Some(4),
            ..Flaws::default()
        };
        let out = run_with(flaws, &policy(Some(3)));
        let found = out
            .findings
            .iter()
            .find(|f| f.rule_id == "probe.failed-sign-ins-unlimited")
            .unwrap_or_else(|| panic!("{:?}\n{:?}", out.steps, out.not_assessed));
        assert!(
            found.description.contains("only at the attempt after it"),
            "{}",
            found.description
        );
        assert!(
            !found.description.contains("every time"),
            "{}",
            found.description
        );
        assert!(
            !out.verified
                .iter()
                .any(|v| v.check_id == "probe.failed-sign-ins-unlimited")
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

    // --------------------------------------------------------------------------------------------
    // The log markers, end to end: planted against the fake app, read back from what it wrote

    /// The suite run against the fake app with sign-up, writing its log in `style`; the outcome
    /// and the log as one string, as `docker logs` would give it.
    fn logged_run(style: LogStyle, guards_under_private: bool) -> (Outcome, String) {
        let mut app = FakeApp::new(Flaws::default());
        app.log_style = Some(style);
        app.guards_under_private = guards_under_private;
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let out = run(
            &mut app,
            &super::super::tests::with_signup(),
            &acc,
            false,
            &Default::default(),
        );
        let log = app.log.join("\n");
        (out, log)
    }

    fn logged_ids(o: &crate::logs::LogOutcome) -> Vec<&str> {
        o.verified.iter().map(|v| v.check_id.as_str()).collect()
    }

    #[test]
    fn an_app_that_logs_only_paths_and_user_ids_is_assessed() {
        // The family-hub log of 3 October 2026: JSON lines, the path without its query string, a
        // user id and an event name for each sign-in, and never an email address.
        let (out, log) = logged_run(LogStyle::Private, true);
        let m = &out.log_markers;
        // The setup, shown to have worked before anything is read from it: every marker planted,
        // the log really free of email addresses and query strings, and the markers in it.
        let (failed, ok) = (
            m.failed_window
                .clone()
                .expect("the refused sign-in was bracketed"),
            m.successful_window
                .clone()
                .expect("the accepted sign-in was bracketed and shown to work"),
        );
        assert_eq!(
            m.refused_requests
                .iter()
                .map(|(_, s)| *s)
                .collect::<Vec<_>>(),
            vec![302, 302],
            "{:?}",
            m.refused_requests
        );
        assert!(!log.is_empty());
        assert!(!log.contains('@'), "the log holds an email address");
        assert!(!log.contains('?'), "the log holds a query string");
        for marker in [&failed.open, &failed.close, &ok.open, &ok.close] {
            assert!(log.contains(marker.as_str()), "{marker} is not in the log");
        }
        assert!(log.contains("sv-log-denied-"), "{log}");

        let o = crate::logs::evaluate(m, &log);
        for id in [
            "probe.authentication-logged",
            "probe.authorization-failure-logged",
            "probe.log-timestamp-zoned",
            "probe.log-common-format",
        ] {
            assert!(logged_ids(&o).contains(&id), "{id}: {:?}", o.not_assessed);
        }
        let assessed: Vec<&str> = o.not_assessed.iter().map(|(id, _)| id.as_str()).collect();
        // Who made the refused attempt is the one thing such a line cannot be shown to say.
        assert_eq!(assessed, vec!["V16.2.1"], "{:?}", o.not_assessed);
        assert!(o.not_assessed[0].1.contains("who"), "{:?}", o.not_assessed);
        assert!(o.findings.is_empty(), "{:?}", o.findings);
    }

    #[test]
    fn a_marked_path_the_app_calls_no_such_page_is_not_counted_as_a_refusal() {
        // The fake app guards `/account` but answers 404 for anything under it. That 404 is not an
        // authorization decision, so only the marker after `?` is planted; the private log strips
        // it, and the refused request is then not assessed, with privacy named as a reason.
        let (out, log) = logged_run(LogStyle::Private, false);
        let m = &out.log_markers;
        assert_eq!(m.refused_requests.len(), 1, "{:?}", m.refused_requests);
        assert!(m.refused_requests[0].0.starts_with("sv-log-refused-"));
        // The marked path was asked for, and answered 404.
        assert!(log.contains("sv-log-denied-"), "{log}");
        assert!(
            log.lines()
                .any(|l| l.contains("sv-log-denied-") && l.contains(r#""status":404"#)),
            "{log}"
        );
        let o = crate::logs::evaluate(m, &log);
        assert!(!logged_ids(&o).contains(&"probe.authorization-failure-logged"));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V16.3.2" && why.contains("privacy rules")),
            "{:?}",
            o.not_assessed
        );
        // The sign-ins do not depend on it.
        assert!(logged_ids(&o).contains(&"probe.authentication-logged"));
    }

    #[test]
    fn a_private_page_hidden_behind_a_404_gets_no_marker_in_its_path() {
        // When the private page itself answers 404, a 404 under it cannot be told from "no such
        // page", so only the marker after `?` (on the page itself) is planted.
        let mut app = FakeApp::new(Flaws::default());
        app.log_style = Some(LogStyle::Full);
        app.hides_private = true;
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let mut out = Outcome::default();
        plant_log_markers(
            &mut app,
            &super::super::tests::with_signup(),
            &acc,
            true,
            &mut out,
        );
        let log = app.log.join("\n");
        // Both were asked, and both answered 404.
        for marker in ["sv-log-refused-", "sv-log-denied-"] {
            assert!(
                log.lines()
                    .any(|l| l.contains(marker) && l.ends_with(" 404")),
                "{marker}: {log}"
            );
        }
        let planted: Vec<&str> = out
            .log_markers
            .refused_requests
            .iter()
            .map(|(m, _)| m.as_str())
            .collect();
        assert_eq!(planted.len(), 1, "{planted:?}");
        assert!(planted[0].starts_with("sv-log-refused-"), "{planted:?}");
    }

    #[test]
    fn an_app_that_logs_email_addresses_and_query_strings_is_still_read_by_them() {
        // The old way in still works, and, being by the account's name, still speaks to who.
        let (out, log) = logged_run(LogStyle::Full, false);
        let m = &out.log_markers;
        let failed = m
            .failed_sign_in
            .clone()
            .expect("the refused sign-in was planted");
        assert!(log.contains(failed.as_str()), "{log}");
        assert!(log.contains("?sv-log-refused-"), "{log}");
        let o = crate::logs::evaluate(m, &log);
        for id in [
            "probe.authentication-logged",
            "probe.authorization-failure-logged",
            "probe.log-line-metadata",
            "probe.log-timestamp-zoned",
        ] {
            assert!(logged_ids(&o).contains(&id), "{id}: {:?}", o.not_assessed);
        }
        let named = o
            .verified
            .iter()
            .find(|v| v.check_id == "probe.authentication-logged")
            .unwrap();
        assert!(named.scope.contains("both named"), "{}", named.scope);
    }

    #[test]
    fn the_accepted_sign_in_is_bracketed_only_when_it_worked() {
        // A sign-in event that does not say it failed is read as a success, so the success has to
        // be shown, not assumed: with sign-up broken, the window is not planted.
        let mut app = FakeApp::new(Flaws {
            broken_login: true,
            ..Default::default()
        });
        app.log_style = Some(LogStyle::Private);
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let mut out = Outcome::default();
        plant_log_markers(
            &mut app,
            &super::super::tests::with_signup(),
            &acc,
            true,
            &mut out,
        );
        assert!(out.log_markers.failed_window.is_some());
        assert!(out.log_markers.successful_window.is_none());
        assert!(out.log_markers.successful_sign_in.is_none());
    }

    #[test]
    fn a_delay_counts_only_when_every_attempt_past_the_limit_shows_it() {
        // Deep review H16: the times include `docker exec`'s own, which only ever adds. So the
        // quickest attempt within the limit is the baseline, and a delay needs both attempts past
        // the limit markedly slower: four times as long, and at least 900ms longer.
        assert_eq!(slowing(&[40, 300, 45], &[1100, 1300], &[]), Slowing::Slowed);
        // The quickest is 40ms, not the first: a slow first answer no longer hides a limiter.
        assert_eq!(slowing(&[900, 40], &[1000, 1000], &[]), Slowing::Slowed);
        assert_eq!(slowing(&[40, 45], &[50, 60], &[]), Slowing::Not);
        // Four times as long but not 900ms longer, and 900ms longer but not four times as long.
        assert_eq!(slowing(&[40], &[800, 900], &[]), Slowing::Not);
        assert_eq!(slowing(&[400], &[1400, 1500], &[]), Slowing::Not);
        // One slow attempt is what one slow start of the sending container looks like.
        for past in [[1500, 50], [50, 1500]] {
            let Slowing::Unclear(why) = slowing(&[40], &past, &[]) else {
                panic!("{past:?} was read as settled");
            };
            assert!(why.contains("one slow attempt"), "{why}");
        }
        // A page no limit slows was as slow beside them: the delay is not the sign-in's.
        let Slowing::Unclear(why) = slowing(&[40], &[1500, 1500], &[30, 1400]) else {
            panic!("a slow control was read as settled");
        };
        assert!(why.contains("no limit would slow took 1400ms"), "{why}");
        assert_eq!(slowing(&[40], &[1500, 1500], &[30, 60]), Slowing::Slowed);
        assert!(matches!(slowing(&[], &[1500], &[]), Slowing::Unclear(_)));
    }

    /// The sign-up fixture against an app that answers these requests this many real milliseconds
    /// late, with three wrong passwords allowed: attempts `guess-0` to `guess-4`, the last two past
    /// the limit, each after its own `guess-page-N`.
    fn timed(slow: &[(&str, u64)]) -> Outcome {
        let mut app = FakeApp::new(Flaws::default());
        app.slow_ms = slow
            .iter()
            .map(|(id, ms)| ((*id).to_owned(), *ms))
            .collect();
        let mut acc = accounts();
        acc.admin = None;
        acc.totp = None;
        let out = run(&mut app, &with_signup(), &acc, false, &policy(Some(3)));
        // The ids are the ones this check sends, so the delays really landed on its requests.
        for (id, _) in slow {
            assert!(
                app.clock_log.iter().any(|(sent, _)| sent == id),
                "no request {id} was sent"
            );
        }
        out
    }

    fn brute_force(out: &Outcome) -> (bool, bool, Option<&String>) {
        (
            out.verified
                .iter()
                .any(|v| v.check_id == "probe.failed-sign-ins-unlimited"),
            finding_ids(out).contains(&"probe.failed-sign-ins-unlimited"),
            out.not_assessed
                .iter()
                .find(|(ids, _)| ids.contains("V6.3.1"))
                .map(|(_, why)| why),
        )
    }

    #[test]
    fn an_app_that_slows_every_attempt_past_the_limit_is_credited_and_one_slow_attempt_is_not() {
        let out = timed(&[("guess-3", 1000), ("guess-4", 1000)]);
        let (credited, found, _) = brute_force(&out);
        assert!(credited && !found, "{:?}", out.verified);
        let said = out
            .verified
            .iter()
            .find(|v| v.check_id == "probe.failed-sign-ins-unlimited")
            .unwrap();
        assert!(
            said.scope.contains("the two attempts past the limit"),
            "{}",
            said.scope
        );

        // Until H16 one slow last attempt was credited: the review's false *checked*.
        for slow in ["guess-3", "guess-4"] {
            let out = timed(&[(slow, 1000)]);
            let (credited, found, why) = brute_force(&out);
            assert!(!credited && !found, "{slow}: settled on one slow attempt");
            assert!(
                why.is_some_and(|w| w.contains("one slow attempt")),
                "{slow}: {why:?}"
            );
        }

        // Every attempt slow, and the sign-in page beside them too: the app, or the way in, was
        // slow, not the sign-in.
        let out = timed(&[("guess-3", 1000), ("guess-4", 1000), ("guess-page-4", 1000)]);
        let (credited, found, why) = brute_force(&out);
        assert!(!credited && !found);
        assert!(
            why.is_some_and(|w| w.contains("no limit would slow")),
            "{why:?}"
        );
    }
}
