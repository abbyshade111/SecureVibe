//! Open redirects in the sign-in flow (V3.7.2): an address outside the app, given in the
//! parameters a return address is usually read from, and the app sending the browser there.
//!
//! Only ever a finding. Three places and nine parameter names are a sample, and an app that sends
//! the browser to its own pages here may still have a redirect elsewhere that goes anywhere.

use super::*;

/// A host nobody can own: `.invalid` is reserved, so a redirect there can never reach a real site.
const ELSEWHERE: &str = "sv-redirect.invalid";

/// The names a return address is most often read from, across frameworks: Django and Flask-Login
/// (`next`), ASP.NET (`ReturnUrl`), Rails and Express apps (`return_to`, `returnTo`), Spring and
/// Google-style sign-ins (`continue`), and the rest common in hand-written apps.
const PARAMETERS: &[&str] = &[
    "next",
    "redirect",
    "redirect_to",
    "returnTo",
    "return_to",
    "ReturnUrl",
    "url",
    "continue",
    "destination",
];

/// The address outside the app, as it is written into the query: a full one, and one beginning with
/// `//`, which a browser reads as another site and a check that only asks "does it begin with `/`?"
/// takes for one of the app's own pages.
const TARGETS: &[(&str, &str)] = &[
    ("absolute", "https%3A%2F%2Fsv-redirect.invalid%2F"),
    ("scheme-relative", "%2F%2Fsv-redirect.invalid%2F"),
];

/// A target as a person reads it.
fn decoded(target: &str) -> String {
    target.replace("%3A", ":").replace("%2F", "/")
}

fn with_query(path: &str, target: &str) -> String {
    let query: Vec<String> = PARAMETERS.iter().map(|p| format!("{p}={target}")).collect();
    format!(
        "{path}{}{}",
        if path.contains('?') { '&' } else { '?' },
        query.join("&")
    )
}

/// Whether a `Location` sends the browser to `ELSEWHERE`. A browser treats `\` as `/` and ignores
/// the case of the scheme and host, so those are read the same way.
pub(super) fn leaves_the_app(location: &str) -> bool {
    let to = location.trim().replace('\\', "/").to_lowercase();
    let rest = to
        .strip_prefix("https:")
        .or_else(|| to.strip_prefix("http:"))
        .unwrap_or(&to);
    rest.strip_prefix("//")
        .map(|host| host.trim_start_matches('/'))
        .is_some_and(|host| {
            host.split(['/', '?', '#', ':'])
                .next()
                .is_some_and(|h| h == ELSEWHERE)
        })
}

fn redirect_of(answer: &Option<ProbeResponse>) -> Option<String> {
    answer
        .as_ref()
        .filter(|r| (300..400).contains(&r.status))
        .and_then(|r| r.header("location"))
        .filter(|l| leaves_the_app(l))
        .map(str::to_owned)
}

/// Signs A in through the sign-in page with the outside address in its query, then asks for that
/// page again signed in, then signs out with it, and reads where each answer sends the browser.
pub(super) fn open_redirect_check(
    http: &mut dyn Http,
    users: &UsersSection,
    account: &Account,
    out: &mut Outcome,
) {
    let Some(login) = &users.login else {
        return;
    };
    // A sign-in that answers with a token in JSON leaves the next page to the script on the page,
    // which no request here sees.
    if users.token_field.is_some() {
        return;
    }
    let mut seen: Vec<String> = Vec::new();
    for (kind, target) in TARGETS {
        let page = with_query(&login.path, target);
        let mut session = Session::default();
        let mut csrf = None;
        if let Some(form) = http.send(&get(
            &format!("redirect-login-page-{kind}"),
            &page,
            &session,
        )) {
            session.absorb(&form);
            csrf = csrf_token(&form, &session);
        }
        let values = Values {
            user: &account.user,
            password: &account.password,
            csrf,
            ..Default::default()
        };
        let (signed_in, _) = send_template_as(
            http,
            &format!("redirect-login-{kind}"),
            login,
            &values,
            &mut session,
            &[],
            |r| r.path = with_query(&r.path, target),
        );
        let given = decoded(target);
        if let Some(to) = redirect_of(&signed_in) {
            seen.push(format!(
                "signing in at {} with `next` and eight other return parameters set to {given} sent the \
                 browser to {to}",
                login.path
            ));
        }
        if !accepted(&signed_in) {
            continue;
        }
        let again = http.send(&get(&format!("redirect-signed-in-{kind}"), &page, &session));
        if let Some(to) = redirect_of(&again) {
            seen.push(format!(
                "opening {} already signed in, with `next` and eight other return parameters set to \
                 {given}, sent the browser to {to}",
                login.path
            ));
        }
        if let Some(logout) = &users.logout {
            let (signed_out, _) = send_template_as(
                http,
                &format!("redirect-logout-{kind}"),
                logout,
                &Values::default(),
                &mut session,
                &users.private,
                |r| r.path = with_query(&r.path, target),
            );
            if let Some(to) = redirect_of(&signed_out) {
                seen.push(format!(
                    "signing out at {} with `next` and eight other return parameters set to {given} sent \
                     the browser to {to}",
                    logout.path
                ));
            }
        }
    }
    out.steps.push(format!(
        "gave the sign-in{} an address outside the app as `next` and eight other return parameters: \
         {}",
        if users.logout.is_some() {
            " and sign-out"
        } else {
            ""
        },
        if seen.is_empty() {
            "never sent there"
        } else {
            "sent there"
        }
    ));
    if !seen.is_empty() {
        out.findings.push(finding(
            &OPEN_REDIRECT,
            "The sign-in flow sends the browser to any address it is given",
            Severity::Medium,
            format!(
                "Given {ELSEWHERE}, a site outside the app, as the address to return to (in `next` \
                 and eight other parameters a return address is often read from): {}.",
                seen.join("; ")
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::*;

    #[test]
    fn an_address_outside_the_app_is_told_from_its_own_pages() {
        for outside in [
            "https://sv-redirect.invalid/",
            "HTTP://SV-REDIRECT.INVALID",
            "//sv-redirect.invalid/x",
            "/\\sv-redirect.invalid/",
            "\\\\sv-redirect.invalid",
            "https://sv-redirect.invalid:443/?a=b",
            "///sv-redirect.invalid/",
        ] {
            assert!(leaves_the_app(outside), "{outside}");
        }
        for own in [
            "/account",
            "/sv-redirect.invalid/",
            "/account?next=https://sv-redirect.invalid/",
            "https://app.test/?to=sv-redirect.invalid",
            "https://sv-redirect.invalid.app.test/",
            "",
        ] {
            assert!(!leaves_the_app(own), "{own}");
        }
    }

    #[test]
    fn a_sign_in_that_returns_only_to_its_own_pages_raises_nothing() {
        let o = run_against(Flaws::default(), &users());
        assert!(
            !rule_ids(&o).contains(&OPEN_REDIRECT.rule_id),
            "{:?}",
            o.findings
        );
        // The questions were really asked, sign-out included, and the fake really follows a `next`
        // that is one of its own pages: otherwise this would pass on an app that ignores `next`.
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("sign-in and sign-out") && s.ends_with("never sent there")),
            "{:?}",
            o.steps
        );
        let mut app = FakeApp::new(Flaws::default());
        let back = app
            .send(&ProbeRequest {
                id: "own".into(),
                method: "GET".into(),
                path: "/login?next=%2Fnotes".into(),
                headers: vec![],
                body: None,
            })
            .expect("an answer");
        assert_eq!(back.status, 200, "an anonymous sign-in page is a form");
        let mut users = users();
        users.logout = None;
        let o = run_against(Flaws::default(), &users);
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("gave the sign-in an address")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_sign_in_that_goes_anywhere_is_found() {
        for flaws in [
            Flaws {
                redirect_anywhere: true,
                ..Default::default()
            },
            Flaws {
                redirect_checks_slash_only: true,
                ..Default::default()
            },
        ] {
            let o = run_against(flaws, &users());
            assert_eq!(rule_ids(&o), vec![OPEN_REDIRECT.rule_id], "{:?}", o.steps);
            assert!(!verified_ids(&o).contains(&OPEN_REDIRECT.rule_id));
            let f = &o.findings[0];
            // Sign-in, the page opened signed in, and sign-out each sent the browser away.
            for place in ["signing in at", "already signed in", "signing out at"] {
                assert!(f.description.contains(place), "{place}: {}", f.description);
            }
            // Every return parameter was given the address, not `next` alone, and it says so (item
            // 16 of the review of 1 to 4 October).
            assert_eq!(
                f.description
                    .matches("with `next` and eight other return parameters set to")
                    .count(),
                3,
                "{}",
                f.description
            );
            assert_eq!(
                PARAMETERS.len(),
                9,
                "the sentence counts eight besides `next`"
            );
        }
        // Only the `//` address gets past a check for a leading `/`.
        let o = run_against(
            Flaws {
                redirect_checks_slash_only: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(
            !o.findings[0].description.contains("to https://"),
            "{}",
            o.findings[0].description
        );
    }
}
