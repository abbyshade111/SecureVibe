use super::*;

pub(super) fn forgery_check(
    http: &mut dyn Http,
    owned: &sv_manifest::OwnedSection,
    session: &Session,
    a: &SignedIn,
    out: &mut Outcome,
) {
    // The same request A just made, as a page on another site would make it: A's cookies go with
    // it (that is what a browser does), the Origin is somebody else's, and there is no token,
    // because another site cannot read one.
    let values = Values {
        marker: "sv-probe-forged-9b21",
        csrf: Some(String::new()),
        ..Default::default()
    };
    let mut forged = request("forged-create", &owned.create, &values, session);
    forged
        .headers
        .retain(|(n, _)| !n.to_lowercase().contains("csrf") && !n.to_lowercase().contains("xsrf"));
    forged
        .headers
        .push(("Origin".to_owned(), STRANGER.to_owned()));
    forged
        .headers
        .push(("Referer".to_owned(), format!("{STRANGER}/")));
    let response = http.send(&forged);
    if accepted(&response) {
        // SameSite on the session cookie means a browser would not have sent it from another site,
        // which is a real defense — but not the check V3.5.1 asks for, so it lowers the severity
        // rather than removing the finding.
        let protected_by_same_site = !a.set_at_login.is_empty()
            && a.set_at_login
                .iter()
                .all(|c| matches!(c.same_site.as_deref(), Some("lax") | Some("strict")));
        out.findings.push(finding(
            &FORGERY,
            "A request from another site is accepted",
            if protected_by_same_site {
                Severity::Medium
            } else {
                Severity::High
            },
            format!(
                "Creating a record was accepted ({}) when sent with the signed-in user's cookies, an \
                 Origin of {STRANGER} and no anti-forgery token.{}",
                status(&response),
                if protected_by_same_site {
                    " The session cookie's SameSite would stop a browser sending it from another \
                     site, which is why this is not rated higher."
                } else {
                    ""
                }
            ),
        ));
    } else {
        out.verified.push(crate::Verified::new(
            FORGERY.rule_id,
            FORGERY.requirement_ids,
            "a request that creates a record, sent with a signed-in user's cookies from another \
             origin and without a token, and refused"
                .to_owned(),
        ));
    }
}

/// The policy a `Referrer-Policy` header sets: the last value in it a browser knows, as the Fetch
/// standard reads a list.
fn referrer_policy(response: &ProbeResponse) -> Option<String> {
    const KNOWN: &[&str] = &[
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    ];
    response
        .headers
        .iter()
        .filter(|(k, _)| k == "referrer-policy")
        .flat_map(|(_, v)| v.split(','))
        .map(|p| p.trim().to_lowercase())
        .rfind(|p| KNOWN.contains(&p.as_str()))
}

/// Whether the app refuses its own create request as a browser sends it under the app's own
/// `Referrer-Policy: no-referrer`.
///
/// Under that policy the Fetch standard has a browser send `Origin: null`, and no `Referer`, with
/// every request that is not a GET or a HEAD, the app's own forms included. An app that also
/// refuses `Origin: null`, as a cross-site defense reasonably might, refuses its own forms in every
/// real browser, which a test client sending no Origin at all never sees. Asked only when a page
/// the create request is made from sends the policy as a header (a `<meta name="referrer">` is not
/// read), and judged only against a control: the same request, sent straight after it the way
/// the other checks send it, has to be taken, so a refusal is about the Origin and not about the
/// request.
pub(super) fn null_origin_check(
    http: &mut dyn Http,
    owned: &sv_manifest::OwnedSection,
    private: &[String],
    a: &SignedIn,
    out: &mut Outcome,
) {
    let mut session = a.session.clone();
    let own = fill(&owned.create.path, &Values::default());
    let mut policy = None;
    for path in std::iter::once(&own).chain(private.iter()) {
        let page = http.send(&get("null-origin-page", path, &session));
        if let Some(page) = page.filter(|p| (200..300).contains(&p.status)) {
            session.absorb(&page);
            policy = referrer_policy(&page).map(|p| (path.clone(), p));
            break;
        }
    }
    let Some((page, _)) = policy.filter(|(_, p)| p == "no-referrer") else {
        return;
    };
    let values = |marker| Values {
        marker,
        ..Default::default()
    };
    let (nulled, _) = send_template_as(
        http,
        "null-origin-create",
        &owned.create,
        &values("sv-probe-null-origin-5d3a"),
        &mut session,
        private,
        |r| {
            r.headers.retain(|(n, _)| {
                !n.eq_ignore_ascii_case("origin") && !n.eq_ignore_ascii_case("referer")
            });
            r.headers.push(("Origin".to_owned(), "null".to_owned()));
        },
    );
    let (control, _) = send_template(
        http,
        "null-origin-control",
        &owned.create,
        &values("sv-probe-null-origin-control-5d3a"),
        &mut session,
        private,
    );
    let refused = nulled
        .as_ref()
        .is_some_and(|r| (400..500).contains(&r.status));
    if refused && accepted(&control) {
        out.findings.push(finding(
            &OWN_FORMS_REFUSED,
            "The app refuses its own forms in a real browser",
            Severity::Low,
            format!(
                "{page} sends `Referrer-Policy: no-referrer`, under which a browser sends \
                 `Origin: null` with a form. The create request sent that way, signed in and with \
                 its token, was refused ({}); sent straight after without an Origin, it was taken \
                 ({}).",
                status(&nulled),
                status(&control)
            ),
        ));
    } else if accepted(&nulled) {
        out.steps.push(format!(
            "{page} sends `Referrer-Policy: no-referrer`, and the create request sent as a browser \
             then sends it, with `Origin: null`, was taken ({})",
            status(&nulled)
        ));
    } else {
        out.steps.push(format!(
            "{page} sends `Referrer-Policy: no-referrer`; the create request sent with \
             `Origin: null` answered {} and without an Origin {}, which says nothing about the \
             Origin",
            status(&nulled),
            status(&control)
        ));
    }
}

/// Whether the create request can be made in a form browsers send across sites without a CORS
/// preflight (V3.5.2).
///
/// A JSON request from another site makes the browser ask the app first, and an app that answers no
/// is safe from it; many apps rely on exactly that. But the same fields sent as `text/plain`, as a
/// form, or as multipart are "simple" requests a page on any site can send with the person's cookies
/// and no asking. Each goes out with another site's Origin and no token. Taken in any of the three
/// forms is a finding; refused in all three is credit, for this request. Only a 2xx is taken and only
/// a 4xx is refused: a redirect or a server error says neither, and credits nothing.
pub(super) fn simple_request_check(
    http: &mut dyn Http,
    owned: &sv_manifest::OwnedSection,
    session: &Session,
    a: &SignedIn,
    out: &mut Outcome,
) {
    const ID: &str = "V3.5.2";
    if owned.create.json.is_empty() {
        out.not_assessed.push((
            ID.to_owned(),
            "The `owned` create request is a form, which a browser sends from another site without \
             asking the app first anyway, so no preflight is being relied on; whether the app \
             refuses it is the cross-site check's question (V3.5.1)."
                .to_owned(),
        ));
        return;
    }
    let values = Values {
        marker: "sv-probe-simple-request-4e07",
        csrf: Some(String::new()),
        ..Default::default()
    };
    let base = request("simple-request", &owned.create, &values, session);
    let fields: Vec<(String, String)> = owned
        .create
        .json
        .iter()
        .map(|(k, v)| (k.clone(), fill(v, &values)))
        .collect();
    let boundary = "sv-probe-boundary-5c1e";
    let multipart: String = fields
        .iter()
        .map(|(k, v)| {
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
        })
        .chain(std::iter::once(format!("--{boundary}--\r\n")))
        .collect();
    let form: String = fields
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let variants = [
        (
            "text/plain",
            "text/plain;charset=UTF-8".to_owned(),
            base.body_text().into_owned(),
        ),
        (
            "a form",
            "application/x-www-form-urlencoded".to_owned(),
            form,
        ),
        (
            "multipart",
            format!("multipart/form-data; boundary={boundary}"),
            multipart,
        ),
    ];
    let mut taken = Vec::new();
    let mut refused = 0;
    let mut unclear = Vec::new();
    for (name, content_type, body) in variants {
        let mut simple = base.clone();
        simple.id = format!("simple-request-{}", name.replace([' ', '/'], "-"));
        simple.headers.retain(|(n, _)| {
            let n = n.to_lowercase();
            n != "content-type" && !n.contains("csrf") && !n.contains("xsrf")
        });
        simple.headers.extend([
            ("Content-Type".to_owned(), content_type),
            ("Origin".to_owned(), STRANGER.to_owned()),
            ("Referer".to_owned(), format!("{STRANGER}/")),
        ]);
        simple.body = Some(body.into_bytes());
        let response = http.send(&simple);
        match response.as_ref().map(|r| r.status) {
            Some(200..=299) => taken.push(name),
            Some(400..=499) => refused += 1,
            _ => unclear.push(format!("{name} ({})", status(&response))),
        }
    }
    out.steps.push(format!(
        "the create request as another site could send it without a preflight: taken as {}; \
         refused {refused} of 3",
        if taken.is_empty() {
            "none".to_owned()
        } else {
            taken.join(", ")
        }
    ));
    if !taken.is_empty() {
        let protected_by_same_site = !a.set_at_login.is_empty()
            && a.set_at_login
                .iter()
                .all(|c| matches!(c.same_site.as_deref(), Some("lax") | Some("strict")));
        out.findings.push(finding(
            &SIMPLE_REQUEST,
            "A request another site can send without asking is accepted",
            if protected_by_same_site {
                Severity::Medium
            } else {
                Severity::High
            },
            format!(
                "The create request at {} was taken when its fields came as {}, with the signed-in \
                 user's cookies, an Origin of {STRANGER}, and no token. A browser sends those from \
                 any site without a preflight.{}",
                owned.create.path,
                taken.join(" and as "),
                if protected_by_same_site {
                    " The session cookie's SameSite would stop a browser sending it from another \
                     site, which is why this is not rated higher."
                } else {
                    ""
                }
            ),
        ));
    } else if refused == 3 {
        out.verified.push(crate::Verified::new(
            SIMPLE_REQUEST.rule_id,
            SIMPLE_REQUEST.requirement_ids,
            format!(
                "the JSON create request at {}, sent from another origin in each of the three forms \
                 a browser sends without a preflight (text/plain, a form, multipart), refused all \
                 three",
                owned.create.path
            ),
        ));
    } else {
        out.not_assessed.push((
            ID.to_owned(),
            format!(
                "The create request, sent as another site could send it without a preflight, got \
                 answers that neither took it nor refused it: {}.",
                unclear.join(", ")
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::{bearer_ws_users, ws_findings, ws_run};
    use super::*;

    #[test]
    fn an_app_that_asks_for_no_referrer_and_refuses_origin_null_refuses_its_own_forms() {
        let o = run_against(
            Flaws {
                no_referrer: true,
                refuses_null_origin: true,
                ..Default::default()
            },
            &users(),
        );
        let f = o
            .findings
            .iter()
            .find(|f| f.rule_id == OWN_FORMS_REFUSED.rule_id)
            .expect("own forms refused");
        assert!(f.requirement_ids.is_empty(), "{:?}", f.requirement_ids);
        assert!(f.description.contains("/notes"), "{}", f.description);
        assert!(f.description.contains("refused (403)"), "{}", f.description);
        // The control was taken, which is what makes the refusal about the Origin.
        assert!(
            f.description.contains("it was taken (303)"),
            "{}",
            f.description
        );
        // No credit anywhere for a rule that has no requirement.
        assert!(!verified_ids(&o).contains(&OWN_FORMS_REFUSED.rule_id));
    }

    #[test]
    fn an_app_that_asks_for_no_referrer_and_takes_origin_null_is_fine() {
        // The request is sent with the page's token, as the app's own form would send it: a
        // request sent without it would be refused for the token, and read as a refusal of the
        // Origin.
        let o = run_against(
            Flaws {
                no_referrer: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("no-referrer") && s.contains("was taken (303)")),
            "{:#?}",
            o.steps
        );
    }

    #[test]
    fn origin_null_is_not_asked_of_an_app_that_does_not_ask_for_no_referrer() {
        // Refusing `Origin: null` is sensible when no page of the app makes a browser send it.
        let o = run_against(
            Flaws {
                refuses_null_origin: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(o.findings.is_empty(), "{:#?}", o.findings);
        assert!(
            !o.steps.iter().any(|s| s.contains("no-referrer")),
            "{:#?}",
            o.steps
        );
    }

    #[test]
    fn a_refusal_that_the_control_shares_is_not_about_the_origin() {
        // With the anti-forgery check broken the other way, nothing is taken: the refusal of the
        // `Origin: null` request says nothing, and the check says so rather than finding.
        let mut app = FakeApp::new(Flaws {
            no_referrer: true,
            refuses_null_origin: true,
            ..Default::default()
        });
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        let mut steps = Vec::new();
        let a = sign_in(&mut app, &users(), "a", &acc.a, &mut steps).expect("signed in");
        let mut owned = users().owned.unwrap();
        // A create request the app never takes: it names no token field.
        owned.create.form.remove("csrf_token");
        let mut out = Outcome::default();
        null_origin_check(&mut app, &owned, &users().private, &a, &mut out);
        assert!(out.findings.is_empty(), "{:#?}", out.findings);
        assert!(
            out.steps
                .iter()
                .any(|s| s.contains("says nothing about the Origin")),
            "{:#?}",
            out.steps
        );
    }

    /// An app with one page and one form, for the `Origin: null` check alone: its page sends
    /// `policy`, and its form is taken with the token, from `Origin: null` only when `take_null`,
    /// and at all only when `take_any`.
    struct NullOriginApp {
        policy: &'static str,
        take_null: bool,
        take_any: bool,
        sent: Vec<ProbeRequest>,
    }

    impl Http for NullOriginApp {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            self.sent.push(r.clone());
            let respond = |status, headers: Vec<(String, String)>| ProbeResponse {
                id: String::new(),
                status,
                headers,
                body: "<input name='csrf_token' value='t0k'>".to_owned(),
            };
            if r.method == "GET" {
                return Some(respond(
                    200,
                    vec![("referrer-policy".to_owned(), self.policy.to_owned())],
                ));
            }
            let null = r.headers.iter().any(|(k, v)| k == "Origin" && v == "null");
            let token = r.body_text().contains("csrf_token=t0k");
            let taken = self.take_any && token && (self.take_null || !null);
            Some(respond(if taken { 303 } else { 403 }, vec![]))
        }
    }

    fn against_null_origin_app(
        policy: &'static str,
        take_null: bool,
        take_any: bool,
    ) -> (Outcome, Vec<ProbeRequest>) {
        let mut app = NullOriginApp {
            policy,
            take_null,
            take_any,
            sent: Vec::new(),
        };
        let a = SignedIn {
            session: Session::default(),
            set_at_login: Vec::new(),
            before_login: Vec::new(),
            landed: String::new(),
        };
        let mut out = Outcome::default();
        null_origin_check(&mut app, &users().owned.unwrap(), &[], &a, &mut out);
        (out, app.sent)
    }

    #[test]
    fn the_origin_null_request_is_the_apps_own_form_as_a_browser_sends_it() {
        let (out, sent) = against_null_origin_app("no-referrer", false, true);
        assert_eq!(rule_ids(&out), [OWN_FORMS_REFUSED.rule_id]);
        let nulled = sent
            .iter()
            .find(|r| r.id == "null-origin-create")
            .expect("sent");
        assert!(
            nulled
                .headers
                .iter()
                .any(|(k, v)| k == "Origin" && v == "null"),
            "{:?}",
            nulled.headers
        );
        assert!(!nulled.headers.iter().any(|(k, _)| k == "Referer"));
        assert!(
            nulled.body_text().contains("csrf_token=t0k"),
            "{:?}",
            nulled.body
        );
        let (out, _) = against_null_origin_app("no-referrer", true, true);
        assert!(out.findings.is_empty(), "{:#?}", out.findings);
    }

    #[test]
    fn origin_null_is_asked_only_under_a_policy_that_ends_in_no_referrer() {
        // A later value a browser knows replaces the first, so this page's forms carry its origin.
        let (out, sent) = against_null_origin_app("no-referrer, same-origin", false, true);
        assert!(out.findings.is_empty(), "{:#?}", out.findings);
        assert!(!sent.iter().any(|r| r.id == "null-origin-create"));
    }

    #[test]
    fn an_app_that_takes_no_form_at_all_is_not_found_refusing_origin_null() {
        let (out, _) = against_null_origin_app("no-referrer", false, false);
        assert!(out.findings.is_empty(), "{:#?}", out.findings);
        assert!(
            out.steps
                .iter()
                .any(|s| s.contains("says nothing about the Origin")),
            "{:#?}",
            out.steps
        );
    }

    #[test]
    fn the_referrer_policy_is_the_last_value_a_browser_knows() {
        let with = |value: &str| ProbeResponse {
            id: String::new(),
            status: 200,
            headers: vec![("referrer-policy".to_owned(), value.to_owned())],
            body: String::new(),
        };
        assert_eq!(
            referrer_policy(&with("no-referrer")).as_deref(),
            Some("no-referrer")
        );
        assert_eq!(
            referrer_policy(&with("no-referrer, strict-origin-when-cross-origin")).as_deref(),
            Some("strict-origin-when-cross-origin")
        );
        assert_eq!(
            referrer_policy(&with("No-Referrer, made-up-policy")).as_deref(),
            Some("no-referrer")
        );
        assert_eq!(referrer_policy(&with("made-up-policy")), None);
    }

    /// `users()`, with the owned record behind a JSON API.
    fn with_json_api() -> UsersSection {
        let mut u = users();
        u.owned = Some(sv_manifest::OwnedSection {
            create: RequestTemplate {
                method: "POST".into(),
                path: "/api/notes".into(),
                form: BTreeMap::new(),
                json: [("text".to_owned(), "{marker}".to_owned())].into(),
            },
            read: Some("/api/notes/{id}".into()),
            id_field: None,
        });
        u
    }

    fn simple_request_named(o: &Outcome) -> Vec<String> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.split(", ").any(|i| i == "V3.5.2"))
            .map(|(_, why)| why.clone())
            .collect()
    }

    #[test]
    fn a_json_api_that_takes_json_alone_is_credited_for_the_preflight_it_relies_on() {
        let o = run_against(Flaws::default(), &with_json_api());
        assert!(
            verified_ids(&o).contains(&SIMPLE_REQUEST.rule_id),
            "{:?}\n{:?}",
            o.steps,
            o.not_assessed
        );
        assert!(!rule_ids(&o).contains(&SIMPLE_REQUEST.rule_id));
        // The record really was made through the API, or none of this means anything.
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("created a record at /api/notes/")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn each_simple_form_the_api_takes_is_named_in_the_finding() {
        for (flaws, says, not) in [
            (
                Flaws {
                    api_parses_any_type: true,
                    ..Default::default()
                },
                "text/plain",
                "multipart",
            ),
            (
                Flaws {
                    api_takes_forms: true,
                    ..Default::default()
                },
                "a form and as multipart",
                "text/plain",
            ),
        ] {
            let o = run_against(flaws, &with_json_api());
            let f = o
                .findings
                .iter()
                .find(|f| f.rule_id == SIMPLE_REQUEST.rule_id)
                .unwrap_or_else(|| panic!("{says}: no finding: {:?}", o.steps));
            assert!(f.description.contains(says), "{}", f.description);
            assert!(!f.description.contains(not), "{}", f.description);
            assert!(!verified_ids(&o).contains(&SIMPLE_REQUEST.rule_id));
        }
    }

    #[test]
    fn an_api_that_checks_the_origin_is_credited_too() {
        let o = run_against(
            Flaws {
                api_parses_any_type: true,
                api_takes_forms: true,
                api_checks_origin: true,
                ..Default::default()
            },
            &with_json_api(),
        );
        assert!(
            verified_ids(&o).contains(&SIMPLE_REQUEST.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!rule_ids(&o).contains(&SIMPLE_REQUEST.rule_id));
    }

    #[test]
    fn a_redirect_is_neither_taken_nor_refused_and_a_form_needs_no_preflight() {
        let o = run_against(
            Flaws {
                api_redirects_refusals: true,
                ..Default::default()
            },
            &with_json_api(),
        );
        assert!(!verified_ids(&o).contains(&SIMPLE_REQUEST.rule_id));
        assert!(!rule_ids(&o).contains(&SIMPLE_REQUEST.rule_id));
        assert!(
            simple_request_named(&o)
                .iter()
                .any(|w| w.contains("neither took it nor refused it")),
            "{:?}",
            o.not_assessed
        );
        // Two of the three refused and the third a redirect is not three refused.
        let o = run_against(
            Flaws {
                api_redirects_multipart: true,
                ..Default::default()
            },
            &with_json_api(),
        );
        assert!(
            !verified_ids(&o).contains(&SIMPLE_REQUEST.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            simple_request_named(&o)
                .iter()
                .any(|w| w.contains("multipart (302)")),
            "{:?}",
            o.not_assessed
        );
        // The ordinary notes page takes a form, which no preflight ever guarded.
        let o = run_against(Flaws::default(), &users());
        assert!(!verified_ids(&o).contains(&SIMPLE_REQUEST.rule_id));
        assert!(
            simple_request_named(&o)
                .iter()
                .any(|w| w.contains("is a form")),
            "{:?}",
            o.not_assessed
        );
    }

    // --------------------------------------------------------------------------------------------
    // V4.4.2 for a private WebSocket

    fn origin_found(o: &Outcome) -> bool {
        rule_ids(o).contains(&WS_FOREIGN_ORIGIN.rule_id)
    }

    fn origin_credited(o: &Outcome) -> bool {
        verified_ids(o).contains(&WS_FOREIGN_ORIGIN.rule_id)
    }

    #[test]
    fn a_private_socket_that_checks_the_origin_is_credited() {
        let o = ws_run(Flaws::default());
        assert!(origin_credited(&o), "{:?}", o.steps);
        assert!(!origin_found(&o));
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("signed in, from another site: refused")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_private_socket_that_takes_any_origin_is_found() {
        let o = ws_run(Flaws {
            ws_any_origin: true,
            ..Default::default()
        });
        assert!(origin_found(&o), "{:?}", o.steps);
        assert!(!origin_credited(&o));
        // Only the origin is wrong: the session checks still hold.
        assert!(ws_findings(&o).is_empty(), "{:?}", o.findings);
    }

    #[test]
    fn a_socket_open_to_anybody_is_found_for_the_origin_too() {
        let o = ws_run(Flaws {
            ws_open: true,
            ..Default::default()
        });
        assert!(origin_found(&o), "{:?}", o.steps);
        assert!(!origin_credited(&o));
    }

    #[test]
    fn with_a_bearer_session_the_origin_is_still_asked() {
        let o = run_against(Flaws::default(), &bearer_ws_users());
        assert!(origin_credited(&o), "{:?}", o.steps);
        let o = run_against(
            Flaws {
                ws_any_origin: true,
                ..Default::default()
            },
            &bearer_ws_users(),
        );
        assert!(origin_found(&o), "{:?}", o.steps);
    }

    #[test]
    fn a_socket_refusing_everybody_is_not_asked_about_the_origin() {
        let o = ws_run(Flaws {
            ws_refuses_all: true,
            ..Default::default()
        });
        assert!(!origin_found(&o) && !origin_credited(&o), "{:?}", o.steps);
    }
}
