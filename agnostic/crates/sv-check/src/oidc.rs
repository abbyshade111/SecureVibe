//! Signing in through another service ("Sign in with Google"), asked of a test provider of `sv`'s
//! own (V10.1.2, V10.2.1, V10.5.1, V10.5.4, V6.8.2).
//!
//! For the run the app is pointed at a provider that signs anybody in without asking and can be
//! told to get the next ID token wrong in one particular way. The probes play the browser: they
//! open the app's sign-in page, follow it to the provider, follow the provider back, and look at a
//! private page. Everything the app is asked to accept comes from a sign-in the probes started
//! themselves, so a refusal is about the one thing that was changed.
//!
//! # What has to hold first
//!
//! The private page has to be shut to somebody who has not signed in, and an ordinary sign-in
//! through the provider has to open it — or a refusal shows nothing. And an ordinary sign-in
//! has to work again *after* the broken ones, or a refusal could be the app having stopped
//! working rather than it having noticed: nothing is credited without that last one.
//!
//! # What is not asked
//!
//! V6.8.1 and V10.2.2 need a second provider; V10.5.3 needs the provider's published details to
//! change under an app that usually reads them once at start-up; V10.5.2 and V6.8.4 turn on what
//! the app decides, not on anything the provider can send wrong.

use crate::finding::Severity;
use crate::probes::{ProbeRequest, ProbeResponse};
use crate::signed_in::{Http, Outcome, Rule, Session, finding, get, ok, status};
use sv_manifest::OidcSection;

const IDS: &str = "V10.1.2, V10.2.1, V10.5.1, V10.5.4, V6.8.2";

const CROSS_SESSION: Rule = Rule {
    rule_id: "probe.oidc-sign-in-from-another-session",
    requirement_ids: &["V10.1.2", "V10.2.1"],
    cwe: &["CWE-352"],
    impact: "Somebody can finish their own sign-in in another person's browser, and that person is \
             then using the attacker's account without knowing — typing into it, uploading to it, \
             saving card details to it.",
    fix: "Send a `state` value, or a PKCE `code_verifier`'s challenge, that is random and kept in \
          the session that started the sign-in, and refuse a return from the provider that does \
          not match it.",
};

const WRONG_NONCE: Rule = Rule {
    rule_id: "probe.oidc-nonce-not-checked",
    requirement_ids: &["V10.5.1"],
    cwe: &["CWE-294"],
    impact: "An ID token captured from one sign-in can be played back to sign in again.",
    fix: "Keep the `nonce` sent to the provider in the session, and refuse an ID token whose \
          `nonce` claim is not exactly that value.",
};

const WRONG_AUD: Rule = Rule {
    rule_id: "probe.oidc-audience-not-checked",
    requirement_ids: &["V10.5.4"],
    cwe: &["CWE-287"],
    impact: "An ID token issued to any other app that uses the same provider signs its holder in \
             here — including an app an attacker wrote to collect them.",
    fix: "Refuse an ID token whose `aud` claim is not this app's own client id.",
};

const UNCHECKED_SIGNATURE: Rule = Rule {
    rule_id: "probe.oidc-signature-not-checked",
    requirement_ids: &["V6.8.2"],
    cwe: &["CWE-347"],
    impact: "Anybody can write an ID token saying they are whoever they like, and be signed in as \
             that person.",
    fix: "Verify every ID token's signature against the provider's published keys, with the \
          algorithm fixed in advance, and refuse `alg: none` and any token that does not verify.",
};

/// One sign-in, begun: the session it started in, and where the provider sends the browser back.
struct Begun {
    session: Session,
    /// The app's own path to return to, with the provider's code and `state` in it.
    back: String,
    /// Whether the app sent a `nonce` when it sent the browser to the provider.
    nonce_sent: bool,
}

/// The part of an absolute address after its host, or the address itself if it has none.
fn path_of(location: &str) -> String {
    match location.split_once("://") {
        Some((_, rest)) => rest
            .find('/')
            .map_or("/".to_owned(), |i| rest[i..].to_owned()),
        None => location.to_owned(),
    }
}

fn location(response: &Option<ProbeResponse>) -> Option<String> {
    let r = response.as_ref()?;
    if !(300..400).contains(&r.status) {
        return None;
    }
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
}

fn set_mode(http: &mut dyn Http, mode: &str) -> bool {
    let request = ProbeRequest {
        id: format!("oidc-mode-{mode}"),
        method: "POST".to_owned(),
        path: "/_sv/mode".to_owned(),
        headers: vec![(
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        )],
        body: Some(format!("mode={mode}")),
    };
    ok(&http.provider(&request))
}

/// Opens the sign-in page in a fresh session and follows it to the provider and back as far as
/// the app's return address, without going there.
fn begin(http: &mut dyn Http, section: &OidcSection, who: &str) -> Result<Begun, String> {
    let mut session = Session::default();
    let start = http.send(&get(&format!("oidc-start-{who}"), &section.start, &session));
    if let Some(r) = &start {
        session.absorb(r);
    }
    let Some(to_provider) = location(&start) else {
        return Err(format!(
            "{} answered {}, not a redirect to the provider",
            section.start,
            status(&start)
        ));
    };
    let authorize = path_of(&to_provider);
    if !authorize.starts_with("/authorize") {
        return Err(format!(
            "{} sent the browser to {to_provider}, not to the test provider — check that the app \
             uses OIDC_ISSUER when it is set",
            section.start
        ));
    }
    let nonce_sent = authorize.contains("nonce=");
    let from_provider = http.provider(&get(
        &format!("oidc-authorize-{who}"),
        &authorize,
        &Session::default(),
    ));
    let Some(back) = location(&from_provider) else {
        return Err(format!(
            "the test provider refused the sign-in the app asked for ({}) — check that the app \
             uses OIDC_CLIENT_ID",
            status(&from_provider)
        ));
    };
    Ok(Begun {
        session,
        back: path_of(&back),
        nonce_sent,
    })
}

/// Takes a return address to the app in `session`, and says whether the private page then opens.
fn finish(
    http: &mut dyn Http,
    section: &OidcSection,
    session: &mut Session,
    back: &str,
    who: &str,
) -> bool {
    if let Some(r) = http.send(&get(&format!("oidc-back-{who}"), back, session)) {
        session.absorb(&r);
    }
    ok(&http.send(&get(
        &format!("oidc-private-{who}"),
        &section.private,
        session,
    )))
}

/// A whole sign-in, with the provider set to `mode` for it.
fn sign_in(
    http: &mut dyn Http,
    section: &OidcSection,
    mode: &str,
    who: &str,
) -> Result<bool, String> {
    if !set_mode(http, mode) {
        return Err("the test provider did not take its instructions".to_owned());
    }
    let mut begun = begin(http, section, who)?;
    Ok(finish(
        http,
        section,
        &mut begun.session,
        &begun.back.clone(),
        who,
    ))
}

pub fn run(http: &mut dyn Http, section: &OidcSection) -> Outcome {
    let mut out = Outcome::default();
    let not_assessed =
        |out: &mut Outcome, why: String| out.not_assessed.push((IDS.to_owned(), why));

    if !set_mode(http, "normal") {
        not_assessed(
            &mut out,
            "The test provider could not be started or did not answer, so the app's sign-in \
             through another service was not asked about."
                .to_owned(),
        );
        return out;
    }
    // The private page has to be shut to somebody who has not signed in.
    if ok(&http.send(&get(
        "oidc-private-before",
        &section.private,
        &Session::default(),
    ))) {
        not_assessed(
            &mut out,
            format!(
                "{} opened for somebody who had not signed in, so it cannot tell whether a sign-in \
                 worked. Name a page in `private` that only a signed-in person sees.",
                section.private
            ),
        );
        return out;
    }
    // An ordinary sign-in has to open it.
    let control = match begin(http, section, "control") {
        Ok(mut begun) => {
            let back = begun.back.clone();
            let opened = finish(http, section, &mut begun.session, &back, "control");
            (opened, begun.nonce_sent)
        }
        Err(why) => {
            not_assessed(
                &mut out,
                format!("An ordinary sign-in could not be made: {why}."),
            );
            return out;
        }
    };
    let (opened, nonce_sent) = control;
    if !opened {
        not_assessed(
            &mut out,
            format!(
                "An ordinary sign-in through the test provider did not open {}, so nothing can be \
                 told from what the app refuses. Check that it uses OIDC_ISSUER, OIDC_CLIENT_ID, \
                 and OIDC_CLIENT_SECRET when they are set.",
                section.private
            ),
        );
        return out;
    }
    out.steps.push(format!(
        "signed in through the test provider: {} opened",
        section.private
    ));

    // A sign-in started in one session and finished in another.
    let crossed = match (begin(http, section, "x"), begin(http, section, "y")) {
        (Ok(x), Ok(mut y)) => Some(finish(http, section, &mut y.session, &x.back, "crossed")),
        _ => None,
    };

    // The four tokens the provider gets wrong on purpose.
    let mut broken: Vec<(&str, Option<bool>)> = Vec::new();
    for mode in ["wrong-nonce", "wrong-aud", "unsigned", "wrong-key"] {
        let result = if mode == "wrong-nonce" && !nonce_sent {
            None
        } else {
            sign_in(http, section, mode, mode).ok()
        };
        broken.push((mode, result));
    }
    let accepted = |mode: &str| broken.iter().any(|(m, r)| *m == mode && *r == Some(true));
    let refused = |mode: &str| broken.iter().any(|(m, r)| *m == mode && *r == Some(false));

    // And an ordinary sign-in again, or none of the refusals above is credited.
    let still_works = sign_in(http, section, "normal", "after").unwrap_or(false);
    out.steps.push(format!(
        "finished in another session: {}; a wrong nonce: {}; a wrong audience: {}; unsigned: {}; \
         signed with another key: {}; an ordinary sign-in afterwards: {}",
        word(crossed),
        word(broken[0].1),
        word(broken[1].1),
        word(broken[2].1),
        word(broken[3].1),
        if still_works { "opened" } else { "refused" }
    ));

    judge(
        &mut out,
        &CROSS_SESSION,
        crossed,
        still_works,
        "A sign-in can be finished in a session that did not start it",
        Severity::Medium,
        "a return from the provider made for a sign-in begun in one session, taken in another \
         session that had begun its own",
    );
    if nonce_sent {
        judge(
            &mut out,
            &WRONG_NONCE,
            broken[0].1,
            still_works,
            "An ID token with the wrong nonce is accepted",
            Severity::Medium,
            "an ID token whose `nonce` was not the one the app sent",
        );
    } else {
        out.not_assessed.push((
            "V10.5.1".to_owned(),
            "The app sends no `nonce` when it sends the browser to the provider, so there is no \
             value for an ID token to be held to. PKCE or `state` may be protecting the sign-in \
             instead; this does not say which."
                .to_owned(),
        ));
    }
    judge(
        &mut out,
        &WRONG_AUD,
        broken[1].1,
        still_works,
        "An ID token issued to another app is accepted",
        Severity::High,
        "an ID token issued to a different client",
    );
    let signature = if accepted("unsigned") || accepted("wrong-key") {
        Some(true)
    } else if refused("unsigned") && refused("wrong-key") {
        Some(false)
    } else {
        None
    };
    judge(
        &mut out,
        &UNCHECKED_SIGNATURE,
        signature,
        still_works,
        "An ID token that is not properly signed is accepted",
        Severity::High,
        if accepted("unsigned") {
            "an ID token with no signature at all (`alg: none`)"
        } else if accepted("wrong-key") {
            "an ID token signed with a key the provider never published"
        } else {
            "an ID token with no signature, and one signed with a key the provider never \
             published"
        },
    );
    out
}

fn word(result: Option<bool>) -> &'static str {
    match result {
        Some(true) => "opened",
        Some(false) => "refused",
        None => "not tried",
    }
}

/// A finding if the app signed the probes in, a credit if it refused and an ordinary sign-in
/// still worked afterwards, and otherwise nothing but the reason.
fn judge(
    out: &mut Outcome,
    rule: &Rule,
    result: Option<bool>,
    still_works: bool,
    title: &str,
    severity: Severity,
    what: &str,
) {
    let ids = rule.requirement_ids.join(", ");
    match result {
        Some(true) => out.findings.push(finding(
            rule,
            title,
            severity,
            format!("The app signed the probes in with {what}."),
        )),
        Some(false) if still_works => out.verified.push(crate::Verified::new(
            rule.rule_id,
            rule.requirement_ids,
            format!("{what}, refused, where an ordinary sign-in afterwards worked"),
        )),
        Some(false) => out.not_assessed.push((
            ids,
            format!(
                "The app refused {what}, but an ordinary sign-in afterwards did not work either, \
                 so the refusal may not have been about the token."
            ),
        )),
        None => out.not_assessed.push((
            ids,
            format!("A sign-in with {what} could not be made through to the end."),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default, Clone, Copy)]
    struct Flaws {
        no_state_check: bool,
        no_nonce_check: bool,
        no_nonce_sent: bool,
        no_aud_check: bool,
        accepts_unsigned: bool,
        accepts_wrong_key: bool,
        /// Every sign-in fails.
        broken: bool,
        /// After refusing one bad token, stops signing anybody in.
        breaks_after_a_refusal: bool,
        /// The private page is open to everybody.
        private_public: bool,
        /// There is no provider at all.
        no_provider: bool,
        /// The provider gives no answer when asked for this one mode.
        provider_fails_on: Option<&'static str>,
    }

    /// A token as the fake provider issues it: what it says, and how it was signed.
    #[derive(Clone)]
    struct Token {
        nonce: Option<String>,
        aud: String,
        signed: &'static str, // "good", "none", or "stranger"
    }

    #[derive(Default)]
    struct Fake {
        flaws: Flaws,
        mode: String,
        codes: BTreeMap<String, (Option<String>, Token)>, // code -> (nonce sent, token to issue)
        pending: BTreeMap<String, (String, Option<String>)>, // session -> (state, nonce)
        signed_in: Vec<String>,
        next: u32,
        refused_once: bool,
        mode_requests: u32,
    }

    fn cookie(r: &ProbeRequest) -> Option<String> {
        r.headers
            .iter()
            .find(|(k, _)| k == "Cookie")
            .and_then(|(_, v)| v.split("; ").find_map(|c| c.strip_prefix("sid=")))
            .map(str::to_owned)
    }

    fn query(path: &str) -> BTreeMap<String, String> {
        path.split_once('?')
            .map(|(_, q)| {
                q.split('&')
                    .filter_map(|p| p.split_once('='))
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn answer(status: u16, headers: Vec<(&str, String)>) -> ProbeResponse {
        ProbeResponse {
            id: String::new(),
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
            body: String::new(),
        }
    }

    impl Fake {
        fn id(&mut self) -> String {
            self.next += 1;
            format!("v{}", self.next)
        }

        fn accepts(&self, token: &Token, nonce_sent: &Option<String>) -> bool {
            let f = self.flaws;
            if f.broken || (f.breaks_after_a_refusal && self.refused_once) {
                return false;
            }
            let signature = match token.signed {
                "none" => f.accepts_unsigned,
                "stranger" => f.accepts_wrong_key,
                _ => true,
            };
            let nonce = f.no_nonce_check || token.nonce == *nonce_sent;
            let aud = f.no_aud_check || token.aud == "client";
            signature && nonce && aud
        }
    }

    impl Http for Fake {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            let path = r.path.split('?').next().unwrap_or("").to_owned();
            let sid = cookie(r);
            Some(match path.as_str() {
                "/login/oidc" => {
                    let sid = self.id();
                    let state = self.id();
                    let nonce = (!self.flaws.no_nonce_sent).then(|| self.id());
                    self.pending
                        .insert(sid.clone(), (state.clone(), nonce.clone()));
                    let mut to = format!(
                        "http://idp:9000/authorize?client_id=client&redirect_uri=http://app/callback&state={state}"
                    );
                    if let Some(n) = nonce {
                        to.push_str(&format!("&nonce={n}"));
                    }
                    answer(
                        302,
                        vec![
                            ("location", to),
                            ("set-cookie", format!("sid={sid}; Path=/")),
                        ],
                    )
                }
                "/callback" => {
                    let q = query(&r.path);
                    let Some(sid) = sid else {
                        return Some(answer(400, vec![]));
                    };
                    let Some((state, nonce)) = self.pending.get(&sid).cloned() else {
                        return Some(answer(400, vec![]));
                    };
                    if !self.flaws.no_state_check && q.get("state") != Some(&state) {
                        return Some(answer(400, vec![]));
                    }
                    let Some((_, token)) = q.get("code").and_then(|c| self.codes.remove(c)) else {
                        return Some(answer(400, vec![]));
                    };
                    if self.accepts(&token, &nonce) {
                        self.signed_in.push(sid);
                        answer(302, vec![("location", "/account".into())])
                    } else {
                        self.refused_once = true;
                        answer(401, vec![])
                    }
                }
                "/account" => {
                    if self.flaws.private_public || sid.is_some_and(|s| self.signed_in.contains(&s))
                    {
                        answer(200, vec![])
                    } else {
                        answer(302, vec![("location", "/login/oidc".into())])
                    }
                }
                _ => answer(404, vec![]),
            })
        }

        fn provider(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            if self.flaws.no_provider {
                return None;
            }
            if r.path == "/_sv/mode" {
                self.mode_requests += 1;
                self.mode = r
                    .body
                    .clone()
                    .unwrap_or_default()
                    .trim_start_matches("mode=")
                    .to_owned();
                return Some(answer(200, vec![]));
            }
            let q = query(&r.path);
            let code = self.id();
            let nonce = q.get("nonce").cloned();
            let mode = std::mem::replace(&mut self.mode, "normal".to_owned());
            if self.flaws.provider_fails_on == Some(mode.as_str()) {
                return None;
            }
            let token = Token {
                nonce: match mode.as_str() {
                    "wrong-nonce" => Some("not-it".to_owned()),
                    _ => nonce.clone(),
                },
                aud: if mode == "wrong-aud" {
                    "other".into()
                } else {
                    "client".into()
                },
                signed: match mode.as_str() {
                    "unsigned" => "none",
                    "wrong-key" => "stranger",
                    _ => "good",
                },
            };
            self.codes.insert(code.clone(), (nonce, token));
            Some(answer(
                302,
                vec![(
                    "location",
                    format!(
                        "http://app/callback?code={code}&state={}",
                        q.get("state").cloned().unwrap_or_default()
                    ),
                )],
            ))
        }
    }

    fn section() -> OidcSection {
        OidcSection {
            start: "/login/oidc".into(),
            private: "/account".into(),
        }
    }

    fn run_with(flaws: Flaws) -> Outcome {
        let mut fake = Fake {
            flaws,
            mode: "normal".into(),
            ..Default::default()
        };
        run(&mut fake, &section())
    }

    fn found(o: &Outcome) -> Vec<&str> {
        o.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn credited(o: &Outcome) -> Vec<&str> {
        o.verified.iter().map(|v| v.check_id.as_str()).collect()
    }

    const ALL: [&Rule; 4] = [
        &CROSS_SESSION,
        &WRONG_NONCE,
        &WRONG_AUD,
        &UNCHECKED_SIGNATURE,
    ];

    #[test]
    fn an_app_that_checks_everything_is_credited_for_all_four() {
        let o = run_with(Flaws::default());
        assert!(o.findings.is_empty(), "{:?}", found(&o));
        for rule in ALL {
            assert!(
                credited(&o).contains(&rule.rule_id),
                "{}: {:?}",
                rule.rule_id,
                o.steps
            );
        }
    }

    #[test]
    fn each_missing_check_is_found_by_its_own_rule_and_by_no_other() {
        for (flaws, rule) in [
            (
                // Neither `state` nor a `nonce`: nothing ties the return to the session. With a
                // nonce still checked, the other session's token carries the other session's
                // nonce and is refused — see the test below.
                Flaws {
                    no_state_check: true,
                    no_nonce_sent: true,
                    ..Default::default()
                },
                &CROSS_SESSION,
            ),
            (
                Flaws {
                    no_nonce_check: true,
                    ..Default::default()
                },
                &WRONG_NONCE,
            ),
            (
                Flaws {
                    no_aud_check: true,
                    ..Default::default()
                },
                &WRONG_AUD,
            ),
            (
                Flaws {
                    accepts_unsigned: true,
                    ..Default::default()
                },
                &UNCHECKED_SIGNATURE,
            ),
            (
                Flaws {
                    accepts_wrong_key: true,
                    ..Default::default()
                },
                &UNCHECKED_SIGNATURE,
            ),
        ] {
            let o = run_with(flaws);
            assert_eq!(found(&o), [rule.rule_id], "{:?}", o.steps);
            assert!(
                !credited(&o).contains(&rule.rule_id),
                "{} credited as well",
                rule.rule_id
            );
        }
    }

    #[test]
    fn a_nonce_kept_in_the_session_is_enough_to_refuse_a_crossed_sign_in() {
        // V10.1.2 accepts `state`, PKCE, or a `nonce`, each bound to the session. An app that does
        // not check `state` but does check its session's nonce refuses the crossed return, and is
        // credited for it rather than blamed for the missing `state` check.
        let o = run_with(Flaws {
            no_state_check: true,
            ..Default::default()
        });
        assert!(o.findings.is_empty(), "{:?}", found(&o));
        assert!(credited(&o).contains(&CROSS_SESSION.rule_id));
    }

    #[test]
    fn nothing_is_said_about_tokens_when_the_setup_does_not_hold() {
        for (flaws, says) in [
            (
                Flaws {
                    no_provider: true,
                    ..Default::default()
                },
                "test provider could not",
            ),
            (
                Flaws {
                    private_public: true,
                    ..Default::default()
                },
                "opened for somebody who had not",
            ),
            (
                Flaws {
                    broken: true,
                    ..Default::default()
                },
                "did not open",
            ),
        ] {
            let o = run_with(flaws);
            assert!(
                o.findings.is_empty() && o.verified.is_empty(),
                "{says}: {:?} {:?}",
                found(&o),
                credited(&o)
            );
            assert!(
                o.not_assessed.iter().any(|(_, why)| why.contains(says)),
                "{says}: {:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn refusals_are_not_credited_when_an_ordinary_sign_in_stops_working() {
        // The app refuses the first broken token and then refuses everybody: the refusals after
        // that are not the app noticing anything, and the last ordinary sign-in shows it.
        let o = run_with(Flaws {
            breaks_after_a_refusal: true,
            ..Default::default()
        });
        assert!(
            o.verified
                .iter()
                .all(|v| v.check_id == CROSS_SESSION.rule_id),
            "{:?}",
            credited(&o)
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("did not work either")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_app_that_sends_no_nonce_is_not_judged_on_it() {
        let o = run_with(Flaws {
            no_nonce_sent: true,
            ..Default::default()
        });
        assert!(!found(&o).contains(&WRONG_NONCE.rule_id));
        assert!(!credited(&o).contains(&WRONG_NONCE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V10.5.1" && why.contains("no `nonce`")),
            "{:?}",
            o.not_assessed
        );
        // And the provider is not asked for a token nobody could hold it to.
        assert!(
            o.steps
                .iter()
                .any(|s| s.contains("a wrong nonce: not tried")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn one_refused_signature_is_not_credit_when_the_other_could_not_be_tried() {
        // Refusing an unsigned token says nothing about a token signed with the wrong key, so
        // when that sign-in cannot be made through to the end, V6.8.2 is neither passed nor
        // failed.
        let o = run_with(Flaws {
            provider_fails_on: Some("wrong-key"),
            ..Default::default()
        });
        assert!(!credited(&o).contains(&UNCHECKED_SIGNATURE.rule_id));
        assert!(!found(&o).contains(&UNCHECKED_SIGNATURE.rule_id));
        assert!(
            o.not_assessed.iter().any(|(ids, _)| ids == "V6.8.2"),
            "{:?}",
            o.not_assessed
        );
        // The other three are still judged.
        assert_eq!(credited(&o).len(), 3, "{:?}", credited(&o));
    }

    #[test]
    fn addresses_lose_their_host_and_keep_their_query() {
        assert_eq!(path_of("http://idp:9000/authorize?a=1"), "/authorize?a=1");
        assert_eq!(path_of("http://app:8080"), "/");
        assert_eq!(path_of("/callback?code=x"), "/callback?code=x");
    }
}
