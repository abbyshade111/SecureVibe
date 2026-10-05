//! A feature that fetches an address a person gives it: a link preview, an import from a web
//! address. Asked when `[stack.run.fetch]` says how to reach it.
//!
//! The feature is given the address of the test model's own server on the app's private network,
//! which records each request it gets (`/_sv/fetch/<tag>`). That host is one nobody allowed, on a
//! port no service uses, on a network the outside world cannot see: an app that checks where it is
//! told to go has no reason to go there.
//!
//! - **V1.3.6 and V13.2.4.** Fetched is a finding: nothing stopped the server going to an address
//!   on a host and port nobody listed. Not fetched is not assessed and never credit: from outside, a
//!   feature that refused the address cannot be told from one that did not work, since the fence
//!   has no address that should be allowed to use as the control.
//! - **V15.3.2.** Given an address that answers with a redirect (`/_sv/redirect/<tag>`), the first
//!   request reaching the test server is the control; the redirect's target being fetched as well is
//!   the finding, and not being fetched is credited. When the owner says following a redirect is
//!   what the feature is for (`follows-redirects`), this is not asked.

use crate::finding::Severity;
use crate::probes::ProbeRequest;
use crate::signed_in::{
    Account, Http, Outcome, Rule, Session, finding, send_filled, sign_in, status,
};
use sv_manifest::{FetchSection, UsersSection};

const FETCHES_ANYWHERE: Rule = Rule {
    rule_id: "probe.fetch-goes-anywhere",
    requirement_ids: &["V1.3.6", "V13.2.4"],
    cwe: &["CWE-918"],
    impact: "The feature fetches whatever address it is given, including one on the app's own \
             private network that nobody listed. Somebody can use it to make the server reach \
             places only the server can reach: internal services, a cloud provider's metadata \
             address that hands out the server's credentials, or the app's own admin pages.",
    fix: "Before fetching, check the address against a list of what the feature may reach: the \
          scheme (`https` only), the host, and the port. Resolve the host first and refuse private, \
          loopback, and link-local addresses (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, and \
          their IPv6 forms), and check again after any redirect. Libraries such as \
          `ssrf-req-filter` (Node) and `advocate` (Python) do this.",
};

const FOLLOWS_REDIRECT: Rule = Rule {
    rule_id: "probe.fetch-follows-redirect",
    requirement_ids: &["V15.3.2"],
    cwe: &["CWE-918"],
    impact: "Given an address that answers with a redirect, the feature went on to wherever the \
             redirect pointed. A check on the first address is then no check at all: somebody gives \
             an allowed address that redirects to a forbidden one.",
    fix: "Turn redirects off where the feature fetches (`allow_redirects=False` in Python \
          `requests`, `redirect: 'manual'` in `fetch`, `maxRedirects: 0` in axios), or follow \
          them yourself and check each new address as you checked the first.",
};

/// The requirements asked, for a reason that stops all of them.
fn asked(section: &FetchSection) -> &'static str {
    if section.follows_redirects {
        "V1.3.6, V13.2.4"
    } else {
        "V1.3.6, V13.2.4, V15.3.2"
    }
}

/// What the feature needs from the rest of the run.
pub struct Context<'a> {
    /// The users section and the account to sign in as, when the feature needs a signed-in user.
    pub signed_in: Option<(&'a UsersSection, &'a Account)>,
    /// The test server's address as the app reaches it, such as `http://sv-1-model:9100`. Absent
    /// when it could not be started.
    pub canary: Option<&'a str>,
}

/// A value made for this run, so a fetch an earlier run caused cannot stand in for this one.
pub(crate) fn tag(n: u32) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:x}{n:x}", now ^ (u128::from(std::process::id()) << 64))
}

/// Whether the test server was asked for `/_sv/fetch/<tag>`.
pub(crate) fn fetched(http: &mut dyn Http, tag: &str) -> Option<bool> {
    let answer = http.model(&ProbeRequest {
        id: format!("fetched-{tag}"),
        method: "GET".into(),
        path: format!("/_sv/fetched/{tag}"),
        headers: Vec::new(),
        body: None,
    })?;
    let value: serde_json::Value = serde_json::from_str(&answer.body).ok()?;
    value.get("fetched").and_then(serde_json::Value::as_bool)
}

/// The feature's request with `{url}` written in.
fn with_url(section: &FetchSection, url: &str) -> sv_manifest::RequestTemplate {
    let mut t = section.request.clone();
    t.path = t.path.replace("{url}", url);
    for v in t.form.values_mut().chain(t.json.values_mut()) {
        *v = v.replace("{url}", url);
    }
    t
}

pub fn run(http: &mut dyn Http, section: &FetchSection, ctx: &Context) -> Outcome {
    let mut out = Outcome::default();
    let all = asked(section);
    let say = |ids: &str, why: String, out: &mut Outcome| {
        out.not_assessed.push((ids.to_owned(), why));
    };
    let t = &section.request;
    if !(t.path.contains("{url}")
        || t.form
            .values()
            .chain(t.json.values())
            .any(|v| v.contains("{url}")))
    {
        say(
            all,
            format!(
                "[stack.run.fetch] `request` ({}) has no `{{url}}`, so no address could be given \
                 to the feature.",
                t.path
            ),
            &mut out,
        );
        return out;
    }
    let Some(canary) = ctx.canary else {
        say(
            all,
            "Where the feature that fetches addresses will go: the test server that records each \
             fetch could not be started, so nothing could see one."
                .to_owned(),
            &mut out,
        );
        return out;
    };
    let mut session = Session::default();
    let mut pages = Vec::new();
    if section.signed_in {
        let Some((users, account)) = ctx.signed_in else {
            say(
                all,
                "`fetch.signed-in` is set, and there is no `[stack.run.users]` to sign in with."
                    .to_owned(),
                &mut out,
            );
            return out;
        };
        let Some(signed) = sign_in(http, users, "b-fetch", account, &mut out.steps) else {
            say(
                all,
                "The feature that fetches addresses needs a signed-in user, and signing in as the \
                 second test user got no answer."
                    .to_owned(),
                &mut out,
            );
            return out;
        };
        session = signed.session;
        pages = users.private.clone();
    }

    // V1.3.6 and V13.2.4: an address on a host and port nobody listed.
    let first = tag(1);
    let url = format!("{canary}/_sv/fetch/{first}");
    let answer = send_filled(
        http,
        "fetch-unlisted",
        &with_url(section, &url),
        &mut session,
        &pages,
    );
    let went = fetched(http, &first);
    out.steps.push(format!(
        "gave the feature an address on the app's own private network, on a host and port nobody \
         listed ({}): {}",
        status(&answer),
        match went {
            Some(true) => "it fetched it",
            Some(false) => "it did not fetch it",
            None => "the test server could not say",
        }
    ));
    match went {
        Some(true) => out.findings.push(finding(
            &FETCHES_ANYWHERE,
            "A feature fetches addresses nobody allowed",
            Severity::High,
            format!(
                "Given {url}, an address on the app's own private network, on a port no service \
                 uses and a host nobody listed, the feature fetched it."
            ),
        )),
        Some(false) => say(
            "V1.3.6, V13.2.4",
            format!(
                "The feature did not fetch an address on the app's own private network that it was \
                 given ({}). It may check where it goes, which is what these requirements ask, or \
                 it may not have worked: the run has no address that should be allowed to tell \
                 the two apart, so this is not credited.",
                status(&answer)
            ),
            &mut out,
        ),
        None => say(
            all,
            "Where the feature that fetches addresses will go: the test server did not say what it \
             was asked for."
                .to_owned(),
            &mut out,
        ),
    }
    if section.follows_redirects {
        say(
            "V15.3.2",
            "securevibe.toml says following a redirect is what the feature is for, so whether it \
             does was not asked."
                .to_owned(),
            &mut out,
        );
        return out;
    }
    if went != Some(true) {
        say(
            "V15.3.2",
            "Whether the feature follows a redirect: it did not fetch the first address it was \
             given, so whether it would go on from one cannot be seen."
                .to_owned(),
            &mut out,
        );
        return out;
    }

    // V15.3.2: an address that answers with a redirect to another on the same server.
    let second = tag(2);
    let url = format!("{canary}/_sv/redirect/{second}");
    let answer = send_filled(
        http,
        "fetch-redirect",
        &with_url(section, &url),
        &mut session,
        &pages,
    );
    let hop = fetched(http, &second);
    let after = fetched(http, &format!("{second}-after"));
    out.steps.push(format!(
        "gave it an address that answers with a redirect ({}): {}",
        status(&answer),
        match (hop, after) {
            (Some(true), Some(true)) => "it fetched it and followed the redirect",
            (Some(true), Some(false)) => "it fetched it and did not follow the redirect",
            (Some(false), _) => "it did not fetch it",
            _ => "the test server could not say",
        }
    ));
    match (hop, after) {
        (Some(true), Some(true)) => out.findings.push(finding(
            &FOLLOWS_REDIRECT,
            "A feature follows redirects to wherever they point",
            Severity::Medium,
            format!(
                "Given {url}, which answers with a redirect to another address, the feature \
                 fetched the address it was given and then the one the redirect named."
            ),
        )),
        (Some(true), Some(false)) => out.verified.push(crate::Verified::new(
            FOLLOWS_REDIRECT.rule_id,
            FOLLOWS_REDIRECT.requirement_ids,
            "given an address that answered with a redirect, the feature fetched that address and \
             did not go on to the one the redirect named; one feature, one redirect"
                .to_owned(),
        )),
        _ => say(
            "V15.3.2",
            "Whether the feature follows a redirect: it did not fetch the redirecting address, or \
             the test server could not say, so nothing was seen either way."
                .to_owned(),
            &mut out,
        ),
    }
    out
}

/// What a fake test server and app answer, for the tests: the app fetches as its flaws say, and the
/// server records each fetch, as `assets/model-provider.mjs` does.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::ProbeResponse;
    use std::collections::BTreeSet;

    #[derive(Default, Clone, Copy)]
    struct Flaws {
        /// Fetches any address it is given.
        fetches_anything: bool,
        /// Follows redirects.
        follows: bool,
        /// Fails whatever it is given, fetching nothing.
        broken: bool,
        /// Needs a signed-in user.
        needs_sign_in: bool,
    }

    #[derive(Default)]
    struct FakeApp {
        flaws: Flaws,
        fetched: BTreeSet<String>,
        signed_in: bool,
    }

    const CANARY: &str = "http://sv-1-model:9100";

    impl Http for FakeApp {
        fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            let reply = |status: u16, body: &str| {
                Some(ProbeResponse {
                    id: r.id.clone(),
                    status,
                    headers: Vec::new(),
                    body: body.to_owned(),
                })
            };
            if r.path == "/login" {
                self.signed_in = true;
                return reply(200, "welcome");
            }
            if r.path != "/preview" {
                return reply(200, "<html>page</html>");
            }
            if self.flaws.needs_sign_in && !self.signed_in {
                return reply(401, "sign in");
            }
            if self.flaws.broken {
                return reply(500, "error");
            }
            let text = r.body_text();
            let url = text
                .split('&')
                .find_map(|kv| kv.strip_prefix("url="))
                .map(|v| v.replace("%3A", ":").replace("%2F", "/"))
                .unwrap_or_default();
            let Some(path) = url.strip_prefix(CANARY) else {
                return reply(400, "bad address");
            };
            if !self.flaws.fetches_anything {
                return reply(400, "that address is not allowed");
            }
            if let Some(tag) = path.strip_prefix("/_sv/fetch/") {
                self.fetched.insert(tag.to_owned());
            } else if let Some(tag) = path.strip_prefix("/_sv/redirect/") {
                // The redirect itself is recorded under its own tag, as the test server does.
                self.fetched.insert(tag.to_owned());
                if self.flaws.follows {
                    self.fetched.insert(format!("{tag}-after"));
                }
            }
            reply(200, "Preview: a page")
        }

        fn model(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
            let tag = r.path.strip_prefix("/_sv/fetched/")?;
            Some(ProbeResponse {
                id: r.id.clone(),
                status: 200,
                headers: Vec::new(),
                body: serde_json::json!({"fetched": self.fetched.contains(tag)}).to_string(),
            })
        }
    }

    fn section() -> FetchSection {
        FetchSection {
            request: sv_manifest::RequestTemplate {
                method: "POST".into(),
                path: "/preview".into(),
                form: [("url".to_owned(), "{url}".to_owned())].into(),
                json: Default::default(),
            },
            signed_in: false,
            follows_redirects: false,
        }
    }

    fn ask(flaws: Flaws, section: &FetchSection) -> (Outcome, FakeApp) {
        let mut app = FakeApp {
            flaws,
            ..Default::default()
        };
        let ctx = Context {
            signed_in: None,
            canary: Some(CANARY),
        };
        let out = run(&mut app, section, &ctx);
        (out, app)
    }

    fn found(o: &Outcome) -> Vec<&str> {
        o.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn credited(o: &Outcome) -> Vec<&str> {
        o.verified.iter().map(|v| v.check_id.as_str()).collect()
    }

    fn why<'o>(o: &'o Outcome, id: &str) -> Vec<&'o str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids.split(", ").any(|i| i == id))
            .map(|(_, w)| w.as_str())
            .collect()
    }

    #[test]
    fn a_feature_that_fetches_anything_and_follows_redirects_is_found_for_both() {
        let (o, app) = ask(
            Flaws {
                fetches_anything: true,
                follows: true,
                ..Default::default()
            },
            &section(),
        );
        assert_eq!(
            found(&o),
            [FETCHES_ANYWHERE.rule_id, FOLLOWS_REDIRECT.rule_id],
            "{:?}",
            o.steps
        );
        let f = o
            .findings
            .iter()
            .find(|f| f.rule_id == FETCHES_ANYWHERE.rule_id)
            .unwrap();
        assert_eq!(f.requirement_ids, ["V1.3.6", "V13.2.4"]);
        assert!(credited(&o).is_empty());
        // The setup: both addresses were really fetched, and the redirect's target too.
        assert_eq!(app.fetched.len(), 3, "{:?}", app.fetched);
    }

    #[test]
    fn a_feature_that_does_not_follow_a_redirect_is_credited_for_that_alone() {
        let (o, _) = ask(
            Flaws {
                fetches_anything: true,
                ..Default::default()
            },
            &section(),
        );
        assert_eq!(found(&o), [FETCHES_ANYWHERE.rule_id], "{:?}", o.steps);
        assert_eq!(credited(&o), [FOLLOWS_REDIRECT.rule_id]);
    }

    #[test]
    fn a_feature_that_fetches_nothing_settles_nothing_and_is_never_credited() {
        for flaws in [
            Flaws::default(),
            Flaws {
                broken: true,
                fetches_anything: true,
                ..Default::default()
            },
        ] {
            let (o, app) = ask(flaws, &section());
            assert!(
                found(&o).is_empty() && credited(&o).is_empty(),
                "{:?}",
                o.steps
            );
            assert!(app.fetched.is_empty());
            assert!(why(&o, "V1.3.6").iter().any(|w| w.contains("not credited")));
            assert!(
                why(&o, "V15.3.2")
                    .iter()
                    .any(|w| w.contains("did not fetch the first"))
            );
        }
    }

    #[test]
    fn redirects_the_owner_wants_followed_are_not_asked_about() {
        let mut s = section();
        s.follows_redirects = true;
        let (o, app) = ask(
            Flaws {
                fetches_anything: true,
                follows: true,
                ..Default::default()
            },
            &s,
        );
        assert_eq!(found(&o), [FETCHES_ANYWHERE.rule_id]);
        assert!(
            why(&o, "V15.3.2")
                .iter()
                .any(|w| w.contains("what the feature is for"))
        );
        assert!(
            !app.fetched.iter().any(|t| t.ends_with("-after")),
            "no redirect was sent"
        );
    }

    #[test]
    fn each_run_gives_addresses_of_its_own() {
        let (_, one) = ask(
            Flaws {
                fetches_anything: true,
                ..Default::default()
            },
            &section(),
        );
        let (_, two) = ask(
            Flaws {
                fetches_anything: true,
                ..Default::default()
            },
            &section(),
        );
        assert!(
            one.fetched.is_disjoint(&two.fetched),
            "{:?} {:?}",
            one.fetched,
            two.fetched
        );
    }

    #[test]
    fn what_cannot_be_asked_is_said() {
        let mut s = section();
        s.request.form = [("url".to_owned(), "https://example.test".to_owned())].into();
        let (o, _) = ask(Flaws::default(), &s);
        assert!(why(&o, "V1.3.6").iter().any(|w| w.contains("no `{url}`")));
        let mut app = FakeApp::default();
        let o = run(
            &mut app,
            &section(),
            &Context {
                signed_in: None,
                canary: None,
            },
        );
        assert!(
            why(&o, "V15.3.2")
                .iter()
                .any(|w| w.contains("could not be started"))
        );
        let mut s = section();
        s.signed_in = true;
        let (o, _) = ask(
            Flaws {
                needs_sign_in: true,
                ..Default::default()
            },
            &s,
        );
        assert!(
            why(&o, "V1.3.6")
                .iter()
                .any(|w| w.contains("no `[stack.run.users]`"))
        );
    }
}
