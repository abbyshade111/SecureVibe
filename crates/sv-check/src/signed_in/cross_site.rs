//! Another site's Origin on the signed-in pages (ADR-055).
//!
//! `probe.cors-any-origin` (V3.4.2) asks the health path with another site's `Origin`, as somebody not
//! signed in. A page that lets any site read it does harm where it holds the person's data, which is
//! behind sign-in: a JSON API for a phone app, an account page. So the first test user, signed in,
//! asks each `private` page the same question, judged as the health path is. A page that echoes the
//! origin is a finding; nothing is credited here, as the credit from the health path stands and a
//! finding outranks it.

use super::*;

pub(super) fn private_pages(
    http: &mut dyn Http,
    users: &UsersSection,
    a: &SignedIn,
    out: &mut Outcome,
) {
    let mut echoed = Vec::new();
    let mut worst = None;
    for (i, path) in users.private.iter().enumerate() {
        let mut request = get(&format!("cors-private-{i}"), path, &a.session);
        request
            .headers
            .push(("Origin".to_owned(), crate::probes::STRANGER.to_owned()));
        let Some(response) = http.send(&request) else {
            continue;
        };
        if let Some(found) = crate::probes::reflected_origin(&response) {
            echoed.push(path.clone());
            // `Severity` sorts Critical first, so the more severe is the smaller.
            if worst
                .as_ref()
                .is_none_or(|w: &Finding| found.severity < w.severity)
            {
                worst = Some(found);
            }
        }
    }
    if let Some(mut found) = worst {
        found.description = format!(
            "On {}, as a signed-in user: {}",
            echoed.join(", "),
            found.description
        );
        out.findings.push(found);
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::*;

    #[test]
    fn a_signed_in_page_any_site_can_read_is_found_where_the_health_path_question_cannot_see_it() {
        // ADR-055. The account page echoes any Origin with credentials allowed, the health path does
        // not: found, high, naming the page.
        let o = run_against(
            Flaws {
                private_cors_echoes: true,
                ..Default::default()
            },
            &users(),
        );
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == "probe.cors-any-origin")
            .expect("found on the signed-in page");
        assert_eq!(found.severity, Severity::High, "credentials allowed");
        assert!(
            found
                .description
                .starts_with("On /account, as a signed-in user:"),
            "{}",
            found.description
        );
        // The control: an app that echoes nothing is found at fault by nothing here.
        let o = run_against(Flaws::default(), &users());
        assert!(
            !o.findings
                .iter()
                .any(|f| f.rule_id == "probe.cors-any-origin"),
            "{:?}",
            o.findings
        );
    }
}
