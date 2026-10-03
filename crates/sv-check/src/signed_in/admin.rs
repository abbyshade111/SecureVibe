use super::*;

pub(super) fn admin_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    a: &SignedIn,
    out: &mut Outcome,
) {
    if users.admin.is_empty() {
        out.not_assessed.push((
            "V8.2.1".to_owned(),
            "Admin pages: securevibe.toml lists none under [stack.run.users] admin.".to_owned(),
        ));
        return;
    }
    let admin = accounts
        .admin
        .as_ref()
        .and_then(|account| sign_in(http, users, "admin", account, &mut out.steps));
    let mut refused_and_confirmed = 0;
    let mut opened_by_ordinary = Vec::new();
    let mut unconfirmed = Vec::new();
    for path in &users.admin {
        let as_a = http.send(&get("admin-a", path, &a.session));
        let as_admin = admin
            .as_ref()
            .map(|admin| http.send(&get("admin-admin", path, &admin.session)));
        let admin_opens = as_admin.as_ref().is_some_and(ok);
        if ok(&as_a) {
            // A 2xx to an ordinary user is a finding whether or not the admin was confirmed.
            opened_by_ordinary.push(path.clone());
        } else if admin_opens {
            refused_and_confirmed += 1;
        } else {
            unconfirmed.push(path.clone());
        }
    }
    if !opened_by_ordinary.is_empty() {
        out.findings.push(finding(
            &ADMIN_PAGE,
            "An ordinary user can open an admin page",
            Severity::High,
            format!(
                "Signed in as an ordinary test user, the app served {}.",
                opened_by_ordinary.join(", ")
            ),
        ));
    }
    if !unconfirmed.is_empty() {
        out.not_assessed.push((
            "V8.2.1".to_owned(),
            format!(
                "The admin account did not open {} either, so the ordinary user being refused says \
                 nothing: the page may not be where securevibe.toml says.",
                unconfirmed.join(", ")
            ),
        ));
    }
    if refused_and_confirmed > 0 && opened_by_ordinary.is_empty() {
        out.verified.push(crate::Verified::new(
            ADMIN_PAGE.rule_id,
            ADMIN_PAGE.requirement_ids,
            format!(
                "{refused_and_confirmed} admin page{}, refused to an ordinary user and opened by the admin",
                if refused_and_confirmed == 1 { "" } else { "s" }
            ),
        ));
    }
}

/// Fields a sign-up request might carry to make its account an admin. Values are sent as text,
/// in a form and in JSON alike, because a template's values are text; most frameworks read `"true"`
/// as true.
const ROLE_FIELDS: &[(&str, &str)] = &[
    ("role", "admin"),
    ("roles", "admin"),
    ("is_admin", "true"),
    ("isAdmin", "true"),
    ("admin", "true"),
];

/// Signs in and shows the session signed in by opening `confirm`, or says it could not.
fn signed_in_session(
    http: &mut dyn Http,
    users: &UsersSection,
    who: &str,
    account: &Account,
    confirm: &str,
    steps: &mut Vec<String>,
) -> Option<SignedIn> {
    let signed = sign_in(http, users, who, account, steps)?;
    ok(&http.send(&get(&format!("private-{who}"), confirm, &signed.session))).then_some(signed)
}

/// A sign-up with a role written into it (V8.3.1, V15.3.3).
///
/// Two accounts are made through the app's own sign-up: one plain, and one whose request also
/// carries `role=admin`, `is_admin=true` and the like. Both are shown signed in first, then each asks
/// for the admin pages. A page that opens to the second and not to the first opened because of a
/// field the browser sent, which is the decision V8.3.1 says must not rest on the client. A page the
/// plain account opens too is the admin-page check's finding, not this one's.
pub(super) fn role_field_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V8.3.1, V15.3.3";
    let (Some(signup), false) = (&users.signup, users.admin.is_empty()) else {
        out.not_assessed.push((
            IDS.to_owned(),
            "A role written into the sign-up form: this needs both `signup` and an `admin` page \
             under [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "A role written into the sign-up form: no private page was shown open to a signed-in \
             user, so a sign-in here could not be confirmed."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let plain = Account {
        user: format!("plain.{}", accounts.a.user),
        password: format!("Pl-{}-aZ9!", &spare[2..26]),
    };
    let claimed = Account {
        user: format!("role.{}", accounts.a.user),
        password: format!("Ro-{}-aZ9!", &spare[6..30]),
    };
    let mut with_role = signup.clone();
    let fields = if with_role.json.is_empty() {
        &mut with_role.form
    } else {
        &mut with_role.json
    };
    for (name, value) in ROLE_FIELDS {
        fields
            .entry((*name).to_owned())
            .or_insert_with(|| (*value).to_owned());
    }
    sign_up(http, users, signup, "role-plain", &plain);
    sign_up(http, users, &with_role, "role-claimed", &claimed);

    let plain_in = signed_in_session(http, users, "role-plain", &plain, confirm, &mut out.steps);
    let claimed_in = signed_in_session(
        http,
        users,
        "role-claimed",
        &claimed,
        confirm,
        &mut out.steps,
    );
    let (Some(plain_in), Some(claimed_in)) = (plain_in, claimed_in) else {
        out.not_assessed.push((
            IDS.to_owned(),
            "A role written into the sign-up form: the two accounts made for it could not both be \
             shown signed in. With the extra fields that may be the app refusing fields it does not \
             expect, which is what V15.3.3 asks for, but nothing here showed it."
                .to_owned(),
        ));
        return;
    };

    let mut opened = Vec::new();
    let mut compared = 0usize;
    for (i, page) in users.admin.iter().enumerate() {
        let as_plain = http.send(&get(
            &format!("role-admin-{i}-plain"),
            page,
            &plain_in.session,
        ));
        if ok(&as_plain) {
            // Open to anybody signed in: the admin-page check says so, and the role field is not
            // what opened it.
            continue;
        }
        compared += 1;
        let as_claimed = http.send(&get(
            &format!("role-admin-{i}-claimed"),
            page,
            &claimed_in.session,
        ));
        if ok(&as_claimed) {
            opened.push(page.clone());
        }
    }
    if !opened.is_empty() {
        out.findings.push(finding(
            &ROLE_FIELD,
            "A new account can make itself an admin at sign-up",
            Severity::Critical,
            format!(
                "An account signed up with {} added to the form opened {}, which the same sign-up \
                 without them did not.",
                ROLE_FIELDS
                    .iter()
                    .map(|(k, v)| format!("`{k}={v}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
                opened.join(", ")
            ),
        ));
    } else if compared > 0 {
        // Only ever a finding: five guessed names refused say nothing about a sixth, so the check is
        // recorded as having run and credits no requirement.
        out.verified.push(crate::Verified::new(
            ROLE_FIELD.rule_id,
            &[],
            format!(
                "an account signed up with {} role field{} added was refused {compared} admin \
                 page{}, as a plain one was; other field names were not tried",
                ROLE_FIELDS.len(),
                if ROLE_FIELDS.len() == 1 { "" } else { "s" },
                if compared == 1 { "" } else { "s" }
            ),
        ));
    }
}

/// Admin actions, sent straight to the app by the first ordinary user and then by the admin.
///
/// The admin-page check asks for pages; this sends the requests an admin makes, which is where an
/// app that only hides its buttons gives itself away. Each request carries a marker of its own, and
/// the `check` page, read by the admin, says whose request took effect. A refusal counts only when
/// the admin's own request then did, because a refusal the admin shares says the request was wrong,
/// not that the rule was enforced. The ordinary user goes first, so the admin's success cannot be
/// what the ordinary user's request ran into.
///
/// Without `check`, a refusal cannot be told from a request that did nothing, so nothing is credited
/// and only a 2xx to the ordinary user is reported, at medium confidence.
pub(super) fn admin_action_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    if users.admin_actions.is_empty() {
        out.not_assessed.push((
            "V8.3.1".to_owned(),
            "Admin actions: securevibe.toml lists none under [stack.run.users] admin-actions, so no \
             request only an admin should make was sent by an ordinary user."
                .to_owned(),
        ));
        return;
    }
    let Some(admin_account) = accounts.admin.as_ref() else {
        out.not_assessed.push((
            "V8.3.1".to_owned(),
            "Admin actions: there is no admin account to confirm them with; an admin is made by `seed`."
                .to_owned(),
        ));
        return;
    };
    let a = sign_in(http, users, "a-actions", &accounts.a, &mut out.steps);
    let admin = sign_in(http, users, "admin-actions", admin_account, &mut out.steps);
    // Both sessions have to be shown signed in before anything they are refused means anything: a
    // request refused because nobody was signed in looks, from here, exactly like one refused
    // because the user was not an admin. Found building this: a sign-in that quietly failed made a
    // correct app's refusal, and an open app's, read the same.
    let signed_in = |http: &mut dyn Http, who: &SignedIn, id: &str| {
        confirm.is_some_and(|page| ok(&http.send(&get(id, page, &who.session))))
    };
    let (Some(mut a), Some(mut admin)) = (a, admin) else {
        out.not_assessed.push((
            "V8.3.1".to_owned(),
            "Admin actions: the first user and the admin could not both sign in, so none was sent."
                .to_owned(),
        ));
        return;
    };
    if !signed_in(http, &a, "admin-actions-a-confirm")
        || !signed_in(http, &admin, "admin-actions-admin-confirm")
    {
        out.not_assessed.push((
            "V8.3.1".to_owned(),
            "Admin actions: the first user and the admin could not both be shown signed in (a \
             private page did not open for each), so a refusal would say nothing and none was sent."
                .to_owned(),
        ));
        return;
    }

    // Pages an anti-forgery token may come from: the ordinary user's own, then the admin's.
    let a_pages: Vec<String> = users.private.clone();
    let admin_pages: Vec<String> = users.admin.iter().chain(&users.private).cloned().collect();
    let tag = accounts.spare.get(..8).unwrap_or("0");

    let mut refused = 0usize;
    let mut done_by_ordinary = Vec::new();
    let mut answered_ordinary = Vec::new();
    let mut unconfirmed = Vec::new();
    let mut unjudged = Vec::new();
    for (i, action) in users.admin_actions.iter().enumerate() {
        let request = action.request();
        let a_marker = format!("sv-admin-action-{tag}-{i}-a");
        let admin_marker = format!("sv-admin-action-{tag}-{i}-admin");
        let as_a = send_template(
            http,
            &format!("admin-action-{i}-a"),
            &request,
            &Values {
                marker: &a_marker,
                ..Values::default()
            },
            &mut a.session,
            &a_pages,
        )
        .0;
        let Some(check) = &action.check else {
            if ok(&as_a) {
                answered_ordinary.push(format!(
                    "{} {} (answered {})",
                    request.method,
                    request.path,
                    as_a.as_ref().map_or(0, |r| r.status)
                ));
            } else {
                unjudged.push(format!("{} {}", request.method, request.path));
            }
            continue;
        };
        // Whether the check page, read by the admin, shows this marker. `None` when the page could
        // not be read at all, which settles nothing.
        fn shows(
            http: &mut dyn Http,
            check: &str,
            marker: &str,
            id: String,
            session: &Session,
        ) -> Option<bool> {
            http.send(&get(&id, check, session))
                .filter(|page| (200..300).contains(&page.status))
                .map(|page| page.body.contains(marker))
        }
        match shows(
            http,
            check,
            &a_marker,
            format!("admin-action-{i}-check-a"),
            &admin.session,
        ) {
            Some(true) => {
                done_by_ordinary.push(format!("{} {}", request.method, request.path));
                continue;
            }
            None => {
                unconfirmed.push(format!(
                    "{} {} (the admin could not read {check})",
                    request.method, request.path
                ));
                continue;
            }
            Some(false) => {}
        }
        send_template(
            http,
            &format!("admin-action-{i}-admin"),
            &request,
            &Values {
                marker: &admin_marker,
                ..Values::default()
            },
            &mut admin.session,
            &admin_pages,
        );
        if shows(
            http,
            check,
            &admin_marker,
            format!("admin-action-{i}-check-admin"),
            &admin.session,
        ) == Some(true)
        {
            refused += 1;
        } else {
            unconfirmed.push(format!(
                "{} {} (the admin's own request did not show on {check} either)",
                request.method, request.path
            ));
        }
    }

    if !done_by_ordinary.is_empty() {
        out.findings.push(finding(
            &ADMIN_ACTION,
            "An ordinary user can do what only an admin should",
            Severity::High,
            format!(
                "Signed in as an ordinary test user and sending the request directly, the app carried \
                 out {}: the page named to show it had the ordinary user's marker on it.",
                done_by_ordinary.join(", ")
            ),
        ));
    }
    if !answered_ordinary.is_empty() {
        let mut f = finding(
            &ADMIN_ACTION,
            "An ordinary user's admin request was answered as if it worked",
            Severity::High,
            format!(
                "Signed in as an ordinary test user, the app answered {} with a success status. \
                 This is judged by the status alone, and some apps answer a refused request that \
                 way; a `check` page for the action in securevibe.toml would show whether it took \
                 effect.",
                answered_ordinary.join(", ")
            ),
        );
        f.confidence = Confidence::Medium;
        out.findings.push(f);
    }
    if !unconfirmed.is_empty() {
        out.not_assessed.push((
            "V8.3.1".to_owned(),
            format!(
                "Admin actions whose refusal says nothing, because the admin could not be shown to \
                 do them either: {}.",
                unconfirmed.join("; ")
            ),
        ));
    }
    if !unjudged.is_empty() {
        out.not_assessed.push((
            "V8.3.1".to_owned(),
            format!(
                "Admin actions refused to an ordinary user with no `check` page to show the admin's \
                 would have worked, so the refusal cannot be told from a request that did nothing: {}.",
                unjudged.join(", ")
            ),
        ));
    }
    if refused > 0 && done_by_ordinary.is_empty() && answered_ordinary.is_empty() {
        out.verified.push(crate::Verified::new(
            ADMIN_ACTION.rule_id,
            ADMIN_ACTION.requirement_ids,
            format!(
                "{refused} admin action{}, sent straight to the app: refused to an ordinary user and \
                 carried out for the admin, as the page named to show each said",
                if refused == 1 { "" } else { "s" }
            ),
        ));
    }
}

/// Returns the path of A's record when A could read it, for the logout check to reuse.
pub(super) fn owned_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    a: &SignedIn,
    out: &mut Outcome,
) -> Option<String> {
    let Some(owned) = &users.owned else {
        out.not_assessed.push((
            "V8.2.2, V3.5.1".to_owned(),
            "Another user's records, and requests from another site: securevibe.toml lists no \
             `owned` record under [stack.run.users]."
                .to_owned(),
        ));
        return None;
    };
    let marker = "sv-probe-private-4c7e";
    let mut session = a.session.clone();
    let values = Values {
        marker,
        ..Default::default()
    };
    let (created, _) = send_template(
        http,
        "owned-create",
        &owned.create,
        &values,
        &mut session,
        &users.private,
    );
    let read_path = created.as_ref().and_then(|r| record_path(owned, r));
    let Some(read_path) = read_path.filter(|_| accepted(&created)) else {
        out.not_assessed.push((
            "V8.2.2, V3.5.1".to_owned(),
            format!(
                "Creating a record as the first user did not work ({}), or did not say where it \
                 went, so there is nothing to ask another user to read.",
                status(&created)
            ),
        ));
        return None;
    };
    let holds_marker =
        |r: &Option<ProbeResponse>| ok(r) && r.as_ref().is_some_and(|r| r.body.contains(marker));
    let as_a = http.send(&get("owned-a", &read_path, &session));
    if !holds_marker(&as_a) {
        out.not_assessed.push((
            "V8.2.2, V3.5.1".to_owned(),
            format!(
                "The first user could not read back the record they created at {read_path} ({}), \
                 so another user being refused it would prove nothing.",
                status(&as_a)
            ),
        ));
        return None;
    }
    out.steps.push(format!(
        "A created a record at {read_path} and read it back"
    ));
    // The record the owner is entitled to read is exactly the place to look for fields nobody
    // should be handed at all (V15.3.1). Read from the response already in hand.
    if let Some(body) = as_a.as_ref().map(|r| r.body.as_str()) {
        record_fields_check(body, &read_path, out);
    }

    let b = sign_in(http, users, "b", &accounts.b, &mut out.steps);
    let as_b = b
        .as_ref()
        .map(|b| http.send(&get("owned-b", &read_path, &b.session)));
    let as_nobody = http.send(&get("owned-anonymous", &read_path, &Session::default()));
    let mut leaked_to = Vec::new();
    if as_b.as_ref().is_some_and(holds_marker) {
        leaked_to.push("another signed-in user");
    }
    if holds_marker(&as_nobody) {
        leaked_to.push("somebody not signed in");
    }
    if !leaked_to.is_empty() {
        out.findings.push(finding(
            &OTHER_USERS_DATA,
            "One user can read another user's records",
            Severity::Critical,
            format!(
                "A record the first test user created at {read_path} was served, with its contents, \
                 to {}.",
                leaked_to.join(" and to ")
            ),
        ));
    } else if b.is_some() {
        out.verified.push(crate::Verified::new(
            OTHER_USERS_DATA.rule_id,
            OTHER_USERS_DATA.requirement_ids,
            format!(
                "a record one test user created at {read_path}, refused to a second test user and to \
                 somebody not signed in, and read back by its owner"
            ),
        ));
    } else {
        out.not_assessed.push((
            "V8.2.2".to_owned(),
            "The second test user could not sign in, so whether they can read the first user's \
             record is unknown."
                .to_owned(),
        ));
    }

    forgery_check(http, owned, &session, a, out);
    simple_request_check(http, owned, &session, a, out);
    null_origin_check(http, owned, &users.private, a, out);
    Some(read_path)
}

/// Where a created record can be read: the `read` path with its id, or the `Location` it was sent to.
fn record_path(owned: &sv_manifest::OwnedSection, created: &ProbeResponse) -> Option<String> {
    let location = created
        .header("location")
        .map(|l| strip_origin(l).to_owned());
    match &owned.read {
        Some(read) if read.contains("{id}") => {
            let id = record_id(owned, created)?;
            Some(read.replace("{id}", &id))
        }
        Some(read) => Some(read.clone()),
        None => location,
    }
}

/// The id the app gave a record it created: the `id-field` of a JSON answer, or else the last part
/// of where it sent the browser (`/notes/7` gives 7).
pub(super) fn record_id(
    owned: &sv_manifest::OwnedSection,
    created: &ProbeResponse,
) -> Option<String> {
    let field = owned.id_field.as_deref().unwrap_or("id");
    let from_json = serde_json::from_str::<serde_json::Value>(&created.body)
        .ok()
        .and_then(|v| match v.get(field)? {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        });
    let from_location = created
        .header("location")
        .map(|l| strip_origin(l).to_owned())
        .and_then(|l| {
            l.trim_end_matches('/')
                .rsplit('/')
                .next()
                .map(str::to_owned)
        });
    from_json.or(from_location)
}

fn strip_origin(location: &str) -> &str {
    match location.find("://") {
        Some(i) => {
            let rest = &location[i + 3..];
            rest.find('/').map_or("/", |j| &rest[j..])
        }
        None => location,
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::with_signup;
    use super::*;

    #[test]
    fn the_admin_page_speaks_to_server_side_authorization_both_ways() {
        // Refused: evidence about V8.3.1, which the report shows as supporting only, because the
        // requirement is on `manualOnly`. Opened: a finding against it.
        let refused = run_against(Flaws::default(), &users());
        let evidence = refused
            .verified
            .iter()
            .find(|v| v.check_id == ADMIN_PAGE.rule_id)
            .expect("a correct app's admin page is refused and the admin's opens");
        assert!(
            evidence.requirement_ids.iter().any(|r| r == "V8.3.1"),
            "{evidence:?}"
        );
        let opened = run_against(
            Flaws {
                admin_open: true,
                ..Default::default()
            },
            &users(),
        );
        let finding = opened
            .findings
            .iter()
            .find(|f| f.rule_id == ADMIN_PAGE.rule_id)
            .expect("an admin page an ordinary user opens is a finding");
        assert!(
            finding.requirement_ids.iter().any(|r| r == "V8.3.1"),
            "{finding:?}"
        );
    }

    fn without_check(mut u: UsersSection) -> UsersSection {
        for action in &mut u.admin_actions {
            action.check = None;
        }
        u
    }

    fn action_findings(o: &Outcome) -> Vec<&Finding> {
        o.findings
            .iter()
            .filter(|f| f.rule_id == ADMIN_ACTION.rule_id)
            .collect()
    }

    fn action_credited(o: &Outcome) -> bool {
        o.verified
            .iter()
            .any(|v| v.check_id == ADMIN_ACTION.rule_id)
    }

    #[test]
    fn an_admin_action_refused_to_an_ordinary_user_supports_v8_3_1() {
        // The correct app: the ordinary user's announcement is refused and the admin's is posted,
        // and the page named to show them says which. Supporting evidence, as the page check is.
        let o = run_against(Flaws::default(), &users());
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == ADMIN_ACTION.rule_id)
            .unwrap_or_else(|| panic!("no credit: {:#?}", o.not_assessed));
        assert!(credit.requirement_ids.iter().any(|r| r == "V8.3.1"));
        assert!(credit.scope.contains("1 admin action,"), "{}", credit.scope);
        assert!(action_findings(&o).is_empty());
    }

    #[test]
    fn an_admin_action_an_ordinary_user_gets_done_is_a_finding() {
        let o = run_against(
            Flaws {
                admin_action_open: true,
                ..Default::default()
            },
            &users(),
        );
        let found = action_findings(&o);
        assert_eq!(found.len(), 1, "{:#?}", o.findings);
        assert_eq!(found[0].confidence, Confidence::High);
        assert!(found[0].requirement_ids.iter().any(|r| r == "V8.3.1"));
        assert!(found[0].description.contains("/admin/announce"));
        assert!(!action_credited(&o));
    }

    #[test]
    fn a_refusal_answered_200_is_judged_by_its_effect_when_there_is_a_check() {
        // With the check page, the misleading 200 fools nothing: the marker is not there, the
        // admin's is, and the refusal is credited.
        let flaws = Flaws {
            admin_action_says_ok: true,
            ..Default::default()
        };
        let checked = run_against(flaws, &users());
        assert!(
            action_findings(&checked).is_empty(),
            "{:#?}",
            checked.findings
        );
        assert!(action_credited(&checked));

        // Without it, the status is all there is: a finding, at medium confidence, saying so, and
        // no credit.
        let status_only = run_against(flaws, &without_check(users()));
        let found = action_findings(&status_only);
        assert_eq!(found.len(), 1, "{:#?}", status_only.findings);
        assert_eq!(found[0].confidence, Confidence::Medium);
        assert!(found[0].description.contains("status alone"));
        assert!(!action_credited(&status_only));
    }

    #[test]
    fn a_refusal_the_admin_shares_says_nothing() {
        let o = run_against(
            Flaws {
                admin_action_broken: true,
                ..Default::default()
            },
            &users(),
        );
        assert!(action_findings(&o).is_empty());
        assert!(!action_credited(&o));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V8.3.1" && why.contains("admin's own request")),
            "{:#?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_refusal_to_somebody_not_signed_in_is_not_credited() {
        // Found building this. Sign-in reports what it sent, not whether it worked, and a request
        // from somebody who is not signed in is refused just as an ordinary user's should be. So the
        // probe first shows both sessions signed in, and here A's password is wrong in the app.
        fn outcome(a_password_works: bool) -> Outcome {
            let mut app = FakeApp::new(Flaws::default());
            let acc = accounts();
            let password = if a_password_works {
                acc.a.password.clone()
            } else {
                "not-the-password".to_owned()
            };
            app.users.insert(acc.a.user.clone(), (password, false));
            let admin = acc.admin.clone().unwrap();
            app.users.insert(admin.user, (admin.password, true));
            let mut out = Outcome::default();
            admin_action_checks(&mut app, &users(), &acc, Some("/account"), &mut out);
            out
        }
        // The control: the same call with A's password right is credited, so the setup works.
        assert!(action_credited(&outcome(true)));
        let o = outcome(false);
        assert!(!action_credited(&o), "{:#?}", o.verified);
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V8.3.1" && why.contains("shown signed in")),
            "{:#?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_refusal_with_no_check_page_is_not_credited() {
        let o = run_against(Flaws::default(), &without_check(users()));
        assert!(action_findings(&o).is_empty());
        assert!(!action_credited(&o));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V8.3.1" && why.contains("no `check` page")),
            "{:#?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_leak_says_who_it_leaked_to_and_no_more() {
        // A record open to everybody is a worse leak than one open to other users, and the finding
        // has to say which, or the fix looks smaller than it is.
        let open = run_against(
            Flaws {
                records_public: true,
                ..Default::default()
            },
            &users(),
        );
        let leak = open
            .findings
            .iter()
            .find(|f| f.rule_id == OTHER_USERS_DATA.rule_id)
            .expect("the leak is found");
        assert!(
            leak.description.contains("somebody not signed in"),
            "{}",
            leak.description
        );

        let signed_in_only = run_against(
            Flaws {
                idor: true,
                ..Default::default()
            },
            &users(),
        );
        let leak = signed_in_only
            .findings
            .iter()
            .find(|f| f.rule_id == OTHER_USERS_DATA.rule_id)
            .expect("the leak is found");
        assert!(
            !leak.description.contains("not signed in"),
            "it did not leak to anonymous visitors: {}",
            leak.description
        );
    }

    #[test]
    fn a_record_without_the_marker_cannot_be_recognized_so_is_not_assessed() {
        // Second shape of the read-back check: the owner reads the record, but nothing in it says
        // it is the one created, so another user reading "a record" would prove nothing.
        let mut u = users();
        u.owned
            .as_mut()
            .unwrap()
            .create
            .form
            .insert("text".into(), "no marker here".into());
        let o = run_against(
            Flaws {
                idor: true,
                ..Default::default()
            },
            &u,
        );
        assert!(
            !rule_ids(&o).contains(&OTHER_USERS_DATA.rule_id),
            "{:?}",
            rule_ids(&o)
        );
        assert!(!verified_ids(&o).contains(&OTHER_USERS_DATA.rule_id));
    }

    #[test]
    fn an_owner_who_cannot_read_their_own_record_makes_the_other_user_check_not_assessed() {
        // B being refused A's record proves nothing if A was refused it too.
        let mut u = users();
        u.owned.as_mut().unwrap().read = Some("/notes/999".into());
        let o = run_against(
            Flaws {
                idor: true,
                ..Default::default()
            },
            &u,
        );
        assert!(!rule_ids(&o).contains(&OTHER_USERS_DATA.rule_id));
        assert!(!verified_ids(&o).contains(&OTHER_USERS_DATA.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V8.2.2") && why.contains("could not read back")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_admin_page_the_admin_cannot_open_either_is_not_assessed() {
        let mut u = users();
        u.admin = vec!["/not-the-admin-page".into()];
        let o = run_against(Flaws::default(), &u);
        assert!(!verified_ids(&o).contains(&ADMIN_PAGE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("/not-the-admin-page")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_created_record_is_found_from_a_location_or_a_json_id() {
        let created = |headers: Vec<(&str, &str)>, body: &str| ProbeResponse {
            id: String::new(),
            status: 201,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            body: body.into(),
        };
        let owned = |read: Option<&str>| sv_manifest::OwnedSection {
            create: RequestTemplate::default(),
            read: read.map(str::to_owned),
            id_field: None,
        };
        assert_eq!(
            record_path(
                &owned(None),
                &created(vec![("location", "http://app:8080/notes/7")], "")
            )
            .as_deref(),
            Some("/notes/7")
        );
        assert_eq!(
            record_path(
                &owned(Some("/api/notes/{id}")),
                &created(vec![], "{\"id\": 42}")
            )
            .as_deref(),
            Some("/api/notes/42")
        );
        assert_eq!(record_path(&owned(None), &created(vec![], "{}")), None);
    }

    /// Seed for A, B and the admin; sign-up for the accounts the role-field check makes.
    fn with_role_signup() -> UsersSection {
        let mut u = with_signup();
        u.seed = Some("seed".into());
        u.admin = vec!["/admin".into()];
        u
    }

    #[test]
    fn field_level_access_is_found_from_both_sides_in_a_full_run() {
        // Writing a field the user has no permission to (the role on sign-up)...
        let wrote = run_against(
            Flaws {
                signup_trusts_role: true,
                ..Default::default()
            },
            &with_role_signup(),
        );
        // ...and reading one (a record handed back with its password hash).
        let read = run_against(
            Flaws {
                record_leaks_fields: true,
                ..Default::default()
            },
            &users(),
        );
        for (o, rule) in [
            (&wrote, ROLE_FIELD.rule_id),
            (&read, RECORD_LEAKS_FIELDS.rule_id),
        ] {
            let f = o
                .findings
                .iter()
                .find(|f| f.rule_id == rule)
                .unwrap_or_else(|| panic!("{rule} was not found: {:?}", rule_ids(o)));
            assert!(f.requirement_ids.iter().any(|q| q == "V8.2.3"), "{f:?}");
        }
        // The control: a correct app carries V8.2.3 in nothing it credits.
        let correct = run_against(Flaws::default(), &with_role_signup());
        assert!(
            !correct
                .verified
                .iter()
                .any(|v| v.requirement_ids.iter().any(|q| q == "V8.2.3"))
        );
    }

    fn role_findings(o: &Outcome) -> Vec<&Finding> {
        o.findings
            .iter()
            .filter(|f| f.rule_id == ROLE_FIELD.rule_id)
            .collect()
    }

    #[test]
    fn a_sign_up_that_takes_a_role_from_the_form_is_found() {
        let o = run_against(
            Flaws {
                signup_trusts_role: true,
                ..Default::default()
            },
            &with_role_signup(),
        );
        let found = role_findings(&o);
        assert_eq!(found.len(), 1, "{:#?}\n{:#?}", o.findings, o.not_assessed);
        assert_eq!(
            found[0].requirement_ids,
            vec!["V8.3.1", "V15.3.3", "V8.2.3"]
        );
        assert!(
            found[0].description.contains("/admin"),
            "{}",
            found[0].description
        );
        // The plain accounts are still refused: this is the role field's finding, not the page's.
        assert!(
            !rule_ids(&o).contains(&ADMIN_PAGE.rule_id),
            "{:#?}",
            o.findings
        );
    }

    #[test]
    fn a_sign_up_that_ignores_the_role_credits_nothing_and_says_it_ran() {
        let o = run_against(Flaws::default(), &with_role_signup());
        assert!(role_findings(&o).is_empty(), "{:#?}", o.findings);
        let ran = o
            .verified
            .iter()
            .find(|v| v.check_id == ROLE_FIELD.rule_id)
            .unwrap_or_else(|| panic!("the check did not run: {:#?}", o.not_assessed));
        assert!(
            ran.requirement_ids.is_empty(),
            "only ever a finding: {ran:?}"
        );
    }

    #[test]
    fn the_role_field_check_needs_a_sign_up_and_an_admin_page() {
        let o = run_against(Flaws::default(), &users());
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V8.3.1, V15.3.3" && why.contains("needs both")),
            "{:#?}",
            o.not_assessed
        );
    }

    #[test]
    fn accounts_that_never_sign_in_answer_nothing_about_the_role_field() {
        // Sign-up answers as if it worked and makes nobody. Without the signed-in guard the admin
        // page would be refused to both, which says nothing either way; with it, the check says it
        // could not run.
        let o = run_against(
            Flaws {
                signup_does_nothing: true,
                signup_trusts_role: true,
                ..Default::default()
            },
            &with_role_signup(),
        );
        assert!(role_findings(&o).is_empty());
        assert!(!verified_ids(&o).contains(&ROLE_FIELD.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V8.3.1, V15.3.3" && why.contains("shown signed in")),
            "{:#?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_admin_page_open_to_everybody_is_the_page_checks_finding_not_this_one() {
        let o = run_against(
            Flaws {
                admin_open: true,
                signup_trusts_role: true,
                ..Default::default()
            },
            &with_role_signup(),
        );
        assert!(rule_ids(&o).contains(&ADMIN_PAGE.rule_id));
        assert!(role_findings(&o).is_empty(), "{:#?}", o.findings);
    }
}
