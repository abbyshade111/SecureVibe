use super::*;

/// The admin, signed in, and when the session could not be shown signed in, why: in words for a
/// not-assessed reason, naming where the sign-in stopped.
pub(super) struct AdminSignIn {
    pub(super) signed: Option<SignedIn>,
    /// `None` when the private page opened for the admin, or there is no private page to tell by.
    pub(super) stopped: Option<String>,
}

/// Signs the admin in, and finishes a two-factor sign-in when the app asks for one.
///
/// The admin is signed in with its password, as A and B are. When `totp` is set, the private page
/// is asked first: open, and the password was enough. Shut, and the sign-in may be waiting at the
/// code step, so the code for this moment is worked out from the admin's secret
/// (`SV_ADMIN_TOTP_SECRET`) and given through `totp`, and the private page asked again. A code is
/// refused when an earlier sign-in in the run used the same one — most apps take a code once — so
/// a refused code is tried once more, from a new sign-in, after the next 30-second step begins.
///
/// When the admin is still not shown signed in, `stopped` says where it stopped, so a page the
/// admin could not open is not blamed on securevibe.toml naming the wrong page.
pub(super) fn sign_in_admin(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    who: &str,
    steps: &mut Vec<String>,
) -> AdminSignIn {
    let Some(account) = accounts.admin.as_ref() else {
        return AdminSignIn {
            signed: None,
            stopped: Some("there is no admin account; `seed` makes one, from SV_ADMIN".to_owned()),
        };
    };
    let Some(signed) = sign_in(http, users, who, account, steps) else {
        return AdminSignIn {
            signed: None,
            stopped: Some("the app did not answer the admin's sign-in".to_owned()),
        };
    };
    let secret = accounts.admin_totp_secret.as_deref();
    let Some(confirm) = users.private.first() else {
        // Nothing to tell the sign-in by. A code is still given when there is one to give: an app
        // that did not ask for it refuses it, and the session is as it was.
        let mut signed = signed;
        if let (Some(entry), Some(secret)) = (&users.totp, secret) {
            give_admin_code(http, users, entry, account, secret, who, &mut signed);
        }
        return AdminSignIn {
            signed: Some(signed),
            stopped: None,
        };
    };
    let opened = |http: &mut dyn Http, signed: &SignedIn, id: &str| {
        let answer = http.send(&get(id, confirm, &signed.session));
        (ok(&answer), status(&answer))
    };
    let (open, answered) = opened(http, &signed, &format!("admin-private-{who}"));
    if open {
        return AdminSignIn {
            signed: Some(signed),
            stopped: None,
        };
    }
    let Some(entry) = &users.totp else {
        let stopped = format!(
            "after its password, the admin's sign-in {} and {confirm} then answered {answered}. \
             If the app asks admins for a further step, such as a code from an authenticator app, \
             add it to securevibe.toml as `totp` and have `seed` enroll the admin with \
             SV_ADMIN_TOTP_SECRET",
            signed.landed
        );
        return AdminSignIn {
            signed: Some(signed),
            stopped: Some(stopped),
        };
    };
    let Some(secret) = secret else {
        let stopped = format!(
            "after its password, the admin's sign-in {} and {confirm} then answered {answered}: it \
             most likely stopped at the authenticator-code step ({}), and there was no secret to \
             work out the admin's code from. `sv` makes one, SV_ADMIN_TOTP_SECRET, when `seed` \
             makes the admin; have `seed` enroll the admin with it",
            signed.landed, entry.path
        );
        return AdminSignIn {
            signed: Some(signed),
            stopped: Some(stopped),
        };
    };
    let mut signed = signed;
    let mut given = 0;
    for round in 0..2 {
        if round > 0 {
            // A refused code may be one an earlier sign-in used in this same step.
            let into_next = crate::totp::STEP - http.now() % crate::totp::STEP + 1;
            http.wait(into_next);
            let again = format!("{who}-again");
            let Some(fresh) = sign_in(http, users, &again, account, steps) else {
                break;
            };
            signed = fresh;
        }
        give_admin_code(http, users, entry, account, secret, who, &mut signed);
        given += 1;
        let (open, _) = opened(http, &signed, &format!("admin-private-{who}-code-{round}"));
        steps.push(format!(
            "gave the admin's authenticator code at {}; {confirm} then {}",
            entry.path,
            if open { "opened" } else { "stayed shut" }
        ));
        if open {
            return AdminSignIn {
                signed: Some(signed),
                stopped: None,
            };
        }
    }
    let stopped = format!(
        "after its password, the admin's sign-in {}; the authenticator code worked out from \
         SV_ADMIN_TOTP_SECRET was then given at {}{}, and {confirm} still did not open, so the \
         sign-in stopped at the code step. Check that `seed` enrolls the admin in two-factor \
         sign-in with SV_ADMIN_TOTP_SECRET, and `totp` in securevibe.toml",
        signed.landed,
        entry.path,
        if given > 1 {
            ", twice, 30 seconds apart"
        } else {
            ""
        }
    );
    AdminSignIn {
        signed: Some(signed),
        stopped: Some(stopped),
    }
}

/// Gives the admin's current two-factor code through `entry`, in the session the password began.
/// The code is never written into the run's steps: it is worked out from a secret.
fn give_admin_code(
    http: &mut dyn Http,
    users: &UsersSection,
    entry: &RequestTemplate,
    account: &Account,
    secret: &[u8],
    who: &str,
    signed: &mut SignedIn,
) {
    let code = crate::totp::code_at_step(secret, http.now() / crate::totp::STEP);
    let values = Values {
        user: &account.user,
        password: &account.password,
        code: &code,
        ..Default::default()
    };
    send_template(
        http,
        &format!("admin-code-{who}"),
        entry,
        &values,
        &mut signed.session,
        &users.private,
    );
}

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
    let AdminSignIn {
        signed: admin,
        stopped,
    } = sign_in_admin(http, users, accounts, "admin", &mut out.steps);
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
        let pages = unconfirmed.join(", ");
        out.not_assessed.push((
            "V8.2.1".to_owned(),
            match (&stopped, users.private.first()) {
                // The admin was never shown signed in: say where its sign-in stopped, not that the
                // page is in the wrong place. family-hub's was where the file said; its admin's
                // sign-in had stopped at the authenticator-code step.
                (Some(stopped), _) => format!(
                    "The admin account was not shown signed in, so it not opening {pages}, and the \
                     ordinary user being refused it, say nothing: {stopped}."
                ),
                (None, Some(private)) => format!(
                    "The admin account was signed in (it opened {private}) but did not open \
                     {pages} either, so the ordinary user being refused says nothing: the page may \
                     not be where securevibe.toml says, or the account `seed` made from SV_ADMIN \
                     may not be an admin."
                ),
                (None, None) => format!(
                    "The admin account did not open {pages} either, so the ordinary user being \
                     refused says nothing. No private page is listed to show the admin's sign-in \
                     worked, so it may not have, or the page may not be where securevibe.toml says."
                ),
            },
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
    if accounts.admin.is_none() {
        out.not_assessed.push((
            "V8.3.1".to_owned(),
            "Admin actions: there is no admin account to confirm them with; an admin is made by `seed`."
                .to_owned(),
        ));
        return;
    }
    let a = sign_in(http, users, "a-actions", &accounts.a, &mut out.steps);
    let AdminSignIn {
        signed: admin,
        stopped,
    } = sign_in_admin(http, users, accounts, "admin-actions", &mut out.steps);
    let why_admin = stopped.map_or(String::new(), |s| format!(" For the admin, {s}."));
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
            format!(
                "Admin actions: the first user and the admin could not both sign in, so none was \
                 sent.{why_admin}"
            ),
        ));
        return;
    };
    if !signed_in(http, &a, "admin-actions-a-confirm")
        || !signed_in(http, &admin, "admin-actions-admin-confirm")
    {
        out.not_assessed.push((
            "V8.3.1".to_owned(),
            format!(
                "Admin actions: the first user and the admin could not both be shown signed in (a \
                 private page did not open for each), so a refusal would say nothing and none was \
                 sent.{why_admin}"
            ),
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

    // Where apps most often show one person's data to another: their lists. The second user opens
    // every private page and the record's list, and the first user's marker in any of them is the
    // record shown to somebody else (ADR-053).
    let mut listed = Vec::new();
    let mut looked = Vec::new();
    if let Some(b) = &b {
        let mut places = users.private.clone();
        if let Some(list) = owned.list.as_ref().filter(|l| !places.contains(l)) {
            places.push(list.clone());
        }
        for (i, place) in places.iter().enumerate() {
            let seen = http.send(&get(&format!("owned-b-list-{i}"), place, &b.session));
            if ok(&seen) {
                looked.push(place.clone());
            }
            if holds_marker(&seen) {
                listed.push(place.clone());
            }
        }
    }

    // Changing and deleting it, as the second user, when securevibe.toml says how. What decides is
    // what the first user then reads back, not what the second was told: `Some(true)` the change or
    // the deletion took, `Some(false)` it did not, `None` the read-back said neither (ADR-053).
    let id = created.as_ref().and_then(|c| record_id(owned, c));
    let changed_marker = "sv-probe-changed-9d2a";
    let mut changed = None;
    let mut deleted = None;
    if let (Some(b), Some(id)) = (&b, id.as_deref()) {
        let mut b_session = b.session.clone();
        if let Some(update) = &owned.update {
            let values = Values {
                marker: changed_marker,
                id,
                ..Default::default()
            };
            send_template(
                http,
                "owned-b-update",
                update,
                &values,
                &mut b_session,
                &users.private,
            );
            let after = http.send(&get("owned-a-after-update", &read_path, &session));
            changed = ok(&after).then(|| {
                after
                    .as_ref()
                    .is_some_and(|r| r.body.contains(changed_marker) || !r.body.contains(marker))
            });
        }
        if let Some(delete) = &owned.delete {
            let values = Values {
                id,
                ..Default::default()
            };
            send_template(
                http,
                "owned-b-delete",
                delete,
                &values,
                &mut b_session,
                &users.private,
            );
            let after = http.send(&get("owned-a-after-delete", &read_path, &session));
            deleted = match after.as_ref().map(|r| r.status) {
                Some(404 | 410) => Some(true),
                _ if holds_marker(&after) => Some(false),
                _ => None,
            };
        }
    }

    // The control (ADR-053, Later): the second user's request leaving the record as it was counts as
    // a refusal only when the same request, sent by the first user at a second record of their own,
    // does change or delete it. Otherwise it may never have reached a route at all (a form POSTed
    // where the app takes PUT, a path it does not have), and an unchanged record would show nothing.
    // A second record, so the first stays as it was for the checks that read it later.
    let mut controls_failed = Vec::new();
    if changed == Some(false) || deleted == Some(false) {
        let mut own = session.clone();
        let control_values = Values {
            marker: "sv-probe-control-3f7b",
            ..Default::default()
        };
        let (made, _) = send_template(
            http,
            "owned-control-create",
            &owned.create,
            &control_values,
            &mut own,
            &users.private,
        );
        let control = made
            .as_ref()
            .filter(|_| accepted(&made))
            .and_then(|m| Some((record_path(owned, m)?, record_id(owned, m)?)));
        if changed == Some(false) {
            let own_marker = "sv-probe-own-change-5e1b";
            let works = match (&control, &owned.update) {
                (Some((path, control_id)), Some(update)) => {
                    let values = Values {
                        marker: own_marker,
                        id: control_id,
                        ..Default::default()
                    };
                    send_template(
                        http,
                        "owned-control-update",
                        update,
                        &values,
                        &mut own,
                        &users.private,
                    );
                    let back = http.send(&get("owned-control-after-update", path, &session));
                    ok(&back) && back.as_ref().is_some_and(|r| r.body.contains(own_marker))
                }
                _ => false,
            };
            if !works {
                changed = None;
                controls_failed.push("change");
            }
        }
        if deleted == Some(false) {
            let works = match (&control, &owned.delete) {
                (Some((path, control_id)), Some(delete)) => {
                    let values = Values {
                        id: control_id,
                        ..Default::default()
                    };
                    send_template(
                        http,
                        "owned-control-delete",
                        delete,
                        &values,
                        &mut own,
                        &users.private,
                    );
                    let back = http.send(&get("owned-control-after-delete", path, &session));
                    matches!(back.as_ref().map(|r| r.status), Some(404 | 410))
                }
                _ => false,
            };
            if !works {
                deleted = None;
                controls_failed.push("delete");
            }
        }
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
    }
    if !listed.is_empty() {
        out.findings.push(finding(
            &OTHER_USERS_DATA,
            "One user's records show on another user's pages",
            Severity::Critical,
            format!(
                "What the first test user wrote in a record was on {} when the second test user \
                 opened {}.",
                listed.join(", "),
                if listed.len() == 1 { "it" } else { "them" }
            ),
        ));
    }
    if changed == Some(true) {
        out.findings.push(finding(
            &OTHER_USERS_DATA,
            "One user can change another user's records",
            Severity::Critical,
            format!(
                "The second test user sent the change request for the first user's record at \
                 {read_path}, and when the first user read it back, it had changed."
            ),
        ));
    }
    if deleted == Some(true) {
        out.findings.push(finding(
            &OTHER_USERS_DATA,
            "One user can delete another user's records",
            Severity::Critical,
            format!(
                "The second test user sent the delete request for the first user's record at \
                 {read_path}, and afterwards the first user was told it was not there."
            ),
        ));
    }
    let found = !leaked_to.is_empty()
        || !listed.is_empty()
        || changed == Some(true)
        || deleted == Some(true);
    if !found && b.is_some() {
        let mut tried = vec![format!(
            "a record one test user created at {read_path}, refused to a second test user and to \
             somebody not signed in, and read back by its owner"
        )];
        if !looked.is_empty() {
            tried.push(format!(
                "not shown to the second user on {}",
                looked.join(", ")
            ));
        }
        if changed == Some(false) {
            tried.push("not changed by the second user's change request".to_owned());
        }
        if deleted == Some(false) {
            tried.push("not deleted by the second user's delete request".to_owned());
        }
        let writes_refused = changed == Some(false) || deleted == Some(false);
        let credit = crate::Verified::new(
            OTHER_USERS_DATA.rule_id,
            OTHER_USERS_DATA.requirement_ids,
            tried.join("; "),
        );
        if writes_refused {
            out.verified.push(credit);
        } else {
            // Reading alone is one of the ways one user reaches another's data, not all of them.
            out.verified.push(credit.in_part());
            out.not_assessed.push((
                "V8.2.2".to_owned(),
                if owned.update.is_none() && owned.delete.is_none() {
                    "Whether one user can change or delete another user's records: securevibe.toml \
                     gives no `update` or `delete` under `owned`, so only reading was tried, and V8.2.2 \
                     is checked in part."
                        .to_owned()
                } else if !controls_failed.is_empty() {
                    format!(
                        "Whether one user can change or delete another user's records: the {} request \
                         left the first user's own record as it was when the first user sent it too, so \
                         it may not reach the app's route at all (a request is a form POST unless it \
                         gives `method`, and `json` in place of `form`), and the second user's being \
                         refused shows nothing. V8.2.2 is checked in part.",
                        controls_failed.join(" and ")
                    )
                } else {
                    "Whether one user can change or delete another user's records: the first user's \
                     read-back after the second user's request said neither, so only reading is \
                     known, and V8.2.2 is checked in part."
                        .to_owned()
                },
            ));
        }
    } else if b.is_none() {
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

pub(super) fn strip_origin(location: &str) -> &str {
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

    /// The credit for V8.2.2 from a run, and the findings about it (ADR-053).
    fn other_users(flaws: Flaws, users: &UsersSection) -> (Option<crate::Verified>, Vec<String>) {
        let o = run_against(flaws, users);
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == OTHER_USERS_DATA.rule_id)
            .cloned();
        let titles = o
            .findings
            .iter()
            .filter(|f| f.rule_id == OTHER_USERS_DATA.rule_id)
            .map(|f| f.title.clone())
            .collect();
        (credit, titles)
    }

    #[test]
    fn refused_reading_listing_changing_and_deleting_is_checked_and_reading_alone_is_checked_in_part()
     {
        // All four tried and refused: checked, and the line says what was tried.
        let (full, found) = other_users(Flaws::default(), &users_full());
        assert!(found.is_empty(), "{found:?}");
        let full = full.expect("credited");
        assert!(!full.in_part, "{full:?}");
        for said in [
            "refused to a second test user",
            "not shown to the second user on /account, /my-notes",
            "not changed by the second user's change request",
            "not deleted by the second user's delete request",
        ] {
            assert!(full.scope.contains(said), "{said}: {}", full.scope);
        }
        // Reading alone, as securevibe.toml gives no change or delete request: in part, and the
        // report says why and how to make it whole.
        let o = run_against(Flaws::default(), &users());
        let part = o
            .verified
            .iter()
            .find(|v| v.check_id == OTHER_USERS_DATA.rule_id)
            .expect("credited in part");
        assert!(part.in_part, "{part:?}");
        assert!(
            o.not_assessed
                .iter()
                .any(|(r, why)| r == "V8.2.2" && why.contains("no `update` or `delete`")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_change_or_delete_that_never_reaches_a_route_is_not_taken_for_a_refusal() {
        // ADR-053, Later. The app's change and delete routes take another method, so the form POSTs
        // answer 405 for everybody: the second user's request leaves the record as it was, and so
        // does the owner's own. That is no refusal, and V8.2.2 is checked in part, saying why.
        let o = run_against(
            Flaws {
                writes_need_another_method: true,
                ..Default::default()
            },
            &users_full(),
        );
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == OTHER_USERS_DATA.rule_id)
            .expect("reading is still credited, in part");
        assert!(credit.in_part, "{credit:?}");
        assert!(!credit.scope.contains("not changed"), "{}", credit.scope);
        assert!(
            o.not_assessed.iter().any(|(r, why)| r == "V8.2.2"
                && why.contains("change and delete request")
                && why.contains("`method`")),
            "{:?}",
            o.not_assessed
        );
        // The control: a correct app's routes do change and delete the owner's own record, so the
        // second user's being refused counts, and V8.2.2 is checked in full.
        let (full, found) = other_users(Flaws::default(), &users_full());
        assert!(found.is_empty(), "{found:?}");
        assert!(!full.expect("credited").in_part);
    }

    #[test]
    fn another_users_record_in_a_list_changed_or_deleted_is_found_by_what_its_owner_then_sees() {
        for (flaws, title) in [
            (
                Flaws {
                    list_shows_others: true,
                    ..Default::default()
                },
                "One user's records show on another user's pages",
            ),
            (
                Flaws {
                    idor_update: true,
                    ..Default::default()
                },
                "One user can change another user's records",
            ),
            (
                Flaws {
                    idor_delete: true,
                    ..Default::default()
                },
                "One user can delete another user's records",
            ),
        ] {
            let (credit, found) = other_users(flaws, &users_full());
            assert_eq!(found, vec![title.to_owned()], "{title}");
            assert!(credit.is_none(), "{title}: no credit beside a finding");
        }
        // Each is found by itself: with only the read guarded wrongly, nothing else is reported.
        let (_, found) = other_users(
            Flaws {
                idor: true,
                ..Default::default()
            },
            &users_full(),
        );
        assert_eq!(
            found,
            vec!["One user can read another user's records".to_owned()]
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
            list: None,
            update: None,
            delete: None,
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

    // --------------------------------------------------------------------------------------------
    // An admin the app asks for a code (family-hub, 3 October 2026)

    /// The suite against the fake app seeded as `seed` would seed it, with the admin enrolled in
    /// two-factor sign-in with `enrolled`, after `change` has had the accounts.
    fn run_with_admin_code(
        enrolled: Vec<u8>,
        users: &UsersSection,
        change: impl FnOnce(&mut Accounts),
    ) -> Outcome {
        let mut app = FakeApp::new(Flaws::default());
        let mut acc = accounts();
        for account in [&acc.a, &acc.b] {
            app.users
                .insert(account.user.clone(), (account.password.clone(), false));
        }
        let admin = acc.admin.clone().unwrap();
        app.users
            .insert(admin.user.clone(), (admin.password.clone(), true));
        app.totp.insert(admin.user.clone(), enrolled);
        let totp = acc.totp.clone().unwrap();
        app.users.insert(
            totp.account.user.clone(),
            (totp.account.password.clone(), false),
        );
        app.totp.insert(totp.account.user, totp.secret);
        // The setup: with the password alone, the admin does not get in. Without this, the credit
        // below could be an app that never asked for a code.
        let mut quiet = Vec::new();
        let password_only = sign_in(&mut app, users, "setup", &admin, &mut quiet).unwrap();
        assert!(
            !ok(&app.send(&get("setup-private", "/account", &password_only.session))),
            "the fake app let the admin in without a code, so this proves nothing"
        );
        change(&mut acc);
        run(&mut app, users, &acc, true, &Default::default())
    }

    fn admin_page_reasons(o: &Outcome, id: &str) -> Vec<String> {
        o.not_assessed
            .iter()
            .filter(|(ids, why)| ids == id && why.contains("dmin"))
            .map(|(_, why)| why.clone())
            .collect()
    }

    #[test]
    fn an_admin_who_needs_a_code_is_signed_in_with_its_secret_and_the_admin_checks_are_assessed() {
        let o = run_with_admin_code(admin_secret(), &users(), |_| {});
        assert!(
            verified_ids(&o).contains(&ADMIN_PAGE.rule_id),
            "{:#?}",
            o.not_assessed
        );
        assert!(action_credited(&o), "{:#?}", o.not_assessed);
        assert!(
            o.steps.iter().any(|s| s
                .starts_with("gave the admin's authenticator code at /login/2fa")
                && s.ends_with("opened")),
            "{:#?}",
            o.steps
        );
        // The second sign-in (the admin actions') came in the same 30-second step as the first,
        // and the fake app takes a code once, as most apps do: it got in with the next step's.
        assert!(
            o.steps.iter().any(|s| s.contains("ADMIN-ACTIONS-AGAIN")),
            "{:#?}",
            o.steps
        );
        // And a wrong ordinary user is still found: the admin being in is what makes it evidence.
        assert!(
            admin_page_reasons(&o, "V8.2.1").is_empty(),
            "{:#?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_admin_page_open_to_everybody_is_still_found_when_the_admin_needs_a_code() {
        let mut app = FakeApp::new(Flaws {
            admin_open: true,
            ..Default::default()
        });
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user.clone(), (admin.password, true));
        app.totp.insert(admin.user, admin_secret());
        let mut acc = acc;
        acc.totp = None;
        let o = run(&mut app, &users(), &acc, true, &Default::default());
        assert!(rule_ids(&o).contains(&ADMIN_PAGE.rule_id));
    }

    #[test]
    fn without_the_secret_the_message_names_the_authenticator_step() {
        let o = run_with_admin_code(admin_secret(), &users(), |acc| {
            acc.admin_totp_secret = None;
        });
        assert!(!verified_ids(&o).contains(&ADMIN_PAGE.rule_id));
        assert!(!action_credited(&o));
        for id in ["V8.2.1", "V8.3.1"] {
            let reasons = admin_page_reasons(&o, id);
            assert!(
                reasons
                    .iter()
                    .any(|why| why.contains("authenticator-code step (/login/2fa)")
                        && why.contains("SV_ADMIN_TOTP_SECRET")),
                "{id}: {reasons:#?}"
            );
            assert!(
                reasons.iter().all(|why| !why.contains("may not be where")),
                "{id}: the page is where the file says: {reasons:#?}"
            );
        }
    }

    #[test]
    fn a_code_the_app_refuses_says_the_sign_in_stopped_at_the_code_step() {
        // `seed` enrolled the admin with a secret of its own, not SV_ADMIN_TOTP_SECRET.
        let other: Vec<u8> = admin_secret().iter().map(|b| b ^ 0x5a).collect();
        let o = run_with_admin_code(other, &users(), |_| {});
        assert!(!verified_ids(&o).contains(&ADMIN_PAGE.rule_id));
        let reasons = admin_page_reasons(&o, "V8.2.1");
        assert!(
            reasons
                .iter()
                .any(|why| why.contains("stopped at the code step")
                    && why.contains(
                        "enrolls the admin in two-factor sign-in with SV_ADMIN_TOTP_SECRET"
                    )),
            "{reasons:#?}"
        );
        assert!(reasons.iter().all(|why| !why.contains("may not be where")));
    }

    #[test]
    fn an_admin_stopped_by_a_step_the_manifest_does_not_name_is_told_apart_from_a_wrong_page() {
        let mut u = users();
        u.totp = None;
        let o = run_with_admin_code(admin_secret(), &u, |acc| acc.totp = None);
        let reasons = admin_page_reasons(&o, "V8.2.1");
        assert!(
            reasons.iter().any(|why| why.contains("not shown signed in")
                && why.contains("answered 200")
                && why.contains("as `totp`")),
            "{reasons:#?}"
        );
        assert!(reasons.iter().all(|why| !why.contains("may not be where")));
        // The control: an admin who is in, and a page that really is not there, keeps that reason.
        let mut wrong = users();
        wrong.admin = vec!["/not-the-admin-page".into()];
        let o = run_with_admin_code(admin_secret(), &wrong, |_| {});
        let reasons = admin_page_reasons(&o, "V8.2.1");
        assert!(
            reasons.iter().any(|why| why.contains("it opened /account")
                && why.contains("may not be where securevibe.toml says")),
            "{reasons:#?}"
        );
    }

    /// The forms a secret could be written in, by name: base32 as `seed` is given it, in either
    /// case, and hex. Its raw bytes are not text, and are only ever handed on as base32.
    fn forms_of(secret: &[u8]) -> Vec<(&'static str, String)> {
        let encoded = crate::totp::base32(secret);
        vec![
            ("base32", encoded.clone()),
            ("base32, lowercase", encoded.to_lowercase()),
            (
                "hex",
                secret
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            ),
        ]
    }

    /// Which form of `secret` is anywhere in what the run hands the report: every finding,
    /// credit, reason and step, and the log markers. Named, never printed.
    fn leaked(o: &Outcome, secret: &[u8]) -> Option<&'static str> {
        let everything = format!("{o:?}");
        forms_of(secret)
            .into_iter()
            .find(|(_, form)| everything.contains(form.as_str()))
            .map(|(name, _)| name)
    }

    #[test]
    fn the_admins_secret_never_reaches_the_report() {
        let secret = admin_secret();
        // The search can find it: a run note that did carry it is caught, in each form.
        for (name, form) in forms_of(&secret) {
            let mut planted = Outcome::default();
            planted.steps.push(format!("seed said {form}"));
            assert_eq!(leaked(&planted, &secret), Some(name));
        }
        // Signed in with it; refused it; and without it. Each run is shown to have used the
        // secret, or to have stopped where it says, before its silence is believed.
        let used = run_with_admin_code(secret.clone(), &users(), |_| {});
        assert!(verified_ids(&used).contains(&ADMIN_PAGE.rule_id));
        let other: Vec<u8> = secret.iter().map(|b| b ^ 0x5a).collect();
        let refused = run_with_admin_code(other.clone(), &users(), |_| {});
        assert!(!admin_page_reasons(&refused, "V8.2.1").is_empty());
        let without = run_with_admin_code(secret.clone(), &users(), |acc| {
            acc.admin_totp_secret = None;
        });
        assert!(!admin_page_reasons(&without, "V8.2.1").is_empty());
        for (what, o) in [
            ("used", &used),
            ("refused", &refused),
            ("without", &without),
        ] {
            assert_eq!(leaked(o, &secret), None, "{what}: the admin's secret");
            assert_eq!(
                leaked(o, &other),
                None,
                "{what}: the secret the app enrolled"
            );
            let user_secret = &accounts().totp.unwrap().secret;
            assert_eq!(
                leaked(o, user_secret),
                None,
                "{what}: the two-factor account's"
            );
        }
    }
}
