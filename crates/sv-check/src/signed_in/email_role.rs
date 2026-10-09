//! A role sent with an email change (mass assignment beyond sign-up; the gap analysis of 7 October
//! 2026, finding 13(a), on `change-email`).
//!
//! An account made for it is shown refused the admin pages, then sends the email change with the
//! sign-up check's role fields added. An admin page that opens to it afterwards opened because of a
//! field the browser sent. Never A or B: the other checks rely on them staying as they are.

use super::*;

/// Runs when stackvet.toml has `signup`, `change-email`, and an `admin` page.
pub(super) fn email_role_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    const IDS: &str = "V8.3.1, V15.3.3";
    // Without `signup` or an admin page the sign-up check has already said these were not asked.
    let (Some(signup), false) = (&users.signup, users.admin.is_empty()) else {
        return;
    };
    let Some(change) = &users.change_email else {
        out.not_assessed.push((
            IDS.to_owned(),
            "A role written into the email change: stackvet.toml sets no `change-email` under \
             [stack.run.users]."
                .to_owned(),
        ));
        return;
    };
    let Some(confirm) = confirm else {
        out.not_assessed.push((
            IDS.to_owned(),
            "A role written into the email change: no private page was shown open to a signed-in \
             user, so a sign-in here could not be confirmed."
                .to_owned(),
        ));
        return;
    };
    let spare = &accounts.spare;
    if spare.len() < 32 {
        return;
    }
    let account = Account {
        user: format!("emailrole.{}", accounts.a.user),
        password: format!("Er-{}-aZ9!", &spare[7..31]),
    };
    sign_up(http, users, signup, "email-role", &account);
    let mut quiet = Vec::new();
    let signed = sign_in(http, users, "email-role", &account, &mut quiet)
        .filter(|s| ok(&http.send(&get("private-email-role", confirm, &s.session))));
    let Some(signed) = signed else {
        out.not_assessed.push((
            IDS.to_owned(),
            format!(
                "A role written into the email change: the account made for it, {}, could not be \
                 shown signed in to begin with.",
                account.user
            ),
        ));
        return;
    };
    let mut session = signed.session;

    // The control: only the admin pages refused to this account before the change are asked again.
    // One it opens already is the admin-page check's finding, not this one's.
    let refused: Vec<&String> = users
        .admin
        .iter()
        .enumerate()
        .filter(|(i, page)| {
            !ok(&http.send(&get(
                &format!("email-role-admin-{i}-before"),
                page,
                &session,
            )))
        })
        .map(|(_, page)| page)
        .collect();
    if refused.is_empty() {
        return;
    }

    let mut with_role = change.clone();
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
    let moved = format!("moved-role.{}", account.user);
    let values = Values {
        user: &account.user,
        password: &account.password,
        new_email: &moved,
        ..Default::default()
    };
    let (answer, _) = send_template(
        http,
        "email-role-change",
        &with_role,
        &values,
        &mut session,
        &users.private,
    );
    out.steps.push(format!(
        "an account refused {} admin page{} sent its email change with {} role field{} added ({})",
        refused.len(),
        if refused.len() == 1 { "" } else { "s" },
        ROLE_FIELDS.len(),
        if ROLE_FIELDS.len() == 1 { "" } else { "s" },
        status(&answer)
    ));

    // Asked with the session it had, and signed in afresh under either address, since an app may
    // read the role into a session only at sign-in.
    let mut sessions = vec![session];
    for (label, user) in [("old", &account.user), ("new", &moved)] {
        let again = Account {
            user: user.clone(),
            password: account.password.clone(),
        };
        if let Some(s) = sign_in(
            http,
            users,
            &format!("email-role-{label}"),
            &again,
            &mut quiet,
        ) {
            sessions.push(s.session);
        }
    }
    let opened: Vec<String> = refused
        .iter()
        .enumerate()
        .filter(|(i, page)| {
            sessions.iter().enumerate().any(|(j, s)| {
                ok(&http.send(&get(&format!("email-role-admin-{i}-after-{j}"), page, s)))
            })
        })
        .map(|(_, page)| (*page).clone())
        .collect();
    if !opened.is_empty() {
        out.findings.push(finding(
            &EMAIL_ROLE_FIELD,
            "An account can make itself an admin by changing its email address",
            Severity::Critical,
            format!(
                "An account refused {} sent its email change through {} with {} added, and was then \
                 let into {}.",
                refused
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                change.path,
                ROLE_FIELDS
                    .iter()
                    .map(|(k, v)| format!("`{k}={v}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
                opened.join(", ")
            ),
        ));
    } else {
        // Only ever a finding: five guessed names refused say nothing about a sixth, so the check is
        // recorded as having run and credits no requirement, as at sign-up.
        out.verified.push(crate::Verified::new(
            EMAIL_ROLE_FIELD.rule_id,
            &[],
            format!(
                "an account that sent its email change with {} role fields added was still refused \
                 {} admin page{}; other field names were not tried",
                ROLE_FIELDS.len(),
                refused.len(),
                if refused.len() == 1 { "" } else { "s" }
            ),
        ));
    }
}
