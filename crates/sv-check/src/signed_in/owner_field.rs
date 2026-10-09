//! A record's owner taken from the request that creates it (mass assignment beyond sign-up; the gap
//! analysis of 7 October 2026, finding 13(a)).
//!
//! When the record the first user reads back names its owner (`"user_id": 7`), the second user
//! creates two records: one as stackvet.toml says, and one with that owner field set to the first
//! user's value. The second record shown to the first user as theirs, while the plain one is not, is
//! the owner taken from the request. Only ever a finding: an app that ignores seven guessed field
//! names may take an eighth.

use super::*;

/// The fields an app most often names a record's owner by, in the order they are looked for.
pub(super) const OWNER_FIELDS: &[&str] = &[
    "user_id",
    "owner_id",
    "userId",
    "ownerId",
    "author_id",
    "created_by",
    "owner",
];

/// The owner a record names: the first of `OWNER_FIELDS` written as a JSON field with a string or a
/// number, in a JSON answer or in JSON inside a page. Gives the field and its value as JSON, so a
/// number is sent back as a number.
pub(super) fn named_owner(body: &str) -> Option<(&'static str, serde_json::Value)> {
    OWNER_FIELDS.iter().find_map(|field| {
        let pattern = format!(
            r#""{}"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+)"#,
            regex::escape(field)
        );
        let found = regex::Regex::new(&pattern).ok()?.captures(body)?;
        let value = serde_json::from_str::<serde_json::Value>(found.get(1)?.as_str()).ok()?;
        let empty = value.as_str().is_some_and(|s| s.trim().is_empty());
        (!empty).then_some((*field, value))
    })
}

/// `sent` with `field` set to `value` in its body: a JSON body keeps the value's type, and a form
/// gets it as text. `None` for a body that is neither, which has nowhere to put a field.
pub(super) fn with_field(
    mut sent: ProbeRequest,
    field: &str,
    value: &serde_json::Value,
) -> Option<ProbeRequest> {
    let content_type = sent
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_lowercase())?;
    let body = String::from_utf8(sent.body.clone()?).ok()?;
    let new_body = if content_type.starts_with("application/json") {
        let mut object =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body).ok()?;
        object.insert(field.to_owned(), value.clone());
        serde_json::Value::Object(object).to_string()
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        let text = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let pair = format!("{}={}", form_encode(field), form_encode(&text));
        if body.is_empty() {
            pair
        } else {
            format!("{body}&{pair}")
        }
    } else {
        return None;
    };
    sent.body = Some(new_body.into_bytes());
    Some(sent)
}

/// Whether the first user is shown a record of the second user's with `marker` in it: at the
/// record's own address, or on any page where the first user's records are listed.
fn shown_to_a(
    http: &mut dyn Http,
    id: &str,
    record: Option<&str>,
    places: &[String],
    a: &Session,
    marker: &str,
) -> bool {
    let holds =
        |r: &Option<ProbeResponse>| ok(r) && r.as_ref().is_some_and(|r| r.body.contains(marker));
    if let Some(path) = record
        && holds(&http.send(&get(&format!("{id}-record"), path, a)))
    {
        return true;
    }
    places
        .iter()
        .enumerate()
        .any(|(i, place)| holds(&http.send(&get(&format!("{id}-list-{i}"), place, a))))
}

/// Runs once the first user has read back their record (`as_a`) and the second user has signed in.
pub(super) fn owner_field_check(
    http: &mut dyn Http,
    users: &UsersSection,
    owned: &sv_manifest::OwnedSection,
    a: &Session,
    b: &Session,
    as_a: &str,
    out: &mut Outcome,
) {
    let Some((field, value)) = named_owner(as_a) else {
        out.not_assessed.push((
            "V15.3.3".to_owned(),
            format!(
                "Whether a record's owner can be set by whoever creates it: the record the first \
                 user read back names no owner by a field stackvet knows ({}), so there was no \
                 value to send.",
                OWNER_FIELDS.join(", ")
            ),
        ));
        return;
    };
    let mut places = users.private.clone();
    if let Some(list) = owned.list.as_ref().filter(|l| !places.contains(l)) {
        places.push(list.clone());
    }

    // The control first: the same request, without the field, as the second user.
    let plain_marker = "sv-probe-owner-plain-2b8d";
    let mut b_session = b.clone();
    let (plain, _) = send_template(
        http,
        "owner-field-plain",
        &owned.create,
        &Values {
            marker: plain_marker,
            ..Default::default()
        },
        &mut b_session,
        &users.private,
    );
    if !accepted(&plain) {
        out.not_assessed.push((
            "V15.3.3".to_owned(),
            format!(
                "Whether a record's owner can be set by whoever creates it: the second user could \
                 not create a record ({}), so there is nothing to compare with.",
                status(&plain)
            ),
        ));
        return;
    }

    let claimed_marker = "sv-probe-owner-claimed-6f1c";
    let sent = prepared(
        http,
        "owner-field-claimed",
        &owned.create,
        &Values {
            marker: claimed_marker,
            ..Default::default()
        },
        &mut b_session,
        &users.private,
    );
    let Some(sent) = with_field(sent, field, &value) else {
        out.not_assessed.push((
            "V15.3.3".to_owned(),
            "Whether a record's owner can be set by whoever creates it: the `create` request in \
             stackvet.toml sends neither `form` nor `json`, so there is no body to add a field to."
                .to_owned(),
        ));
        return;
    };
    let claimed = http.send(&sent);
    if let Some(r) = &claimed {
        b_session.absorb(r);
    }
    out.steps.push(format!(
        "B created a record with `{field}` set to the value A's own record names as its owner, \
         and one without it ({}, {})",
        status(&claimed),
        status(&plain)
    ));
    if !accepted(&claimed) {
        // Refused for the field, most likely: what a careful app does, and still no credit.
        return;
    }

    let path_of = |r: &Option<ProbeResponse>| r.as_ref().and_then(|r| record_path(owned, r));
    let plain_path = path_of(&plain);
    let claimed_path = path_of(&claimed);
    let plain_shown = shown_to_a(
        http,
        "owner-field-plain-a",
        plain_path.as_deref(),
        &places,
        a,
        plain_marker,
    );
    let claimed_shown = shown_to_a(
        http,
        "owner-field-claimed-a",
        claimed_path.as_deref(),
        &places,
        a,
        claimed_marker,
    );
    if plain_shown {
        out.not_assessed.push((
            "V15.3.3".to_owned(),
            "Whether a record's owner can be set by whoever creates it: the first user was shown \
             the second user's record made without an owner field too, so being shown the one with \
             it says nothing about the field."
                .to_owned(),
        ));
        return;
    }
    if claimed_shown {
        out.findings.push(finding(
            &OWNER_FIELD,
            "A record can be put into another user's account",
            Severity::High,
            format!(
                "The second test user created a record with `{field}` added to the request, set to \
                 the value the first test user's own record names as its owner, and the first user \
                 was then shown it as theirs. The same request without `{field}` was not shown to \
                 the first user, so the app took the record's owner from the request."
            ),
        ));
    }
}
