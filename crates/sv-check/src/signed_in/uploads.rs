use super::*;

/// The most this check will ever send in one upload.
///
/// A limit stated far above this is not tested: the point is to find an app that takes anything,
/// not to become a denial-of-service attempt against somebody's own app.
const MOST_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;

/// A GIF's magic bytes, which are ASCII and so survive a body that must be valid text.
///
/// The probe requests carry a `String` body, so a real PNG or JPEG header cannot be written into
/// one: `\x89PNG` is not valid UTF-8. GIF87a is, which is why the correct file here is a GIF. That
/// is a convenience of the harness rather than a claim about what apps accept, and it is why the
/// mismatched file below claims `.gif` too: both halves of the comparison are the same extension,
/// so a refusal can only be about the contents.
const GIF_MAGIC: &str = "GIF87a";

/// One file the probes send: its name, its contents, and what it is for.
struct Upload<'a> {
    id: &'a str,
    name: &'a str,
    contents: String,
}

/// Builds a multipart body by hand, because there is no HTTP client here to do it.
fn multipart(
    boundary: &str,
    field: &str,
    file: &Upload,
    form: &BTreeMap<String, String>,
) -> String {
    let mut body = String::new();
    for (name, value) in form {
        body.push_str(&format!("--{boundary}\r\n"));
        body.push_str(&format!(
            "Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}\r\n"));
    body.push_str(&format!(
        "Content-Disposition: form-data; name=\"{field}\"; filename=\"{}\"\r\n",
        file.name
    ));
    body.push_str("Content-Type: application/octet-stream\r\n\r\n");
    body.push_str(&file.contents);
    body.push_str(&format!("\r\n--{boundary}--\r\n"));
    body
}

/// Where each upload's anti-forgery token comes from, when the form takes one: a page fetched just
/// before, so every upload carries a fresh token. One token for every upload is what an app with
/// single-use tokens refuses from the second on, which would read as the file being refused.
struct Token<'a> {
    page: Option<&'a str>,
    session: &'a Session,
    wanted: bool,
}

impl Token<'_> {
    fn fresh(&self, http: &mut dyn Http, id: &str) -> Option<String> {
        if !self.wanted {
            return None;
        }
        http.send(&get(&format!("{id}-page"), self.page?, self.session))
            .and_then(|page| csrf_token(&page, self.session))
    }
}

/// Sends one file and returns what the app answered. Each carries a fresh token and its own id as
/// `{marker}`, so no two uploads repeat a value an app might keep unique.
fn send_upload(
    http: &mut dyn Http,
    upload: &UploadSection,
    file: &Upload,
    session: &Session,
    token: &Token,
) -> Option<ProbeResponse> {
    const BOUNDARY: &str = "----sv-probe-boundary-6f21a9";
    let values = Values {
        user: "",
        password: "",
        csrf: token.fresh(http, file.id),
        marker: file.id,
        ..Default::default()
    };
    let form: BTreeMap<String, String> = upload
        .form
        .iter()
        .map(|(k, v)| (k.clone(), fill(v, &values)))
        .collect();
    let body = multipart(BOUNDARY, &upload.field, file, &form);
    let mut request = ProbeRequest {
        id: file.id.to_owned(),
        method: "POST".into(),
        path: upload.path.clone(),
        headers: vec![(
            "Content-Type".into(),
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )],
        body: Some(body.into_bytes()),
    };
    for (name, value) in session.headers() {
        request.headers.push((name, value));
    }
    http.send(&request)
}

/// Whether a refusal can be credited to the file: an ordinary GIF, with its own token and marker,
/// sent straight after and accepted. A quota reached, a token spent, or a value the app keeps
/// unique would refuse that too, and then the refusal is not assessed, and `false` comes back.
/// After rather than before, because a quota the refused file would have reached is only shown by
/// what comes next.
#[allow(clippy::too_many_arguments)]
fn refusal_stands(
    http: &mut dyn Http,
    upload: &UploadSection,
    session: &Session,
    token: &Token,
    after: &str,
    requirement: &str,
    what: &str,
    out: &mut Outcome,
) -> bool {
    let id = format!("upload-after-{after}");
    let name = format!("sv-probe-after-{after}.gif");
    let ordinary = Upload {
        id: &id,
        name: &name,
        contents: format!("{GIF_MAGIC}sv-probe-ordinary-file"),
    };
    let answer = send_upload(http, upload, &ordinary, session, token);
    if refused(&answer) {
        out.steps.push(format!(
            "sent {} and then an ordinary GIF: both refused",
            what.to_lowercase()
        ));
        out.not_assessed.push((
            requirement.to_owned(),
            format!(
                "{what} was refused at {}, but so was an ordinary GIF sent straight after it ({}), \
                 so the refusal may have been a quota, a limit, or a spent token rather than \
                 anything about the file.",
                upload.path,
                status(&answer)
            ),
        ));
        return false;
    }
    true
}

/// The three files an app ought to refuse, and what it serves back afterwards.
///
/// Every part of this establishes its own setup first. A refusal proves nothing unless an ordinary
/// file of the same shape was accepted, so an ordinary GIF goes first and each later answer is read
/// against it: if the app refuses everything, or the upload path is not what securevibe.toml says,
/// the questions are reported *not assessed* rather than passed.
pub(super) fn upload_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    signed_in: &SignedIn,
    out: &mut Outcome,
) {
    let Some(upload) = &users.upload else {
        return;
    };
    let session = &signed_in.session;
    let token = Token {
        page: users.private.first().map(String::as_str),
        session,
        wanted: upload.form.values().any(|v| v.contains("{csrf}")),
    };

    // 1. An ordinary file, to show the upload works at all. Without this every refusal below is
    //    a refusal of everything.
    let ordinary = Upload {
        id: "upload-ordinary",
        name: "sv-probe.gif",
        contents: format!("{GIF_MAGIC}sv-probe-ordinary-file"),
    };
    let accepted = send_upload(http, upload, &ordinary, session, &token);
    if accepted.as_ref().is_none_or(|r| r.status >= 400) {
        out.not_assessed.push((
            "V5.2.1, V5.2.2, V5.3.1, V3.2.1".to_owned(),
            format!(
                "An ordinary file was not accepted at {} ({}), so nothing here can tell a file \
                 refused for being wrong from one refused because the upload does not work as \
                 securevibe.toml describes.",
                upload.path,
                status(&accepted)
            ),
        ));
        return;
    }
    out.steps
        .push(format!("uploaded an ordinary GIF to {}", upload.path));

    // 2. V5.2.1: a file larger than the owner says the app accepts.
    match upload.max_bytes {
        None => out.not_assessed.push((
            "V5.2.1".to_owned(),
            "Whether the app refuses files that are too large: say the largest it should accept, \
             as `max-bytes` under the `upload` entry in securevibe.toml, and this will send one \
             larger than that."
                .to_owned(),
        )),
        // A cap, so one check cannot become a denial-of-service against somebody's own app. Above
        // it the check says what it did rather than pretending to have tested the policy.
        Some(most) if most > MOST_UPLOAD_BYTES => out.not_assessed.push((
            "V5.2.1".to_owned(),
            format!(
                "`max-bytes` is {most}. This check sends at most {MOST_UPLOAD_BYTES} bytes, so it \
                 cannot exceed that number without becoming a denial-of-service attempt against \
                 your own app."
            ),
        )),
        Some(most) => {
            let big = Upload {
                id: "upload-oversized",
                name: "sv-probe-big.gif",
                contents: format!("{GIF_MAGIC}{}", "A".repeat((most + 1024) as usize)),
            };
            let answer = send_upload(http, upload, &big, session, &token);
            let refused = answer.as_ref().is_none_or(|r| r.status >= 400);
            out.steps.push(format!(
                "sent a file of {} bytes where {most} is the stated limit: {}",
                most + 1024 + GIF_MAGIC.len() as u64,
                if refused { "refused" } else { "accepted" }
            ));
            if refused
                && !refusal_stands(
                    http,
                    upload,
                    session,
                    &token,
                    "oversized",
                    "V5.2.1",
                    "A file larger than the stated limit",
                    out,
                )
            {
                // Not assessed, and said so.
            } else if refused {
                out.verified.push(crate::Verified::new(
                    OVERSIZED_FILE.rule_id,
                    OVERSIZED_FILE.requirement_ids,
                    format!(
                        "a file about {} bytes larger than the {most} you stated, refused where an \
                         ordinary one was accepted",
                        1024 + GIF_MAGIC.len() as u64
                    ),
                ));
            } else {
                out.findings.push(finding(
                    &OVERSIZED_FILE,
                    "A file larger than the stated limit was accepted",
                    Severity::Medium,
                    format!(
                        "securevibe.toml says the app accepts at most {most} bytes. A file larger \
                         than that was accepted at {} ({}).",
                        upload.path,
                        status(&answer)
                    ),
                ));
            }
        }
    }

    // 3. V5.2.2: contents that are not what the extension promises. Same extension as the ordinary
    //    file above, so a refusal can only be about what is inside it.
    let mismatched = Upload {
        id: "upload-mismatched",
        name: "sv-probe-not-really.gif",
        contents: "<?php echo 'sv-probe'; ?>\nthis is not a GIF at all\n".to_owned(),
    };
    let answer = send_upload(http, upload, &mismatched, session, &token);
    let refused = answer.as_ref().is_none_or(|r| r.status >= 400);
    out.steps.push(format!(
        "sent a .gif whose contents are not a GIF: {}",
        if refused { "refused" } else { "accepted" }
    ));
    if refused
        && !refusal_stands(
            http,
            upload,
            session,
            &token,
            "mismatched",
            "V5.2.2",
            "A .gif whose contents are not a GIF",
            out,
        )
    {
        // Not assessed, and said so.
    } else if refused {
        out.verified.push(crate::Verified::new(
            CONTENT_MISMATCH.rule_id,
            CONTENT_MISMATCH.requirement_ids,
            "a file named .gif whose contents are not a GIF, refused where a real GIF of the same \
             name and shape was accepted"
                .to_owned(),
        ));
    } else {
        out.findings.push(finding(
            &CONTENT_MISMATCH,
            "A file is accepted on the strength of its name",
            Severity::Medium,
            format!(
                "A file called `.gif` holding no GIF at all was accepted at {} ({}), where a real \
                 GIF was accepted too: nothing looked at the contents.",
                upload.path,
                status(&answer)
            ),
        ));
    }

    // 4. V1.3.4 and V5.4.3: an SVG image carrying a script, and the antivirus test file. Each can
    //    be answered by a refusal, so each is sent whether or not the app serves uploads back.
    svg_check(http, upload, session, &token, out);
    scan_check(http, upload, session, &token, out);
    traversal_check(http, upload, session, &token, out);

    // 5. V5.3.1 and V3.2.1: what the app does with an upload when it is fetched back.
    let Some(serves_at) = &upload.serves_at else {
        out.not_assessed.push((
            "V5.3.1, V3.2.1".to_owned(),
            "The `upload` entry has no `serves-at`, so nothing here could fetch an uploaded file \
             back. An app that never serves uploads over the web has nothing to get wrong here, \
             which is the safest arrangement and not a failure."
                .to_owned(),
        ));
        return;
    };
    served_upload_checks(http, upload, serves_at, session, &token, out);
    download_name_checks(http, upload, serves_at, session, &token, out);
}

/// The address one folder above where uploads are served, for a name: `/files/{name}` gives `/{name}`,
/// `/static/uploads/{name}` gives `/static/{name}`. `None` when there is no folder above to ask
/// for, or the name goes in a query rather than the path.
fn served_one_folder_up(serves_at: &str, name: &str) -> Option<String> {
    let (before, after) = serves_at.split_once("{name}")?;
    if before.contains('?') || !before.ends_with('/') {
        return None;
    }
    let folder = before.trim_end_matches('/');
    let parent = &folder[..folder.rfind('/')?];
    Some(format!("{parent}/{name}{after}"))
}

/// V5.3.2: a file whose name starts with `../`, and where it ends up.
///
/// The name and the contents carry a value made for this run, so a file left by an earlier run
/// cannot answer for this one. Refused, where an ordinary file was accepted, is credited: the app
/// would not use that name. Found one folder above where uploads are served is the finding: the
/// `../` was used to build the path. Found where uploads are served under the name without its
/// `../` is credited: the name was reduced to its last part. Found in neither is not assessed,
/// which is what an app that stores uploads under names of its own looks like, the safest
/// arrangement of all, and one nothing here can see.
fn traversal_check(
    http: &mut dyn Http,
    upload: &UploadSection,
    session: &Session,
    token: &Token,
    out: &mut Outcome,
) {
    let nonce = format!(
        "{:x}{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let base = format!("sv-probe-escaped-{nonce}.gif");
    let marker = format!("sv-probe-traversal-{nonce}");
    let file = Upload {
        id: "upload-traversal",
        name: &format!("../{base}"),
        contents: format!("{GIF_MAGIC}{marker}"),
    };
    let stored = send_upload(http, upload, &file, session, token);
    if refused(&stored) {
        let what = "A file named to land outside the upload folder";
        if !refusal_stands(
            http,
            upload,
            session,
            token,
            "traversal",
            "V5.3.2",
            what,
            out,
        ) {
            return;
        }
        out.steps
            .push("sent a file named `../…` to land outside the upload folder: refused".to_owned());
        out.verified.push(crate::Verified::new(
            UPLOAD_PATH_TRAVERSAL.rule_id,
            UPLOAD_PATH_TRAVERSAL.requirement_ids,
            format!(
                "a file named `../{base}`, refused at {} where an ordinary GIF was accepted",
                upload.path
            ),
        ));
        return;
    }
    let Some(serves_at) = &upload.serves_at else {
        out.not_assessed.push((
            "V5.3.2".to_owned(),
            "A file named to land outside the upload folder was accepted, and the `upload` entry \
             has no `serves-at`, so nothing here could look for where it was saved."
                .to_owned(),
        ));
        return;
    };
    let holds = |answer: &Option<ProbeResponse>| {
        answer
            .as_ref()
            .is_some_and(|r| r.status < 400 && r.body.contains(&marker))
    };
    if let Some(above) = served_one_folder_up(serves_at, &base) {
        let escaped = http.send(&get("upload-traversal-above", &above, session));
        if holds(&escaped) {
            out.steps.push(format!(
                "sent a file named `../{base}`: it was saved outside the upload folder, at {above}"
            ));
            out.findings.push(finding(
                &UPLOAD_PATH_TRAVERSAL,
                "An uploaded file's name decides where it is saved",
                Severity::High,
                format!(
                    "A file named `../{base}` uploaded to {} came back from {above}, one folder \
                     above where uploads are served, so the `../` in its name was used to build \
                     the path it was saved at.",
                    upload.path
                ),
            ));
            return;
        }
    }
    let inside = serves_at.replace("{name}", &base);
    let kept = http.send(&get("upload-traversal-inside", &inside, session));
    if holds(&kept) {
        out.steps.push(format!(
            "sent a file named `../{base}`: saved in the upload folder as `{base}`"
        ));
        out.verified.push(crate::Verified::new(
            UPLOAD_PATH_TRAVERSAL.rule_id,
            UPLOAD_PATH_TRAVERSAL.requirement_ids,
            format!(
                "a file named `../{base}`, uploaded to {} and found at {inside}, with the `../` \
                 taken off its name",
                upload.path
            ),
        ));
        return;
    }
    out.not_assessed.push((
        "V5.3.2".to_owned(),
        format!(
            "A file named `../{base}` was accepted, and found neither at {inside} nor one folder \
             above it, so where it was saved is not known. An app that saves uploads under names \
             of its own looks like this, which is the safest arrangement, and nothing here can see \
             it."
        ),
    ));
}

/// The EICAR antivirus test file: 68 harmless characters every antivirus scanner is built to
/// recognize, made for checking that a scanner is there at all.
///
/// Kept here as three pieces, each backwards, and put together only while the check runs, so
/// neither this source nor the `sv` binary holds it: a scanner on the owner's computer would
/// otherwise set aside the repository, or `sv` itself. For the same reason it is never written
/// into a report, a step, or a test's output.
pub(super) fn eicar() -> String {
    [
        "$}7)CC7)^P(45XZP\\4[PA@%P!O5X",
        "-SURIVITNA-DRADNATS-RACIE",
        "*H+H$!ELIF-TSET",
    ]
    .iter()
    .map(|piece| piece.chars().rev().collect::<String>())
    .collect()
}

/// Whether the app refused an upload: an error, or no answer at all. A crash reads the same way,
/// which `RESTS_ON_A_REFUSAL` answers for the passes that rest on one.
fn refused(answer: &Option<ProbeResponse>) -> bool {
    answer.as_ref().is_none_or(|r| r.status >= 400)
}

/// V1.3.4: an SVG image carrying a script, and whether the script is still in it when it comes
/// back.
///
/// The image has two ways to run code (a `<script>` and a `<foreignObject>` holding HTML) and one
/// harmless drawing (a `<circle>`). Refused is credited: an app that takes no SVG has disabled
/// the scriptable content V1.3.4 is about. Fetched back with the drawing and neither of the two is
/// credited for those two, which is not every dangerous SVG feature. Either one still there is a
/// finding. A file that comes back without the drawing either was changed into something else,
/// and is not judged.
fn svg_check(
    http: &mut dyn Http,
    upload: &UploadSection,
    session: &Session,
    token: &Token,
    out: &mut Outcome,
) {
    const MARKER: &str = "sv-probe-svg-marker-3d9e";
    // The drawing's own mark, which a cleaner that keeps the drawing keeps too: how the image is
    // told from anything else the address might answer with.
    const SHAPE: &str = "sv-probe-svg-shape-3d9e";
    let svg = Upload {
        id: "upload-svg",
        name: "sv-probe.svg",
        contents: format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>/*{MARKER}*/</script>\
             <foreignObject><div>{MARKER}</div></foreignObject><circle id=\"{SHAPE}\" \
             r=\"1\"/></svg>"
        ),
    };
    let stored = send_upload(http, upload, &svg, session, token);
    if refused(&stored) {
        let what = "An SVG image carrying a script";
        if !refusal_stands(http, upload, session, token, "svg", "V1.3.4", what, out) {
            return;
        }
        out.steps
            .push("sent an SVG image carrying a script: refused".to_owned());
        out.verified.push(crate::Verified::new(
            UPLOAD_SVG_SCRIPT.rule_id,
            UPLOAD_SVG_SCRIPT.requirement_ids,
            format!(
                "an SVG image carrying a script, refused at {} where an ordinary GIF was accepted",
                upload.path
            ),
        ));
        return;
    }
    let Some(serves_at) = &upload.serves_at else {
        out.not_assessed.push((
            "V1.3.4".to_owned(),
            "An SVG image carrying a script was accepted, and the `upload` entry has no \
             `serves-at`, so nothing here could fetch it back to see whether the script was kept."
                .to_owned(),
        ));
        return;
    };
    let path = serves_at.replace("{name}", svg.name);
    let fetched = http.send(&get("upload-svg-fetch", &path, session));
    let Some(fetched) = fetched.filter(|r| r.status < 400) else {
        out.not_assessed.push((
            "V1.3.4".to_owned(),
            format!(
                "An SVG image carrying a script was accepted but could not be fetched back from \
                 {path}, so nothing here saw whether the script was kept."
            ),
        ));
        return;
    };
    // What came back is the uploaded image only when it carries one of the image's own marks. A
    // page the app answers every address with is not it, and its `<script>` is not the image's
    // (the review of 1 to 4 October, item 12).
    if !fetched.body.contains(MARKER) && !fetched.body.contains(SHAPE) {
        out.not_assessed.push((
            "V1.3.4".to_owned(),
            format!(
                "What {path} answered is not the SVG image this check uploaded (none of its marks \
                 is in it), so `serves-at` may not be where the app keeps uploads, and nothing \
                 here saw whether the script was kept."
            ),
        ));
        return;
    }
    let body = fetched.body.to_lowercase();
    let kept: Vec<&str> = [
        ("<script", "its `<script>`"),
        ("<foreignobject", "its `<foreignObject>`"),
    ]
    .iter()
    .filter(|(tag, _)| body.contains(tag))
    .map(|(_, what)| *what)
    .collect();
    if !kept.is_empty() {
        let disposition = fetched
            .header("content-disposition")
            .unwrap_or_default()
            .to_lowercase();
        let csp = fetched
            .header("content-security-policy")
            .unwrap_or_default()
            .to_lowercase();
        let contained = disposition.contains("attachment") || csp.contains("sandbox");
        out.steps.push(format!(
            "fetched an uploaded SVG back from {path}: {} kept",
            kept.join(" and ")
        ));
        out.findings.push(finding(
            &UPLOAD_SVG_SCRIPT,
            "An uploaded SVG image keeps its script",
            if contained {
                Severity::Medium
            } else {
                Severity::High
            },
            format!(
                "An SVG image this check uploaded came back from {path} with {} still in it. {}",
                kept.join(" and "),
                if contained {
                    "It was served as an attachment or with a sandbox policy, so opening that \
                     address does not run it, but the file itself was not cleaned."
                } else {
                    "It was served for the browser to show, so opening that address runs the \
                     script as this app."
                }
            ),
        ));
    } else if fetched.body.contains(SHAPE) {
        out.steps.push(format!(
            "fetched an uploaded SVG back from {path}: cleaned, its drawing kept"
        ));
        out.verified.push(crate::Verified::new(
            UPLOAD_SVG_SCRIPT.rule_id,
            UPLOAD_SVG_SCRIPT.requirement_ids,
            format!(
                "an SVG image uploaded with a `<script>` and a `<foreignObject>`, fetched back from \
                 {path} with both removed and its drawing kept (these two, not every dangerous SVG \
                 feature)"
            ),
        ));
    } else {
        out.not_assessed.push((
            "V1.3.4".to_owned(),
            format!(
                "An SVG image carrying a script came back from {path} without its drawing either, \
                 so it was changed into something else and there was no SVG left to judge."
            ),
        ));
    }
}

/// V5.4.3: the antivirus test file, and whether the app keeps it and hands it back.
///
/// A plain text file of the same kind goes first, so a refusal can only be about the contents:
/// an app that takes no `.txt` files at all refuses both, and then nothing is said. The test file
/// served back unchanged is looked for again after a short wait, since a scanner may run a little
/// after the upload is stored.
fn scan_check(
    http: &mut dyn Http,
    upload: &UploadSection,
    session: &Session,
    token: &Token,
    out: &mut Outcome,
) {
    /// Seconds a scanner that runs after the upload is stored is given before the file is
    /// looked for again.
    const SCANNER_GRACE: u64 = 10;
    let plain = Upload {
        id: "upload-plain-text",
        name: "sv-probe-plain.txt",
        contents: "sv-probe: an ordinary text file, sent to show that text files are accepted.\n"
            .to_owned(),
    };
    let control = send_upload(http, upload, &plain, session, token);
    if refused(&control) {
        out.not_assessed.push((
            "V5.4.3".to_owned(),
            format!(
                "An ordinary text file was refused at {} ({}), so a refusal of the antivirus test \
                 file, also a text file, could not be told from a refusal of text files.",
                upload.path,
                status(&control)
            ),
        ));
        return;
    }
    let test_file = Upload {
        id: "upload-eicar",
        name: "sv-probe-eicar.txt",
        contents: eicar(),
    };
    let stored = send_upload(http, upload, &test_file, session, token);
    if refused(&stored) {
        let what = "The antivirus test file (EICAR)";
        if !refusal_stands(http, upload, session, token, "eicar", "V5.4.3", what, out) {
            return;
        }
        out.steps.push(
            "sent the antivirus test file (EICAR) after an ordinary text file: refused".to_owned(),
        );
        out.verified.push(crate::Verified::new(
            UPLOAD_NOT_SCANNED.rule_id,
            UPLOAD_NOT_SCANNED.requirement_ids,
            format!(
                "the antivirus test file (EICAR), refused at {} where an ordinary text file was \
                 accepted",
                upload.path
            ),
        ));
        return;
    }
    let Some(serves_at) = &upload.serves_at else {
        out.not_assessed.push((
            "V5.4.3".to_owned(),
            "The antivirus test file (EICAR) was accepted, and the `upload` entry has no \
             `serves-at`, so nothing here could see whether it was kept or set aside afterwards."
                .to_owned(),
        ));
        return;
    };
    let path = serves_at.replace("{name}", test_file.name);
    let unchanged = |answer: &Option<ProbeResponse>| {
        answer
            .as_ref()
            .is_some_and(|r| r.status < 400 && r.body == test_file.contents)
    };
    let first = http.send(&get("upload-eicar-fetch", &path, session));
    if !unchanged(&first) {
        out.not_assessed.push((
            "V5.4.3".to_owned(),
            format!(
                "The antivirus test file (EICAR) was accepted but did not come back unchanged from \
                 {path} ({}). It may have been set aside or cleaned, which would be right, or it may \
                 be served somewhere else; nothing here can tell which.",
                status(&first)
            ),
        ));
        return;
    }
    http.wait(SCANNER_GRACE);
    let again = http.send(&get("upload-eicar-fetch-again", &path, session));
    if !unchanged(&again) {
        out.not_assessed.push((
            "V5.4.3".to_owned(),
            format!(
                "The antivirus test file (EICAR) was accepted and served back unchanged from \
                 {path}, and {SCANNER_GRACE} seconds later it no longer was ({}). A scanner may \
                 have caught it after it was stored, but it was served in the meantime.",
                status(&again)
            ),
        ));
        return;
    }
    out.steps.push(format!(
        "sent the antivirus test file (EICAR): accepted, and served back unchanged from {path} \
         {SCANNER_GRACE} seconds later"
    ));
    out.findings.push(finding(
        &UPLOAD_NOT_SCANNED,
        "Uploaded files are not scanned for viruses",
        Severity::Medium,
        format!(
            "The antivirus test file (EICAR), which every antivirus scanner recognizes, was \
             accepted at {} and served back unchanged from {path}, both at once and \
             {SCANNER_GRACE} seconds later. A scanner that runs later than that would not show \
             here.",
            upload.path
        ),
    ));
}

/// The parameters of a `Content-Disposition` value, split on `;` the way RFC 6266 means it:
/// never inside a quoted string, and with `\"` inside one taken as a quote rather than its end.
///
/// A naive split on `;` would itself be the bug V5.4.2 is about, so it cannot be how the check
/// reads the header.
fn disposition_params(header: &str) -> Vec<(String, String)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in header.chars() {
        if escaped {
            current.push(c);
            escaped = false;
        } else if quoted && c == '\\' {
            current.push(c);
            escaped = true;
        } else if c == '"' {
            current.push(c);
            quoted = !quoted;
        } else if c == ';' && !quoted {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    parts.push(current);
    parts
        .iter()
        .filter_map(|p| {
            let (name, value) = p.split_once('=')?;
            Some((
                name.trim().to_lowercase(),
                value.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

/// The name a file comes back under (V5.4.1), and whether a hostile name can break the header it
/// comes back in (V5.4.2).
///
/// V5.4.1 is read off the ordinary GIF the upload check already put in: an upload fetched back is
/// a download, and the requirement asks that it be served under a name.
///
/// V5.4.2 needs a name built to break things. `sv-probe;svinjected=1.gif` is a legal file name
/// whose `;` and `=` would start a new header parameter if the app wrote the name into
/// `Content-Disposition` unquoted, and nothing else on earth sets a parameter called `svinjected`.
/// So the question becomes exact: after the round trip, does the header have a parameter by that
/// name?
fn download_name_checks(
    http: &mut dyn Http,
    upload: &UploadSection,
    serves_at: &str,
    session: &Session,
    token: &Token,
    out: &mut Outcome,
) {
    const HOSTILE: &str = "sv-probe;svinjected=1.gif";

    // ---- V5.4.1: the ordinary file, uploaded before any of this ran.
    let ordinary_path = serves_at.replace("{name}", "sv-probe.gif");
    match http.send(&get("download-ordinary", &ordinary_path, session)) {
        Some(r) if r.status < 400 => {
            let header = r
                .header("content-disposition")
                .unwrap_or_default()
                .to_owned();
            let named = disposition_params(&header)
                .iter()
                .any(|(k, v)| (k == "filename" || k == "filename*") && !v.is_empty());
            out.steps.push(format!(
                "fetched the ordinary upload back from {ordinary_path}: {}",
                if named {
                    "served under a name"
                } else {
                    "served with no file name"
                }
            ));
            if named {
                out.verified.push(crate::Verified::new(
                    "probe.download-unnamed",
                    &["V5.4.1"],
                    format!(
                        "an uploaded file fetched back from {ordinary_path} came with \
                         `Content-Disposition: {}`, naming the file",
                        header.trim()
                    ),
                ));
            } else {
                out.findings.push(finding(
                    &DOWNLOAD_UNNAMED,
                    "An uploaded file is served back without a file name",
                    Severity::Low,
                    format!(
                        "{ordinary_path} answered {} with {}, so nothing tells the browser what \
                         the file is called; it falls back to a name taken from the address.",
                        r.status,
                        if header.is_empty() {
                            "no `Content-Disposition` header".to_owned()
                        } else {
                            format!(
                                "`Content-Disposition: {}` and no file name in it",
                                header.trim()
                            )
                        }
                    ),
                ));
            }
        }
        answer => out.not_assessed.push((
            "V5.4.1".to_owned(),
            format!(
                "The ordinary upload could not be fetched back from {ordinary_path} ({}), so \
                 nothing here saw what name it is served under.",
                status(&answer)
            ),
        )),
    }

    // ---- V5.4.2: a name built to break the header.
    let hostile = Upload {
        id: "upload-hostile-name",
        name: HOSTILE,
        contents: format!("{GIF_MAGIC}sv-probe-hostile-name"),
    };
    let stored = send_upload(http, upload, &hostile, session, token);
    if stored.as_ref().is_none_or(|r| r.status >= 400) {
        out.not_assessed.push((
            "V5.4.2".to_owned(),
            format!(
                "The app refused a file named `{HOSTILE}` ({}), which is a sound thing to do with \
                 a name like that, but it means nothing here saw such a name served back.",
                status(&stored)
            ),
        ));
        return;
    }
    let path = serves_at.replace("{name}", HOSTILE);
    let fetched = http.send(&get("download-hostile", &path, session));
    let Some(fetched) = fetched.filter(|r| r.status < 400) else {
        out.not_assessed.push((
            "V5.4.2".to_owned(),
            format!(
                "A file named `{HOSTILE}` was accepted but could not be fetched back from {path}. \
                 The app may have stored it under a safer name, which would be right; either way \
                 nothing here saw the name served."
            ),
        ));
        return;
    };
    let header = fetched
        .header("content-disposition")
        .unwrap_or_default()
        .to_owned();
    let params = disposition_params(&header);
    let injected = params.iter().any(|(k, _)| k == "svinjected");
    let named = params
        .iter()
        .any(|(k, v)| (k == "filename" || k == "filename*") && !v.is_empty());
    out.steps.push(format!(
        "fetched a file named `{HOSTILE}` back: {}",
        if injected {
            "its name broke the header"
        } else if named {
            "its name was served intact"
        } else {
            "served with no file name"
        }
    ));
    if injected {
        out.findings.push(finding(
            &DOWNLOAD_NAME_INJECTED,
            "A file name is written into a response header unescaped",
            Severity::Medium,
            format!(
                "A file named `{HOSTILE}` came back from {path} with `Content-Disposition: {}`. The \
                 `;` in the name ended the file name and began a parameter of its own.",
                header.trim()
            ),
        ));
    } else if named {
        out.verified.push(crate::Verified::new(
            DOWNLOAD_NAME_INJECTED.rule_id,
            DOWNLOAD_NAME_INJECTED.requirement_ids,
            format!(
                "a file named `{HOSTILE}` fetched back from {path} with `Content-Disposition: {}`, \
                 its name kept inside the file name rather than starting a parameter",
                header.trim()
            ),
        ));
    } else {
        out.not_assessed.push((
            "V5.4.2".to_owned(),
            format!(
                "A file named `{HOSTILE}` came back from {path} with no file name in its \
                 headers, so there was no served name to judge."
            ),
        ));
    }
}

/// The two questions that need the file fetched back again.
fn served_upload_checks(
    http: &mut dyn Http,
    upload: &UploadSection,
    serves_at: &str,
    session: &Session,
    token: &Token,
    out: &mut Outcome,
) {
    // Server-side code, and a page. One file answers both only if the app serves it, so each is
    // uploaded and fetched on its own.
    const MARKER: &str = "sv-probe-upload-marker-7c31";
    let code = Upload {
        id: "upload-code",
        name: "sv-probe.php",
        contents: format!("<?php echo \"{MARKER}\"; ?>"),
    };
    let page = Upload {
        id: "upload-page-file",
        name: "sv-probe.html",
        contents: format!("<html><body>{MARKER}<script>1</script></body></html>"),
    };

    for (file, rule) in [(&code, &UPLOAD_EXECUTED), (&page, &UPLOAD_RENDERED)] {
        let stored = send_upload(http, upload, file, session, token);
        if stored.as_ref().is_none_or(|r| r.status >= 400) {
            // Refusing the file outright is a perfectly good answer, and a better one than serving
            // it safely — but it is not evidence about how uploads are served, so it is not a pass.
            out.not_assessed.push((
                rule.requirement_ids.join(", "),
                format!(
                    "The app refused `{}` ({}), which is a sound thing to do, but it means nothing \
                     here saw how an uploaded file of that kind is served.",
                    file.name,
                    status(&stored)
                ),
            ));
            continue;
        }
        let path = serves_at.replace("{name}", file.name);
        let Some(fetched) = http.send(&get(&format!("{}-fetch", file.id), &path, session)) else {
            out.not_assessed.push((
                rule.requirement_ids.join(", "),
                format!("Fetching the uploaded file back from {path} got no answer."),
            ));
            continue;
        };
        if fetched.status >= 400 {
            out.not_assessed.push((
                rule.requirement_ids.join(", "),
                format!(
                    "The file was accepted but {path} answered {}, so `serves-at` is not where \
                     this app serves uploads and nothing here saw one served.",
                    fetched.status
                ),
            ));
            continue;
        }

        // What came back is the uploaded file only when it carries its mark, whether as source, as
        // output, or as a page: an app that answers every address with its own page sends back
        // something else, which says nothing about how uploads are served (the review of 1 to 4
        // October, item 12).
        if !fetched.body.contains(MARKER) {
            out.not_assessed.push((
                rule.requirement_ids.join(", "),
                format!(
                    "What {path} answered is not the `{}` this check uploaded (its mark is not in \
                     it), so `serves-at` may not be where the app keeps uploads, and nothing here \
                     saw one served.",
                    file.name
                ),
            ));
            continue;
        }

        if std::ptr::eq(rule, &UPLOAD_EXECUTED) {
            // The source came back: not executed. Its output alone, without the source, is.
            let source_intact = fetched.body.contains("<?php");
            let ran = !source_intact && fetched.body.contains(MARKER);
            out.steps.push(format!(
                "fetched an uploaded .php back from {path}: {}",
                if ran {
                    "it had been run"
                } else {
                    "served as-is"
                }
            ));
            if ran {
                out.findings.push(finding(
                    &UPLOAD_EXECUTED,
                    "An uploaded file is executed as server-side code",
                    Severity::High,
                    format!(
                        "A `.php` file this check uploaded came back from {path} with its code \
                         gone and only its output left, so the server ran it."
                    ),
                ));
            } else {
                out.verified.push(crate::Verified::new(
                    UPLOAD_EXECUTED.rule_id,
                    UPLOAD_EXECUTED.requirement_ids,
                    format!(
                        "a `.php` file uploaded and fetched back from {path}, which came back as \
                         it was written rather than as its output"
                    ),
                ));
            }
        } else {
            // A page is safe when the browser is told not to render it as part of this app.
            let disposition = fetched
                .header("content-disposition")
                .unwrap_or_default()
                .to_lowercase();
            let content_type = fetched
                .header("content-type")
                .unwrap_or_default()
                .to_lowercase();
            let csp = fetched
                .header("content-security-policy")
                .unwrap_or_default()
                .to_lowercase();
            let attachment = disposition.contains("attachment");
            let sandboxed = csp.contains("sandbox");
            let not_html = !content_type.contains("text/html");
            let safe = attachment || sandboxed || not_html;
            let how = if attachment {
                "as an attachment"
            } else if sandboxed {
                "with a sandbox policy"
            } else {
                "as something other than a page"
            };
            out.steps.push(format!(
                "fetched an uploaded .html back from {path}: {}",
                if safe { how } else { "served as a page" }
            ));
            if safe {
                out.verified.push(crate::Verified::new(
                    UPLOAD_RENDERED.rule_id,
                    UPLOAD_RENDERED.requirement_ids,
                    format!("an uploaded HTML file, served back from {path} {how}"),
                ));
            } else {
                out.findings.push(finding(
                    &UPLOAD_RENDERED,
                    "An uploaded page is served for the browser to render",
                    Severity::High,
                    format!(
                        "An HTML file this check uploaded came back from {path} as \
                         `{content_type}` with no `Content-Disposition: attachment` and no sandbox \
                         policy, so a browser renders it as part of this app."
                    ),
                ));
            }
        }
    }
}

/// Whether the rules the form states are applied again on the server (V2.2.2).
///
/// The form's own HTML is the list of what the app says it wants: `maxlength`, `type=number`, and
/// `pattern`. Each of those is a rule a browser applies and anybody sending the request directly
/// does not have to. So the probe reads one off the sign-up page and sends a value that breaks it.
///
/// It establishes its setup first, as everything here does: a *correct* sign-up has to be accepted,
/// or "refused" means only that sign-up does not work. And it only ever produces a finding — an app
/// that refuses the broken value might be refusing it for some other reason, so refusing is not
/// proof that this rule in particular is applied.
pub(super) fn client_side_validation_check(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    out: &mut Outcome,
) {
    let Some(signup) = &users.signup else {
        out.not_assessed.push((
            "V2.2.2".to_owned(),
            "Whether the server applies the rules its own form states: this needs `signup` in \
             [stack.run.users], so a value that breaks one of them can be sent."
                .to_owned(),
        ));
        return;
    };
    // Which field the password goes in, so the constraint found is not the password's own.
    let password_fields: Vec<&str> = signup
        .form
        .iter()
        .filter(|(_, v)| v.contains("{password}"))
        .map(|(k, _)| k.as_str())
        .collect();

    let Some(page) = http.send(&get("validation-form", &signup.path, &Session::default())) else {
        return;
    };
    let session = {
        let mut s = Session::default();
        s.absorb(&page);
        s
    };

    // The first constraint the form states that this can break by sending a longer or non-numeric
    // value. `required` is not usable: leaving a field out is refused by almost everything.
    let mut broken: Option<(String, String, String)> = None;
    for tag in tags(&page.body, "input") {
        let Some(name) = attribute(&tag, "name") else {
            continue;
        };
        if password_fields.contains(&name.as_str()) || !signup.form.contains_key(&name) {
            continue;
        }
        if let Some(max) = attribute(&tag, "maxlength").and_then(|m| m.trim().parse::<usize>().ok())
            && (1..=512).contains(&max)
        {
            broken = Some((name, format!("maxlength={max}"), "a".repeat(max + 10)));
            break;
        }
        if attribute(&tag, "type").is_some_and(|t| t.eq_ignore_ascii_case("number")) {
            broken = Some((name, "type=number".to_owned(), "not-a-number".to_owned()));
            break;
        }
    }
    let Some((field, constraint, value)) = broken else {
        out.not_assessed.push((
            "V2.2.2".to_owned(),
            format!(
                "The sign-up page at {} states no rule in its own HTML that this could break \
                 (`maxlength` or `type=number` on a field securevibe.toml fills in), so there was \
                 nothing to send against.",
                signup.path
            ),
        ));
        return;
    };

    // Setup: an ordinary sign-up has to work, or a refusal below says nothing.
    let control = Account {
        user: format!("valid.{}", accounts.a.user),
        password: format!("Sv-Valid-{}-aZ9!", accounts.b.password.len()),
    };
    if sign_up(http, users, signup, "validation-control", &control).is_none_or(|r| r.status >= 400)
    {
        out.not_assessed.push((
            "V2.2.2".to_owned(),
            "An ordinary sign-up was not accepted, so a refusal of the broken value would say \
             nothing about the rule being applied."
                .to_owned(),
        ));
        return;
    }

    let broken_account = Account {
        user: format!("broken.{}", accounts.a.user),
        password: control.password.clone(),
    };
    let values = Values {
        user: &broken_account.user,
        password: &broken_account.password,
        csrf: csrf_token(&page, &session),
        ..Default::default()
    };
    let mut session = session.clone();
    let mut template = signup.clone();
    template.form.insert(field.clone(), value);
    let (response, _) = send_template(
        http,
        "validation-broken",
        &template,
        &values,
        &mut session,
        &[],
    );
    let accepted = response.as_ref().is_some_and(|r| r.status < 400);
    out.steps.push(format!(
        "sent `{field}` breaking the form's own {constraint}: {}",
        if accepted { "accepted" } else { "refused" }
    ));
    if accepted {
        out.findings.push(finding(
            &CLIENT_SIDE_VALIDATION,
            "A rule the form states is not applied on the server",
            Severity::Medium,
            format!(
                "The sign-up page says `{field}` must satisfy {constraint}. Sent directly, without \
                 a browser, a value breaking that was accepted ({}).",
                status(&response)
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::super::tests::with_signup;
    use super::*;

    #[test]
    fn a_rule_the_form_states_and_the_server_does_not_apply_is_found() {
        // Needs `signup`, so it is its own test rather than a row in the table below, which runs
        // against a fixture that has none.
        let flawed = run_with_users(
            Flaws {
                validation_only_in_browser: true,
                ..Default::default()
            },
            &with_signup(),
        );
        assert!(
            rule_ids(&flawed).contains(&CLIENT_SIDE_VALIDATION.rule_id),
            "{:?} / {:?}",
            rule_ids(&flawed),
            flawed.not_assessed
        );
        let correct = run_with_users(Flaws::default(), &with_signup());
        assert!(
            !rule_ids(&correct).contains(&CLIENT_SIDE_VALIDATION.rule_id),
            "an app that applies its own rule was accused: {:?}",
            rule_ids(&correct)
        );
        // Never credited: refusing the broken value might be a refusal for some other reason.
        assert!(!verified_ids(&correct).contains(&CLIENT_SIDE_VALIDATION.rule_id));
    }

    #[test]
    fn without_a_sign_up_the_form_rule_question_is_not_asked() {
        let o = run_against(Flaws::default(), &users());
        assert!(!rule_ids(&o).contains(&CLIENT_SIDE_VALIDATION.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V2.2.2" && why.contains("signup")),
            "{:?}",
            o.not_assessed
        );
    }
    // ---- Uploads (V5.2.1, V5.2.2, V5.3.1, V3.2.1)

    fn with_upload(serves_at: Option<&str>, max_bytes: Option<u64>) -> UsersSection {
        let mut u = users();
        u.upload = Some(sv_manifest::UploadSection {
            path: "/upload".into(),
            field: "file".into(),
            form: [("csrf_token".to_owned(), "{csrf}".to_owned())]
                .into_iter()
                .collect(),
            serves_at: serves_at.map(str::to_owned),
            max_bytes,
        });
        u
    }

    fn upload_run_keeping_app(flaws: Flaws, users: &UsersSection) -> (Outcome, FakeApp) {
        let mut app = FakeApp::new(flaws);
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        let out = run(&mut app, users, &acc, true, &Default::default());
        (out, app)
    }

    #[test]
    fn the_cap_is_about_what_is_sent_not_only_about_what_is_reported() {
        // The second reading of the cap, on the thing it is actually for. Saying "not assessed" is
        // the report half; the half that matters to somebody's app is that no enormous body ever
        // left this process, and no finding or note can show that.
        let (_, app) = upload_run_keeping_app(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(64 * 1024 * 1024)),
        );
        assert!(
            (app.largest_upload as u64) <= MOST_UPLOAD_BYTES,
            "sent {} bytes, past the {MOST_UPLOAD_BYTES}-byte cap",
            app.largest_upload
        );
        // And it really did send something, so this cannot pass by never uploading at all.
        assert!(app.largest_upload > 0, "nothing was sent");
    }

    #[test]
    fn serving_the_source_and_serving_its_output_are_told_apart() {
        // V5.3.1 turns on one distinction: the file came back as written, or only what running it
        // produced. Both bodies contain the marker, so anything keyed on the marker alone cannot
        // tell them apart — which is exactly the wrong check to write here.
        let safe = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            verified_ids(&safe).contains(&UPLOAD_EXECUTED.rule_id),
            "serving the source as-is should be credited: {:?}",
            safe.not_assessed
        );
        let unsafe_app = run_against(
            Flaws {
                runs_uploaded_code: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            rule_ids(&unsafe_app).contains(&UPLOAD_EXECUTED.rule_id),
            "serving only the output should be a finding: {:?}",
            rule_ids(&unsafe_app)
        );
        assert!(!verified_ids(&unsafe_app).contains(&UPLOAD_EXECUTED.rule_id));
    }

    #[test]
    fn any_one_of_the_three_ways_to_stop_a_browser_rendering_counts() {
        // V3.2.1 asks that the browser not render the file as part of this app, and names several
        // ways. Insisting on one of them would report apps that chose another; accepting none of
        // them would credit every app. Both halves are asserted here.
        let served_safely = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(verified_ids(&served_safely).contains(&UPLOAD_RENDERED.rule_id));
        let rendered = run_against(
            Flaws {
                renders_uploaded_pages: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            rule_ids(&rendered).contains(&UPLOAD_RENDERED.rule_id),
            "an uploaded page served as text/html with nothing else is a finding: {:?}",
            rule_ids(&rendered)
        );
        assert!(!verified_ids(&rendered).contains(&UPLOAD_RENDERED.rule_id));
    }

    #[test]
    fn a_disposition_header_is_split_the_way_rfc_6266_means_it() {
        // A `;` inside a quoted name is part of the name; outside quotes it starts a parameter.
        // Splitting naively on `;` would be the very bug V5.4.2 is about.
        let quoted = disposition_params(r#"attachment; filename="sv-probe;svinjected=1.gif""#);
        assert!(!quoted.iter().any(|(k, _)| k == "svinjected"), "{quoted:?}");
        assert!(
            quoted
                .iter()
                .any(|(k, v)| k == "filename" && v == "sv-probe;svinjected=1.gif")
        );

        let raw = disposition_params("attachment; filename=sv-probe;svinjected=1.gif");
        assert!(raw.iter().any(|(k, _)| k == "svinjected"), "{raw:?}");

        // An escaped quote stays inside the quoted string rather than ending it.
        let escaped = disposition_params(r#"attachment; filename="a\"b;svinjected=1.gif""#);
        assert!(
            !escaped.iter().any(|(k, _)| k == "svinjected"),
            "{escaped:?}"
        );

        let star = disposition_params("attachment; filename*=UTF-8''sv-probe%3Bsvinjected%3D1.gif");
        assert!(star.iter().any(|(k, _)| k == "filename*"));
        assert!(!star.iter().any(|(k, _)| k == "svinjected"));
    }

    #[test]
    fn a_download_is_named_and_a_hostile_name_does_not_break_its_header() {
        let o = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        for rule in [DOWNLOAD_UNNAMED.rule_id, DOWNLOAD_NAME_INJECTED.rule_id] {
            assert!(
                verified_ids(&o).contains(&rule),
                "{rule} was not confirmed: {:?}",
                o.not_assessed
            );
            assert!(
                !rule_ids(&o).contains(&rule),
                "{rule} also raised a finding"
            );
        }
    }

    #[test]
    fn each_download_fault_is_found_by_its_own_rule() {
        for (flaw, rule) in [
            (
                Flaws {
                    download_no_filename: true,
                    ..Default::default()
                },
                DOWNLOAD_UNNAMED.rule_id,
            ),
            (
                Flaws {
                    download_name_raw: true,
                    ..Default::default()
                },
                DOWNLOAD_NAME_INJECTED.rule_id,
            ),
        ] {
            let o = run_against(
                flaw,
                &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
            );
            let found = rule_ids(&o);
            assert!(found.contains(&rule), "{rule} did not fire: {found:?}");
            let other = if rule == DOWNLOAD_UNNAMED.rule_id {
                DOWNLOAD_NAME_INJECTED.rule_id
            } else {
                DOWNLOAD_UNNAMED.rule_id
            };
            assert!(
                !found.contains(&other),
                "{rule}'s fault also raised {other}"
            );
        }
    }

    #[test]
    fn a_quoted_name_with_a_semicolon_in_it_is_correct_and_credited() {
        // The second witness for reading the header properly, end to end. Quoting is enough under
        // RFC 6266 — the app does not have to clean the name as well — and a check that split on
        // every `;` would accuse this correct app of the exact fault it avoided.
        let o = run_against(
            Flaws {
                download_name_quoted_uncleaned: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            !rule_ids(&o).contains(&DOWNLOAD_NAME_INJECTED.rule_id),
            "a correctly quoted name was reported as injected: {:?}",
            rule_ids(&o)
        );
        assert!(verified_ids(&o).contains(&DOWNLOAD_NAME_INJECTED.rule_id));
    }

    #[test]
    fn the_run_note_says_when_a_name_broke_the_header() {
        // Second witness for the injection finding, on the surface the owner reads.
        let o = run_against(
            Flaws {
                download_name_raw: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        let note = o.steps.join(" | ");
        assert!(note.contains("its name broke the header"), "{note}");
        let fine = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(
            fine.steps
                .join(" | ")
                .contains("its name was served intact")
        );
    }

    #[test]
    fn the_run_note_says_when_a_download_has_no_name() {
        // Second witness for V5.4.1, on the note rather than the verdict: "served under a name" and
        // "served with no file name" are what the owner reads, and a check that stopped telling
        // them apart would leave the findings list looking clean.
        let unnamed = run_against(
            Flaws {
                download_no_filename: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        let note = unnamed.steps.join(" | ");
        assert!(note.contains("served with no file name"), "{note}");
        assert!(
            !note.contains("upload back from /files/sv-probe.gif: served under a name"),
            "{note}"
        );

        let named = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(named.steps.join(" | ").contains("served under a name"));
    }

    #[test]
    fn with_no_file_name_served_the_hostile_name_has_nothing_to_break() {
        // V5.4.2 is about a name that is served. When none is, there is nothing to judge, and the
        // absence is V5.4.1's finding to make, not V5.4.2's.
        let o = run_against(
            Flaws {
                download_no_filename: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        assert!(!rule_ids(&o).contains(&DOWNLOAD_NAME_INJECTED.rule_id));
        assert!(!verified_ids(&o).contains(&DOWNLOAD_NAME_INJECTED.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V5.4.2" && why.contains("no file name")),
            "{:?}",
            o.not_assessed
        );
    }

    /// The five upload rules a refusal can earn credit for.
    const CREDITED_ON_REFUSAL: [&str; 5] = [
        OVERSIZED_FILE.rule_id,
        CONTENT_MISMATCH.rule_id,
        UPLOAD_SVG_SCRIPT.rule_id,
        UPLOAD_NOT_SCANNED.rule_id,
        UPLOAD_PATH_TRAVERSAL.rule_id,
    ];

    /// A run with the upload form carrying a `title` of `{marker}`, against the app as `adjust`
    /// leaves it.
    fn upload_run_adjusted(flaws: Flaws, adjust: impl FnOnce(&mut FakeApp)) -> Outcome {
        let mut users = with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64));
        if let Some(upload) = &mut users.upload {
            upload
                .form
                .insert("title".to_owned(), "{marker}".to_owned());
        }
        let mut app = FakeApp::new(flaws);
        adjust(&mut app);
        let acc = accounts();
        app.users
            .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
        app.users
            .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
        let admin = acc.admin.clone().unwrap();
        app.users.insert(admin.user, (admin.password, true));
        run(&mut app, &users, &acc, true, &Default::default())
    }

    /// Every upload flaw a refusal could hide.
    fn accepts_everything() -> Flaws {
        Flaws {
            oversized_upload_ok: true,
            unchecked_contents_ok: true,
            svg_scripts_kept: true,
            no_malware_scan: true,
            upload_path_traversal: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_refusal_for_a_repeat_or_a_spent_token_is_not_the_file_refused() {
        for (what, adjust) in [
            (
                "repeats",
                (|a: &mut FakeApp| a.refuses_repeats = true) as fn(&mut FakeApp),
            ),
            ("single-use tokens", |a: &mut FakeApp| {
                a.single_use_tokens = true
            }),
        ] {
            // An app that takes every bad file, and would refuse the second upload on for a
            // reason of its own: each upload carries its own marker and a fresh token, so the
            // bad files are seen being taken.
            let o = upload_run_adjusted(accepts_everything(), adjust);
            for rule in [OVERSIZED_FILE.rule_id, CONTENT_MISMATCH.rule_id] {
                assert!(
                    rule_ids(&o).contains(&rule),
                    "{what}: {rule} not found: {:#?}",
                    o.steps
                );
            }
            for rule in CREDITED_ON_REFUSAL {
                assert!(!verified_ids(&o).contains(&rule), "{what}: {rule} credited");
            }
            // The control: a correct app with the same habit is credited for all five.
            let o = upload_run_adjusted(Flaws::default(), adjust);
            for rule in CREDITED_ON_REFUSAL {
                assert!(
                    verified_ids(&o).contains(&rule),
                    "{what}: {rule} not credited: {:#?}\n{:#?}",
                    o.steps,
                    o.not_assessed
                );
            }
        }
    }

    #[test]
    fn a_refusal_is_credited_only_when_an_ordinary_file_is_taken_straight_after() {
        // Full after the first file: every later upload is refused, the bad ones included, and
        // the ordinary one after each shows the refusal was the quota's.
        let o = upload_run_adjusted(accepts_everything(), |a| a.upload_quota = Some(1));
        for rule in CREDITED_ON_REFUSAL {
            assert!(
                !verified_ids(&o).contains(&rule),
                "{rule} credited: {:#?}",
                o.steps
            );
            assert!(!rule_ids(&o).contains(&rule), "{rule} found");
        }
        for id in ["V5.2.1", "V5.2.2", "V1.3.4", "V5.3.2", "V5.4.3"] {
            assert!(
                o.not_assessed.iter().any(|(ids, _)| ids.contains(id)),
                "{id} not said: {:#?}",
                o.not_assessed
            );
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("ordinary GIF sent straight after")),
            "{:#?}",
            o.not_assessed
        );
        // The control: room enough, and a correct app is credited for all five.
        let o = upload_run_adjusted(Flaws::default(), |a| a.upload_quota = Some(1000));
        for rule in CREDITED_ON_REFUSAL {
            assert!(
                verified_ids(&o).contains(&rule),
                "{rule}: {:#?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn a_correct_app_confirms_all_four_upload_questions() {
        let o = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        for rule in [
            OVERSIZED_FILE.rule_id,
            CONTENT_MISMATCH.rule_id,
            UPLOAD_EXECUTED.rule_id,
            UPLOAD_RENDERED.rule_id,
        ] {
            assert!(
                verified_ids(&o).contains(&rule),
                "{rule} was not confirmed: {:?} / {:?}",
                verified_ids(&o),
                o.not_assessed
            );
            assert!(
                !rule_ids(&o).contains(&rule),
                "{rule} also raised a finding"
            );
        }
    }

    #[test]
    fn each_upload_flaw_is_found_by_its_own_rule_and_by_no_other() {
        for (flaw, rule) in [
            (
                Flaws {
                    oversized_upload_ok: true,
                    ..Default::default()
                },
                OVERSIZED_FILE.rule_id,
            ),
            (
                Flaws {
                    unchecked_contents_ok: true,
                    ..Default::default()
                },
                CONTENT_MISMATCH.rule_id,
            ),
            (
                Flaws {
                    runs_uploaded_code: true,
                    ..Default::default()
                },
                UPLOAD_EXECUTED.rule_id,
            ),
            (
                Flaws {
                    renders_uploaded_pages: true,
                    ..Default::default()
                },
                UPLOAD_RENDERED.rule_id,
            ),
        ] {
            let o = run_against(
                flaw,
                &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
            );
            let found = rule_ids(&o);
            assert!(found.contains(&rule), "{rule} did not fire: {found:?}");
            let others: Vec<&str> = found
                .iter()
                .copied()
                .filter(|f| {
                    *f != rule
                        && [
                            OVERSIZED_FILE.rule_id,
                            CONTENT_MISMATCH.rule_id,
                            UPLOAD_EXECUTED.rule_id,
                            UPLOAD_RENDERED.rule_id,
                        ]
                        .contains(f)
                })
                .collect();
            assert!(others.is_empty(), "{rule}'s flaw also raised {others:?}");
        }
    }

    #[test]
    fn an_upload_that_refuses_everything_answers_nothing() {
        // The setup-first rule, and the one that matters most here: an app whose upload path is not
        // what securevibe.toml says refuses every file, and "refused" is what each of these checks
        // is looking for. Without the ordinary file first, a broken upload would read as four
        // passes — the most flattering possible result for the least working app.
        let o = run_against(
            Flaws {
                upload_broken: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        for rule in [
            OVERSIZED_FILE.rule_id,
            CONTENT_MISMATCH.rule_id,
            UPLOAD_EXECUTED.rule_id,
            UPLOAD_RENDERED.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&rule), "{rule} was credited");
            assert!(!rule_ids(&o).contains(&rule), "{rule} raised a finding");
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V5.2.1")
                    && ids.contains("V3.2.1")
                    && why.contains("ordinary file")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn the_run_note_never_claims_an_upload_that_did_not_happen() {
        // The second reading of the setup proof, on the surface the owner sees. The findings list
        // can be empty for two very different reasons — nothing was wrong, or nothing was asked —
        // and the run note is where those are told apart. An app that refused every file must not
        // leave a line saying a file went in.
        let broken = run_against(
            Flaws {
                upload_broken: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        let note = broken.steps.join(" | ");
        assert!(
            !note.contains("uploaded an ordinary"),
            "the note says a file was uploaded to an app that refused every one: {note}"
        );
        assert!(
            !note.contains("stated limit") && !note.contains("not a GIF"),
            "the note describes files that were never really tried: {note}"
        );

        // And the opposite, so this cannot pass by the note always being empty.
        let working = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(UPLOAD_LIMIT as u64)),
        );
        let note = working.steps.join(" | ");
        assert!(note.contains("uploaded an ordinary"), "{note}");
        assert!(note.contains("stated limit"), "{note}");
    }

    #[test]
    fn without_a_stated_size_the_oversize_question_is_not_asked() {
        // V5.2.1 is a documented-policy requirement like V6.3.1: prose cannot be checked, a number
        // can. With no number there is nothing to hold the app to, and the other three still run.
        let o = run_against(Flaws::default(), &with_upload(Some("/files/{name}"), None));
        assert!(!verified_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(!rule_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V5.2.1") && why.contains("max-bytes")),
            "{:?}",
            o.not_assessed
        );
        assert!(
            verified_ids(&o).contains(&CONTENT_MISMATCH.rule_id),
            "the other questions do not depend on the stated size"
        );
    }

    #[test]
    fn a_size_beyond_the_cap_is_refused_rather_than_sent() {
        // One check must not become a denial-of-service attempt against somebody's own app.
        let o = run_against(
            Flaws::default(),
            &with_upload(Some("/files/{name}"), Some(64 * 1024 * 1024)),
        );
        assert!(!verified_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(!rule_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V5.2.1") && why.contains("denial-of-service")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn without_serves_at_nothing_is_claimed_about_what_is_served() {
        // An app that stores uploads where no URL reaches them is the safest arrangement there is.
        // Reporting it as a failure, or as a pass, would both be wrong.
        let o = run_against(
            Flaws::default(),
            &with_upload(None, Some(UPLOAD_LIMIT as u64)),
        );
        for rule in [UPLOAD_EXECUTED.rule_id, UPLOAD_RENDERED.rule_id] {
            assert!(!verified_ids(&o).contains(&rule), "{rule} was credited");
            assert!(!rule_ids(&o).contains(&rule), "{rule} raised a finding");
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, _)| ids.contains("V5.3.1") && ids.contains("V3.2.1")),
            "{:?}",
            o.not_assessed
        );
        // The two that need no serving still ran.
        assert!(verified_ids(&o).contains(&OVERSIZED_FILE.rule_id));
        assert!(verified_ids(&o).contains(&CONTENT_MISMATCH.rule_id));
    }

    #[test]
    fn no_upload_entry_means_the_questions_are_never_raised() {
        // An app with no `upload` entry is not an app that failed these; it is one nobody asked.
        let o = run_against(Flaws::default(), &users());
        for rule in [
            OVERSIZED_FILE.rule_id,
            CONTENT_MISMATCH.rule_id,
            UPLOAD_EXECUTED.rule_id,
            UPLOAD_RENDERED.rule_id,
        ] {
            assert!(!verified_ids(&o).contains(&rule));
            assert!(!rule_ids(&o).contains(&rule));
        }
    }

    #[test]
    fn the_antivirus_test_file_is_the_standard_one_and_this_source_does_not_hold_it() {
        // Checked without printing it: a test's output is a file a scanner may read too.
        let file = eicar();
        assert_eq!(file.len(), 68);
        assert!(file.starts_with("X5O!") && file.ends_with("H+H*"));
        assert_eq!(file.bytes().map(u32::from).sum::<u32>(), 4622);
        assert!(
            !include_str!("uploads.rs").contains(file.as_str()),
            "found in uploads.rs"
        );
        assert!(
            !include_str!("fake_app.rs").contains(file.as_str()),
            "found in fake_app.rs"
        );
    }

    /// Every word of the outcome, to show the test file was never written into it.
    fn every_word(o: &Outcome) -> String {
        let mut all = o.steps.join("\n");
        for f in &o.findings {
            all.push_str(&f.description);
            all.push_str(&f.title);
        }
        for (ids, why) in &o.not_assessed {
            all.push_str(ids);
            all.push_str(why);
        }
        for v in &o.verified {
            all.push_str(&v.scope);
        }
        all
    }

    fn svg_verdict(flaws: Flaws, serves_at: Option<&str>) -> Outcome {
        upload_run_keeping_app(flaws, &with_upload(serves_at, None)).0
    }

    #[test]
    fn an_svg_cleaned_of_its_script_is_credited_for_those_parts() {
        let o = svg_verdict(Flaws::default(), Some("/files/{name}"));
        assert!(!rule_ids(&o).contains(&UPLOAD_SVG_SCRIPT.rule_id));
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == UPLOAD_SVG_SCRIPT.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(credit.scope.contains("both removed"), "{}", credit.scope);
        assert!(
            credit.scope.contains("not every dangerous SVG feature"),
            "{}",
            credit.scope
        );
    }

    #[test]
    fn an_svg_that_keeps_its_script_is_found_and_how_it_is_served_sets_how_serious() {
        for (attachment, severity, words) in [
            (false, Severity::High, "runs the script as this app"),
            (true, Severity::Medium, "the file itself was not cleaned"),
        ] {
            let o = svg_verdict(
                Flaws {
                    svg_scripts_kept: true,
                    svg_as_attachment: attachment,
                    ..Default::default()
                },
                Some("/files/{name}"),
            );
            let found = o
                .findings
                .iter()
                .find(|f| f.rule_id == UPLOAD_SVG_SCRIPT.rule_id)
                .unwrap_or_else(|| panic!("{:?}", o.steps));
            assert_eq!(found.severity, severity);
            assert!(
                found.description.contains("`<script>`"),
                "{}",
                found.description
            );
            assert!(
                found.description.contains("`<foreignObject>`"),
                "{}",
                found.description
            );
            assert!(found.description.contains(words), "{}", found.description);
            assert!(!verified_ids(&o).contains(&UPLOAD_SVG_SCRIPT.rule_id));
        }
    }

    #[test]
    fn an_svg_refused_is_credited_and_one_kept_unseen_is_not_assessed() {
        let o = svg_verdict(
            Flaws {
                refuses_svg: true,
                ..Default::default()
            },
            None,
        );
        assert!(
            verified_ids(&o).contains(&UPLOAD_SVG_SCRIPT.rule_id),
            "{:?}",
            o.steps
        );

        // Kept, with no `serves-at` to fetch it from: nothing seen, so nothing said.
        let o = svg_verdict(
            Flaws {
                svg_scripts_kept: true,
                ..Default::default()
            },
            None,
        );
        assert!(!rule_ids(&o).contains(&UPLOAD_SVG_SCRIPT.rule_id));
        assert!(!verified_ids(&o).contains(&UPLOAD_SVG_SCRIPT.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V1.3.4" && why.contains("no `serves-at`")),
            "{:?}",
            o.not_assessed
        );
    }

    fn traversal_verdict(flaws: Flaws, serves_at: Option<&str>) -> Outcome {
        upload_run_keeping_app(flaws, &with_upload(serves_at, None)).0
    }

    fn v532(o: &Outcome) -> Vec<&String> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids == "V5.3.2")
            .map(|(_, why)| why)
            .collect()
    }

    #[test]
    fn a_name_that_climbs_out_of_the_upload_folder_is_found() {
        let o = traversal_verdict(
            Flaws {
                upload_path_traversal: true,
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == UPLOAD_PATH_TRAVERSAL.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert_eq!(found.requirement_ids, ["V5.3.2"]);
        assert_eq!(found.severity, Severity::High);
        assert!(
            found.description.contains("one folder"),
            "{}",
            found.description
        );
        assert!(!verified_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id));
    }

    #[test]
    fn a_page_the_app_answers_every_address_with_is_not_the_uploaded_file() {
        // The review of 1 to 4 October, item 12: an app that keeps uploads under names of its own
        // and answers unknown addresses with its page (and its `<script>`) was credited for not
        // running the .php, and found to render the .html and keep the SVG's script.
        let o = upload_run_keeping_app(
            Flaws {
                renames_every_upload: true,
                answers_every_path: true,
                ..Default::default()
            },
            &with_upload(Some("/files/{name}"), None),
        )
        .0;
        for rule in [&UPLOAD_EXECUTED, &UPLOAD_RENDERED, &UPLOAD_SVG_SCRIPT] {
            assert!(
                !rule_ids(&o).contains(&rule.rule_id),
                "{} found: {:?}",
                rule.rule_id,
                o.steps
            );
            assert!(
                !verified_ids(&o).contains(&rule.rule_id),
                "{} credited: {:?}",
                rule.rule_id,
                o.steps
            );
        }
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("is not the") && why.contains("this check uploaded")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_name_cut_to_its_last_part_or_refused_is_credited() {
        // Cut to its last part, the default, as `secure_filename` does.
        let o = traversal_verdict(Flaws::default(), Some("/files/{name}"));
        assert!(!rule_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id));
        let credit = o
            .verified
            .iter()
            .find(|v| v.check_id == UPLOAD_PATH_TRAVERSAL.rule_id)
            .unwrap_or_else(|| panic!("{:?} {:?}", o.steps, v532(&o)));
        assert!(
            credit.scope.contains("taken off its name"),
            "{}",
            credit.scope
        );

        // Refused, with or without a `serves-at`: a refusal needs nothing fetched back.
        for serves_at in [Some("/files/{name}"), None] {
            let o = traversal_verdict(
                Flaws {
                    refuses_path_names: true,
                    ..Default::default()
                },
                serves_at,
            );
            let credit = o
                .verified
                .iter()
                .find(|v| v.check_id == UPLOAD_PATH_TRAVERSAL.rule_id)
                .unwrap_or_else(|| panic!("{:?}", o.steps));
            assert!(credit.scope.contains("refused"), "{}", credit.scope);
        }
    }

    #[test]
    fn a_name_saved_where_nothing_can_see_it_settles_nothing() {
        // Saved under a name of the app's own: the safest arrangement, and invisible.
        let o = traversal_verdict(
            Flaws {
                renames_path_names: true,
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        assert!(!rule_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id));
        assert!(!verified_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id));
        assert!(
            v532(&o).iter().any(|why| why.contains("names of its own")),
            "{:?}",
            o.not_assessed
        );
        // Accepted, and no `serves-at` to look with: even the flaw is not seen, and not passed.
        let o = traversal_verdict(
            Flaws {
                upload_path_traversal: true,
                ..Default::default()
            },
            None,
        );
        assert!(!rule_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id));
        assert!(!verified_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id));
        assert!(v532(&o).iter().any(|why| why.contains("no `serves-at`")));
        // An app that answers every address with its own page: an answer is not the file, so
        // neither place is read as holding it.
        let o = traversal_verdict(
            Flaws {
                renames_path_names: true,
                answers_every_path: true,
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        assert!(
            !rule_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            !verified_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id),
            "{:?}",
            o.steps
        );
        assert!(v532(&o).iter().any(|why| why.contains("names of its own")));
        // An upload that does not work at all: nothing about names is said.
        let o = traversal_verdict(
            Flaws {
                upload_broken: true,
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        assert!(!verified_ids(&o).contains(&UPLOAD_PATH_TRAVERSAL.rule_id));
    }

    #[test]
    fn one_folder_up_is_worked_out_from_where_uploads_are_served() {
        assert_eq!(
            served_one_folder_up("/files/{name}", "x.gif").as_deref(),
            Some("/x.gif")
        );
        assert_eq!(
            served_one_folder_up("/static/uploads/{name}", "x.gif").as_deref(),
            Some("/static/x.gif")
        );
        assert_eq!(
            served_one_folder_up("/u/{name}?download=1", "x.gif").as_deref(),
            Some("/x.gif?download=1")
        );
        // At the top already, in a query, or in the middle of a segment: no folder above to ask.
        assert_eq!(served_one_folder_up("/{name}", "x.gif"), None);
        assert_eq!(served_one_folder_up("/download?name={name}", "x.gif"), None);
        assert_eq!(served_one_folder_up("/files/f-{name}", "x.gif"), None);
        assert_eq!(served_one_folder_up("/files/", "x.gif"), None);
    }

    #[test]
    fn each_run_names_its_file_afresh() {
        // A file an earlier run left behind must not answer for this one.
        let names = |o: &Outcome| -> Vec<String> {
            o.steps
                .iter()
                .filter_map(|s| s.split("`../").nth(1))
                .map(|rest| rest.split('`').next().unwrap_or_default().to_owned())
                .collect()
        };
        let first = names(&traversal_verdict(Flaws::default(), Some("/files/{name}")));
        let second = names(&traversal_verdict(Flaws::default(), Some("/files/{name}")));
        assert_eq!(first.len(), 1, "the setup: the step names the file");
        assert_ne!(first, second);
    }

    fn scan_verdict(flaws: Flaws, serves_at: Option<&str>) -> (Outcome, FakeApp) {
        upload_run_keeping_app(flaws, &with_upload(serves_at, None))
    }

    fn scan_not_assessed(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(ids, _)| ids == "V5.4.3")
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn the_antivirus_test_file_refused_after_a_text_file_is_credited() {
        let (o, app) = scan_verdict(Flaws::default(), Some("/files/{name}"));
        assert!(
            app.clock_log.iter().any(|(id, _)| id == "upload-eicar"),
            "the test file was sent"
        );
        assert!(
            verified_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!rule_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id));
        assert!(
            !every_word(&o).contains(eicar().as_str()),
            "the test file is in the outcome"
        );
    }

    #[test]
    fn the_antivirus_test_file_kept_and_served_is_found_without_being_repeated() {
        let (o, _) = scan_verdict(
            Flaws {
                no_malware_scan: true,
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == UPLOAD_NOT_SCANNED.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(
            found.description.contains("10 seconds later"),
            "{}",
            found.description
        );
        assert!(!verified_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id));
        assert!(
            !every_word(&o).contains(eicar().as_str()),
            "the test file is in the outcome"
        );
    }

    #[test]
    fn a_scanner_that_runs_after_storing_is_given_a_moment_and_not_blamed_or_credited() {
        // Caught within the wait: served for a while, so not credited, and not found either.
        let (o, _) = scan_verdict(
            Flaws {
                scans_after: Some(5),
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        assert!(
            !rule_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id));
        let why = scan_not_assessed(&o);
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(why[0].contains("no longer was"), "{}", why[0]);

        // Slower than the wait: it reads as no scanner, and the finding says so.
        let (o, _) = scan_verdict(
            Flaws {
                scans_after: Some(600),
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        let found = o
            .findings
            .iter()
            .find(|f| f.rule_id == UPLOAD_NOT_SCANNED.rule_id)
            .unwrap_or_else(|| panic!("{:?}", o.steps));
        assert!(
            found.description.contains("runs later than that"),
            "{}",
            found.description
        );
    }

    #[test]
    fn an_app_that_takes_no_text_files_is_not_credited_with_a_scanner() {
        let (o, _) = scan_verdict(
            Flaws {
                refuses_text: true,
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        assert!(
            !verified_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id),
            "{:?}",
            o.steps
        );
        let why = scan_not_assessed(&o);
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(
            why[0].contains("ordinary text file was refused"),
            "{}",
            why[0]
        );
    }

    #[test]
    fn the_antivirus_test_file_kept_with_nowhere_to_fetch_it_is_not_assessed() {
        let (o, _) = scan_verdict(
            Flaws {
                no_malware_scan: true,
                ..Default::default()
            },
            None,
        );
        assert!(!rule_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id));
        assert!(!verified_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id));
        let why = scan_not_assessed(&o);
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(why[0].contains("was accepted"), "{}", why[0]);
    }

    #[test]
    fn an_svg_turned_into_something_else_is_not_judged() {
        let o = svg_verdict(
            Flaws {
                svg_converted: true,
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        assert!(!rule_ids(&o).contains(&UPLOAD_SVG_SCRIPT.rule_id));
        assert!(
            !verified_ids(&o).contains(&UPLOAD_SVG_SCRIPT.rule_id),
            "{:?}",
            o.steps
        );
        assert!(
            o.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V1.3.4" && why.contains("is not the SVG image")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_scanner_that_cleans_the_file_is_neither_blamed_nor_credited() {
        // Accepted, and served back, but not as it was sent: the app did something to it, and
        // this check cannot tell a scanner's cleaning from anything else.
        let (o, _) = scan_verdict(
            Flaws {
                scan_cleans: true,
                ..Default::default()
            },
            Some("/files/{name}"),
        );
        assert!(
            !rule_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id),
            "{:?}",
            o.steps
        );
        assert!(!verified_ids(&o).contains(&UPLOAD_NOT_SCANNED.rule_id));
        let why = scan_not_assessed(&o);
        assert_eq!(why.len(), 1, "{:?}", o.not_assessed);
        assert!(why[0].contains("did not come back unchanged"), "{}", why[0]);
    }
}
