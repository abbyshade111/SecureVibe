use super::*;

pub(crate) struct Rule {
    pub(crate) rule_id: &'static str,
    pub(crate) requirement_ids: &'static [&'static str],
    pub(crate) cwe: &'static [&'static str],
    pub(crate) impact: &'static str,
    pub(crate) fix: &'static str,
}

pub(crate) fn finding(
    rule: &Rule,
    title: &str,
    severity: Severity,
    description: String,
) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        marked_test_code: false,
        rule_id: rule.rule_id.to_owned(),
        title: title.to_owned(),
        severity,
        confidence: Confidence::High,
        location: Location {
            file: "the running app".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: rule
            .requirement_ids
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        cwe: rule.cwe.iter().map(|s| (*s).to_owned()).collect(),
        description,
        impact: rule.impact.to_owned(),
        fix: rule.fix.to_owned(),
    }
}

pub(super) const PRIVATE_PAGE: Rule = Rule {
    rule_id: "probe.private-page-anonymous",
    requirement_ids: &["V8.2.1"],
    cwe: &["CWE-862"],
    impact: "Anybody can open a page meant only for people who have signed in, without signing in.",
    fix: "Require a signed-in session on the server for every page that shows a user's own things, \
          and send anyone without one to the sign-in page.",
};

pub(super) const ADMIN_PAGE: Rule = Rule {
    rule_id: "probe.admin-page-ordinary-user",
    // V8.3.1 (authorization enforced on the server) is on `manualOnly` at the owner's word, so a
    // refusal only supports the owner's answer: one page refused is not every rule enforced, and
    // actions sent straight to an API are not tried. An admin page that opens is a finding against
    // both.
    requirement_ids: &["V8.2.1", "V8.3.1"],
    cwe: &["CWE-285"],
    impact: "An ordinary account can open a page meant only for administrators, so anyone who signs \
             up can do what an administrator does there.",
    fix: "Check the signed-in user's role on the server before serving an admin page or acting on \
          an admin request; hiding the link is not a check.",
};

pub(super) const ADMIN_ACTION: Rule = Rule {
    rule_id: "probe.admin-action-ordinary-user",
    // Beside the admin page, and for the same reason: V8.3.1 is on `manualOnly`, so an action refused
    // supports the owner's answer and does not settle it. One the ordinary user got done is a
    // finding against both.
    requirement_ids: &["V8.2.1", "V8.3.1"],
    cwe: &["CWE-285"],
    impact: "An ordinary account can do something only an administrator should be able to do, by \
             sending the request itself. Hiding the button does not stop that.",
    fix: "Check the signed-in user's role on the server when the request arrives, for every admin \
          action, not only on the page that shows the button for it.",
};

pub(super) const ROLE_FIELD: Rule = Rule {
    rule_id: "probe.role-field-trusted",
    // V8.3.1 names exactly this: an authorization decision resting on something the client can
    // change. V15.3.3 is mass assignment: a field set that the action was never meant to take.
    // V8.2.3 is field-level access (BOPLA): a user writing a field they have no permission to. Only
    // ever a finding: five guessed field names refused say nothing about a sixth.
    requirement_ids: &["V8.3.1", "V15.3.3", "V8.2.3"],
    cwe: &["CWE-915", "CWE-269"],
    impact: "Anybody who signs up can make themselves an administrator by adding one field to the \
             sign-up form, which takes a browser's developer tools and no skill.",
    fix: "Take only the fields sign-up is meant to set (name, email, password) and ignore or refuse \
          the rest; set a new account's role on the server, never from the request.",
};

pub(super) const OTHER_USERS_DATA: Rule = Rule {
    rule_id: "probe.other-users-data",
    requirement_ids: &["V8.2.2"],
    cwe: &["CWE-639"],
    impact: "Changing a number in the address is enough to read what another person saved, which is \
             how most data leaks from web apps happen.",
    fix: "Look records up by their owner as well as their id — `where id = ? and owner = ?` — so a \
          record that is not yours is simply not found.",
};

/// A private page that tells shared caches they may keep it (V14.2.2).
pub(super) const PRIVATE_PAGE_HEADERS: Rule = Rule {
    rule_id: "probe.private-page-headers",
    // The same four headers `probe.security-headers` asks of the pages a stranger sees, asked of the
    // pages a signed-in person sees, which are the ones that show somebody's own data.
    requirement_ids: &["V3.4.3", "V3.4.4", "V3.4.5", "V3.4.6"],
    cwe: &["CWE-693", "CWE-1021"],
    impact: "These are the instructions a browser follows to protect the person using the app, and \
             a private page is where a page somebody else wrote could do the most: read what the \
             person sees and act as them.",
    fix: "Set them once, in whatever sits in front of every response, signed in or not, rather \
          than per route.",
};

pub(super) const PRIVATE_PAGE_SHARED_CACHE: Rule = Rule {
    rule_id: "probe.private-page-shared-cache",
    // V14.2.2 asks that sensitive data is kept out of server-side caches such as load balancers.
    // `public` or `s-maxage` on a signed-in page tells exactly those caches they may keep it. Only
    // ever a finding: a page without them can still be cached by a server this cannot see.
    requirement_ids: &["V14.2.2"],
    cwe: &["CWE-525"],
    impact: "A shared cache in front of the app, such as a load balancer or a content delivery \
             network, may keep one person's private page and hand it to the next person who asks \
             for the same address.",
    fix: "Send `Cache-Control: private, no-store` on every page that shows somebody's own data, \
          and never `public` or `s-maxage` on one.",
};

pub(super) const PRIVATE_PAGE_CACHING: Rule = Rule {
    rule_id: "probe.private-page-cached",
    requirement_ids: &["V14.3.2"],
    cwe: &["CWE-525"],
    impact: "A private page a browser is allowed to store stays on the machine after the person \
             signs out, where the next person to press Back can read it — which is what shared and \
             public computers make ordinary.",
    fix: "Send `Cache-Control: no-store` on every response that shows somebody's own data. \
          `no-cache` is not the same thing: it allows the copy to be kept and asks for it to be \
          revalidated.",
};

pub(super) const SIGN_OUT_LINK: Rule = Rule {
    rule_id: "probe.no-sign-out-link",
    requirement_ids: &["V7.4.4"],
    cwe: &["CWE-613"],
    impact: "Somebody who cannot find how to sign out stays signed in, and a session left open on \
             a shared machine is the next person's session.",
    fix: "Put a visible sign-out control on every page that needs signing in — a link to the \
          sign-out address, or a small form that posts to it.",
};

pub(super) const OVERSIZED_FILE: Rule = Rule {
    rule_id: "probe.oversized-file-accepted",
    requirement_ids: &["V5.2.1"],
    cwe: &["CWE-400"],
    impact: "A file larger than the app says it accepts was taken anyway, so anybody can fill the \
             disk or tie the app up processing something enormous.",
    fix: "Refuse a request whose body is larger than the limit before reading it \
          \u{2014} in the web server or the framework, not after the file is already in memory.",
};

pub(super) const CONTENT_MISMATCH: Rule = Rule {
    rule_id: "probe.file-contents-unchecked",
    requirement_ids: &["V5.2.2"],
    cwe: &["CWE-434"],
    impact: "A file is trusted on the strength of its name. Something that is not an image at all \
             can be stored, and later served, as though it were one.",
    fix: "Read the first bytes of the file and check they are what the extension promises, with a \
          library for the type rather than by hand.",
};

pub(super) const UPLOAD_SVG_SCRIPT: Rule = Rule {
    rule_id: "probe.uploaded-svg-keeps-script",
    requirement_ids: &["V1.3.4"],
    cwe: &["CWE-79"],
    impact: "An SVG image can carry a script. Stored as it came in and opened from this app's own \
             address, it runs as the app for whoever opens it, with their cookies.",
    fix: "Refuse SVG uploads if the app does not need them. If it does, clean each one with an SVG \
          sanitizer (DOMPurify with its SVG profile, or svg-sanitizer) before storing it, and serve \
          uploads with `Content-Disposition: attachment` or a `Content-Security-Policy: sandbox` \
          header as well.",
};

pub(super) const UPLOAD_PATH_TRAVERSAL: Rule = Rule {
    rule_id: "probe.upload-path-traversal",
    requirement_ids: &["V5.3.2"],
    cwe: &["CWE-22"],
    impact: "The app builds where it saves an upload from the name the uploader chose. A name starting \
             `../` puts the file outside the upload folder, so whoever uploads can write files where \
             the app keeps its own: over a page it serves, or a script it runs.",
    fix: "Never use the uploaded name to build the path. Store each file under a name the app makes \
          (a random id), keep the original only as data, or at least reduce it to its last part \
          (`werkzeug.utils.secure_filename`, `path.basename`) before using it.",
};

pub(super) const UPLOAD_NOT_SCANNED: Rule = Rule {
    rule_id: "probe.upload-not-scanned",
    requirement_ids: &["V5.4.3"],
    cwe: &["CWE-434"],
    impact: "Nothing checks uploaded files for known malicious content, so a file carrying a known \
             virus is kept and handed to whoever downloads it next.",
    fix: "Scan each uploaded file with antivirus software before keeping it: your host's upload \
          service may offer this, or a scanner such as ClamAV can be added. Refuse or set aside \
          what it flags.",
};

pub(super) const UPLOAD_EXECUTED: Rule = Rule {
    rule_id: "probe.uploaded-file-executed",
    requirement_ids: &["V5.3.1"],
    cwe: &["CWE-434"],
    impact: "Code somebody uploaded runs on the server when the file is fetched. This is the whole \
             app, and usually the machine: it is the most serious thing an upload can do wrong.",
    fix: "Keep uploads outside the folder the web server serves, hand them back through code that \
          reads and sends the bytes, and never let the server execute anything in that folder.",
};

pub(super) const UPLOAD_RENDERED: Rule = Rule {
    rule_id: "probe.uploaded-file-rendered",
    requirement_ids: &["V3.2.1"],
    cwe: &["CWE-79"],
    impact: "A page somebody uploaded is shown by the browser as part of this app, so a script in \
             it runs with the app's cookies and can do whatever the signed-in person can.",
    fix: "Serve uploads with `Content-Disposition: attachment`, or with a \
          `Content-Security-Policy: sandbox` header, or from a different hostname \
          \u{2014} any one stops the browser treating the file as a page of this app.",
};

pub(super) const DOWNLOAD_UNNAMED: Rule = Rule {
    rule_id: "probe.download-unnamed",
    requirement_ids: &["V5.4.1"],
    cwe: &["CWE-116"],
    impact: "The browser names the file from the address instead, which is whatever the person who \
             uploaded it chose, and a name somebody else chose is the start of most download tricks.",
    fix: "Send `Content-Disposition: attachment; filename=\"...\"` with a name the app made or \
          cleaned, not the one that came in with the upload.",
};

pub(super) const DOWNLOAD_NAME_INJECTED: Rule = Rule {
    rule_id: "probe.download-name-injected",
    requirement_ids: &["V5.4.2"],
    cwe: &["CWE-113"],
    impact: "Whoever names the file writes part of the response header, and can change how the \
             browser handles the download, or what it thinks the file is.",
    fix: "Quote the name and escape what is inside it (RFC 6266), or better, send \
          `filename*=UTF-8''` with the name percent-encoded; most frameworks have a helper for \
          exactly this.",
};

pub(super) const CLIENT_SIDE_VALIDATION: Rule = Rule {
    rule_id: "probe.validation-only-in-the-browser",
    requirement_ids: &["V2.2.2"],
    cwe: &["CWE-602"],
    impact: "The rule the form shows a person is not applied on the server, so anybody sending the \
             request directly \u{2014} which takes no special tools \u{2014} can put in whatever \
             they like.",
    fix: "Apply every rule the form states again on the server, and refuse the request when it \
          does not hold. The form's own attributes are a good list of what to check.",
};

pub(super) const SESSION_TOKEN_UNVERIFIED: Rule = Rule {
    rule_id: "probe.session-token-unverified",
    requirement_ids: &["V7.2.1"],
    cwe: &["CWE-290"],
    impact: "A session value this check invented opened a private page, so the app is believing \
             the cookie rather than checking it. Anybody can make one up.",
    fix: "Look the session up on the server on every request \u{2014} in the session store, or by \
          verifying the token's signature \u{2014} and refuse it when it is not found.",
};

pub(super) const SQL_INJECTION: Rule = Rule {
    rule_id: "probe.sql-injection",
    requirement_ids: &["V1.2.4"],
    cwe: &["CWE-89"],
    impact: "Part of a web address the app reads changed what its database did: the same request \
             with an always-true condition added was answered differently from one with an \
             always-false condition. The app is joining what it was sent into a database query, \
             so anybody can rewrite that query: read other people's records, or worse.",
    fix: "Pass what the request sends to the database as a parameter (a placeholder such as `?` \
          or `$1`, or the query builder of the app's database library), never by joining it into \
          the text of the query.",
};

pub(super) const APP_TOKEN_UNSIGNED: Rule = Rule {
    rule_id: "probe.app-token-signature-not-checked",
    requirement_ids: &["V9.1.1"],
    cwe: &["CWE-347"],
    impact: "The app's own sign-in token, with something added to what it says and the signature \
             left as it was, opened a private page. The app is reading the token without checking \
             its signature, so anybody can write one that says they are somebody else.",
    fix: "Check the token's signature with the app's key before reading anything in it, on every \
          request, and refuse it when the signature does not match. Most token libraries do this \
          in their `verify` function; `decode` alone usually does not.",
};

pub(super) const APP_TOKEN_ALG_NONE: Rule = Rule {
    rule_id: "probe.app-token-alg-none",
    requirement_ids: &["V9.1.2"],
    cwe: &["CWE-347"],
    impact: "The app's own sign-in token, marked as needing no signature (`alg: none`) and sent \
             with none, opened a private page. Anybody can write such a token.",
    fix: "Tell the token library which signing method the app uses (for example `algorithms: \
          ['HS256']`), so it refuses every other, `none` included.",
};

pub(super) const APP_TOKEN_EXPIRED: Rule = Rule {
    rule_id: "probe.app-token-expired-accepted",
    requirement_ids: &["V9.2.1"],
    cwe: &["CWE-613"],
    impact: "The app's own sign-in token still opened a private page more than a minute after the \
             time written in it as its expiry (`exp`). A token copied or stolen once keeps working \
             after it should have run out.",
    fix: "Check the token's `exp` time on every request, as token libraries do by default, and do \
          not switch that check off.",
};

pub(super) const WS_WITHOUT_SESSION: Rule = Rule {
    rule_id: "probe.websocket-without-session",
    requirement_ids: &["V4.4.4"],
    cwe: &["CWE-306"],
    impact: "A WebSocket meant for signed-in users that opens without a real session hands whatever \
             it carries to anybody who connects — no sign-in, no password.",
    fix: "Check the session during the handshake, the same way a private page does, and refuse the \
          upgrade when there is none; or hand out a short-lived token from a signed-in request and \
          require it.",
};

pub(super) const WS_FOREIGN_ORIGIN: Rule = Rule {
    // The anonymous probe's rule, asked here of a socket that needs a sign-in, which that probe
    // cannot open.
    rule_id: "probe.websocket-origin-unchecked",
    requirement_ids: &["V4.4.2"],
    cwe: &["CWE-1385"],
    impact: "Browsers do not stop cross-site WebSocket connections the way they stop other \
             cross-site requests, so another site can open this one as the signed-in visitor and \
             read what comes back.",
    fix: "Compare the handshake's `Origin` with the app's own origins and refuse the rest.",
};

pub(super) const WS_AFTER_SIGN_OUT: Rule = Rule {
    rule_id: "probe.websocket-after-sign-out",
    requirement_ids: &["V4.4.3"],
    cwe: &["CWE-613"],
    impact: "Somebody who signed out still has a live channel: anybody holding the old cookie, on a \
             shared computer or from a copied request, can keep opening it.",
    fix: "End whatever the WebSocket checks when the session ends, and refuse a handshake carrying \
          a session that has been signed out.",
};

pub(super) const RECORD_LEAKS_FIELDS: Rule = Rule {
    rule_id: "probe.record-returns-secret-fields",
    // V8.2.3 as well as V15.3.1: a field handed to a user with no permission to read it is the
    // reading half of field-level access (BOPLA). Only ever a finding, like the check itself.
    requirement_ids: &["V15.3.1", "V8.2.3"],
    cwe: &["CWE-213"],
    impact: "A record handed back to the browser carries fields nobody outside the server should \
             ever see. Whatever is in them has already left.",
    fix: "Return only the fields the page needs, named one by one, rather than handing back the \
          whole row as it came out of the database.",
};

pub(super) const SESSION_COOKIE: Rule = Rule {
    rule_id: "probe.session-cookie-attributes",
    requirement_ids: &["V3.3.2", "V3.3.4"],
    cwe: &["CWE-1004", "CWE-1275"],
    impact: "A session cookie a script can read is a session any injected script can take; one with \
             no SameSite travels with requests another site makes.",
    fix: "Set HttpOnly and SameSite (Lax or Strict) on the session cookie, and Secure once the app is \
          served over HTTPS.",
};

pub(super) const SESSION_RENEWAL: Rule = Rule {
    rule_id: "probe.session-not-renewed",
    requirement_ids: &["V7.2.4"],
    cwe: &["CWE-384"],
    impact: "The session id a visitor had before signing in keeps working after, so somebody who \
             planted that id in their browser is signed in as them too.",
    fix: "Issue a new session id at sign-in and discard the old one; most frameworks have a single \
          call for this (regenerate, rotate or cycle the session).",
};

pub(super) const LOGOUT: Rule = Rule {
    rule_id: "probe.logout-keeps-session",
    requirement_ids: &["V7.4.1"],
    cwe: &["CWE-613"],
    impact: "Signing out does not end the session: a copied cookie, or a shared computer, still has \
             the account after the person has left.",
    fix: "End the session on the server at logout — delete it from the session store, or record the \
          token as revoked — rather than only clearing the cookie in the browser.",
};

pub(super) const FORGERY: Rule = Rule {
    rule_id: "probe.cross-site-request-accepted",
    requirement_ids: &["V3.5.1"],
    cwe: &["CWE-352"],
    impact: "Another website can make a signed-in person's browser send this request, and the app \
             carries it out as them.",
    fix: "Require an anti-forgery token on every request that changes something, or check the \
          Origin header against the app's own address, and set SameSite on the session cookie.",
};

pub(super) const OWN_FORMS_REFUSED: Rule = Rule {
    rule_id: "probe.own-forms-refused",
    // Nothing in ASVS asks an app to accept its own forms; this is a finding about the app not
    // working, found on the way to the cross-site checks, and it credits nothing.
    requirement_ids: &[],
    cwe: &[],
    impact: "The app tells browsers to send no referrer, and under that policy a browser sends \
             `Origin: null` with the app's own forms. The app refuses that, so the forms fail for \
             real people, and the usual way out is to switch the cross-site defense off.",
    fix: "Accept `Origin: null` on a request that carries a valid anti-forgery token, or send a \
          Referrer-Policy such as `strict-origin-when-cross-origin` or `same-origin`, under which \
          browsers send the app's own origin.",
};

pub(super) const SIMPLE_REQUEST: Rule = Rule {
    rule_id: "probe.preflight-skipped",
    requirement_ids: &["V3.5.2"],
    cwe: &["CWE-352"],
    impact: "The app takes this request in a form a page on another site can send without the \
             browser asking the app first, so a signed-in person's browser can be made to carry it \
             out for that site. A JSON request is only safe from that because browsers ask first, \
             and this one did not need to be JSON.",
    fix: "Refuse a request that changes something unless its Content-Type is `application/json`, \
          or unless it carries a header of the app's own that only its own pages send, and check \
          the Origin header against the app's own address as well.",
};

pub(super) const SHORT_PASSWORD: Rule = Rule {
    rule_id: "probe.short-password-accepted",
    requirement_ids: &["V6.2.1"],
    cwe: &["CWE-521"],
    impact: "A password of seven characters can be tried exhaustively, and people will choose one if \
             the app lets them.",
    fix: "Refuse passwords shorter than 8 characters at sign-up and at password change; 15 is the \
          recommended minimum.",
};

pub(super) const COMMON_PASSWORD: Rule = Rule {
    rule_id: "probe.common-password-accepted",
    requirement_ids: &["V6.2.4"],
    cwe: &["CWE-521"],
    impact: "The passwords everybody uses are the first ones anybody trying to get in will try.",
    fix: "Check new passwords against a list of the most common ones (at least the top 3000 that \
          meet the app's length rule) and refuse a match.",
};

pub(super) const BREACHED_PASSWORD: Rule = Rule {
    rule_id: "probe.breached-password-accepted",
    requirement_ids: &["V6.2.12"],
    cwe: &["CWE-521"],
    impact: "A password other people have already used, and lost, is on the lists anybody trying to \
             get in works through first — long after the top few thousand.",
    fix: "Check new passwords against a large set of breached passwords, not only the most common \
          few thousand: a downloaded copy of the Pwned Passwords list, or its range API, which is \
          sent only the first five characters of the password's SHA-1 hash.",
};

pub(super) const CONTEXT_WORD_PASSWORD: Rule = Rule {
    rule_id: "probe.context-word-password-accepted",
    requirement_ids: &["V6.2.11"],
    cwe: &["CWE-521"],
    impact: "A password built from the app's own name, or the organization's, is one of the first \
             things somebody who knows where they are will try.",
    fix: "Refuse a new password that contains any word from your list of context-specific words, \
          compared without regard to case.",
};

pub(super) const STEP_SKIPPED: Rule = Rule {
    rule_id: "probe.flow-step-skipped",
    requirement_ids: &["V2.3.1"],
    cwe: &["CWE-841"],
    impact: "A step that can be skipped is a check that can be skipped: the payment before the order, \
             the confirmation before the change, the approval before the release.",
    fix: "Keep where each person is in the flow on the server, and have every step refuse unless the \
          step before it was completed by the same person in the same flow.",
};

pub(super) const TOTP_REUSED: Rule = Rule {
    rule_id: "probe.totp-reused",
    requirement_ids: &["V6.5.1"],
    cwe: &["CWE-294"],
    impact: "A code that works twice works for whoever sees it the first time: over a shoulder, in \
             a screenshot, or captured on its way to the app.",
    fix: "Record the last time step each account's code was accepted for, and refuse a code for \
          that step or an earlier one.",
};

pub(super) const TOTP_OLD_CODE: Rule = Rule {
    rule_id: "probe.totp-old-code-accepted",
    requirement_ids: &["V6.5.5"],
    cwe: &["CWE-613"],
    impact: "A code that still works minutes after it was shown gives anybody who saw it minutes \
             to use it.",
    fix: "Accept the code for the current 30-second step, and at most one step either side for a \
          clock that has drifted.",
};

pub(super) const FORWARDED_TRUSTED: Rule = Rule {
    rule_id: "probe.forwarded-for-trusted",
    requirement_ids: &["V15.3.4"],
    cwe: &["CWE-348"],
    impact: "Anybody can step around the limit on guessing passwords by claiming a different \
             address in each request, which costs them nothing.",
    fix: "Take the client's address from X-Forwarded-For only when the request came through a \
          proxy you run, and only the entry that proxy added: set the framework's trusted-proxy \
          setting to your proxy rather than reading the header yourself.",
};

/// Only ever a finding: an app that ignores these headers has shown nothing about the others a
/// proxy might add.
pub(super) const IDENTITY_HEADER: Rule = Rule {
    rule_id: "probe.identity-header-trusted",
    requirement_ids: &["V4.1.3"],
    cwe: &["CWE-290"],
    impact: "Anybody can open a private page as somebody else, without signing in, by adding a \
             header that says who they are.",
    fix: "Take who the user is from the session alone. Trust a header such as X-Remote-User only \
          behind a proxy you run that sets it on every request and strips it from what the browser \
          sends, and never read it from a request that did not come through that proxy.",
};

pub(super) const COMPOSITION_RULES: Rule = Rule {
    rule_id: "probe.password-composition-rules",
    requirement_ids: &["V6.2.5"],
    cwe: &["CWE-521"],
    impact: "Rules like \"must contain a digit\" push people towards predictable passwords such as \
             Password1, and refuse long passphrases that are stronger.",
    fix: "Drop the rules about which kinds of character a password must contain; require length, \
          and check against common passwords instead.",
};

pub(super) const DEFAULT_ACCOUNT: Rule = Rule {
    rule_id: "probe.default-account",
    requirement_ids: &["V6.3.2"],
    cwe: &["CWE-1392"],
    impact: "An account with a name and password everybody knows is an account anybody can sign in \
             to.",
    fix: "Remove the default account, or disable it, and create administrators with passwords chosen \
          when they are set up.",
};

pub(super) const PASSWORD_IN_URL: Rule = Rule {
    rule_id: "probe.password-in-url",
    requirement_ids: &["V14.2.1"],
    cwe: &["CWE-598"],
    impact: "A password in the address ends up in browser history, server logs, and any proxy in \
             between, where it can be read long after.",
    fix: "Accept sign-in only as a POST with the password in the body, and refuse it in the query \
          string.",
};

pub(super) const WEAK_SESSION_ID: Rule = Rule {
    rule_id: "probe.session-id-weak",
    requirement_ids: &["V7.2.3"],
    cwe: &["CWE-330"],
    impact: "A session id short enough, or repeated, can be guessed, and a guessed session id is a \
             signed-in session.",
    fix: "Use the framework's own session store, which makes ids of at least 128 random bits from a \
          cryptographically secure generator, rather than making them by hand.",
};

pub(super) const ALTERED_PASSWORD: Rule = Rule {
    rule_id: "probe.password-altered",
    requirement_ids: &["V6.2.8"],
    cwe: &["CWE-521"],
    impact: "A password that still works when its capitals are changed, or when everything past a \
             certain length is left off, is a much smaller thing to guess than the one the person \
             chose.",
    fix: "Compare the password exactly as it was typed: no changing its case, no cutting it short. \
          If the hashing function has a length limit (bcrypt stops at 72 bytes), hash a digest of the \
          password, or use one without the limit, such as Argon2id.",
};

pub(super) const LONG_PASSWORD: Rule = Rule {
    rule_id: "probe.long-password-refused",
    requirement_ids: &["V6.2.9"],
    cwe: &["CWE-521"],
    impact: "People who use a password manager or a long passphrase are told to choose something \
             shorter, which is weaker.",
    fix: "Allow passwords of at least 64 characters; there is no need for a maximum below 128.",
};

pub(super) const UNMASKED_PASSWORD: Rule = Rule {
    rule_id: "probe.password-field-unmasked",
    requirement_ids: &["V6.2.6"],
    cwe: &["CWE-549"],
    impact: "A password typed into an ordinary text field is shown on the screen for anybody nearby \
             to read, and may be remembered by the browser as ordinary text.",
    fix: "Use `<input type=\"password\">` for every password field. A button that lets the person \
          show what they typed is fine; showing it by default is not.",
};

pub(super) const PASTE_BLOCKED: Rule = Rule {
    rule_id: "probe.password-paste-blocked",
    requirement_ids: &["V6.2.7"],
    cwe: &["CWE-521"],
    impact: "Stopping people pasting a password stops them using a password manager, which pushes \
             them towards short passwords they can type from memory.",
    fix: "Remove the handler that blocks pasting into the password field.",
};

pub(super) const CHANGE_PASSWORD: Rule = Rule {
    rule_id: "probe.password-change",
    requirement_ids: &["V6.2.2"],
    cwe: &["CWE-620"],
    impact: "A password that cannot really be changed cannot be changed after it leaks: the old one \
             keeps working.",
    fix: "Replace the stored password hash when the password is changed, so only the new password \
          signs in afterwards.",
};

/// Only ever a finding: a sample of places and parameter names, never every redirect the app makes.
pub(super) const OPEN_REDIRECT: Rule = Rule {
    rule_id: "probe.open-redirect",
    requirement_ids: &["V3.7.2"],
    cwe: &["CWE-601"],
    impact: "A link to the app's own sign-in page can send whoever follows it on to any site, which can \
             look like the app and ask for the password again. People trust the link because it \
             begins with the app's own address.",
    fix: "Only follow a return address that is a path on the app itself: it begins with a single `/`, \
          not `//` or `/\\`, and has no scheme or host. Otherwise go to a fixed page such as the home \
          page. Most frameworks have a helper for this, such as Django's `url_has_allowed_host_and_scheme`.",
};

pub(super) const CREATE_UNLIMITED: Rule = Rule {
    rule_id: "probe.create-rate-unlimited",
    requirement_ids: &["V2.4.1"],
    cwe: &["CWE-770"],
    impact: "One person, or a script, can create records as fast as it can send them: the app fills \
             with junk, its storage and any per-record costs run up, and others are slowed down.",
    fix: "Limit how many records each signed-in user can create in a minute, at the number \
          securevibe.toml states, and answer the rest with 429 Too Many Requests. Most frameworks \
          have a package for it.",
};

pub(super) const DONE_TWICE: Rule = Rule {
    rule_id: "probe.action-done-twice",
    requirement_ids: &["V2.3.4"],
    cwe: &["CWE-362"],
    impact: "Two requests arriving together can both take the one thing there was: the last seat is \
             booked twice, a one-time code pays out twice. Anybody can do it on purpose by sending \
             the same request several times at once.",
    fix: "Take the thing and check it was there in one step the database does at once: an update \
          that only matches while one is left (`UPDATE ... SET left = left - 1 WHERE left > 0`, \
          then check a row changed), a row lock (`SELECT ... FOR UPDATE`), or a unique constraint \
          that refuses the second. Reading first and writing afterwards leaves a gap.",
};

pub(super) const CHANGE_WITHOUT_CURRENT: Rule = Rule {
    rule_id: "probe.password-change-without-current",
    requirement_ids: &["V6.2.3"],
    cwe: &["CWE-620"],
    impact: "Anybody who gets hold of a signed-in session for a moment, on a shared computer or \
             through a stolen cookie, can change the password and keep the account.",
    fix: "Ask for the current password when the password is changed, check it against the stored \
          hash, and refuse the change when it does not match.",
};

pub(super) const EMAIL_CHANGE_WITHOUT_PASSWORD: Rule = Rule {
    rule_id: "probe.email-change-without-password",
    requirement_ids: &["V7.5.1"],
    cwe: &["CWE-620"],
    impact: "Anybody who gets hold of a signed-in session for a moment can move the account to an \
             email address of their own, then reset the password through it and keep the account.",
    fix: "Ask for the current password again before the email address is changed, check it against \
          the stored hash, and refuse the change when it does not match.",
};

/// Only ever credited. Other sessions that keep working after a change are not a finding, since
/// V7.4.3 is also met by an app that offers to end them, which no request can see.
pub(super) const CHANGE_ENDS_SESSIONS: Rule = Rule {
    rule_id: "probe.password-change-ends-sessions",
    requirement_ids: &["V7.4.3"],
    cwe: &["CWE-613"],
    impact: "Somebody who already has a session, from a stolen cookie or a computer left signed in, \
             keeps it after the account holder changes the password to lock them out.",
    fix: "When the password is changed, end every other session of that account, or offer the \
          person a way to do so on the same page.",
};

/// Only ever credited. No email is not a finding: the app may tell people some other way.
pub(super) const CHANGE_NOTIFIED: Rule = Rule {
    rule_id: "probe.password-change-notified",
    requirement_ids: &["V6.3.7"],
    cwe: &["CWE-778"],
    impact: "Somebody who takes over an account and changes its password does so without the \
             account holder being told, so they find out only when they cannot sign in.",
    fix: "Send an email to the account's address whenever its password is changed, saying when, and \
          what to do if it was not them.",
};

pub(super) const RESET_REUSABLE: Rule = Rule {
    rule_id: "probe.reset-reusable",
    requirement_ids: &["V6.4.3"],
    cwe: &["CWE-640"],
    impact: "A reset link that works more than once works for whoever finds it next — in a mailbox, \
             a browser history, or a forwarded email — long after the owner used it.",
    fix: "Mark the reset code as used, or delete it, in the same step that sets the new password, \
          and refuse a code that has been used.",
};

pub(super) const RESET_KEEPS_OLD: Rule = Rule {
    rule_id: "probe.reset-keeps-old-password",
    requirement_ids: &["V6.4.3"],
    cwe: &["CWE-640"],
    impact: "Somebody who resets a password because it leaked is still locked in with whoever has the \
             old one.",
    fix: "Replace the stored password hash when the password is reset, so only the new password \
          signs in afterwards.",
};

pub(super) const RESET_CODE_GUESSABLE: Rule = Rule {
    rule_id: "probe.reset-code-guessable",
    requirement_ids: &["V6.4.3"],
    cwe: &["CWE-640", "CWE-330"],
    impact: "A reset code that can be guessed lets anybody who knows an email address take the \
             account, without ever seeing the email.",
    fix: "Make each reset code from a secure random generator, long enough that guessing is hopeless \
          (16 random bytes is a common choice), and never reuse or count up from an earlier one.",
};

pub(super) const RESET_REVEALS_ACCOUNT: Rule = Rule {
    rule_id: "probe.reset-reveals-account",
    requirement_ids: &["V6.3.8"],
    cwe: &["CWE-204"],
    impact: "Anybody can find out whether an email address has an account, which is where guessing \
             passwords and targeted phishing begin.",
    fix: "Answer a reset request the same way whether or not the address has an account — the same \
          status and the same words, such as \"if that address has an account, we have sent it a \
          link\" — and send the email, or not, afterwards.",
};

pub(super) const EMAIL_CODE_REUSABLE: Rule = Rule {
    rule_id: "probe.email-code-reusable",
    requirement_ids: &["V6.5.1"],
    cwe: &["CWE-294"],
    impact: "A sign-in code or link that works more than once signs in whoever finds it next — in a \
             mailbox, a browser history, or a forwarded email.",
    fix: "Mark the code as used, or delete it, in the same step that signs the user in, and refuse a \
          code that has been used.",
};

pub(super) const EMAIL_CODE_LONG_LIVED: Rule = Rule {
    rule_id: "probe.email-code-long-lived",
    requirement_ids: &["V6.5.5"],
    cwe: &["CWE-613"],
    impact: "A sign-in code that keeps working long after it was sent gives whoever reads the email \
             later — in a shared mailbox, a synced phone, or a forwarded message — as good a way in \
             as the person who asked for it.",
    fix: "Store when each code was sent and refuse it once ten minutes have passed; a shorter \
          lifetime is better still.",
};

pub(super) const EMAIL_CODE_UNBOUND: Rule = Rule {
    rule_id: "probe.email-code-unbound",
    requirement_ids: &["V6.6.2"],
    cwe: &["CWE-294"],
    impact: "A code that completes a sign-in other than the one it was sent for can be used by \
             somebody who started their own sign-in and then got hold of the code — a phishing page \
             that asks for it is enough.",
    fix: "Tie each code to the sign-in request that asked for it, for instance by storing the \
          session it was asked from, and refuse it anywhere else.",
};

pub(super) const EMAIL_CODE_SHORT: Rule = Rule {
    rule_id: "probe.email-code-short",
    requirement_ids: &["V6.5.4"],
    cwe: &["CWE-330"],
    impact: "A sign-in code short enough to guess lets anybody who knows an email address sign in \
             as its owner without ever seeing the email.",
    fix: "Make each code from a secure random generator, with at least six random digits (20 bits), \
          and more for a code in a link.",
};

pub(super) const EMAIL_CODE_GUESSING: Rule = Rule {
    rule_id: "probe.email-code-guessing-unlimited",
    requirement_ids: &["V6.6.3"],
    cwe: &["CWE-307"],
    impact: "Codes can be tried until one works: at six digits, a million tries sign anybody in.",
    fix: "Count wrong codes for each sign-in request and each account, and after a few, refuse more \
          attempts or cancel the code and ask for a new one.",
};

pub(super) const NO_IDLE_TIMEOUT: Rule = Rule {
    rule_id: "probe.session-idle-timeout",
    requirement_ids: &["V7.3.1"],
    cwe: &["CWE-613"],
    impact: "A session left open on a shared or stolen computer stays signed in long after its owner \
             walked away.",
    fix: "End a session that has not been used for the time you stated, on the server: record when \
          it was last used, and refuse it once that is longer ago than the timeout.",
};

pub(super) const NO_SESSION_LIFETIME: Rule = Rule {
    rule_id: "probe.session-lifetime",
    requirement_ids: &["V7.3.2"],
    cwe: &["CWE-613"],
    impact: "A session kept busy — by its owner, or by whoever stole it — never has to sign in again.",
    fix: "Record when each session began, and ask for the password again once it is older than the \
          lifetime you stated, however recently it was used.",
};

pub(super) const ACTIVATION_GUESSABLE: Rule = Rule {
    rule_id: "probe.activation-code-guessable",
    requirement_ids: &["V6.4.1"],
    cwe: &["CWE-330"],
    impact: "An activation code that can be guessed lets anybody finish somebody else's sign-up, or \
             activate an account made in another person's name.",
    fix: "Make each activation code from a secure random generator, long enough that guessing is \
          hopeless (16 random bytes is a common choice), and never count up from an earlier one.",
};

pub(super) const ACTIVATION_REUSABLE: Rule = Rule {
    rule_id: "probe.activation-link-reusable",
    requirement_ids: &["V6.4.1"],
    cwe: &["CWE-294"],
    impact: "An activation link that signs its account in works for whoever finds it later — in a \
             mailbox, a browser history, or a forwarded email — for as long as it keeps working.",
    fix: "Mark the activation code as used, or delete it, when it is used, and refuse it afterwards.",
};

pub(super) const SESSIONS_SURVIVE_DELETION: Rule = Rule {
    rule_id: "probe.sessions-survive-deletion",
    requirement_ids: &["V7.4.2"],
    cwe: &["CWE-613"],
    impact: "An account that has been deleted can still be used from any browser that was signed in \
             to it, so deleting a compromised or departed person's account does not lock them out.",
    fix: "When an account is deleted or disabled, delete every session belonging to it from the \
          session store, or check on each request that the session's account still exists.",
};

pub(super) const PASSWORD_HINTS: Rule = Rule {
    rule_id: "probe.password-hints",
    requirement_ids: &["V6.4.2"],
    cwe: &["CWE-640"],
    impact: "A password hint or a secret question is a second, weaker password: the answer to \
             \"your first pet\" is often on a social media profile.",
    fix: "Remove password hints and secret questions; recover accounts through a link sent to the \
          email address or phone the person registered.",
};

pub(super) const NO_BRUTE_FORCE_LIMIT: Rule = Rule {
    rule_id: "probe.failed-sign-ins-unlimited",
    requirement_ids: &["V6.3.1"],
    cwe: &["CWE-307"],
    impact: "Someone can try passwords as fast as the network allows, so a weak or leaked password is found in minutes rather than never. This is how most accounts are actually taken.",
    fix: "Count failed sign-ins per account and per address, and once the number you stated is reached, slow the next attempt down or refuse it for a while. Refusing for a while beats locking the account outright, which lets somebody lock a real person out on purpose.",
};

pub(super) const SIGN_OUT_ON_GET: Rule = Rule {
    rule_id: "probe.sign-out-on-get",
    requirement_ids: &["V3.5.3"],
    cwe: &["CWE-352"],
    impact: "Signing out by visiting an address means any page, image, or link can sign a person out \
             without their asking, and it is a sign that other actions may be reachable the same \
             way.",
    fix: "Accept sign-out, and anything else that changes something, only as a POST (or PUT, PATCH, \
          DELETE), and answer a GET to it with an error or a page asking to confirm.",
};
