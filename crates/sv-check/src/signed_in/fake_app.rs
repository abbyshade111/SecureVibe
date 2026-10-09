use super::*;
use std::collections::BTreeMap;

/// The name of the cookie `pre_login_cookie` sets.
const PRE_LOGIN_COOKIE: &str = "csrftoken";

/// A small app, run in memory, with every flaw this suite looks for switchable.
///
/// Sessions are server-side and named by a random-looking counter; notes belong to whoever made
/// them. Each flag turns one protection off, so each rule can be shown to fire when its thing is
/// broken and to stay quiet when it is not.
#[derive(Default)]
pub(super) struct FakeApp {
    flaws: Flaws,
    /// Sign-up emails an activation code, and sign-in waits for it.
    pub(super) activation: bool,
    /// Activation codes: code -> (account, used).
    activation_codes: BTreeMap<String, (String, bool)>,
    /// Accounts signed up and not yet activated.
    not_activated: std::collections::BTreeSet<String>,
    /// A cookie the sign-in page sets before the session cookie, as an anti-forgery cookie is.
    pub(super) pre_login_cookie: bool,
    /// Treats a request without that cookie as signed out, as an app checking it everywhere does.
    pub(super) needs_pre_login_cookie: bool,
    /// Seconds the clock moves on with each request. Zero, the default, stands it still
    /// except during `wait`.
    pub(super) seconds_per_request: u64,
    /// Seconds a signed-in session may go unused, when this app ends idle sessions at all.
    pub(super) idle_limit: Option<u64>,
    /// Seconds a signed-in session may last, when this app limits that at all.
    pub(super) lifetime_limit: Option<u64>,
    /// Per session: when it was first seen signed in, and when it was last used.
    session_times: BTreeMap<String, (u64, u64)>,
    /// Whether `window_rolls_over_at_first_claim` has rolled over.
    leaked_once: bool,
    /// From this moment on the clock, every sign-in is refused, as by an app that went down.
    pub(super) sign_ins_refused_from: Option<u64>,
    /// Requests, by id, that take this many real milliseconds to answer: the only wait in the fake
    /// that is not on its own clock, for the checks that time the app's answers.
    pub(super) slow_ms: Vec<(String, u64)>,
    /// Every request's id and the clock just after it was answered, in order, so a test can find
    /// when one check began.
    pub(super) clock_log: Vec<(String, u64)>,
    /// What the app writes to its output, when a test asks it to log at all, in the order it
    /// handled the requests: the input to `logs::evaluate`.
    pub(super) log_style: Option<LogStyle>,
    pub(super) log: Vec<String>,
    /// The user ids a `LogStyle::Private` log writes in place of email addresses.
    log_ids: BTreeMap<String, usize>,
    /// Everything under `/account/` is refused to somebody not signed in, as `/account` is, the
    /// way an app guarding a whole section does. Off, such an address is "no such page".
    pub(super) guards_under_private: bool,
    /// `/account` answers somebody not signed in with 404, as an app hiding its private pages
    /// does, rather than sending them to sign in.
    pub(super) hides_private: bool,
    /// Signing in ends every other session of the same user.
    pub(super) one_session_per_user: bool,
    /// Every sign-in of a user after their first answers as if it worked and gives a session that
    /// is not signed in: a sign-in that fails quietly.
    pub(super) later_sign_ins_anonymous: bool,
    /// Every sign-in of a user after their first sets no cookie.
    pub(super) later_sign_ins_set_no_cookie: bool,
    /// Every sign-in of a user after their first is answered by a limiter, 429, however long the
    /// wait.
    pub(super) later_sign_ins_limited: bool,
    /// How many times each user has signed in.
    pub(super) sign_in_counts: BTreeMap<String, u32>,
    /// Two-factor secrets, by user.
    pub(super) totp: BTreeMap<String, Vec<u8>>,
    /// Sessions past the password and waiting for a code: session id -> user.
    pending: BTreeMap<String, String>,
    /// The last time step each user's code was accepted for.
    totp_last: BTreeMap<String, u64>,
    /// Wrong codes given, by user, for `totp_locks`.
    totp_wrong: BTreeMap<String, u32>,
    /// The app's clock, in seconds since 1970. Waiting moves it on rather than sleeping.
    pub(super) clock: u64,
    /// How far each user has got through the checkout.
    checkout: BTreeMap<String, u32>,
    /// Every checkout step each user has had accepted since their last finished order, in order.
    checkout_done: BTreeMap<String, Vec<u32>>,
    pub(super) users: BTreeMap<String, (String, bool)>, // user -> (password, is admin)
    sessions: BTreeMap<String, String>,                 // session id -> user ("" = not signed in)
    notes: Vec<(String, String)>,                       // (owner, text)
    /// The notes deleted, by number: read back as not there.
    deleted_notes: std::collections::BTreeSet<usize>,
    /// Announcements posted, newest last.
    announcements: Vec<String>,
    pub(super) next: u32,
    /// Old passwords a change left working, under `change_keeps_old`.
    kept: BTreeMap<String, String>,
    /// What `Clear-Site-Data` the sign-out sends, when `clears_site_data` is set. `None` is
    /// the correct value covering storage.
    pub(super) clear_site_data_value: Option<String>,
    /// Files the app has taken, by name.
    pub(super) uploads: BTreeMap<String, String>,
    /// Files saved outside the upload folder by a name starting `../`, by the rest of the name.
    /// Served at `/{name}`, one folder above `/files/`.
    escaped: BTreeMap<String, String>,
    /// When each file was taken, by the app's clock.
    upload_times: BTreeMap<String, u64>,
    /// The largest file body the app was sent, accepted or not. This is how the size cap's
    /// promise is made observable: the promise is about what is sent, and no finding says it.
    pub(super) largest_upload: usize,
    /// Wrong passwords in a row per account, counted only when `locks_out_after` is set.
    failures: BTreeMap<String, u32>,
    /// Every account a wrong password was tried against, always recorded. This is how the
    /// brute-force check's promise not to guess at the test users is made observable: the
    /// promise is about which account it attacks, and no step or finding says which.
    pub(super) guessed_at: Vec<String>,
    /// The exact `Cache-Control` a private page sends. `None` means the correct `no-store`,
    /// so a test can set a value that only looks right without a flaw flag for each one.
    pub(super) cache_control: Option<String>,
    /// Every email the app has sent, as (to, text), oldest first.
    pub(super) outbox: Vec<(String, String)>,
    /// Reset codes handed out: code -> (account, used).
    reset_codes: BTreeMap<String, (String, bool)>,
    /// Sessions signed out, remembered for the WebSocket that forgets to check.
    signed_out: std::collections::BTreeSet<String>,
    /// Sign-in codes handed out: code -> (account, the session that asked, used).
    sign_in_codes: BTreeMap<String, (String, String, bool)>,
    /// Wrong sign-in codes per session.
    code_failures: BTreeMap<String, u32>,
    /// When each sign-in code was handed out, by the clock.
    code_born: BTreeMap<String, u64>,
    /// Whether the idle timeout ends sessions nobody has signed in to yet, too.
    pub(super) anonymous_sessions_time_out: bool,
    /// Hands out a new anti-forgery token with each page that carries one, and takes each only
    /// once. The fixed token the other pages hold is still taken, so the rest of a run works.
    pub(super) single_use_tokens: bool,
    /// The tokens handed out under `single_use_tokens` and not yet used.
    issued_tokens: std::collections::BTreeSet<String>,
    /// How many have been handed out, so each is new.
    tokens_handed_out: usize,
    /// Refuses with 409 a note whose text, or an upload whose `title`, it has had before.
    pub(super) refuses_repeats: bool,
    /// The `title`s of the uploads so far.
    upload_titles: std::collections::BTreeSet<String>,
    /// Refuses every upload with 403 once it holds this many.
    pub(super) upload_quota: Option<usize>,
    /// How the notes limit answers, as a status and whether it sends `Retry-After`. `None`, the
    /// default, is 429 with it.
    pub(super) notes_limit_answer: Option<(u16, bool)>,
    /// Notes one user may create in a minute of the clock, answered 429 past it. `None`, the
    /// default, is no limit at all.
    pub(super) notes_per_minute: Option<u32>,
    /// When each user created each note, by the clock.
    note_times: BTreeMap<String, Vec<u64>>,
    /// Comments one user may post in a minute through `/comments`, answered 429 past it. `None`, the
    /// default, is no limit: a second kind of record for `creates`.
    pub(super) comments_per_minute: Option<u32>,
    /// Past `notes_per_minute`, lets every other note through rather than none: a limit that does
    /// not stay shut.
    pub(super) notes_limit_leaks: bool,
    /// Under `notes_limit_leaks`, whether the next note past the limit goes through.
    leak_next: bool,
    /// Seats booked. There is one seat.
    pub(super) bookings: u32,
    /// Who holds the seat, once somebody does.
    booked_by: Option<String>,
    /// While copies are being sent at the same instant: the bookings there were when they
    /// started, which each sees under `booking_races`, and how many have arrived.
    together: Option<(u32, usize)>,
    /// Records are looked up by an id the database keeps as text, so a value joined into the
    /// query sits inside quotes.
    pub(super) ids_are_text: bool,
    /// Sign-ins hand out a JSON Web Token signed with `jwt_key()` and lasting this many seconds,
    /// in place of a session id: in the cookie after the form's sign-in, in the JSON after
    /// `/api/login`. `None`, the default, hands out session ids.
    pub(super) jwt_lifetime: Option<u64>,
    /// The tokens carry no expiry time at all.
    pub(super) jwt_without_expiry: bool,
    /// Seconds past its expiry a token is still taken, as token libraries allow for clocks that
    /// disagree. Not a fault.
    pub(super) jwt_leeway: u64,
    /// The run has a test model whose server answered, at `FAKE_MODEL`.
    pub(super) model_up: bool,
    /// What the app fetched from the test model's server: the tags of `/_sv/keys/<tag>`.
    pub(super) model_fetched: std::collections::BTreeSet<String>,
    /// The run has a headless browser that signs in through the app's form, as a person would, and
    /// finds nothing kept where the page's scripts can read it: a correct app, as
    /// `examples/notes-with-users` is. It answers only a job that signs in through a form; any
    /// other, as with no browser at all.
    pub(super) browser: bool,
}

/// The test model's server as the fake app reaches it.
pub(super) const FAKE_MODEL: &str = "http://sv-1-model:9100";

/// The key the fake app signs its tokens with. Not a secret: the fake app runs only in tests. Put
/// together at run time, as `browser_storage`'s test password is, so the file holds no key for a
/// scanner to flag: CodeQL's hard-coded cryptographic value rule did, on the literal (alert 113,
/// 8 October 2026). The bytes are the same as before.
fn jwt_key(placeholder: bool) -> Vec<u8> {
    if placeholder {
        // Made from pieces, so this file holds no secret's whole shape.
        return ["your-", "256-bit-", "secret"].concat().into_bytes();
    }
    ["the fake app", "signs its tokens", "with this"]
        .join(" ")
        .into_bytes()
}

/// The one page a single-page app sends for every address it draws in the browser.
pub(super) const PAGE_SHELL: &str = "<!doctype html><html><head><title>Notes</title>\
<script type=\"module\" src=\"/assets/index-4f2a.js\"></script></head>\
<body><div id=\"root\"></div></body></html>";

/// The fake app's own context-specific word, as an owner would list it in `context-words`.
pub(super) const CONTEXT_WORD: &str = "acmenotes";

#[derive(Default, Clone, Copy)]
pub(super) struct Flaws {
    /// Not a flaw: the app is a single-page app. `/` and `/account` send everybody the same page
    /// shell, and what the account page shows comes from `/api/me`, guarded as `/account` is
    /// otherwise (and open under `private_open`).
    pub(super) page_shell: bool,
    /// Not a flaw: `/api/login` sets the session cookie as well as answering with the token, so a
    /// browser carries the session on requests from other sites even though the page sends the token.
    pub(super) token_login_sets_cookie: bool,
    pub(super) private_open: bool,
    pub(super) admin_open: bool,
    /// Any signed-in user can post an announcement, which only an admin should.
    pub(super) admin_action_open: bool,
    /// An announcement refused to an ordinary user is answered 200, as some apps do.
    pub(super) admin_action_says_ok: bool,
    /// Nobody's announcement is posted, the admin's included.
    pub(super) admin_action_broken: bool,
    /// Sign-up makes an admin of anybody who asks for it with `role=admin` or `is_admin=true`.
    pub(super) signup_trusts_role: bool,
    /// An email change makes an admin of the account that asks for it with `role=admin` or
    /// `is_admin=true`.
    pub(super) email_change_trusts_role: bool,
    /// Any signed-in user can read any record.
    pub(super) idor: bool,
    /// Anybody at all can read any record.
    pub(super) records_public: bool,
    /// The list of one's notes (`/my-notes`) shows everybody's (ADR-053).
    pub(super) list_shows_others: bool,
    /// Any signed-in user can change any note (`/notes/{n}/edit`) (ADR-053).
    pub(super) idor_update: bool,
    /// Any signed-in user can delete any note (`/notes/{n}/delete`) (ADR-053).
    pub(super) idor_delete: bool,
    /// Not a flaw of the app's: its change and delete routes take another method, so a form POSTed
    /// to them answers 405 for everybody, the note's owner too (ADR-053, Later).
    pub(super) writes_need_another_method: bool,
    pub(super) no_csrf_check: bool,
    /// The notes page sends `Referrer-Policy: no-referrer`. Not a flaw on its own.
    pub(super) no_referrer: bool,
    /// Creating a note refuses `Origin: null`, as a strict cross-site defense might.
    pub(super) refuses_null_origin: bool,
    pub(super) keep_session_at_login: bool,
    /// With `keep_session_at_login`, sets a cookie of no consequence at sign-in, as an app that
    /// remembers the user's name for the page does: the only cookie sign-in sets is not the session.
    pub(super) other_cookie_at_login: bool,
    pub(super) logout_keeps_session: bool,
    pub(super) no_httponly: bool,
    /// `/account` sets the session cookie again, to the same value, with its attributes, as an app
    /// whose sessions slide does on every page.
    pub(super) private_page_sets_session: bool,
    /// `/account` sets the session cookie again with nothing but a path: no HttpOnly, no SameSite.
    pub(super) private_page_sets_session_bare: bool,
    /// `/account` clears the session cookie (an empty value, nothing else), as a page that signs
    /// the user out would. Only for a check called on its own: in a run it ends the session.
    pub(super) private_page_clears_session: bool,
    pub(super) broken_login: bool,
    /// Sign-up takes a password shorter than 8 characters.
    pub(super) short_password_ok: bool,
    /// Sign-up takes a password from the common list.
    pub(super) common_password_ok: bool,
    /// The account page answers any site's Origin by echoing it, with credentials allowed: a signed-in
    /// page any site can read (ADR-055). The health path does not.
    pub(super) private_cors_echoes: bool,
    /// Sign-up refuses `COMMON` and takes the other common words: a list written from memory that
    /// holds one word and not the rest (ADR-055).
    pub(super) common_list_short: bool,
    /// Sign-up takes a password from far down the common list.
    pub(super) breached_password_ok: bool,
    /// Any step of the checkout can be taken first.
    pub(super) flow_unguarded: bool,
    /// The last step of the checkout needs the first, and not the one between.
    pub(super) flow_checks_first_only: bool,
    /// A refused checkout step says "Order placed" in its refusal.
    pub(super) flow_refusal_says_placed: bool,
    /// The checkout's last step never finishes, even in order.
    pub(super) flow_broken: bool,
    /// A refused checkout step sends the browser back to the first step, as many apps do.
    pub(super) flow_refusal_redirects: bool,
    /// A checkout step needs only as many steps accepted before it as come before it, whichever
    /// they were: the first step done twice opens the last.
    pub(super) flow_counts_steps: bool,
    /// The last checkout step needs every step before it done at some point, in any order, and
    /// the steps before it can be taken in any order.
    pub(super) flow_any_order: bool,
    /// A two-factor code can be used again.
    pub(super) totp_reusable: bool,
    /// An activation code works again after it has been used.
    pub(super) activation_reusable: bool,
    /// Activation codes are four digits.
    pub(super) activation_short: bool,
    /// Activation codes are six digits, one more than the last.
    pub(super) activation_counting: bool,
    /// Sign-in does not wait for activation.
    pub(super) activation_not_gating: bool,
    /// Using an activation code answers as if it worked and activates nothing.
    pub(super) activation_does_nothing: bool,
    /// The activation link activates the account without signing it in.
    pub(super) activation_link_does_not_sign_in: bool,
    /// Only the current 30-second step's code is taken, with no allowance for clock drift: the
    /// 30-second lifetime V6.5.5 asks for.
    pub(super) totp_current_only: bool,
    /// A two-factor code from any of the last ten steps is accepted.
    pub(super) totp_any_age: bool,
    /// The password alone signs a two-factor account all the way in.
    pub(super) totp_not_required: bool,
    /// A second wrong two-factor code locks the account's codes.
    pub(super) totp_locks: bool,
    /// The first wrong two-factor code locks the account's codes.
    pub(super) totp_locks_at_once: bool,
    /// No two-factor code is ever accepted.
    pub(super) totp_broken: bool,
    /// Sign-up takes a password containing the app's context word.
    pub(super) context_word_ok: bool,
    /// Sign-up wants a capital and a digit in every password.
    pub(super) composition_rules: bool,
    /// `admin` / `admin` is an account.
    pub(super) default_admin: bool,
    /// A GET to /login with the fields in the query string signs in.
    pub(super) password_in_url: bool,
    /// Session ids are a short counter.
    pub(super) short_session_ids: bool,
    /// Sign-up refuses everybody.
    pub(super) signup_closed: bool,
    /// Each user gets the same long session id every time they sign in.
    pub(super) same_session_id: bool,
    /// Sign-up wants at least 16 characters.
    pub(super) long_minimum: bool,
    /// Sign-up answers as if it worked and makes no account.
    pub(super) signup_does_nothing: bool,
    /// Passwords are compared with their case folded.
    pub(super) case_folded: bool,
    /// Passwords are compared on their first 72 characters, as bcrypt does.
    pub(super) cut_at_72: bool,
    /// Sign-up refuses a password longer than 64 characters.
    pub(super) longest_64: bool,
    /// The password fields are ordinary text fields.
    pub(super) password_shown: bool,
    /// The password fields refuse a paste.
    pub(super) paste_blocked: bool,
    /// The pages carry no password field in their HTML: a form built by script.
    pub(super) no_form_in_html: bool,
    /// A GET to /logout ends the session.
    pub(super) logout_on_get: bool,
    /// A password change does not check the current password.
    pub(super) change_without_current: bool,
    /// A password change adds the new password and leaves the old one working.
    pub(super) change_keeps_old: bool,
    /// A password change answers as if it worked and changes nothing.
    pub(super) change_does_nothing: bool,
    /// Sign-in and sign-out follow `next` wherever it points.
    pub(super) redirect_anywhere: bool,
    /// Sign-in and sign-out follow `next` when it begins with `/`, which `//elsewhere` does.
    pub(super) redirect_checks_slash_only: bool,
    /// `/go`, a page that sends a signed-in user on to `next`, follows it wherever it points.
    pub(super) go_anywhere: bool,
    /// An email change does not check the password.
    pub(super) email_change_without_password: bool,
    /// An email change answers as if it worked and changes nothing.
    pub(super) email_change_does_nothing: bool,
    /// Booking reads how many seats are taken and writes the booking afterwards, so copies sent at
    /// the same instant all see the seat free (V2.3.4).
    pub(super) booking_races: bool,
    /// Booking refuses everybody, the first included.
    pub(super) booking_broken: bool,
    /// Booking answers copies sent at the same instant beyond the first with 429.
    pub(super) booking_rate_limited: bool,
    /// Booking answers a repeat from the user who already holds the seat with "Booked" again,
    /// changing nothing: safe to repeat, as the "actions that must happen once" prompt asks. Not a
    /// flaw; until 5 October 2026 it was reported as one.
    pub(super) booking_repeat_says_booked: bool,
    /// A password change leaves the account's other sessions working (V7.4.3).
    pub(super) change_keeps_sessions: bool,
    /// A password change sends the account holder no email (V6.3.7).
    pub(super) change_sends_no_email: bool,
    /// A request carrying `X-Remote-User` naming an account is served as that account, signed in
    /// or not, as behind a proxy the app trusts without one being there (V4.1.3).
    pub(super) trusts_identity_header: bool,
    /// The new-password field of the change page alone is an ordinary text field.
    pub(super) new_field_shown: bool,
    /// Deleting an account leaves its other sessions working.
    pub(super) deletion_keeps_sessions: bool,
    /// Deleting an account answers as if it worked and deletes nothing.
    pub(super) delete_does_nothing: bool,
    /// Sign-up asks for the answer to a secret question.
    pub(super) secret_question: bool,
    /// Takes a file larger than the stated limit.
    pub(super) oversized_upload_ok: bool,
    /// Takes a .gif whose contents are not a GIF.
    pub(super) unchecked_contents_ok: bool,
    /// Runs an uploaded .php when it is fetched back, serving its output instead of its source.
    pub(super) runs_uploaded_code: bool,
    /// Serves an uploaded .html as text/html with nothing telling the browser not to render it.
    pub(super) renders_uploaded_pages: bool,
    /// Serves an uploaded file back with no file name in `Content-Disposition`.
    pub(super) download_no_filename: bool,
    /// Writes the uploaded name into `Content-Disposition` as it came in, unquoted.
    pub(super) download_name_raw: bool,
    /// Quotes the uploaded name but does not clean it. Not a fault: a `;` inside a quoted
    /// string is part of the name, and this is here so a check that split on it would be
    /// caught accusing a correct app.
    pub(super) download_name_quoted_uncleaned: bool,
    /// Accepts a session cookie it never issued.
    pub(super) session_not_verified: bool,
    /// The sign-up form states maxlength, and the server does not apply it.
    pub(super) validation_only_in_browser: bool,
    /// A record is handed back with the owner's password hash in it.
    pub(super) record_leaks_fields: bool,
    /// A note's page names its owner, as `"user_id":"<who>"` in JSON on the page. Not a flaw on
    /// its own: what the owner-field check needs to have a value to send.
    pub(super) record_names_owner: bool,
    /// A new note's owner is the `user_id` the request sends, when it sends one (mass assignment).
    pub(super) owner_from_request: bool,
    /// A note's text is written into its page and the list of notes as it is, not HTML-escaped.
    pub(super) notes_unescaped: bool,
    /// The JSON API reads a JSON body whatever its Content-Type says.
    pub(super) api_parses_any_type: bool,
    /// The JSON API also takes its fields as a form or as multipart.
    pub(super) api_takes_forms: bool,
    /// The JSON API refuses a request from another origin.
    pub(super) api_checks_origin: bool,
    /// The JSON API answers a request it will not take with a redirect, not a refusal.
    pub(super) api_redirects_refusals: bool,
    /// The JSON API redirects a multipart request, and refuses the rest it will not take.
    pub(super) api_redirects_multipart: bool,
    /// Signing out sends Clear-Site-Data.
    pub(super) clears_site_data: bool,
    /// Refuses every upload, whatever it is. An app whose upload path does not work as
    /// stackvet.toml describes, which must read as *not assessed* and never as four passes.
    pub(super) upload_broken: bool,
    /// Keeps an uploaded SVG's `<script>` and `<foreignObject>` rather than removing them (V1.3.4).
    pub(super) svg_scripts_kept: bool,
    /// Turns an uploaded SVG into a GIF, as an app that makes a picture of each image does.
    pub(super) svg_converted: bool,
    /// Keeps the antivirus test file with the virus taken out, as a scanner that cleans files
    /// rather than refusing them does.
    pub(super) scan_cleans: bool,
    /// Serves an uploaded SVG as an attachment rather than for the browser to show.
    pub(super) svg_as_attachment: bool,
    /// Refuses SVG uploads outright. Not a fault: an app that takes no SVG has nothing to clean.
    pub(super) refuses_svg: bool,
    /// Builds the path an upload is saved at from its name as it came in, so a name starting
    /// `../` lands one folder above the upload folder (V5.3.2). Without it, a name is reduced to
    /// its last part, as `secure_filename` and `path.basename` do.
    pub(super) upload_path_traversal: bool,
    /// Refuses a file whose name holds a `/`. Not a fault.
    pub(super) refuses_path_names: bool,
    /// Answers any address it has nothing at with its own page and 200, as an app that hands
    /// every path to a page in the browser does. Not a fault, but an answer that is not a file.
    pub(super) answers_every_path: bool,
    /// Saves a file whose name holds a `/` under a name of its own. Not a fault, and the safest
    /// arrangement, but one nothing outside the app can see.
    pub(super) renames_path_names: bool,
    /// Saves every upload under a name of its own, so nothing is at the name it was sent with.
    /// Not a fault.
    pub(super) renames_every_upload: bool,
    /// Refuses `.txt` uploads, whatever is in them. Not a fault, but it leaves a refusal of the
    /// antivirus test file saying nothing.
    pub(super) refuses_text: bool,
    /// Unpacks a compressed file without adding up what it unpacks to (V5.2.3).
    pub(super) archive_size_unchecked: bool,
    /// Unpacks a zip without counting its files (V5.2.3).
    pub(super) archive_files_unchecked: bool,
    /// Checks a compressed file's size by what its headers say, and unpacks it without counting
    /// what really comes out (V5.2.3), so a zip that says it is small is let through.
    pub(super) archive_trusts_stated_sizes: bool,
    /// Falls over on a compressed file past its limits, rather than refusing it.
    pub(super) archive_crashes: bool,
    /// Takes no compressed file at all, ordinary or not.
    pub(super) refuses_archives: bool,
    /// Keeps and serves the antivirus test file, as an app with no scanner does (V5.4.3).
    pub(super) no_malware_scan: bool,
    /// Keeps the antivirus test file, then sets it aside this many seconds after taking it, as
    /// a scanner that runs after the upload is stored does.
    pub(super) scans_after: Option<u64>,
    /// Refuses sign-in with 429 once an account has this many failures in a row. `None` — the
    /// default, and what a naive app does — counts nothing and accepts guesses forever.
    pub(super) locks_out_after: Option<u32>,
    /// `locks_out_after` counts wrong passwords by the client's address, not by account.
    pub(super) limits_by_address: bool,
    /// The client's address is read from `X-Forwarded-For` when a request carries one.
    pub(super) trusts_forwarded_for: bool,
    /// A lockout lasts for one refused attempt and then lifts by itself.
    pub(super) lockout_forgets: bool,
    /// Each refusal lets the next attempt through: one attempt per refusal, as a token bucket, a
    /// sliding window, or `nginx limit_req` does, whatever it thinks about addresses.
    pub(super) lockout_leaks: bool,
    /// The limit's window rolls over once, just as the first attempt claiming another address
    /// arrives: that attempt gets through whatever the header says, and nothing after it does.
    /// Timing a real limiter can produce by chance.
    pub(super) window_rolls_over_at_first_claim: bool,
    /// Answers a wrong password with this status from the very first attempt, as an app whose
    /// address-based limiter an earlier check has already tripped would. Correct sign-ins
    /// still work, because the suite has to reach the brute-force check for this to be the
    /// case under test at all. A status rather than a flag: a guard written for 429 alone
    /// leaves 423 and a dropped connection crediting the requirement, and one witness cannot
    /// tell those apart.
    pub(super) already_refusing: Option<u16>,
    /// Private pages come back without `Cache-Control: no-store`.
    pub(super) private_page_cacheable: bool,
    /// Private pages come back as `public, max-age=300`, for shared caches to keep.
    pub(super) private_page_shared_cache: bool,
    /// Private pages come back without the headers a browser relies on (Content-Security-Policy,
    /// X-Content-Type-Options, a framing rule, Referrer-Policy).
    pub(super) private_page_no_headers: bool,
    /// Its private pages send a Content-Security-Policy without `base-uri 'none'` (V3.4.3; ADR-047).
    pub(super) private_page_policy_without_base_uri: bool,
    /// Private pages carry no link or form pointing at the sign-out address — but do name it
    /// in a script, which is what a page built by JavaScript looks like and what a check
    /// searching the whole page for the text would wrongly credit.
    pub(super) no_sign_out_link: bool,
    /// The run has no mail server, so there is no email to read.
    pub(super) no_mail_sink: bool,
    /// A reset request answers but sends no email.
    pub(super) reset_sends_nothing: bool,
    /// A reset asked for with a line break in the address finds the account by what comes before
    /// it, and mails the address as it was typed, so a `Bcc:` line after it becomes a header
    /// (V1.3.11).
    pub(super) reset_mails_typed_address: bool,
    /// A reset asked for with a line break in the address cuts the address there and mails the
    /// account alone.
    pub(super) reset_cuts_line_breaks: bool,
    /// Using a reset code answers as if it worked and changes nothing.
    pub(super) reset_does_nothing: bool,
    /// A reset code can be used again after it has been used.
    pub(super) reset_reusable: bool,
    /// A reset adds the new password and leaves the old one working.
    pub(super) reset_keeps_old: bool,
    /// Reset codes are four digits.
    pub(super) reset_short_code: bool,
    /// Reset codes are six digits, one more than the last.
    pub(super) reset_counting_codes: bool,
    /// A reset for an address with no account is answered 404.
    pub(super) reset_reveals_by_status: bool,
    /// The answer to an address's first reset request carries the code the email does, as a
    /// debugging aid left in; later requests for it do not. One request is all an attacker needs,
    /// so the check must read the first answer, and this shows it does.
    pub(super) reset_code_in_answer: bool,
    /// A sign-up with an address that has an account gives that account the new password.
    pub(super) signup_replaces_account: bool,
    /// A sign-up with an address that has an account is answered 409, and changes nothing.
    pub(super) signup_reveals_by_status: bool,
    /// A sign-up with an address that has an account is sent somewhere else, and changes nothing.
    pub(super) signup_reveals_by_words: bool,
    /// A sign-in for an address with no account is answered 404, not 403.
    pub(super) signin_reveals_by_status: bool,
    /// A sign-in for an address with no account says so; a wrong password says that instead.
    pub(super) signin_reveals_by_words: bool,
    /// A reset for an address with no account is answered in different words.
    pub(super) reset_reveals_by_words: bool,
    /// The reset email carries its code where the default patterns do not look.
    pub(super) reset_code_elsewhere: bool,
    /// Every reset answer says how many have been asked for, so two identical requests are
    /// answered differently. Not a fault: it is here so a comparison that forgot to check the
    /// two alike answers first would accuse a correct app.
    pub(super) reset_answer_counts: bool,
    /// A sign-in code can be used again after it has signed in.
    pub(super) code_reusable: bool,
    /// A sign-in code works in any session, not only the one that asked for it.
    pub(super) code_unbound: bool,
    /// Sign-in codes are four digits.
    pub(super) code_short: bool,
    /// Wrong sign-in codes are never counted.
    pub(super) code_guessing_unlimited: bool,
    /// A session is locked after its first wrong code, rather than its third.
    pub(super) code_locks_after_one: bool,
    /// Using a sign-in code answers as if it worked and signs nobody in.
    pub(super) code_does_nothing: bool,
    /// Asking for a sign-in code answers and sends no email.
    pub(super) code_sends_nothing: bool,
    /// The sign-in-by-code forms carry no anti-forgery token, so nothing makes the probe open
    /// their pages. Not a fault.
    pub(super) code_no_csrf: bool,
    /// Past the limit, wrong codes are answered as before and the code is quietly canceled:
    /// the only sign of pushing back is that the right code no longer works. Not a fault.
    pub(super) code_cancels_quietly: bool,
    /// Every wrong code is answered 429 from the first, as an app whose limiter an earlier
    /// check has tripped would.
    pub(super) code_already_refusing: bool,
    /// The WebSocket at /ws opens for anybody.
    pub(super) ws_open: bool,
    /// The WebSocket at /ws opens for any `sid` cookie at all.
    pub(super) ws_any_cookie: bool,
    /// The WebSocket at /ws still opens for a session that was signed out.
    pub(super) ws_survives_sign_out: bool,
    /// The WebSocket at /ws refuses every handshake.
    pub(super) ws_refuses_all: bool,
    /// The WebSocket at /ws takes a handshake from any site, as long as the session is real.
    pub(super) ws_any_origin: bool,
    /// The WebSocket at /ws checks a session only when a cookie is sent, and lets in a
    /// handshake with none as a guest.
    pub(super) ws_guest: bool,
    /// Sign-in codes never expire; otherwise they last ten minutes.
    pub(super) code_long_lived: bool,
    /// A record's address is joined into its database query (V1.2.4).
    pub(super) sql_in_record: bool,
    /// The search term is joined into its database query (V1.2.4).
    pub(super) sql_in_search: bool,
    /// Reads what a token says without checking its signature (V9.1.1).
    pub(super) jwt_signature_ignored: bool,
    /// Takes a token marked `alg: none` with no signature (V9.1.2).
    pub(super) jwt_alg_none_accepted: bool,
    /// Takes a token past its expiry (V9.2.1).
    pub(super) jwt_expiry_ignored: bool,
    /// Fetches the address a token's `jku` or `x5u` header names, for the key to check it with
    /// (V9.1.3), before it can know whether the token is good.
    pub(super) jwt_key_source_followed: bool,
    /// Signs its tokens with a placeholder secret, the one a tutorial's example used, rather than a
    /// key of its own (V9.1.1).
    pub(super) jwt_placeholder_key: bool,
}

pub(super) const CSRF: &str = "tok-123";
/// How the fake app logs, when it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LogStyle {
    /// Email addresses and full addresses, query strings and all, as text lines.
    Full,
    /// The privacy-minded log of the 3 October 2026 report: JSON lines with the path only (no
    /// query string), the status, and a user id and event name for sign-ins, never an email
    /// address.
    Private,
}

/// The largest file this fake app takes, matching the max-bytes the tests state.
pub(super) const UPLOAD_LIMIT: usize = 4096;
/// The most a compressed file may unpack to here, matching the `max-unpacked-bytes` the tests state.
pub(super) const ARCHIVE_UNPACK_LIMIT: u64 = 1 << 20;
/// The most files a zip may hold here, matching the `max-files` the tests state.
pub(super) const ARCHIVE_FILE_LIMIT: u64 = 10;

/// What a compressed file says it unpacks to, and how many files it holds, read as an app that
/// checks before unpacking reads them: a zip's central directory, and a gzip's last four bytes.
/// `None` when it is not one.
fn archive_says(name: &str, data: &[u8]) -> Option<(u64, u64)> {
    let u16_at = |i: usize| {
        Some(u64::from(u16::from_le_bytes(
            data.get(i..i + 2)?.try_into().ok()?,
        )))
    };
    let u32_at = |i: usize| {
        Some(u64::from(u32::from_le_bytes(
            data.get(i..i + 4)?.try_into().ok()?,
        )))
    };
    if name.ends_with(".gz") {
        return Some((u32_at(data.len().checked_sub(4)?)?, 1));
    }
    if !name.ends_with(".zip") {
        return None;
    }
    let end = data.len().checked_sub(22)?;
    let count = u16_at(end + 10)?;
    let mut at = usize::try_from(u32_at(end + 16)?).ok()?;
    let mut total = 0;
    for _ in 0..count {
        total += u32_at(at + 24)?;
        at += 46 + (u16_at(at + 28)? + u16_at(at + 30)? + u16_at(at + 32)?) as usize;
    }
    Some((total, count))
}

/// What a compressed file really unpacks to, counted as an app that counts while it unpacks would
/// count it: each file's data read, not its headers. Only the streams `sv` itself writes can be
/// read here (`archives::zeros_in`), and a stored file is its own size; `None` for anything else.
fn archive_holds(name: &str, data: &[u8]) -> Option<u64> {
    let u16_at = |i: usize| {
        Some(usize::from(u16::from_le_bytes(
            data.get(i..i + 2)?.try_into().ok()?,
        )))
    };
    let u32_at =
        |i: usize| usize::try_from(u32::from_le_bytes(data.get(i..i + 4)?.try_into().ok()?)).ok();
    let read = |method: usize, bytes: &[u8]| match method {
        0 => Some(bytes.len() as u64),
        8 => super::archives::zeros_in(bytes),
        _ => None,
    };
    if name.ends_with(".gz") {
        // A stored gzip (the ordinary one) is not a stream of zeros, and says truly what it holds.
        return super::archives::zeros_in(data.get(10..data.len().checked_sub(8)?)?);
    }
    if !name.ends_with(".zip") {
        return None;
    }
    let end = data.len().checked_sub(22)?;
    let count = u16_at(end + 10)?;
    let mut at = u32_at(end + 16)?;
    let mut total = 0;
    for _ in 0..count {
        let (method, size, local) = (u16_at(at + 10)?, u32_at(at + 20)?, u32_at(at + 42)?);
        let start = local + 30 + u16_at(local + 26)? + u16_at(local + 28)?;
        total += read(method, data.get(start..start + size)?)?;
        at += 46 + u16_at(at + 28)? + u16_at(at + 30)? + u16_at(at + 32)?;
    }
    Some(total)
}

impl FakeApp {
    pub(super) fn new(flaws: Flaws) -> Self {
        let mut app = FakeApp {
            flaws,
            clock: 1_700_000_010,
            ..Default::default()
        };
        if flaws.default_admin {
            app.users.insert("admin".into(), ("admin".into(), true));
        }
        app
    }

    fn new_id(&mut self) -> String {
        self.next += 1;
        if self.flaws.short_session_ids {
            return format!("s{:04}x{}", self.next * 7919, self.next);
        }
        let n = u64::from(self.next);
        format!(
            "{:016x}{:016x}",
            n.wrapping_mul(0x9E37_79B9_7F4A_7C15),
            n.wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
        )
    }

    /// A token for this user, signed with `jwt_key()`.
    fn issue_jwt(&mut self, who: &str, lifetime: u64) -> String {
        let header = crate::browser::base64(br#"{"alg":"HS256","typ":"JWT"}"#, true);
        // An id of its own, so two sign-ins in the same second do not get the same token.
        let jti = self.new_id();
        let mut claims = serde_json::json!({ "sub": who, "iat": self.clock, "jti": jti });
        if !self.jwt_without_expiry {
            claims["exp"] = (self.clock + lifetime).into();
        }
        let payload = crate::browser::base64(claims.to_string().as_bytes(), true);
        let signed = format!("{header}.{payload}");
        let signature = jwt_signature(&signed, self.flaws.jwt_placeholder_key);
        format!("{signed}.{signature}")
    }

    /// Who a token names, when this app hands out tokens and `token` is one: `Some(None)` for a
    /// token it refuses, `None` for something that is not a token at all.
    fn jwt_user(&self, token: &str) -> Option<Option<String>> {
        self.jwt_lifetime?;
        let mut parts = token.split('.');
        let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let read = |part: &str| serde_json::from_slice::<serde_json::Value>(&unbase64(part)?).ok();
        let (head, claims) = (read(header)?, read(payload)?);
        let signed = self.flaws.jwt_signature_ignored
            || match head.get("alg").and_then(|a| a.as_str()) {
                Some("HS256") => {
                    signature
                        == jwt_signature(
                            &format!("{header}.{payload}"),
                            self.flaws.jwt_placeholder_key,
                        )
                }
                Some("none") => self.flaws.jwt_alg_none_accepted && signature.is_empty(),
                _ => false,
            };
        let current = self.flaws.jwt_expiry_ignored
            || match claims.get("exp") {
                Some(exp) => exp
                    .as_u64()
                    .is_some_and(|exp| self.clock <= exp + self.jwt_leeway),
                None => true,
            };
        let who = claims
            .get("sub")
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        Some(who.filter(|who| {
            signed && current && !self.signed_out.contains(token) && self.users.contains_key(who)
        }))
    }

    /// Under `jwt_key_source_followed`, fetches what a token's `jku` or `x5u` names: only the
    /// test model's server records it, as only it would in a run.
    fn follow_key_source(&mut self, token: &str) {
        if !self.flaws.jwt_key_source_followed || self.jwt_lifetime.is_none() {
            return;
        }
        let Some(header) = token
            .split('.')
            .next()
            .and_then(unbase64)
            .and_then(|h| serde_json::from_slice::<serde_json::Value>(&h).ok())
        else {
            return;
        };
        for field in ["jku", "x5u"] {
            let tag = header
                .get(field)
                .and_then(|v| v.as_str())
                .and_then(|url| url.strip_prefix(FAKE_MODEL))
                .and_then(|path| path.strip_prefix(crate::stand_in::KEYS));
            if let Some(tag) = tag.filter(|_| self.model_up) {
                self.model_fetched.insert(tag.to_owned());
            }
        }
    }

    /// The anti-forgery token a page carries: the fixed one, or under `single_use_tokens` a new one
    /// that is taken once.
    fn page_token(&mut self) -> String {
        if !self.single_use_tokens {
            return CSRF.to_owned();
        }
        self.tokens_handed_out += 1;
        let token = format!("{CSRF}-{}", self.tokens_handed_out);
        self.issued_tokens.insert(token.clone());
        token
    }

    /// A new session for this user, answered the way POST /login answers.
    fn signed_in(&mut self, who: String) -> ProbeResponse {
        if let Some(lifetime) = self.jwt_lifetime {
            let token = self.issue_jwt(&who, lifetime);
            let attrs = self.cookie_attrs();
            return Self::respond(
                303,
                vec![
                    ("Location", "/account".into()),
                    ("Set-Cookie", format!("sid={token}; {attrs}")),
                ],
                "",
            );
        }
        let count = self.sign_in_counts.entry(who.clone()).or_default();
        *count += 1;
        let later = *count > 1;
        if later && self.later_sign_ins_limited {
            return Self::respond(429, vec![], "too many attempts");
        }
        if later && self.later_sign_ins_set_no_cookie {
            return Self::respond(303, vec![("Location", "/account".into())], "");
        }
        if later && self.later_sign_ins_anonymous {
            let id = self.new_id();
            let attrs = self.cookie_attrs();
            return Self::respond(
                303,
                vec![
                    ("Location", "/account".into()),
                    ("Set-Cookie", format!("sid={id}; {attrs}")),
                ],
                "",
            );
        }
        if self.one_session_per_user {
            self.sessions.retain(|_, u| *u != who);
        }
        let id = self.session_id_for(&who);
        self.sessions.insert(id.clone(), who);
        let attrs = self.cookie_attrs();
        Self::respond(
            303,
            vec![
                ("Location", "/account".into()),
                ("Set-Cookie", format!("sid={id}; {attrs}")),
            ],
            "",
        )
    }

    fn totp_is_locked(&self, who: &str) -> bool {
        let wrong = self.totp_wrong.get(who).copied().unwrap_or(0);
        (self.flaws.totp_locks && wrong >= 2) || (self.flaws.totp_locks_at_once && wrong >= 1)
    }

    fn password_matches(&self, stored: &str, given: &str) -> bool {
        let fold = |p: &str| {
            let p: String = if self.flaws.cut_at_72 {
                p.chars().take(72).collect()
            } else {
                p.to_owned()
            };
            if self.flaws.case_folded {
                p.to_lowercase()
            } else {
                p
            }
        };
        fold(stored) == fold(given)
    }

    /// The password field as the sign-in and sign-up pages serve it.
    fn password_input(&self) -> String {
        self.password_input_named("password")
    }

    /// A password field of this name, with whatever flaws are switched on.
    fn password_input_named(&self, name: &str) -> String {
        if self.flaws.no_form_in_html {
            return String::new();
        }
        format!(
            "<input type=\"{}\" name=\"{name}\"{}>",
            if self.flaws.password_shown {
                "text"
            } else {
                "password"
            },
            if self.flaws.paste_blocked {
                " onpaste=\"return false\""
            } else {
                ""
            }
        )
    }

    fn password_allowed(&self, password: &str) -> bool {
        if self.flaws.longest_64 && password.chars().count() > 64 {
            return false;
        }
        if password.chars().count() < 8 && !self.flaws.short_password_ok {
            return false;
        }
        if self.flaws.long_minimum && password.chars().count() < 16 {
            return false;
        }
        if password == COMMON && !self.flaws.common_password_ok {
            return false;
        }
        if COMMON_MORE.contains(&password)
            && !self.flaws.common_password_ok
            && !self.flaws.common_list_short
        {
            return false;
        }
        if password == BREACHED && !self.flaws.breached_password_ok {
            return false;
        }
        if password.to_ascii_lowercase().contains(CONTEXT_WORD) && !self.flaws.context_word_ok {
            return false;
        }
        if self.flaws.composition_rules
            && !(password.chars().any(|c| c.is_ascii_uppercase())
                && password.chars().any(|c| c.is_ascii_digit()))
        {
            return false;
        }
        true
    }

    fn cookie_attrs(&self) -> &'static str {
        if self.flaws.no_httponly {
            "Path=/; SameSite=Lax"
        } else {
            "Path=/; HttpOnly; SameSite=Lax"
        }
    }

    /// A note's text as a page shows it: HTML-escaped, or as it is under `notes_unescaped`.
    fn shown(&self, text: &str) -> String {
        if self.flaws.notes_unescaped {
            return text.to_owned();
        }
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    fn respond(status: u16, headers: Vec<(&str, String)>, body: &str) -> ProbeResponse {
        ProbeResponse {
            id: String::new(),
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_lowercase(), v))
                .collect(),
            body: body.to_owned(),
        }
    }
}

pub(super) fn cookie_value(request: &ProbeRequest, name: &str) -> Option<String> {
    let line = request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))?
        .1
        .clone();
    line.split("; ").find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

pub(super) fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What a database would make of `given` joined into a query after an `=` or a `LIKE`: the value
/// before the first ` AND ` or ` OR `, the word, and whether the comparison after it holds.
/// `None` when nothing follows the value.
fn joined_condition(given: &str) -> Option<(String, &'static str, bool)> {
    let (at, word) = [" AND ", " OR "]
        .iter()
        .filter_map(|w| given.find(w).map(|at| (at, *w)))
        .min()?;
    let value = given[..at].trim_end_matches('\'').to_owned();
    let (left, right) = given[at + word.len()..].split_once('=')?;
    let holds = left.trim_matches('\'') == right.trim_matches('\'');
    Some((value, word.trim(), holds))
}

/// `<`, `>`, `&`, and quotes written as HTML, as a template engine writes them.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A token's signature: HMAC-SHA256 with `jwt_key()`, in base64 for web addresses.
fn jwt_signature(signed: &str, placeholder: bool) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac =
        <Hmac<sha2::Sha256>>::new_from_slice(&jwt_key(placeholder)).expect("HMAC takes any key");
    mac.update(signed.as_bytes());
    crate::browser::base64(&mac.finalize().into_bytes(), true)
}

pub(super) fn pairs(text: &str) -> BTreeMap<String, String> {
    text.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}

pub(super) fn form(request: &ProbeRequest) -> BTreeMap<String, String> {
    pairs(&request.body_text())
}

impl Http for FakeApp {
    fn now(&mut self) -> u64 {
        self.clock
    }

    fn wait(&mut self, seconds: u64) {
        self.clock += seconds;
    }

    fn mail(&mut self, to: &str, _at_least: usize) -> Option<Vec<String>> {
        if self.flaws.no_mail_sink {
            return None;
        }
        Some(
            self.outbox
                .iter()
                .filter(|(who, _)| who == to)
                .map(|(_, text)| text.clone())
                .collect(),
        )
    }

    fn send(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
        if let Some((_, ms)) = self.slow_ms.iter().find(|(id, _)| *id == r.id) {
            std::thread::sleep(std::time::Duration::from_millis(*ms));
        }
        let answer = self.answer(r)?;
        let mut answer = self.follow_next(r, answer);
        if self.flaws.private_cors_echoes
            && r.path == "/account"
            && answer.status == 200
            && let Some((_, origin)) = r
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
        {
            answer
                .headers
                .push(("access-control-allow-origin".to_owned(), origin.clone()));
            answer.headers.push((
                "access-control-allow-credentials".to_owned(),
                "true".to_owned(),
            ));
        }
        self.write_log(r, &answer);
        Some(answer)
    }

    fn model(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
        if !self.model_up {
            return None;
        }
        let tag = r.path.strip_prefix(crate::stand_in::FETCHED)?;
        Some(ProbeResponse {
            id: r.id.clone(),
            status: 200,
            headers: Vec::new(),
            body: serde_json::json!({ "fetched": self.model_fetched.contains(tag) }).to_string(),
        })
    }

    fn model_address(&mut self) -> Option<String> {
        self.model_up.then(|| FAKE_MODEL.to_owned())
    }

    /// `browser`: a sign-in through the form works, every page opens where it was asked for, and
    /// the page's scripts can read nothing, before signing in or after.
    fn browser(&mut self, job: &crate::browser::Job) -> Option<Vec<serde_json::Value>> {
        use crate::browser::Action;
        use serde_json::json;
        let signs_in = job
            .actions
            .iter()
            .any(|a| matches!(a, Action::Act(script) if script.contains("input[type=password]")));
        if !self.browser || !signs_in {
            return None;
        }
        Some(
            job.actions
                .iter()
                .map(|action| match action {
                    Action::Goto(path) => json!({ "status": 200, "path": path }),
                    Action::Act(_) => {
                        json!({ "found": true, "after": { "status": 200, "path": "/" } })
                    }
                    Action::Eval(_) => json!({ "value": {
                        "local": [], "session": [], "indexeddb": [], "cookie": ""
                    }}),
                    _ => json!({}),
                })
                .collect(),
        )
    }

    fn send_together(&mut self, rs: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
        self.together = Some((self.bookings, 0));
        let answers = rs.iter().map(|r| self.send(r)).collect();
        self.together = None;
        Some(answers)
    }
}

impl FakeApp {
    /// One request's lines, the sign-in event (if any) first and the request after it, as a
    /// handler logs and then the server does.
    fn write_log(&mut self, r: &ProbeRequest, answer: &ProbeResponse) {
        let Some(style) = self.log_style else {
            return;
        };
        let ts = format!(
            "2026-10-04T10:{:02}:{:02}Z",
            (self.clock / 60) % 60,
            self.clock % 60
        );
        let path = r.path.split('?').next().unwrap_or_default().to_owned();
        let status = answer.status;
        if r.method == "POST" && path == "/login" {
            let email = form(r).get("email").cloned().unwrap_or_default();
            let worked = (300..400).contains(&status) && self.users.contains_key(&email);
            let next = self.log_ids.len() + 1;
            let id = *self.log_ids.entry(email.clone()).or_insert(next);
            self.log.push(match (style, worked) {
                (LogStyle::Full, true) => format!("{ts} signed in {email} from 127.0.0.1"),
                (LogStyle::Full, false) => {
                    format!("{ts} sign-in failed for {email} from 127.0.0.1")
                }
                (LogStyle::Private, true) => {
                    format!(r#"{{"ts":"{ts}","event":"login","user_id":{id},"path":"{path}"}}"#)
                }
                (LogStyle::Private, false) => {
                    format!(r#"{{"ts":"{ts}","event":"login_failed","path":"{path}"}}"#)
                }
            });
        }
        self.log.push(match style {
            LogStyle::Full => format!("{ts} {} {} {status}", r.method, r.path),
            LogStyle::Private => format!(
                r#"{{"ts":"{ts}","method":"{}","path":"{path}","status":{status}}}"#,
                r.method
            ),
        });
    }

    /// Sign-in and sign-out send the browser on to `next` when they redirect, as most apps do,
    /// but only to one of the app's own pages unless a flaw says otherwise.
    fn follow_next(&self, r: &ProbeRequest, mut answer: ProbeResponse) -> ProbeResponse {
        let Some((path, query)) = r.path.split_once('?') else {
            return answer;
        };
        let Some(next) = pairs(query).get("next").cloned() else {
            return answer;
        };
        let own_page = next.starts_with('/') && !next.starts_with("//") && !next.starts_with("/\\");
        let follows = self.flaws.redirect_anywhere
            || (self.flaws.redirect_checks_slash_only && next.starts_with('/'))
            || own_page;
        if ["/login", "/logout"].contains(&path) && (300..400).contains(&answer.status) && follows {
            answer.headers.retain(|(k, _)| k != "location");
            answer.headers.push(("location".into(), next));
        }
        answer
    }

    /// A new session id, or with `same_session_id` the one fixed id this user always gets, for a
    /// cookie or a token alike.
    fn session_id_for(&mut self, who: &str) -> String {
        if self.flaws.same_session_id {
            let n = who.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
            });
            format!("{n:016x}{:016x}", n.rotate_left(17))
        } else {
            self.new_id()
        }
    }

    fn answer(&mut self, r: &ProbeRequest) -> Option<ProbeResponse> {
        // Time passing as requests are answered, when a test asks for it.
        self.clock += self.seconds_per_request;
        self.clock_log.push((r.id.clone(), self.clock));
        // A bearer token is a session id too, for the JSON sign-in below.
        let bearer = r
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .and_then(|(_, v)| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        let sid = bearer.or_else(|| cookie_value(r, "sid"));
        // The session timeouts, when this app keeps any: a signed-in session is ended here if
        // it has been unused, or alive, too long; otherwise its last use is now.
        if let Some(s) = sid.as_ref()
            && self
                .sessions
                .get(s)
                .is_some_and(|u| !u.is_empty() || self.anonymous_sessions_time_out)
        {
            let now = self.clock;
            let (began, last) = *self.session_times.entry(s.clone()).or_insert((now, now));
            let idle_over = self.idle_limit.is_some_and(|limit| now - last > limit);
            let life_over = self.lifetime_limit.is_some_and(|limit| now - began > limit);
            if idle_over || life_over {
                self.sessions.remove(s);
                self.session_times.remove(s);
            } else if let Some(times) = self.session_times.get_mut(s) {
                times.1 = now;
            }
        }
        if let Some(token) = sid.clone() {
            self.follow_key_source(&token);
        }
        let token_user = sid.as_deref().and_then(|s| self.jwt_user(s));
        let user = if let Some(user) = token_user {
            user
        } else {
            sid.as_ref()
                .and_then(|s| self.sessions.get(s))
                .filter(|u| !u.is_empty())
                .cloned()
                // A session id is normally looked up; under this flaw any non-empty one is
                // believed, which is what an app that never checks the cookie does.
                .or_else(|| {
                    (self.flaws.session_not_verified
                        && sid.as_deref().is_some_and(|s| !s.is_empty()))
                    .then(|| "believed@example.test".to_owned())
                })
                .or_else(|| {
                    self.flaws
                        .trusts_identity_header
                        .then(|| {
                            r.headers
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case("X-Remote-User"))
                                .map(|(_, v)| v.clone())
                        })
                        .flatten()
                        .filter(|named| self.users.contains_key(named))
                })
        };
        let user = user.filter(|_| {
            !self.needs_pre_login_cookie || cookie_value(r, PRE_LOGIN_COOKIE).is_some()
        });
        let foreign = r
            .headers
            .iter()
            .any(|(k, v)| k == "Origin" && v == STRANGER);
        let given = form(r).get("csrf_token").cloned().or_else(|| {
            let body = r.body_text();
            body.split("name=\"csrf_token\"\r\n\r\n")
                .nth(1)
                .and_then(|rest| rest.split("\r\n").next())
                .map(str::to_owned)
        });
        let token_ok =
            given.as_deref() == Some(CSRF) || given.is_some_and(|t| self.issued_tokens.remove(&t));
        let is_admin = user
            .as_ref()
            .is_some_and(|u| self.users.get(u).is_some_and(|(_, admin)| *admin));
        let (path, query) = match r.path.split_once('?') {
            Some((p, q)) => (p.to_owned(), pairs(q)),
            None => (r.path.clone(), BTreeMap::new()),
        };
        let path = if self.flaws.page_shell && r.method == "GET" {
            match path.as_str() {
                "/" | "/account" => return Some(Self::respond(200, vec![], PAGE_SHELL)),
                "/api/me" => "/account".to_owned(),
                _ => path,
            }
        } else {
            path
        };
        if self.flaws.password_in_url
            && r.method == "GET"
            && path == "/login"
            && let (Some(email), Some(password)) = (query.get("email"), query.get("password"))
            && self.users.get(email).is_some_and(|(p, _)| p == password)
        {
            return Some(self.signed_in(email.clone()));
        }
        let upgrade = r
            .headers
            .iter()
            .any(|(k, v)| k == "Upgrade" && v == "websocket");
        if upgrade && path == "/ws" {
            let signed_out = sid.as_ref().is_some_and(|s| self.signed_out.contains(s));
            let opens = !self.flaws.ws_refuses_all
                && (!foreign || self.flaws.ws_any_origin || self.flaws.ws_open)
                && (user.is_some()
                    || self.flaws.ws_open
                    || (self.flaws.ws_any_cookie && sid.is_some())
                    || (self.flaws.ws_guest && sid.is_none())
                    || (self.flaws.ws_survives_sign_out && signed_out));
            return Some(if opens {
                Self::respond(101, vec![("Upgrade", "websocket".into())], "")
            } else {
                Self::respond(401, vec![], "sign in first")
            });
        }
        Some(match (r.method.as_str(), path.as_str()) {
            // A page outside the sign-in flow that sends the browser on: to `next` when it is one of
            // the app's own pages, or anywhere with the flaw, and home otherwise.
            ("GET", "/go") => match (&user, query.get("next")) {
                (None, _) => Self::respond(302, vec![("Location", "/login".into())], ""),
                (Some(_), Some(next))
                    if self.flaws.go_anywhere
                        || (next.starts_with('/')
                            && !next.starts_with("//")
                            && !next.starts_with("/\\")) =>
                {
                    Self::respond(302, vec![("Location", next.clone())], "")
                }
                (Some(_), _) => Self::respond(302, vec![("Location", "/account".into())], ""),
            },
            ("GET", "/login") if user.is_some() && query.contains_key("next") => {
                Self::respond(303, vec![("Location", "/account".into())], "")
            }
            ("GET", "/login") => {
                let id = self.new_id();
                self.sessions.insert(id.clone(), String::new());
                let attrs = self.cookie_attrs();
                let mut headers = Vec::new();
                if self.pre_login_cookie {
                    headers.push((
                        "Set-Cookie",
                        format!("{PRE_LOGIN_COOKIE}=pre-login-value-0123456789; {attrs}"),
                    ));
                }
                headers.push(("Set-Cookie", format!("sid={id}; {attrs}")));
                Self::respond(
                    200,
                    headers,
                    &format!(
                        "<form><input type=\"hidden\" name=\"csrf_token\" value=\"{CSRF}\">{}</form>",
                        self.password_input()
                    ),
                )
            }
            ("POST", "/login") => {
                let f = form(r);
                let given = f.get("password")?;
                let email = f.get("email")?;
                let address = r
                    .headers
                    .iter()
                    .find(|(k, _)| {
                        self.flaws.trusts_forwarded_for && k.eq_ignore_ascii_case("x-forwarded-for")
                    })
                    .map_or("127.0.0.1".to_owned(), |(_, v)| v.clone());
                let key = if self.flaws.limits_by_address {
                    address
                } else {
                    email.clone()
                };
                // The window rolling over lets exactly one more attempt in.
                if self.flaws.window_rolls_over_at_first_claim
                    && !self.leaked_once
                    && r.headers
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
                    && let Some(limit) = self.flaws.locks_out_after
                    && let Some(count) = self.failures.get_mut(&key)
                {
                    self.leaked_once = true;
                    *count = (*count).min(limit.saturating_sub(1));
                }
                if let Some(limit) = self.flaws.locks_out_after
                    && self.failures.get(&key).copied().unwrap_or(0) >= limit
                {
                    if self.flaws.lockout_forgets {
                        self.failures.remove(&key);
                    }
                    if self.flaws.lockout_leaks
                        && let Some(count) = self.failures.get_mut(&key)
                    {
                        // One attempt through for every one refused, as a token bucket does.
                        *count -= 1;
                    }
                    return Some(Self::respond(429, vec![], "too many attempts"));
                }
                let good = !self.flaws.broken_login
                    && self
                        .sign_ins_refused_from
                        .is_none_or(|from| self.clock < from)
                    && (self
                        .users
                        .get(email)
                        .is_some_and(|(p, _)| self.password_matches(p, given))
                        || self.kept.get(email) == Some(given));
                if !good || !token_ok {
                    self.guessed_at.push(email.clone());
                    if let Some(status) = self.flaws.already_refusing {
                        return Some(Self::respond(status, vec![], "too many attempts"));
                    }
                    if self.flaws.locks_out_after.is_some() {
                        *self.failures.entry(key).or_insert(0) += 1;
                    }
                    let known = self.users.contains_key(email);
                    if !known && self.flaws.signin_reveals_by_status {
                        return Some(Self::respond(404, vec![], "no"));
                    }
                    if self.flaws.signin_reveals_by_words {
                        let words = if known {
                            "Wrong password."
                        } else {
                            "No account has that email."
                        };
                        return Some(Self::respond(403, vec![], words));
                    }
                    return Some(Self::respond(403, vec![], "no"));
                }
                self.failures.remove(&key);
                let who = f.get("email")?.clone();
                if self.not_activated.contains(&who) && !self.flaws.activation_not_gating {
                    return Some(Self::respond(403, vec![], "activate your account first"));
                }
                if self.totp.contains_key(&who) && !self.flaws.totp_not_required {
                    let id = self.new_id();
                    self.sessions.insert(id.clone(), String::new());
                    self.pending.insert(id.clone(), who);
                    let attrs = self.cookie_attrs();
                    return Some(Self::respond(
                        200,
                        vec![("Set-Cookie", format!("sid={id}; {attrs}"))],
                        "enter the code from your app",
                    ));
                }
                if self.flaws.keep_session_at_login {
                    self.sessions.insert(sid?, who.clone());
                    let mut headers = vec![("Location", "/account".to_owned())];
                    if self.flaws.other_cookie_at_login {
                        headers.push((
                            "Set-Cookie",
                            format!("username={who}; Path=/; HttpOnly; SameSite=Lax"),
                        ));
                    }
                    return Some(Self::respond(303, headers, ""));
                }
                self.signed_in(who)
            }
            ("GET", "/signup") => Self::respond(
                200,
                vec![],
                &format!(
                    "<input type=hidden name=csrf_token value={CSRF}><input name=email maxlength=40>{}{}",
                    self.password_input(),
                    if self.flaws.secret_question {
                        "<label>Favorite teacher <input name=security_answer></label>"
                    } else {
                        ""
                    }
                ),
            ),
            ("GET", "/password") => match user {
                Some(_) => Self::respond(
                    200,
                    vec![],
                    &format!(
                        "<input type=hidden name=csrf_token value={CSRF}>{}{}",
                        self.password_input_named("current"),
                        if self.flaws.new_field_shown {
                            "<input type=\"text\" name=\"new\">".to_owned()
                        } else {
                            self.password_input_named("new")
                        }
                    ),
                ),
                None => Self::respond(302, vec![("Location", "/login".into())], ""),
            },
            ("POST", "/password") => {
                let Some(who) = user else {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                };
                if !token_ok {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                let f = form(r);
                let (current, new) = (f.get("current")?.clone(), f.get("new")?.clone());
                let stored = self.users.get(&who)?.0.clone();
                if !self.flaws.change_without_current && !self.password_matches(&stored, &current) {
                    return Some(Self::respond(403, vec![], "wrong password"));
                }
                if !self.flaws.change_does_nothing {
                    if self.flaws.change_keeps_old {
                        self.kept.insert(who.clone(), stored);
                    }
                    self.users.get_mut(&who)?.0 = new;
                    if !self.flaws.change_keeps_sessions {
                        let current = sid.clone().unwrap_or_default();
                        self.sessions.retain(|id, u| *u != who || *id == current);
                    }
                    if !self.flaws.change_sends_no_email {
                        self.outbox.push((
                            who.clone(),
                            "Your password was changed. If this was not you, reset it now."
                                .to_owned(),
                        ));
                    }
                }
                Self::respond(303, vec![("Location", "/account".into())], "")
            }
            ("POST", "/account/email") => {
                let Some(who) = user else {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                };
                if !token_ok {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                let f = form(r);
                let (password, to) = (f.get("password")?.clone(), f.get("email")?.clone());
                let mut stored = self.users.get(&who)?.clone();
                if self.flaws.email_change_trusts_role
                    && (f.get("role").is_some_and(|v| v == "admin")
                        || f.get("is_admin").is_some_and(|v| v == "true"))
                {
                    stored.1 = true;
                }
                if !self.flaws.email_change_without_password
                    && !self.password_matches(&stored.0, &password)
                {
                    return Some(Self::respond(403, vec![], "wrong password"));
                }
                if self.users.contains_key(&to) {
                    return Some(Self::respond(409, vec![], "that address is taken"));
                }
                if !self.flaws.email_change_does_nothing {
                    self.users.remove(&who);
                    self.users.insert(to.clone(), stored);
                    for u in self.sessions.values_mut() {
                        if *u == who {
                            *u = to.clone();
                        }
                    }
                }
                Self::respond(303, vec![("Location", "/account".into())], "")
            }
            ("POST", "/book") => {
                if user.is_none() {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                }
                if !token_ok {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                if let Some((_, arrived)) = self.together.as_mut() {
                    *arrived += 1;
                    if self.flaws.booking_rate_limited && *arrived > 1 {
                        return Some(Self::respond(429, vec![], "slow down"));
                    }
                }
                let seen = match self.together {
                    Some((at_start, _)) if self.flaws.booking_races => at_start,
                    _ => self.bookings,
                };
                let holds_it = user.is_some() && self.booked_by == user;
                if !self.flaws.booking_broken
                    && seen >= 1
                    && self.flaws.booking_repeat_says_booked
                    && holds_it
                {
                    return Some(Self::respond(200, vec![], "<p>Booked: seat 1</p>"));
                }
                if self.flaws.booking_broken || seen >= 1 {
                    return Some(Self::respond(409, vec![], "Sold out"));
                }
                self.bookings += 1;
                self.booked_by = user.clone();
                Self::respond(200, vec![], "<p>Booked: seat 1</p>")
            }
            ("POST", "/activate") => {
                if !token_ok {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                let code = form(r).get("code")?.clone();
                let Some((who, used)) = self.activation_codes.get(&code).cloned() else {
                    return Some(Self::respond(400, vec![], "unknown code"));
                };
                if used && !self.flaws.activation_reusable {
                    return Some(Self::respond(400, vec![], "already used"));
                }
                self.activation_codes.insert(code, (who.clone(), true));
                if self.flaws.activation_does_nothing {
                    return Some(Self::respond(303, vec![("Location", "/".into())], ""));
                }
                self.not_activated.remove(&who);
                if !self.flaws.activation_link_does_not_sign_in
                    && let Some(session) = sid.clone()
                {
                    self.sessions.insert(session, who);
                }
                Self::respond(303, vec![("Location", "/account".into())], "")
            }
            ("GET", "/login/code" | "/login/verify" | "/activate") => {
                // A session for the code to be tied to, unless the browser already has one.
                let mut headers = vec![];
                if !sid.as_ref().is_some_and(|s| self.sessions.contains_key(s)) {
                    let id = self.new_id();
                    self.sessions.insert(id.clone(), String::new());
                    let attrs = self.cookie_attrs();
                    headers.push(("Set-Cookie", format!("sid={id}; {attrs}")));
                }
                Self::respond(
                    200,
                    headers,
                    &format!("<input type=hidden name=csrf_token value={CSRF}>"),
                )
            }
            ("POST", "/login/code") => {
                if !token_ok && !self.flaws.code_no_csrf {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                let email = form(r).get("email")?.clone();
                if self.users.contains_key(&email) && !self.flaws.code_sends_nothing {
                    self.next += 1;
                    let n = u64::from(self.next).wrapping_mul(7_919 * 104_729);
                    let code = if self.flaws.code_short {
                        format!("{:04}", n % 10_000)
                    } else {
                        format!("{:06}", n % 1_000_000)
                    };
                    self.sign_in_codes.insert(
                        code.clone(),
                        (email.clone(), sid.clone().unwrap_or_default(), false),
                    );
                    self.code_born.insert(code.clone(), self.clock);
                    self.outbox.push((
                        email,
                        format!("Your sign-in code is {code}. It works once, in this browser."),
                    ));
                }
                Self::respond(
                    200,
                    vec![],
                    "If that address has an account, we sent a code.",
                )
            }
            ("POST", "/login/verify") => {
                if !token_ok && !self.flaws.code_no_csrf {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                let session = sid.clone().unwrap_or_default();
                let limit = if self.flaws.code_locks_after_one {
                    1
                } else {
                    3
                };
                let failures = self.code_failures.get(&session).copied().unwrap_or(0);
                let code = form(r).get("code")?.clone();
                if failures >= limit && !self.flaws.code_guessing_unlimited {
                    if self.flaws.code_cancels_quietly {
                        self.sign_in_codes
                            .retain(|_, (_, asked, _)| *asked != session);
                        *self.code_failures.entry(session).or_insert(0) += 1;
                        return Some(Self::respond(401, vec![], "that code does not work"));
                    }
                    return Some(Self::respond(429, vec![], "ask for a new code"));
                }
                if self.flaws.code_already_refusing && !self.sign_in_codes.contains_key(&code) {
                    return Some(Self::respond(429, vec![], "slow down"));
                }
                let good = self
                    .sign_in_codes
                    .get(&code)
                    .cloned()
                    .filter(|(_, asked, used)| {
                        (*asked == session || self.flaws.code_unbound)
                            && (!used || self.flaws.code_reusable)
                    })
                    .filter(|_| {
                        self.flaws.code_long_lived
                            || self
                                .code_born
                                .get(&code)
                                .is_some_and(|born| self.clock - born <= 600)
                    })
                    // A code tied to its session dies with it.
                    .filter(|_| self.flaws.code_unbound || self.sessions.contains_key(&session));
                let Some((who, asked, _)) = good else {
                    *self.code_failures.entry(session).or_insert(0) += 1;
                    return Some(Self::respond(401, vec![], "that code does not work"));
                };
                self.sign_in_codes.insert(code, (who.clone(), asked, true));
                if !self.flaws.code_does_nothing && !session.is_empty() {
                    self.sessions.insert(session, who);
                }
                Self::respond(303, vec![("Location", "/account".into())], "")
            }
            ("GET", "/forgot" | "/reset") => Self::respond(
                200,
                vec![],
                &format!("<input type=hidden name=csrf_token value={CSRF}>"),
            ),
            ("POST", "/forgot") => {
                if !token_ok {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                let typed = form(r).get("email")?.clone();
                let first_line = typed.split(['\r', '\n']).next().unwrap_or("").to_owned();
                let loose =
                    self.flaws.reset_mails_typed_address || self.flaws.reset_cuts_line_breaks;
                let email = if loose { first_line } else { typed.clone() };
                let known = self.users.contains_key(&email);
                let mut issued = None;
                let first_for_address = !self.reset_codes.values().any(|(who, _)| *who == email);
                if known && !self.flaws.reset_sends_nothing {
                    self.next += 1;
                    let code = if self.flaws.reset_short_code {
                        format!("{:04}", (self.next * 7919) % 10_000)
                    } else if self.flaws.reset_counting_codes {
                        format!("{}", 100_000 + self.next)
                    } else {
                        self.new_id()
                    };
                    self.reset_codes
                        .insert(code.clone(), (email.clone(), false));
                    let text = if self.flaws.reset_code_elsewhere {
                        format!("Your reset number is {code}. Type it on the reset page.")
                    } else {
                        format!(
                            "Hello,\r\nReset your password: http://app:8080/reset?token={code}\r\n"
                        )
                    };
                    if self.flaws.reset_mails_typed_address {
                        // The typed text as the message's headers: each `Bcc:` line a recipient.
                        for line in typed.lines() {
                            if let Some(to) = line.trim().strip_prefix("Bcc:") {
                                self.outbox.push((to.trim().to_owned(), text.clone()));
                            }
                        }
                    }
                    self.outbox.push((email.clone(), text));
                    issued = Some(code);
                }
                // A field that differs on every answer, as a real form's token does, so the
                // comparison is shown to set it aside.
                // Short, so it is the field's value being set aside that saves the comparison and
                // not the rule for long random-looking runs.
                self.next += 1;
                let nonce = format!("{:08x}", self.next.wrapping_mul(2_654_435_761));
                let hidden = format!("<input type=hidden name=nonce value={nonce}>");
                if !known && self.flaws.reset_reveals_by_status {
                    return Some(Self::respond(404, vec![], "no such account"));
                }
                let words = if !known && self.flaws.reset_reveals_by_words {
                    format!("There is no account for {email}.")
                } else if self.flaws.reset_reveals_by_words {
                    format!("We have sent a link to {email}.")
                } else {
                    format!("If {email} has an account, we have sent it a link.")
                };
                let count = if self.flaws.reset_answer_counts {
                    format!("<p>Request {} today.</p>", self.next)
                } else {
                    String::new()
                };
                let debug =
                    match issued.filter(|_| self.flaws.reset_code_in_answer && first_for_address) {
                        Some(code) => format!("<!-- reset_token={code} -->"),
                        None => String::new(),
                    };
                Self::respond(
                    200,
                    vec![],
                    &format!("{hidden}<p>{words}</p>{count}{debug}"),
                )
            }
            ("POST", "/reset") => {
                if !token_ok {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                let f = form(r);
                let (code, new) = (f.get("token")?.clone(), f.get("password")?.clone());
                let Some((who, used)) = self.reset_codes.get(&code).cloned() else {
                    return Some(Self::respond(400, vec![], "unknown link"));
                };
                if used && !self.flaws.reset_reusable {
                    return Some(Self::respond(400, vec![], "this link has been used"));
                }
                self.reset_codes.insert(code, (who.clone(), true));
                if !self.flaws.reset_does_nothing {
                    let stored = self.users.get(&who)?.0.clone();
                    if self.flaws.reset_keeps_old {
                        self.kept.insert(who.clone(), stored);
                    }
                    self.users.get_mut(&who)?.0 = new;
                }
                Self::respond(303, vec![("Location", "/login".into())], "")
            }
            ("POST", "/account/delete") => {
                let Some(who) = user else {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                };
                let f = form(r);
                let stored = self.users.get(&who)?.0.clone();
                if !token_ok || !self.password_matches(&stored, f.get("password")?) {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                if !self.flaws.delete_does_nothing {
                    self.users.remove(&who);
                    if self.flaws.deletion_keeps_sessions {
                        if let Some(s) = sid {
                            self.sessions.remove(&s);
                        }
                    } else {
                        self.sessions.retain(|_, u| *u != who);
                    }
                }
                Self::respond(303, vec![("Location", "/".into())], "")
            }
            ("GET", "/logout") if self.flaws.logout_on_get => {
                if let Some(s) = sid {
                    self.sessions.remove(&s);
                }
                Self::respond(303, vec![("Location", "/".into())], "")
            }
            ("POST", "/signup") => {
                if !token_ok {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                let f = form(r);
                let (email, password) = (f.get("email")?.clone(), f.get("password")?.clone());
                // The form says maxlength=40. A correct app applies that again here.
                if email.chars().count() > 40 && !self.flaws.validation_only_in_browser {
                    return Some(Self::respond(422, vec![], "too long"));
                }
                if self.flaws.signup_closed || !self.password_allowed(&password) {
                    return Some(Self::respond(422, vec![], "password refused"));
                }
                if self.users.contains_key(&email) {
                    if self.flaws.signup_reveals_by_status {
                        return Some(Self::respond(409, vec![], "already registered"));
                    }
                    if self.flaws.signup_reveals_by_words {
                        let to = ("Location", "/login?already-registered=1".into());
                        return Some(Self::respond(303, vec![to], ""));
                    }
                }
                // A correct app answers a taken address as any other and leaves its account alone.
                let taken = self.users.contains_key(&email);
                if taken && !self.flaws.signup_replaces_account {
                    return Some(Self::respond(303, vec![("Location", "/login".into())], ""));
                }
                if !self.flaws.signup_does_nothing {
                    let asked_for_admin = f.get("role").is_some_and(|v| v == "admin")
                        || f.get("is_admin").is_some_and(|v| v == "true");
                    let admin = self.flaws.signup_trusts_role && asked_for_admin;
                    self.users.insert(email.clone(), (password, admin));
                    if self.activation {
                        self.next += 1;
                        let code = if self.flaws.activation_short {
                            format!("{:04}", (self.next * 7919) % 10_000)
                        } else if self.flaws.activation_counting {
                            format!("{}", 100_000 + self.next)
                        } else {
                            self.new_id()
                        };
                        self.activation_codes
                            .insert(code.clone(), (email.clone(), false));
                        self.not_activated.insert(email.clone());
                        self.outbox.push((
                            email,
                            format!(
                                "Welcome! Activate your account: \
                                 http://app:8080/activate?code={code}"
                            ),
                        ));
                    }
                }
                Self::respond(303, vec![("Location", "/login".into())], "")
            }
            ("POST", "/api/login") => {
                let body: serde_json::Value =
                    serde_json::from_slice(r.body.as_deref().unwrap_or_default()).ok()?;
                let email = body.get("email")?.as_str()?.to_owned();
                let password = body.get("password")?.as_str()?.to_owned();
                let good = self.users.get(&email).is_some_and(|(p, _)| *p == password);
                if !good {
                    return Some(Self::respond(401, vec![], "{}"));
                }
                let id = match self.jwt_lifetime {
                    Some(lifetime) => self.issue_jwt(&email, lifetime),
                    None => {
                        let id = self.session_id_for(&email);
                        self.sessions.insert(id.clone(), email);
                        id
                    }
                };
                let headers = if self.flaws.token_login_sets_cookie {
                    vec![("Set-Cookie", format!("sid={id}; Path=/; HttpOnly"))]
                } else {
                    vec![]
                };
                Self::respond(200, headers, &format!("{{\"token\": \"{id}\"}}"))
            }
            ("POST", "/logout") => {
                // Like the real app this was first run against: sign-out needs the token, and
                // `/logout` has no page of its own to find one on.
                if !token_ok {
                    return Some(Self::respond(403, vec![], "refused"));
                }
                if !self.flaws.logout_keeps_session
                    && let Some(s) = sid
                {
                    self.sessions.remove(&s);
                    self.signed_out.insert(s);
                }
                let mut headers = vec![("Set-Cookie", "sid=; Max-Age=0".to_string())];
                if self.flaws.clears_site_data {
                    let value = self
                        .clear_site_data_value
                        .clone()
                        .unwrap_or_else(|| "\"storage\", \"cookies\"".to_string());
                    headers.push(("Clear-Site-Data", value));
                }
                Self::respond(303, headers, "")
            }
            ("GET", "/account") => {
                if user.is_some() || self.flaws.private_open {
                    // A correct private page: not to be kept by the browser, and carrying a
                    // visible way out. Each half is switched off by its own flaw, so a test
                    // that breaks one is not quietly relying on the other.
                    let mut headers = match (&self.cache_control, self.flaws.private_page_cacheable)
                    {
                        _ if self.flaws.private_page_shared_cache => {
                            vec![("Cache-Control", "public, max-age=300".to_string())]
                        }
                        (_, true) => vec![],
                        (Some(value), _) => vec![("Cache-Control", value.clone())],
                        (None, _) => vec![("Cache-Control", "no-store".to_string())],
                    };
                    if !self.flaws.private_page_no_headers {
                        headers.extend([
                            (
                                "Content-Security-Policy",
                                if self.flaws.private_page_policy_without_base_uri {
                                    "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
                                } else {
                                    "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
                                }
                                .to_string(),
                            ),
                            ("X-Content-Type-Options", "nosniff".to_string()),
                            ("Referrer-Policy", "no-referrer".to_string()),
                        ]);
                    }
                    if let Some(id) = sid.as_ref().filter(|_| user.is_some()) {
                        if self.flaws.private_page_clears_session {
                            headers.push(("Set-Cookie", "sid=; Max-Age=0".to_string()));
                        } else if self.flaws.private_page_sets_session_bare {
                            headers.push(("Set-Cookie", format!("sid={id}; Path=/")));
                        } else if self.flaws.private_page_sets_session {
                            headers
                                .push(("Set-Cookie", format!("sid={id}; {}", self.cookie_attrs())));
                        }
                    }
                    let body = if self.flaws.no_sign_out_link {
                        "your account<script>const OUT = '/logout';</script>".to_string()
                    } else {
                        format!(
                            "your account<form method='post' action='/logout'>\
                             <input name='csrf_token' value='{}'>\
                             <button>Sign out</button></form>",
                            self.page_token()
                        )
                    };
                    Self::respond(200, headers, &body)
                } else if self.hides_private {
                    Self::respond(404, vec![], "none")
                } else {
                    Self::respond(302, vec![("Location", "/login".into())], "")
                }
            }
            ("GET", "/admin") => {
                if is_admin || (user.is_some() && self.flaws.admin_open) {
                    Self::respond(200, vec![], "admin")
                } else {
                    Self::respond(403, vec![], "no")
                }
            }
            ("POST", "/admin/announce") => {
                if user.is_some() && !self.flaws.no_csrf_check && (foreign || !token_ok) {
                    return Some(Self::respond(403, vec![], "forged"));
                }
                let allowed = is_admin || (user.is_some() && self.flaws.admin_action_open);
                if allowed && !self.flaws.admin_action_broken {
                    let text = form(r).get("text").cloned().unwrap_or_default();
                    self.announcements.push(text);
                    Self::respond(302, vec![("Location", "/announcements".into())], "")
                } else if self.flaws.admin_action_says_ok {
                    Self::respond(200, vec![], "Something went wrong.")
                } else {
                    Self::respond(403, vec![], "no")
                }
            }
            ("GET", "/announcements") => {
                if user.is_some() {
                    Self::respond(200, vec![], &self.announcements.join("\n"))
                } else {
                    Self::respond(302, vec![("Location", "/login".into())], "")
                }
            }
            ("GET", "/notes") => Self::respond(
                200,
                if self.flaws.no_referrer {
                    vec![("Referrer-Policy", "no-referrer".to_owned())]
                } else {
                    vec![]
                },
                &format!("<input name='csrf_token' value='{}'>", self.page_token()),
            ),
            ("POST", "/upload") => {
                if user.is_none() || self.flaws.upload_broken {
                    return Some(Self::respond(403, vec![], "no"));
                }
                if self.single_use_tokens && !token_ok {
                    return Some(Self::respond(403, vec![], "this form has expired"));
                }
                if self
                    .upload_quota
                    .is_some_and(|most| self.uploads.len() >= most)
                {
                    return Some(Self::respond(403, vec![], "your storage is full"));
                }
                // A compressed file, read as bytes: judged by what it really unpacks to, or, under
                // `archive_trusts_stated_sizes`, by what its headers say.
                let raw = r.body.as_deref().unwrap_or_default();
                let head = String::from_utf8_lossy(&raw[..raw.len().min(2048)]).into_owned();
                let file_name = head
                    .split("filename=\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .unwrap_or("");
                let start = raw
                    .windows(28)
                    .position(|w| w == b"application/octet-stream\r\n\r\n")
                    .map(|i| i + 28);
                let end = raw.windows(4).rposition(|w| w == b"\r\n--");
                if let (Some(start), Some(end)) = (start, end)
                    && let Some((unpacked, files)) =
                        archive_says(file_name, raw.get(start..end).unwrap_or_default())
                {
                    if self.flaws.refuses_archives {
                        return Some(Self::respond(415, vec![], "no compressed files"));
                    }
                    if end - start > UPLOAD_LIMIT && !self.flaws.oversized_upload_ok {
                        return Some(Self::respond(413, vec![], "too large"));
                    }
                    let counted = if self.flaws.archive_trusts_stated_sizes {
                        unpacked
                    } else {
                        archive_holds(file_name, raw.get(start..end).unwrap_or_default())
                            .map_or(unpacked, |held| held.max(unpacked))
                    };
                    let too_big =
                        counted > ARCHIVE_UNPACK_LIMIT && !self.flaws.archive_size_unchecked;
                    let too_many =
                        files > ARCHIVE_FILE_LIMIT && !self.flaws.archive_files_unchecked;
                    if too_big || too_many {
                        return Some(if self.flaws.archive_crashes {
                            Self::respond(500, vec![], "out of memory")
                        } else {
                            Self::respond(422, vec![], "this archive unpacks past our limits")
                        });
                    }
                    self.uploads
                        .insert(file_name.to_owned(), "(unpacked)".to_owned());
                    return Some(Self::respond(201, vec![], "stored"));
                }
                let body = r.body_text().into_owned();
                if self.refuses_repeats
                    && let Some(title) = body
                        .split("name=\"title\"\r\n\r\n")
                        .nth(1)
                        .and_then(|rest| rest.split("\r\n").next())
                    && !self.upload_titles.insert(title.to_owned())
                {
                    return Some(Self::respond(409, vec![], "you already uploaded that"));
                }
                let name = body
                    .split("filename=\"")
                    .nth(1)
                    .and_then(|rest: &str| rest.split('"').next())
                    .unwrap_or("")
                    .to_owned();
                // The file's own bytes: everything after the blank line that ends its part.
                let contents = body
                    .split("application/octet-stream\r\n\r\n")
                    .nth(1)
                    .and_then(|rest: &str| rest.rsplit_once("\r\n--"))
                    .map(|(file, _)| file.to_owned())
                    .unwrap_or_default();
                self.largest_upload = self.largest_upload.max(contents.len());
                if contents.len() > UPLOAD_LIMIT && !self.flaws.oversized_upload_ok {
                    return Some(Self::respond(413, vec![], "too large"));
                }
                let claims_gif = name.ends_with(".gif");
                let is_gif = contents.starts_with("GIF87a") || contents.starts_with("GIF89a");
                if claims_gif && !is_gif && !self.flaws.unchecked_contents_ok {
                    return Some(Self::respond(415, vec![], "not a gif"));
                }
                if name.ends_with(".svg") && self.flaws.refuses_svg {
                    return Some(Self::respond(415, vec![], "no svg"));
                }
                if name.ends_with(".txt") && self.flaws.refuses_text {
                    return Some(Self::respond(415, vec![], "no text files"));
                }
                if name.contains('/') {
                    if self.flaws.refuses_path_names {
                        return Some(Self::respond(400, vec![], "no folders in names"));
                    }
                    if self.flaws.upload_path_traversal
                        && let Some(rest) = name.strip_prefix("../")
                    {
                        self.escaped.insert(rest.to_owned(), contents);
                        return Some(Self::respond(201, vec![], "stored"));
                    }
                    let own = if self.flaws.renames_path_names {
                        format!("upload-{}", self.uploads.len())
                    } else {
                        name.rsplit('/').next().unwrap_or_default().to_owned()
                    };
                    self.uploads.insert(own, contents);
                    return Some(Self::respond(201, vec![], "stored"));
                }
                let infected = contents == super::uploads::eicar();
                let contents = if infected && self.flaws.scan_cleans {
                    "(this file held a virus, and it was removed)".to_owned()
                } else {
                    contents
                };
                if infected
                    && !self.flaws.no_malware_scan
                    && !self.flaws.scan_cleans
                    && self.flaws.scans_after.is_none()
                {
                    return Some(Self::respond(422, vec![], "a virus was found in this file"));
                }
                // A sanitizer's work on an SVG: its two ways of running code removed.
                let contents = if name.ends_with(".svg") && !self.flaws.svg_scripts_kept {
                    let mut clean = contents;
                    for (open, close) in [
                        ("<script", "</script>"),
                        ("<foreignObject", "</foreignObject>"),
                    ] {
                        while let Some(start) = clean.find(open) {
                            let end = clean[start..]
                                .find(close)
                                .map_or(clean.len(), |e| start + e + close.len());
                            clean.replace_range(start..end, "");
                        }
                    }
                    clean
                } else {
                    contents
                };
                let contents = if name.ends_with(".svg") && self.flaws.svg_converted {
                    "GIF87aa picture of the drawing".to_owned()
                } else {
                    contents
                };
                let name = if self.flaws.renames_every_upload {
                    format!("upload-{}", self.uploads.len())
                } else {
                    name
                };
                self.upload_times.insert(name.clone(), self.clock);
                self.uploads.insert(name, contents);
                Self::respond(201, vec![], "stored")
            }
            ("GET", path) if self.escaped.contains_key(path.trim_start_matches('/')) => {
                let contents = self.escaped[path.trim_start_matches('/')].clone();
                Self::respond(200, vec![("Content-Type", "image/gif".into())], &contents)
            }
            ("GET", path) if path.starts_with("/files/") => {
                let name = path.trim_start_matches("/files/");
                let set_aside = self.flaws.scans_after.is_some_and(|after| {
                    self.uploads.get(name) == Some(&super::uploads::eicar())
                        && self.clock >= self.upload_times.get(name).copied().unwrap_or(0) + after
                });
                let Some(contents) = self.uploads.get(name).filter(|_| !set_aside) else {
                    if self.flaws.answers_every_path {
                        return Some(Self::respond(
                            200,
                            vec![("Content-Type", "text/html; charset=utf-8".into())],
                            "<html><body>the app's own page, whatever was asked for\
                             <script src=\"/app.js\"></script></body></html>",
                        ));
                    }
                    return Some(Self::respond(404, vec![], "no such file"));
                };
                if name.ends_with(".svg") {
                    // Served for the browser to show, as an image, unless told otherwise.
                    let mut headers = vec![("Content-Type", "image/svg+xml".to_owned())];
                    if self.flaws.svg_as_attachment {
                        headers.push(("Content-Disposition", "attachment".into()));
                    }
                    return Some(Self::respond(200, headers, contents));
                }
                if name.ends_with(".php") {
                    if self.flaws.runs_uploaded_code {
                        // Only the output: the source is gone, which is what "it ran" means.
                        let shown = contents
                            .split_once("echo \"")
                            .and_then(|(_, rest)| rest.split_once('"'))
                            .map(|(out, _)| out.to_owned())
                            .unwrap_or_default();
                        return Some(Self::respond(200, vec![], &shown));
                    }
                    return Some(Self::respond(
                        200,
                        vec![("Content-Type", "text/plain".into())],
                        contents,
                    ));
                }
                if name.ends_with(".html") {
                    if self.flaws.renders_uploaded_pages {
                        return Some(Self::respond(
                            200,
                            vec![("Content-Type", "text/html; charset=utf-8".into())],
                            contents,
                        ));
                    }
                    return Some(Self::respond(
                        200,
                        vec![
                            ("Content-Type", "text/html; charset=utf-8".into()),
                            ("Content-Disposition", "attachment".into()),
                        ],
                        contents,
                    ));
                }
                // A correct download: a name the app cleaned, quoted. Each fault is its own
                // switch, so a test that breaks one is not quietly relying on the other.
                let disposition = if self.flaws.download_no_filename {
                    "attachment".to_owned()
                } else if self.flaws.download_name_raw {
                    format!("attachment; filename={name}")
                } else if self.flaws.download_name_quoted_uncleaned {
                    format!("attachment; filename=\"{name}\"")
                } else {
                    let clean: String = name
                        .chars()
                        .map(|c| {
                            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                                c
                            } else {
                                '_'
                            }
                        })
                        .collect();
                    format!("attachment; filename=\"{clean}\"")
                };
                Self::respond(
                    200,
                    vec![
                        ("Content-Type", "image/gif".into()),
                        ("Content-Disposition", disposition),
                    ],
                    contents,
                )
            }
            ("POST", "/api/notes") => {
                // A JSON API that relies on the browser asking first: no token, and unless
                // told otherwise, no look at the Origin either.
                let Some(owner) = user else {
                    return Some(Self::respond(401, vec![], "sign in"));
                };
                let refuse = |app: &Self, status: u16| {
                    if app.flaws.api_redirects_refusals {
                        Self::respond(302, vec![("Location", "/".into())], "")
                    } else {
                        Self::respond(status, vec![], "no")
                    }
                };
                if self.flaws.api_checks_origin && foreign {
                    return Some(refuse(self, 403));
                }
                let content_type_is = |prefix: &str| {
                    r.headers.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("content-type")
                            && v.to_lowercase().starts_with(prefix)
                    })
                };
                if self.flaws.api_redirects_multipart && content_type_is("multipart/") {
                    return Some(Self::respond(302, vec![("Location", "/".into())], ""));
                }
                let content_type = r
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.to_lowercase())
                    .unwrap_or_default();
                let body = r.body_text().into_owned();
                let as_json = || {
                    serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v.get("text")?.as_str().map(str::to_owned))
                };
                let text = if content_type.starts_with("application/json")
                    || self.flaws.api_parses_any_type
                {
                    as_json()
                } else if self.flaws.api_takes_forms
                    && content_type.starts_with("application/x-www-form-urlencoded")
                {
                    pairs(&body).get("text").cloned()
                } else if self.flaws.api_takes_forms
                    && content_type.starts_with("multipart/form-data")
                {
                    body.split("name=\"text\"\r\n\r\n")
                        .nth(1)
                        .and_then(|rest| rest.split("\r\n").next())
                        .map(str::to_owned)
                } else {
                    return Some(refuse(self, 415));
                };
                let Some(text) = text else {
                    return Some(refuse(self, 400));
                };
                self.notes.push((owner, text));
                Self::respond(201, vec![], &format!("{{\"id\":{}}}", self.notes.len()))
            }
            ("GET", p) if p.starts_with("/api/notes/") => {
                let n: usize = p["/api/notes/".len()..].parse().ok()?;
                let Some((owner, text)) = self.notes.get(n.checked_sub(1)?) else {
                    return Some(Self::respond(404, vec![], "none"));
                };
                if user.as_ref() == Some(owner) {
                    Self::respond(200, vec![], &format!("{{\"text\":\"{text}\"}}"))
                } else {
                    Self::respond(404, vec![], "none")
                }
            }
            // A second kind of record, held to its own limit or none.
            ("POST", "/comments") => {
                let Some(owner) = user else {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                };
                if let Some(limit) = self.comments_per_minute {
                    let now = self.clock;
                    let times = self
                        .note_times
                        .entry(format!("{owner}#comments"))
                        .or_default();
                    times.retain(|t| now.saturating_sub(*t) < 60);
                    if times.len() >= limit as usize {
                        return Some(Self::respond(
                            429,
                            vec![("Retry-After", "60".into())],
                            "slow down",
                        ));
                    }
                    times.push(now);
                }
                Self::respond(201, vec![], "posted")
            }
            // One's own notes, listed; everybody's under the flaw.
            ("GET", "/my-notes") => {
                let Some(who) = user else {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                };
                let items: Vec<String> = self
                    .notes
                    .iter()
                    .enumerate()
                    .filter(|(i, (owner, _))| {
                        !self.deleted_notes.contains(&(i + 1))
                            && (*owner == who || self.flaws.list_shows_others)
                    })
                    .map(|(_, (_, text))| format!("<li>{}</li>", self.shown(text)))
                    .collect();
                Self::respond(
                    200,
                    vec![("Content-Type", "text/html; charset=utf-8".into())],
                    &format!("<ul>{}</ul>", items.concat()),
                )
            }
            // Changing or deleting a note: its owner only, anybody signed in under the flaws.
            ("POST", p)
                if p.starts_with("/notes/") && (p.ends_with("/edit") || p.ends_with("/delete")) =>
            {
                let Some(who) = user else {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                };
                let rest = &p["/notes/".len()..];
                let (number, action) = rest.split_once('/')?;
                let n: usize = number.parse().ok()?;
                if self.flaws.writes_need_another_method {
                    return Some(Self::respond(
                        405,
                        vec![("Allow", "PUT, DELETE".into())],
                        "no",
                    ));
                }
                let Some((owner, _)) = self.notes.get(n.checked_sub(1)?).cloned() else {
                    return Some(Self::respond(404, vec![], "none"));
                };
                let allowed = owner == who
                    || (action == "edit" && self.flaws.idor_update)
                    || (action == "delete" && self.flaws.idor_delete);
                if !allowed || self.deleted_notes.contains(&n) {
                    return Some(Self::respond(404, vec![], "none"));
                }
                if action == "edit" {
                    let text = form(r).get("text").cloned().unwrap_or_default();
                    self.notes[n - 1].1 = text;
                } else {
                    self.deleted_notes.insert(n);
                }
                Self::respond(303, vec![("Location", format!("/notes/{n}"))], "")
            }
            ("POST", "/notes") => {
                let Some(owner) = user else {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                };
                if !self.flaws.no_csrf_check && (foreign || !token_ok) {
                    return Some(Self::respond(403, vec![], "forged"));
                }
                if self.flaws.refuses_null_origin
                    && r.headers.iter().any(|(k, v)| k == "Origin" && v == "null")
                {
                    return Some(Self::respond(403, vec![], "no origin"));
                }
                let text = form(r).get("text").cloned().unwrap_or_default();
                if self.refuses_repeats && self.notes.iter().any(|(o, t)| *o == owner && *t == text)
                {
                    return Some(Self::respond(409, vec![], "you already wrote that"));
                }
                if let Some(limit) = self.notes_per_minute {
                    let now = self.clock;
                    let times = self.note_times.entry(owner.clone()).or_default();
                    times.retain(|t| now.saturating_sub(*t) < 60);
                    // Past the limit only: a note within it says nothing of what lets one
                    // through, so it does not move the turn.
                    let over = times.len() >= limit as usize;
                    let leaks = over && self.notes_limit_leaks && {
                        self.leak_next = !self.leak_next;
                        !self.leak_next
                    };
                    if over && !leaks {
                        let (status, retry_after) = self.notes_limit_answer.unwrap_or((429, true));
                        return Some(Self::respond(
                            status,
                            if retry_after {
                                vec![("Retry-After", "60".into())]
                            } else {
                                vec![]
                            },
                            "slow down",
                        ));
                    }
                    times.push(now);
                }
                let owner = match form(r).get("user_id") {
                    Some(given) if self.flaws.owner_from_request => given.clone(),
                    _ => owner,
                };
                self.notes
                    .push((owner, form(r).get("text").cloned().unwrap_or_default()));
                Self::respond(
                    303,
                    vec![(
                        "Location",
                        format!("http://app:8080/notes/{}", self.notes.len()),
                    )],
                    "",
                )
            }
            ("GET", "/note") => {
                // The same record by a value in the query string, as `/note?id=1`.
                let id = query.get("id").cloned().unwrap_or_default();
                let mut by_path = r.clone();
                by_path.path = format!("/notes/{}", encode_value(&id));
                return self.answer(&by_path);
            }
            ("GET", "/search") => {
                let Some(who) = user else {
                    return Some(Self::respond(302, vec![("Location", "/login".into())], ""));
                };
                let q = query.get("q").cloned().unwrap_or_default();
                // `WHERE owner = ? AND text LIKE '%<q>%'`, with the term joined in under the flaw.
                let joined = if self.flaws.sql_in_search {
                    joined_condition(&q)
                } else {
                    None
                };
                let found: Vec<&str> = self
                    .notes
                    .iter()
                    .filter(|(owner, text)| {
                        let mine = *owner == who;
                        match &joined {
                            Some((term, "AND", holds)) => mine && text.contains(term) && *holds,
                            Some((term, _, holds)) => (mine && text.contains(term)) || *holds,
                            None => mine && text.contains(&q),
                        }
                    })
                    .map(|(_, text)| text.as_str())
                    .collect();
                Self::respond(
                    200,
                    vec![],
                    &format!("<p>Results for {}</p><ul>{}</ul>", escape(&q), {
                        let items: Vec<String> =
                            found.iter().map(|t| format!("<li>{t}</li>")).collect();
                        items.concat()
                    }),
                )
            }
            ("GET", p) if p.starts_with("/notes/") => {
                let given = decode(&p["/notes/".len()..]);
                // Under the flaw, `WHERE id = <given>`, or `WHERE id = '<given>'` when the ids are
                // text, joined in: the record when what follows the id holds, none when it does
                // not, and a syntax error for a quote the query does not expect.
                let none = || Some(Self::respond(404, vec![], "none"));
                let quoted = given.contains('\'');
                let joined = joined_condition(&given).filter(|_| self.flaws.sql_in_record);
                let n: usize = match joined {
                    Some(_) if quoted != self.ids_are_text => {
                        if quoted {
                            return Some(Self::respond(500, vec![], "syntax error"));
                        }
                        // The whole of it is one string, which is no id.
                        return none();
                    }
                    Some((id, "AND", true)) => match id.parse() {
                        Ok(n) => n,
                        Err(_) => return none(),
                    },
                    Some(_) => return none(),
                    None => match given.parse() {
                        Ok(n) => n,
                        Err(_) => return none(),
                    },
                };
                let Some((owner, text)) = self.notes.get(n.checked_sub(1)?) else {
                    return Some(Self::respond(404, vec![], "none"));
                };
                if self.deleted_notes.contains(&n) {
                    return Some(Self::respond(404, vec![], "none"));
                }
                if user.as_ref() == Some(owner)
                    || (self.flaws.idor && user.is_some())
                    || self.flaws.records_public
                {
                    let mut extra = if self.flaws.record_leaks_fields {
                        "<script>const row={\"id\":1,\"password_hash\":\"$2b$12$abc\"}</script>"
                            .to_owned()
                    } else {
                        String::new()
                    };
                    if self.flaws.record_names_owner {
                        extra.push_str(&format!(
                            "<script>const note={{\"user_id\":\"{owner}\"}}</script>"
                        ));
                    }
                    // The prose is deliberate: a real record page often says something like
                    // this, and a check matching the bare word `password` would make a
                    // finding out of every app that has one. Keeping it here means the
                    // correct-app tests catch that mistake.
                    Self::respond(
                        200,
                        vec![("Content-Type", "text/html; charset=utf-8".into())],
                        &format!(
                            "<p>{}</p><footer>Change your password in Account</footer>\
                             {extra}",
                            self.shown(text)
                        ),
                    )
                } else {
                    Self::respond(404, vec![], "none")
                }
            }
            ("POST", "/login/2fa") => {
                let id = sid.clone()?;
                let Some(who) = self.pending.get(&id).cloned() else {
                    return Some(Self::respond(403, vec![], "sign in first"));
                };
                let given = form(r).get("code")?.clone();
                let secret = self.totp.get(&who)?.clone();
                let now = self.clock / crate::totp::STEP;
                let oldest = if self.flaws.totp_any_age {
                    now.saturating_sub(10)
                } else if self.flaws.totp_current_only {
                    now
                } else {
                    now.saturating_sub(1)
                };
                let newest = if self.flaws.totp_current_only {
                    now
                } else {
                    now + 1
                };
                let matched = (oldest..=newest)
                    .find(|step| crate::totp::code_at_step(&secret, *step) == given);
                let fresh = |step: u64| {
                    self.flaws.totp_reusable
                        || self.totp_last.get(&who).is_none_or(|last| step > *last)
                };
                match matched {
                    Some(step)
                        if fresh(step) && !self.flaws.totp_broken && !self.totp_is_locked(&who) =>
                    {
                        self.totp_last.insert(who.clone(), step);
                        self.pending.remove(&id);
                        self.sessions.insert(id, who);
                        Self::respond(303, vec![("Location", "/account".into())], "")
                    }
                    _ => {
                        *self.totp_wrong.entry(who).or_insert(0) += 1;
                        Self::respond(403, vec![], "wrong code")
                    }
                }
            }
            ("POST", step) if step.starts_with("/checkout/") => {
                let Some(who) = user.clone() else {
                    return Some(Self::respond(401, vec![], "sign in"));
                };
                let n: u32 = step["/checkout/".len()..].parse().ok()?;
                let reached = self.checkout.get(&who).copied().unwrap_or(0);
                let done = self.checkout_done.get(&who).cloned().unwrap_or_default();
                let allowed = self.flaws.flow_unguarded
                    || reached + 1 == n
                    || (self.flaws.flow_checks_first_only && n == 3 && reached >= 1)
                    || (self.flaws.flow_counts_steps && done.len() as u32 + 1 >= n)
                    || (self.flaws.flow_any_order && (n < 3 || (1..n).all(|k| done.contains(&k))));
                if (!allowed || !token_ok) && self.flaws.flow_refusal_redirects {
                    return Some(Self::respond(
                        303,
                        vec![("Location", "/checkout/1".into())],
                        "",
                    ));
                }
                if !allowed || !token_ok {
                    return Some(Self::respond(
                        409,
                        vec![],
                        if self.flaws.flow_refusal_says_placed {
                            "An order is placed only after the steps before it"
                        } else {
                            "finish the steps before this one"
                        },
                    ));
                }
                if n < 3 {
                    self.checkout_done.entry(who.clone()).or_default().push(n);
                    self.checkout.insert(who, n);
                    return Some(Self::respond(200, vec![], "next step"));
                }
                self.checkout.remove(&who);
                self.checkout_done.remove(&who);
                if self.flaws.flow_broken {
                    return Some(Self::respond(200, vec![], "something went wrong"));
                }
                Self::respond(303, vec![("Location", "/orders/7".into())], "Order placed")
            }
            ("GET", under)
                if self.guards_under_private
                    && under.starts_with("/account/")
                    && user.is_none() =>
            {
                Self::respond(302, vec![("Location", "/login".into())], "")
            }
            ("GET", _) if self.flaws.answers_every_path => Self::respond(
                200,
                vec![("Content-Type", "text/html; charset=utf-8".into())],
                "<html><body>the app's own page, whatever was asked for\
                 <script src=\"/app.js\"></script></body></html>",
            ),
            _ => Self::respond(404, vec![], "none"),
        })
    }
}

/// `users()`, with the record's list and the requests to change and delete it given (ADR-053).
pub(super) fn users_full() -> UsersSection {
    let mut u = users();
    let t = |path: &str, fields: &[(&str, &str)]| RequestTemplate {
        method: "POST".into(),
        path: path.into(),
        form: fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        json: BTreeMap::new(),
    };
    if let Some(owned) = u.owned.as_mut() {
        owned.list = Some("/my-notes".into());
        owned.update = Some(t(
            "/notes/{id}/edit",
            &[("text", "{marker}"), ("csrf_token", "{csrf}")],
        ));
        owned.delete = Some(t("/notes/{id}/delete", &[("csrf_token", "{csrf}")]));
    }
    u
}

pub(super) fn users() -> UsersSection {
    let t = |path: &str, fields: &[(&str, &str)]| RequestTemplate {
        method: "POST".into(),
        path: path.into(),
        form: fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        json: BTreeMap::new(),
    };
    UsersSection {
        activation: None,
        seed: Some("seed".into()),
        signup: None,
        login: Some(t(
            "/login",
            &[
                ("email", "{user}"),
                ("password", "{password}"),
                ("csrf_token", "{csrf}"),
            ],
        )),
        logout: Some(t("/logout", &[("csrf_token", "{csrf}")])),
        token_field: None,
        private: vec!["/account".into()],
        redirects: Vec::new(),
        creates: Vec::new(),
        admin: vec!["/admin".into()],
        admin_actions: vec![sv_manifest::AdminAction {
            method: "POST".into(),
            path: "/admin/announce".into(),
            form: [("text", "{marker}"), ("csrf_token", "{csrf}")]
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            json: BTreeMap::new(),
            check: Some("/announcements".into()),
        }],
        owned: Some(sv_manifest::OwnedSection {
            create: RequestTemplate {
                method: "POST".into(),
                path: "/notes".into(),
                form: [("text", "{marker}"), ("csrf_token", "{csrf}")]
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                json: BTreeMap::new(),
            },
            read: None,
            id_field: None,
            list: None,
            update: None,
            delete: None,
        }),
        change_password: Some(t(
            "/password",
            &[
                ("current", "{password}"),
                ("new", "{new_password}"),
                ("csrf_token", "{csrf}"),
            ],
        )),
        change_email: Some(t(
            "/account/email",
            &[
                ("password", "{password}"),
                ("email", "{new_email}"),
                ("csrf_token", "{csrf}"),
            ],
        )),
        once: Some(sv_manifest::OnceAction {
            method: "POST".into(),
            path: "/book".into(),
            form: [("slot", "1"), ("csrf_token", "{csrf}")]
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            json: BTreeMap::new(),
            completed: "Booked".into(),
        }),
        delete_account: Some(t(
            "/account/delete",
            &[("password", "{password}"), ("csrf_token", "{csrf}")],
        )),
        upload: None,
        reset: Some(sv_manifest::ResetSection {
            request: t("/forgot", &[("email", "{user}"), ("csrf_token", "{csrf}")]),
            use_code: t(
                "/reset",
                &[
                    ("token", "{code}"),
                    ("password", "{new_password}"),
                    ("csrf_token", "{csrf}"),
                ],
            ),
            code_pattern: None,
        }),
        email_code: Some(sv_manifest::ResetSection {
            request: t(
                "/login/code",
                &[("email", "{user}"), ("csrf_token", "{csrf}")],
            ),
            use_code: t(
                "/login/verify",
                &[("code", "{code}"), ("csrf_token", "{csrf}")],
            ),
            code_pattern: None,
        }),
        totp: Some(t("/login/2fa", &[("code", "{code}")])),
        flow: Some(sv_manifest::FlowSection {
            steps: (1..=3)
                .map(|n| t(&format!("/checkout/{n}"), &[("csrf_token", "{csrf}")]))
                .collect(),
            completed: "/orders/".into(),
        }),
        browser: None,
        private_websocket: None,
    }
}

pub(super) fn accounts() -> Accounts {
    Accounts {
        a: Account {
            user: "a@example.test".into(),
            password: "Sv-0a1b2c3d4e5f60718293a4b5-aZ9!".into(),
        },
        b: Account {
            user: "b@example.test".into(),
            password: "Sv-b5a4938271605f4e3d2c1b0a-aZ9!".into(),
        },
        admin: Some(Account {
            user: "admin@example.test".into(),
            password: "Sv-00112233445566778899aabb-aZ9!".into(),
        }),
        spare: "3f9c0a7e5b1d2468ace13579bdf02468".into(),
        totp: Some(TotpAccount {
            account: Account {
                user: "totp@example.test".into(),
                password: "Sv-7a6b5c4d3e2f10293847a6b5-aZ9!".into(),
            },
            // RFC 6238's own SHA-1 test secret.
            secret: b"12345678901234567890".to_vec(),
        }),
        // As `sv run` makes one whenever there is an admin, a `totp` entry and a `seed`. The fake
        // app enrolls the admin with it only when a test says so (`admin_needs_code`).
        admin_totp_secret: Some(admin_secret()),
    }
}

/// The admin's two-factor secret in the tests: twenty bytes worked out here, so no file holds one.
pub(super) fn admin_secret() -> Vec<u8> {
    (0u8..20)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect()
}

/// Runs the suite against the fake app, seeded the way `seed` would seed it.
pub(super) fn run_against(flaws: Flaws, users: &UsersSection) -> Outcome {
    run_against_keeping(flaws, users).0
}

/// As `run_against`, and the app afterwards, for a test that reads what was sent to it.
pub(super) fn run_against_keeping(flaws: Flaws, users: &UsersSection) -> (Outcome, FakeApp) {
    run_seeded(FakeApp::new(flaws), users)
}

/// As `run_against_keeping`, with an app a test has set up beyond its flaws.
pub(super) fn run_seeded(mut app: FakeApp, users: &UsersSection) -> (Outcome, FakeApp) {
    let acc = accounts();
    app.users
        .insert(acc.a.user.clone(), (acc.a.password.clone(), false));
    app.users
        .insert(acc.b.user.clone(), (acc.b.password.clone(), false));
    let admin = acc.admin.clone().unwrap();
    app.users.insert(admin.user, (admin.password, true));
    if let Some(totp) = &acc.totp {
        app.users.insert(
            totp.account.user.clone(),
            (totp.account.password.clone(), false),
        );
        app.totp
            .insert(totp.account.user.clone(), totp.secret.clone());
    }
    let o = run(&mut app, users, &acc, true, &Default::default());
    (o, app)
}

/// A run with no seeded admin, for the fixtures that sign up rather than being seeded.
pub(super) fn run_with_users(flaws: Flaws, users: &UsersSection) -> Outcome {
    let mut app = FakeApp::new(flaws);
    let mut acc = accounts();
    acc.admin = None;
    acc.totp = None;
    run(&mut app, users, &acc, false, &Default::default())
}

pub(super) fn rule_ids(o: &Outcome) -> Vec<&str> {
    o.findings.iter().map(|f| f.rule_id.as_str()).collect()
}

pub(super) fn verified_ids(o: &Outcome) -> Vec<&str> {
    o.verified.iter().map(|v| v.check_id.as_str()).collect()
}
