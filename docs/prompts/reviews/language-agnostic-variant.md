# A review of the prompt library, and five new prompts (7 October 2026)

Written by session securevibe-e2, at the request of session paper-facts, made at the owner's asking on 6 October 2026.
It is a reading, not a trial. No build was made for it, nothing here has been tested, and no prompt file was changed.
Every suggestion below is for a trial to try before anything changes status.

**What was read:**
- the 17 coding prompts in `data/prompts.json` and the 14 design-time prompts in `data/design-prompts.json`;
- the trial records: `docs/prompts/library-trial/README.md` and `delivery-protocol.md`, and
  `docs/prompts/loop-scale/README.md`;
- every finding of the 69 loop-scale builds in `item6-findings.json`, counted by rule;
- the specification `sv init` prints (`crates/sv-manifest/src/spec.rs`);
- the code of each check a prompt names;
- the text of each requirement cited, in `data/frameworks/`.

Counts such as "53 of 69" are builds of the loop-scale trial with that finding. They come from one brief (the club
app) and two models, so they say what is common there, not everywhere.

## The short version

1. **Three prompts can stop `sv` from testing the app,** and one more can stop the app's own forms working:
   - `secrets-in-the-environment` says to stop when a key is missing, and `sv run` gives an app none of its own keys.
   - `files-under-own-names` says nothing about where files go, and `sv run` makes the app's folder read-only.
   - `design-limits` and `design-sign-in` can lock `sv` out or stop its admin checks.
   - `security-headers` allows a Referrer-Policy that, with `changes-from-own-pages`, makes an app refuse its own
     forms.
   Each has a small change, below.
2. **Three "not shown" prompts were held back by false alarms in `sv` that have since been fixed:**
   - `database-placeholders` and `files-under-own-names`: names bound to fixed text, and paths from the app's own
     database;
   - `design-actions-once`: a booking repeated by its holder.
   They should be tried again before anything else; they may simply work now. A fourth, `same-site-redirects`, is
   tied to a code rule that by the owner's decision still flags a checked redirect. It should be held to the running
   app's redirect check instead (Part 1).
3. **Two citations look wrong:**
   - `password-hashing` cites V11.4.4, which is about making an encryption key from a password. Storing passwords is
     V11.4.2.
   - `security-headers` cites V3.4.3, whose text asks for `object-src 'none'` and `base-uri 'none'`. Neither the
     prompt nor `probe.security-headers` asks for either.
4. **The commonest problems `sv` found have no prompt.** The leaders: no window isolation (63 of 69), no way to
   report a security problem (53), a Content-Security-Policy that reports nowhere (35), a version number in the answers
   (29), no limit on wrong passwords (19, high), and no limit on creating records (18). The five new prompts below cover
   them.
5. **Prompts that ask the owner a question stall when the owner is away.** In the library trial, six of ten
   `design-limits` builds stopped and wrote nothing. Every prompt that asks should say what to do when no answer comes.

## Part 1: each prompt as it stands

For each: whether it is clear, whether an AI tool can follow it with no person there, whether following it could break
something, whether its check is the right one, and what I would change. "Fine" means I found nothing to change.

### Coding prompts (`data/prompts.json`)

**`settings-file-first`** (shown). Clear, and followable alone.
- **Conflict:** it says to *delete* a capability line the builder is unsure of, while `design-brief` says to write
  `true`. A builder given both is told opposite things. The owner chose on 6 October 2026 to keep this prompt's
  wording, because both readings leave nothing excluded. That holds, but the two prompts should not be handed to the
  same builder without one line saying which wins.
- **Change:** none to the words. In delivery, never send both.

**`git-from-the-start`** (shown). Clear, and followable alone.
- **Gap:** the committable `.env` is still the commonest high finding, in 61 of 69 loop-scale builds, which had no
  library prompt. The prompt says to leave `.env` files out, but not how to spell the line.
- **Change:** name the lines: "`.env` and `.env.*`, with `!.env.example` so the example is still committed". A
  builder that writes `*.env` leaves `.env` itself committable.

**`secrets-in-the-environment`** (shown, with the harm flag recorded).
- **Breaks the run:** "stop with a clear message if one is missing" makes the app refuse to start under `sv run`. The
  run gives an app no keys of its own: only placeholder AI keys, the test sign-in provider's settings, and the mail
  server's address. So an app that needs, say, an email service's key never starts, and every running-app check
  says "not assessed".
- **Change:** "If a key for one feature is missing (email, payments, an outside service), start anyway, turn off only
  that feature, and say so in the log and on that feature's page. Only the app's own session-signing secret may be
  made up when missing: generate a random one at start, and write a warning to the log that sessions will not
  survive a restart." Leave the `.env.example` sentence as it is.
- **Also:** the record notes six of its ten builds wrote an unreadable `securevibe.toml`, against three of ten
  without it. A shorter version is worth trying beside it: the change above and the `.env.example` sentence, dropping
  "or anything else that gets committed".

**`database-placeholders`** (not shown: `sv`'s false alarm).
- Clear and safe. The citation (V1.2.4) and the check are right.
- The false alarm was a fixed setup script and a fixed list of queries. Names bound once to fixed text and lookups in
  a table of fixed queries were fixed on 4 October (DESIGN, "Names that stand for fixed text"). Whether the setup
  script's case is covered too I have not checked.
- **Change:** none. Try it again.

**`no-shell-with-input`** (not shown: no build took the shortcut).
- Clear and safe; the citation (V1.2.5) and the check are right.
- Twice now the build without the prompt already did the safe thing. The brief does not tempt this shortcut.
- **Change:** none to the words. Try it with a brief that asks for "convert the uploaded file with ImageMagick" or
  similar, where the obvious code is a shell line.

**`files-under-own-names`** (not shown: `sv`'s false alarm, since fixed).
- **Breaks the run:** it does not say *where* to save files. The app's folder is read-only while `sv` runs it (the
  specification says so), so an app that saves uploads under its own folder fails every upload.
- **Change:** add "Save them in a folder the app is told about through a setting (for example `UPLOAD_DIR`), outside
  the code's folder, created at start if it is missing." Then try it again; the false alarm (a path from the app's
  own database) was fixed on 5 October (#738).

**`password-hashing`** (not shown: no reading).
- **Wrong citation:** it cites V11.4.4, which is about deriving *encryption keys* from passwords. Storing passwords is
  V11.4.2: "passwords are stored using an approved, computationally intensive, key derivation function". It also
  cites V11.4.1 (no MD5 for anything), which is right.
- **Gap:** one trial build used PBKDF2, which the prompt does not name, and 23 Haiku loop-scale builds had a PBKDF2
  count too low.
- **Change:** cite V11.4.2 in place of V11.4.4, and add a sentence on PBKDF2. The check's own citation
  (`ast.weak-password-key-derivation`, V11.4.4 only) should then be looked at too. That changes what counts as
  evidence, so it is a decision with a record, not part of this review.
- The PBKDF2 sentence: "If you use PBKDF2, use at least 600,000 rounds with SHA-256, 210,000 with SHA-512, or
  1,300,000 with SHA-1." Those are the figures `sv`'s rule holds code to.

**`same-site-redirects`** (not shown: `sv` flagged a checked redirect).
- Clear and safe; V3.7.2 fits.
- **Wrong check for showing it:** both builds checked the destination with a function of their own, and
  `ast.open-redirect` flagged both. That is not fixed and will not be. The owner decided on 5 October 2026 that the
  finding stays for a checked destination, at the rule's low confidence, naming the function (DESIGN, "A redirect to
  a parameter every caller fills with the app's own route says so"). So this rule can never show the prompt
  working.
- **Change:** hold the prompt to `probe.open-redirect`. That is the running check: it sends the sign-in flow an
  address on another site, as a full address and as one beginning with `//`, and reads where the app sends the
  browser. It is only ever a finding, so "passes" means no finding. It needs `[stack.run.users]`.

**`sanitize-rich-text`** (not shown).
- Clear and safe; V1.3.1 fits.
- The blind spot that hid the trial-2 build was fixed (the check now reads declared packages with no lockfile).
- **Change:** none to the words. Both briefs' builds already cleaned the HTML without it, so it needs a brief that
  tempts the shortcut more, such as one asking to "show the notes exactly as the editor wrote them".

**`security-headers`** (shown). Four changes:
- **Can break the app's own forms:** "`Referrer-Policy: strict-origin-when-cross-origin` or stricter" lets a builder
  pick `no-referrer`. Under that policy browsers send `Origin: null` with the app's own forms. An app that also
  checks Origin (as `changes-from-own-pages` asks) then refuses its own forms. `sv` has a rule for exactly this,
  `probe.own-forms-refused`, and it was found in 10 of the 35 Sonnet loop-scale builds. Say "`strict-origin-when-
  cross-origin` or `same-origin`; never `no-referrer`".
- **Citation:** V3.4.3 asks for a policy that includes `object-src 'none'` and `base-uri 'none'`. Add both to the
  prompt. Separately, `probe.security-headers` credits V3.4.3 for any Content-Security-Policy at all, which is more
  than it checks. That is a question about the check, for the owner, not about the prompt.
- **Check:** add `probe.private-page-headers` to its rules. It asks the same four headers of signed-in pages, and the
  prompt already says "every response". It was a finding in 23 Haiku loop-scale builds.
- **Optional:** the two commonest header findings, `Cross-Origin-Opener-Policy` and CSP reporting, could go here too.
  I have kept them as a separate prompt (new prompt 1 below) so this one, already shown, is not changed by more than
  the trial needs.

**`cross-site-access`** (not shown: no build turned it on).
- Clear and safe; V3.4.2 fits. The brief never tempts it.
- **Change:** none. Try it with a brief that has a separate front end on another port, where turning on CORS is the
  obvious shortcut.

**`plain-error-pages`** (not shown: every build already did it).
- Fine. V13.4.2 and V16.5.1 fit.
- **Change:** none. It may simply not be needed with these models.

**`check-every-request`** (not shown: every build already did it).
- Fine.
- **Change:** none.

**`ai-feature-guard`** (shown). Long, but every builder followed it.
- **Possible harm:** a home-made "ruleset of the known patterns" can refuse ordinary messages that contain "ignore"
  or "instructions". Say "match whole phrases, not single words, and test that an ordinary question containing
  those words still gets an answer."
- **Gap:** the reply's length is not limited. `probe.ai-output-unbounded` (C7.1.2, level 1: "model-generated output
  is bounded by length limits") was a finding in 6 loop-scale builds. Add: "Set a maximum reply length on every call
  to the model." Add the rule and C7.1.2 to the prompt only once a trial shows it.

**`changes-from-own-pages`** (untested). Clear.
- **Can break the app's own forms:** "or the server checks the request's Origin header" is safe only if a request with
  a valid token is accepted even when Origin is `null` (see `security-headers` above).
- **Change:** add "Accept a request with a valid token even when its Origin is `null`; refuse one from another
  site's Origin." V3.5.1 fits.

**`private-pages-no-store`** (shown).
- Fine. V14.3.2 fits.

**`sessions-hard-to-steal`** (not shown: no reading).
- Clear, and V3.3.2, V3.3.4, V7.2.3, and V7.4.1 all fit. "Secure once the app is served over HTTPS" is the right
  wording: `sv run` speaks plain HTTP.
- **Change:** none. It needs a brief with no framework session handling to tempt a home-made one.

### Design-time prompts (`data/design-prompts.json`)

**`design-who-may-do-what`** (not shown: no build needed it).
- **Stalls:** "If something I ask for later does not fit the table, stop and ask me" stalls with the owner away.
- **Change:** add "If I am not here to ask, choose the more restrictive answer, note it under the table as a question
  for me, and go on."

**`design-actions-once`** (not shown: `sv`'s false alarm, since fixed). Clear.
- Since 5 October the check sends the copies as two users, so a repeat answered "Booked" to its holder is no longer
  counted.
- **Change:** none. Try it again.

**`design-limits`** (shown, with a warning).
- **Stalls:** "Ask me how many..." stalled six of ten builds with the owner away.
- **Can lock `sv` out:** "counted per account ... so not only by address" invites a second, per-address limit. `sv`
  signs in up to 60 times in one run from one address, so a per-address limit can lock it out. That happened in one
  loop-scale build; its checks fell to 8.
- **Change, three parts:**
  - "If I am not here to answer, use 5 wrong passwords in 15 minutes and 30 new records a minute, write them down,
    and say so."
  - "Count wrong passwords in a row for each account, and start again after a right one."
  - "If you also limit by address, set that limit well above what one person does (at least 100 an hour)."

**`design-when-things-fail`** (not shown: every build already did it).
- **Can break the app in real use:** "Every outside call has a time limit of a few seconds" is too short for an AI
  service, whose replies can take tens of seconds. An app built to it fails for real users, and `sv`'s test model
  answers at once, so no check would notice.
- **Change:** "a few seconds for most services, and up to a minute for an AI service".

**`design-logging`** (shown). Fine, and "write to standard output" suits the read-only folder `sv run` makes.

**`design-sign-in`** (shown).
- **Stopped `sv`'s admin checks:** the record says "Admins sign in with a second step" stopped them, because the
  settings had no field for the code. They have one now. The specification's `totp` entry lets `sv` work out the
  admin's codes from `SV_ADMIN_TOTP_SECRET`, made fresh for each run.
- **Change:** add "In the seed script, enroll the admin account with the secret in `SV_ADMIN_TOTP_SECRET`, and fill
  in the `totp` entry in securevibe.toml."
- **Stalls:** "Ask me" needs the same fallback as `design-limits`: use 30 minutes and 12 hours, and say so.

**`design-brief`** (untested).
- **Stalls:** "Do not start on the code until I have agreed the brief" is the right rule with an owner present and a
  certain stall without one.
- **Change:** add "If I am not here, write the brief from what I have said, mark each guess as a guess, and go on."
- See also `settings-file-first` above for the conflicting "write true".

**`design-when-to-bring-in-a-person`**, **`design-what-we-do-if`**, and **`design-which-rules-apply`** (untested; no
check).
- Clear, safe, and honest that no check shows them.
- **Change:** none.

**`design-data-list`** (untested).
- **Gap:** it says to write the categories under `[data]`, but not that only the spellings on the specification's
  list count. A category not on the list holds the app to level 2.
- **Change:** add "using only the names the specification lists (contact, financial, payment-card, health,
  government-id, credentials, children, location, files, business-confidential, other-personal)".

**`design-what-the-app-talks-to`**, **`design-safe-defaults`**, and **`design-before-changing`** (untested).
- Clear and safe.
- **Change:** none.

## Part 2: five new prompts

Each is for a problem `sv` checks, that no prompt covers, and that the loop-scale builds had often. I read each
requirement's text in `data/frameworks/` before citing it. The level is each requirement's ASVS level.

### 1. `isolate-pages-and-report` (window isolation and CSP reports)

> Send `Cross-Origin-Opener-Policy: same-origin` on every HTML page the app serves, error pages included (use
> `same-origin-allow-popups` only if the app opens a sign-in pop-up). Add a reporting address to the
> Content-Security-Policy: `report-uri /csp-reports`, and a route at that path that accepts the report, writes one
> line to the log, and answers 204. Set both in the same place as the other security headers.

- **Requirements:**
  - V3.4.8 (level 3): "...include the Cross-Origin-Opener-Policy header field with the same-origin directive or the
    same-origin-allow-popups directive";
  - V3.4.7 (level 3): "...specifies a location to report violations".
- **Rules:** `probe.opener-policy-missing`, `probe.csp-no-report`.
- **Why AI-built apps get it wrong:** the two headers are rarely in examples or framework defaults. Window isolation
  was missing in 63 of 69 builds, both models alike. CSP reporting was missing in all 35 Sonnet builds; Haiku's
  apps mostly sent no policy at all, so they could not be found for it.
- **Note:** both requirements are level 3, so for most apps this fixes low findings rather than the level they are
  held to. It is cheap, and it removes the finding seen in nearly every report.

### 2. `quiet-production-server` (no version numbers, a type on every answer)

> Run the app under a production server, never the framework's development server (for Python, gunicorn or uvicorn;
> for Node, the app's own server with `app.disable('x-powered-by')` in Express). Remove version numbers from every
> answer: no `Server` or `X-Powered-By` header carrying a version, and none on error pages. Send a `Content-Type` on
> every answer with a body, with `; charset=utf-8` on text, HTML, and JSON. Put the start command in securevibe.toml's
> `start`.

- **Requirements:**
  - V13.4.6 (level 3): "...does not expose detailed version information of backend components";
  - V4.1.1 (level 1): "...every HTTP response with a message body contains a Content-Type header field that matches
    the actual content of the response, including the charset parameter".
- **Rules:** `probe.version-disclosed`, `probe.content-type`.
- **Why AI-built apps get it wrong:** the quickest way to start an app is the development server, which announces
  itself with its version. Version numbers were found in 29 of 69 builds, all Haiku; a missing type or charset in 11.
  I could not confirm from the stored summaries which server those builds ran, so "the development server" is my
  likely explanation, not a finding.
- **Can break:** a production server needs its own start line. The prompt says to put it in `start`, which is where
  `sv` reads it.

### 3. `limits-without-asking` (wrong passwords and new records, counted on the server)

> Limit wrong passwords and new records on the server, using the numbers under [policy] in securevibe.toml. If they
> are not there, write `failed-sign-ins = 5`, `within-minutes = 15`, and `requests-per-minute = 30` under [policy],
> and use those; do not stop to ask. Count wrong passwords in a row for each account, and start the count again after
> a right one. Count new records per signed-in person per minute. Past either limit, answer 429 Too Many Requests
> with a `Retry-After` header, and keep refusing until then. If you also limit by address, set that limit well above
> what one person does (at least 100 an hour). Write a test that goes one past each limit.

- **Requirements:**
  - V6.3.1 (level 1): "controls to prevent attacks such as credential stuffing and password brute force are
    implemented according to the application's security documentation". Writing the numbers into [policy] is that
    documentation.
  - V2.4.1 (level 2): "anti-automation controls are in place to protect against excessive calls to application
    functions that could lead to ... garbage-data creation".
- **Rules:** `probe.failed-sign-ins-unlimited`, `probe.create-rate-unlimited`.
- **Why AI-built apps get it wrong:** nothing in a feature request asks for a limit, and a limit is invisible while
  building. No limit on wrong passwords was found in 19 of 69 builds (18 of 34 Haiku; high). No limit on new records
  was found in 18.
- **How it differs from `design-limits`:** this is its coding-time version, which never stops to ask. A trial can
  compare the two, with the owner away.
- **Can break:** the per-address clause and the reset after a right password are there so `sv`'s own 60 sign-ins
  from one address are not refused.

### 4. `password-rules` (length, common, and breached passwords)

> At sign-up and at every password change, refuse a password shorter than 8 characters (15 is better), and refuse
> one found in a list of common and breached passwords that ships with the app: at least the 100,000 most common, in
> a file in the repository, not fetched over the network. Say plainly why a password was refused. Allow any other
> password, spaces and any characters included, up to at least 64 characters.

- **Requirements:**
  - V6.2.1 (level 1): "user set passwords are at least 8 characters in length";
  - V6.2.4 (level 1): "...checked against ... at least, the top 3000 passwords";
  - V6.2.12 (level 2): "...checked against a set of breached passwords".
- **Rules:** `probe.short-password-accepted`, `probe.common-password-accepted`, `probe.breached-password-accepted`.
- **Why AI-built apps get it wrong:** they check length and stop. In the loop-scale builds, short passwords were
  accepted in 2, common ones in 4, and breached ones in 4, all Haiku, so this prompt is a smaller gain than the others.
- **Why "in the repository":** `sv run` gives the app no network, so a check against an online breached-password
  service fails there and in any closed network. `sv`'s breached test password is far down the common list (past the
  12,000th), so a list of only the top 10,000 would not refuse it. The prompt should not name `sv`'s test passwords:
  a prompt that teaches the test proves nothing.
- **Can break:** a list file in the repository adds about a megabyte, which is acceptable.

### 5. `security-contact` (a way to report a problem)

> Add a SECURITY.md at the top of the repository saying how to report a security problem (an email address or a
> form), what to include, and how soon a reply should come. If the app is on the web, also serve
> `/.well-known/security.txt` with a `Contact:` line and an `Expires:` line a year ahead.

- **Requirements:** none. Nothing in ASVS, AISVS, or Appendix C asks for this, and `config.security-contact` credits
  no requirement (its code says so). It is offered because it is the second commonest finding.
- **Rule:** `config.security-contact`.
- **Why AI-built apps get it wrong:** nobody asks for it. It was found in 53 of 69 builds, and in none of the loop arm,
  where the check named it.
- **Note:** the prompt shows nothing about the app's security, only that there is somewhere to send a report. Mark it
  that way in the library.

**Runner-up, not one of the five:** a maximum reply length for the AI feature (C7.1.2, `probe.ai-output-unbounded`,
6 builds). It belongs inside `ai-feature-guard` as one more sentence, above.

## Part 3: how prompts reach the builder

1. **The loop arm fixed what `securevibe_check` named, and nothing it could not see.** In the loop-scale trial, code
   findings fell to almost none in the loop arm, while the running-app findings stayed the same in every arm. The
   commonest of those were the AI feature's three, missing headers, and missing sign-in limits. Those are exactly the
   prompts shown to work (`ai-feature-guard`, `security-headers`) or proposed here (`limits-without-asking`). So
   delivering prompts at the start (ADR-044) is aimed at the right gap. The delivery test in `delivery-protocol.md`
   will say whether it closes it.
2. **Deliver only prompts that cannot stop the run.** Until the changes in Part 1 are made, `secrets-in-the-
   environment` and `files-under-own-names` can leave the app unable to start or to take files under `sv run`.
   `design-limits` and `design-brief` can stall with the owner away. A builder given these through the MCP server
   cannot know.
3. **Never deliver two prompts that disagree** (`settings-file-first` and `design-brief` on unsure capabilities;
   `security-headers`' "or stricter" and `changes-from-own-pages`' Origin check). Either fix the words or have the
   delivery choose one.
4. **Every prompt that asks the owner should carry its "if I am not here" line.** The trials run with the owner away
   by design, and real builders often are too.
5. **Length crowds out the specification.** `secrets-in-the-environment`'s builds wrote more unreadable settings files.
   That may be chance, but a delivery that adds several prompts at once should be tried for the same effect: count
   unreadable `securevibe.toml` files in the delivering arm, as Part A of the delivery protocol does for the
   specification.
6. **A prompt that `sv` cannot see working should say so where it is delivered** (the design prompts with no check, and
   `security-contact` above). Otherwise a builder reads "follow this" as "this is checked".
