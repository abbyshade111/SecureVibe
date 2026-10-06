//! The spec `sv init` prints. This is what the user hands to their AI coding tool, and it is the
//! only interface between the back-and-forth that builds the app and the checks that grade it.
//!
//! It is written to be pasted into a chat, so it says what each answer is used for and is explicit
//! that over-claiming is cheap and under-claiming is not.

pub const STARTER_MANIFEST: &str = r#"# securevibe.toml — what this app is, so `sv` knows which security requirements apply.
# Written by your AI coding tool; read it yourself before you trust the report.
manifest-version = 1

[app]
name = ""
description = ""          # plain language, one or two sentences
audience = "customers"    # just-me | my-team | customers | public
deployment = "internet"   # local-only | local-network | internet

[stack]
languages = []            # e.g. ["python", "typescript"]

[stack.run]
# How to run the app, so `sv` can test it rather than only read it.
# Leave blank and every check that needs a running app reports "not assessed".
image = ""                # container image, e.g. "python:3.12-slim"
build = ""                # e.g. "pip install -r requirements.txt"
start = ""                # e.g. "uvicorn app:app --host 0.0.0.0 --port $PORT"
#   Listen on 0.0.0.0, not 127.0.0.1 or localhost: `sv` runs the app in a container and asks it
#   from a second one, and an app listening on 127.0.0.1 answers only from inside its own.
test = ""                 # e.g. "pytest -q". Name requirement ids in your test names — see below.
test-report = ""          # where `test` writes JUnit XML, e.g. "junit.xml". See below.
# test-time-limit = 600     # seconds the tests may run before `sv` stops them; ten minutes if left out
health = "/"              # a path that returns 200 once the app is up
# graphql = "/graphql"      # where it answers GraphQL, if it does
# websocket = "/ws"         # where it accepts WebSocket connections, if it does

# [stack.run.oidc]
# Only if people sign in through another service ("Sign in with Google" and the like). For the run,
# the app is given a test provider of `sv`'s own instead of the real one, and must use it: read
# OIDC_ISSUER, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET from the environment when they are set.
# start = "/login/google"   # the path that sends the browser to the provider to sign in
# private = "/account"      # a page only a signed-in person sees

# [stack.run.ai]
# Only if the app has a feature that sends what people type to an AI model. For the run, the app is
# given a test model of `sv`'s own instead of the real service, and must use it: read
# OPENAI_BASE_URL and ANTHROPIC_BASE_URL (and the placeholder keys in OPENAI_API_KEY and
# ANTHROPIC_API_KEY) from the environment when they are set; the OpenAI and Anthropic libraries do
# this by themselves. Nothing is sent to an AI service and nothing is spent.
# chat = { path = "/api/chat", json = { message = "{prompt}" } }   # sends one message; {prompt} is the text
# signed-in = true          # the feature needs a signed-in user (uses [stack.run.users])
# base-url-env = ["LLM_BASE_URL"]   # other variables the app reads the model's address from
# kill-switch = "AI_DISABLED=1"   # the setting that turns the feature off; a second copy of the app
#                                 # is started with it and must answer without calling the model
# mcp-url-env = "MCP_SERVER_URL"  # where the app reads its MCP server's address, if it gives the
#                                 # model tools from one; it is given a test MCP server there
# record-tool = { name = "get_note", args = { id = "{id}" } }   # a tool of the app's own the model
#                                 # calls to read one record; the test model asks it, as the second
#                                 # user, for the first user's `owned` record (needs signed-in)
# reads-owned = true              # the feature searches people's own `owned` records to answer; the
#                                 # second user asks about a private note the first one saved

# [stack.run.fetch]
# Only if a feature fetches a web address a person gives it (a link preview, an import from a web
# address). The run gives it the address of a test server on the app's own private network, which
# nobody allowed, and one that redirects, and sees whether either was fetched.
# request = { path = "/preview", form = { url = "{url}", csrf_token = "{csrf}" } }
# signed-in = true          # if the feature needs a signed-in user
# follows-redirects = true  # only if following a redirect is what the feature is for

# [stack.run.mcp-server]
# Only if the app itself serves tools to AI models over MCP's HTTP transport. The run asks it to
# start a session as usual, then from a foreign web page (an `Origin` it has never heard of) and
# under a foreign name (a `Host` it is not), and ends a session and tries to use it again.
# path = "/mcp"             # where the MCP endpoint answers
# token-env = "MCP_TOKEN"   # if it takes one fixed access token, the variable it reads it from; the
#                           # run gives it a random one and asks whether none, or a made-up one, works
# public = true             # instead, if it is meant to answer anyone with no token at all
# probe-tool = { name = "echo", args = { text = "hello" } }   # a tool safe to call again and again,
#                           # with arguments it accepts; the run sends it an unknown argument, one far
#                           # too long, one of the wrong type, and a very large request

[stack.run.users]
# Optional: how to sign in, so `sv run` can check what a signed-in user can reach — other users'
# data, admin pages, whether logging out really ends the session. Leave it out and all of that is
# reported as "not assessed". `sv` makes two ordinary accounts, A and B, with fresh passwords.
# The app's folder is read-only while `sv` runs it, so keep its data somewhere like /tmp.
# `sv` signs in up to 60 times in one run, all from one address, a few of them on purpose with a
# wrong password, and last of all the wrong passwords of the guessing check (`failed-sign-ins`
# under [policy], plus two). An app should limit sign-in attempts; let the copy `sv` runs allow
# that many (for example, through a setting only the test copy is started with) and keep the real
# limit everywhere else. A sign-in the limit refuses is named in the report, and the checks that
# needed it are not assessed.
# seed = "python seed.py"   # creates them; gets SV_USER_A, SV_PASSWORD_A, SV_USER_B, SV_PASSWORD_B,
#                           # and SV_ADMIN, SV_ADMIN_PASSWORD when `admin` is listed, and
#                           # SV_USER_TOTP, SV_PASSWORD_TOTP, SV_TOTP_SECRET when `totp` is set,
#                           # and SV_ADMIN_TOTP_SECRET too when both are
#   `sv` runs it once in each copy of the app it starts, inside that copy's container, after the
#   app answers on `health`, never before. So the app must make its own tables when it starts,
#   and the seed must work on the fresh database of a new copy.
# signup = { path = "/signup", form = { email = "{user}", password = "{password}", csrf_token = "{csrf}" } }
# login  = { path = "/login",  form = { email = "{user}", password = "{password}", csrf_token = "{csrf}" } }
# logout = { path = "/logout", form = { csrf_token = "{csrf}" } }
# private = ["/account"]    # pages only a signed-in user should see
# admin = ["/admin"]        # pages only an admin should see (needs `seed`)
# admin-actions = [{ path = "/admin/announce", form = { text = "{marker}", csrf_token = "{csrf}" }, check = "/announcements" }]
#   Requests only an admin should be able to make (needs `seed`). Each is sent by the first ordinary
#   user and then by the admin, so list only what is safe to do twice in a test copy of the app. Put
#   `{marker}` in a field and name in `check` a page where that text shows once the action has been
#   done, within the page's first 4,000 characters: that is how `sv` tells whose request worked.
#   Without `check`, only an ordinary user's request answered as a success is reported.
# once = { path = "/book", form = { slot = "1", csrf_token = "{csrf}" }, completed = "Booked" }
#   An action that should go through only once, such as booking the last seat or redeeming a
#   one-time code. It is sent 20 times at the same instant, half as the first user and half as the
#   second, and the answers that carry `completed` (in the page, or in the address it sends the
#   browser to) are counted for each. It going through for both users is the finding; a repeat from
#   the user who already has it may say `completed` again. The app has to start the run with exactly
#   one of the thing to take, which either user could take (set it up in `seed`), and nothing else in
#   the run may take it. A `private` page is needed, to show both users were signed in.
# owned = { create = { path = "/notes", form = { text = "{marker}", csrf_token = "{csrf}" } }, read = "/notes/{id}" }
# change-password = { path = "/password", form = { current = "{password}", new = "{new_password}", csrf_token = "{csrf}" } }
# change-email = { path = "/account/email", form = { password = "{password}", email = "{new_email}", csrf_token = "{csrf}" } }
#   Changing the signed-in user's email address, with `{password}` where the app asks for the
#   password again. Only ever done to an account made for it through `signup`.
# delete-account = { path = "/account/delete", form = { password = "{password}", csrf_token = "{csrf}" } }
# upload = { path = "/upload", field = "file", form = { csrf_token = "{csrf}" }, serves-at = "/files/{name}", max-bytes = 1048576 }
#   `field` is the form field the file goes in; `serves-at` is where an upload can be fetched back,
#   with {name} standing for its file name — leave it out if uploads are never served over the web.
#   `max-bytes` is the largest file you say the app accepts, which is what it is held to.
# reset = { request = { path = "/forgot", form = { email = "{user}", csrf_token = "{csrf}" } }, use = { path = "/reset", form = { token = "{code}", password = "{new_password}", csrf_token = "{csrf}" } } }
#   A forgotten-password reset. The run gives the app a mail server that keeps what it is sent, at
#   SMTP_HOST and SMTP_PORT (no encryption, any user name and password accepted); `{code}` is the
#   code or the token from the link in the email. Add `code-pattern = "…"`, a regular expression
#   whose first group is the code, when it is not a link's `token`, `code`, or `key`.
# email-code = { request = { path = "/login/code", form = { email = "{user}", csrf_token = "{csrf}" } }, use = { path = "/login/verify", form = { code = "{code}", csrf_token = "{csrf}" } } }
#   Signing in with a code or link the app emails, beside the password. The code is used in the
#   same browser session that asked for it; `code-pattern` works as for `reset`.
# activation = { use = { path = "/activate", form = { code = "{code}", csrf_token = "{csrf}" } } }
#   Activating an account with the code the app emails at sign-up (needs `signup`). `code-pattern`
#   works as for `reset`.
# flow = { steps = [{ path = "/checkout/address", form = { street = "1 Main St", csrf_token = "{csrf}" } }, { path = "/checkout/pay", form = { card = "4242", csrf_token = "{csrf}" } }, { path = "/checkout/confirm", form = { csrf_token = "{csrf}" } }], completed = "Order placed" }
#   Anything done in more than one step, in order. `completed` is text the last step answers with
#   only when the whole thing really finished — in the page, or in the address it sends you on to.
#   The probes go through it once in order, then try skipping steps as another user.
# totp = { path = "/login/2fa", form = { code = "{code}", csrf_token = "{csrf}" } }
#   The code step of a two-factor sign-in, sent after the password in the same session. Needs
#   `seed`: make one more account from SV_USER_TOTP and SV_PASSWORD_TOTP, and enroll it in
#   two-factor sign-in with SV_TOTP_SECRET (base32, as an authenticator app takes it). The probes
#   work out its codes themselves and try one twice, and one from a few minutes ago. If admins
#   sign in with a code too, enroll the SV_ADMIN account with SV_ADMIN_TOTP_SECRET (also base32):
#   the admin checks then finish the admin's sign-in with its code. Both secrets are made fresh for
#   each run and never appear in a report.
# browser = { text-form = "/notes/new", shows = "/notes" }
#   Checks made in a real browser (a headless Chromium on the same fenced network), signed in as the
#   first user: that the sign-out control on each private page can really be seen; that clicking it,
#   with a sign-in made for the purpose, empties what the app kept in the browser's storage; and,
#   with `text-form`, that text typed into that page's form is shown as text and not run as code on
#   the page that shows it (`shows`, or wherever the form leads when that is left out). It also
#   lists what the signed-in pages try to send to other sites, and looks in it for the test
#   account's own details. `browser = {}` asks all but the typed text.
# private-websocket = "/ws"
#   A WebSocket that only a signed-in user should be able to open. The handshake is sent with the
#   first user's session, then with no session, with one the probes made up, and after signing out.

[data]
# What kinds of information the app holds about people. Starts commented out, like the capabilities:
# a list nobody filled in is read as unanswered, and the app is held to ASVS level 2, the level for
# apps that hold sensitive information, until it is answered. Remove the `#` and list what it holds,
# or write [] if it holds nothing about people at all.
# contact | financial | payment-card | health | government-id | credentials
# children | location | files | business-confidential | other-personal
# categories = ?

[capabilities]
# Every answer below starts commented out, so a line nobody answered is read as unanswered, never as a
# quiet "no". For each one you can answer, remove the `#` and replace `?` with true or false.
# auth = ?                    # does anyone sign in?
# oauth = ?                   # sign-in through Google/Microsoft/etc.
# authorization-server = ?    # do OTHER apps sign their users in through THIS one?
# mcp-server = ?              # do AI tools connect to THIS app over MCP, to use tools it offers?
# jwt = ?                     # self-contained tokens (JWT) rather than opaque session ids
# uploads = ?                 # can anyone upload a file?
# payments = ?                # does it take money?
# email = ?                   # does it send email?
# public-api = ?              # can other programs connect with an API key?
# scheduler = ?               # are there background or scheduled jobs?
# multi-tenant = ?            # do separate customer organizations share one system?
# webrtc = ?                  # real-time audio or video calls
# out-of-band-auth = ?        # sign-in codes sent by phone, SMS or push notification
# shared-hostname = ?         # do other applications share this app's address?
# multiple-services = ?       # does this run as more than one service talking over a network?
# external-apis = ["api.example.com"]   # host names it calls; [] if it calls none
tls = "terminated-upstream"   # off | self | terminated-upstream

[repository]
# How the code is developed and shipped. Ten AISVS Appendix C requirements turn on the first one.
# ci-cd = ?                   # GitHub Actions, GitLab CI, Jenkins or similar
# hosted-scm = ?              # hosted source control with branch protection or a merge queue
# outside-contributors = ?    # code contributions from people outside the team
# iac = ?                     # Terraform, CloudFormation or CI workflow files in the repository
# Folders that are not the app: test fixtures, example apps, sample code. Still checked, and their
# findings still count, listed apart; what they use cannot change which requirements apply.
# `*` stands for one folder name. The report lists them, so never put the app's own code here.
# not-the-app = ["examples", "crates/*/tests/fixtures"]

[capabilities.ai]
# enabled = ?                 # does the app have an AI feature at all?
# can-act = ?                 # may it change data, not just answer?
# stores-history = ?          # is conversation history kept between visits?
# moderation = ?
# rag = ?                     # does it search documents of the app's own: a document store, search index, or vector database?
# web-search = ?              # does it search the web or read web pages? (a web search is this, not rag)
# generates-media = ?        # does it make images, audio, or video? (matters only at level 3)
# mcp = ?                     # does it reach tools over the Model Context Protocol?
# training = ?                # does this app train or fine-tune a model?
# self-hosted = ?             # does it host or deploy model files itself, rather than calling a vendor's API?
# multi-agent = ?             # several AI agents that must identify each other?
# multimodal = ?              # does it take images, video or audio, rather than typed text only?

# Numbers you state as policy, which the checks hold the running app to.
# Leave one out and nothing is claimed about it either way.
[policy]
# failed-sign-ins = 5     # wrong passwords in a row the app should allow before pushing back
# failed-codes = 5        # wrong emailed sign-in codes in a row before pushing back (with `email-code`)
# ai-requests-per-minute = 20   # messages a minute the AI feature passes on before refusing (with `ai`)
# requests-per-minute = 30   # records a minute one user can create through `owned` before the app
#                            # pushes back; one more than this is sent
# idle-timeout-minutes = 15       # how long a session may sit unused (checked by `sv run --slow`)
# session-lifetime-minutes = 60   # how long a session may last however busy (`sv run --slow`, up to 90)
# within-minutes = 15     # the window that count applies within (recorded, not tested: every
#                         # attempt this makes lands within a few seconds)
# The most days a known vulnerability may stay unfixed, by how serious it is. `sv audit` compares
# each one's age with these; a severity left out is counted as overdue whatever its age.
# fix-within-days = { critical = 7, high = 30, medium = 90, low = 180 }
# Words nobody should be able to build a password from: the app's name, your organization's, a
# product or project name. The sign-up probe tries a password made of the first one of at least
# four letters, and the app should refuse it.
# context-words = ["myapp", "myorganization"]

# How the app is built. These are the questions no tool can settle, so a person has to answer them.
# Each one is "yes", "no", "not-sure", or "planned", `where` names the file that does it, and `by` says who
# answered: "owner" for you, "ai-tool" for the AI coding tool that wrote the app.
#   yes       — the word of whoever answered that the control is there. Yours is reported as
#               "attested by the owner"; the AI tool's as "stated by the AI coding tool", which is
#               weaker still, because it is the author grading its own work. Neither is evidence,
#               and each requirement stays on the list of tests to write.
#   no        — the control is not there. The report says so, as something to fix.
#   not-sure  — adds nothing, and is the right answer when you do not know. Leaving a question
#               out entirely comes to the same thing.
#   planned   — decided, and not built yet: the answer to give before there is code, with `where`
#               naming the file it will be in. It counts for nothing. Once the app has code, a
#               planned file that is not there is reported as decided, never built; once it is
#               there, change the answer to yes or no.
# An answer without `by` counts as the AI tool's: write by = "owner" only for an answer the
# owner gave. It counts as the owner's only once they run `sv review` in their own terminal, which
# records it with a `seal`; until then it counts as the AI tool's. Run `sv report` to see the
# questions that apply to this app; there are at most sixteen.
#
# A person can confirm what the AI tool answered, after looking for themselves, and it then counts as
# much as their own word, shown as "stated by the AI coding tool, confirmed through sv review". The AI
# tool may propose one, saying what the person could look at:
#   confirmed = { by = "ai-tool", how = "what to look at, and what it should show" }
# It counts only once the person runs `sv review` in their own terminal and records it: that writes
# their name, the date, the answer and `where` it confirms, and a seal. An entry written any other
# way, `by = "owner"` included, is a proposal; `sv` cannot tell who typed a line in this file.
# It stops counting after 90 days, when the answer changes, or when the `where` file changes after `on`.
[design]
# "V8.3.1" = { answer = "yes", where = "server/auth.py", by = "owner" }
# "V2.2.2" = { answer = "not-sure", by = "ai-tool" }
# "V13.2.1" = { answer = "planned", where = "server/services.py", by = "owner" }
# "V15.3.1" = { answer = "yes", where = "views/index.ejs", by = "ai-tool", confirmed = { by = "ai-tool", how = "Open a product page and its source; only the fields shown should be sent." } }

# Checks made by hand: the ones no tool can make, such as the certificate on the live site or two
# people booking the same slot. `sv questions` lists them, with how to make each one. Record what
# happened, keyed by the requirement id:
#   result = "done"     — checked, and it holds. Reported as "checked by hand by the owner" when
#                         by = "owner", never as "checked", which means an automated check looked.
#   result = "problem"  — checked, and it failed. The report lists it as something to fix.
#   result = "not-yet"  — adds nothing.
#   on  = the day it was checked, as "YYYY-MM-DD". A check older than 90 days counts for nothing
#         until it is made again, because certificates expire and apps change.
#   how = one sentence of what was done and what was seen. Required: it is the evidence, and the
#         report prints it.
#   by  = "owner" or "ai-tool", as for [design]; left out, it counts as the AI tool's, and
#         "owner" counts as the owner's only once recorded through `sv review`.
#   confirmed = { by = "ai-tool", how } — proposes that a person make a check the AI tool made; as
#         for [design], it counts, as much as their own check made by hand, once they have made it
#         and recorded it through `sv review`.
[checked-by-hand]
# "V12.2.2" = { result = "done", on = "2026-09-26", by = "owner", how = "Opened the live site; the padlock shows a trusted certificate for the right name, valid to December." }

# Findings a person has looked at and set aside. One [[finding-review]] each, naming the finding by
# the rule, file, and fingerprint the report prints beside it:
#   verdict = "false-alarm"    — the code is fine. The finding leaves the list of things to fix,
#                                and holds until the flagged line changes, or a line above it
#                                that sets a value it uses.
#   verdict = "accepted-risk"  — a real problem, lived with for now. It stays on the list, labeled,
#                                and lapses after 90 days.
#   why = what was looked at and what it showed, at least 40 characters (80 for a key or password,
#         saying why it is not a real one; a key or password cannot be an accepted risk).
#   by  = "ai-tool" for the AI tool's proposal. Every entry is only a proposal, and the finding
#         still counts, until a person has read the code and recorded it by running `sv review` in
#         their own terminal, which writes their name in `by`, the day in `on`, and a `seal`.
# Setting a finding aside never makes its requirement "checked": a person's word that a warning
# was wrong does not show the protection is there.
# [[finding-review]]
# rule = "ast.open-redirect"
# file = "app.py"
# fingerprint = "v2-3f2a9c1e0b7d4a55"
# verdict = "false-alarm"
# why = "The next= value is looked up in a fixed list of our own paths on the line above."
# by = "ai-tool"
"#;

pub const INSTRUCTIONS: &str = r#"Hand this to your AI coding tool, along with the starter file above.

  Fill in securevibe.toml for the app in this folder. Every answer decides which OWASP ASVS
  requirements are judged to apply.

  - If there is no code yet, write it first, before any code, for the app as it will be. It is the
    design brief: decide each answer with the person, and what you decide here is what the app is
    built to and checked against. Then go through the design-time prompts (`sv prompts`) for the
    features the app will have, before writing the code for each.
  - Once there is code, answer for the app as it actually is, not as it is meant to become.

  Three rules:

  1. Every capability line starts commented out, with `?` where the answer goes. Remove the `#` and
     write true or false for each one you can answer. A line left commented out is read as
     "nobody answered": every requirement that turns on it is reported as not assessed, never as
     resolved, which is the honest answer when nobody knows. The same holds for `[data]
     categories`: left commented out, the app is held to the higher level; `[]` says it holds
     nothing about people, so write it only when that is true.

  2. If you are unsure whether a capability is present, say true. A capability claimed but absent
     costs a requirement that did not need meeting. A capability present but denied is the one
     mistake that matters: it is how a real requirement gets marked "not applicable". Never write
     false to get a line out of the way.

  3. Once there is code, do not describe the app you were asked to build. Describe the code that is
     there. If the payment flow was planned and then dropped, payments is false. Before there is
     code, and for a feature still to be written, a capability the app is planned to have is true:
     rule 2, applied to the plan. Change the file before you add a capability the plan does not have.

`sv` does not take this file at its word. It looks for each claim in the code and reports what it
finds: confirmed, contradicted, asserted-but-unsupported, or unverifiable. A claim of "no" never
switches off a requirement the code says applies.

  Naming requirements in your tests

  If a test exists to satisfy a particular OWASP requirement, write that requirement's id into the
  test — in its name, or in a comment on the line above it:

      def test_V1_2_4_search_uses_bound_parameters():   # or: # covers V1.2.4
          ...

  `sv` reads those ids back and, when the whole suite passes, reports that requirement as checked
  by the app's own tests, naming the file and line so anybody can go and look. Ids may be written
  with underscores or dots; `V1.2.4` and `V1_2_4` are the same requirement.

  This is the only way a test counts. Matching tests to requirements by what they are called would
  credit a requirement on the strength of a name somebody chose for other reasons, and `sv` will
  not do that. A test that names nothing is not evidence about anything in particular, which is a
  perfectly fair thing for a test to be — most tests are.

  Which tests to write

  `sv report` lists, under "Tests to write" in compliance.md, every requirement that applies to the
  app and has no evidence of any kind and no test naming it, lowest level first; `sv mcp` gives the
  same list. Work down it: for each requirement the app really meets, a test that shows it, with the
  id in its name. Where the app does not meet one yet, that is the thing to fix first, and the test
  follows.

  Writing a test report

  If your test command can write JUnit XML, say where in `test-report` and have the command write
  it there. Every common runner can: `pytest --junitxml=/sv-reports/junit.xml`, `gotestsum
  --junitfile=…`, `jest --reporters=jest-junit`, Maven's surefire, RSpec's JUnit formatter.

  It matters more than it sounds. Without a report `sv` sees one exit code, so a suite with a
  single failing test credits nothing at all — not even the forty tests that passed and named a
  requirement. With one, those still count.

  Write it under `/sv-reports`. Your app's own folder is mounted read-only while it runs, because
  `sv` reads code and does not let the code it is checking rewrite itself mid-check, so that is the
  one place a runner can put a file. A relative path in `test-report` is taken as relative to it.

  Name only what the test really covers. Nothing here can check that the test does what it says,
  and a test pointed at the wrong requirement leaves that requirement looking examined when nothing
  examined it.
"#;
