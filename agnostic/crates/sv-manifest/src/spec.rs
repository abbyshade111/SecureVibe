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
start = ""                # e.g. "uvicorn app:app --host 127.0.0.1 --port $PORT"
test = ""                 # e.g. "pytest -q". Name requirement ids in your test names — see below.
test-report = ""          # where `test` writes JUnit XML, e.g. "junit.xml". See below.
health = "/"              # a path that returns 200 once the app is up

[stack.run.users]
# Optional: how to sign in, so `sv run` can check what a signed-in user can reach — other users'
# data, admin pages, whether logging out really ends the session. Leave it out and all of that is
# reported as "not assessed". `sv` makes two ordinary accounts, A and B, with fresh passwords.
# The app's folder is read-only while `sv` runs it, so keep its data somewhere like /tmp.
# seed = "python seed.py"   # creates them; gets SV_USER_A, SV_PASSWORD_A, SV_USER_B, SV_PASSWORD_B,
#                           # and SV_ADMIN, SV_ADMIN_PASSWORD when `admin` is listed
# signup = { path = "/signup", form = { email = "{user}", password = "{password}", csrf_token = "{csrf}" } }
# login  = { path = "/login",  form = { email = "{user}", password = "{password}", csrf_token = "{csrf}" } }
# logout = { path = "/logout", form = { csrf_token = "{csrf}" } }
# private = ["/account"]    # pages only a signed-in user should see
# admin = ["/admin"]        # pages only an admin should see (needs `seed`)
# owned = { create = { path = "/notes", form = { text = "{marker}", csrf_token = "{csrf}" } }, read = "/notes/{id}" }
# change-password = { path = "/password", form = { current = "{password}", new = "{new_password}", csrf_token = "{csrf}" } }
# delete-account = { path = "/account/delete", form = { password = "{password}", csrf_token = "{csrf}" } }

[data]
# What kinds of information the app holds about people.
# contact | financial | payment-card | health | government-id | credentials
# children | location | files | business-confidential | other-personal
categories = []

[capabilities]
auth = false                  # does anyone sign in?
oauth = false                 # sign-in through Google/Microsoft/etc.
authorization-server = false  # do OTHER apps sign their users in through THIS one?
jwt = false                   # self-contained tokens (JWT) rather than opaque session ids
uploads = false               # can anyone upload a file?
payments = false              # does it take money?
email = false                 # does it send email?
public-api = false            # can other programs connect with an API key?
scheduler = false             # are there background or scheduled jobs?
multi-tenant = false          # do separate customer organizations share one system?
webrtc = false                # real-time audio or video calls
out-of-band-auth = false      # sign-in codes sent by phone, SMS or push notification
shared-hostname = false       # do other applications share this app's address?
multiple-services = false     # does this run as more than one service talking over a network?
external-apis = []            # host names it calls, e.g. ["api.stripe.com"]
tls = "terminated-upstream"   # off | self | terminated-upstream

[repository]
# How the code is developed and shipped. Ten AISVS Appendix C requirements turn on the first one.
ci-cd = false             # GitHub Actions, GitLab CI, Jenkins or similar
hosted-scm = false        # hosted source control with branch protection or a merge queue
outside-contributors = false  # code contributions from people outside the team
iac = false               # Terraform, CloudFormation or CI workflow files in the repository

[capabilities.ai]
enabled = false
can-act = false           # may it change data, not just answer?
stores-history = false    # is conversation history kept between visits?
moderation = false
rag = false               # does it search a document store or vector database?
mcp = false               # does it reach tools over the Model Context Protocol?
training = false          # does this app train or fine-tune a model?
self-hosted = false       # does it host or deploy model files itself, rather than calling a vendor's API?
multi-agent = false       # several AI agents that must identify each other?
multimodal = false        # does it take images, video or audio, rather than typed text only?
"#;

pub const INSTRUCTIONS: &str = r#"Hand this to your AI coding tool, along with the starter file above.

  Fill in securevibe.toml for the app in this folder. Every answer decides which OWASP ASVS
  requirements are judged to apply, so answer for the app as it actually is, not as it is meant
  to become.

  Two rules:

  1. If you are unsure whether a capability is present, say true. A capability claimed but absent
     costs a requirement that did not need meeting. A capability present but denied is the one
     mistake that matters — it is how a real requirement gets marked "not applicable".

  2. Do not describe the app you were asked to build. Describe the code that is there. If the
     payment flow was planned and never written, payments is false.

  3. Leave nothing out. A line you delete is not read as "no" — it is read as "nobody answered",
     and every requirement that turned on it is reported as not assessed rather than resolved.
     If you genuinely do not know, leaving it out is the honest thing to do; guessing "false" is
     not.

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
