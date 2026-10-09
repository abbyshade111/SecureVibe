#!/usr/bin/env python3
"""Writes docs/COVERAGE.md: which requirements any check in `sv` can speak to, and what it needs to run;
with it, docs/REQUIREMENTS.md (every requirement and its checks) and data/reach.json.

    python3 tools/coverage.py            # rewrite all three
    python3 tools/coverage.py --check    # fail if any of the three is not what this would write
    python3 tools/coverage.py --credits LOG  # fail if the suite's credits disagree with the lists below
    python3 tools/coverage.py --withheld LOG # list the checks the suite saw credit and never saw withhold

Everything is read from where the checks themselves keep their citations, so the document cannot
claim a check the code does not have:

- `data/ast-rules.json`, `data/secret-rules.json`, `data/adapters.json`: the rules and their
  requirements;
- the checks whose citations are written in Rust (probes, signed-in checks, configuration, the bill
  of materials, advisories), listed in `RUST_CHECKS` below. A requirement id written into `sv`'s
  code as a string of its own that is in neither that table nor `MENTIONS` stops this script, so a
  new hard-coded check cannot be left out;
- `data/knowledge/applicability.json`'s `manualOnly`, and the Secure by Design prefix, for the
  requirements a check can support but never settle;
- `data/sbd-asvs-crosswalk.json`, for the checklist controls with an ASVS counterpart.

It also holds `data/prompts.json` and `data/design-prompts.json` to the same citations: each prompt names the requirements it
targets and the rules whose result shows whether it worked, and every one of those requirements has
to be cited by one of those rules, and every rule has to cite one of them, or one the prompt sets aside with its reason
(`check_prompts`).

A test (`crates/sv-check/tests/coverage_doc.rs`) runs `--check`, so a change to the checks that is not
followed by regenerating this document fails the build.

`--credits` reads the file the test suite writes when `SV_CREDIT_LOG` names it (CI's test job does):
one line for every credit a check gave, with the place in the code that gave it (`check_credits`).
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = ROOT / "docs" / "COVERAGE.md"
LIST_OUT = ROOT / "docs" / "REQUIREMENTS.md"
# Which kinds of run can credit each requirement, read by the report's short version to say how many
# requirements only a kind of run that did not happen could have reached.
REACH_OUT = ROOT / "data" / "reach.json"

# What each kind of check needs before it can run at all.
TIERS = [
    ("static", "Reads the code", "nothing: plain `sv check`"),
    ("advisories", "Known vulnerabilities", "a local copy of the OSV database (`--advisories DIR`)"),
    (
        "running",
        "The running app",
        "a container backend and a `run` section (`--run`); for the AI checks, an `ai` section too",
    ),
    (
        "signed-in",
        "Signed in",
        "the above, and a `users` section with test accounts, or an `oidc` section for a sign-in "
        "through another service",
    ),
    ("tools", "Outside tools", "the tool installed (`--tools`)"),
    (
        "production",
        "Your own live site",
        "the address your app is served from, typed at the terminal (`sv probe https://…`)",
    ),
]

# Checks whose citations are written in Rust rather than in a data file.
RUST_CHECKS = {
    "config.secrets-file-committed": ("static", ["V13.3.1"]),
    "config.development-server-started": ("static", ["V15.2.3"]),
    "config.mcp-server-unpinned": ("static", ["C10.1.1"]),
    "config.mcp-transport-unencrypted": ("static", ["C10.3.1"]),
    "config.rich-text-without-sanitizer": ("static", ["V1.3.1"]),
    "config.retired-grant-enabled": ("static", ["V10.4.4"]),
    "config.model-file-can-run-code": ("static", ["C4.1.2"]),
    "config.certificate-checks-off": ("static", ["V12.3.2", "V12.3.4"]),
    "config.firebase-rules-open": ("static", ["V8.2.2", "V8.2.1"]),
    "config.supabase-table-without-rls": ("static", ["V8.2.2", "V8.2.1"]),
    "config.supabase-policy-allows-all": ("static", ["V8.2.2", "V8.2.1"]),
    "config.secret-under-public-name": ("static", ["V13.3.1", "SBD-AC-05"]),
    "probe.retired-grants-offered": ("running", ["V10.4.4"]),
    "probe.admin-opened-by-address": ("running", ["V8.4.2"]),
    "probe.private-files-served": ("running", ["V13.4.7"]),
    "probe.app-stopped-during-questions": ("running", ["V16.5.4"]),
    "config.gitignore-covers-env": ("static", ["V13.3.1"]),
    "config.versions-pinned": ("static", ["V15.1.2"]),
    "config.workflow-runs-fork-code": ("static", ["AC.12.1"]),
    "config.workflow-checkout-keeps-token": ("static", ["AC.12.2"]),
    "config.workflow-secrets-with-fork-code": ("static", ["AC.12.3"]),
    "config.workflow-hands-out-all-secrets": ("static", ["V13.3.2"]),
    "config.workflow-untrusted-text-in-run": ("static", ["AC.12.1"]),
    "sbom": ("static", ["V15.1.2"]),
    "secrets.credential-assignment": ("static", ["V13.3.1", "V13.2.3", "SBD-AC-05"]),
    "secrets.password-in-url": ("static", ["V13.3.1", "SBD-AC-05"]),
    "advisories": ("advisories", ["V15.2.1"]),
    "probe.security-headers": ("running", ["V3.4.3", "V3.4.4", "V3.4.5", "V3.4.6"]),
    "probe.cookie-attributes": ("running", ["V3.3.2", "V3.3.4"]),
    "probe.cors-any-origin": ("running", ["V3.4.2"]),
    "probe.error-detail-leak": ("running", ["V13.4.2", "V16.5.1"]),
    "probe.trace-enabled": ("running", ["V13.4.4"]),
    "probe.ai-instructions-leaked": ("running", ["C7.3.2"]),
    "probe.ai-output-fetched": ("running", ["C7.3.3", "C9.3.7"]),
    "probe.ai-output-unbounded": ("running", ["C7.1.2"]),
    "probe.ai-injection-unscreened": ("running", ["C2.1.3"]),
    "probe.ai-call-log-incomplete": ("running", ["C12.1.3"]),
    "probe.ai-injection-logged": ("running", ["C12.2.1"]),
    "probe.ai-rate-unlimited": ("running", ["C11.2.2"]),
    "probe.ai-kill-switch-ignored": ("running", ["C9.6.1"]),
    "probe.ai-mcp-output-unvalidated": ("running", ["C10.4.1", "C9.3.2"]),
    "probe.ai-mcp-injection-unscreened": ("running", ["C10.4.2"]),
    "probe.ai-input-truncated": ("running", ["C2.1.4"]),
    "probe.ai-injection-other-languages": ("running", ["C2.2.2"]),
    "probe.ai-hidden-content-passed": ("running", ["C7.3.4"]),
    "probe.ai-flagged-reply-shown": ("running", ["C7.3.1"]),
    "probe.ai-raw-response-exposed": ("running", ["C11.3.2"]),
    "probe.ai-floating-model-sent": ("running", ["C3.2.3"]),
    "probe.ai-service-error-shown": ("running", ["V16.5.1"]),
    "probe.ai-service-failure-handled": ("running", ["V16.5.2"]),
    "probe.ai-output-shape-unchecked": ("running", ["C7.1.1"]),
    "probe.ai-agent-unbounded": ("running", ["C9.1.2"]),
    "probe.ai-tool-timeout": ("running", ["C9.1.1"]),
    "probe.ai-hidden-input": ("running", ["C2.1.2"]),
    "probe.ai-input-charset-unrestricted": ("running", ["C2.1.5"]),
    "probe.ai-call-log-session": ("running", ["C12.1.1"]),
    "probe.ai-tool-reads-others-records": ("signed-in", ["C9.5.3"]),
    "probe.ai-retrieval-ignores-user": ("signed-in", ["C5.2.2", "C8.1.3"]),
    "probe.ai-reply-carries-others-data": ("signed-in", ["C5.2.4"]),
    "probe.mcp-server-origin-unchecked": ("running", ["C10.3.3"]),
    "probe.fetch-goes-anywhere": ("running", ["V1.3.6", "V13.2.4"]),
    "probe.fetch-follows-redirect": ("running", ["V15.3.2"]),
    "probe.mcp-server-token-unchecked": ("running", ["C10.2.1"]),
    "probe.mcp-server-takes-unknown-or-oversized-arguments": ("running", ["C10.4.3"]),
    "probe.mcp-server-takes-wrong-types": ("running", ["C10.4.4"]),
    "probe.mcp-server-no-size-limit": ("running", ["C10.4.5"]),
    "probe.mcp-session-survives-end": ("running", ["C10.2.6"]),
    "probe.unused-method-accepted": ("running", ["V4.1.4"]),
    "probe.jsonp-enabled": ("running", ["V3.5.6"]),
    "probe.docs-or-monitoring-exposed": ("running", ["V13.4.5"]),
    "probe.development-console-open": ("running", ["V15.2.3", "V13.4.2"]),
    "probe.version-disclosed": ("running", ["V13.4.6"]),
    "probe.reflected-unencoded": ("running", ["V1.2.1"]),
    "probe.sql-injection": ("signed-in", ["V1.2.4"]),
    "probe.reflected-json-unescaped": ("running", ["V1.2.3"]),
    "probe.opener-policy-missing": ("running", ["V3.4.8"]),
    "probe.csp-no-report": ("running", ["V3.4.7"]),
    "probe.content-type": ("running", ["V4.1.1"]),
    "probe.source-control-exposed": ("running", ["V13.4.1"]),
    "probe.private-page-anonymous": ("signed-in", ["V8.2.1"]),
    "probe.admin-page-ordinary-user": ("signed-in", ["V8.2.1", "V8.3.1"]),
    "probe.admin-action-ordinary-user": ("signed-in", ["V8.2.1", "V8.3.1"]),
    "probe.role-field-trusted": ("signed-in", ["V8.3.1", "V15.3.3", "V8.2.3"]),
    "probe.owner-field-trusted": ("signed-in", ["V15.3.3", "V8.2.3", "V8.2.2"]),
    "probe.stored-unencoded": ("signed-in", ["V1.2.1"]),
    "probe.other-users-data": ("signed-in", ["V8.2.2"]),
    "probe.session-cookie-attributes": ("signed-in", ["V3.3.2", "V3.3.4"]),
    "probe.session-not-renewed": ("signed-in", ["V7.2.4"]),
    "probe.logout-keeps-session": ("signed-in", ["V7.4.1"]),
    "probe.cross-site-request-accepted": ("signed-in", ["V3.5.1"]),
    "probe.short-password-accepted": ("signed-in", ["V6.2.1"]),
    "probe.common-password-accepted": ("signed-in", ["V6.2.4"]),
    "probe.breached-password-accepted": ("signed-in", ["V6.2.12"]),
    "probe.context-word-password-accepted": ("signed-in", ["V6.2.11"]),
    "probe.flow-step-skipped": ("signed-in", ["V2.3.1"]),
    "probe.activation-code-guessable": ("signed-in", ["V6.4.1"]),
    "probe.activation-link-reusable": ("signed-in", ["V6.4.1"]),
    "probe.email-code-long-lived": ("signed-in", ["V6.5.5"]),
    "probe.websocket-without-session": ("signed-in", ["V4.4.4"]),
    "probe.websocket-after-sign-out": ("signed-in", ["V4.4.3"]),
    "probe.totp-reused": ("signed-in", ["V6.5.1"]),
    "probe.totp-old-code-accepted": ("signed-in", ["V6.5.5"]),
    "probe.forwarded-for-trusted": ("signed-in", ["V15.3.4"]),
    "probe.password-composition-rules": ("signed-in", ["V6.2.5"]),
    "probe.default-account": ("signed-in", ["V6.3.2"]),
    "probe.password-in-url": ("signed-in", ["V14.2.1"]),
    "probe.oidc-sign-in-from-another-session": ("signed-in", ["V10.1.2", "V10.2.1"]),
    "probe.oidc-nonce-not-checked": ("signed-in", ["V10.5.1"]),
    "probe.oidc-audience-not-checked": ("signed-in", ["V10.5.4"]),
    "probe.oidc-signature-not-checked": ("signed-in", ["V6.8.2"]),
    "probe.oidc-issuer-not-checked": ("signed-in", ["V10.2.2"]),
    "probe.oidc-user-keyed-on-email": ("signed-in", ["V10.5.2"]),
    "probe.sign-out-control-hidden": ("signed-in", ["V7.4.4"]),
    "probe.text-rendered-as-markup": ("signed-in", ["V3.2.2"]),
    "probe.storage-kept-after-sign-out": ("signed-in", ["V14.3.1"]),
    "probe.account-details-sent-elsewhere": ("signed-in", ["V14.2.3"]),
    "probe.preflight-skipped": ("signed-in", ["V3.5.2"]),
    "probe.session-id-weak": ("signed-in", ["V7.2.3"]),
    "probe.session-token-static": ("signed-in", ["V7.2.2"]),
    "probe.password-altered": ("signed-in", ["V6.2.8"]),
    "probe.long-password-refused": ("signed-in", ["V6.2.9"]),
    "probe.password-field-unmasked": ("signed-in", ["V6.2.6"]),
    "probe.password-paste-blocked": ("signed-in", ["V6.2.7"]),
    "probe.sign-out-on-get": ("signed-in", ["V3.5.3"]),
    "probe.password-change": ("signed-in", ["V6.2.2"]),
    "probe.password-change-without-current": ("signed-in", ["V6.2.3"]),
    "probe.action-done-twice": ("signed-in", ["V2.3.4"]),
    "probe.create-rate-unlimited": ("signed-in", ["V2.4.1"]),
    "probe.open-redirect": ("signed-in", ["V3.7.2"]),
    "probe.email-change-without-password": ("signed-in", ["V7.5.1"]),
    "probe.password-change-ends-sessions": ("signed-in", ["V7.4.3"]),
    "probe.password-change-notified": ("signed-in", ["V6.3.7"]),
    "probe.identity-header-trusted": ("signed-in", ["V4.1.3"]),
    "probe.uploaded-svg-keeps-script": ("signed-in", ["V1.3.4"]),
    "probe.upload-path-traversal": ("signed-in", ["V5.3.2"]),
    "probe.upload-not-scanned": ("signed-in", ["V5.4.3"]),
    "probe.token-in-browser-storage": ("signed-in", ["V10.1.1"]),
    "probe.password-in-browser-storage": ("signed-in", ["V14.3.3"]),
    "probe.sessions-survive-deletion": ("signed-in", ["V7.4.2"]),
    "probe.password-hints": ("signed-in", ["V6.4.2"]),
    "probe.reset-reusable": ("signed-in", ["V6.4.3"]),
    "probe.mail-header-injected": ("signed-in", ["V1.3.11"]),
    "probe.reset-keeps-old-password": ("signed-in", ["V6.4.3"]),
    "probe.reset-code-guessable": ("signed-in", ["V6.4.3"]),
    "probe.reset-code-in-answer": ("signed-in", ["V6.4.3"]),
    "probe.reset-reveals-account": ("signed-in", ["V6.3.8"]),
    "probe.signin-reveals-account": ("signed-in", ["V6.3.8"]),
    "probe.signup-reveals-account": ("signed-in", ["V6.3.8"]),
    "probe.signup-replaces-account": ("signed-in", ["V6.2.3"]),
    "probe.email-code-reusable": ("signed-in", ["V6.5.1"]),
    "probe.session-idle-timeout": ("signed-in", ["V7.3.1"]),
    "probe.session-lifetime": ("signed-in", ["V7.3.2"]),
    "probe.email-code-unbound": ("signed-in", ["V6.6.2"]),
    "probe.email-code-short": ("signed-in", ["V6.5.4"]),
    "probe.email-code-guessing-unlimited": ("signed-in", ["V6.6.3"]),
    "probe.failed-sign-ins-unlimited": ("signed-in", ["V6.3.1"]),
    "probe.certificate-not-trusted": ("production", ["V12.2.2"]),
    "probe.plain-http-served": ("production", ["V12.2.1"]),
    "probe.ocsp-not-stapled": ("production", ["V12.1.4"]),
    "probe.api-redirected-to-https": ("production", ["V4.1.2"]),
    "probe.old-tls-accepted": ("production", ["V12.1.1"]),
    "probe.no-hsts": ("production", ["V3.4.1"]),
    "live.ech-not-offered": ("production", ["V12.1.5"]),
    "live.hsts-not-preloaded": ("production", ["V3.7.4"]),
    "probe.cookie-without-host-prefix": ("production", ["V3.3.3"]),
    "probe.directory-listing": ("running", ["V13.4.3"]),
    "probe.private-page-cached": ("signed-in", ["V14.3.2"]),
    "probe.private-page-shared-cache": ("signed-in", ["V14.2.2"]),
    "probe.private-page-headers": ("signed-in", ["V3.4.3", "V3.4.4", "V3.4.5", "V3.4.6"]),
    "probe.no-sign-out-link": ("signed-in", ["V7.4.4"]),
    "probe.oversized-file-accepted": ("signed-in", ["V5.2.1"]),
    "probe.archive-unchecked": ("signed-in", ["V5.2.3"]),
    "probe.file-contents-unchecked": ("signed-in", ["V5.2.2"]),
    "probe.uploaded-file-executed": ("signed-in", ["V5.3.1"]),
    "probe.uploaded-file-rendered": ("signed-in", ["V3.2.1"]),
    "probe.authentication-logged": ("signed-in", ["V16.3.1"]),
    "probe.authorization-failure-logged": ("signed-in", ["V16.3.2"]),
    "probe.log-line-metadata": ("signed-in", ["V16.2.1"]),
    "probe.log-timestamp-zoned": ("signed-in", ["V16.2.2"]),
    "probe.download-unnamed": ("signed-in", ["V5.4.1"]),
    "probe.download-name-injected": ("signed-in", ["V5.4.2"]),
    "probe.log-common-format": ("signed-in", ["V16.2.4"]),
    "probe.graphql-introspection": ("running", ["V4.3.2"]),
    "probe.graphql-no-amount-limit": ("running", ["V4.3.1"]),
    "probe.websocket-origin-unchecked": ("running", ["V4.4.2"]),
    "probe.validation-only-in-the-browser": ("signed-in", ["V2.2.2"]),
    "probe.session-token-unverified": ("signed-in", ["V7.2.1"]),
    "probe.app-token-signature-not-checked": ("signed-in", ["V9.1.1"]),
    "probe.app-token-alg-none": ("signed-in", ["V9.1.2"]),
    "probe.app-token-expired-accepted": ("signed-in", ["V9.2.1"]),
    "probe.app-token-key-source-followed": ("signed-in", ["V9.1.3"]),
    "probe.app-token-placeholder-key": ("signed-in", ["V9.1.1"]),
    "probe.record-returns-secret-fields": ("signed-in", ["V15.3.1", "V8.2.3"]),
    "probe.clear-site-data": ("signed-in", ["V14.3.1"]),
}

# Checks in RUST_CHECKS that only ever raise their requirement as a finding: a clean run of one
# credits nothing, because what would settle the requirement is not in anything the check reads.
RUST_FINDINGS_ONLY = {
    # An `https://` address shows neither that the link is authenticated nor that it is the only one
    # (ADR-068).
    "config.mcp-transport-unencrypted",
    # A few characters kept out do not show an allow-list (ADR-065).
    "probe.ai-input-charset-unrestricted",
    # Found on 3 October 2026 to be counted as crediting when no code path gives them credit: each
    # only ever raises a finding. Several have a control that could let them credit (see the backlog).
    "probe.directory-listing",
    "probe.open-redirect",
    "probe.docs-or-monitoring-exposed",
    "probe.jsonp-enabled",
    "probe.unused-method-accepted",
    "probe.version-disclosed",
    "probe.account-details-sent-elsewhere",
    "probe.activation-code-guessable",
    "probe.activation-link-reusable",
    "probe.default-account",
    "probe.email-code-short",
    "probe.forwarded-for-trusted",
    "probe.password-in-url",
    "probe.password-paste-blocked",
    "probe.reset-code-guessable",
    "probe.reset-code-in-answer",
    "probe.reset-keeps-old-password",
    "probe.reset-reusable",
    "probe.reset-reveals-account",
    "probe.signin-reveals-account",
    "probe.signup-reveals-account",
    "probe.signup-replaces-account",
    "probe.session-id-weak",
    "probe.sign-out-on-get",
    "probe.validation-only-in-the-browser",
    "probe.websocket-after-sign-out",
    "config.workflow-secrets-with-fork-code",
    "probe.role-field-trusted",
    "probe.owner-field-trusted",
    "probe.stored-unencoded",
    "probe.record-returns-secret-fields",
    "probe.private-page-shared-cache",
    "probe.ai-output-fetched",
    "config.development-server-started",
    "config.mcp-server-unpinned",
    "config.rich-text-without-sanitizer",
    # A refusal of TLS 1.0 and 1.1 is half of V12.1.1; the other half, the newest version preferred,
    # is not something curl reports reliably, so a refusal is said and not credited.
    "probe.old-tls-accepted",
    # One value on three pages is not every place the app writes out what it was sent.
    "probe.reflected-unencoded",
    "probe.reflected-json-unescaped",
    # A few values in a few addresses, told apart or not, is not every query the app builds.
    "probe.sql-injection",
    # One note each and one question is not every way an app searches.
    "probe.ai-retrieval-ignores-user",
    "probe.ai-reply-carries-others-data",
    # The requirement names no size, and this is one size.
    "probe.mcp-server-no-size-limit",
    # The fence has no address that should be allowed, so not fetching is never credit.
    "probe.fetch-goes-anywhere",
    # An app that ignores a token's `jku` cannot be told from one that checks it against a list.
    "probe.app-token-key-source-followed",
    # Not matching a list of placeholder secrets does not show the app's secret is strong.
    "probe.app-token-placeholder-key",
    "config.retired-grant-enabled",
    "config.model-file-can-run-code",
    # A setting made on the server itself is in no file.
    "config.certificate-checks-off",
    # A rules file or migration with none of these shapes may still let one user reach another's data.
    "config.firebase-rules-open",
    "config.supabase-table-without-rls",
    "config.supabase-policy-allows-all",
    "config.secret-under-public-name",
    # Secrets handed out with care in the workflows say nothing of who else can read them.
    "config.workflow-hands-out-all-secrets",
    # An address with no password in it says nothing of keys kept elsewhere.
    "secrets.password-in-url",
    # Text pasted into commands carefully elsewhere says nothing of what the workflow runs.
    "config.workflow-untrusted-text-in-run",
    "probe.retired-grants-offered",
    "probe.admin-opened-by-address",
    "probe.private-files-served",
    "probe.app-stopped-during-questions",
    "probe.ai-input-truncated",
    "probe.ai-injection-other-languages",
    "probe.ai-raw-response-exposed",
    "probe.ai-floating-model-sent",
    "probe.ai-service-error-shown",
    "probe.development-console-open",
    "probe.identity-header-trusted",
    "probe.token-in-browser-storage",
    "probe.password-in-browser-storage",
    # Found on 6 October 2026 by the census of what the suite credits (`check_credits`). A hint or a
    # secret question only ever raises a finding. The assignment rule's clean run is credited as
    # `secrets.scan`, which names the requirements of `data/secret-rules.json` and not V13.2.3.
    "probe.password-hints",
    "secrets.credential-assignment",
    # One API address the owner names is not every endpoint (ADR-027, Later, 6 October 2026).
    "probe.api-redirected-to-https",
}

# The other way round: checks in RUST_CHECKS that only ever credit their requirement. What they
# would find missing may be met some way the check cannot see, so it is left not assessed.
RUST_CREDITS_ONLY = {
    "probe.password-change-ends-sessions",
    "probe.password-change-notified",
    "probe.ai-tool-timeout",
}

# Checks in RUST_CHECKS whose credit is only ever *in part* (ADR-053): they try one piece of what
# their requirement asks, so a requirement they alone credit is *checked in part*, never *checked*.
# C9.1.1 names five quotas, and a check from outside the app can time only one (ADR-064); C2.1.2's
# smuggling is tried in one family of characters, not in encodings or look-alike letters (ADR-065).
# V1.3.11's mail header injection is tried in one field of one kind of mail, the reset (ADR-069).
RUST_IN_PART = {"probe.ai-tool-timeout", "probe.ai-hidden-input", "probe.mail-header-injected"}

# Ids written into the code as strings that are not evidence: examples in comments on how ids are
# parsed, a requirement named only to say it is not assessed, and the three ids `sv init` prints as
# worked examples of a [design] answer. The design questions cite their requirements in
# `data/design-questions.json`, and they are deliberately absent from this document: an answer there
# is the owner's word, which is the one thing this file must not count as coverage. V12.1.2 is named in the
# report's "Before going live" list (`crates/sv-report/src/live.rs`) as one to check with a scanner, which
# credits nothing.
MENTIONS = {"AC.4.1", "SBD-AC-01", "V6.2.1", "V3.3.1", "V8.3.1", "V2.2.2", "V13.2.1", "V12.1.2"}

ID = r"(?:V|C)\d+\.\d+\.\d+|AC\.\d+\.\d+|SBD-[A-Z]+-\d+"


def load(path):
    return json.loads(Path(path).read_text())


def framework(path):
    out = {}
    for chapter in load(path)["chapters"]:
        for section in chapter.get("sections", []):
            for r in section.get("requirements", []):
                out[r["id"]] = {
                    "level": r.get("level"),
                    "chapter": chapter["id"],
                    "chapter_name": chapter["name"],
                    "section": section["id"],
                    "section_name": section["name"],
                    "text": r.get("description", ""),
                }
    return out


# What a check of sv's own looks for, for the few whose code carries no title or impact of its own to
# read it from: checks that only ever credit a requirement, and the configuration checks built
# differently. Every other check's words are read from the code or data where the check is defined.
DESCRIBED = {
    "config.certificate-checks-off": "A setting that switches off certificate checking for every connection the app makes",
    "config.firebase-rules-open": "A Firebase rules file that lets anybody in: an `allow` with no condition, `if true`, or test mode's date alone, or a Realtime Database `.read` or `.write` set to true",
    "config.supabase-table-without-rls": "A table a Supabase migration creates with no row-level security turned on, open to the key every visitor's browser holds",
    "config.supabase-policy-allows-all": "A Supabase policy that lets rows be added, changed, or deleted on the condition `true`",
    "config.secret-under-public-name": "A server's key under a name the build hands to the browser (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`): a name that says it holds a secret, or a value shaped like a service-role, Stripe, OpenAI, Anthropic, Supabase secret, or GitHub key",
    "config.workflow-runs-fork-code": "A CI workflow that runs code from a pull request by someone outside the project with the repository's privileges",
    "config.workflow-checkout-keeps-token": "A CI workflow whose checkout step leaves the repository token where later steps can read it",
    "config.workflow-secrets-with-fork-code": "A CI workflow that hands secrets to a job running code from outside the project",
    "secrets.password-in-url": "A password written into a web address's user part (`postgresql://user:password@host`), placeholders, references, and stock passwords set aside",
    "config.workflow-untrusted-text-in-run": "A CI workflow that pastes text a stranger writes (a pull request's title, a branch name, an issue) into a `run:` line, where it is read as commands",
    "config.workflow-hands-out-all-secrets": "A CI workflow that hands every secret to a job (`toJSON(secrets)`, `secrets: inherit`), or puts secrets in the workflow-wide `env:` where every step reads them",
    "sbom": "Whether the list of what the app ships (its bill of materials) could be read completely from its lockfiles",
    "advisories": "Every package the app ships, compared with a local copy of the OSV database of known vulnerabilities",
    "probe.ai-injection-logged": "Whether the app writes down that it caught the textbook prompt injection the run sent",
    "probe.authentication-logged": "Whether the app writes down a refused sign-in the run made",
    "probe.authorization-failure-logged": "Whether the app writes down a request it refused to someone not allowed to make it",
    "probe.log-line-metadata": "Whether the line recording a security event says when, where from, and who",
    "probe.log-common-format": "Whether that line is written in a format log tools read without being taught",
    "probe.clear-site-data": "Whether signing out tells the browser to clear what the site stored in it",
}


def rust_string(text, i):
    """The Rust string literal that starts at the quote at `text[i]`, with line continuations joined."""
    out, j = [], i + 1
    while True:
        ch = text[j]
        if ch == "\\":
            nxt = text[j + 1]
            if nxt == "\n":
                j += 2
                while text[j] in " \t":
                    j += 1
                continue
            if nxt == "u" and text[j + 2] == "{":
                # `\u{2014}`: the character it names, not the letters.
                end = text.index("}", j + 3)
                out.append(chr(int(text[j + 3:end], 16)))
                j = end + 1
                continue
            out.append({"n": "\n", '"': '"', "\\": "\\", "t": "\t"}.get(nxt, nxt))
            j += 2
            continue
        if ch == '"':
            return "".join(out)
        out.append(ch)
        j += 1


def rust_code():
    """(path, code) for every Rust file that ships: each file under a crate's `src`, subfolders
    included, with its tests cut off at the first `#[cfg(test)]`. A file that is a test module of
    its own, declared `#[cfg(test)] mod name;` by the file beside it (as `signed_in/fake_app.rs`
    is), is left out whole."""
    paths = sorted((ROOT / "crates").glob("*/src/**/*.rs"))
    test_only = set()
    for path in paths:
        folder = path.parent if path.name in ("mod.rs", "lib.rs", "main.rs") else path.with_suffix("")
        for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", path.read_text()):
            test_only.add(folder / f"{m.group(1)}.rs")
            test_only.add(folder / m.group(1) / "mod.rs")
    return [(p, p.read_text().split("#[cfg(test)]")[0]) for p in paths if p not in test_only]


def check_words():
    """sv's own check id -> (label, words): what it looks for, from where the check is defined."""
    words = {}
    for rule in load(ROOT / "data/ast-rules.json")["rules"]:
        words[rule["id"]] = ("Looks for", rule["title"])
    for rule in load(ROOT / "data/secret-rules.json")["rules"]:
        words[rule["id"]] = ("Looks for", rule["title"])
    code = "".join(code for _, code in rust_code())
    for m in re.finditer(r'rule_id:\s*"([^"]+)"', code):
        if m.group(1) in words:
            continue
        nxt = code.find("rule_id:", m.end())
        body = code[m.end():min(nxt if nxt != -1 else len(code), m.end() + 4000)]
        for field, label in (("title", "Looks for"), ("impact", "If it fails")):
            f = re.search(field + r':\s*"', body)
            if f:
                words[m.group(1)] = (label, rust_string(body, f.end() - 1))
                break
    # The credential-assignment rule's title and advice depend on whether the value reads like a
    # sentence, so its words are its `ASSIGNMENT_WHAT`, the constant the citation guard reads too.
    m = re.search(r'pub const ASSIGNMENT_WHAT: &str =\s*"', code)
    if m:
        words.setdefault("secrets.credential-assignment", ("Looks for", rust_string(code, m.end() - 1)))
    for check, text in DESCRIBED.items():
        words.setdefault(check, ("Looks for", text))
    unsaid = sorted(c for c in RUST_CHECKS if c not in words)
    if unsaid:
        sys.exit("checks with no words to show in docs/REQUIREMENTS.md; add them to DESCRIBED: "
                 + ", ".join(unsaid))
    extra = sorted(c for c in DESCRIBED if c not in RUST_CHECKS)
    if extra:
        sys.exit("DESCRIBED names checks RUST_CHECKS does not have: " + ", ".join(extra))
    return words


# Requirement id -> {tool: [what each of its rules looks for]}, for the outside tools.
TOOL_RULES = defaultdict(lambda: defaultdict(list))
# Requirement id -> {tool: the ids of its rules that speak to it}, to count rules rather than their
# descriptions, which many rules share.
TOOL_RULE_IDS = defaultdict(lambda: defaultdict(set))


def appendix_c(path):
    out = {}
    for family in load(path)["families"]:
        for section in family.get("sections") or [family]:
            for r in section.get("requirements", section.get("controls", [])):
                out[r["id"]] = {"chapter": family["id"], "chapter_name": family["name"]}
    return out


def rust_literals():
    found = defaultdict(set)
    for path, code in rust_code():
        for m in re.finditer(r'"(' + ID + r')"', code):
            found[m.group(1)].add(path.name)
    return found


# Requirement id -> the rules that can only ever raise it as a finding (`findings_against` in
# adapters.json), by their folder name. A clean run credits none of these.
# Requirement id -> {(tool, rule)}: rules that are only ever a finding against it.
FINDINGS_ONLY = defaultdict(set)
# Requirement id -> {tool}: tools with some rule a clean run credits to it.
CREDITED_BY_TOOL = defaultdict(set)
# Requirement id -> {rule}: semgrep rules in the map that name it, in no pack the adapter runs.
NOT_RUN = defaultdict(set)


# Requirement id -> {rule}: semgrep rules a pack loads that read only files `sv` never hands semgrep.
NEVER_HANDED = defaultdict(set)


def code_extensions():
    """The file extensions `sv` reads as code (`language_of` in sv-scan's ecosystems.rs): the only
    files it hands semgrep."""
    text = (ROOT / "crates/sv-scan/src/ecosystems.rs").read_text()
    body = text[text.index("pub fn language_of"):]
    body = body[: body.index("_ => return None")]
    # An arm may run over several lines, as rustfmt wraps a long one.
    return {e for arm in re.findall(r'((?:"[^"\n]+"\s*\|\s*)*"[^"\n]+")\s*=>', body)
            for e in re.findall(r'"([^"]+)"', arm)}


def reads_code(rule, extensions):
    """Whether a rule that names the files it reads (`targets`, its `paths.include`) can be handed
    one by `sv`. A sample name is made from each pattern, as its test does: a rule for `*.erb` or
    `*.conf` never is, one for `*.html` or `*session.php` can be."""
    targets = rule.get("targets") or []
    if not targets:
        return True
    samples = [g.replace("**/", "").replace("*", "x").replace("?", "x") for g in targets]
    return any("." in s.rsplit("/", 1)[-1] and s.rsplit(".", 1)[-1] in extensions for s in samples)


# How a condition reads in "run unless the app is known not to …".
CONDITION_WORDS = {"ai": "call a model"}


def semgrep_packs(adapter):
    """Pack -> the condition it runs for, or None for every app. A pack in `conditional_args` is left
    out of a run only for an app known not to meet its condition."""
    out = {}
    for args, condition in [(adapter["run"]["args"], None)] + [
            (c["args"], c["condition"]) for c in adapter.get("conditional_args", [])]:
        for i, a in enumerate(args[:-1]):
            if a == "--config":
                out[args[i + 1]] = condition
    return out


def semgrep_loaded(adapter):
    """The semgrep rules the adapter's packs load, as measured in data/semgrep-packs.json.

    The map knows about a thousand rules; the adapter runs registry packs, and a pack loads only some
    of them. A rule no pack loads is never run, so it is evidence of nothing, whatever the map says.
    """
    packs = list(semgrep_packs(adapter))
    measured = load(ROOT / "data/semgrep-packs.json")["packs"]
    unmeasured = [p for p in packs if p not in measured]
    if unmeasured:
        sys.exit(
            "the semgrep adapter runs " + ", ".join(unmeasured) + ", which data/semgrep-packs.json has "
            "not measured; run tools/semgrep_packs.py"
        )
    return {rule for p in packs for rule in measured[p]["rules"]}


def evidence():
    """Requirement id -> {tier: [check, ...]}."""
    ev = defaultdict(lambda: defaultdict(list))
    for rule in load(ROOT / "data/ast-rules.json")["rules"]:
        for q in rule["requirementIds"]:
            ev[q]["static"].append(rule["id"])
            if rule.get("findingsOnly"):
                FINDINGS_ONLY[q].add(("sv", rule["id"]))
    for rule in load(ROOT / "data/secret-rules.json")["rules"]:
        for q in rule["requirementIds"]:
            ev[q]["static"].append(rule["id"])
    for adapter in load(ROOT / "data/adapters.json")["adapters"]:
        loaded = semgrep_loaded(adapter) if adapter["id"] == "semgrep" else None
        for rule_id in [r for r in adapter["rules"] if loaded is not None and r not in loaded]:
            rule = adapter["rules"][rule_id]
            for q in rule["requirements"] + rule.get("findings_against", []):
                NOT_RUN[q].add(rule_id)
        rules = {k: v for k, v in adapter["rules"].items() if loaded is None or k in loaded}
        # A tool of every language is handed, besides the code, each file a rule of its names
        # (`handed_files` in adapters.rs; gap analysis, item 34), so none of its rules is never
        # handed one. A tool of one language is handed only that language's code.
        extensions = code_extensions()
        for rule_id in [r for r, rule in rules.items()
                        if adapter["language"] != "*" and not reads_code(rule, extensions)]:
            for q in rules[rule_id]["requirements"] + rules[rule_id].get("findings_against", []):
                NEVER_HANDED[q].add(rule_id)
            del rules[rule_id]
        for rule_id, rule in rules.items():
            for q in rule["requirements"]:
                if adapter["id"] not in ev[q]["tools"]:
                    ev[q]["tools"].append(adapter["id"])
                CREDITED_BY_TOOL[q].add(adapter["id"])
                TOOL_RULE_IDS[q][adapter["id"]].add(rule_id)
                if rule.get("what"):
                    TOOL_RULES[q][adapter["id"]].append(rule["what"])
        for rule_id, rule in rules.items():
            for q in rule.get("findings_against", []):
                if adapter["id"] not in ev[q]["tools"]:
                    ev[q]["tools"].append(adapter["id"])
                TOOL_RULE_IDS[q][adapter["id"]].add(rule_id)
                if rule.get("what"):
                    TOOL_RULES[q][adapter["id"]].append(rule["what"])
                # The AI rules by their folder, which names the family across vendors and
                # languages; the rest by their own id.
                parts = rule_id.split(".")
                FINDINGS_ONLY[q].add((adapter["id"], parts[2] if parts[0] == "ai" else parts[-1]))
    for check, (tier, ids) in RUST_CHECKS.items():
        for q in ids:
            ev[q][tier].append(check)
            if check in RUST_FINDINGS_ONLY:
                FINDINGS_ONLY[q].add(("sv", check))
    return ev


PROMPT_STATUSES = {"shown", "not-shown", "untested"}


PROMPT_FILES = ("prompts.json", "design-prompts.json")


def check_prompts(known_requirements, sbd_controls):
    """Holds each prompt in `data/prompts.json` to the rules it names as its check.

    A prompt claims requirements, and names the rules whose result shows whether it worked. A claim
    is only as good as the check behind it, so every requirement a prompt names has to be cited by
    one of its rules, and every rule has to cite one of the prompt's requirements. A rule ending in
    `.` names a family (`secrets.`), and each rule in it is held to the same.
    """
    cites = {}
    for name in ("ast-rules.json", "secret-rules.json"):
        for rule in load(ROOT / "data" / name)["rules"]:
            cites[rule["id"]] = set(rule["requirementIds"])
    for check, (_, ids) in RUST_CHECKS.items():
        cites[check] = set(ids)
    faults = []
    prompts = []
    for name in PROMPT_FILES:
        held = load(ROOT / "data" / name)["prompts"]
        if not held:
            faults.append(f"data/{name} holds no prompts")
        prompts += held
    seen = Counter(p["id"] for p in prompts)
    faults += [f"{pid}: the id is used {n} times across {', '.join(PROMPT_FILES)}"
               for pid, n in seen.items() if n > 1]
    for p in prompts:
        pid = p["id"]
        for c in p.get("sbd_controls", []):
            if c not in sbd_controls:
                faults.append(f"{pid}: {c} is not a control in the Secure by Design checklist")
        wanted = set(p["requirements"])
        if p.get("status") not in PROMPT_STATUSES:
            faults.append(f"{pid}: status {p.get('status')!r} is not one of {sorted(PROMPT_STATUSES)}")
        if p.get("status") in ("shown", "not-shown") and not (p.get("tested") or {}).get("result"):
            faults.append(f"{pid}: says it was tried, and `tested` does not say what happened")
        for q in sorted(wanted - known_requirements):
            faults.append(f"{pid}: {q} is not a requirement in ASVS 5.0 or AISVS 1.0")
        rules = p["check"].get("rules", [])
        # A rule that ran and did not show the prompt working stays listed, with the requirement it
        # cites set aside and the reason said, rather than claimed.
        set_aside = p["check"].get("not_claimed", {})
        for q, why in set_aside.items():
            if q in wanted:
                faults.append(f"{pid}: {q} is both claimed and set aside")
            if len(why.strip()) < 30:
                faults.append(f"{pid}: {q} is set aside without saying why")
        if wanted and not rules:
            faults.append(f"{pid}: names requirements and no rule that could show the prompt working")
        covered = set()
        for rule in rules:
            matched = [r for r in cites if r.startswith(rule)] if rule.endswith(".") else (
                [rule] if rule in cites else [])
            if not matched:
                faults.append(f"{pid}: the rule {rule} is not one sv has")
            for r in matched:
                if not cites[r] & (wanted | set(set_aside)):
                    faults.append(f"{pid}: the rule {r} cites {', '.join(sorted(cites[r]))}, "
                                  f"none of the prompt's {', '.join(sorted(wanted)) or 'requirements (it names none)'}")
                covered |= cites[r]
        for q in sorted(set(set_aside) - covered):
            faults.append(f"{pid}: sets aside {q}, which none of its rules cites")
        for q in sorted(wanted - covered):
            faults.append(f"{pid}: names {q}, which none of its rules cites")
    return faults


def check_credits(log):
    """Holds the findings-only lists to what the test suite saw each check credit.

    Reading the code for where a check gives credit is not reliable: it does so through helpers and
    tables of rules as often as by name. So `Verified::new`, in a debug build with `SV_CREDIT_LOG`
    set, writes each credit to a file, with the place in the code that gave it, and this reads it.
    A credit made in a test module, or in a test of its own, is a test building its own evidence and
    is left out. Faults: a check listed as findings-only that was credited; a check never credited
    that is not listed, which is either findings-only or a credit no test reaches; a credit naming a
    requirement the check does not cite; and a requirement a crediting check cites that it was never
    seen crediting.
    """
    shipping = {str(p.relative_to(ROOT)): code.count("\n") + 1 for p, code in rust_code()}
    credited = defaultdict(set)
    lines = 0
    for line in Path(log).read_text().splitlines():
        check, ids, at = line.split("\t")
        path, number = at.rsplit(":", 1)
        if shipping.get(path, 0) < int(number):
            continue
        lines += 1
        credited[check].update(q for q in ids.split(",") if q)
    if not lines:
        return [f"{log} holds no credit from a check: was the suite run with SV_CREDIT_LOG set?"]
    cites = {check: (set(ids), check in RUST_FINDINGS_ONLY) for check, (_, ids) in RUST_CHECKS.items()}
    for rule in load(ROOT / "data/ast-rules.json")["rules"]:
        cites[rule["id"]] = (set(rule["requirementIds"]), bool(rule.get("findingsOnly")))
    faults = []
    for check, (ids, findings_only) in sorted(cites.items()):
        got = credited.get(check, set())
        if findings_only and got:
            faults.append(f"{check} is listed as only ever a finding, and the suite saw it credit "
                          + ", ".join(sorted(got)))
        if not findings_only and not got:
            faults.append(f"{check} was never credited in the suite: list it as findings-only, or add "
                          "a test that reaches its credit")
        if got - ids:
            faults.append(f"{check} credited {', '.join(sorted(got - ids))}, which it does not cite")
        # Per requirement, not only per check (the review of 8 October 2026, item 5): a check that cites
        # two requirements and was only ever seen crediting one passed, with the other cited on no evidence.
        if not findings_only and got and ids - got:
            faults.append(f"{check} cites {', '.join(sorted(ids - got))} and the suite never saw it credit "
                          "that: add a test that reaches the credit, or stop citing it")
    faults += check_withheld(log)
    return faults


# Checks that give credit and cannot be made, in a test, to withhold it, each with its reason. Empty: every
# check the suite sees credit was seen withholding (backlog item 32, ADR-059). A check added here is one the
# suite cannot show working; the reason says why, and it is expected to stay short.
NEVER_WITHHELD = {}


def check_withheld(log):
    """ADR-059: every check the suite saw credit was also seen withholding it, by a finding
    (`finding::found`) or through `verified::unless_credited`, in code that ships; unless it is listed in
    `NEVER_WITHHELD` with its reason. A listed one that was seen withholding is listed for nothing."""
    if not Path(str(log) + ".withheld").exists():
        return [f"{log}.withheld is not there: the census of what checks withhold is written beside the credits "
                "in a debug build (finding::found, verified::unless_credited); was the suite run in one?"]
    _, seen, never = withheld_report(log)
    faults = []
    for check in never:
        if check not in NEVER_WITHHELD:
            faults.append(f"{check} gives credit and was never seen withholding it: add a test in which what "
                          "it looks for is missing and it says no (a finding, or verified::unless_credited "
                          "where it has run), or list it in NEVER_WITHHELD with the reason it cannot")
    for check in sorted(NEVER_WITHHELD):
        if check in seen:
            faults.append(f"{check} is in NEVER_WITHHELD, and the suite saw it withhold: take it off the list")
    return faults


def unrecorded_findings():
    """Every place in the code that ships that builds a `Finding` hands it through `finding::found`, so the
    census sees it (ADR-059). Returns "file:line" for each that does not."""
    out = []
    for path, code in rust_code():
        for m in re.finditer(r"(?<![\w:])((?:crate::|sv_check::)?(?:finding::)?Finding) \{", code):
            before = code[max(0, m.start() - 40):m.start()]
            if re.search(r"(struct|impl|->)\s*$", before) or re.search(r"found\(\s*$", before):
                continue
            out.append(f"{path.relative_to(ROOT)}:{code[:m.start()].count(chr(10)) + 1}")
    return out


# A check whose findings carry names of their own, one per thing found, rather than the check's: each
# finding named with the prefix is that check withholding.
WITHHELD_UNDER = {"advisory.": "advisories", "sbom.": "sbom"}


def withheld_report(log):
    """The checks the suite saw give credit and never saw withhold it (backlog item 32, step 1).

    A check known to work says no when the thing it guards is broken. `Verified::new` writes each credit
    to `log`; `finding::found` writes each finding a check makes to `log` + `.withheld`, with the place
    in the code that made it. A finding made in a test module, or in a test of its own, is a test
    building its own finding and is left out, as a credit is. Returns (credited, seen withholding,
    never seen withholding), each a sorted list of check ids, for the checks this script knows (the
    Rust checks and the tree-sitter rules). Fails nothing: it measures.
    """
    shipping = {str(p.relative_to(ROOT)): code.count("\n") + 1 for p, code in rust_code()}

    def read(path, columns):
        seen = set()
        for line in Path(path).read_text().splitlines():
            parts = line.split("\t")
            if len(parts) != columns:
                continue
            at = parts[-1]
            source, number = at.rsplit(":", 1)
            if shipping.get(source, 0) < int(number):
                continue
            check = parts[0]
            for prefix, owner in WITHHELD_UNDER.items():
                if columns == 2 and check.startswith(prefix):
                    check = owner
            seen.add(check)
        return seen

    credited = read(log, 3)
    withheld_log = Path(str(log) + ".withheld")
    withheld = read(withheld_log, 2) if withheld_log.exists() else set()
    known = {check for check, _ in RUST_CHECKS.items() if check not in RUST_FINDINGS_ONLY}
    known |= {r["id"] for r in load(ROOT / "data/ast-rules.json")["rules"] if not r.get("findingsOnly")}
    crediting = sorted(credited & known)
    return crediting, sorted(set(crediting) & withheld), sorted(set(crediting) - withheld)


def reach_json(asvs, aisvs, ev, tiers, settles):
    """Requirement id -> the kinds of run (`TIERS` ids) with a check that can credit it, for every
    requirement a check can settle. A check that is only ever a finding is left out: it can show a
    requirement failing, never met, so it is not what a run that did not happen would have added."""
    def credits(q, tier, check):
        if tier == "tools":
            return check in CREDITED_BY_TOOL.get(q, set())
        return ("sv", check) not in FINDINGS_ONLY.get(q, set())
    reach = {}
    for q in sorted(set(asvs) | set(aisvs), key=lambda q: (q[0], [int(x) for x in re.findall(r"\d+", q)])):
        if not settles(q):
            continue
        kinds = [t for t in tiers(q) if any(credits(q, t, c) for c in ev[q][t])]
        if kinds:
            reach[q] = kinds
    return json.dumps({
        "_comment": "Generated by tools/coverage.py; do not edit. For each requirement a check can "
                    "settle, the kinds of run with a check that can credit it: static (plain sv check), "
                    "advisories, running (--run), signed-in (--run with test accounts), tools (--tools), "
                    "production (sv probe). Read by the report's short version.",
        "requirements": reach,
    }, indent=1) + "\n"


def main():
    if "--withheld" in sys.argv[1:]:
        log = sys.argv[sys.argv.index("--withheld") + 1]
        crediting, seen, never = withheld_report(log)
        if not crediting:
            sys.exit(f"{log} holds no credit from a check: was the suite run with SV_CREDIT_LOG set?")
        if not Path(log + ".withheld").exists():
            sys.exit(f"{log}.withheld is not there: was the suite run with SV_CREDIT_LOG set, in a debug build?")
        print(f"{len(crediting)} checks were seen giving credit; {len(seen)} of them were also seen "
              f"withholding it, and {len(never)} never were:")
        for check in never:
            print(f"  {check}")
        return
    if "--credits" in sys.argv[1:]:
        faults = check_credits(sys.argv[sys.argv.index("--credits") + 1])
        if faults:
            sys.exit("the suite's credits disagree with tools/coverage.py:\n  " + "\n  ".join(faults))
        print("every check credited as the lists say")
        return
    check = "--check" in sys.argv[1:]

    written = rust_literals()
    known = {q for _, ids in RUST_CHECKS.values() for q in ids} | MENTIONS
    missing = {q: sorted(files) for q, files in written.items() if q not in known}
    if missing:
        sys.exit(
            "requirement ids written into sv's code that tools/coverage.py does not know about; add the "
            "check to RUST_CHECKS, or the id to MENTIONS if it is not evidence:\n  "
            + "\n  ".join(f"{q} in {', '.join(f)}" for q, f in sorted(missing.items()))
        )
    code = "".join(code for _, code in rust_code())
    unnamed = sorted(c for c in RUST_CHECKS if f'"{c}"' not in code)
    if unnamed:
        sys.exit("RUST_CHECKS names checks the code does not have: " + ", ".join(unnamed))
    stale = sorted(q for _, ids in RUST_CHECKS.values() for q in ids if q not in written)
    stale += sorted(q for q in MENTIONS if q not in written)
    if stale:
        sys.exit("RUST_CHECKS or MENTIONS names ids no longer in the code: " + ", ".join(stale))

    asvs = framework(ROOT / "data/frameworks/asvs-5.0.0.json")
    aisvs = framework(ROOT / "data/frameworks/aisvs-1.0.json")
    sbd_controls = {f"SBD-{c['id']}" for d in load(ROOT / "data/frameworks/sbd-checklist-0.5.0.json")["checklistDomains"]
                    for c in d["controls"]}
    unrecorded = unrecorded_findings()
    if unrecorded:
        sys.exit("a finding is built without going through finding::found, so the census of what each check "
                 "withholds cannot see it (ADR-059); wrap it, `crate::finding::found(Finding { .. })`:\n  "
                 + "\n  ".join(unrecorded))
    faults = check_prompts(set(asvs) | set(aisvs), sbd_controls)
    if faults:
        sys.exit("the prompt library claims what its checks do not cite:\n  " + "\n  ".join(faults))
    appendix = appendix_c(ROOT / "data/frameworks/aisvs-1.0-appendix-c.json")
    sbd = load(ROOT / "data/frameworks/sbd-checklist-0.5.0.json")
    crosswalk = load(ROOT / "data/sbd-asvs-crosswalk.json")["controls"]
    manual_only = set(load(ROOT / "data/knowledge/applicability.json")["manualOnly"])
    ev = evidence()

    def tiers(q):
        return [t for t, _, _ in TIERS if ev.get(q, {}).get(t)]

    def settles(q):
        return bool(tiers(q)) and q not in manual_only and not q.startswith("SBD-")

    def supports_only(q):
        return bool(tiers(q)) and not settles(q)

    def credited(q):
        """A check can mark q *checked*, not only *needs attention* (gap analysis 1.8): one of `sv`'s
        own that is not only ever a finding, or a tool with some rule a clean run credits to q."""
        sv_only = {r for tool, r in FINDINGS_ONLY.get(q, ()) if tool == "sv"}
        return settles(q) and any(
            c in CREDITED_BY_TOOL[q] if tier == "tools" else c not in sv_only
            for tier, checks in ev[q].items() for c in checks)

    out = []
    w = out.append

    w("# Coverage: what the checks can speak to\n")
    w("Generated by `tools/coverage.py` from the checks' own citations. Do not edit by hand; run")
    w("`python3 tools/coverage.py` after changing a check, and the build fails until you do.\n")
    w("## How to read this\n")
    w("- **Can settle**: at least one check can mark the requirement *checked* or *needs attention*.")
    w("  A check is almost always about part of a requirement: a clean result is one automated check")
    w("  that was satisfied, not a pass.")
    w("- **Can be credited**: of those, the ones a check can mark *checked*. The rest can only ever be")
    w("  found failing: a check can show the control missing, and finding nothing does not show it")
    w("  present, so a clean run credits nothing for them.")
    w("- **Supporting only**: a check speaks to it, but the requirement asks something no check can")
    w("  answer, such as a documented policy or a design decision. The check is shown beside it and")
    w("  a person still has to answer it. No Secure by Design control is ever settled by a check: each")
    w("  is answered by a person, and those no check speaks to at all are counted under *Nothing*.")
    w("- **Nothing**: no check in `sv` names it. The app's own tests that name the requirement id in")
    w("  code and pass, which is how `sv init` asks for tests to be written, give it a tier of their own,")
    w("  *tested by the app's own tests*, below *checked* (ADR-050); otherwise it stays *not verified*.")
    w("- Which requirements apply to a given app is decided separately; this counts every requirement.")
    w("")
    w("What each kind of check needs before it can run:\n")
    w("| Kind | Needs |")
    w("|---|---|")
    for _, name, needs in TIERS:
        w(f"| {name} | {needs} |")
    w("")

    # ---- summary
    def sbd_supported(q):
        return bool(tiers(q)) or any(tiers(a) for a in crosswalk.get(q, {}))

    def summary_row(name, reqs):
        n = len(reqs)
        s = sum(settles(q) for q in reqs)
        p = sum(supports_only(q) or (q.startswith("SBD-") and sbd_supported(q)) for q in reqs)
        c = sum(credited(q) for q in reqs)
        pct = lambda k: f"{100 * k / n:.0f}%" if n else "–"
        return f"| {name} | {n} | {s} ({pct(s)}) | {c} ({pct(c)}) | {p} | {n - s - p} |"

    sbd_ids = [f"SBD-{c['id']}" for d in sbd["checklistDomains"] for c in d["controls"]]
    w("## Summary\n")
    w("| Framework | Requirements | Can settle | Can be credited | Supporting only | Nothing |")
    w("|---|---|---|---|---|---|")
    w(summary_row("OWASP ASVS 5.0", list(asvs)))
    w(summary_row("OWASP AISVS 1.0", list(aisvs)))
    w(summary_row("AISVS Appendix C", list(appendix)))
    w(summary_row("Secure by Design checklist 0.5.0", sbd_ids))
    w("")

    # ---- ASVS by level and kind
    w("## ASVS 5.0 by level\n")
    w("A requirement reached by more than one kind of check is counted under each.\n")
    head = " | ".join(name for _, name, _ in TIERS)
    w(f"| Level | Requirements | Can settle | Can be credited | {head} |")
    w("|---|---|---|---|" + "---|" * len(TIERS))
    for level in sorted({v["level"] for v in asvs.values()}):
        reqs = [q for q, v in asvs.items() if v["level"] == level]
        cells = " | ".join(
            str(sum(1 for q in reqs if settles(q) and t in tiers(q))) for t, _, _ in TIERS
        )
        w(f"| L{level} | {len(reqs)} | {sum(settles(q) for q in reqs)} | "
          f"{sum(credited(q) for q in reqs)} | {cells} |")
    w("")
    settled_asvs = [q for q in asvs if settles(q)]
    found_only = [q for q in settled_asvs if not credited(q)]
    w(f"{len(found_only)} of the {len(settled_asvs)} ASVS requirements that can be settled can only ever be "
      "marked *needs attention*: a check can show the control missing, and finding nothing does not show "
      "it present, so a clean run credits none of them. They are counted under *Can settle* and not under "
      "*Can be credited*, and the kinds of check above count every requirement a check can settle either "
      "way.\n")
    plain = [q for q in asvs if settles(q) and tiers(q) == ["static"]]
    only_tools = [q for q in asvs if settles(q) and tiers(q) == ["tools"]]
    w(f"With nothing beyond plain `sv check`, {sum(settles(q) and 'static' in tiers(q) for q in asvs)} "
      f"ASVS requirements can be settled. {len(only_tools)} can be settled only by an outside tool, "
      "almost all by semgrep and CodeQL, and only for the languages their rules are written for.\n")

    # ---- semgrep rules in the map that no pack it runs loads
    packs = load(ROOT / "data/semgrep-packs.json")["packs"]
    when = semgrep_packs(next(a for a in load(ROOT / "data/adapters.json")["adapters"]
                              if a["id"] == "semgrep"))
    named_elsewhere = {q for q in NOT_RUN if "semgrep" not in ev[q]["tools"]}
    order = lambda q: [int(x) for x in re.findall(r"\d+", q)]
    w("### Semgrep: rules in its map that are not run\n")
    w("Semgrep is counted above only through rules in a pack the adapter runs ("
      + ", ".join(f"`{p}`, {len(v['rules'])} rules"
                  + (f", run unless the app is known not to {CONDITION_WORDS.get(when[p], 'meet `' + when[p] + '`')}"
                     if when.get(p) else "")
                  + f", measured {v['measured']} with semgrep {v['semgrep']}"
                  for p, v in sorted(packs.items()) if p in when)
      + "). Its map names more requirements through rules no pack it runs loads; nothing counts those,"
      " and a report never credited them either, since a clean run is credited only with the rules its"
      f" own report lists. {len(named_elsewhere)} requirements are named that way and by no semgrep rule"
      " that runs:\n")
    w(", ".join(sorted(named_elsewhere, key=lambda q: (q[0], order(q)))) + ".\n")
    never = sorted({r for rules in NEVER_HANDED.values() for r in rules})
    only_there = {q for q in NEVER_HANDED if "semgrep" not in ev[q]["tools"]}
    if never:
        w(f"{len(never)} rules that a pack loads read only files `sv` never hands semgrep. A rule none "
          "of whose files it was handed ran over nothing, so they are not counted, and a report does "
          "not credit them (ADR-018, Later, 7 October 2026). "
          + (f"{len(only_there)} requirements are named only by them: "
             + ", ".join(sorted(only_there, key=lambda q: (q[0], order(q)))) + ".\n" if only_there
             else "No requirement is named only by them, so the counts above do not change with it.\n"))
    else:
        w("Every rule a pack loads reads files `sv` hands semgrep: the app's code files, templates "
          "among them since 8 October 2026 (ADR-054), and the other files a rule in the map names, "
          "such as nginx's `*.conf` and `web.config`, since the same day (ADR-018, Later). A rule "
          "credits a clean run only for an app that has a file it reads.\n")

    # ---- ASVS by chapter
    w("## ASVS 5.0 by chapter\n")
    w("| Chapter | Requirements | Can settle | Can be credited | Supporting only | Nothing |")
    w("|---|---|---|---|---|---|")
    chapters = defaultdict(list)
    for q, v in asvs.items():
        chapters[(v["chapter"], v["chapter_name"])].append(q)
    for (cid, name), reqs in sorted(chapters.items(), key=lambda x: int(x[0][0][1:])):
        s = sum(settles(q) for q in reqs)
        c = sum(credited(q) for q in reqs)
        p = sum(supports_only(q) for q in reqs)
        w(f"| {cid} {name} | {len(reqs)} | {s} | {c} | {p} | {len(reqs) - s - p} |")
    w("")

    # ---- ASVS lists
    def listing(title, ids, show_checks=True):
        w(f"### {title} ({len(ids)})\n")
        if not ids:
            w("None.\n")
            return
        w("| Requirement | Level | Checks |")
        w("|---|---|---|")
        for q in sorted(ids, key=lambda q: [int(x) for x in re.findall(r"\d+", q)]):
            checks = []
            for t, name, _ in TIERS:
                names = ev.get(q, {}).get(t, [])
                if names:
                    shown = ", ".join(f"`{c}`" for c in names[:4])
                    if len(names) > 4:
                        shown += f" and {len(names) - 4} more"
                    checks.append(f"{name}: {shown}")
            only = ""
            if q in FINDINGS_ONLY:
                by_tool = defaultdict(list)
                for tool, r in sorted(FINDINGS_ONLY[q]):
                    by_tool[tool].append(f"`{r}`")
                only = " (" + "; ".join(f"{tool} only ever as a finding: {', '.join(rules)}"
                                        for tool, rules in by_tool.items()) + ")"
            w(f"| {q} | L{asvs[q]['level']} | {'; '.join(checks)}{only} |")
        w("")

    w("## ASVS 5.0 requirement by requirement\n")
    listing("Settled by reading the code", [q for q in asvs if settles(q) and "static" in tiers(q)])
    listing("Settled by asking the running app", [q for q in asvs if settles(q) and ({"running", "signed-in"} & set(tiers(q)))])
    listing("Settled by known-vulnerability data", [q for q in asvs if settles(q) and "advisories" in tiers(q)])
    listing("Settled only by an outside tool", only_tools)
    listing("Supporting only", [q for q in asvs if supports_only(q)])
    l1 = sorted((q for q, v in asvs.items() if v["level"] == 1 and not tiers(q)),
                key=lambda q: [int(x) for x in re.findall(r"\d+", q)])
    w(f"### Level 1 with no check at all ({len(l1)})\n")
    w("The baseline every app is assessed against, and where a new check does the most good.\n")
    w(", ".join(l1) + "\n")

    # ---- AISVS
    w("## AISVS 1.0 by chapter\n")
    w("Whether these apply at all is decided from what the app says and what its code shows about AI;")
    w("most of AISVS is about how models are trained and run, which reading an application's code")
    w("does not reach.\n")
    w("| Chapter | Requirements | Can settle | Can be credited | Supporting only | Nothing |")
    w("|---|---|---|---|---|---|")
    chapters = defaultdict(list)
    for q, v in aisvs.items():
        chapters[(v["chapter"], v["chapter_name"])].append(q)
    for (cid, name), reqs in sorted(chapters.items(), key=lambda x: int(x[0][0][1:])):
        s = sum(settles(q) for q in reqs)
        c = sum(credited(q) for q in reqs)
        p = sum(supports_only(q) for q in reqs)
        w(f"| {cid} {name} | {len(reqs)} | {s} | {c} | {p} | {len(reqs) - s - p} |")
    w("")
    settled_ai = sorted((q for q in list(aisvs) + list(appendix) if settles(q)),
                        key=lambda q: [int(x) for x in re.findall(r"\d+", q)])

    def sv_finding_only(q):
        """`sv`'s own checks that only ever raise q as a finding."""
        return {r for tool, r in FINDINGS_ONLY.get(q, ()) if tool == "sv"}

    def credited_by_other(q):
        return any(c for tier, checks in ev[q].items() for c in checks
                   if c not in sv_finding_only(q)
                   and not (tier == "tools"
                            and any(tool == c for tool, _ in FINDINGS_ONLY.get(q, ()))
                            and c not in CREDITED_BY_TOOL[q]))

    only = [q for q in settled_ai if q in FINDINGS_ONLY and not credited_by_other(q)]
    w(f"{len(only)} of these {len(settled_ai)} can only ever be marked *needs attention*: a check can")
    w("show the control missing, and finding nothing does not show it present, so a clean run credits")
    w("none of them. Most are `sv`'s own checks: rules that read the code, and questions asked of the")
    w("running app (`--run`, with an `ai` section). The rest are semgrep's and CodeQL's, and need `--tools`.\n")
    for q in settled_ai:
        rules = sorted(FINDINGS_ONLY.get(q, ()))
        # A tool whose rules only ever find this failing does not settle it, whichever tool it is.
        finding_only_tools = {tool for tool, _ in rules} - CREDITED_BY_TOOL[q]
        names = [c for tier, checks in ev[q].items() for c in checks
                 if not (tier == "tools" and c in finding_only_tools)
                 and c not in sv_finding_only(q)]
        parts = []
        if names:
            whole = [c for c in names if c not in RUST_IN_PART]
            if whole:
                parts.append(f"settled by {', '.join(f'`{c}`' for c in whole[:4])}"
                             + (f" and {len(whole) - 4} more" if len(whole) > 4 else ""))
            partial = [c for c in names if c in RUST_IN_PART]
            if partial:
                parts.append(f"checked in part only, by {', '.join(f'`{c}`' for c in partial)}")
        by_tool = defaultdict(list)
        for tool, r in rules:
            by_tool[tool].append(f"`{r}`")
        for tool, found in by_tool.items():
            parts.append(f"found failing by {tool}'s " + ", ".join(found))
        w(f"- {q}: " + "; and ".join(parts) + ".")
    w("")

    # ---- SbD
    w("## Secure by Design checklist 0.5.0 by domain\n")
    w("Every control is design review, answered by a person, so none is ever *checked*. A control with")
    w("an ASVS counterpart takes its level from it, and a check on that counterpart is shown beside the")
    w("control as supporting evidence.\n")
    w("| Domain | Controls | Critical | With an ASVS counterpart | With supporting evidence |")
    w("|---|---|---|---|---|")
    supported = []
    for domain in sbd["checklistDomains"]:
        ids = [f"SBD-{c['id']}" for c in domain["controls"]]
        crit = sum(c["critical"] for c in domain["controls"])
        with_cw = [q for q in ids if crosswalk.get(q)]
        with_ev = [q for q in ids if sbd_supported(q)]
        supported += with_ev
        w(f"| {domain['id']} {domain['name']} | {len(ids)} | {crit} | {len(with_cw)} | {len(with_ev)} |")
    w("")
    for q in supported:
        via = [a for a in crosswalk.get(q, {}) if tiers(a)]
        direct = ", ".join(f"`{c}`" for t in ev.get(q, {}).values() for c in t[:2])
        how = f"through {', '.join(via)}" if via else f"directly, from {direct}"
        w(f"- {q}: {how}")
    w("")

    text = "\n".join(out).rstrip() + "\n"
    reach_text = reach_json(asvs, aisvs, ev, tiers, settles)
    # Two readings of "a check can credit it", made separately: the count in the tables above and
    # the kinds of run in data/reach.json. They must name the same requirements.
    reached = set(json.loads(reach_text)["requirements"])
    counted = {q for q in list(asvs) + list(aisvs) if credited(q)}
    if reached != counted:
        sys.exit("the tables and data/reach.json disagree about what a check can credit: "
                 + ", ".join(sorted(reached ^ counted)))
    rows = requirement_rows(asvs, aisvs, ev, tiers, settles, supports_only, manual_only, credited)
    listing_text = requirements_markdown(rows)
    if "--json" in sys.argv[1:]:
        path = Path(sys.argv[sys.argv.index("--json") + 1])
        path.write_text(json.dumps({"tiers": [{"id": t, "name": n, "needs": d} for t, n, d in TIERS],
                                    "requirements": rows}, indent=1) + "\n")
        print(f"wrote {path}")
    if check:
        for path, want in ((OUT, text), (LIST_OUT, listing_text), (REACH_OUT, reach_text)):
            current = path.read_text() if path.exists() else ""
            if current != want:
                sys.exit(f"{path.relative_to(ROOT)} is out of date: run `python3 tools/coverage.py` at "
                         "the repository root")
        return
    OUT.write_text(text)
    LIST_OUT.write_text(listing_text)
    REACH_OUT.write_text(reach_text)
    print(f"wrote {OUT.relative_to(ROOT)}, {LIST_OUT.relative_to(ROOT)} and {REACH_OUT.relative_to(ROOT)}")


# How each coverage status reads in the list, in words a person who is not a programmer reads easily.
STATUS = {
    "settle": "Can be checked",
    "found": "Can only be found failing",
    "support": "A check helps; a person decides",
    "none": "No check",
}


def requirement_rows(asvs, aisvs, ev, tiers, settles, supports_only, manual_only, credited):
    """One row per ASVS and AISVS requirement: where it sits, what it asks, and what speaks to it."""
    words = check_words()
    tier_name = {t: n for t, n, _ in TIERS}
    rows = []
    for name, reqs in (("ASVS 5.0", asvs), ("AISVS 1.0", aisvs)):
        for q, v in reqs.items():
            status = ("settle" if credited(q) else "found") if settles(q) else \
                "support" if supports_only(q) else "none"
            only = {r for _, r in FINDINGS_ONLY.get(q, ())}
            checks = []
            for t in tiers(q):
                for c in ev[q][t]:
                    if t == "tools":
                        # Each phrase once: one rule's words can join two with "; " that
                        # another rule says alone.
                        what = sorted({p.strip() for w in TOOL_RULES[q].get(c, [])
                                       for p in w.split("; ") if p.strip()})
                        finding_only = c not in CREDITED_BY_TOOL[q]
                        checks.append({
                            "id": c, "kind": tier_name[t], "tool": True,
                            "label": "Its rules look for",
                            "words": "; ".join(what[:6])
                                     + (f"; and {len(what) - 6} more" if len(what) > 6 else ""),
                            "rules": len(TOOL_RULE_IDS[q][c]), "finding_only": finding_only,
                            "credited_only": False, "in_part": False,
                        })
                    else:
                        label, text = words.get(c, ("Looks for", ""))
                        checks.append({"id": c, "kind": tier_name[t], "tool": False, "label": label,
                                       "words": text, "finding_only": c in only,
                                       "credited_only": c in RUST_CREDITS_ONLY,
                                       "in_part": c in RUST_IN_PART})
            rows.append({
                "id": q, "framework": name, "level": v["level"],
                "family": v["chapter"], "family_name": v["chapter_name"],
                "section": v["section"], "section_name": v["section_name"],
                "text": v["text"], "status": status, "status_words": STATUS[status],
                "person_decides": q in manual_only, "checks": checks,
            })
    return rows


def requirements_markdown(rows):
    order = lambda q: [int(x) for x in re.findall(r"\d+", q)]
    out = []
    w = out.append
    w("# Every ASVS and AISVS requirement, and what checks it\n")
    w("Generated by `tools/coverage.py` from the checks' own citations, with `docs/COVERAGE.md`. Do not")
    w("edit by hand; run `python3 tools/coverage.py` after changing a check, and the build fails until")
    w("you do. It lists every requirement, whether or not it applies to a given app; which apply is")
    w("decided per app, from its `stackvet.toml` and its code.\n")
    w("## How to read this\n")
    w(f"- **{STATUS['settle']}**: at least one check can mark it *checked* or *needs attention*. A check")
    w("  is almost always about part of a requirement, so a clean result is one automated check that")
    w("  was satisfied, not proof the whole requirement is met.")
    w(f"- **{STATUS['found']}**: every check that speaks to it can show it is not met, and none can show")
    w("  it is, so it can be marked *needs attention* and never *checked*.")
    w(f"- **{STATUS['support']}**: a check speaks to it, but it asks for something no check can settle,")
    w("  such as a documented policy or a design decision.")
    w(f"- **{STATUS['none']}**: nothing in `sv` checks it. A passing test of the app's own that names the")
    w("  requirement's id in code gives it *tested by the app's own tests*, below *checked* (ADR-050);")
    w("  otherwise it stays *not verified*.")
    w("- *found failing only*: that check can show the requirement is not met, and finding nothing does")
    w("  not show it is, so a clean run credits nothing.")
    w("- *credited only*: that check can show the requirement is met, and never marks it *needs")
    w("  attention*, since the app may meet it in a way the check cannot see; it says so instead.")
    w("- *only ever in part*: that check tries one piece of what the requirement asks, so what it credits")
    w("  is marked *checked in part*, never *checked* (ADR-053).")
    w("- Each check says what kind it is and so what it needs to run:\n")
    w("| Kind | Needs |")
    w("|---|---|")
    for _, name, needs in TIERS:
        w(f"| {name} | {needs} |")
    w("")
    for framework in ("ASVS 5.0", "AISVS 1.0"):
        mine = [r for r in rows if r["framework"] == framework]
        w(f"## OWASP {framework}\n")
        counts = Counter(r["status"] for r in mine)
        w(f"{len(mine)} requirements: {counts['settle']} can be checked, {counts['found']} can only be found "
          f"failing, {counts['support']} where a check "
          f"helps but a person decides, and {counts['none']} with no check.\n")
        for level in sorted({r["level"] for r in mine}):
            at = [r for r in mine if r["level"] == level]
            c = Counter(r["status"] for r in at)
            w(f"### Level {level} ({len(at)} requirements, {c['settle']} can be checked, {c['found']} can only "
              "be found failing)\n")
            families = defaultdict(list)
            for r in at:
                families[(r["family"], r["family_name"])].append(r)
            for (fid, fname), reqs in sorted(families.items(), key=lambda x: order(x[0][0])):
                w(f"#### {fid} {fname}\n")
                w("| Requirement | Coverage | Checks |")
                w("|---|---|---|")
                for r in sorted(reqs, key=lambda r: order(r["id"])):
                    parts = []
                    for ch in r["checks"]:
                        if ch["tool"]:
                            n = ch["rules"]
                            desc = f"{ch['kind']}: {ch['id']}, {n} rule{'' if n == 1 else 's'}"
                        else:
                            desc = f"{ch['kind']}: `{ch['id']}`"
                        if ch["words"]:
                            desc += f", {ch['label'].lower()}: {ch['words']}"
                        if ch["finding_only"]:
                            desc += " (found failing only)"
                        if ch["credited_only"] and ch["in_part"]:
                            desc += " (credited only, and only ever in part)"
                        elif ch["credited_only"]:
                            desc += " (credited only)"
                        elif ch["in_part"]:
                            desc += " (only ever in part)"
                        parts.append(desc.replace("|", "\\|"))
                    text = r["text"].replace("|", "\\|").replace("\n", " ")
                    checks = "<br>".join(parts) if parts else "–"
                    w(f"| **{r['id']}** {text} | {r['status_words']} | {checks} |")
                w("")
    return "\n".join(out).rstrip() + "\n"


if __name__ == "__main__":
    main()
