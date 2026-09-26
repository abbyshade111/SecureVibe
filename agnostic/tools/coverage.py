#!/usr/bin/env python3
"""Writes docs/COVERAGE.md: which requirements any check in `sv` can speak to, and what it needs to run.

    python3 tools/coverage.py            # rewrite docs/COVERAGE.md
    python3 tools/coverage.py --check    # fail if docs/COVERAGE.md is not what this would write

Everything is read from where the checks themselves keep their citations, so the document cannot
claim a check the code does not have:

- `data/ast-rules.json`, `data/secret-rules.json`, `data/adapters.json`: the rules and their
  requirements;
- the checks whose citations are written in Rust (probes, signed-in checks, configuration, the bill
  of materials, advisories), listed in `RUST_CHECKS` below. A requirement id written into `sv`'s
  code as a string of its own that is in neither that table nor `MENTIONS` stops this script, so a
  new hard-coded check cannot be left out;
- `../data/knowledge/applicability.json`'s `manualOnly`, and the Secure by Design prefix, for the
  requirements a check can support but never settle;
- `data/sbd-asvs-crosswalk.json`, for the checklist controls with an ASVS counterpart.

A test (`crates/sv-check/tests/coverage_doc.rs`) runs `--check`, so a change to the checks that is not
followed by regenerating this document fails the build.
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGNOSTIC = HERE.parent
ROOT = AGNOSTIC.parent
OUT = AGNOSTIC / "docs" / "COVERAGE.md"

# What each kind of check needs before it can run at all.
TIERS = [
    ("static", "Reads the code", "nothing: plain `sv check`"),
    ("advisories", "Known vulnerabilities", "a local copy of the OSV database (`--advisories DIR`)"),
    ("running", "The running app", "a container backend and a `run` section (`--run`)"),
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
    "config.gitignore-covers-env": ("static", ["V13.3.1"]),
    "config.versions-pinned": ("static", ["V15.1.2"]),
    "sbom": ("static", ["V15.1.2"]),
    "secrets.credential-assignment": ("static", ["V13.3.1", "V13.2.3", "SBD-AC-05"]),
    "advisories": ("advisories", ["V15.2.1"]),
    "probe.security-headers": ("running", ["V3.4.3", "V3.4.4", "V3.4.5", "V3.4.6"]),
    "probe.cookie-attributes": ("running", ["V3.3.2", "V3.3.4"]),
    "probe.cors-any-origin": ("running", ["V3.4.2"]),
    "probe.error-detail-leak": ("running", ["V13.4.2", "V16.5.1"]),
    "probe.trace-enabled": ("running", ["V13.4.4"]),
    "probe.content-type": ("running", ["V4.1.1"]),
    "probe.source-control-exposed": ("running", ["V13.4.1"]),
    "probe.private-page-anonymous": ("signed-in", ["V8.2.1"]),
    "probe.admin-page-ordinary-user": ("signed-in", ["V8.2.1"]),
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
    "probe.session-id-weak": ("signed-in", ["V7.2.3"]),
    "probe.password-altered": ("signed-in", ["V6.2.8"]),
    "probe.long-password-refused": ("signed-in", ["V6.2.9"]),
    "probe.password-field-unmasked": ("signed-in", ["V6.2.6"]),
    "probe.password-paste-blocked": ("signed-in", ["V6.2.7"]),
    "probe.sign-out-on-get": ("signed-in", ["V3.5.3"]),
    "probe.password-change": ("signed-in", ["V6.2.2"]),
    "probe.password-change-without-current": ("signed-in", ["V6.2.3"]),
    "probe.sessions-survive-deletion": ("signed-in", ["V7.4.2"]),
    "probe.password-hints": ("signed-in", ["V6.4.2"]),
    "probe.reset-reusable": ("signed-in", ["V6.4.3"]),
    "probe.reset-keeps-old-password": ("signed-in", ["V6.4.3"]),
    "probe.reset-code-guessable": ("signed-in", ["V6.4.3"]),
    "probe.reset-reveals-account": ("signed-in", ["V6.3.8"]),
    "probe.email-code-reusable": ("signed-in", ["V6.5.1"]),
    "probe.session-idle-timeout": ("signed-in", ["V7.3.1"]),
    "probe.session-lifetime": ("signed-in", ["V7.3.2"]),
    "probe.email-code-unbound": ("signed-in", ["V6.6.2"]),
    "probe.email-code-short": ("signed-in", ["V6.5.4"]),
    "probe.email-code-guessing-unlimited": ("signed-in", ["V6.6.3"]),
    "probe.failed-sign-ins-unlimited": ("signed-in", ["V6.3.1"]),
    "probe.certificate-not-trusted": ("production", ["V12.2.2"]),
    "probe.plain-http-served": ("production", ["V12.2.1"]),
    "probe.no-hsts": ("production", ["V3.4.1"]),
    "live.ech-not-offered": ("production", ["V12.1.5"]),
    "live.hsts-not-preloaded": ("production", ["V3.7.4"]),
    "probe.cookie-without-host-prefix": ("production", ["V3.3.3"]),
    "probe.directory-listing": ("running", ["V13.4.3"]),
    "probe.private-page-cached": ("signed-in", ["V14.3.2"]),
    "probe.no-sign-out-link": ("signed-in", ["V7.4.4"]),
    "probe.oversized-file-accepted": ("signed-in", ["V5.2.1"]),
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
    "probe.record-returns-secret-fields": ("signed-in", ["V15.3.1"]),
    "probe.clear-site-data": ("signed-in", ["V14.3.1"]),
}

# Ids written into the code as strings that are not evidence: examples in comments on how ids are
# parsed, a requirement named only to say it is not assessed, and the two ids `sv init` prints as
# worked examples of a [design] answer. The design questions cite their requirements in
# `data/design-questions.json`, and they are deliberately absent from this document: an answer there
# is the owner's word, which is the one thing this file must not count as coverage.
MENTIONS = {"AC.4.1", "SBD-AC-01", "V6.2.1", "V3.3.1", "V8.3.1", "V2.2.2"}

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
                    "text": r.get("description", ""),
                }
    return out


def appendix_c(path):
    out = {}
    for family in load(path)["families"]:
        for section in family.get("sections") or [family]:
            for r in section.get("requirements", section.get("controls", [])):
                out[r["id"]] = {"chapter": family["id"], "chapter_name": family["name"]}
    return out


def rust_literals():
    found = defaultdict(set)
    for path in sorted((AGNOSTIC / "crates").glob("*/src/*.rs")):
        code = path.read_text().split("#[cfg(test)]")[0]
        for m in re.finditer(r'"(' + ID + r')"', code):
            found[m.group(1)].add(path.name)
    return found


# Requirement id -> the rules that can only ever raise it as a finding (`findings_against` in
# adapters.json), by their folder name. A clean run credits none of these.
# Requirement id -> {(tool, rule)}: rules that are only ever a finding against it.
FINDINGS_ONLY = defaultdict(set)
# Requirement id -> {tool}: tools with some rule a clean run credits to it.
CREDITED_BY_TOOL = defaultdict(set)


def evidence():
    """Requirement id -> {tier: [check, ...]}."""
    ev = defaultdict(lambda: defaultdict(list))
    for rule in load(AGNOSTIC / "data/ast-rules.json")["rules"]:
        for q in rule["requirementIds"]:
            ev[q]["static"].append(rule["id"])
    for rule in load(AGNOSTIC / "data/secret-rules.json")["rules"]:
        for q in rule["requirementIds"]:
            ev[q]["static"].append(rule["id"])
    for adapter in load(AGNOSTIC / "data/adapters.json")["adapters"]:
        for rule in adapter["rules"].values():
            for q in rule["requirements"]:
                if adapter["id"] not in ev[q]["tools"]:
                    ev[q]["tools"].append(adapter["id"])
                CREDITED_BY_TOOL[q].add(adapter["id"])
        for rule_id, rule in adapter["rules"].items():
            for q in rule.get("findings_against", []):
                if adapter["id"] not in ev[q]["tools"]:
                    ev[q]["tools"].append(adapter["id"])
                # The AI rules by their folder, which names the family across vendors and
                # languages; the rest by their own id.
                parts = rule_id.split(".")
                FINDINGS_ONLY[q].add((adapter["id"], parts[2] if parts[0] == "ai" else parts[-1]))
    for check, (tier, ids) in RUST_CHECKS.items():
        for q in ids:
            ev[q][tier].append(check)
    return ev


def main():
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
    code = "".join(p.read_text().split("#[cfg(test)]")[0] for p in (AGNOSTIC / "crates").glob("*/src/*.rs"))
    unnamed = sorted(c for c in RUST_CHECKS if f'"{c}"' not in code)
    if unnamed:
        sys.exit("RUST_CHECKS names checks the code does not have: " + ", ".join(unnamed))
    stale = sorted(q for _, ids in RUST_CHECKS.values() for q in ids if q not in written)
    stale += sorted(q for q in MENTIONS if q not in written)
    if stale:
        sys.exit("RUST_CHECKS or MENTIONS names ids no longer in the code: " + ", ".join(stale))

    asvs = framework(ROOT / "data/frameworks/asvs-5.0.0.json")
    aisvs = framework(ROOT / "data/frameworks/aisvs-1.0.json")
    appendix = appendix_c(ROOT / "data/frameworks/aisvs-1.0-appendix-c.json")
    sbd = load(ROOT / "data/frameworks/sbd-checklist-0.5.0.json")
    crosswalk = load(AGNOSTIC / "data/sbd-asvs-crosswalk.json")["controls"]
    manual_only = set(load(ROOT / "data/knowledge/applicability.json")["manualOnly"])
    ev = evidence()

    def tiers(q):
        return [t for t, _, _ in TIERS if ev.get(q, {}).get(t)]

    def settles(q):
        return bool(tiers(q)) and q not in manual_only and not q.startswith("SBD-")

    def supports_only(q):
        return bool(tiers(q)) and not settles(q)

    out = []
    w = out.append

    w("# Coverage: what the checks can speak to\n")
    w("Generated by `tools/coverage.py` from the checks' own citations. Do not edit by hand; run")
    w("`python3 tools/coverage.py` after changing a check, and the build fails until you do.\n")
    w("## How to read this\n")
    w("- **Can settle**: at least one check can mark the requirement *checked* or *needs attention*.")
    w("  A check is almost always about part of a requirement: a clean result is one automated check")
    w("  that was satisfied, not a pass.")
    w("- **Supporting only**: a check speaks to it, but the requirement asks something no check can")
    w("  answer, such as a documented policy or a design decision. The check is shown beside it and")
    w("  a person still has to answer it. The whole Secure by Design checklist is this by design.")
    w("- **Nothing**: no check in `sv` names it. It can still be credited by the app's own tests that")
    w("  name the requirement id and pass, which is how `sv init` asks for tests to be written, and")
    w("  otherwise stays *not verified*.")
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
        pct = f"{100 * s / n:.0f}%" if n else "–"
        return f"| {name} | {n} | {s} ({pct}) | {p} | {n - s - p} |"

    sbd_ids = [f"SBD-{c['id']}" for d in sbd["checklistDomains"] for c in d["controls"]]
    w("## Summary\n")
    w("| Framework | Requirements | Can settle | Supporting only | Nothing |")
    w("|---|---|---|---|---|")
    w(summary_row("OWASP ASVS 5.0", list(asvs)))
    w(summary_row("OWASP AISVS 1.0", list(aisvs)))
    w(summary_row("AISVS Appendix C", list(appendix)))
    w(summary_row("Secure by Design checklist 0.5.0", sbd_ids))
    w("")

    # ---- ASVS by level and kind
    w("## ASVS 5.0 by level\n")
    w("A requirement reached by more than one kind of check is counted under each.\n")
    head = " | ".join(name for _, name, _ in TIERS)
    w(f"| Level | Requirements | Can settle | {head} |")
    w("|---|---|---|" + "---|" * len(TIERS))
    for level in sorted({v["level"] for v in asvs.values()}):
        reqs = [q for q, v in asvs.items() if v["level"] == level]
        cells = " | ".join(
            str(sum(1 for q in reqs if settles(q) and t in tiers(q))) for t, _, _ in TIERS
        )
        w(f"| L{level} | {len(reqs)} | {sum(settles(q) for q in reqs)} | {cells} |")
    w("")
    plain = [q for q in asvs if settles(q) and tiers(q) == ["static"]]
    only_tools = [q for q in asvs if settles(q) and tiers(q) == ["tools"]]
    w(f"With nothing beyond plain `sv check`, {sum(settles(q) and 'static' in tiers(q) for q in asvs)} "
      f"ASVS requirements can be settled. {len(only_tools)} can be settled only by an outside tool, "
      "almost all by semgrep and CodeQL, and only for the languages their rules are written for.\n")

    # ---- ASVS by chapter
    w("## ASVS 5.0 by chapter\n")
    w("| Chapter | Requirements | Can settle | Supporting only | Nothing |")
    w("|---|---|---|---|---|")
    chapters = defaultdict(list)
    for q, v in asvs.items():
        chapters[(v["chapter"], v["chapter_name"])].append(q)
    for (cid, name), reqs in sorted(chapters.items(), key=lambda x: int(x[0][0][1:])):
        s = sum(settles(q) for q in reqs)
        p = sum(supports_only(q) for q in reqs)
        w(f"| {cid} {name} | {len(reqs)} | {s} | {p} | {len(reqs) - s - p} |")
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
    w("| Chapter | Requirements | Can settle | Supporting only | Nothing |")
    w("|---|---|---|---|---|")
    chapters = defaultdict(list)
    for q, v in aisvs.items():
        chapters[(v["chapter"], v["chapter_name"])].append(q)
    for (cid, name), reqs in sorted(chapters.items(), key=lambda x: int(x[0][0][1:])):
        s = sum(settles(q) for q in reqs)
        p = sum(supports_only(q) for q in reqs)
        w(f"| {cid} {name} | {len(reqs)} | {s} | {p} | {len(reqs) - s - p} |")
    w("")
    settled_ai = sorted((q for q in list(aisvs) + list(appendix) if settles(q)),
                        key=lambda q: [int(x) for x in re.findall(r"\d+", q)])

    def credited_by_other(q):
        return any(c for tier, checks in ev[q].items() for c in checks
                   if not (tier == "tools"
                           and any(tool == c for tool, _ in FINDINGS_ONLY.get(q, ()))
                           and c not in CREDITED_BY_TOOL[q]))

    only = [q for q in settled_ai if q in FINDINGS_ONLY and not credited_by_other(q)]
    w(f"{len(only)} of these {len(settled_ai)} can only ever be marked *needs attention*: the rules")
    w("about applications that call a model, semgrep's and CodeQL's, can show the control missing, and finding nothing does not")
    w("show it present, so a clean run credits none of them. Each needs `--tools`.\n")
    for q in settled_ai:
        rules = sorted(FINDINGS_ONLY.get(q, ()))
        names = [c for tier, checks in ev[q].items() for c in checks
                 if not (tier == "tools" and c == "semgrep" and rules)]
        parts = []
        if names:
            parts.append(f"settled by {', '.join(f'`{c}`' for c in names[:4])}"
                         + (f" and {len(names) - 4} more" if len(names) > 4 else "")
                         + " (its applicability rule classifies it `scanner-clean`, so a clean credential"
                         " scan counts; the scan reads the repository, not what reaches the model's"
                         " context at run time)")
        if rules:
            parts.append("found failing by semgrep's " + ", ".join(f"`{r}`" for r in rules))
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
    if check:
        current = OUT.read_text() if OUT.exists() else ""
        if current != text:
            sys.exit("docs/COVERAGE.md is out of date: run `python3 tools/coverage.py` in agnostic/")
        return
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(AGNOSTIC)}")


if __name__ == "__main__":
    main()
