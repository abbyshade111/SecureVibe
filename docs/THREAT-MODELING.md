# Threat modeling without the AI tool: an investigation

Asked for by the owner on 25 September 2026: could `sv` produce a threat model on its own, without
asking the connected AI system? This is the answer, and a proposal. Nothing here is built yet.

## Short answer

Yes, and most of it already exists. v1 has a rule-based threat model that needs no AI, and `sv`
already knows almost everything those rules ask. What has to change is the one thing v1 could take
for granted: v1 wrote the app, so it could call a threat *mitigated*. `sv` reads an app somebody else
wrote, so it can only say what its checks showed about each threat. Done that way, the threat model
becomes a new way to read the evidence `sv` already collects, arranged by *what could go wrong*
rather than by requirement number, and it makes no claim the evidence does not support.

## What exists in v1

`server/src/design/threat-model.ts` is a STRIDE model, built entirely from rules:

- **32 threats**, each tied to a part of the app (the browser-to-app connection, the database, file
  storage, the AI provider, email, payments, an outside API, and so on) and to a STRIDE category
  (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of
  privilege).
- **About 20 facts decide which threats apply**: sign-in, uploads, AI, AI that can act, email,
  payments, a public API, outside services, scheduled jobs, personal or sensitive data, whether it is
  on the internet, and how bad a breach would be.
- **Likelihood and impact** come from who uses the app (public, customers, a team) and what data it
  holds. Risk is their product: low, medium, or high.
- **Each threat lists its mitigations**: a template control that v1 wrote into the app, and the ASVS or
  AISVS requirements that verify it: 80 different requirements in all.

v1 also has an AI step (`server/src/llm/flows/threat-model.ts`) that may replace the rule-based model,
and falls back to it whenever the AI is not configured, declines, or answers with something that does
not fit. So the rule-based model is already the one v1 relies on when there is no AI.

## What `sv` already knows

| v1 fact | In `sv` |
|---|---|
| sign-in, uploads, AI, AI that acts, email, payments, public API, outside services, scheduled jobs | Conditions of the same names, from securevibe.toml and corrected by the code: a Stripe package in the lockfile switches payments on whatever the manifest says (`claim-corroborators.json`) |
| which outside service | The package that matched, named in the evidence: `stripe`, `openai`, `@sendgrid/mail` |
| MCP, retrieval (RAG), several services, multi-tenant, WebSockets | Conditions too; v1 had no threats for these, and they are where AI apps differ most |
| audience, deployment, data categories | `[app]` and `[data]` in securevibe.toml |
| mitigations | Not known, and this is the point: `sv` did not write the app |
| whether each mitigation holds | The report's status for each cited requirement: *checked*, *needs attention*, or *not verified* |

## Proposal

**1. Move the rules into data.** A file, `data/knowledge/threats.json`, holding each threat: its
STRIDE category, the part of the app it concerns, a plain description, the conditions it needs, how
likelihood and impact are decided, and the requirements that answer it. v1's 32 are the start. New ones
where `sv` sees more than v1 did: MCP tools (C10), retrieval (C5.2.2, C8), several services, WebSockets,
multi-tenant data. Being data, the rules fall under the same guards as every other citation: the id
exists, and the threat's words share vocabulary with each requirement it names
(`crates/sv-check/tests/citations.rs`). And, being in `data/knowledge`, v1 could later read the same
file, so the two products would stop keeping two copies (that is a v1 change, and a separate
decision).

**2. Say what the evidence says about each threat, and nothing more.** Each threat that applies gets
one of four statuses, computed from the requirements it cites:

| Status | When | What the report says |
|---|---|---|
| **Found** | any cited requirement *needs attention* | the threat is real in this app, with the finding |
| **Checked in part** | some cited requirements *checked*, none failing | which parts were checked, and which were not |
| **Not verified** | nothing checked, nothing found | nothing here has looked; the tests to write for it |
| **Cannot place** | a condition it depends on is unanswered | which question to answer in securevibe.toml |

There is no *mitigated*. A threat is never marked handled on the strength of checks that each cover
part of a requirement, and the report says so where the table starts.

**3. A data-flow outline.** The parts of the app that were detected (browser, app, database, files,
each outside service by the package that showed it) and the connections between them, as a list and
as a Mermaid diagram in the HTML report. Only what was detected is drawn; a part the manifest claims
and the code does not show is drawn with that said.

**4. Sorted by what matters.** Found first, then by risk (likelihood × impact from audience,
deployment, and data), so the first screen is the threats that are both likely and serious and have
nothing checking them.

## What it may claim, and what it may not

- **May:** these threats apply to what was detected; this one is found, with the finding; these
  requirements, which answer it, were checked.
- **May not:** a threat is mitigated; the list is complete; there are no other threats. A rule-based
  model lists the threats someone wrote rules for. The report states that plainly, beside the list,
  every time.
- **May not:** a threat does not apply because a condition was not detected, when not detecting it
  is not evidence (`absenceIsEvidence: false` in the corroborators). Such threats are listed as
  *cannot place*, the same way the requirements are.

## What the owner gets

- The same evidence as the compliance report, arranged by *what could go wrong with this app*, which is
  the question a non-programmer actually has.
- A short list of the serious threats nothing has checked yet, each with the tests to write for it,
  since every threat names its requirements and "Tests to write" already lists them by requirement.
- Supporting evidence for the Secure by Design checklist: MT-03 asks for security tests "from
  threat-modeling", and the threat model's tests-to-write list is exactly that. Supporting only: the
  checklist is design review a person answers.
- Free, the same on every run, and testable, because no model is asked anything.

## Why not the AI tool for this

It is deterministic, costs nothing, gives the same answer twice, and can be tested the way every other
check here is (a threat's rule is broken, and a test goes red). An AI step could later *add* threats
for a person to review, the way v1's does, but never mark one handled, and never replace the rules.

## Cost, and order

Three pull requests, each small enough to review:

1. `threats.json` with v1's 32 threats ported and cited, the condition logic, the guards (ids exist,
   vocabulary shared, every condition named is one `sv` has), and the status computation, with tests
   that break each rule and watch which test catches it.
2. The report section (HTML and Markdown), the data-flow outline, and the MCP summary.
3. The new threats for what `sv` sees and v1 did not: MCP, retrieval, several services, WebSockets,
   multi-tenant.

## Progress

**Part 1 of 3, done on 25 September 2026:** `data/knowledge/threats.json` and
`crates/sv-report/src/threats.rs`. v1's rules became 30 threats across ten parts of the app, citing 90
requirements, each citation carrying a few words the threat and the requirement share (`because`),
which the citation guard reads against both. Only 53 of v1's 107 citations shared a word with their
threat as written; reading them one by one, most were right in different words, and these were not:
SameSite cited for a stolen session cookie (HttpOnly and session-id randomness are what answer it), an
outbound allowlist for a forged "payment succeeded" message (authenticated backend messages are),
log protection for a copied database, and five weaker links dropped. The report section is part 2.

**Part 2 of 3, done on 25 September 2026:** a "Threats" section in `compliance.md` and `report.html`,
after the requirements and before the tests to write: what the section can and cannot say, the parts of
the app (each one nobody answered for is named with the question in securevibe.toml that would place
it), a count, and one row per threat with its status and its requirements grouped by what is known
about them. `sv report` prints the count, and `sv mcp` gives the AI tool the found and not-verified
threats. The data-flow outline is a list rather than the Mermaid diagram proposed above: `report.html`
opens offline by double-clicking, and Mermaid draws with a script fetched from the web. No threat is
ever called mitigated, and a test reads both reports for the word.

**Part 3 of 3, done on 25 September 2026:** twelve threats for what v1 did not model, on four new
parts of the app and one condition: tools the model can use over MCP (poisoned tool responses, tools
called beyond the person's permission, tokens not checked, untrusted or unsandboxed servers; AISVS
C10), the documents the model searches (answers from documents the person may not see, planted
content, sensitive fields embedded; C5.2.2, C8), the app's own separate services (calls between them
not authenticated; V13.2), live WebSocket connections (a connection from another site, messages read
on the network; V4.4), and several tenants in one system (V8.4.1, and, with retrieval, C8.1.1 and
C5.3.1). 42 threats across 14 parts, citing 115 requirements, every citation under the guard. What
remains is v1 reading the same file, which is a change to v1 and its own piece of work.

## Decided by the owner, 25 September 2026

1. **No scoring.** v1's likelihood and impact are not carried over. The list is ordered by what the
   evidence says (found, then not verified, then checked in part), with no low/medium/high attached.
2. **One copy.** v1 is to read the same `threats.json` later, so a threat is fixed in one place. That
   change to v1's design engine is its own piece of work, after this one.
3. **A section of the report**, not a file of its own: in the HTML and Markdown reports, beside
   compliance and security.

So proposal step 4 ("sorted by what matters") becomes: found first, then not verified, then checked in
part, then cannot place; within each, in the order of the parts of the app in the data-flow outline.

## The questions as they were asked

1. **Scoring.** v1 scores likelihood and impact low/medium/high from the answers. That is a judgment,
   and it orders the list. Keep it, as v1 does, or order only by *found* then *not verified* and
   leave out the scores?
2. **One copy or two.** Should v1 later read the same `threats.json`, so a threat is fixed in one
   place? That changes v1's design engine and is separate from this.
3. **Where it shows.** A section of the existing report, or its own file (`threat-model.md`) the way
   v1 writes one?
