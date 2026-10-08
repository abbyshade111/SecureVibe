# The security notes (25 September 2026)

Nineteen ASVS requirements at level 1 and 2 ask for a written decision and nothing else: what the
validation rules are, who may do what, how long a session lasts, how soon a vulnerable library is
updated. No scanner will settle one of them, because there is nothing in the code to read — the thing
asked for is a decision somebody made. They sat in the report as *not verified*, indistinguishable
from the requirements nobody had looked at, which told the owner nothing about what to do next.

`sv notes` writes `security-notes.md` beside the app: one section per applicable requirement, headed
by its id, with the question in plain words, the requirement's own wording quoted under it, and every
fact `sv` found that bears on it — the outside services by the package that showed each one, the kinds
of data from the manifest, the package ecosystems in use. The owner writes the answer underneath.

### A new tier, and what it is not

A section the owner has written makes its requirement **documented by the owner**. That is its own
tier, ranked below *checked* and above *not verified*, and it is never folded into either:

- Nothing reads whether the answer is right, or whether the app does what it says. Several of these
  requirements have a twin that asks exactly that — V2.3.2 for the business limits, V6.3.1 for the
  brute-force controls, V16.2.3 for where logs go — and those twins stay unverified. The catalog's
  `elsewhere` list names all twenty, each with why it is not a section.
- A finding beats an answer, and so does a check that ran. Writing "we rate limit sign-in" must never
  bury a check that found otherwise, and the owner's word about the app never outranks evidence read
  from it.
- **A documented requirement does not settle a threat.** The threat model reads requirement statuses,
  so without this a written answer would lift a threat from *not verified* to *checked in part* — an
  app talking its way out of a threat by describing itself. The status is shown in the threat's row,
  labeled as not being evidence about it, and counted toward nothing.

### The template's own words are not an answer

The one way this could lie is by counting the question as its answer, making every requirement
documented the moment the file existed. The reader strips what `sv` itself wrote — the heading, the
quoted question, the italic lines, the facts, the placeholder — and asks whether anything is left,
with a floor of 40 characters so a word left while editing does not document a policy. Rewriting the
file keeps every answer, and an answer whose requirement stopped applying is kept too, under a note
saying so, because the manifest may be what is wrong and deleting somebody's writing to tidy a file is
not `sv`'s call.

### Guards on the catalog, and the one the citations cannot have

`data/security-notes.json` is prose, and prose drifts from what it paraphrases. Every id must exist,
and every question must share vocabulary with the requirement it claims to ask about — the same weak
overlap test the citations use. Then two more:

- **Every documentation requirement is accounted for.** Any ASVS requirement at level 1 or 2 whose own
  words say "document" is either a section or named in `elsewhere` with why. Without it, adding the
  nineteenth question and forgetting the twentieth looks exactly like deciding there are nineteen.
- **Each question fits its own requirement better than any other.** This is the blindness
  `citations.rs` admits to and cannot fix: two neighboring requirements share vocabulary, so a
  question written for one and filed under the other passes the overlap test. Here it is fixable,
  because these nineteen are a small closed set that can be compared against each other. Four swaps
  between neighbors — the key policy against the key inventory, the session timeouts against the
  concurrent-session limit, and two more — passed every other guard and were caught by nothing until
  this test existed. Writing it also found the one real fault in the catalog: V2.1.2's question had
  drifted far enough that it fit two other requirements better than its own.
