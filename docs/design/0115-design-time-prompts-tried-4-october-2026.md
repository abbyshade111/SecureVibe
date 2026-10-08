# Design-time prompts, tried (4 October 2026)

The prompt library (`docs/PROMPTS.md`) asks the AI coding tool for something `sv` checks; these ask it to decide
something with the owner first and write it down. They come from the OWASP Secure by Design checklist, whose controls
are all design review: no check settles one (see "The checklist that was named and never loaded"). So each prompt
names the controls it *helps answer* in `sbd_controls` (`data/design-prompts.json`) and is held to an ASVS requirement
`data/sbd-asvs-crosswalk.json` pairs with them and a check of `sv`'s speaks to. Six were tried, under the library's
rule (the owner's decision of 3 October 2026): shown only when a build with the prompt passed and the builds without
it failed.

**The trial.** One brief (`docs/prompts/trial/brief.md`): a club site in Python's standard library with sign-in,
private notes, one seat to book, an assistant calling an OpenAI-compatible service, and an admin page. Fresh helper
agents built it in folders of their own, twice without a prompt and once with each; `tools/prompt_trial.py` ran
`sv report --run` on each behind the fence (Docker started by hand in this container) and read the targeted rules out
of `report.json`. Where a build wrote [policy] numbers it was held to them; where it wrote none, the numbers in
`docs/prompts/trial/policy.toml` stood in for the owner's.

**What the first round got wrong, twice.** It gave every build a `securevibe.toml` that already held the [policy]
numbers. The builds without a prompt read them and enforced them, so the settings file was acting as the prompt and
prompts 3 and 7 could not fail without. And builds that read "10 requests a minute" applied it to sign-in by address;
`sv` sends everything from one address and signs in dozens of times, so the limiter stopped it and the run credited
almost nothing (ADR-021 working as meant). The second round took the numbers out and added a plain line to the brief
that a tester signs in many times from one address.

**What it showed.** Shown: 3 (limits; V2.4.1 and V6.3.1), 6 (logging; V16.2.1 and V16.2.2), and 7 (sign-in; V7.3.1).
For 7, and 3's password limit, the builds without the prompt had a timeout or lockout of their own choosing, written
down nowhere, so `sv` held them to the stand-in numbers: what the prompt changed is that the decision was recorded
where it can be held to. That is worth having, and it is not the same as making sessions end, so the page says so.
Not shown: 1 (who may do what) and 4 (when things fail), which both builds without a prompt already passed, and 2
(actions once), where `sv` raised `probe.action-done-twice` against the build made with it: it took the seat in one
conditional UPDATE and answered the holder's repeats with "Booked", which is what the prompt asks for and which the
check counts as twenty bookings. That is a false alarm in `sv`, recorded in the backlog. Prompt 6's first wording
asked for "the path"; both builds with it logged the path without its query string and without the status, so
`probe.authorization-failure-logged` (which plants its marker in the query string and wants the status on the same
line) could not credit them. It was reworded to ask for both and built again, and V16.3.2 is still not claimed,
because one build without the prompt logged the refusal too.

Not done: the eight design-time prompts no check can show working (backlog items 8 to 15), a second build per
prompt, another brief, and another AI tool. One build each is a small sample, and every builder was the same model.
