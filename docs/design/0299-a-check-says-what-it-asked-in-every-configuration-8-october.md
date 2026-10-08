# A check says what it asked, in every configuration (8 October 2026)

Item 8 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October
2026"), in its cheaper form. A check of the running app is `fn(.., out: &mut Outcome)`, and nothing makes it touch
`out`: when there was no private page to confirm a session against, five checks returned without a word (the invented
session, deleting an account, the default accounts, signing out by a plain link, the password in the address), the
sign-out check named V7.4.1 but not the V14.3.1 it reads from the same answer, and the owned-record checks named their
two requirements but not the preflight check's (V3.5.2) that runs on the record they create. Each of those requirements
was then missing from the report: neither credited, nor found, nor not assessed, which reads as "fine" to anybody
counting.

The fuller form, a guard per check whose drop records "asked and never answered", is not built; this is the test that
makes the fault visible: `every_configuration_of_the_suite_names_every_requirement_the_correct_app_does`
(`crates/sv-check/src/signed_in/asked_tests.rs`) runs the signed-in suite against the fake app three ways, correct,
with its private pages open and its sign-in broken (so no page confirms a session), and with many flaws, and holds
every requirement the correct app's run names, in any of the three buckets, to be named again in the other two. It
found the two it names above that the assessment had not (V14.3.1 and V3.5.2); with the seven places fixed it passes,
and it runs in under a second, the three runs side by side. A check that goes silent in a configuration it covers fails
it by requirement id. What it does not cover: a configuration it does not run (a check that goes silent only with, say,
an admin section and no owned record), which the fuller form would; add the configuration when such a case is found.

The older test `what_is_not_listed_is_named_as_not_assessed` looked for a requirement by the whole list it was named in
("V8.2.2, V3.5.1"); it looks for each id as a member now, so a list that names one more does not read as the first gone.
