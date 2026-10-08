# The run's script is in `sv-check`, and runs without Docker (8 October 2026)

Item 4 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October
2026"), second half. `sv-run` depended on `sv-check`, the reverse of the stated layering, because `run_after_cleanup`
in `crates/sv-run/src/docker.rs` (568 lines) was the whole run: the network and the helpers, the app started and
waited for, and then, in the same function, which suites were asked, in which order, as which user, and the kill
switch tried on a second copy. The order could be tried only with Docker, so a change to it was tested by CI's fence
tests or not at all.

The script is `crates/sv-check/src/script.rs` now: `run(services, plan, probes)`, written against the trait
`Services`, which is what only the harness can do (a way to the app with the helpers the run has, the test model's
address when it answers, the app's log, the seed, the second copy for the kill-switch check, a look at whether the
app is still up) and nothing about containers. `sv-run`'s `DockerRun` implements it over Docker, each method one of
the calls the function made before; what is left in `run_after_cleanup` (430 lines) is the fence, the helpers, the
app's start and readiness, the install step, the app's own tests inside its container, and the teardown. The order of
the suites and the helpers each is given are as they were: the anonymous questions, a look at the app, the signed-in
suites (the mail server, the browser, and the model when it answers), the test provider, the MCP server, the fetch
(the model's address first), the AI feature, its log, the kill switch on the second copy (the model as started),
and a second look when any of those was asked. One difference: the fetch suite asks the model's readiness twice (for
its address, and for its way to the app) where it asked once, which is one more health request when the model
answers and a second wait of up to ten seconds when it does not.

`sv-run` still depends on `sv-check` for the types the harness hands over (`ProbeRequest`, `Accounts`, the suites'
outcomes, `Liveness`) and for the `Http` trait it implements; what moved is the decision of what to ask. The script's
tests (`script::tests`) run it against a harness that answers nothing and writes down every call: with nothing in the
manifest, the anonymous questions and one look; with everything, every suite in its order and the second look; and
the kill-switch copy never started when the model was not reached. The test that holds the specification's sentence
about when `seed` runs to the code (`the_spec_says_the_seed_runs_after_the_health_check_and_it_does`) now reads both
files: the health check before the script in `docker.rs`, and the seed inside the signed-in stage and after the
anonymous questions in `script.rs`.
