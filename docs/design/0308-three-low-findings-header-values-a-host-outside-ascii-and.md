# Three low findings: header values, a host outside ASCII, and the Ctrl-C exits (8 October 2026)



From the review of 8 October 2026, item 6 (`docs/backlog/0188-from-the-review-of-8-october-2026-the-medium-and-low.md`),
three of its low findings.

**A header value quoted whole.** The site chooses its headers. `sv probe` quoted a Strict-Transport-Security value, a
redirect's address, and the other host a redirect named, and the running-app checks quoted a version header
(`Server`, `X-Powered-By`, and the rest), each as it came. One of 100 KB buried the report, and a line break in one
started a line of its own in it. Each is now quoted through `finding::quoted`: on one line (any control character
becomes a space) and cut at 200 characters, with how long it was in all ("… (100011 characters in all)"). The value
is still read whole: a policy whose `max-age` sits in a 100 KB header is still found weak.

**A host name with letters outside ASCII.** `sv probe https://bücher.example` was taken as typed. Such a name is looked
up, and connected to, by its `xn--` form, so the one lookup `sv` makes and the address curl is held to by `--resolve`
were for a name curl never asks for, and the hold would not have held. It is now refused before anything is asked,
with a sentence saying to give the `xn--` form, which copying the address from a browser's address bar gives. `sv`
does not convert the name itself, which would take a dependency for a case met rarely (ADR-027, Later).

**The Ctrl-C exits.** `main.rs` ended a run stopped with Ctrl-C in two places with `std::process::exit`, without the
flush `exit::exit_with` does first; one of the two was added the same day by the Ctrl-C fix for `--tools`. Both now
go through `exit_with`, with the code named (`exit::INTERRUPTED`, 130). Rust writes whole lines to the screen as they
are printed, so no test can see a flush that was skipped; a test reads `sv`'s source instead and fails on
`process::exit` anywhere but `exit.rs`.

Tests: three in `crates/sv-check/src/finding/quoted_tests.rs`, five in `crates/sv-check/src/production/quoted_tests.rs`
(a 100 KB HSTS header quoted short and still read; a redirect's long address, its line break, and a long other host,
each on one short line; an API redirect's long address; a short header quoted as it came; a host outside ASCII refused
and its `xn--` form taken), two in `crates/sv-check/src/probes/quoted_tests.rs`, and one in
`crates/sv-cli/tests/one_way_out.rs`. Nine guards broken in turn, each caught: no cut (5 tests), line breaks kept (2),
and each of the six places quoting whole again, and the non-ASCII host taken (1 each), and `process::exit` put back (1).
