# The fence test can pass without proving anything

**Status:** done, 10 October 2026

Found on 26 September 2026 running the suite
on the owner's Mac (Docker Desktop). **Claimed on 26 September 2026 by session
admiring-murdock-875699. Done the same day:** with `--internal` removed the test now fails
(`Some(0)`), with `nc` renamed to a program that does not exist it fails (the control reports 127;
the old test passed that case), and with a dead address it fails (the control reports 1).
`the_fence_really_blocks_outbound_traffic` in
`crates/sv-run/tests/fence.rs` counts *any* failure of `docker exec … nc` as "blocked": `nc` missing
from the image, a flag it does not understand, or the container gone would all pass. And its only
control is the host reaching `1.1.1.1:53`, but on Docker Desktop containers run in a separate Linux
VM, so the host getting out does not show a container could. Fix: a control container on an
ordinary network created the same way minus `--internal`, running the identical command, which
must connect; and the fenced run must show that `nc` really ran and failed to connect.

**Checked against origin/main, 10 October 2026:** built: `crates/sv-run/tests/fence.rs:112-135` requires the control network to reach `1.1.1.1:53`, and the fenced run must exit with a code other than 0, 126 or 127.
