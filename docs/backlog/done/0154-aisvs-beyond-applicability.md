# AISVS, beyond applicability

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026 by session securevibe-e8. Semgrep's
AI rules now name eight AISVS requirements (C2.1.6, C2.2.1, C7.1.2, C7.3.1, C9.1.2, C9.3.1, C9.5.4,
C10.4.2) through a new `findings_against` list: a finding is evidence against them, and a clean run
credits none, because these patterns can show a control missing and never present. See DESIGN,
"AISVS from semgrep's AI rules". Left over: `sv`'s own code rules match a call and its arguments,
and every one of these is a flow from one place to another, so none was written. Seen firing in a real
run: 11 of the 24 rules, in Python and JavaScript; the rest are the same patterns for other vendors.
