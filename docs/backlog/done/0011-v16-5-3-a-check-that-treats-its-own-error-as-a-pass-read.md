# V16.5.3: a check that treats its own error as a pass, read from the code

**Status:** done, as its markers read on 8 October 2026

From `docs/PARTIAL-CHECKS.md`
(V16.5.3, level 2, "reads the code, finding only"), which no check speaks to yet. A function that decides whether
someone may go on (its name says verify, check, authorize, allow, and the like) and that answers "yes" when the
check throws: `except: return True`, `catch { return true; }`, `.unwrap_or(true)`. Only ever a finding: finding none
says nothing about the app's other error handling, so it credits nothing.
**Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the
backlog when ready"), in branch `claude/securevibe-e2-fail-open`. A new rule that only ever raises findings changes
no requirement's status, so no ADR is proposed.
**Done the same day** (DESIGN, "A check that answers "yes" when it fails"): `ast.check-passes-on-error`, in
fourteen languages (C has nothing to find, and says why), with a new rule setting, `enclosingFunctionPatterns`, that
reads the name of the function around a match as words. Only ever a finding.
