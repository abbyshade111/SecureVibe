# `sv`'s credential rule reads a form's anti-forgery token placeholder as a credential

**Status:** done, as its markers read on 8 October 2026

Found on 7 October 2026 by
session paper-facts, in the start-of-build test: one Haiku app drew eight `secrets.credential-assignment` findings
(high) at lines like `<input type=hidden name=csrf_token value="{html.escape(csrf_token)}">`: a template filling in
the token the app made for that page, the protection V3.5.1 asks for. A value that is a `{...}` or `{{...}}`
placeholder, or a call (`html.escape(...)`), is not a written-in secret. A fixture of exactly this line, and the
rule kept quiet on it, would hold the fix.
**Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the
backlog when ready"), in branch `claude/securevibe-e2-csrf-placeholder`: a value that is wholly one `{...}` template
expression is a placeholder. Read on `main` just before this claim: no other session had claimed it.
**Done the same day** (DESIGN, "A template filling in its own token is not a credential"): a value that is wholly
one `{...}` holding names, dots, calls, and indexes is a placeholder, as `{name}` already was. A quote inside the
braces, text outside them, or a first character that is not a letter keeps it judged. The line from the report is a
fixture, with three relatives; four guards broken in turn, each caught.
