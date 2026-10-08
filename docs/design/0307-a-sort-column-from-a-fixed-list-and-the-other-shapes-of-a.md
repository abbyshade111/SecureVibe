# A sort column from a fixed list, and the other shapes of a safe query (8 October 2026)


Backlog 215, from the Haiku 5.5 trial (`docs/prompts/library-trial/haiku55.md`): `ast.sql-built-by-hand` (V1.2.4,
high) fired in all ten Haiku 5.5 apps, and in the four read by hand every query was safe. Read in `Fixed`, two causes:
a name was fixed text only when the whole file bound it once, and a Flask app binds `sort`, `clauses` and `direction`
in several routes; and four shapes of fixed text were not read as fixed at all.

**A Python name judged in its own function** (`Fixed::local`). When the function a name is used in binds it, the
function's bindings decide, whatever other functions do with the same name: one binding, not a parameter, to fixed
text. Anything that may bind it unseen makes it not fixed: `global`, `nonlocal`, `with ... as`, `except ... as`, an
import. A list, set or dictionary can change after it is bound, so one binding says nothing on its own: a list is
judged by everything done to it (below), the others are not fixed. A function that does not bind the name leaves the
file's judgment (A1, "Names that stand for fixed text") as it was.

**A guard on a fixed list** (`Fixed::guarded`): a statement of the function's own body, before the use, `if name not
in FIXED:` with no `elif` or `else`, whose block's last statement is a `return`, a `raise`, or a call to `abort`, and
nothing after it binds the name again. `FIXED` is a list, tuple or set of fixed text, a name for one, or a table whose
keys are all fixed (`keys_are_fixed`).

**A choice between fixed values:** `a if c else b`, both values fixed.

**Fixed pieces joined:** `SEP.join(pieces)`, the separator fixed and the pieces a list or tuple of fixed text written
in place, or a list the function binds once to fixed items and otherwise only grows with `append` or `extend` of fixed
items, joins, or hands to the call being judged (`Fixed::fixed_list`). Handed to any other function, indexed, sorted:
not fixed. A module's list is never trusted here, since any function may append to it.

**An f-string whose every piece is fixed,** with no format spec holding a value of its own.

Python only: the other languages' rules are as they were. The shell, code-execution, redirect and file-path rules use
the same judgment, so they too stay quiet on these shapes (a command list grown only with fixed text, for one).

**What it changes in a report.** `ast.sql-built-by-hand` credits when it finds nothing and every language was read, so
an app written in these shapes now has V1.2.4 *checked* where it had "needs attention"; rules that use this judgment
and credit the same way gain the same. A credit is only as good as the judgment behind it, so every guard has a
witness that it still reports the unsafe form.

Witnesses in `the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one`: the trial's four shapes quiet, each beside
a second function that rebinds the same names from the request; reported, each guard undone one way at a time (no
guard, a guard that does not leave, a list the caller gives, the name bound again after the guard, a choice with a
request value, a request value appended, the list handed to another function, a separator not fixed, `global`, a
module's list joined, an f-string half guarded, a command list grown with a request value). Thirteen breaks, one per
guard, each caught; two were caught by nothing at first (a list judged as a name bound once, an f-string with one
fixed piece), and each got the witness that catches it. The first version also trusted a list bound once even when a
request value was appended to it, and a module's list joined; both witnesses caught it before it was committed as done.
