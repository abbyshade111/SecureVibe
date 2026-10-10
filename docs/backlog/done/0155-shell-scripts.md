# Shell scripts

**Status:** done, as its markers read on 8 October 2026

Done on 25 September 2026 by session securevibe-e8. `.sh` and `.bash` are
read as `shell`, every rule is taught it or says why not, and a new rule,
`ast.download-piped-to-shell` (V15.2.4), finds `curl … | sh` and its relatives. See DESIGN, "Shell
scripts". Left over: unquoted variables are ShellCheck's, which cannot write SARIF; a request value
copied into another variable before it reaches a path or a redirect is not followed.
**A request value copied into another variable claimed on 7 October 2026 by session securevibe-e2**, at the owner's
word ("please continue to work off the backlog when ready"), in branch `claude/securevibe-e2-shell-copied`: the
path rule follows a variable the script set from `QUERY_STRING` and the like, with the `argumentNamesRead` switch
#846 added. The redirect rule needs nothing: in shell it already reports a `Location` header printed from any
variable. Read on `main` just before this claim: no other session had claimed it.
**Done the same day** (DESIGN, "A web request value copied into another variable, in shell"). The path rule follows a
variable the script sets from a request variable, anywhere in the script, since shell variables are global.
