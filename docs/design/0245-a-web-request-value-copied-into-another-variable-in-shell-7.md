# A web request value copied into another variable, in shell (7 October 2026)

In shell scripts, `ast.file-path-from-value` reports a command such as `cat` or `rm` given a path from a web request
variable (`QUERY_STRING`, `PATH_INFO`, `HTTP_…`), the way a CGI script receives what a visitor sent. It judged the
variable by its name, so the usual way such a script is written was missed:

```sh
file="${QUERY_STRING#name=}"
cat "/srv/files/$file"
```

The rule now uses `argumentNamesRead`, the switch added for the provider-email rule (#846). A variable counts when the
script sets it from a request variable, such as `"${QUERY_STRING#…}"` or `$(printf '%s' "$PATH_INFO" | …)`. Three
changes do that:
- **The shell pattern.** It still matches a request variable's own name, and now also a value that reads one, with
  its `$` (so a path that only contains the words `QUERY_STRING` is not read as one).
- **The engine reads Bash's `variable_assignment`.** That covers `x=…`, `local x=…`, and `declare x=…`.
- **In shell, the whole script is searched.** A shell variable is global unless declared `local`, so one set in
  another function is the same variable. Other languages keep searching only the function around the call.

The redirect rule needed nothing: in shell it already reports a `Location` header printed from any variable.

The switch is on for the whole rule, but it changes only shell. Swift, the one other language whose path rule has an
argument pattern, judges an argument label, and Swift names are not among the names followed.

Broken on purpose 6 ways, each caught by the witness written for it:
- Bash's assignment not read;
- shell searched by function;
- every language searched across the whole file (the provider-email rule's case of a name set in another function
  catches it);
- the value alternative removed;
- the value alternative without its `$`;
- the switch off.
