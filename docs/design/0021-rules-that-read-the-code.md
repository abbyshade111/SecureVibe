# Rules that read the code

Everything else in `sv-check` works on text. That is right for credentials, where the thing being looked
for *is* a string, and wrong for "is this SQL built by pasting a variable into it" — a regex either
misses the case split over two lines or fires on the word `execute` inside a comment. Both are in the
tests, because both are what a text rule gets wrong.

tree-sitter was taken as a dependency where a YAML crate was not, on the argument that decides these:
there is no honest hand-rolled alternative to a parser, it is actively maintained, and four grammars
build in about four seconds. Python, JavaScript, TypeScript and Go today; Ruby, PHP and Java are named as
unread rather than silently producing nothing.

Four rules so far: code built and executed at run time, a shell command assembled from a value, a
database query joined together from pieces, and data from outside deserialized with a reader that builds
objects. Each is a tree-sitter query per language in `data/ast-rules.json`, so teaching one about Ruby is
a data entry.

### Saying what a clean result looked for

A clean result used to say only what was read: "1 shell file". Beside the path rule, that reads as "the
shell scripts were checked for path traversal", when in shell the rule looks only at commands such as
`cat` or `rm` given a web request variable, which is right for a CGI script and says nothing about a path
built from any other variable. Found by the other session in review, 25 September 2026, and true of every
rule in some language.

So each rule says in plain words what it looks for (`looksFor`), and, per language, where it looks for
something narrower (`looksForIn`), and a clean result names both beside the files:

    a file opened, written, or deleted at a path built from a value rather than written out, in
    2 python files; only commands such as cat, rm, or cp given a path from a web request variable
    (QUERY_STRING, PATH_INFO, and similar); a path from any other variable is not looked at, in
    1 shell file

Every rule that reads shell has its shell wording, because commands and variables are a different shape
from calls and arguments, and a test holds that; a phrase for a language the rule has no query for is
refused at load. The phrases were written from the queries and their patterns, not from what the rule
is meant to catch.

### What a query cannot decide

Whether the argument is a literal. `eval("1 + 1")` cannot be made to run anything its author did not
write, and reporting it beside `eval(request.args["code"])` at the same seriousness is how a rule teaches
people to skip its findings. That judgment is Rust, where it is tested — the same split as the secrets
scanner, patterns as data and meaning as code.

It is subtler than it looks. A template string is a literal only when nothing is interpolated, and a
Python f-string is still a plain `string` node in its grammar — so `f"… WHERE id = {user_id}"` looked
like a constant, and the SQL rule reported nothing for the case it exists for. The check now asks whether
anything is substituted in, at any depth, whatever the grammar calls it. Breaking that fails four tests.

### A predicate that parses and does nothing

Every rule was first written with tree-sitter's own `(#match? @fn "^eval$")` predicates. **The Rust
binding parses them and does not apply them**, so every rule matched every call in the file — the
deserialization rule fired on `os.system`, the shell rule on `eval`. Nothing about the queries looked
wrong, and the only reason it surfaced is that the tests assert what must *not* be reported as well as
what must.

Name matching moved into Rust, per language, because the dangerous names differ — `eval`, `exec` and
`compile` in Python against `eval` and `Function` in JavaScript, which one shared pattern would get
wrong. And a query containing `#match?` is now **refused at load**, with a test that feeds one in and
expects the refusal, because a guard against a mistake nobody is currently making has no witness
otherwise.
