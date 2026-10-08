# Fourteen languages, and why the fifteenth silences everything

The rules that read code have grammars for Python, JavaScript, TypeScript, Go, Ruby, PHP, Java, C#,
Kotlin, Rust, C, C++, Dart and Swift. Each one is worth more than one more entry suggests, because of how the fail-closed
rule works: **no rule may speak while a language present in the app goes unparsed.** One Ruby file used
to silence every rule for the whole app — correct behavior on an app `sv` could not read, and a lot of
silence. Every language added is one fewer kind of app that gets nothing. Objective-C is the fifteenth
now, recognized by `.m`/`.mm` and deliberately left without a grammar: the test for "a language present
and unread silences every rule" needs a real example, and the list it draws from is meant to keep
shrinking, one language at a time, rather than being emptied by construction.

### A page of markup is not a hole in the coverage

`html` covers `.html`, `.vue` and `.svelte`, and almost every web application has at least one. Counting
every page as unread therefore silenced every rule for nearly every real app — a great deal of silence
bought by a file that in most cases hides nothing at all. So the script is taken out of the page and
read as what it is. `<script>` elements go to the JavaScript grammar — or TypeScript, when the page
says `lang="ts"` — and so do `on…=` handler attributes and `javascript:` URLs, whose values are
statements that parse on their own once their HTML entities and percent escapes are put back. A
`<script src="app.js">` with nothing between its tags holds no code at all: the file it names is
parsed like any other.

**Tags are read the way a browser reads them**, because a page is written for a browser and anything
read differently is a place for code to hide. The first version took only quoted values and named
the rest as left behind, on the view that where an unquoted value ends was a question with two
answers. It is not: the HTML standard's tokenizer ends it at whitespace or at `>`, and every browser
follows it. Checking that first version against pages a browser runs found two it counted as read
with nothing taken out of them, which is a false clean: `<button onclick=eval(location.hash)>` (an
unquoted handler), and `<img/onerror="…">` (a `/` between attributes, which a browser treats as a
space). A third, `href="java&#9;script:…"`, was meant to be named and was not, because the entity
became a tab only after the check for a disguised scheme had looked.

So `html_fragments` now walks the start tags the way the tokenizer does. A quoted value ends at its
quote, an unquoted one at whitespace or `>`, and `/` separates attributes. A comment holds no tags,
and neither do the bodies of `<script>`, `<style>`, `<textarea>`, `<title>`, and `<xmp>`. Each value
has its character references put back, both numeric (`&#9;`, `&#x6A;`, with or without the `;`) and
named ones for every ASCII character (`&Tab;`, `&colon;`). Then it is checked for a URL the way the
URL standard does it: strip control characters and spaces from both ends, remove every tab and
newline, and only then read the scheme. `java<tab>script:` is therefore read as the program it is.

Some things are still named rather than read, each for its own reason:

- **A named reference this does not know, inside code.** Most such names are ones a browser leaves
  alone too, but a few hundred stand for letters JavaScript accepts in a name.
- **A value that becomes the scheme only once some other control character is removed**
  (`java\x01script:`). By the URL standard a browser does not run it. The cost of being wrong about
  that reading is a false clean, though, so the page stays unread.
- **A quote or a tag never closed.**
- **A `javascript:` anywhere this did not read**: text, a comment, or a template language's own
  syntax. Every occurrence of the scheme is still counted against the attribute values and script
  bodies that were read.

The last check is the safety net under the rest. Before the tokenizer it caught a second way of
writing a URL; now it catches a place the tokenizer does not model.

A finding in a page names the line **in the page**. The fragment's offset is added back before the
finding is written, because a reader sent to line 3 of something they cannot see is worse off than one
given nothing.

**Anything taken out has to parse.** Tree-sitter always returns a tree, so a fragment of something
that is not JavaScript comes back as a wreck that matches no rule and reports nothing — which reads
exactly like a fragment that was clean. A page whose fragments do not parse is left unread. That catches
less than it looks like it does, and the reason is worth knowing: the JavaScript grammar includes JSX,
so a Vue or React template parses cleanly and reaches the rules as markup. Handlebars, ERB and Jinja do
not. Both halves of that were measured, not assumed.

One function decides both what a page holds and what comes out of it. When "does this page hold code"
and "what code does this page hold" are answered by two pieces of code they drift, and the direction
they drift in is a page declared read whose code nobody extracted. So `html_fragments` returns the
fragments *and* whatever it could not take — an unclosed `<script`, a `javascript:` URL — and while
anything was left behind the page is still unread and every rule stays silent about the whole app. A
page that cannot be opened at all counts as left behind too.

The terminal's wording followed the behavior twice: it said *there is no grammar for html* when every
page was unread, then *a page with a script written into it* when only those were, and now says what is
actually true — that something in the page could not be taken out of it.

### A language that was read is not a language every rule looked in

A rule with no query for a language says nothing about it. That used to be the whole of it, and it left
a hole: in an app of Python and Rust, the shell-command rule read the Python, found nothing, and claimed
V1.2.5 for the app, with the Rust beside it never looked at by that rule. The parser having read a file
is not the same as each rule having looked in it.

So every rule now accounts for every language `sv` reads, one of two ways: a query, or an entry in
`nothingToFind` saying why the language has nothing for that rule to find. Go has no `eval`; Dart's
decoders give back maps and lists; backticks in Swift quote a name. Each entry carries its reason, and a
language cannot have both. A rule that met a language with neither claims nothing for the app, and the
report says which rule and which language (`AstScan::untaught`), rather than letting the line go
missing. The claim itself still names only the languages the rule has a query for, so an entry in
`nothingToFind` can let a claim through but never widens one.

Adding the rule turned up the gaps it was built to show, and most were filled in the same change:
Kotlin and C# `eval`, JavaScript's `unserialize`, PHP's backticks, Go's `exec.Command("sh", "-c", …)`,
file paths in Kotlin, Rust and C, weak hashes in Rust and C, weak ciphers in C, and redirects in Kotlin
and Rust. The last three followed: shell commands in Rust, weak ciphers in Rust, and redirects in C.
Every rule is now taught every language `sv` reads, and a test pins it, so a grammar added without its
queries shows up there before it shows up as a gap in someone's report. The tests of the mechanism
itself use a small rule file written for them, since the real rules no longer produce the case.

What those three look for, and what they miss:

- **Rust's shell command is a method chain.** `Command::new("sh").arg("-c").arg(cmd)` is three calls,
  each the receiver of the next, so the query follows the chain back two links to the `new` whose
  argument is a shell. `.args(["-c", cmd])` is the same thing written as an array, which is literal when
  every element is. A `Command` built in one statement and given its arguments in another is not
  followed, and neither is a shell named by a variable. `Command::new(exe)` with a value is reported
  whatever the arguments.
- **Rust's weak ciphers are types.** RustCrypto names them (`TdesEde3::new_from_slice`,
  `ecb::Encryptor::<Aes128>::new`) and the `openssl` crate has a function per cipher
  (`Cipher::des_ede3_cbc()`, `Cipher::aes_128_ecb()`). Both are a call on a path, and the path says
  which. A cipher type imported under another name is not seen.
- **C's redirect is a header printed by hand.** A CGI program writes `Location: …` to standard output,
  so the query is `printf`, `fprintf`, `sprintf` or `dprintf` whose format string begins with
  `Location:` and has a value after it. A header built with `strcat` first, or written with `puts`, is
  not seen.

### Dart and Swift

Both used to be read by nothing, which silenced every code rule for any app with a Flutter front end or
an iOS client, back end included. Now each of the nine rules has a query for both or a reason there is
nothing to find. What they needed that the others did not:

- **A shell command is a list.** Neither language has a `system` in common use; Dart writes
  `Process.run('sh', ['-c', cmd])` and Swift `task.arguments = ["-c", cmd]`. A list literal is literal
  when every element in it is, so `['-c', 'ls -la']` is left alone. Dart's `<String>[…]` puts a type in
  the list, which is not an element and is skipped. The Swift query takes the list when its first element
  is `"-c"`, so `["log", name]`, an argument rather than a command, is not reported.
- **Swift's arguments are labeled, and the label matters.** GRDB's `db.execute(literal: "… \(n)")`
  binds what it interpolates, while `db.execute(sql: q)` runs `q` as written. So the Swift queries capture
  the whole argument, label included; the literal check looks at the value inside it, and a pattern can
  read the label: `literal:` is safe, and a file-path call is reported only with a path label
  (`atPath:`, `contentsOfFile:`), so `String(describing: n)` is not.
- **Swift interpolation is `\(x)`**, an `interpolated_expression` node, including inside a raw string
  written `#"…\#(x)"#`. Dart's `$x` and `${x}` are `template_substitution`, which JavaScript already had.
- **Concatenation is an `additive_expression`** in both, and `'a' + 'b'` is as fixed as its parts.

The code rules reading Dart and Swift does not mean the technology scan does. That scan reads no
`pubspec.yaml` or `Package.swift` and has no patterns for either language, so a GraphQL server in Dart
would go unseen and be called absent. Their files still count as not looked in there
(`NO_TECHNOLOGY_READER`), and no technology is called absent on their account.

The queries were written against dumped parse trees rather than against what the grammars plausibly
produce, which is two minutes' work and settled three things guessing would have got wrong. Ruby uses
one `call` node whether or not there is a receiver, so one pattern covers both. PHP splits them into
`function_call_expression` and `member_call_expression` and wraps each argument in an `argument` node.
Java matches Go's shape exactly.

Three things these languages needed that the others did not:

- **Ruby's backticks are a `subshell` node with no method name.** The name filter drops any match that
  cannot offer a name, which is what keeps a rule from firing on every call in a file — so rather than
  teach that filter to let unnamed matches through, the backtick form is its own rule. `ls` is as fixed
  as any string and `ls #{dir}` is not, and the literal check tells them apart once `subshell` is on the
  list of things that can be literal.
- **PHP interpolates a bare `$name` inside a double-quoted string**, with no wrapper node to recognize.
  A check that only knows `${…}` and `#{…}` reads `"select … $name"` as a written-out constant, which
  is the exact case the SQL rule exists for.

- **Kotlin's grammar gives an interpolated string no node at all.** `"select $n"` is three plain
  `string_content` children with the bare `$` standing alone as one of them, and that last part is the
  whole discriminator — measured, because the obvious alternatives are both wrong. Counting children
  reports `"cost \$5"`, where an escaped dollar leaves two of them either side of an `escape_sequence`.
  Without this, the most natural way to write a Kotlin query reads as a written-out constant.

Ruby's `load` is too common a method name to report on its own, so the receiver has to be one of the
classes that really deserializes. Breaking that check is what showed the test for it was passing for the
wrong reason: `config.load(path)` was being excluded by the query's own shape, because a lower-case
receiver is an `identifier` and the query asks for a `constant`. The receiver pattern could have been
deleted with every test still green. `Settings.load(path)` is the case that actually exercises it.

### Shell scripts

AI coding tools put a deploy or setup script in most repositories, and until 25 September 2026 `sv`
did not count `.sh` at all: not read, and not listed as unread either. Now `.sh` and `.bash` are read with
the Bash grammar, as the language `shell`, and every rule is taught it or says why there is nothing to
find. A shell script is not an application, so most of what the rules look for looks different in one:

- **Code and commands.** `eval "$x"` is the code-execution rule's and `sh -c "… $x"` is the
  shell-command rule's. `eval "$(ssh-agent -s)"` is the idiom every setup guide prints, running the
  output of a fixed program, and is named as safe. Single quotes expand nothing, so `sh -c '…'` is a
  literal whatever it holds, and a double-quoted string is literal unless something is expanded in it.
- **A download piped into a shell** is a rule of its own, `ast.download-piped-to-shell`, citing V15.2.4
  (third-party components included from the expected repository). `curl … | sh`, `wget -qO- … | sudo
  bash`, and `bash <(curl …)` run whatever the address serves, unchecked. `curl … | sudo tee` writes a
  file and is not reported, and neither is the download-check-run form the rule's fix describes.
  An interpreter runs what it is sent only when it takes its program from standard input, so the rule
  reports `| sh`, `| sh -s stable`, `| python3 -`, and `| sudo -E bash`, and not `| python3 -c '…'`,
  `| perl -ne '…'`, `| python3 -m json.tool`, or `| bash count.sh`, which read the download as data
  (found by cato-pipeline, 28 September 2026). The program given with `-c` is the author's own text, the
  same judgment `literal_argument_is_safe` makes for `eval("1 + 1")`: `python3 -c
  "exec(sys.stdin.read())"` runs the download on purpose, and a rule cannot tell that from the text. The
  command must begin with the interpreter, after any variable assignments and `sudo` or `doas` with its
  options, so `| grep python` is not an interpreter.
  `sh -c "$(curl …)"` is found by the shell-command rule instead. Every other language has no pipe
  syntax, and says so; a literal `curl … | sh` written inside a Python string and handed to a shell is
  found by neither rule, because the shell-command rule only reports commands built from a value.
- **SQL, hashes, and ciphers** are the command-line tools: `psql -c`, `mysql -e`, `sqlite3 app.db`,
  `md5sum`, `openssl dgst -sha1`, `openssl enc -des3`.
- **Paths and redirects only for CGI.** In a deploy script `cat "$FILE"` is the whole point, and a
  path-from-a-value rule would report every line. What V5.3.2 and V3.7.2 are about in shell is a CGI
  script, so those two look only at the request variables the web server sets (`QUERY_STRING`,
  `PATH_INFO`, `REQUEST_URI`, `HTTP_*`), written into a path or a `Location:` header. A request value
  copied into another variable first is not followed.

Two things stay out on purpose. Unquoted variables are the commonest shell bug, but they are word
splitting rather than an ASVS requirement, and ShellCheck already finds them; it cannot write SARIF, so
it cannot be an adapter under the rule that adapters speak SARIF only. And the technology scan does not
treat shell as a language it failed to look in, as it does Dart and Swift: before the grammar a `.sh`
file was invisible to it, and listing shell would take every "this app does not use X" answer away from
any app with a deploy script. The price is that a technology written only in shell, a CGI app in Bash
using XML, say, is called absent.

A shell file whose parse holds an error silences every rule's claim for the app, the same as any other
language. The Bash grammar reads Bash; a `.sh` file written in zsh's own syntax may not parse, and the
report then names it.

### C++

C++ was the standing example of a recognized-but-unparsed language until 27 September 2026; the fixture
that needed one moved to Objective-C, above. Given the choice, C++ was assessed against what AI coding
tools actually produce and judged to matter least of the candidates for a web application, behind Dart,
Swift, and shell, which is why it came last.

tree-sitter-cpp turned out to need nothing new. Dumping the parse tree for `fopen`, `system`, `MD5`, and
a `printf`-style `Location:` header showed the same `call_expression`, `argument_list`, `identifier`, and
`string_literal` nodes tree-sitter-c already produces — C++'s grammar is C's plus more, not a different
one for the part these rules look at — so every rule reuses C's query and function names outright:
`fopen`/`unlink`/`remove` for a path, `MD5`/`EVP_sha1` for a hash, `EVP_aes_128_ecb` for a cipher,
`printf`/`fprintf` for a header, and the same four reasons (no `eval`, no object deserializer, no
backticks, no pipe syntax) for the rules that have nothing to find here. The 998-line data change is
almost entirely that: one more key per rule, copied from `"c"`.

What copying does not reach, stated rather than found by surprise later: a call written with a scope —
`std::system(cmd)`, `::remove(path)`, `Logger::log(msg)` — parses as a `qualified_identifier`, not the
plain `identifier` these queries match, so it is not seen. Neither is `std::cout << "Location: " << u`,
which is a chain of `binary_expression` nodes and never a call at all — the open-redirect rule only
reaches the printf-style form a C program would use. Both are real C++ idioms and both are silent gaps,
the same kind the file-path rule already has in every language ("cannot tell a request value from an
internal one"): written down so a clean scan is read for what it covers, not for what a reader might
assume "C++ support" means.
