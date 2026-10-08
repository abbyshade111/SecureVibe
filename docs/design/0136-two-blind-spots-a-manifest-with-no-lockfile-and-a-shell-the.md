# Two blind spots: a manifest with no lockfile, and a shell the call asked for (4 October 2026)

Both were found testing the prompt library: each shortcut was put back into an app built without it, and two were
reported by nothing.

**A rich-text editor declared, with no lockfile.** `config.rich-text-without-sanitizer` (V1.3.1) took its editors
and sanitizers from the bill of materials, which lists an npm app's packages only from its lockfile. An app an AI
tool wrote where nothing could be installed has a `package.json` and no lockfile, so a recipe app listing `quill`
and no sanitizer was reported as "0 packages: none is a rich-text editor `sv` knows", while the same app with a
lockfile was caught. The check needs which packages an app uses, not which versions, and the manifest says that:
where the bill of materials could read nothing for an ecosystem, the check now reads the names the manifest
declares, through the readers `manifest_lock.rs` already has for nine manifests (`declared_names`). Where it cannot
read those either, it says the check was not assessed and why, rather than "none is an editor", which it had been
saying for any app whose packages it could not read. It still credits nothing either way.

**A command handed to a shell the call asked for.** `ast.shell-command` knows the calls that always use a shell
(`os.system`, `exec` in Node, `system` in Ruby). Python's `subprocess` uses one only when told to, with
`shell=True`, and so does Node's `spawn` and `execFile` with `shell: true` and Dart's `Process` with
`runInShell: true`: `subprocess.run(f'notes-export "{title}" out.pdf', shell=True)` was reported by nothing unless
Bandit or Semgrep ran. A new rule, `ast.shell-command-shell-true`, reports those calls when what reaches the shell
was built: in Python and Node the command, unless it is a fixed string; in Node and Dart a list of arguments too,
since with the shell option they are joined into one line for it. A fixed Node list (`['-la']`) is reported as well,
because the grammar's arrays are not counted as fixed; that is a false alarm the rule accepts rather than missing a
list with a value in it.

A query cannot tell `shell=True` from `check=True` (the text predicates that would are parsed by the Rust binding
and not applied), so the rule engine gains `keywordPatterns`: a pattern the `@kw` capture, the keyword's name, must
match. The rule is findings-only: it reads Python, JavaScript, TypeScript, and Dart, and says for the other eleven
languages why there is nothing to find (each either always uses a shell, which is `ast.shell-command`'s, or has no
shell option at all). A clean run credits nothing, so no app's credit for V1.2.5 changed.

Seven guards broken in turn, each caught: the manifest names not read, "none is an editor" said with a manifest
unread, a sanitizer assumed where a manifest was unread, the keyword filter, the function names, a fixed command
counted as built, and Node without its keyword pattern. The recipe app with its sanitizer removed, and a Python file
with `shell=True`, are now caught; the app as built, and the list form with no shell, are not.
