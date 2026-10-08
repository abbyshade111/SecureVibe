# Two blind spots found testing the prompt library, 4 October 2026

**Status:** open

Found by session securevibe-e10, each
reproduced against `sv` on `main`. **Each can be claimed on its own.**
1. **The rich-text check reads only locked packages.** `config.rich-text-without-sanitizer` (V1.3.1) takes its
   editors and sanitizers from the bill of materials, which holds nothing for an npm app with a `package.json` and
   no lockfile. A recipe app listing `quill` and no sanitizer was reported as "0 packages: none is a rich-text
   editor `sv` knows"; the same app with a `package-lock.json` was caught. AI-built apps often have no lockfile,
   because nothing could be installed where they were written. It credits nothing, so this is a missed finding,
   not a false pass. Read the declared dependencies too, or report the check not assessed when the bill of
   materials is incomplete. Witnesses: the app with and without the lockfile, and a declared sanitizer that keeps
   it quiet.
2. **`ast.shell-command` in Python misses `subprocess` with `shell=True`.** Its Python names are `system`,
   `popen`, `getoutput`, and `getstatusoutput`, so `subprocess.run(f'notes-export "{title}" out.pdf', shell=True)`
   is reported by nothing unless Bandit or Semgrep runs (`--tools`), while `os.system` with the same text is
   caught. The same holds for `call`, `check_call`, `check_output`, and `Popen` with `shell=True`. Witnesses: each
   of those with a built string and `shell=True` caught; each with a list and no shell, and with `shell=True` and
   a fixed string, quiet.
**Items 1 and 2 claimed on 4 October 2026 by session securevibe-e10**, at the owner's word ("keep going"), in
branch `claude/blind-spots`.
**Both done the same day** (DESIGN, "Two blind spots: a manifest with no lockfile, and a shell the call asked
for"). 1: the check reads the names a manifest declares where the bill of materials could read nothing, and says
not assessed, never "none is an editor", when it cannot read those either. 2: a new findings-only rule,
`ast.shell-command-shell-true`, for Python's `subprocess` with `shell=True`, Node's `spawn` and `execFile` with
`shell: true`, and Dart's `Process` with `runInShell: true`. Seven guards broken in turn, each caught; the recipe
app and the Python file that showed the gaps are now caught, and their safe forms are not.
