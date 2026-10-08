# One setting that switches off certificate checking for the whole app (V12.3.2, V12.3.4, 7 October 2026)

V12.3.2 asks that the app check the certificate of every server it connects to; V12.3.4, that services inside one
system trust only their own certificates. The code-reading rules and the outside tools find the line that turns
checking off for one call (`requests.get(url, verify=False)`, Go's `InsecureSkipVerify: true`). Nothing found the
settings that turn it off for every call at once, from outside the code, which an AI coding tool reaches for when a
certificate error stops it, and which then outlast the error. `docs/PARTIAL-CHECKS.md` proposed reading for them.

**`config.certificate-checks-off`** (`crates/sv-check/src/cert_checks.rs`; high, high confidence, only ever a
finding, citing V12.3.2 and V12.3.4) reads the app's files for:

- `NODE_TLS_REJECT_UNAUTHORIZED` set to `0` (Node.js, and Bun, which honors it, then accept any certificate) and
  `PYTHONHTTPSVERIFY` set to `0` (Python's standard library then connects unchecked by default, PEP 476), however
  the file writes it: `NAME=0`, Dockerfile's `ENV NAME 0`, `NAME: "0"`, `process.env.NAME = '0'`,
  `os.environ["NAME"] = "0"`, and Kubernetes' `- name: NAME` with `value: "0"` on the next line;
- Python's `ssl._create_default_https_context = ssl._create_unverified_context` and Node's
  `https.globalAgent.options.rejectUnauthorized = false`, the same switch made from inside the code;
- Deno's `--unsafely-ignore-certificate-errors` with no list of addresses (with one, it is limited to them).

It reads every file of the app's own: code, Dockerfiles, compose files, Kubernetes manifests, `.env` files,
workflows, scripts, `package.json`, and Procfiles; a file over 2 MB in pieces, since a setting is a line or two. It
leaves out commented-out lines, prose (Markdown and plain text, where a setting is described rather than made), and
the files the production start-command check leaves out: those named or kept for development or tests
(`Dockerfile.dev`, `.env.development`, `tests/`) and the folders that configure a developer's own tools
(`.vscode/`, `.claude/`). The fix it gives is to trust one certificate for one server (`NODE_EXTRA_CA_CERTS`, a
`verify=` path) rather than none for every server.

**What it does not do.** A clean reading credits nothing: the same setting can be made on the server the app runs
on, which no file shows. `CURL_CA_BUNDLE=""`, in the proposal's list, is not looked for, since whether today's
`requests` checks nothing for an empty value was not confirmed, and a citation is a claim. The proposal's supporting
list of internal certificates the app trusts is not built.

**Break and watch.** Three tests: fourteen files, each writing a switch-off a different way, each found on its own
line; eleven that leave checking on, describe it, comment it out, or keep it for development, none found and the
clean reading crediting nothing; and a file over 2 MB with the setting on its last line, found on that line.
**Eleven guards broken in turn, each caught:**
- the setting not read at all (ten of the fourteen found cases, and the large file);
- Dockerfile's space form (`ENV NAME 0`) not read;
- any digit taken for `0` (`=1` reported);
- the name-and-value pair not read (the Kubernetes case);
- a name kept past its own value line (`- name: PORT` then `value: "0"` reported);
- comments read;
- prose read;
- development and test files read;
- developer tools' folders read;
- Deno's flag with a list of addresses counted;
- a file over 2 MB not read.

The developer-tools break was missed at first: its case was `.vscode/launch.json`, and the listing never hands
`.vscode` to any check, so the case guarded nothing. It is now `.claude/settings.json`, with an assertion that the
listing reaches it, and the break is caught.
