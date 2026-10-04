# sv (SecureVibe) — what the checks found

Produced by `sv` 0.1.0 (commit 84dcbd47db74).

## What was not examined

- **the running app** — `sv report` does not start the app unless you pass --run. Without it, nothing here has asked the app anything — what it sends to a browser, what it says when something goes wrong, which sites it accepts.
- **what `semgrep` would have found** — Semgrep is not installed on this computer, so nothing here has checked the code in this app the way it would have. Install it with `pip install semgrep` and run this again. Opengrep, which can run in its place, is not installed either.
- **what `codeql-javascript` would have found** — CodeQL (JavaScript and TypeScript) is not installed on this computer, so nothing here has checked the javascript and typescript in this app the way it would have. Install it with `download the CodeQL bundle from https://github.com/github/codeql-action/releases, unpack it, and put its `codeql` on your PATH` and run this again.
- **what the folders named as not the app use** — securevibe.toml says these folders are not the app (`[repository] not-the-app`): none of them is in this app. Their code is still checked, and its findings count, listed with test and sample code. What is in them cannot change which requirements apply: a library an example uses is not one the app uses. If the app's own code is in one of them, take it off the list.
- **the check `config.secrets-file-committed`** — This folder is not a git repository, so `sv` cannot say whether a secrets file was ever committed. Putting the app in git (version control, which keeps every saved version) makes this check run, and is worth doing anyway. Ask your AI coding tool to do it, and to add a .gitignore that leaves out .env and other secret files before the first commit, so that commit does not save them. If the app is already kept in version control somewhere else, that copy's history is still unchecked.
- **22 requirements that are design review, not scanning** — these ask how the system was designed and how it is run — whether trust zones are enforced, whether an incident response plan is rehearsed, whether data has named owners. No check here reaches them and none ever will, so they are counted as applicable and unverified, and a person has to answer them.
- **known vulnerabilities in the packages this app ships** — `sv report` compares against known vulnerabilities only when you pass --advisories DIR. `sv` does not fetch anything, because the list of packages an app depends on is yours: download an OSV export for this app's ecosystems, unpack it, and pass its folder with --advisories.
- **4 requirements that ask for a written decision** — No tool can answer these: they ask what your rules are, who may do what, and how long things are kept. Run `sv notes` to write security-notes.md, answer the questions in it, and they become documented. Your AI coding tool can ask you them: `sv questions` prints them for its chat.
- **4 questions about how this app is built** — No tool can settle these — whether input is validated on the server, whether the app's own services authenticate to each other. Answer them in the [design] section of securevibe.toml: V2.2.2, V7.2.1, V8.3.1, V15.3.1. Your AI coding tool can ask you them: `sv questions` prints them for its chat.

## 75 things to fix

Worst first.

### [high] A shell command is built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 444

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `4344aed478151c23`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 622

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `33c42c55e315c356`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 646

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `aa637e954c77c7dd`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-run/src/docker.rs` line 83

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `c08705a14924f538`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-run/src/docker.rs` line 135

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `c08705a14924f538`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-run/src/docker.rs` line 605

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `3c201443967bf8e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-run/src/docker.rs` line 1342

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `c08705a14924f538`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in/fake_app.rs` line 2072

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `e464f02c7262811d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in/fake_app.rs` line 2076

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `2c95479224c352a3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in/fake_app.rs` line 2080

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `0ed1c5962efba75f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in/fake_app.rs` line 2086

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `643179156e5d706e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in/signin.rs` line 219

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `1f9bb986ae9b3cf2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in/signin.rs` line 226

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `71b7925949a447e6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in/signin.rs` line 373

*How sure: likely. Rules like this one are usually right, not always.*

*Fingerprint: `645bcc25cccd218e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 218

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `42c20b9c0560f2bc`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 583

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `fafd4c919f943d44`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 614

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `a7b8319ac065f384`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 636

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `a7b8319ac065f384`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 663

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `a7b8319ac065f384`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 675

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `48d036a0e3297d0a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 685

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `8d288f9654b9004b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 686

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `fafd4c919f943d44`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 737

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `ce0bd74e89a1abd1`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 790

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `ce0bd74e89a1abd1`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1389

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `ac7040ba2b0a5645`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1398

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `766cc246ccf60e36`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1440

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `7ba50a8a7768c51a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1455

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `b82df7e1ce875a5b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/advisories.rs` line 144

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `8edcb4e2354d349f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 724

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `0bd59a0f469a8892`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/coding_rules.rs` line 74

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `a4a75f49a5c1c611`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 234

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `5f0693c982067c8b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/design.rs` line 89

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `debbdfa9cc8e0ca7`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/finding.rs` line 152

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `7facc820fd9ea327`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/human.rs` line 48

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `76475cd104f2cb24`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 55

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `93eb9a2f3c4a56bb`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/notes.rs` line 182

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `b40eff15fa69b7eb`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/prompts.rs` line 85

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `6a55eb343de8811f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/review.rs` line 60

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `af73d98013a7ef70`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 239

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `e1f10acc2551c73f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 284

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `c204086ba30aaddc`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 86

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `86a10b3ed11ec7ed`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 426

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `58f0697586b13abb`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 685

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `910474f613b7cb64`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1019

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `6ba74f19c9e6c203`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1028

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `22ba84d07ffe5709`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1157

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `dabda536362466df`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1177

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `89f351bdbc15e3dd`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 2293

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `c5d494457c842b75`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 2306

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `e3b07e7df08da862`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 2311

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `5529e9719a9fae97`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 2348

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `a1f0b3e618c6ee56`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 2428

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `1d7499a693946549`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 3346

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `36b3cbf9561c6309`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 4392

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `ec62cbe9bab60188`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 618

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `4492c661c148acea`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/applicability.rs` line 80

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `d835e6d8b557b993`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/applicability.rs` line 91

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `ac4c1643734c0c26`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/load.rs` line 133

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `373bb3ee837f5a61`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/load.rs` line 168

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `373bb3ee837f5a61`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/load.rs` line 211

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `373bb3ee837f5a61`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-manifest/src/lib.rs` line 1147

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `c544dd988fc892bc`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/src/threats.rs` line 203

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `1112f61e44ed5479`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/deps.rs` line 29

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `5a35208f7844df9c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/ecosystems.rs` line 193

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `06acd518c2757c51`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/ecosystems.rs` line 375

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `7934e889a7ecf8fe`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 112

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `814b70db83355f87`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 137

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `8e72ba86b849f18a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 218

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `70feee27d808ce17`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 266

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `df65fae140356349`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 443

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `14944f8290ca3aa2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 510

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `6a76387b8c66e27b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 574

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `cd696dd63afa2afe`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/lib.rs` line 96

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `2e32368d672bcaf0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/lib.rs` line 318

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*Fingerprint: `a80b408ef0b9f2a2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

## 404 in test or sample code

Listed apart because they are in code that tests the app or shows how to use it, not in the app itself: a folder or file named for tests, fixtures, or examples, Rust code built only for its tests, or a folder securevibe.toml says is not the app. They still count toward the requirements they are about. Test code can hold a real key, and sample code gets copied, so read each one before deciding it does not matter.

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 3601

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0dd3a0b5d566cde0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 3712

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8b50b2d848e4c5fb`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 3716

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0dd3a0b5d566cde0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 4141

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0dd3a0b5d566cde0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 4328

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0dd3a0b5d566cde0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 4913

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0dd3a0b5d566cde0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 5187

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0dd3a0b5d566cde0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 5272

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0dd3a0b5d566cde0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/browser.rs` line 991

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a243e349ce3d361a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`API_KEY`)

**Where:** `crates/sv-check/src/secrets.rs` line 612

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `597d4cf8108cb058`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`API_KEY` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/secrets.rs` line 641

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `5af80b9f018d18de`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/secrets.rs` line 653

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3c7b09de7478a083`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`secret`)

**Where:** `crates/sv-cli/src/mcp.rs` line 3335

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `08d4f004d7fee683`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

`secret` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1275

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b82df7e1ce875a5b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1333

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a299b1beda1b4a60`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1336

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `51e37f5b34f00ce8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1344

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `766cc246ccf60e36`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1359

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b82df7e1ce875a5b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1465

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b82df7e1ce875a5b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 1493

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b82df7e1ce875a5b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1460

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0abdf2bc4746c803`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1461

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `5e2971e7d7583efd`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1463

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c69aec300d303036`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1478

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a9d3c661e0ec550e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1480

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `cbe1ef715d876c19`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 515

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 525

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 530

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `cb47e9ebc734409f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 538

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 544

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 590

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `545ba903520d4b9d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 591

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3bc5bbfc14803d7b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 620

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3aefa7ada6b0038c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 629

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `77146cf18a3d0324`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 639

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `87f33d94a4c3053e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 654

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 663

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `72da0f02d3035092`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 664

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `66d4b6b9bb3ddd48`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 674

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 682

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6a7fb3bb94ed9146`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 703

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 713

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d94ab8615c2f1749`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 714

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6a7fb3bb94ed9146`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 733

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 739

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `edd04bbf4aae04ef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 747

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `4910a6af170d1983`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 756

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 763

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e33aeca0285f189b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 772

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 778

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8ec398188fdc5b71`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 787

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 795

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8ec398188fdc5b71`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 796

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 807

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 816

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 829

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 837

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 862

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 889

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 905

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 911

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 928

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 935

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 946

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 954

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 964

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 970

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 983

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 990

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 996

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1a61e82d3268d5c3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1010

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1025

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6d5fa23181d61c3e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1036

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1042

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `66d4b6b9bb3ddd48`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1055

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d445f949f9679799`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1070

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8fea313ec7f1925d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1071

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `4d800717f5880f57`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1073

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `40d60213505c39f4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1112

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `799da6d18c14d12c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1114

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `5118f14c0c344770`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1117

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `41ab0479db6744a4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1119

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `01482b1a43878998`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 1138

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `40d60213505c39f4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/finding.rs` line 601

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `cd5e5f2809d3de3a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/finding.rs` line 603

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `37806b34a0c0bd20`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/finding.rs` line 609

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `37806b34a0c0bd20`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/finding.rs` line 629

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `cd5e5f2809d3de3a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 287

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `83e12d95363991b8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 358

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e2a865ffe0a5336e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 369

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6f627404357f94ec`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 383

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `83e12d95363991b8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 393

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a9d131a00b026441`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 398

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3a78188a35e0d0d0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 399

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a9d131a00b026441`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 420

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `83e12d95363991b8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 427

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a9d131a00b026441`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 432

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a9d131a00b026441`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 437

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a9d131a00b026441`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/grants.rs` line 444

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `83e12d95363991b8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 727

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `33daf59d616c8ed6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 746

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 787

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c40e77b93fd7d825`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 799

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `33daf59d616c8ed6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 805

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 810

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 819

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 836

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `33daf59d616c8ed6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 843

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 848

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 869

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `60fc341e3f4774a6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 871

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `33daf59d616c8ed6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 959

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 971

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `23cb499be574bffa`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1027

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1033

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `33daf59d616c8ed6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1049

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e02c5d44be329f7a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1050

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `9589010ed193ba8b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1052

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1079

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `2b5b7223ea910627`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1080

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1085

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d83602edc935ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/launch.rs` line 1111

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `33daf59d616c8ed6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 181

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e1dd1a8eac797617`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 253

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `546ceb5a4186de83`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 263

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e1dd1a8eac797617`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 272

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `45dca169412d182f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 273

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8ede2b7d63b73033`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 278

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `9a21014a3b632a0e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 279

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b81a70e4f2ca89b3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 280

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8ede2b7d63b73033`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 302

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e1dd1a8eac797617`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 310

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `810695ec1367f4b1`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/model_files.rs` line 313

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e1dd1a8eac797617`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/review.rs` line 425

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c6b25ddad2977f62`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/review.rs` line 429

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `7d957e168b1b14aa`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/review.rs` line 433

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `5bdc608d19d4852e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/review.rs` line 436

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a59a60dd2b2a0f89`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/rich_text.rs` line 278

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c8f0704bba2a6a74`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/rich_text.rs` line 300

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3e69d1c2d31f9516`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/rich_text.rs` line 308

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3e69d1c2d31f9516`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/rich_text.rs` line 370

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3e69d1c2d31f9516`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/rich_text.rs` line 379

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c8f0704bba2a6a74`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/rich_text.rs` line 397

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3e69d1c2d31f9516`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/rich_text.rs` line 402

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e4eaf8bdb0df2e9a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/rich_text.rs` line 413

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c8f0704bba2a6a74`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/running.rs` line 697

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `17779083caee5a6d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/running.rs` line 712

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `f9a3e070a33680df`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/running.rs` line 713

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `aaa0183bc9f15ff4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/running.rs` line 718

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `aaa0183bc9f15ff4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/running.rs` line 723

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `aaa0183bc9f15ff4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/running.rs` line 728

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `aaa0183bc9f15ff4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/running.rs` line 733

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `885aef12ca73c615`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/running.rs` line 781

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `17779083caee5a6d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 982

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 990

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0249db6adcef154a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 991

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1003

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1011

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `84914da0a7717d70`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1019

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1025

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1040

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1047

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b4987decbc564ab6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1053

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1059

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6fcfc428836a5c58`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1060

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1069

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1080

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `7f80a66c990e04ac`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1081

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1090

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1121

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `7a20a67d163e4129`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1122

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `4eb06026593a0cdd`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1124

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1142

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ec25f40c59080ef2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1143

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1151

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1169

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1177

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1195

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1200

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1231

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1237

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1242

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1248

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1253

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1307

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1312

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1325

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1331

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `25c7b219c9bddf0f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1332

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1338

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1343

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1365

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1371

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6fcfc428836a5c58`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1372

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1377

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e5d6e59676afb1b5`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1378

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1383

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `f510437cd29926a1`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1410

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1418

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6b2993b7ad2bfb6b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1419

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1440

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1448

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0249db6adcef154a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1449

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1463

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1513

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1f9052af209986f7`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1514

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ed620a104ea54af5`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1516

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1559

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1f9052af209986f7`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1560

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `042455da71dbd631`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1564

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1588

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1f9052af209986f7`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1589

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `734b26b6e73bf5eb`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1593

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1623

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1e9a3f38a5f8dfca`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1624

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1630

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1644

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1649

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1655

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1669

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1a774e91b79a88d8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1670

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1679

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1685

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0249db6adcef154a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1686

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1707

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1713

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0249db6adcef154a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1714

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1722

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1731

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0249db6adcef154a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1732

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1746

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1754

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0249db6adcef154a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1755

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c7c616cabd1c442c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1764

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1794

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e0d3b10c18cb4a81`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1796

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `560c72954502ec9c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1797

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `de9b88bed20d7f6a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1806

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1813

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `6034797541896527`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1814

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1822

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1828

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `4d5f7631dd4c73ea`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1829

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c91d4c2c210e65e8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1841

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8baf7bdc0ca27eef`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 843

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c3b0f01b3e8bae2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 878

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `f442b86e4ff2307a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 882

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c3b0f01b3e8bae2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 963

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d13c1e77a9c05239`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 965

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c3b0f01b3e8bae2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 997

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `84dbe2108185ad29`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 1001

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c3b0f01b3e8bae2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 1033

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `f442b86e4ff2307a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 1035

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c3b0f01b3e8bae2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 1063

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a66e49bd17e2c98c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 1065

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c3b0f01b3e8bae2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 1086

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `84b737100e4bc062`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 1087

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d76f06ff03fd1ac7`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 1093

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c3b0f01b3e8bae2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 725

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8bdf4806ab418e68`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 728

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `986f0232fad3e142`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 731

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3d27c3b8977de7ea`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 739

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `86030d13632ca082`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 1027

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8bdf4806ab418e68`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 1030

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `86030d13632ca082`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/bundle.rs` line 602

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `669b20d046bcb90f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 4401

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `44f16ce4f1a6c9e0`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 4410

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1601922511b72b1c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 4412

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ecd5b3a3cd345f46`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 4417

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ec62cbe9bab60188`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 4448

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ec62cbe9bab60188`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1876

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1883

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1900

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1901

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `9a26f96898cd5517`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1919

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1920

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `9a26f96898cd5517`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1953

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `2b19f2a5c8c662fa`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1955

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `396edb820afdf0a3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1970

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `15c86c13e9d8e398`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1976

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1977

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `2b19f2a5c8c662fa`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2003

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `2b19f2a5c8c662fa`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2013

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2014

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `2b19f2a5c8c662fa`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2031

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c75155c5065516a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2038

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2064

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2087

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2155

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2158

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c75155c5065516a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2163

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c75155c5065516a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2170

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2184

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2196

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2205

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `9a26f96898cd5517`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2212

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `9a26f96898cd5517`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2218

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2226

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `148a9ce1453dab07`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2233

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `148a9ce1453dab07`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2315

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2317

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c75155c5065516a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2322

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d085cea17f84baa8`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2361

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2456

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2574

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `2cd12713a18d0181`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2587

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a14846d2c09a6691`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2590

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b84c5d88e256f94a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2591

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2610

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a325b5596b6e7199`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2616

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `26d759d6a580d625`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2620

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2645

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c20b5baf0f7a71b3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2650

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a86a595c0141e08d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2651

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2721

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c75155c5065516a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2726

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `f04e4950ca1a861d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2750

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2887

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 2953

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3022

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3112

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3252

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `94f549eaa79c4101`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3333

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `2b19f2a5c8c662fa`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3336

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `66b4e984fd36489e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3337

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a01438ee996a919e`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3346

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `08f05d96516c389f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3348

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `cb67bf07495f2c57`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3351

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c75155c5065516a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3366

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8418cedbda5a3f0c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3375

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `17602b4e0f2a00ba`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3376

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1609b8d39c00bfd5`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3380

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8d0aff16357a50c4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3797

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e0957038b2d2b087`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3812

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `bf5438dcfb9cc906`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3924

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `32e197bc8e7f3e25`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3934

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3945

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a7326ac090115ae7`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3946

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e7c91f774a747cc7`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 3958

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4037

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4044

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `fead512cf987af62`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4045

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `0c75155c5065516a`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4080

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4105

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c7cc905d2a2bcbe4`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4135

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4150

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4158

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e4957507092fce79`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4169

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `74319cca52a0f671`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 4170

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e4957507092fce79`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-run/src/lib.rs` line 699

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `e360dd358f464c57`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-run/src/lib.rs` line 703

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `71ea2a6bc60c4598`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-run/src/lib.rs` line 709

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3872227397c11359`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-run/src/lib.rs` line 921

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `71ea2a6bc60c4598`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-run/src/lib.rs` line 924

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `2d05e752c6f97813`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-run/src/lib.rs` line 956

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `71ea2a6bc60c4598`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-run/src/lib.rs` line 957

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d46d26030e5f3d85`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 367

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ee07be8bcabc32a3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 385

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `cad06be86e7b009b`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 386

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `8fe89adeae09441c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 387

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `28c6f1c876b9b621`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 389

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `be17e18852bcedad`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 407

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d9016a2a07e7de0f`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 408

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `7d1d1ef5e8d39397`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 414

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `be17e18852bcedad`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 430

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b3a0408edc75ef13`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 432

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a032cc500c8b42ab`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 433

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `81401ba072093a87`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 440

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `4f0aae2aaf8c200c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 441

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `39148d094b724fee`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 444

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `be17e18852bcedad`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 463

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `5870a53f70098a51`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 464

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `55f7489fc43c90d5`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 465

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a5e5e4b7d62d26f3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 467

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `be17e18852bcedad`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 490

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d370b77decde1bf2`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 491

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b6cbc3645bd10354`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 492

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `7d7a6f1c0a65d7ad`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 503

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `be17e18852bcedad`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 565

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `f9dcf0c1719d4fee`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 568

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ee07be8bcabc32a3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 583

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `f9dcf0c1719d4fee`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 586

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ee07be8bcabc32a3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 599

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `4efcce418010b5ea`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 604

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ee07be8bcabc32a3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 611

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `29f62bb98c704e31`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 616

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `ee07be8bcabc32a3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 657

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d3c029ae27e1bc86`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/files.rs` line 669

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `be17e18852bcedad`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 859

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a21bde85c5cee36d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 863

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3d7d99f95927d8d9`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 898

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a21bde85c5cee36d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 930

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a21bde85c5cee36d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 968

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `a21bde85c5cee36d`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 994

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `1734572a4fce7633`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 1013

*How sure: possible. Rules like this one often misfire, so read the code before changing anything; if it is not a problem, it is a false alarm and the code can stay.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `c82a94a16ff4d1b6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A disallowed hash function is used

**Where:** `crates/sv-check/src/signed_in/passwords.rs` line 2026

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `532c106e3acc05c6`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

MD5 or SHA-1 is used as a hash function. Both have practical collision attacks, and approved-hash rules disallow them for any cryptographic use.

**Why it matters.** Anything that relies on the hash to tell two things apart, or to prove something was not changed, can be fooled by somebody who builds a second input with the same hash. Used for passwords, both are also fast enough to guess through quickly.

**What to do.** Use SHA-256 or stronger for integrity and signatures, and a password hashing function (Argon2id, scrypt, bcrypt) for passwords. If this hash is only a cache key or a file checksum with no security purpose, say so where it is used; Python lets you pass usedforsecurity=False.

Evidence about: V11.4.1

Known as: CWE-328, CWE-327

### [medium] An MCP server is downloaded fresh, at whatever version is newest, every time it starts

**Where:** `crates/sv-check/src/launch.rs` line 1029

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `702beb066b650321`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

This starts an MCP server from `@modelcontextprotocol/server-github` with no exact version, through `npx`. Each start downloads whatever was published last, and nothing checks it is the code that was reviewed.

**Why it matters.** If the package or image is taken over or replaced, the next start runs the new code with the app's access to its tools and data, and nothing records that it changed.

**What to do.** Name an exact version (`package@1.2.3` for npx, `package==1.2.3` for uvx), or better, add the server to the app's own dependencies and lockfile so its version and checksum are recorded and checked on install.

Evidence about: C10.1.1

Known as: CWE-494, CWE-829

### [medium] An MCP server is downloaded fresh, at whatever version is newest, every time it starts

**Where:** `crates/sv-check/src/launch.rs` line 1048

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `702beb066b650321`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

This starts an MCP server from `@modelcontextprotocol/server-github` with no exact version, through `npx`. Each start downloads whatever was published last, and nothing checks it is the code that was reviewed.

**Why it matters.** If the package or image is taken over or replaced, the next start runs the new code with the app's access to its tools and data, and nothing records that it changed.

**What to do.** Name an exact version (`package@1.2.3` for npx, `package==1.2.3` for uvx), or better, add the server to the app's own dependencies and lockfile so its version and checksum are recorded and checked on install.

Evidence about: C10.1.1

Known as: CWE-494, CWE-829

### [medium] An MCP server is downloaded fresh, at whatever version is newest, every time it starts

**Where:** `crates/sv-check/src/launch.rs` line 1082

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `702beb066b650321`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

This starts an MCP server from `mcp-server-time` with no exact version, through `uvx`. Each start downloads whatever was published last, and nothing checks it is the code that was reviewed.

**Why it matters.** If the package or image is taken over or replaced, the next start runs the new code with the app's access to its tools and data, and nothing records that it changed.

**What to do.** Name an exact version (`package@1.2.3` for npx, `package==1.2.3` for uvx), or better, add the server to the app's own dependencies and lockfile so its version and checksum are recorded and checked on install.

Evidence about: C10.1.1

Known as: CWE-494, CWE-829

### [medium] JSON Web Token found in a file

**Where:** `crates/sv-check/src/browser_storage.rs` line 460

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `14e51122ee0540b3`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

A string shaped like a JSON Web Token (eyJ....eyJ....xxxx) appears in a file. A credential in a file is a secret kept in the app's code, where anyone who can read the code, or its history, can use it.

**Why it matters.** It may be a valid access token for a service; whoever has it can act as its owner until it expires.

**What to do.** Remove the token from the file. Generate tokens at test/run time instead of committing them.

Evidence about: V13.3.1, SBD-AC-05

Known as: CWE-798

### [low] A hosted model is asked for by a name that moves

**Where:** `crates/sv-check/src/ai.rs` line 2716

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b4dff4ce73bdd098`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

The code asks the AI provider for a model by a name ending in `-latest` (or `:latest`). The provider points that name at a new model whenever it releases one.

**Why it matters.** The model behind the app can change on the provider's schedule with no change to your code, so nothing prompts anyone to test the new one for safety before users meet it.

**What to do.** Name a dated model version (for example `gpt-4o-2024-08-06` rather than `chatgpt-4o-latest`), and when you move to a new one, do it on purpose and re-run your checks.

Evidence about: C3.2.3

Known as: CWE-1357

### [low] A hosted model is asked for by a name that moves

**Where:** `crates/sv-check/src/ai.rs` line 2717

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `b06373462d4bb86c`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

The code asks the AI provider for a model by a name ending in `-latest` (or `:latest`). The provider points that name at a new model whenever it releases one.

**Why it matters.** The model behind the app can change on the provider's schedule with no change to your code, so nothing prompts anyone to test the new one for safety before users meet it.

**What to do.** Name a dated model version (for example `gpt-4o-2024-08-06` rather than `chatgpt-4o-latest`), and when you move to a new one, do it on purpose and re-run your checks.

Evidence about: C3.2.3

Known as: CWE-1357

### [low] A hosted model is asked for by a name that moves

**Where:** `crates/sv-check/src/ai.rs` line 2718

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `3912bf0d1f8f2f89`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

The code asks the AI provider for a model by a name ending in `-latest` (or `:latest`). The provider points that name at a new model whenever it releases one.

**Why it matters.** The model behind the app can change on the provider's schedule with no change to your code, so nothing prompts anyone to test the new one for safety before users meet it.

**What to do.** Name a dated model version (for example `gpt-4o-2024-08-06` rather than `chatgpt-4o-latest`), and when you move to a new one, do it on purpose and re-run your checks.

Evidence about: C3.2.3

Known as: CWE-1357

### [low] A hosted model is asked for by a name that moves

**Where:** `crates/sv-check/src/ai.rs` line 3267

*How sure: likely. Rules like this one are usually right, not always.*

*In test or sample code, not the app itself. It still counts: test code can hold a real key, and sample code gets copied.*

*Fingerprint: `d405c605c1183c80`. A person who has looked and found it a false alarm, or a risk to live with for now, can set it aside under `[[finding-review]]` in securevibe.toml.*

The code asks the AI provider for a model by a name ending in `-latest` (or `:latest`). The provider points that name at a new model whenever it releases one.

**Why it matters.** The model behind the app can change on the provider's schedule with no change to your code, so nothing prompts anyone to test the new one for safety before users meet it.

**What to do.** Name a dated model version (for example `gpt-4o-2024-08-06` rather than `chatgpt-4o-latest`), and when you move to a new one, do it on purpose and re-run your checks.

Evidence about: C3.2.3

Known as: CWE-1357

