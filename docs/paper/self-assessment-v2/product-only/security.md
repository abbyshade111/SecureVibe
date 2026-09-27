# sv (SecureVibe) — what the checks found

## What was not examined

- **the running app** — `sv report` does not start the app unless you pass --run. Without it, nothing here has asked the app anything — what it sends to a browser, what it says when something goes wrong, which sites it accepts.
- **what `codeql-javascript` would have found** — CodeQL (JavaScript and TypeScript) is not installed on this computer, so nothing here has checked the javascript and typescript in this app the way it would have. Install it with `download the CodeQL bundle from https://github.com/github/codeql-action/releases, unpack it, and put its `codeql` on your PATH` and run this again.
- **the check `config.secrets-file-committed`** — This folder is not a git repository, so `sv` cannot say whether a secrets file was ever committed. Putting the app in git (version control, which keeps every saved version) makes this check run, and is worth doing anyway. Ask your AI coding tool to do it, and to add a .gitignore that leaves out .env and other secret files before the first commit, so that commit does not save them. If the app is already kept in version control somewhere else, that copy's history is still unchecked.
- **22 requirements that are design review, not scanning** — these ask how the system was designed and how it is run — whether trust zones are enforced, whether an incident response plan is rehearsed, whether data has named owners. No check here reaches them and none ever will, so they are counted as applicable and unverified, and a person has to answer them.
- **4 requirements that ask for a written decision** — No tool can answer these: they ask what your rules are, who may do what, and how long things are kept. Run `sv notes` to write security-notes.md, answer the questions in it, and they become documented. Your AI coding tool can ask you them: `sv questions` prints them for its chat.
- **4 questions about how this app is built** — No tool can settle these — whether input is validated on the server, whether the app's own services authenticate to each other. Answer them in the [design] section of securevibe.toml: V2.2.2, V7.2.1, V8.3.1, V15.3.1. Your AI coding tool can ask you them: `sv questions` prints them for its chat.

## 252 things to fix

Worst first.

### [high] A shell command is built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 350

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 461

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 484

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-run/src/docker.rs` line 75

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 1940

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 2097

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 2665

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 2939

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/ai.rs` line 3024

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/browser.rs` line 991

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/secrets.rs` line 514

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/secrets.rs` line 526

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in.rs` line 1977

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in.rs` line 1984

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in.rs` line 2131

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in.rs` line 8654

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in.rs` line 8658

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in.rs` line 8662

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-check/src/signed_in.rs` line 8668

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] A value that looks like a credential is written into the code (`password`)

**Where:** `crates/sv-manifest/src/spec.rs` line 73

`password` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 103

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2405

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2408

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2410

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2411

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2413

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2415

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2417

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2419

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2421

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2423

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2425

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2427

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2429

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2431

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2433

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2435

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/src/ast.rs` line 2437

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: typescript.react.security.react-insecure-request.react-insecure-request

**Where:** `crates/sv-run/assets/browser-driver.mjs` line 38

Unencrypted request over HTTP detected.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Unencrypted request over HTTP detected.

Evidence about: V12.3.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 167

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 422

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 453

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 474

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 500

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 512

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 522

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 523

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 556

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/adapters.rs` line 592

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/advisories.rs` line 132

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 691

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1240

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1311

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1364

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/ast.rs` line 1366

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/coding_rules.rs` line 74

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 200

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 431

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 469

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 484

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 493

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 494

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 504

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 512

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 533

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 543

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 544

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 563

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 569

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 577

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 586

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 593

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 602

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 608

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 617

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 623

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 624

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 631

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 640

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 653

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 661

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 686

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 713

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 729

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 735

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 752

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 759

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 770

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 778

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 788

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 794

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 807

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 814

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 820

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 834

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 849

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 860

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 866

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 879

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 894

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 895

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 897

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 925

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 927

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 930

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 932

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/config.rs` line 951

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/design.rs` line 89

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/human.rs` line 48

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/notes.rs` line 182

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 107

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 654

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 662

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 663

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 675

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 683

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 691

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 697

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 712

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 719

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 725

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 731

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 732

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 741

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 752

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 753

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 762

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 771

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 772

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 793

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 801

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 802

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 816

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 825

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 826

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 832

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 846

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 851

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 857

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 871

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 872

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 881

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 887

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 888

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 909

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 915

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 916

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 924

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 933

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 934

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 948

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 956

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 957

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 966

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 996

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 998

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 999

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1008

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1015

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1016

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1024

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1030

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1031

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/sbom.rs` line 1043

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 84

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/secrets.rs` line 467

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/suite.rs` line 167

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 423

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 722

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 725

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 728

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 736

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 1024

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/src/workflows.rs` line 1027

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/bundle.rs` line 557

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 466

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 753

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 762

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 872

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 891

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1658

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1671

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1676

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1713

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1734

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 1747

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/main.rs` line 2348

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 853

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 860

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 877

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 878

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 896

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 897

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 913

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 936

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1006

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1018

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1027

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1034

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1040

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1048

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1055

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1137

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1139

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1144

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1183

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1215

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1333

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1346

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1349

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1350

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1369

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1375

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1379

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1404

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1409

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1410

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1488

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1495

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1496

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1526

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1543

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1565

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1580

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1588

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1599

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/src/mcp.rs` line 1600

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/applicability.rs` line 80

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/applicability.rs` line 91

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/load.rs` line 133

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/load.rs` line 168

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/src/load.rs` line 211

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-manifest/src/lib.rs` line 819

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/src/threats.rs` line 203

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/deps.rs` line 23

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/ecosystems.rs` line 231

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 218

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 266

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 443

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 510

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 574

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 859

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 863

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 898

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 930

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 968

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 994

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/jvm.rs` line 1013

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/lib.rs` line 95

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/lib.rs` line 213

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/src/lib.rs` line 490

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A disallowed hash function is used

**Where:** `crates/sv-check/src/signed_in.rs` line 10944

MD5 or SHA-1 is used as a hash function. Both have practical collision attacks, and approved-hash rules disallow them for any cryptographic use.

**Why it matters.** Anything that relies on the hash to tell two things apart, or to prove something was not changed, can be fooled by somebody who builds a second input with the same hash. Used for passwords, both are also fast enough to guess through quickly.

**What to do.** Use SHA-256 or stronger for integrity and signatures, and a password hashing function (Argon2id, scrypt, bcrypt) for passwords. If this hash is only a cache key or a file checksum with no security purpose, say so where it is used; Python lets you pass usedforsecurity=False.

Evidence about: V11.4.1

Known as: CWE-328, CWE-327

