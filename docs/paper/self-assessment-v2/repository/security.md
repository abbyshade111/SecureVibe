# sv (SecureVibe) — what the checks found

## What was not examined

- **the running app** — `sv report` does not start the app unless you pass --run. Without it, nothing here has asked the app anything — what it sends to a browser, what it says when something goes wrong, which sites it accepts.
- **what `gosec` would have found** — gosec is not installed on this computer, so nothing here has checked the go in this app the way it would have. Install it with `go install github.com/securego/gosec/v2/cmd/gosec@latest` and run this again.
- **what `brakeman` would have found** — Brakeman is not installed on this computer, so nothing here has checked the ruby in this app the way it would have. Install it with `gem install brakeman` and run this again.
- **what `codeql-javascript` would have found** — CodeQL (JavaScript and TypeScript) is not installed on this computer, so nothing here has checked the javascript and typescript in this app the way it would have. Install it with `download the CodeQL bundle from https://github.com/github/codeql-action/releases, unpack it, and put its `codeql` on your PATH` and run this again.
- **what `codeql-python` would have found** — CodeQL (Python) is not installed on this computer, so nothing here has checked the python in this app the way it would have. Install it with `download the CodeQL bundle from https://github.com/github/codeql-action/releases, unpack it, and put its `codeql` on your PATH` and run this again.
- **3 files not read while looking for credentials** — a credential in a file nothing read is a credential nothing found
- **files ending dart, swift** — the technology scan did not look in these, so no technology can be called absent on their account
- **24 requirements that are design review, not scanning** — these ask how the system was designed and how it is run — whether trust zones are enforced, whether an incident response plan is rehearsed, whether data has named owners. No check here reaches them and none ever will, so they are counted as applicable and unverified, and a person has to answer them.
- **everything Go installs** — `crates/sv-scan/tests/fixtures/go-stdlib-xml/go.sum` was read and no packages could be taken from it, so nothing from Go is listed. This is not an approximate list of this app's Go dependencies, it is an empty one: nothing here can say whether a package with a known vulnerability is among them
- **everything npm installs** — `crates/sv-scan/tests/fixtures/node-websockets/package-lock.json` was read and no packages could be taken from it, so nothing from npm is listed. This is not an approximate list of this app's npm dependencies, it is an empty one: nothing here can say whether a package with a known vulnerability is among them
- **everything npm installs** — `crates/sv-scan/tests/fixtures/pinned-clean/package-lock.json` was read and no packages could be taken from it, so nothing from npm is listed. This is not an approximate list of this app's npm dependencies, it is an empty one: nothing here can say whether a package with a known vulnerability is among them
- **everything npm installs** — npm is in use but nothing readable says which versions are installed, so none of its packages are listed. This is not an approximate list of this app's npm dependencies, it is an empty one: nothing here can say whether a package with a known vulnerability is among them
- **everything Python installs** — Python is in use but nothing readable says which versions are installed, so none of its packages are listed. This is not an approximate list of this app's Python dependencies, it is an empty one: nothing here can say whether a package with a known vulnerability is among them
- **everything npm installs** — `crates/sv-scan/tests/fixtures/unreadable-language/package-lock.json` was read and no packages could be taken from it, so nothing from npm is listed. This is not an approximate list of this app's npm dependencies, it is an empty one: nothing here can say whether a package with a known vulnerability is among them
- **everything Ruby installs** — Ruby is in use but nothing readable says which versions are installed, so none of its packages are listed. This is not an approximate list of this app's Ruby dependencies, it is an empty one: nothing here can say whether a package with a known vulnerability is among them
- **everything Go installs** — Go is in use but nothing readable says which versions are installed, so none of its packages are listed. This is not an approximate list of this app's Go dependencies, it is an empty one: nothing here can say whether a package with a known vulnerability is among them
- **4 requirements that ask for a written decision** — No tool can answer these: they ask what your rules are, who may do what, and how long things are kept. Run `sv notes` to write security-notes.md, answer the questions in it, and they become documented. Your AI coding tool can ask you them: `sv questions` prints them for its chat.
- **4 questions about how this app is built** — No tool can settle these — whether input is validated on the server, whether the app's own services authenticate to each other. Answer them in the [design] section of securevibe.toml: V2.2.2, V7.2.1, V8.3.1, V15.3.1. Your AI coding tool can ask you them: `sv questions` prints them for its chat.

## 804 things to fix

Worst first.

### [critical] AWS access key ID found in a file

**Where:** `crates/sv-check/tests/own_output.rs` line 25

A string shaped like an Amazon Web Services access key id (AKIA...) appears in a file. A credential in a file is a secret kept in the app's code, where anyone who can read the code, or its history, can use it.

**Why it matters.** Combined with its secret key it gives access to your cloud account.

**What to do.** Deactivate the key in AWS IAM and load credentials from the environment instead.

Evidence about: V13.3.1, SBD-AC-05

Known as: CWE-798

### [critical] AWS access key ID found in a file

**Where:** `crates/sv-check/tests/own_output.rs` line 101

A string shaped like an Amazon Web Services access key id (AKIA...) appears in a file. A credential in a file is a secret kept in the app's code, where anyone who can read the code, or its history, can use it.

**Why it matters.** Combined with its secret key it gives access to your cloud account.

**What to do.** Deactivate the key in AWS IAM and load credentials from the environment instead.

Evidence about: V13.3.1, SBD-AC-05

Known as: CWE-798

### [critical] Private key found in a file

**Where:** `crates/sv-cli/tests/bundle.rs` line 56

 A credential in a file is a secret kept in the app's code, where anyone who can read the code, or its history, can use it.

**Why it matters.** A private key lets an attacker impersonate your server or decrypt its traffic.

**What to do.** Remove the key from the file, regenerate it, and keep private keys only in certs/ with restrictive permissions.

Evidence about: V11.1.1, V13.3.1, SBD-AC-05

Known as: CWE-321

### [high] Code is built at run time and executed

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 32

A value decided while the app is running is handed to something that executes it as code.

**Why it matters.** If any part of that value can be influenced from outside, whoever influences it chooses what the app does next.

**What to do.** Work out what the code is actually for. A lookup table, a match on a fixed set of names, or a small parser will do the job without running text as code.

Evidence about: V1.3.2

Known as: CWE-95, CWE-94

### [high] Code is built at run time and executed

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 16

A value decided while the app is running is handed to something that executes it as code.

**Why it matters.** If any part of that value can be influenced from outside, whoever influences it chooses what the app does next.

**What to do.** Work out what the code is actually for. A lookup table, a match on a fixed set of names, or a small parser will do the job without running text as code.

Evidence about: V1.3.2

Known as: CWE-95, CWE-94

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

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 13

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-check/tests/fixtures/suppressed/gosec-app/main.go` line 13

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 13

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 101

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/atlas_references.rs` line 21

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/audit_deadlines.rs` line 57

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 87

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/confirmations.rs` line 59

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/data_unanswered.rs` line 24

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/dependency_gap.rs` line 30

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/dependency_gap.rs` line 59

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/mcp_stdio.rs` line 11

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/notes_authorship.rs` line 14

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/notes_authorship.rs` line 79

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/notes_disclaimer.rs` line 12

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/report_advisories.rs` line 72

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 9

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 111

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/run_status.rs` line 35

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/unanswered_questions.rs` line 50

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 24

A command line is assembled from something other than fixed text and handed to the shell.

**Why it matters.** A semicolon or a backtick in the wrong place turns one command into two, and the second one is whatever the attacker wanted.

**What to do.** Pass the program and its arguments as a list instead of a string, so the shell never parses them. Where a shell is genuinely needed, validate the value against a fixed set first.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A shell command is built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 46

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

### [high] A command is run with backticks, built from text

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 14

Backticks run a shell command and hand back its output. This one is assembled from pieces rather than written out.

**Why it matters.** Whatever ends up inside the backticks is run by a shell, so a semicolon in someone's input starts a second command with the app's own permissions.

**What to do.** Run the program directly with its arguments as a list, rather than building one string for a shell to pull apart.

Evidence about: V1.2.5

Known as: CWE-78

### [high] A database query is built by joining text together

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 5

A query is assembled from pieces rather than sent with its values kept separate.

**Why it matters.** A quote in someone's name is enough to change what the query does, and a deliberate one can read or delete any table the app can reach.

**What to do.** Send the query with placeholders and pass the values alongside it. Every database library supports this, and it is shorter than building the string.

Evidence about: V1.2.4

Known as: CWE-89

### [high] A database query is built by joining text together

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 22

A query is assembled from pieces rather than sent with its values kept separate.

**Why it matters.** A quote in someone's name is enough to change what the query does, and a deliberate one can read or delete any table the app can reach.

**What to do.** Send the query with placeholders and pass the values alongside it. Every database library supports this, and it is shorter than building the string.

Evidence about: V1.2.4

Known as: CWE-89

### [high] A database query is built by joining text together

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 15

A query is assembled from pieces rather than sent with its values kept separate.

**Why it matters.** A quote in someone's name is enough to change what the query does, and a deliberate one can read or delete any table the app can reach.

**What to do.** Send the query with placeholders and pass the values alongside it. Every database library supports this, and it is shorter than building the string.

Evidence about: V1.2.4

Known as: CWE-89

### [high] A database query is built by joining text together

**Where:** `crates/sv-check/tests/fixtures/suppressed/bandit-app/blanket.py` line 2

A query is assembled from pieces rather than sent with its values kept separate.

**Why it matters.** A quote in someone's name is enough to change what the query does, and a deliberate one can read or delete any table the app can reach.

**What to do.** Send the query with placeholders and pass the values alongside it. Every database library supports this, and it is shorter than building the string.

Evidence about: V1.2.4

Known as: CWE-89

### [high] A database query is built by joining text together

**Where:** `crates/sv-check/tests/fixtures/suppressed/bandit-app/targeted.py` line 2

A query is assembled from pieces rather than sent with its values kept separate.

**Why it matters.** A quote in someone's name is enough to change what the query does, and a deliberate one can read or delete any table the app can reach.

**What to do.** Send the query with placeholders and pass the values alongside it. Every database library supports this, and it is shorter than building the string.

Evidence about: V1.2.4

Known as: CWE-89

### [high] A database query is built by joining text together

**Where:** `crates/sv-check/tests/fixtures/suppressed/gosec-app/main.go` line 9

A query is assembled from pieces rather than sent with its values kept separate.

**Why it matters.** A quote in someone's name is enough to change what the query does, and a deliberate one can read or delete any table the app can reach.

**What to do.** Send the query with placeholders and pass the values alongside it. Every database library supports this, and it is shorter than building the string.

Evidence about: V1.2.4

Known as: CWE-89

### [high] Data from outside is turned back into objects unsafely

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 27

A format that can describe arbitrary objects is being read with the reader that builds them.

**Why it matters.** Reading the data is enough to run code: the attacker does not need the app to use the result, only to load it.

**What to do.** Use the safe reader — yaml.safe_load rather than yaml.load — and prefer a format that carries data only, such as JSON, for anything that arrives from outside.

Evidence about: V1.5.2

Known as: CWE-502

### [high] Data from outside is turned back into objects unsafely

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 28

A format that can describe arbitrary objects is being read with the reader that builds them.

**Why it matters.** Reading the data is enough to run code: the attacker does not need the app to use the result, only to load it.

**What to do.** Use the safe reader — yaml.safe_load rather than yaml.load — and prefer a format that carries data only, such as JSON, for anything that arrives from outside.

Evidence about: V1.5.2

Known as: CWE-502

### [high] Data from outside is turned back into objects unsafely

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 32

A format that can describe arbitrary objects is being read with the reader that builds them.

**Why it matters.** Reading the data is enough to run code: the attacker does not need the app to use the result, only to load it.

**What to do.** Use the safe reader — yaml.safe_load rather than yaml.load — and prefer a format that carries data only, such as JSON, for anything that arrives from outside.

Evidence about: V1.5.2

Known as: CWE-502

### [high] Data from outside is turned back into objects unsafely

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 37

A format that can describe arbitrary objects is being read with the reader that builds them.

**Why it matters.** Reading the data is enough to run code: the attacker does not need the app to use the result, only to load it.

**What to do.** Use the safe reader — yaml.safe_load rather than yaml.load — and prefer a format that carries data only, such as JSON, for anything that arrives from outside.

Evidence about: V1.5.2

Known as: CWE-502

### [high] A cipher or block mode that is not approved is used

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 19

Data is encrypted with ECB, the block mode that encrypts equal blocks to equal output, or with a retired cipher such as DES, triple DES, RC4, RC2 or Blowfish.

**Why it matters.** ECB leaves the shape of the data visible through the encryption, and the retired ciphers can be broken or have known practical attacks, so the encrypted data is less private than it looks.

**What to do.** Use AES with GCM (or ChaCha20-Poly1305) through your language's high-level library, which chooses the mode and the nonce for you. In Java, always name the mode: Cipher.getInstance("AES") quietly means ECB.

Evidence about: V11.3.1, V11.3.2

Known as: CWE-327

### [high] Bandit reported B324

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 56

Use of weak MD5 hash for security. Consider usedforsecurity=False

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B324.

Evidence about: V11.4.1

Known as: CWE-327

### [high] Bandit reported B324

**Where:** `tools/pwned_passwords.py` line 66

Use of weak SHA1 hash for security. Consider usedforsecurity=False

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B324.

Evidence about: V11.4.1

Known as: CWE-327

### [high] Bandit reported B501

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 52

Call to requests with verify=False disabling SSL certificate checks, security issue.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B501.

Evidence about: V12.3.2

Known as: CWE-295

### [high] Bandit reported B602

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 27

subprocess call with shell=True identified, security issue.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B602.

Evidence about: V1.2.5

Known as: CWE-78

### [high] Bandit reported B602

**Where:** `crates/sv-check/tests/fixtures/suppressed/semgrep-app/app.py` line 3

subprocess call with shell=True identified, security issue.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B602.

Evidence about: V1.2.5

Known as: CWE-78

### [high] Bandit reported B602

**Where:** `crates/sv-check/tests/fixtures/suppressed/semgrep-app/app.py` line 6

subprocess call with shell=True identified, security issue.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B602.

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

### [high] A value that looks like a credential is written into the code (`PASSWORD`)

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/models/settings.rb` line 2

`PASSWORD` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

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

### [high] A value that looks like a credential is written into the code (`DB_PASSWORD`)

**Where:** `crates/sv-report/tests/report.rs` line 673

`DB_PASSWORD` is set to a value in the code itself. The name says it holds a credential, and the value is not a placeholder.

**Why it matters.** Anyone who can read the code — or the history it is kept in — has the credential.

**What to do.** Move the value into the app's environment or secret store, and change the credential: anything committed should be treated as known.

Evidence about: V13.3.1, V13.2.3, SBD-AC-05

Known as: CWE-798, CWE-259

### [high] Semgrep Finding: ai.ai-best-practices.langchain-dangerous-exec.langchain-dangerous-exec.langchain-dangerous-exec-python

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.py` line 38

Dangerous LangChain execution utility detected. PythonREPL, BashProcess, PythonAstREPLTool, and LLMMathChain allow arbitrary code execution and should not be used in production. If an LLM agent can invoke these tools, prompt injection can lead to remote code execution.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Dangerous LangChain execution utility detected. PythonREPL, BashProcess, PythonAstREPLTool, and LLMMathChain allow arbitrary code execution and should not be used in production. If an LLM agent can invoke these tools, prompt injection can lead to remote code execution.

Evidence about: V1.3.2, C9.3.1

Known as: CWE-94: Improper Control of Generation of Code ('Code Injection')

### [high] Semgrep Finding: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value

**Where:** `crates/sv-check/tests/own_output.rs` line 25

AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.

Evidence about: V13.3.1

Known as: CWE-798: Use of Hard-coded Credentials

### [high] Semgrep Finding: generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value

**Where:** `crates/sv-check/tests/own_output.rs` line 101

AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.

Evidence about: V13.3.1

Known as: CWE-798: Use of Hard-coded Credentials

### [high] Semgrep Finding: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command

**Where:** `crates/sv-check/tests/fixtures/suppressed/gosec-app/main.go` line 13

Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

Evidence about: V1.2.5

Known as: CWE-94: Improper Control of Generation of Code ('Code Injection')

### [high] Semgrep Finding: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 15

Detected string concatenation with a non-literal variable in a "database/sql" Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use prepared statements with the 'Prepare' and 'PrepareContext' calls.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected string concatenation with a non-literal variable in a "database/sql" Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use prepared statements with the 'Prepare' and 'PrepareContext' calls.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [high] Semgrep Finding: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli

**Where:** `crates/sv-check/tests/fixtures/suppressed/gosec-app/main.go` line 9

Detected string concatenation with a non-literal variable in a "database/sql" Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use prepared statements with the 'Prepare' and 'PrepareContext' calls.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected string concatenation with a non-literal variable in a "database/sql" Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use prepared statements with the 'Prepare' and 'PrepareContext' calls.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [high] Semgrep Finding: go.lang.security.injection.tainted-sql-string.tainted-sql-string

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 15

User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`db.Query("SELECT * FROM t WHERE id = ?", id)`) or a safe library.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`db.Query("SELECT * FROM t WHERE id = ?", id)`) or a safe library.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

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

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 65

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 77

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `crates/sv-scan/tests/scan.rs` line 166

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `docs/paper/figure-security.html` line 168

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `docs/paper/figure-security.html` line 168

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `tools/semgrep_rule_map.py` line 248

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket

**Where:** `tools/semgrep_rule_map.py` line 251

Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

Evidence about: V12.3.1, V4.4.1

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [high] Semgrep Finding: python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 47

Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist, do not forward the response to the user, and ensure proper authentication and transport-layer security in the proxied request. See https://owasp.org/www-community/attacks/Server_Side_Request_Forgery to learn more about SSRF vulnerabilities.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist, do not forward the response to the user, and ensure proper authentication and transport-layer security in the proxied request. See https://owasp.org/www-community/attacks/Server_Side_Request_Forgery to learn more about SSRF vulnerabilities.

Evidence about: V1.3.6

Known as: CWE-918: Server-Side Request Forgery (SSRF)

### [high] Semgrep Finding: python.django.security.injection.tainted-sql-string.tainted-sql-string

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 22

Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using the Django object-relational mappers (ORM) instead of raw SQL queries.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using the Django object-relational mappers (ORM) instead of raw SQL queries.

Evidence about: V1.2.4

Known as: CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

### [high] Semgrep Finding: python.flask.security.injection.path-traversal-open.path-traversal-open

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 60

Found request data in a call to 'open'. Ensure the request data is validated or sanitized, otherwise it could result in path traversal attacks.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found request data in a call to 'open'. Ensure the request data is validated or sanitized, otherwise it could result in path traversal attacks.

Evidence about: V5.3.2

Known as: CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### [high] Semgrep Finding: python.flask.security.injection.ssrf-requests.ssrf-requests

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 47

Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist, do not forward the response to the user, and ensure proper authentication and transport-layer security in the proxied request.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist, do not forward the response to the user, and ensure proper authentication and transport-layer security in the proxied request.

Evidence about: V1.3.6

Known as: CWE-918: Server-Side Request Forgery (SSRF)

### [high] Semgrep Finding: python.flask.security.injection.subprocess-injection.subprocess-injection

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 27

Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability. An attacker could use this vulnerability to execute arbitrary commands on the host, which allows them to download malware, scan sensitive data, or run any command they wish on the server. Do not let users choose the command to run. In general, prefer to use Python API versions of system commands. If you must use subprocess, use a dictionary to allowlist a set of commands.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability. An attacker could use this vulnerability to execute arbitrary commands on the host, which allows them to download malware, scan sensitive data, or run any command they wish on the server. Do not let users choose the command to run. In general, prefer to use Python API versions of system commands. If you must use subprocess, use a dictionary to allowlist a set of commands.

Evidence about: V1.2.5

Known as: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### [high] Semgrep Finding: python.flask.security.injection.tainted-sql-string.tainted-sql-string

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 22

Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries.

Evidence about: V1.2.4

Known as: CWE-704: Incorrect Type Conversion or Cast

### [high] Semgrep Finding: python.flask.security.injection.user-eval.eval-injection

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 16

Detected user data flowing into eval. This is code injection and should be avoided.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected user data flowing into eval. This is code injection and should be avoided.

Evidence about: V1.3.2

Known as: CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

### [high] Semgrep Finding: python.flask.security.insecure-deserialization.insecure-deserialization

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 32

Detected the use of an insecure deserialization library in a Flask route. These libraries are prone to code execution vulnerabilities. Ensure user data does not enter this function. To fix this, try to avoid serializing whole objects. Consider instead using a serializer such as JSON.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected the use of an insecure deserialization library in a Flask route. These libraries are prone to code execution vulnerabilities. Ensure user data does not enter this function. To fix this, try to avoid serializing whole objects. Consider instead using a serializer such as JSON.

Evidence about: V1.5.2

Known as: CWE-502: Deserialization of Untrusted Data

### [high] Semgrep Finding: python.flask.security.insecure-deserialization.insecure-deserialization

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 37

Detected the use of an insecure deserialization library in a Flask route. These libraries are prone to code execution vulnerabilities. Ensure user data does not enter this function. To fix this, try to avoid serializing whole objects. Consider instead using a serializer such as JSON.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected the use of an insecure deserialization library in a Flask route. These libraries are prone to code execution vulnerabilities. Ensure user data does not enter this function. To fix this, try to avoid serializing whole objects. Consider instead using a serializer such as JSON.

Evidence about: V1.5.2

Known as: CWE-502: Deserialization of Untrusted Data

### [high] Semgrep Finding: python.flask.security.open-redirect.open-redirect

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 42

Data from request is passed to redirect(). This is an open redirect and could be exploited. Consider using 'url_for()' to generate links to known locations. If you must use a URL to unknown pages, consider using 'urlparse()' or similar and checking if the 'netloc' property is the same as your site's host name. See the references for more information.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Data from request is passed to redirect(). This is an open redirect and could be exploited. Consider using 'url_for()' to generate links to known locations. If you must use a URL to unknown pages, consider using 'urlparse()' or similar and checking if the 'netloc' property is the same as your site's host name. See the references for more information.

Evidence about: V3.7.2

Known as: CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### [high] Semgrep Finding: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 27

Found 'subprocess' function 'call' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found 'subprocess' function '$FUNC' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.

Evidence about: V1.2.5

Known as: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### [high] Semgrep Finding: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true

**Where:** `crates/sv-check/tests/fixtures/suppressed/semgrep-app/app.py` line 3

Found 'subprocess' function 'call' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.

This one is marked to be ignored (by a comment on the line), so Semgrep would not normally show it. It is shown here because a finding somebody chose to hide is still a finding until somebody has looked at why.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found 'subprocess' function '$FUNC' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.

Evidence about: V1.2.5

Known as: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### [high] Semgrep Finding: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true

**Where:** `crates/sv-check/tests/fixtures/suppressed/semgrep-app/app.py` line 6

Found 'subprocess' function 'call' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found 'subprocess' function '$FUNC' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.

Evidence about: V1.2.5

Known as: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### [high] Semgrep Finding: python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 27

Detected subprocess function 'call' with user controlled data. A malicious actor could leverage this to perform command injection. You may consider using 'shlex.escape()'.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected subprocess function '$FUNC' with user controlled data. A malicious actor could leverage this to perform command injection. You may consider using 'shlex.escape()'.

Evidence about: V1.2.5

Known as: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

### [high] Semgrep Finding: python.lang.security.use-defused-xml.use-defused-xml

**Where:** `crates/sv-scan/tests/fixtures/stdlib-xml-python/app.py` line 1

The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential data and "XML bombs" can cause denial of service.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential data and "XML bombs" can cause denial of service.

Evidence about: V1.5.1

Known as: CWE-611: Improper Restriction of XML External Entity Reference

### [high] Semgrep Finding: python.lang.security.use-defused-xml.use-defused-xml

**Where:** `examples/flask-booking/app.py` line 3

The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential data and "XML bombs" can cause denial of service.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential data and "XML bombs" can cause denial of service.

Evidence about: V1.5.1

Known as: CWE-611: Improper Restriction of XML External Entity Reference

### [high] Semgrep Finding: python.lang.security.use-defused-xml.use-defused-xml

**Where:** `examples/partly-passing/run_tests.py` line 12

The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential data and "XML bombs" can cause denial of service.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential data and "XML bombs" can cause denial of service.

Evidence about: V1.5.1

Known as: CWE-611: Improper Restriction of XML External Entity Reference

### [high] Semgrep Finding: python.requests.security.disabled-cert-validation.disabled-cert-validation

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 52

Certificate verification has been explicitly disabled. This permits insecure connections to insecure servers. Re-enable certification validation.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Certificate verification has been explicitly disabled. This permits insecure connections to insecure servers. Re-enable certification validation.

Evidence about: V12.3.2

Known as: CWE-295: Improper Certificate Validation

### [high] Semgrep Finding: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 22

Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [high] Semgrep Finding: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

**Where:** `crates/sv-check/tests/fixtures/suppressed/bandit-app/blanket.py` line 2

Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [high] Semgrep Finding: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query

**Where:** `crates/sv-check/tests/fixtures/suppressed/bandit-app/targeted.py` line 2

Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [high] Semgrep Finding: ruby.lang.security.bad-deserialization.bad-deserialization

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 27

Checks for unsafe deserialization. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of load and object_load can cause remote code execution. Loading user input with MARSHAL or CSV can potentially be dangerous. Use JSON in a secure fashion instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Checks for unsafe deserialization. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of load and object_load can cause remote code execution. Loading user input with MARSHAL or CSV can potentially be dangerous. Use JSON in a secure fashion instead.

Evidence about: V1.5.2

Known as: CWE-502: Deserialization of Untrusted Data

### [high] Semgrep Finding: ruby.lang.security.missing-csrf-protection.missing-csrf-protection

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/application_controller.rb` line 1

Detected controller which does not enable cross-site request forgery protections using 'protect_from_forgery'. Add 'protect_from_forgery :with => :exception' to your controller class.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected controller which does not enable cross-site request forgery protections using 'protect_from_forgery'. Add 'protect_from_forgery :with => :exception' to your controller class.

Evidence about: V3.5.1

Known as: CWE-352: Cross-Site Request Forgery (CSRF)

### [high] Semgrep Finding: ruby.lang.security.missing-csrf-protection.missing-csrf-protection

**Where:** `crates/sv-check/tests/fixtures/suppressed/brakeman-app/app/controllers/application_controller.rb` line 1

Detected controller which does not enable cross-site request forgery protections using 'protect_from_forgery'. Add 'protect_from_forgery :with => :exception' to your controller class.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected controller which does not enable cross-site request forgery protections using 'protect_from_forgery'. Add 'protect_from_forgery :with => :exception' to your controller class.

Evidence about: V3.5.1

Known as: CWE-352: Cross-Site Request Forgery (CSRF)

### [high] Semgrep Finding: ruby.rails.security.brakeman.check-regex-dos.check-regex-dos

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 61

Found a potentially user-controllable argument in the construction of a regular expressions. This may result in excessive resource consumption when applied to certain inputs, or when the user is allowed to control the match target. Avoid allowing users to specify regular expressions processed by the server. If you must support user-controllable input in a regular expression, use an allow-list to restrict the expressions users may supply to limit catastrophic backtracking.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found a potentially user-controllable argument in the construction of a regular expressions. This may result in excessive resource consumption when applied to certain inputs, or when the user is allowed to control the match target. Avoid allowing users to specify regular expressions processed by the server. If you must support user-controllable input in a regular expression, use an allow-list to restrict the expressions users may supply to limit catastrophic backtracking.

Evidence about: V1.3.12

Known as: CWE-1333: Inefficient Regular Expression Complexity

### [high] Semgrep Finding: ruby.rails.security.brakeman.check-send-file.check-send-file

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 18

Allowing user input to `send_file` allows a malicious user to potentially read arbitrary files from the server. Avoid accepting user input in `send_file` or normalize with `File.basename(...)`

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Allowing user input to `send_file` allows a malicious user to potentially read arbitrary files from the server. Avoid accepting user input in `send_file` or normalize with `File.basename(...)`

Evidence about: V5.3.2

Known as: CWE-73: External Control of File Name or Path

### [high] Semgrep Finding: ruby.rails.security.brakeman.check-unsafe-reflection.check-unsafe-reflection

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 56

Found user-controllable input to Ruby reflection functionality. This allows a remote user to influence runtime behavior, up to and including arbitrary remote code execution. Do not provide user-controllable input to reflection functionality. Do not call symbol conversion on user-controllable input.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found user-controllable input to Ruby reflection functionality. This allows a remote user to influence runtime behavior, up to and including arbitrary remote code execution. Do not provide user-controllable input to reflection functionality. Do not call symbol conversion on user-controllable input.

Evidence about: V1.3.2

Known as: CWE-94: Improper Control of Generation of Code ('Code Injection')

### [high] Semgrep Finding: ruby.rails.security.injection.tainted-sql-string.tainted-sql-string

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 9

Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as ActiveRecord which will protect your queries.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as ActiveRecord which will protect your queries.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [high] Semgrep Finding: ruby.rails.security.injection.tainted-sql-string.tainted-sql-string

**Where:** `crates/sv-check/tests/fixtures/suppressed/brakeman-app/app/controllers/notes_controller.rb` line 3

Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as ActiveRecord which will protect your queries.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as ActiveRecord which will protect your queries.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

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

**Where:** `crates/sv-check/tests/adapters.rs` line 21

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 32

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 38

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 47

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 72

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 77

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 82

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 158

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 164

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 170

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 178

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 185

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 187

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 320

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 323

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 334

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 400

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 472

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 606

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 692

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 734

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 765

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 797

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 887

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 903

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 915

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/adapters.rs` line 917

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/aisvs.rs` line 22

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/aisvs.rs` line 131

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/aisvs.rs` line 145

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/aisvs.rs` line 147

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/citations.rs` line 94

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/citations.rs` line 179

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/citations.rs` line 270

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/citations.rs` line 362

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/citations.rs` line 365

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/citations.rs` line 437

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/citations.rs` line 542

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 13

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 42

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 48

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 69

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 75

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 81

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 105

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 112

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 138

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 144

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 160

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 161

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 167

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 189

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 194

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 196

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 257

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 258

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 260

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 278

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 287

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 301

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 304

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 342

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 344

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 351

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 354

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 522

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 529

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 546

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 547

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 555

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 569

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 572

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 587

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 703

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 705

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 742

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 747

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 752

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 762

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 793

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 798

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 806

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 823

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 824

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 833

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 855

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 856

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 864

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 879

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 880

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 888

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 900

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 901

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 909

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 923

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 925

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 927

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 930

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 940

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 941

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 949

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 960

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 961

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 969

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 981

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 982

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 990

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1007

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1008

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1016

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1028

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1029

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1037

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1051

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1052

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1060

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1075

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1076

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1084

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1095

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1096

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1104

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1338

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/clean_coverage.rs` line 1348

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 39

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 90

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 103

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 113

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 120

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 142

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 155

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 337

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/codeql.rs` line 352

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 18

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 19

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 60

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/human_checks.rs` line 264

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 29

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 31

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 37

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 38

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 40

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 61

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 74

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 87

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 99

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/own_output.rs` line 105

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suite.rs` line 14

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suite.rs` line 22

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 21

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 31

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 47

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 63

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 70

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 77

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 86

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 101

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 115

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 128

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 165

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 200

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 225

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 243

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 271

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 275

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 279

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 286

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 316

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 321

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 323

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 338

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/suppressed.rs` line 340

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 39

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 49

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 72

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 84

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 99

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 117

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 126

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 141

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 146

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 189

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 201

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 237

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 248

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 256

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 278

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 290

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-check/tests/unread_files.rs` line 309

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

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 12

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 31

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 61

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 62

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 70

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 78

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 86

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 99

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 116

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/appendix_c_section.rs` line 131

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/atlas_references.rs` line 12

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/atlas_references.rs` line 14

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/atlas_references.rs` line 19

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/atlas_references.rs` line 36

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/atlas_references.rs` line 45

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/atlas_references.rs` line 50

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/audit_deadlines.rs` line 18

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/audit_deadlines.rs` line 22

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/audit_deadlines.rs` line 27

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/audit_deadlines.rs` line 35

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/audit_deadlines.rs` line 42

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 26

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 40

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 45

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 46

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 47

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 52

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 53

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 54

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 59

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 64

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 69

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 70

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 71

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 76

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 431

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 436

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 437

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 491

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/bundle.rs` line 496

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/confirmations.rs` line 29

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/confirmations.rs` line 33

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/confirmations.rs` line 36

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/confirmations.rs` line 56

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/confirmations.rs` line 66

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/confirmations.rs` line 67

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/data_readme.rs` line 61

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/data_unanswered.rs` line 12

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/data_unanswered.rs` line 14

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/data_unanswered.rs` line 15

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/data_unanswered.rs` line 31

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/data_unanswered.rs` line 32

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/dependency_gap.rs` line 16

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/dependency_gap.rs` line 22

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/dependency_gap.rs` line 45

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/dependency_gap.rs` line 78

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/dependency_gap.rs` line 118

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/dependency_gap.rs` line 166

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_authorship.rs` line 44

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_authorship.rs` line 46

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_authorship.rs` line 57

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_authorship.rs` line 76

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_authorship.rs` line 86

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_authorship.rs` line 87

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_disclaimer.rs` line 26

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_disclaimer.rs` line 28

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_disclaimer.rs` line 33

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_disclaimer.rs` line 36

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_disclaimer.rs` line 70

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_disclaimer.rs` line 79

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/notes_disclaimer.rs` line 97

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/report_advisories.rs` line 16

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/report_advisories.rs` line 18

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/report_advisories.rs` line 27

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/report_advisories.rs` line 32

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/report_advisories.rs` line 37

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/report_advisories.rs` line 48

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/report_advisories.rs` line 81

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 23

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 38

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 42

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 56

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 59

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 61

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 67

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 73

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 76

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 88

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 103

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 110

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/rules.rs` line 121

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/run_status.rs` line 17

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/run_status.rs` line 19

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/run_status.rs` line 24

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/run_status.rs` line 46

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/run_status.rs` line 47

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/unanswered_questions.rs` line 39

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/unanswered_questions.rs` line 41

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/unanswered_questions.rs` line 48

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/unanswered_questions.rs` line 65

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 13

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 15

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 16

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 17

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 29

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 53

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-cli/tests/untaught_gap.rs` line 54

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

**Where:** `crates/sv-frameworks/tests/real_data.rs` line 772

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/tests/real_data.rs` line 780

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/tests/real_data.rs` line 794

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/tests/real_data.rs` line 795

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/tests/real_data.rs` line 802

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-frameworks/tests/real_data.rs` line 808

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

**Where:** `crates/sv-report/tests/report.rs` line 296

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/tests/report.rs` line 596

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/tests/report.rs` line 599

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/tests/report.rs` line 605

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/tests/threats.rs` line 349

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/tests/threats.rs` line 362

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/tests/threats.rs` line 364

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-report/tests/threats.rs` line 581

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

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 164

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 171

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 252

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 270

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 283

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 292

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 550

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 556

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 581

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 583

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 587

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 642

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 647

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 651

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 667

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 672

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 716

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 719

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 918

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 924

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 930

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1085

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1087

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1097

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1102

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1107

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1113

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1127

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1128

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1133

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1139

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1149

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1150

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1155

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1156

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1162

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1174

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1179

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1180

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1186

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1192

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1197

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1202

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1203

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1209

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1238

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1239

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1240

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1246

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1288

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1293

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1294

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1295

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1297

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1351

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1356

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1372

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1379

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1391

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `crates/sv-scan/tests/scan.rs` line 1475

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `tools/semgrep_rule_map.py` line 311

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `tools/semgrep_rule_map.py` line 372

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] A file is opened at a path built from a value

**Where:** `tools/semgrep_rule_map.py` line 387

A file path used to read, write or delete a file is built from a value rather than written out, so the file operation goes wherever that value points.

**Why it matters.** If any part of the path comes from a request, a name like ../../etc/passwd reads or overwrites a file outside the folder the app meant to use.

**What to do.** Keep user-submitted file names out of file paths: store files under names the app generates, and look them up by id. Where a submitted name has to be used, reduce it to a bare name (secure_filename in Flask, path.basename in Node) and check that the resolved path is still inside the folder it should be in.

Evidence about: V5.3.2

Known as: CWE-22, CWE-73

### [medium] The app redirects to a destination built from a value

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 23

A redirect sends the user to a destination that is built from a value rather than written out or produced from the app's own routes.

**Why it matters.** If the destination comes from the request, as a ?next= parameter usually does, a link on the app's own domain can send somebody to a lookalike sign-in page on another domain, and the address they clicked was genuine.

**What to do.** Redirect only to the app's own routes, built with its router (url_for, reverse, a Rails _path helper), or check the destination against a short list of allowed hosts. For a return-to address, accept only a path that starts with a single / and not //.

Evidence about: V3.7.2

Known as: CWE-601

### [medium] The app redirects to a destination built from a value

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 42

A redirect sends the user to a destination that is built from a value rather than written out or produced from the app's own routes.

**Why it matters.** If the destination comes from the request, as a ?next= parameter usually does, a link on the app's own domain can send somebody to a lookalike sign-in page on another domain, and the address they clicked was genuine.

**What to do.** Redirect only to the app's own routes, built with its router (url_for, reverse, a Rails _path helper), or check the destination against a short list of allowed hosts. For a return-to address, accept only a path that starts with a single / and not //.

Evidence about: V3.7.2

Known as: CWE-601

### [medium] A disallowed hash function is used

**Where:** `crates/sv-check/src/signed_in.rs` line 10944

MD5 or SHA-1 is used as a hash function. Both have practical collision attacks, and approved-hash rules disallow them for any cryptographic use.

**Why it matters.** Anything that relies on the hash to tell two things apart, or to prove something was not changed, can be fooled by somebody who builds a second input with the same hash. Used for passwords, both are also fast enough to guess through quickly.

**What to do.** Use SHA-256 or stronger for integrity and signatures, and a password hashing function (Argon2id, scrypt, bcrypt) for passwords. If this hash is only a cache key or a file checksum with no security purpose, say so where it is used; Python lets you pass usedforsecurity=False.

Evidence about: V11.4.1

Known as: CWE-328, CWE-327

### [medium] A disallowed hash function is used

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 46

MD5 or SHA-1 is used as a hash function. Both have practical collision attacks, and approved-hash rules disallow them for any cryptographic use.

**Why it matters.** Anything that relies on the hash to tell two things apart, or to prove something was not changed, can be fooled by somebody who builds a second input with the same hash. Used for passwords, both are also fast enough to guess through quickly.

**What to do.** Use SHA-256 or stronger for integrity and signatures, and a password hashing function (Argon2id, scrypt, bcrypt) for passwords. If this hash is only a cache key or a file checksum with no security purpose, say so where it is used; Python lets you pass usedforsecurity=False.

Evidence about: V11.4.1

Known as: CWE-328, CWE-327

### [medium] A disallowed hash function is used

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 56

MD5 or SHA-1 is used as a hash function. Both have practical collision attacks, and approved-hash rules disallow them for any cryptographic use.

**Why it matters.** Anything that relies on the hash to tell two things apart, or to prove something was not changed, can be fooled by somebody who builds a second input with the same hash. Used for passwords, both are also fast enough to guess through quickly.

**What to do.** Use SHA-256 or stronger for integrity and signatures, and a password hashing function (Argon2id, scrypt, bcrypt) for passwords. If this hash is only a cache key or a file checksum with no security purpose, say so where it is used; Python lets you pass usedforsecurity=False.

Evidence about: V11.4.1

Known as: CWE-328, CWE-327

### [medium] A disallowed hash function is used

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 20

MD5 or SHA-1 is used as a hash function. Both have practical collision attacks, and approved-hash rules disallow them for any cryptographic use.

**Why it matters.** Anything that relies on the hash to tell two things apart, or to prove something was not changed, can be fooled by somebody who builds a second input with the same hash. Used for passwords, both are also fast enough to guess through quickly.

**What to do.** Use SHA-256 or stronger for integrity and signatures, and a password hashing function (Argon2id, scrypt, bcrypt) for passwords. If this hash is only a cache key or a file checksum with no security purpose, say so where it is used; Python lets you pass usedforsecurity=False.

Evidence about: V11.4.1

Known as: CWE-328, CWE-327

### [medium] A disallowed hash function is used

**Where:** `tools/pwned_passwords.py` line 66

MD5 or SHA-1 is used as a hash function. Both have practical collision attacks, and approved-hash rules disallow them for any cryptographic use.

**Why it matters.** Anything that relies on the hash to tell two things apart, or to prove something was not changed, can be fooled by somebody who builds a second input with the same hash. Used for passwords, both are also fast enough to guess through quickly.

**What to do.** Use SHA-256 or stronger for integrity and signatures, and a password hashing function (Argon2id, scrypt, bcrypt) for passwords. If this hash is only a cache key or a file checksum with no security purpose, say so where it is used; Python lets you pass usedforsecurity=False.

Evidence about: V11.4.1

Known as: CWE-328, CWE-327

### [medium] Bandit reported B102

**Where:** `node_modules/railroad-diagrams/railroad_diagrams.py` line 427

Use of exec detected.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B102.

Known as: CWE-78

### [medium] Bandit reported B104

**Where:** `examples/notes-with-users/app.py` line 355

Possible binding to all interfaces.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B104.

Known as: CWE-605

### [medium] Bandit reported B104

**Where:** `examples/partly-passing/app.py` line 25

Possible binding to all interfaces.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B104.

Known as: CWE-605

### [medium] Bandit reported B104

**Where:** `examples/tested-notes/app.py` line 25

Possible binding to all interfaces.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B104.

Known as: CWE-605

### [medium] Bandit reported B108

**Where:** `examples/notes-with-users/app.py` line 18

Probable insecure usage of temp file/directory.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B108.

Known as: CWE-377

### [medium] Bandit reported B113

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.py` line 48

Call to requests without timeout

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B113.

Known as: CWE-400

### [medium] Bandit reported B113

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 47

Call to requests without timeout

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B113.

Known as: CWE-400

### [medium] Bandit reported B113

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 52

Call to requests without timeout

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B113.

Known as: CWE-400

### [medium] Bandit reported B301

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 32

Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B301.

Evidence about: V1.5.2

Known as: CWE-502

### [medium] Bandit reported B307

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 16

Use of possibly insecure function - consider using safer ast.literal_eval.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B307.

Evidence about: V1.3.2

Known as: CWE-78

### [medium] Bandit reported B310

**Where:** `tools/atlas_references.py` line 43

Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B310.

Known as: CWE-22

### [medium] Bandit reported B310

**Where:** `tools/pwned_passwords.py` line 78

Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B310.

Known as: CWE-22

### [medium] Bandit reported B314

**Where:** `crates/sv-scan/tests/fixtures/stdlib-xml-python/app.py` line 9

Using xml.etree.ElementTree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.fromstring with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B314.

Known as: CWE-20

### [medium] Bandit reported B314

**Where:** `examples/flask-booking/app.py` line 22

Using xml.etree.ElementTree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.fromstring with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B314.

Known as: CWE-20

### [medium] Bandit reported B506

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 37

Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B506.

Evidence about: V1.5.2

Known as: CWE-20

### [medium] Bandit reported B608

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 22

Possible SQL injection vector through string-based query construction.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B608.

Evidence about: V1.2.4

Known as: CWE-89

### [medium] Bandit reported B608

**Where:** `crates/sv-check/tests/fixtures/suppressed/bandit-app/blanket.py` line 2

Possible SQL injection vector through string-based query construction.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B608.

Evidence about: V1.2.4

Known as: CWE-89

### [medium] Bandit reported B608

**Where:** `crates/sv-check/tests/fixtures/suppressed/bandit-app/targeted.py` line 2

Possible SQL injection vector through string-based query construction.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B608.

Evidence about: V1.2.4

Known as: CWE-89

### [medium] npm in crates/sv-scan/tests/fixtures/unpinned-npm/ and Python in crates/sv-scan/tests/fixtures/unpinned-python/ and Ruby in crates/sv-check/tests/fixtures/suppressed/brakeman-app/ and Go in crates/sv-check/tests/fixtures/suppressed/gosec-app/ do not pin the versions they install

**Where:** `crates/sv-scan/tests/fixtures/unpinned-npm/package.json` line 1

`crates/sv-scan/tests/fixtures/unpinned-npm/package.json` is in use and there is no lockfile beside it, so the versions installed today and the versions installed tomorrow can differ.

**Why it matters.** The inventory of third-party libraries this app ships is then a list of what was asked for rather than what is installed, so nobody can say whether a known vulnerability applies to it — and a component that is compromised upstream arrives on the next install without anything changing here.

**What to do.** Install once and commit the lockfile that produces, then install from it from then on.

Evidence about: V15.1.2

Known as: CWE-1104

### [medium] Semgrep Finding: ai.ai-best-practices.agent-unbounded-loop.agent-unbounded-loop.agent-unbounded-loop-python

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.py` line 30

LLM API call inside a `while True` loop without a break condition. This creates an unbounded agent loop that may run indefinitely, consuming API credits and resources. Add a break condition, iteration counter, or timeout to prevent runaway execution.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** LLM API call inside a `while True` loop without a break condition. This creates an unbounded agent loop that may run indefinitely, consuming API credits and resources. Add a break condition, iteration counter, or timeout to prevent runaway execution.

Evidence about: C9.1.2

Known as: CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')

### [medium] Semgrep Finding: ai.ai-best-practices.mcp-credential-in-response.mcp-credential-in-response.mcp-credential-in-response-python

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.py` line 43

MCP tool returns a dictionary containing credential-like keys such as api_key, password, secret, or token. Exposing credentials in tool responses risks leaking them to the LLM context or logs. Remove sensitive fields before returning data from MCP tools.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** MCP tool returns a dictionary containing credential-like keys such as api_key, password, secret, or token. Exposing credentials in tool responses risks leaking them to the LLM context or logs. Remove sensitive fields before returning data from MCP tools.

Evidence about: C9.5.4

Known as: CWE-522: Insufficiently Protected Credentials

### [medium] Semgrep Finding: ai.ai-best-practices.mcp-unsanitized-return.mcp-unsanitized-return.mcp-unsanitized-return-python

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.py` line 49

External HTTP response data flows directly into an MCP tool return value without sanitization. Untrusted API responses may contain prompt injection payloads or malicious content that could manipulate the LLM. Sanitize or validate external data before returning it from MCP tools.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** External HTTP response data flows directly into an MCP tool return value without sanitization. Untrusted API responses may contain prompt injection payloads or malicious content that could manipulate the LLM. Sanitize or validate external data before returning it from MCP tools.

Evidence about: C10.4.2

Known as: CWE-116: Improper Encoding or Escaping of Output

### [medium] Semgrep Finding: ai.ai-best-practices.openai-missing-moderation.openai-missing-moderation.openai-missing-moderation

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.py` line 18

OpenAI chat completion used without content moderation. Consider using the Moderations API (client.moderations.create()) to check user input for harmful content before sending to the model.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** OpenAI chat completion used without content moderation. Consider using the Moderations API (client.moderations.create()) to check user input for harmful content before sending to the model.

Evidence about: C2.2.1

Known as: CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### [medium] Semgrep Finding: ai.ai-best-practices.openai-missing-moderation.openai-missing-moderation.openai-missing-moderation

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.py` line 30

OpenAI chat completion used without content moderation. Consider using the Moderations API (client.moderations.create()) to check user input for harmful content before sending to the model.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** OpenAI chat completion used without content moderation. Consider using the Moderations API (client.moderations.create()) to check user input for harmful content before sending to the model.

Evidence about: C2.2.1

Known as: CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')

### [medium] Semgrep Finding: go.lang.security.audit.crypto.math_random.math-random-used

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 10

Do not use `math/rand`. Use `crypto/rand` instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Do not use `math/rand`. Use `crypto/rand` instead.

Evidence about: V11.5.1

Known as: CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

### [medium] Semgrep Finding: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 28

`MinVersion` is missing from this TLS configuration.  By default, as of Go 1.22, TLS 1.2 is currently used as the minimum. General purpose web applications should default to TLS 1.3 with all other protocols disabled.  Only where it is known that a web server must support legacy clients with unsupported an insecure browsers (such as Internet Explorer 10), it may be necessary to enable TLS 1.0 to provide support. Add `MinVersion: tls.VersionTLS13' to the TLS configuration to bump the minimum version to TLS 1.3.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** `MinVersion` is missing from this TLS configuration.  By default, as of Go 1.22, TLS 1.2 is currently used as the minimum. General purpose web applications should default to TLS 1.3 with all other protocols disabled.  Only where it is known that a web server must support legacy clients with unsupported an insecure browsers (such as Internet Explorer 10), it may be necessary to enable TLS 1.0 to provide support. Add `MinVersion: tls.VersionTLS13' to the TLS configuration to bump the minimum version to TLS 1.3.

Evidence about: V12.1.1

Known as: CWE-327: Use of a Broken or Risky Cryptographic Algorithm

### [medium] Semgrep Finding: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-DES

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 19

Detected DES cipher algorithm which is insecure. The algorithm is considered weak and has been deprecated. Use AES instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected DES cipher algorithm which is insecure. The algorithm is considered weak and has been deprecated. Use AES instead.

Evidence about: V11.3.2

Known as: CWE-327: Use of a Broken or Risky Cryptographic Algorithm

### [medium] Semgrep Finding: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-md5

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 20

Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

Evidence about: V11.4.1

Known as: CWE-328: Use of Weak Hash

### [medium] Semgrep Finding: go.lang.security.audit.database.string-formatted-query.string-formatted-query

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 15

String-formatted SQL query detected. This could lead to SQL injection if the string is not sanitized properly. Audit this call to ensure the SQL is not manipulable by external data.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** String-formatted SQL query detected. This could lead to SQL injection if the string is not sanitized properly. Audit this call to ensure the SQL is not manipulable by external data.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [medium] Semgrep Finding: go.lang.security.audit.database.string-formatted-query.string-formatted-query

**Where:** `crates/sv-check/tests/fixtures/suppressed/gosec-app/main.go` line 9

String-formatted SQL query detected. This could lead to SQL injection if the string is not sanitized properly. Audit this call to ensure the SQL is not manipulable by external data.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** String-formatted SQL query detected. This could lead to SQL injection if the string is not sanitized properly. Audit this call to ensure the SQL is not manipulable by external data.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [medium] Semgrep Finding: javascript.express.security.audit.xss.direct-response-write.direct-response-write

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.js` line 21

Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

Evidence about: V1.2.1

Known as: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### [medium] Semgrep Finding: javascript.express.security.audit.xss.direct-response-write.direct-response-write

**Where:** `crates/sv-check/tests/fixtures/semgrep-aisvs/app/assistant.js` line 30

Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

Evidence about: V1.2.1

Known as: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### [medium] Semgrep Finding: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/main.go` line 28

Checks for disabling of TLS/SSL certificate verification. This should only be used for debugging purposes because it leads to vulnerability to MTM attacks.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Checks for disabling of TLS/SSL certificate verification. This should only be used for debugging purposes because it leads to vulnerability to MTM attacks.

Evidence about: V12.3.2

Known as: CWE-319: Cleartext Transmission of Sensitive Information

### [medium] Semgrep Finding: python.django.security.injection.code.user-eval.user-eval

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 16

Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need.

Evidence about: V1.3.2

Known as: CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

### [medium] Semgrep Finding: python.django.security.injection.path-traversal.path-traversal-join.path-traversal-join

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 60

Data from request is passed to os.path.join() and to open(). This is a path traversal vulnerability, which can lead to sensitive data being leaked. To mitigate, consider using os.path.abspath or os.path.realpath or Path library.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Data from request is passed to os.path.join() and to open(). This is a path traversal vulnerability, which can lead to sensitive data being leaked. To mitigate, consider using os.path.abspath or os.path.realpath or Path library.

Evidence about: V5.3.2

Known as: CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### [medium] Semgrep Finding: python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 21

User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection. For example, you could use `Entry.objects.filter(date=2006)`.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection. For example, you could use `Entry.objects.filter(date=2006)`.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [medium] Semgrep Finding: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected

**Where:** `tools/atlas_references.py` line 43

Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead.

Known as: CWE-939: Improper Authorization in Handler for Custom URL Scheme

### [medium] Semgrep Finding: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected

**Where:** `tools/pwned_passwords.py` line 78

Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead.

Known as: CWE-939: Improper Authorization in Handler for Custom URL Scheme

### [medium] Semgrep Finding: python.lang.security.audit.eval-detected.eval-detected

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 16

Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

Evidence about: V1.3.2

Known as: CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

### [medium] Semgrep Finding: python.lang.security.audit.formatted-sql-query.formatted-sql-query

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 22

Detected possible formatted SQL query. Use parameterized queries instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected possible formatted SQL query. Use parameterized queries instead.

Evidence about: V1.2.4

Known as: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### [medium] Semgrep Finding: python.lang.security.deserialization.pickle.avoid-pickle

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 32

Avoid using `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data as JSON or a similar text-based serialization format.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Avoid using `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data as JSON or a similar text-based serialization format.

Evidence about: V1.5.2

Known as: CWE-502: Deserialization of Untrusted Data

### [medium] Semgrep Finding: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1

**Where:** `tools/pwned_passwords.py` line 66

Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

Evidence about: V11.4.1

Known as: CWE-327: Use of a Broken or Risky Cryptographic Algorithm

### [medium] Semgrep Finding: ruby.lang.security.dangerous-exec.dangerous-exec

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 13

Detected non-static command inside system. Audit the input to 'system'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected non-static command inside $EXEC. Audit the input to '$EXEC'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

Evidence about: V1.2.5

Known as: CWE-94: Improper Control of Generation of Code ('Code Injection')

### [medium] Semgrep Finding: ruby.lang.security.dangerous-subshell.dangerous-subshell

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 14

Detected non-static command inside `...`. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected non-static command inside `...`. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

Evidence about: V1.2.5

Known as: CWE-94: Improper Control of Generation of Code ('Code Injection')

### [medium] Semgrep Finding: ruby.lang.security.force-ssl-false.force-ssl-false

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/config/environments/production.rb` line 2

Checks for configuration setting of force_ssl to false. Force_ssl forces usage of HTTPS, which could lead to network interception of unencrypted application traffic. To fix, set config.force_ssl = true.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Checks for configuration setting of force_ssl to false. Force_ssl forces usage of HTTPS, which could lead to network interception of unencrypted application traffic. To fix, set config.force_ssl = true.

Known as: CWE-311: Missing Encryption of Sensitive Data

### [medium] Semgrep Finding: ruby.lang.security.insufficient-rsa-key-size.insufficient-rsa-key-size

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 65

The RSA key size 1024 is insufficent by NIST standards. It is recommended to use a key length of 2048 or higher.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** The RSA key size $SIZE is insufficent by NIST standards. It is recommended to use a key length of 2048 or higher.

Evidence about: V11.2.3

Known as: CWE-326: Inadequate Encryption Strength

### [medium] Semgrep Finding: ruby.lang.security.no-eval.ruby-eval

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 32

Use of eval with user-controllable input detected. This can lead  to attackers running arbitrary code. Ensure external data does not  reach here, otherwise this is a security vulnerability. Consider  other ways to do this without eval.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Use of eval with user-controllable input detected. This can lead  to attackers running arbitrary code. Ensure external data does not  reach here, otherwise this is a security vulnerability. Consider  other ways to do this without eval.

Evidence about: V1.3.2

Known as: CWE-94: Improper Control of Generation of Code ('Code Injection')

### [medium] Semgrep Finding: ruby.lang.security.ssl-mode-no-verify.ssl-mode-no-verify

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 52

Detected SSL that will accept an unverified connection. This makes the connections susceptible to man-in-the-middle attacks. Use 'OpenSSL::SSL::VERIFY_PEER' instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Detected SSL that will accept an unverified connection. This makes the connections susceptible to man-in-the-middle attacks. Use 'OpenSSL::SSL::VERIFY_PEER' instead.

Evidence about: V12.3.2

Known as: CWE-295: Improper Certificate Validation

### [medium] Semgrep Finding: ruby.lang.security.unprotected-mass-assign.mass-assignment-vuln

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 61

Checks for calls to without_protection during mass assignment (which allows record creation from hash values). This can lead to users bypassing permissions protections. For Rails 4 and higher, mass protection is on by default. Fix: Don't use :without_protection => true. Instead, configure attr_accessible to control attribute access.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Checks for calls to without_protection during mass assignment (which allows record creation from hash values). This can lead to users bypassing permissions protections. For Rails 4 and higher, mass protection is on by default. Fix: Don't use :without_protection => true. Instead, configure attr_accessible to control attribute access.

Evidence about: V15.3.3

Known as: CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

### [medium] Semgrep Finding: ruby.lang.security.weak-hashes-md5.weak-hashes-md5

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 46

Should not use md5 to generate hashes. md5 is proven to be vulnerable through the use of brute-force attacks. Could also result in collisions, leading to potential collision attacks. Use SHA256 or other hashing functions instead.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Should not use md5 to generate hashes. md5 is proven to be vulnerable through the use of brute-force attacks. Could also result in collisions, leading to potential collision attacks. Use SHA256 or other hashing functions instead.

Evidence about: V11.4.1

Known as: CWE-328: Use of Weak Hash

### [medium] Semgrep Finding: ruby.rails.security.audit.avoid-tainted-file-access.avoid-tainted-file-access

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 19

Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.

Evidence about: V5.3.2

Known as: CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### [medium] Semgrep Finding: ruby.rails.security.audit.xss.avoid-redirect.avoid-redirect

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 23

When a redirect uses user input, a malicious user can spoof a website under a trusted URL or access restricted parts of a site. When using user-supplied values, sanitize the value before using it for the redirect.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** When a redirect uses user input, a malicious user can spoof a website under a trusted URL or access restricted parts of a site. When using user-supplied values, sanitize the value before using it for the redirect.

Evidence about: V3.7.2

Known as: CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### [medium] Semgrep Finding: ruby.rails.security.audit.xss.avoid-render-inline.avoid-render-inline

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 41

'render inline: ...' renders an entire ERB template inline and is dangerous. If external data can reach here, this exposes your application to server-side template injection (SSTI) or cross-site scripting (XSS) attacks. Instead, consider using a partial or another safe rendering method.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** 'render inline: ...' renders an entire ERB template inline and is dangerous. If external data can reach here, this exposes your application to server-side template injection (SSTI) or cross-site scripting (XSS) attacks. Instead, consider using a partial or another safe rendering method.

Evidence about: V1.2.1

Known as: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### [medium] Semgrep Finding: ruby.rails.security.brakeman.check-redirect-to.check-redirect-to

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 23

Found potentially unsafe handling of redirect behavior params[:url]. Do not pass `params` to `redirect_to` without the `:only_path => true` hash value.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found potentially unsafe handling of redirect behavior $X. Do not pass `params` to `redirect_to` without the `:only_path => true` hash value.

Evidence about: V3.7.2

Known as: CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

### [medium] Semgrep Finding: ruby.rails.security.brakeman.check-render-local-file-include.check-render-local-file-include

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 41

Found request parameters in a call to `render`. This can allow end users to request arbitrary local files which may result in leaking sensitive information persisted on disk. Where possible, avoid letting users specify template paths for `render`. If you must allow user input, use an allow-list of known templates or normalize the user-supplied value with `File.basename(...)`.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found request parameters in a call to `render`. This can allow end users to request arbitrary local files which may result in leaking sensitive information persisted on disk. Where possible, avoid letting users specify template paths for `render`. If you must allow user input, use an allow-list of known templates or normalize the user-supplied value with `File.basename(...)`.

Evidence about: V5.3.2

Known as: CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### [medium] Semgrep Finding: ruby.rails.security.brakeman.check-render-local-file-include.check-render-local-file-include

**Where:** `crates/sv-check/tests/fixtures/brakeman/app/app/controllers/users_controller.rb` line 42

Found request parameters in a call to `render`. This can allow end users to request arbitrary local files which may result in leaking sensitive information persisted on disk. Where possible, avoid letting users specify template paths for `render`. If you must allow user input, use an allow-list of known templates or normalize the user-supplied value with `File.basename(...)`.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** Found request parameters in a call to `render`. This can allow end users to request arbitrary local files which may result in leaking sensitive information persisted on disk. Where possible, avoid letting users specify template paths for `render`. If you must allow user input, use an allow-list of known templates or normalize the user-supplied value with `File.basename(...)`.

Evidence about: V5.3.2

Known as: CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### [low] Bandit reported B101

**Where:** `node_modules/railroad-diagrams/railroad_diagrams.py` line 177

Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B101.

Known as: CWE-703

### [low] Bandit reported B101

**Where:** `node_modules/railroad-diagrams/railroad_diagrams.py` line 190

Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B101.

Known as: CWE-703

### [low] Bandit reported B101

**Where:** `tools/atlas_references.py` line 38

Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B101.

Known as: CWE-703

### [low] Bandit reported B101

**Where:** `tools/pwned_passwords.py` line 71

Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B101.

Known as: CWE-703

### [low] Bandit reported B105

**Where:** `examples/notes-with-users/app.py` line 123

Possible hardcoded password: ''

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B105.

Evidence about: V13.3.1

Known as: CWE-259

### [low] Bandit reported B112

**Where:** `tools/semgrep_rule_map.py` line 312

Try, Except, Continue detected.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B112.

Known as: CWE-703

### [low] Bandit reported B403

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 4

Consider possible security implications associated with pickle module.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B403.

Known as: CWE-502

### [low] Bandit reported B404

**Where:** `crates/sv-check/tests/fixtures/semgrep/app/app.py` line 5

Consider possible security implications associated with the subprocess module.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B404.

Known as: CWE-78

### [low] Bandit reported B404

**Where:** `crates/sv-check/tests/fixtures/suppressed/semgrep-app/app.py` line 1

Consider possible security implications associated with the subprocess module.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B404.

Known as: CWE-78

### [low] Bandit reported B404

**Where:** `tools/image_smoke.py` line 33

Consider possible security implications associated with the subprocess module.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B404.

Known as: CWE-78

### [low] Bandit reported B404

**Where:** `tools/semgrep_packs.py` line 25

Consider possible security implications associated with the subprocess module.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B404.

Known as: CWE-78

### [low] Bandit reported B404

**Where:** `tools/semgrep_rule_map.py` line 33

Consider possible security implications associated with the subprocess module.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B404.

Known as: CWE-78

### [low] Bandit reported B405

**Where:** `crates/sv-scan/tests/fixtures/stdlib-xml-python/app.py` line 1

Using xml.etree.ElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B405.

Known as: CWE-20

### [low] Bandit reported B405

**Where:** `examples/flask-booking/app.py` line 3

Using xml.etree.ElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B405.

Known as: CWE-20

### [low] Bandit reported B406

**Where:** `examples/partly-passing/run_tests.py` line 12

Using quoteattr to parse untrusted XML data is known to be vulnerable to XML attacks. Replace quoteattr with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B406.

Known as: CWE-20

### [low] Bandit reported B603

**Where:** `tools/image_smoke.py` line 66

subprocess call - check for execution of untrusted input.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B603.

Evidence about: V1.2.5

Known as: CWE-78

### [low] Bandit reported B603

**Where:** `tools/image_smoke.py` line 67

subprocess call - check for execution of untrusted input.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B603.

Evidence about: V1.2.5

Known as: CWE-78

### [low] Bandit reported B603

**Where:** `tools/image_smoke.py` line 68

subprocess call - check for execution of untrusted input.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B603.

Evidence about: V1.2.5

Known as: CWE-78

### [low] Bandit reported B603

**Where:** `tools/image_smoke.py` line 82

subprocess call - check for execution of untrusted input.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B603.

Evidence about: V1.2.5

Known as: CWE-78

### [low] Bandit reported B603

**Where:** `tools/image_smoke.py` line 177

subprocess call - check for execution of untrusted input.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B603.

Evidence about: V1.2.5

Known as: CWE-78

### [low] Bandit reported B603

**Where:** `tools/semgrep_packs.py` line 57

subprocess call - check for execution of untrusted input.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B603.

Evidence about: V1.2.5

Known as: CWE-78

### [low] Bandit reported B603

**Where:** `tools/semgrep_rule_map.py` line 341

subprocess call - check for execution of untrusted input.

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B603.

Evidence about: V1.2.5

Known as: CWE-78

### [low] Bandit reported B607

**Where:** `tools/image_smoke.py` line 177

Starting a process with a partial executable path

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B607.

Known as: CWE-78

### [low] Bandit reported B607

**Where:** `tools/semgrep_packs.py` line 57

Starting a process with a partial executable path

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B607.

Known as: CWE-78

### [low] Bandit reported B607

**Where:** `tools/semgrep_rule_map.py` line 341

Starting a process with a partial executable path

**Why it matters.** Reported by Bandit, which reads python the way its own community has learned to.

**What to do.** See Bandit's documentation for rule B607.

Known as: CWE-78

### [low] Semgrep Finding: javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage

**Where:** `crates/sv-scan/tests/fixtures/node-websockets/server.js` line 2

A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.

Known as: CWE-352: Cross-Site Request Forgery (CSRF)

### [low] Semgrep Finding: javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage

**Where:** `crates/sv-scan/tests/fixtures/pinned-clean/server.js` line 2

A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.

**Why it matters.** Reported by Semgrep, which reads code the way its own community has learned to.

**What to do.** A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.

Known as: CWE-352: Cross-Site Request Forgery (CSRF)

