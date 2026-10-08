# Seals become signatures (6 October 2026)

The owner chose SSH signing for `sv review` (ADR-043, after the Kaspa research in BACKLOG), and took every
recommendation in the plan they were walked through.

- **`sv review` makes a signing key of its own**, `~/.config/securevibe/review-signing-key` (or under
  `XDG_CONFIG_HOME`), an Ed25519 key in OpenSSH's own format, with its public half beside it as `ssh-keygen` writes
  one. The first time, it asks whether to protect the key with a passphrase; with one, it asks for it, without showing
  it, each time it runs, and three wrong ones stop it with nothing recorded. The folder is readable by its owner only,
  and the file is made with a call that fails on anything already there.
- **It puts the app on a list of trusted keys**, `allowed_signers` beside the key, in OpenSSH's own format: the app's
  id (16 hex characters of a SHA-256 of its folder, as before) as the principal, `namespaces="securevibe-review"`, and
  the public key. When it adds a line it shows it, with where to put it for CI: the variable `SV_TRUSTED_SEALS`, from a
  repository variable. The line is the public half, and the private half is never shown.
- **A seal is `v3:<app id>:<signature>`**, an SSH signature under the namespace `securevibe-review`, written in hex,
  over the same fields as before, each with its length first, behind a domain of its own (`sv review seal v3`), so no
  seal of another kind can stand for one.
- **Where it counts** (`sv-check/src/signed.rs`). A report reads `SV_TRUSTED_SEALS` when it is set and not empty, and
  otherwise the list beside the key. A signed entry counts when the list names the key that signed it for the app id
  in the seal, and the signature holds. On this computer's own list the app id must also be this folder's, so an answer
  copied into another app on this computer is a proposal there, as before; on SV_TRUSTED_SEALS the list's own lines say
  which apps count, since CI's folder is never the one it was recorded in. Two apps in one repository share one CI list,
  so on CI an answer copied from one into the other counts. A list `sv` cannot read in full trusts nothing.
- **The reports name the key and the list:** "Recorded through `sv review` and signed with key SHA256:…, which this
  computer's list of trusted keys trusts for this app: the owner set it aside as a false alarm on (date)". An entry that
  does not count says why: no list here (and to set SV_TRUSTED_SEALS to the line `sv review` showed), a key the list
  does not name, a key trusted for another app only, a list that cannot be read, or a signature that does not match.
- **Seals made with `review-key`** (`v2:`) still count on the computer that holds it. `sv review` there lists them,
  says they count here only, and asks one yes to sign them all again; each is signed over what it says now, which is
  what its old seal held for, and only the seal line changes.
- **What it cannot show**, said above the false alarms in every report: who was at the keyboard, unless the key has a
  passphrase; and that a trusted key is the owner's, since whoever can change the list, or the repository variable,
  can add one.
- **`ssh-keygen` checks a seal on its own**: a test writes a seal's signature out as OpenSSH's signature file and runs
  `ssh-keygen -Y verify` with the same list, the app id as the identity.
- **OpenSSH's formats are written here, over `ed25519-dalek`** (`sv-check/src/ssh_format.rs`), not by the `ssh-key`
  library: it put an RSA crate with an unfixed advisory (RUSTSEC-2023-0071) into `Cargo.lock`, which `sv`'s audit of
  its own crates refuses, though `sv` never compiled it, and the owner chose this over accepting the advisory. Only
  Ed25519, a key file plain or locked as `ssh-keygen` locks one, and `SSHSIG` signatures, each read strictly. Tests
  have `ssh-keygen` read the key `sv` makes, plain and locked, and `sv` read the keys `ssh-keygen` makes and check its
  signatures.

Broken on purpose nineteen ways, one at a time, after the move to `ed25519-dalek`: the signature not checked, the folder not checked on this computer's list, the list's app ids ignored, its keys ignored, its namespaces ignored, an option it does not read accepted, the app id left out of what is signed, older seals not offered for signing again, the app not put on the list, the passphrase not kept, the key file readable by others, SV_TRUSTED_SEALS not read by the report, the variable read only where there is no folder, the report not saying what to do, and, in the key file, the seed not checked against the public half and the padding not checked: each of these sixteen went red in two tests or more, after a second test was written for each one first caught by one. Three went otherwise, and are second checks, not the guard: the key file's two check numbers not compared (one test red; a wrong passphrase is still refused by the checks after them), the signature's namespace not compared, and the key file's inner public half not compared (none red: the namespace is part of what is signed, so the signature itself fails, and the seed's own check refuses the same key). Not tested: that the terminal hides the passphrase as it is typed, which needs a person's terminal. Not tried on a real CI run with a repository variable.
