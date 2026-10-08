# `sv review`: what a person records is sealed (4 October 2026)

The deep review's R1, second fix, as the owner decided the same day. Until now an entry in securevibe.toml that set a
finding aside (`[[finding-review]]`), or confirmed what the AI coding tool said (`confirmed` under `[design]` or
`[checked-by-hand]`), counted whenever its `by` named someone other than the tool. The first fix made the reports say so
honestly. This one makes the difference count: **an entry counts only when `sv review` recorded it.**

- **`sv review [PATH]`** runs only when what it reads and what it writes are both a terminal, which an AI coding tool
  running a command does not have. It goes through every entry that does not count on this computer, shows what is being
  decided (the finding's rule, file, and line of code, found by its fingerprint; the answer or result being confirmed),
  and asks for the person's name or `owner`. They can type `edit` to put the reason, or what they looked at, in their own
  words. It refuses the AI coding tool's name, a reason under the length the report requires, and a confirmation that
  says nothing about what was looked at.
- **What it records is written back into securevibe.toml**, through `toml_edit`, so comments and layout stay: `by`, `on`,
  the reason, and a `seal`. A confirmation records the answer and `where` (or the result) that were shown, not what the
  proposal said. After each write the file is read back, and if the entry would not count the file is put back as it was.
- **The seal** (`sv-check/src/seal.rs`) is HMAC-SHA-256 over every field of the entry, each prefixed by its length, under
  a 32-byte key from `/dev/urandom` kept at `~/.config/securevibe/review-key` (or under `XDG_CONFIG_HOME`), outside the
  app's folder. The folder is made readable by its owner only, the file with a call that fails on anything already there.
  A seal is `v1:<key id>:<mac>`; the key id is 16 hex characters of a hash of the key, so the key is never shown.
- **Where it is checked.** On the computer that holds the key, a seal that does not match (anything in the entry changed
  afterwards, or the seal made up) is a proposal, and so is a seal made with another key: this computer cannot check it,
  and a made-up seal naming a key that is not here would look the same. On a computer with no key at all, such as CI, a
  sealed entry counts, as the owner decided, and the report says the seal was sealed on another computer and could not
  be checked. Something in the key's place that cannot be used makes every entry a proposal.
- **The reports** say "Recorded through `sv review` on this computer: the owner set it aside as a false alarm on (date)",
  or, where unchecked, "securevibe.toml says … through `sv review`, sealed on another computer; this one has no key to
  check the seal with". The section opens by saying what a seal shows (how an entry was recorded, and that it has not
  changed) and what it cannot (who was at the keyboard). Entries that do not count say how to make them count: run
  `sv review` in your own terminal. The MCP output tells the AI coding tool to write proposals with `by = "ai-tool"`,
  never to run `sv review` for the person, and never to write a `seal` or a person's name.
- **What it shows is kept safe.** A line is never shown for a rule about keys or passwords, or when the secrets scanner
  finds anything in it; a file named with `..` or an absolute path is never read.

What it does not do, said in the code and the README: the AI coding tool runs as the person, so a tool set on faking
it could read the key or fake a terminal. The seal stops the easy path, one line in a file the tool is already editing,
and makes the hard path a deliberate act. Entries made before this change count only once recorded through `sv review`.

Twenty-one guards undone in turn; see the pull request for what caught each.
