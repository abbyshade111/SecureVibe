# A passphrase unless you say none (9 October 2026)


Gap analysis of 7 October 2026, finding 22(a) (`docs/GAP-ANALYSIS.md`, 4.6); ADR-043, "Later, 9 October 2026".

**The gap.** A seal on an answer shows it was recorded through `sv review`, which needs a terminal someone is typing
in. A key with no passphrase does not show who typed: anything that can run as the owner can run `sv review` with a
pretend terminal, and the AI coding tool runs as the owner. The passphrase is the one step the tool cannot take for
them. `sv review` offered it with Enter meaning "none", and a report could not tell a seal made either way apart.

**What changed.**

- Making the key, `sv review` asks "Protect the key with a passphrase? Press Enter to choose one, or type `none` for
  none." `none`, `no`, and `n` go without; anything else, Enter included, asks for the passphrase twice, unseen. It
  tells the person, before asking, that without one every entry the key signs says so in the report.
- A signed seal that counts (`Sealed::Signed`) carries `lock`: `passphrase`, `no-passphrase`, or `not-here`. The
  checker reads this computer's signing key file once, when it is made, and keeps only its fingerprint and whether
  it is locked. A seal whose key has that fingerprint gets `passphrase` or `no-passphrase`; any other, including
  every seal checked on CI from `SV_TRUSTED_SEALS`, gets `not-here`.
- Every place an entry's seal is worded adds it in brackets after "which … trusts for this app": the false alarms and
  accepted risks set aside (`sv-report`), the answers you confirmed (`confirm.rs`), and the "you answered yes" lines
  of security notes, hand checks, and design answers (`seal::recorded_where`). All three now word a signed seal
  through one function, `seal::signed_with`, so none can leave the passphrase out.

**What it does not do.** It counts nothing differently: a seal made without a passphrase still counts, as the owner
chose on 6 October. It cannot tell CI whether the key had a passphrase, since the seal does not carry it and a field
the signer writes about itself would be the signer's word. A key made before today is left as it is; the report now
says which kind it is.

**Held by** `crates/sv-check/tests/seal_key_lock.rs` (each of the three, and another key on this computer saying
nothing about the one that signed) and `crates/sv-cli/src/review/passphrase_tests.rs` (Enter and `yes` choose a
passphrase; `none`, `No`, and ` n ` do not), and end to end in `crates/sv-cli/tests/review_terminal.rs`, which now
checks the whole sentence in the report on this computer and on CI. The tests that run `sv review` in a terminal
for the first time type `none` where they pressed Enter.

**Broken on purpose**, six ways, one at a time: this computer's key never read (four tests red, across
`seal_key_lock.rs`, the signed-seal unit test, and `review_terminal.rs`); the key here taken for the signer without
comparing fingerprints (two, one each way round); a locked key read as plain (two, one in each crate); the passphrase
left out of the wording (four); Enter meaning none again (two); and only `none` accepted for none (one test, which
types `No` and ` n ` and fails on both). The second and third first went red in one test each, and each got a second
test before this was written.
