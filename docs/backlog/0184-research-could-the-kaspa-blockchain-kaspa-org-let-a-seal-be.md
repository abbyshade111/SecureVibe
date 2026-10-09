# Research: could the Kaspa blockchain (kaspa.org) let a seal be checked beyond one person on one computer?

**Status:** done, 9 October 2026

Asked by the owner on 6 October 2026. Today `sv review` seals what a person records with an HMAC key kept in
`~/.config/securevibe/review-key` (ADR-026), and only a computer holding that same key can check a seal. On CI,
another computer, or a teammate's, a sealed answer is not counted as the owner's, and the report says it could not be
checked there (the owner's decision on item 8 of the review of 1 to 4 October). Several people, or one person on two
computers, cannot share a record that each can check. The research is whether, and how, Kaspa could fix that, and
what it would cost against the alternatives. Nothing is built from it without the owner's decision.
**Open to input from several sessions at once, at the owner's word** ("I'm good with multiple sessions providing
input on this one"). This item is the exception to claiming first: each session adds its findings as a dated note
below, signed with its session name, and reads the notes already there so as not to repeat them. Building anything
still needs a claim and the owner's decision.
Questions to answer, each with its source (Kaspa's own documentation at kaspa.org and its GitHub repositories, read
and cited rather than remembered):
1. **What Kaspa offers that bears on this.** How Kaspa records data in a transaction (a payload, or only payments),
   how long a record stays retrievable (whether nodes prune old data, and what an archival node keeps), how quickly
   a record settles, and what a record costs in fees and in KAS that has to be bought and held.
2. **What a blockchain would and would not fix.** The per-computer limit comes from the seal being a shared secret
   (HMAC): checking one needs the key that made it. A chain could publish a key, or a seal's hash and time, where
   anyone can read them. It cannot show that a person, rather than an AI coding tool with the same access, made a
   seal, which is what ADR-026 rests on (a terminal the tool does not have). Say which of these a chain helps with.
3. **The alternatives without a chain**, compared on the same questions: a public-key signature (Ed25519, say) with
   each person's public key committed in the app's repository, so any computer can check a seal and only the person
   can make one; SSH or GPG signing keys people already have; Sigstore's keyless signing and its public transparency
   log. If one of these fixes the limit without a network connection, a dependency on a chain, or money, say so
   plainly.
4. **What it would cost `sv`'s rules.** `sv` opens no network connection of its own apart from `sv probe`
   (CLAUDE.md, ADR-027): checking a seal against a chain would be a second exception, or the check would read data
   the person downloads, as advisory data is now. Holding KAS spends the owner's money. A new crate is a dependency.
   Each is a decision for the owner, and the research says which ones any design would need.
5. **A recommendation**, with what it rests on, for the owner to decide: Kaspa, another approach, or keeping the
   record per computer.

**Note, 6 October 2026, session securevibe-e10.** The first findings. A read-only research agent read the sources
below; this session opened KIP-14, Kaspa's payload page, and the `ssh-keygen` manual itself and found them as quoted.
"Read" is what a source says; "inferred" is reasoning from it.
1. **What Kaspa offers.**
   - *Data in a transaction:* since the Crescendo hard fork (5 May 2025, which also moved the network from 1 to 10
     blocks a second), a native transaction may carry "arbitrary data in the payload field" (read: KIP-14,
     github.com/kaspanet/kips, `kip-0014.md`; rusty-kaspa's README). For ordinary acceptance "the practical limit is
     about 25 KB if the payload dominates the transaction" (read: docs.kaspa.org, "Transaction payload"). A seal's
     hash or a public key fits many times over (inferred).
   - *How long it stays:* KIP-14 suggests "rounding this up to 30 hours" for the pruning period, so an ordinary node
     forgets a transaction after about 30 hours (read; rusty-kaspa's `consensus/core/src/config/params.rs` agrees, as
     the agent read it). Only an archival node (`--archival`, "heavy disk usage", kaspa.aspectron.org) or a
     third-party indexer keeps it, so checking a seal later needs one of those (inferred).
   - *How fast it settles:* finality depth is "a 12-hour duration at 10 bps" (read: KIP-14). A first confirmation in
     seconds is likely but was **not confirmed** in a primary source (the page for it returned 404).
   - *Cost:* the default minimum relay fee is 100 sompi per gram of mass (read: rusty-kaspa,
     `mining/src/mempool/config.rs`), and mass is the larger of compute and storage mass (kaspa.aspectron.org,
     fees). A small transaction would cost a few thousandths of a KAS (inferred, **not confirmed**). The fee comes
     from the sender's own coins, so publishing means buying KAS and keeping a wallet on the computer (inferred).
2. **What a chain would and would not fix** (inferred). It gives a public, dated record anyone can read: a public
   key, or a seal's hash. It **cannot** show who made a seal: a wallet key on the owner's computer is as usable by an
   AI coding tool running as the owner as `review-key` is, which is ADR-026's own limit ("not who was at the
   keyboard"). It **cannot** tell a checking computer which key is the owner's: a key published on the chain is
   trusted only if the checker already trusts the wallet that published it, so a list of trusted keys is still
   needed. And it **cannot** keep a record readable on its own, past about 30 hours, without an archival node. The one
   thing it adds beyond a public-key signature is a time nobody can backdate.
3. **Without a chain.**
   - *Ed25519 signatures,* each person's public key listed somewhere a checker trusts: any computer checks offline,
     and only the private key's holder signs (inferred). Rust: `ed25519-dalek` (crates.io, BSD-3-Clause).
   - *SSH signatures,* with keys people already have: `ssh-keygen -Y sign` and `ssh-keygen -Y verify` with an
     `allowed_signers_file` and a namespace (read: the OpenBSD `ssh-keygen` manual; checked by this session). Anyone
     can check one with `ssh-keygen` alone. Rust: the `ssh-key` crate's `SshSig`, "ala `ssh-keygen -Y sign`/`-Y
     verify`" (read: docs.rs, `ssh-key`, with its `ed25519` feature; Apache-2.0 or MIT).
   - *Sigstore keyless signing:* free, but signing needs an identity provider (GitHub, Google) and the network, and
     publishes the signer's identity in a public log; checking can be offline with its bundle format (read:
     docs.sigstore.dev, "Security", "Overview", "Verifying"). No Rust crate was looked at.
   - *In every design,* the list of trusted keys is the weak point: if the AI coding tool can edit it in the
     repository, it can add a key of its own. It has to live where the tool cannot write (a CI setting, a file in the
     person's own home folder), or every change to it has to be flagged (inferred).
4. **What each would cost `sv`'s rules.** `Cargo.lock` holds `hmac` and `sha2` and no signature crate today.
   - *Kaspa:* a second exception to "no network of its own" (a node or indexer to publish, archival access to
     check), the owner's money (KAS for every seal), and a Kaspa client and wallet as dependencies (not sized).
   - *Ed25519:* no network, no money, one crate (`ed25519-dalek`).
   - *SSH signatures:* no network, no money, one crate (`ssh-key`).
   - *Sigstore:* the network to sign, an account, and a public record of who signed; crates not sized.
5. **Recommendation, for the owner to decide:** not Kaspa. SSH-format Ed25519 signatures (`ssh-key`) would let any
   computer check a seal offline, with no shared secret, no money, and the "no network" rule unchanged, using a key
   the person may already have and that `ssh-keygen -Y verify` can check without `sv`. The list of trusted public
   keys would have to be kept where the AI coding tool cannot write. Under every design, "a person, not the tool, made
   this" stays unproven, as ADR-026 says. Building it would change ADR-026 and add a dependency, so its record goes in
   the same pull request, and it needs a claim and the owner's decision first.

**Closed 9 October 2026 at the owner's word:** another session answered the owner's questions on this on 8 October
2026, and the owner asked for the item to be taken off the board ("another session answered my questions on that
yesterday"). Nothing was built, and the item is kept as the record of the question.
