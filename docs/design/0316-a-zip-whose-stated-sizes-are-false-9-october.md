# A zip whose stated sizes are false (9 October)

V5.2.3 asks that an app which unpacks compressed files checks what they unpack to before it unpacks them. Since
7 October, StackVet has sent, for each format the owner lists in `unpacks-archives`, an archive just over each
limit the owner states (ADR-046). Every one of those archives said truly what it unpacks to. So an app that checks
only the sizes a zip's headers state, then unpacks without counting what really comes out, refused them all and was
credited. Backlog 0029, part 15, named that gap: "an archive whose stated sizes are false".

**What is sent now.** For an app that lists `"zip"` and states `max-unpacked-bytes`, one more zip goes after the
zip just over the limit. Its headers say its one file unpacks to 1,024 bytes (or half the stated most, if that is
smaller), while its data unpacks to the same mebibyte past the stated most, with the checksum of what really comes
out. It is held to the same caps as the others (at most 1 GiB unpacked, and under `max-bytes` and the 8 MiB the
upload check sends), and judged the same way:
- refused, with the ordinary file sent after it accepted, is credited;
- accepted is a finding, "A compressed file past the stated limits was accepted", naming it as the zip that says
  less than it holds;
- a crash, a 5xx, or no answer is held back as not assessed.

V5.2.3's credit for zip now needs this zip refused too (ADR-046, "Later, 9 October 2026").

**Readers that are not fooled.** Some zip readers, Python's `zipfile` among them, stop reading at the size the
headers state and then check the checksum, which fails. For an app built on one, the lie unpacks nothing; the app
answers with an error, which is a refusal (credited) or held back, and never a finding. A test holds this:
Python's `zipfile` fails the zip, and reading its data with `zlib` past the stated size gives the full amount.

**What stays open.** Tar compresses nothing of its own: a `.tar.gz` is a gzip, which is already sent. 7z and rar
would each need a writer of their own, for formats an upload rarely takes.

**How the fake app counts.** The fake app the tests run against used to judge an archive by what its headers say,
which is exactly the app this zip is for. Its correct behavior now counts what an archive really holds, read with
`zeros_in`, a reader for the one kind of stream StackVet compresses (a run of zeros), tested by round trip against
the compressor; no deflate library was added. A new switch, `archive_trusts_stated_sizes`, makes it judge by the
headers again.

**Tests** (`crates/sv-check/src/signed_in/archives.rs`): the correct app is credited for the new zip with the
others; the app that trusts stated sizes is found for it alone, with the three honest archives still credited; a
stated most too small to say less sends no such zip; the reader counts what StackVet compresses and refuses
anything else, a stream cut short, and a copy with nothing before it; and Python's own readers confirm what the zip
says and holds. Five tests already counting the archives sent were updated for one more. Five guards broken in turn
(the zip never sent, the zip telling the truth, the stated size not kept under the most, the reader accepting a copy
with nothing before it, and the fake app trusting sizes by default), each caught, the fourth only after its test was
added.
