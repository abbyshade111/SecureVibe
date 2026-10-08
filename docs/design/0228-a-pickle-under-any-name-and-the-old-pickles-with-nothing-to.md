# A pickle under any name, and the old pickles with nothing to know them by (6 October 2026)

`config.model-file-can-run-code` (C4.1.2) reads files named like a model file (`.pt`, `.pth`, `.ckpt`, `.bin`, `.pkl`,
`.pickle`, `.joblib`) by their bytes. When it was built it left two kinds of pickle unseen, and named them:

- **A pickle saved under another name**, such as `cache.dat` or a file with no extension. The extensions were the guard
  against reading every file in the app.
- **A pickle in protocol 0 or 1.** These have no opening `PROTO` opcode, so a `.pkl` holding one was counted as "none
  holding a pickle". That was a statement about a file `sv` had not understood.

**Old pickles are now read through.** `walks_as_pickle` reads a file opcode by opcode, with each opcode's argument as
`pickletools` describes it:
- integers, floats, quoted strings, and module names on their lines;
- lengths and the bytes they count.

It counts the file as a pickle only when every byte is an opcode or its argument, no opcode is newer than the
protocol allowed, and a `STOP`, after at least one other opcode, is the very last byte. Under a model file's name, a
file that does not open with `PROTO` is walked with protocols 0 and 1 allowed. Text that happens to start with a byte
that is also an opcode does not survive the walk:
- `(see the README…).` fails at its first space;
- `N.N.` goes on after its `STOP`;
- `cos system` with a space is not a module name.

The shape a harmful pickle has (`os.system` named by `GLOBAL`, a string, `REDUCE`) walks through, as it should. The
fixture is checked against Python's own `pickletools`. It is only ever read as bytes, never loaded.

**Any other file is opened for two bytes.** Every app file that is not code and is not named like a model is opened.
If its first two bytes are `PROTO` with protocol 2 to 5, it is walked to its end with that protocol allowed. So a
pickle under any name is found, and nothing else is read through. A file larger than 64 MB is not walked:
- one that opens with `PROTO` is judged by its opening and its last byte;
- one under a model file's name that does not open with `PROTO` is named in the clean record as not read whole.

A protocol 0 or 1 pickle under another name is still not seen. With no opening to know it by, finding one would mean
walking every file in the app, and the clean record says how many other files were looked at. Code files are left to
the code rules (`ast.model-loaded-with-pickle`).

Broken on purpose twelve ways, each caught in the end:
- other names never judged;
- other names judged without the walk;
- old pickles not walked;
- `STOP` allowed before the end;
- `STOP` alone counted as a pickle;
- the protocol not held;
- a later `PROTO` claiming more than the opening;
- line contents not checked;
- module names not checked;
- counted lengths ignored;
- an unknown byte accepted;
- code files read too.

The later-`PROTO` break was caught by nothing at first, and now has its own witness. The path for files over 64 MB is
not tested, since a test would have to write a file that size.
