# pnpm 5 and 6 told apart, and packages without a version named (5 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H21 and H24) found two JavaScript lockfile readers giving a
package list that was not the whole of what is installed, and saying nothing about it.

- **H24, pnpm's lockfile 6.0.** pnpm 8 writes a package as `/express@4.18.2`. The reader took any key starting with
  `/` to be 5.x's `/express/4.18.2`, so a real 6.0 file gave no packages at all, and the test named for 6.0 used 5.x's
  shape. The reader now reads the lockfile's own `lockfileVersion` line: 5.x keys are read by their slashes, with the
  peer variant after `_` taken off the version (`/react-dom/18.2.0_react@18.2.0` is react-dom 18.2.0), and 6.0 and
  later by the `@`. The 6.0 test now uses 6.0's shape, peer variant included, and 5.x has a test of its own.
- **H21, packages with no registry version.** A package installed from a folder, a link, a repository, or an
  address is listed by that rather than by a version: pnpm 9 writes `my-lib@file:../lib`, and Yarn Berry
  `local-lib@file:../lib`. Both readers dropped such a package without a word, and the list still counted as
  complete. Each is now named as not listed, the way the `Pipfile.lock` and `pylock.toml` readers already did, so the
  list no longer counts as complete and V15.2.1 is not credited on it. A classic `yarn.lock` entry with no `version`
  line is named the same way. The app's own Yarn workspace (`workspace:`) is its own code, not something installed,
  and is left out.

An earlier test held the opposite for Yarn Berry: it expected a folder the app links to be dropped with nothing said.
It now expects the folder named. Eight guards broken in turn, each caught: reading 6.0 as 5.x (the old behavior),
keeping 5.x's peer suffix in the version, dropping pnpm's packages without a version, not reporting them, dropping
Berry's, naming the app's own workspace, and dropping a classic entry with no version, in the middle of the file or
at its end.
