# Python versions compared as pip compares them (4 October 2026)

The advisory comparison followed semver, where a pre-release comes after `-`. PyPI versions follow PEP 440, which
writes it with no separator (`2.0.0rc1`, `1.0a1`, `3.0.0.dev0`, `1.0.post1`), so those did not parse. An advisory
whose range began at one went unanswered. The cato-pipeline session found this on the owner's family-hub: werkzeug
3.1.9 was left "could not be compared" against three werkzeug records whose ranges begin at `2.0.0rc1`.

PyPI ranges are now compared by PEP 440, and every other ecosystem keeps semver.
- **The order:** epoch, then release numbers (trailing zeros ignored), then pre-release (`a` < `b` < `rc`, with
  `alpha`, `beta`, `c`, `pre`, and `preview` as other spellings), post-release (`.postN`, `-N`, `revN`), and
  development release.
- **What that gives:** `1.0.dev0 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1`.
- **Strings that are not PEP 440** stay "could not be compared".

It was checked against Python's `packaging` 24.0, the library pip uses.
- 345 version strings were tried. Both accepted the same 319 and refused the same 26.
- All 101,481 ordered pairs of the 319 agreed, with one deliberate exception: local labels.
- **The exception.** `packaging` sorts `2.1.0+cu118` after `2.1.0`, and `sv` treats them as equal. A local build
  is built from that release's source. An advisory whose last affected version is `2.1.0` therefore reaches it,
  and following `packaging` would read it as fixed.

The temporary test that read `packaging`'s answers was not kept, since CI does not have them. The cases that matter
are kept as ordinary tests: the six from the report, a chain of fifteen versions in order, eleven equal spellings,
and the werkzeug range end to end.

**Break tests.** Each of these was caught by a test:
- semver used for PyPI;
- a development release not placed before the pre-releases;
- trailing zeros kept;
- post-releases placed before the release.
