# Advisory versions: in order, gaps kept, gems as gems (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H18 to H20) found three ways the advisory comparison could call
an affected version clean, or drop the note that it could not tell.

- **H18, events read in the order they were written.** OSV asks for a range's events to be read in version order.
  They were read as the record lists them, and 86 real ranges list a later `introduced` before an earlier `fixed`, so
  the range ended too soon: PYSEC-2024-265 reported 1.2.1 clean. The events are now sorted by version first. Two
  events at the same version could be read either way, so a range with any is not compared, and says so.
- **H19, a match cleared another advisory's gap.** When one advisory could not be compared with a package's version
  and a later one matched, the match cleared the "could not compare" the first had left. That is now kept per
  advisory: a match settles its own advisory and says nothing about another.
- **H20, gems compared as semver.** Bundler writes a gem built for one platform as `nokogiri (1.15.4-x86_64-linux)`,
  and the semver comparison read `-x86_64-linux` as a pre-release, before 1.15.4 and so inside a range 1.15.4 fixed.
  The lockfile reader now takes the version as Bundler does, everything before the first `-`. RubyGems versions are
  also compared by RubyGems' own rules (`Gem::Version`): `2.0.0.rc1` is a pre-release of `2.0.0`, which semver could
  not compare at all; `1.0` equals `1.0.0`; and zeros before a pre-release's letters do not count.

Eight guards broken in turn. Six were caught at once, each by the test written for it. Two were not: comparing gems
as semver, because the RubyGems test called the comparison directly and the lockfile test used versions on which the
two agree; and keeping the zeros before the letters, because the case tested (`1.0` and `1.0.0`) comes out equal
either way. A test of a gem pre-release held to an advisory, and the cases `2.0.0.rc1` and `2.0.rc1`, were added, and
both were then caught.
