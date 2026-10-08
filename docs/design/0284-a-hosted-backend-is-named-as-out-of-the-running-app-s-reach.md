# A hosted backend is named as out of the running app's reach (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.2; BACKLOG, item 10, its fourth and last part). An app built with
Lovable, Bolt, and the like often signs people in and keeps their data with Firebase or Supabase, reached from the
browser. Behind the network fence the running app cannot reach either, so `sv run` asked it its questions and reported
what it saw, and said nothing about the part of the app that decides who reads whose records.

When the bill of materials shows a Firebase or Supabase package (`firebase`, `firebase-admin`, `@firebase/…`,
`@react-native-firebase/…`, `supabase`, `@supabase/…`, and Dart's `firebase_…` and `supabase_…`, matched by name and
never by a word inside one), `sv run`'s "Not assessed by these probes" and the report's gaps carry one more line, citing
V8 and V6. It names the service and the package that shows it, says nothing signed in through the service or read or
changed its data, and points to what `sv check` reads instead: Firebase's rules files, or the policies in
`supabase/migrations/`. It is a gap, so it credits nothing and finds nothing.

`probes::running_app_gaps` now makes the whole list, which `sv run` printed and the report built separately from the
same three sources; one list means the two cannot drift apart.

Tests: one in `probes.rs`. Five guards broken in turn, each caught: the line left out of the shared list, Supabase
never recognized, Firebase never recognized, a package matched by a word inside its name (`supabase-mock`), and one
service's rules named for the other. Not tested end to end: printing the line needs the app running, which needs a
container backend this test suite does not have everywhere.
