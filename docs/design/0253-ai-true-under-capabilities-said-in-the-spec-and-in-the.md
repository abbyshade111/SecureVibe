# `ai = true` under `[capabilities]`, said in the spec and in the refusal (7 October 2026)

After the spec's two sentences of 6 October, the delivery test's commonest settings file `sv` could not read had
`ai = true` written straight under `[capabilities]`, where `sv` wants `enabled = true` under `[capabilities.ai]`
(BACKLOG, "`ai = true` under `[capabilities]`"). One build was refused with toml's own words, "invalid type: boolean
`true`, expected struct AiClaims (in [capabilities])", which names a type in `sv`'s code and says nothing about what to
write. Two more were refused with "duplicate key" pointing at `[capabilities.ai]`: what a file with both
`ai = true` and the starter file's `[capabilities.ai]` header gets. The builds' files are not kept, so whether those
two were this, or a header written twice, cannot be checked; both fit.

**The spec.** One line among the `[capabilities]` answers: "(No `ai` here: whether the app has an AI feature is
`enabled` under [capabilities.ai], below.)" The `[capabilities.ai]` section already starts with `enabled`.

**The refusal.** `sv_manifest::schema::explain`, which already names the section a misplaced field was read in
("A misplaced field names its section"), now answers two more errors:

- A value given where the schema has a section of that name (the error points at the value, and the walk over the
  manifest's types has a section at that place): "`ai` under [capabilities] is not one value: it is a section of its
  own, [capabilities.ai]. Write [capabilities.ai] on a line of its own, with its fields below it.", then, for a
  section that takes `enabled`, "Whether the app has it at all is `enabled = true` or `enabled = false` there.", and
  the fields it takes. Any other value of the wrong kind keeps toml's message, with its section as before.
- "duplicate key" pointing at the last name of a `[section]` header, when an earlier line in the parent section gives
  that name a value: "[capabilities.ai] starts a section here, but `ai` was already given a value under
  [capabilities], higher up the file. It can be one or the other: take the `ai = ...` line out of [capabilities].",
  with the same `enabled` sentence where it applies. toml cannot read such a file with positions kept, so this is read
  from the header's own line and the lines above it. A key written twice, and a header written twice, keep toml's
  message, which shows the line.

Both are reached by every command and MCP tool, since all of them read securevibe.toml through `Manifest::parse`.
Nothing is credited or counted differently.

**Held by** four tests in `schema.rs` (the trial's line; a section with no `enabled` field, which is not told to
write one; a value then a section of the same name, both with and without `enabled`; a key and a header each written
twice) and one in `lib.rs`, which puts `ai = true` into the starter file itself and holds the spec's sentence to being
in its `[capabilities]` section. That last test is how the duplicate-key form was found: it was written expecting the
first message and got "duplicate key". **Seven guards broken in turn, each caught:** the value-as-section answer
never given (two tests red), its `enabled` sentence never said (one) or always said (one), the duplicate-key answer
never given (two), the earlier line not looked for (one, the header written twice), its `enabled` sentence never
said (two) or always said (one), and the spec's sentence removed (one). The check that the error points at the
header's last name is left without a test of its own: a header whose error points at another of its names has no
earlier line of that name in the parent section, so the line check already answers it.
