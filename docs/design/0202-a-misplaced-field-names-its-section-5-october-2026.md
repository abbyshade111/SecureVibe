# A misplaced field names its section (5 October 2026)

In the loop pilot Haiku 4.5 wrote `enabled = true` under `[stack.run.ai]`. `sv` answered with the line, the field,
and the fields `[stack.run.ai]` takes, which is all serde's `deny_unknown_fields` says, and the builder sent the same
line back five times, rewriting the file twice, before it moved the field to `[capabilities.ai]` (BACKLOG, "A
`securevibe.toml` field in the wrong section"). The message never said which section the line was read in, so a
builder that believed it was in the right one had nothing to correct.

Now every unknown field is answered with its section, and with where a field of that name belongs:

    TOML parse error at line 6, column 1
      |
    6 | enabled = true
      | ^^^^^^^
    `enabled` is not a field of [stack.run.ai]. Did you mean [capabilities.ai]? `enabled` is a field there.
    The fields [stack.run.ai] takes are `chat`, `signed-in`, `base-url-env`, `kill-switch`, `mcp-url-env`, `record-tool`, `reads-owned`.

**Which section.** toml's error carries the position of the field's name in the file. The file is read again with
positions kept (`toml::de::DeTable`, part of the `toml` crate `sv` already uses), and the key at that position gives
its section: `[stack.run.ai]`, `[policy.fix-within-days]` for an inline table, `[design."V6.2.1"]` for a keyed one,
`[[finding-review]] number 2` for the second entry of an array of tables (counted from one, since an entry has no
name of its own every kind shares), or "the top level (before any [section])". An error of another kind that points
into a section, such as a word where a yes or no is wanted, says "(in [section])" after toml's own message.

**Where it belongs, from the types, not a list.** A list of sections written by hand would fall behind the first
time a field was added. Instead `sv_manifest::schema` walks `Manifest`'s own `Deserialize` implementation with a
deserializer that holds no data: serde hands every struct's field names, as they are written in the file, to
`deserialize_struct`, and the walk notes them and visits each field in turn, each option as present, each list as one
entry, each keyed table as one key. A field no other section takes gets no suggestion; one that several take names
them all (`mcp-server` under `[app]`: "Did you mean [stack.run] or [capabilities]?").

**Where it is said.** Every command and MCP tool reads securevibe.toml through `Manifest::parse`, so one change
reaches `sv scope`, `report`, `audit`, `rules`, `plan`, `run`, `review`, and the MCP tools (`securevibe_check`,
`securevibe_plan`, and the rest), whose errors are fenced as before, since the message quotes the file. `sv check`
does not read securevibe.toml, and `securevibe_spec` reads no file, so neither has such a message to give. No
dependency was added; `serde_path_to_error` would have given the path but not the sections a field belongs in.

How it is held: ten tests in `crates/sv-manifest/src/schema.rs` (the pilot's case with its line and allowed fields; a
field two other sections take; one none takes; a deep section; an inline table; `[[finding-review]]` and
`[[stack.run.users.admin-actions]]` entries; a keyed section, with a field that belongs in an array of tables; the
top level; a value of the wrong kind; and the walk finishing with every kind of section),
`a_field_in_the_wrong_section_is_answered_with_the_section_and_where_it_belongs` through the MCP server, and
`every_command_that_reads_the_manifest_names_the_section` through the binary (`crates/sv-cli/tests/misplaced_field.rs`).

Four guards were broken in turn. The new message taken out of `Manifest::parse`: eleven tests red (nine of the ten
in `schema.rs`, all but the walk's own, plus the MCP and binary tests). No suggestion given: six red. The entry's
number dropped: one red. Lists not walked: three red, after the array-of-tables tests were made to ask for the
entry's fields and for a suggestion pointing at `[[finding-review]]`; before that only the walk's own test caught it.
A filter that left the field's own section out of the suggestions was taken out instead of broken: an unknown field
is by definition not a field of its own section, so nothing could catch it.
