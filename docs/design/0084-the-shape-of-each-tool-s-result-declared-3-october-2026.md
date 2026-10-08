# The shape of each tool's result, declared (3 October 2026)

Seven of the MCP server's eight tools send a structured result beside their text, and none said what it would look
like (BACKLOG, "Improving the MCP server", item 3). Each now declares its `outputSchema`, as the 2025-06-18 protocol
provides, so a client can read `findings`, `counts`, or `questions` knowing what will be there. `securevibe_spec`
answers in text only and declares none.

Each schema names every field, requires the ones always present, and allows no other: a field added to a result and
not to its schema fails a test, so the declaration cannot fall behind what is sent. The lists of allowed values
(severity, confidence, a question's route) are compared with every variant the code has, through `match`es with no
catch-all, so a severity added to the code stops the test compiling until the schema has it too. The test calls every
tool on an app planted with what each schema describes (a finding with a key in it and one without, claims, a file
the bundle leaves out) and asserts each was really there, so no part of a schema passes for lack of anything to
check. No JSON Schema library is among `sv`'s dependencies; the test checks the few parts the declarations use
(`type`, `enum`, `minimum`, `properties`, `required`, `additionalProperties`, `items`) with a dozen lines of its own,
and a test of its own holds those lines to refusing what they should. Seven ways broken, each caught: the schemas
not sent, a field added to a result, a field renamed, a severity left out, a type wrong, and the checker letting
extra or missing fields through.

**A departure, on purpose.** The protocol says a tool with a structured result *should* also send that result as
JSON text, for clients that read only text. These tools send the plain-language summary as their text instead,
because the text is what a model reads, and the summary puts what was not examined first; the JSON is in
`structuredContent` for clients that read it.
