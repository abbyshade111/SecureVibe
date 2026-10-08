# What the MCP server answers when it is sent nonsense (3 October 2026)

The server reads one JSON-RPC request per line and answered well the requests it expected. What it did with the
rest (BACKLOG, "Hardening the MCP server", items 4 to 7):

- **A batch** (a JSON array of requests) got no answer at all, so a client that sent one waited for ever. The
  2025-06-18 protocol has no batches; one is now refused with "invalid request", as is anything else that is not a
  JSON object.
- **A request in another protocol's dress** was answered as if it were well formed: `jsonrpc` other than "2.0", an
  id that was an object, a list, or null. Each is now refused; an id that is not a string or a number cannot be
  answered by, so the refusal carries none.
- **Arguments that were not an object** (`"arguments": "x"`) answered every lookup with its default, so the call
  checked the root as if `path` had been left out. They are refused as invalid parameters.
- **A line that was not UTF-8 ended the server**, because `lines()` returns an error for it and the loop passed the
  error on. Such a line is now answered with a parse error, and the next request is read as usual. That includes a
  line whose only bad byte is inside a string, which a lenient reading would have passed.
- **A line had no length limit.** One is now at most 1 MiB; a longer line is read to its end and thrown away, so the
  next request starts where it should, and is answered with "invalid request".
- **`sv mcp` with no `--root` served the folder it was started in**, the home folder included. The top of the
  computer's files and the home folder itself are now refused, with the reason and an example (`sv mcp --root
  ~/code`). Every way the documents tell the owner to start it names a narrower folder, so none is refused.

The loop moved into `serve`, which takes any reader and writer, so the tests drive the real loop rather than the
function behind it, and read their input seven bytes at a time, as a pipe hands it over: one guard, skipping the rest
of an over-long line, was not caught at all while the tests handed over each line in one piece. Two tests: one feeds
nineteen malformed requests, each followed by a ping that must be answered in turn with nothing extra in between;
the other feeds 400 requests cut, flipped, and sprinkled with stray bytes by a fixed-seed generator, each followed by
a ping, and asserts every ping is answered and no request twice. Ten guards broken in turn, each caught.

**Not done here.** A time limit on a check (item 6's other half): a check of a very large folder still has no end.
