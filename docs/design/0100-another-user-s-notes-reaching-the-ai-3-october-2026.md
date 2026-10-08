# Another user's notes reaching the AI (3 October 2026)

An AI feature that answers from the people's own notes or documents must search only the asker's. When the owner
says it does (`reads-owned = true` under `[stack.run.ai]`, with `signed-in = true` and an `owned` record under
`[stack.run.users]`), the run asks:

1. The first test user saves a note: a private marker, `SV-PRIVATE-<value>`, and a made-up word it is about. The
   second user saves one the same way.
2. **The control.** The second user asks the AI feature about their own note's word. The message is a `RECALL`, so the
   test model records every `SV-PRIVATE-` marker anywhere in what the app sent it (instructions, messages, tool
   results, any field), and repeats them in its reply. The second user's own marker must arrive. If it does not, the
   app may not search notes this way at all, and nothing more is concluded.
3. The second user asks about the first user's word. The question names only the word, never the marker, so the
   marker can only reach the model through the app's own search.
   - **The first user's marker reaching the model** is `probe.ai-retrieval-ignores-user` (C5.2.2, C8.1.3, high).
   - **It also coming back in the answer the second user is shown** is `probe.ai-reply-carries-others-data` (C5.2.4,
     high).
   - **It reaching the model but not the answer** is said for C5.2.4: something after the model held it back, or the
     answer does not show replies.

**Only ever findings.** One note each and one question is not every way an app searches, so the first user's note
staying out is said and not credited. `tools/coverage.py` lists both rules in `RUST_FINDINGS_ONLY`.

C5.2.2 is placed by the question of whether the AI searches a document store, and C8.1.3 by whether it keeps
conversation history. Until the owner answers those, a finding against either is shown with the findings whose
requirement nobody has placed yet, not in the requirement table.

Tried on 3 October 2026 with `sv report --run`, through the real test model in Docker, on two copies of
`examples/notes-with-users` given a chat route that answers from notes found by the question's words:
- The copy that searches only the asker's notes: the control held, the first user's note did not reach the model,
  and nothing was found.
- The copy that searches everybody's: both findings.
