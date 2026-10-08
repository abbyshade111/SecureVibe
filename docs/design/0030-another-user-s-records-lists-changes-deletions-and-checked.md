# Another user's records: lists, changes, deletions, and "checked in part" (ADR-053)

V8.2.2 was *checked* when the second test user was refused one read of one record the first user made (gap analysis
1.7). The commonest leaks are elsewhere: one person's notes in another's list, and requests that change or delete a
record by its id without asking whose it is. Now the second user also opens every `private` page and the record's
`list`, and, when securevibe.toml gives `update` and `delete` under `owned`, sends each at the first user's record.
The first user then reads it back, and that decides: the second user's marker there, or the record gone, is a
finding; the record unchanged is a refusal; a crash decides nothing, and a crashed request of the second user's is
never a refusal (the crash sweep found all five ways it could have been before the requests were listed).

When only reading could be tried, the credit is *in part*, and a requirement whose every credit is in part is
*checked in part*: its own status, below *checked*, with its own row in every count and its own words wherever counts
are said. The report says why it is in part and what to add to make it whole.
