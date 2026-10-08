# A log line of plain traffic is not a record of a sign-in (6 October 2026)

Item 14 of the review of 1 to 4 October (BACKLOG); items 5, 6, and 7, claimed with it, were built by session
securevibe-e2 the same day (the section above). Before a line between the markers was read for a sign-in event, only
`login.path` exactly as securevibe.toml writes it was taken out (`logs.rs`). `POST /login/ 200`, `/Login`, a query, a
full address, or a prefix the app is mounted under left the word "login" in, and the request read as a record of the
sign-in, which could credit V16.3.1. Now every path and address is taken out of the line first (`without_paths`),
since a path says where a request went, never that it happened. Seven ways of writing the path, in plain and JSON
lines, credit nothing, and the same lines with an event of the app's own beside them are credited
(`an_access_log_writing_the_sign_in_path_another_way_is_not_a_record_either`). Undone, the guard is caught by that
test.
