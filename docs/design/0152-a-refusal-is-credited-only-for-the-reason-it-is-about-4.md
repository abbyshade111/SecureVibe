# A refusal is credited only for the reason it is about (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H15) found two checks crediting any refusal as the one they ask
about. The burst behind V2.4.1 sent the same record again and again with one anti-forgery token, and read any refusal
of the last as a limit: an app that keeps a value unique, or takes each token once, refused the second record on and
was credited with a limit it does not have. The upload checks (V5.2.1, V5.2.2, V1.3.4, V5.4.3, V5.3.2) sent every file
with one token and the same form values, and credited a refusal of the bad file whatever the reason, a quota reached
included.

- **The burst.** Each record now carries a marker of its own, and the last refusal is credited only when it is how a
  limit answers: 429 Too Many Requests, or 503 with `Retry-After` (which no longer counts as a crash). A refusal of any
  other kind is not assessed, with its status and the reasons it may have had. The token is still fetched once: an app
  that takes each token once is not assessed rather than credited, and fetching a page between the records would
  stretch the burst past the minute it counts over.
- **The uploads.** Each upload fetches a fresh token when the form takes one and carries its own id as `{marker}`.
  A refusal is credited only when an ordinary GIF, with its own token and marker, is accepted straight after it;
  otherwise the requirement is not assessed and the report says both were refused. The review suggested a control just
  before each refusal; it is after, because a quota the refused file would have reached shows only in what comes next,
  and for a spent token or a repeated value either order shows the same.

The in-memory app gained four options to put these to the test: a token taken once, a refusal (409) of a repeated note
or upload title, an upload quota, and the status its notes limit answers with. Seven guards broken in turn, each caught
by a test written for it: the burst repeating its marker, crediting any refusal, taking a 503 without `Retry-After` as
a limit, and taking a 503 with it as a crash; an upload repeating its marker, reusing the first upload's token, and
skipping the ordinary file after a refusal.
