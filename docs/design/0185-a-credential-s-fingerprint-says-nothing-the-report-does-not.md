# A credential's fingerprint says nothing the report does not (5 October 2026)

A review names the line it answers for by a fingerprint, a hash of the line, so it still counts when the line moves.
That hash was of the line as written. The report also shows the credential's rule, its first four characters, and its
length, so anyone with the report could guess the rest of a short test password, hash each guess, and stop at the one
that matches: the deep review recovered one in 190 guesses.

The fingerprint is now the hash of the line with every credential the secret rules find masked, exactly as the
report would show it (`review::masked`, through `secrets::redact_text`). It says nothing more than the report does.
A line with no credential reads the same masked as written, so its fingerprint, and every review recorded for it, is
unchanged. `sv review`, which shows the line it is recording, shows it masked too.

A review recorded by an older `sv` for a line holding a credential no longer matches. It is not quietly dropped: when
an entry matches a line still there by the old hash, and that line holds a credential, the entry is listed as not
counted, saying it was recorded by an older `sv` in a way that could give the credential back, and to record it
again with `sv review`. The old fingerprint stays in the user's file until they do; `sv` does not edit it.

Four guards broken in turn, each caught: hashing the line as written (four tests), showing it as written (one),
dropping the note about older reviews (two), and giving that note for lines with no credential (two).
