# Markers made fresh for each use, and no control character to the terminal (5 October 2026)

Two parts of the deep review's improvement 5: output `sv` splits at a marker the app could print, and text from the
app printed to the owner's terminal as it is.

- **The marker that splits the answers of a request sent several times at once is made fresh for each call**
  (`at_once_mark`, `crates/sv-run/src/docker.rs`). The race checks send one request many times together and read
  the answers from one stream, each after `@@sv-at-once-N@@`. With that marker fixed, the app could print the next
  copy's marker, and an answer of its own, inside its first answer, and the forgery was read as the next copy's: a
  race check fooled into a pass. The app cannot know a marker made after it started.
- **So is the one `sv probe` puts between a site's headers and its certificate's details** (`certs_mark`,
  `crates/sv-check/src/production.rs`), from the standard library's randomly keyed hasher, so no file is read for it.
  A site sending a header line that was the fixed marker, with a responder of its own after it, had that read as
  its certificate's.
- **Nothing `sv` prints carries a control character.** File names, findings, and what an app's tests printed reach
  the terminal, and on Linux and macOS a file name can hold an escape character: printed as it is, it can rewrite
  what is on screen, retitle the window, or on some terminals set the clipboard. `sv_report::visible` keeps line
  breaks and tabs and writes every other control character, and every character that hides or reorders text, as
  `\u{...}`. The `sv` binary's `println!`, `eprintln!`, and `print!` are its own macros that print through it, so no
  line can be missed; `sv review`, which writes to the terminal through a writer, writes through `Visible`. `sv`
  prints no colors of its own, so nothing of its is lost. The MCP server writes its protocol to its own writer, and
  JSON escapes control characters there already.

The other three parts of improvement 5 (two-factor codes from the container's clock, seed secrets through standard
input, WebSockets and workers in the browser driver) are not done here.

How it is held: `an_answer_cannot_forge_the_marker_of_the_next` (`docker.rs`),
`a_site_cannot_write_the_certificate_s_details_into_its_own_headers` (`production.rs`),
`a_file_name_with_an_escape_in_it_is_printed_with_the_escape_written_out` through `sv check`, and
`the_review_shows_an_escape_in_a_proposal_rather_than_sending_it` through `sv review` in a terminal `script` gives it
(`crates/sv-cli/tests/terminal_escapes.rs`). Five guards were undone in turn, each marker fixed again, the macro
printing as it was, `visible` letting everything through, and the review writing straight to the terminal, and each
was caught.
