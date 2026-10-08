# What has to be answered is asked (5 October 2026)

The compliance report lists the requirements nobody has placed, each beside "what has to be answered" to place it.
That column printed each condition's reason for excluding a requirement, which is written as the exclusion: a
WebSocket requirement was shown "No WebSocket library is used", which reads as an answer, and one nobody gave.
`question_for` said it turned the reason round, and returned it unchanged. Found by the cato-pipeline session while
building R12.

Each condition now carries a question beside its reason, in the same line of the same macro in
`crates/sv-frameworks/src/condition.rs`, so a condition added later cannot have one without the other: "Does the
app use WebSockets?", "Does the app send email?", "Can the AI change data or take actions, rather than only answer
questions?". The report's table, Markdown and page alike, asks it; a requirement blocked on two conditions shows
both questions joined by "or", as before. The reasons are unchanged and still explain each exclusion.

`every_condition_asks_a_question_of_its_own_in_its_own_words` holds every condition to one question, ending in a
question mark, beginning with a capital letter, not its reason, and asked by no other condition.
`what_has_to_be_answered_is_asked_as_a_question_never_said_as_an_answer` puts every condition in the table as a
requirement's blocker and finds each row a question and no row a reason. Four guards broken in turn, each caught:
the table given the reason again (one test), one question written as a statement (two), one question made its
reason (two), and two conditions asking the same question (one).
