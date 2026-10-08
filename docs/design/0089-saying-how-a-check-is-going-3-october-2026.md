# Saying how a check is going (3 October 2026)

A check over MCP said nothing until it was done, so a long one looked stuck (BACKLOG, "Improving the MCP server",
item 4). A client that wants to hear how a request is going gives it a token (`_meta.progressToken`, a string or a
number), and the server sends `notifications/progress` with that token as the request goes. This is the same in
every version the server speaks, the stateless one included.

**What is said.** A check has seven stages, and each is named as it starts: reading the app's files, recognizing its
languages and frameworks, listing the packages it uses, looking for keys and passwords, reading its configuration,
reading its code, and putting the report together. Each notification gives the stage's number (from 0, rising each
time), the total (7), and its name. The names are `sv`'s own, so nothing from the app's folder reaches the tool this
way. `sv report` and the MCP server build the report with the same function; the stages are named in it
(`assemble_report_saying`), and `sv report` passes them to nothing.

**When it is said.** Only for the four tools that check the app, and only when the client gave a token; a token that
is neither a string nor a number is taken as none. Nothing is sent after the answer: a check that ran out of time (see
"A time limit on a check over MCP") goes on, but what it starts after the answer is not passed on, since the client
has closed the request. Stages are counted, not timed, so the number says which stage has started, not how much of the
time is gone; reading the code is usually the longest.

**How.** The answer to a request used to be written when the request was done. Now the server's loop also writes a
notification while a request is being answered, and the check, on its own thread, sends each stage back to it.

Two tests, through the server's real loop: a check with a text token and with a number token gets every stage in order
before its answer, and the next request's answer comes after; no token, and tokens that are an object, `null`, or a
list, get only the answer; a tool that does not check the app sends none; a stateless client hears the same; and a
check that ran out of time sends nothing after its answer. Eight ways broken, each caught: the token ignored, progress
sent without one, a token of the wrong kind taken, the number not rising, the stage's name wrong, stages passed on
after time ran out, a stage not named, and stages named out of order.

**Not done here.** Progress is not sent for anything but a check. The server does not say how far into a stage it is.
