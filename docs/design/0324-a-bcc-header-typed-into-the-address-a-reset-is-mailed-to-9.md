# A Bcc header typed into the address a reset is mailed to (9 October 2026)


ASVS V1.3.11 asks that what a person types is cleaned before it reaches the mail system (ADR-069). The password-reset
check already asks the app for a reset and reads the run's mail server, which lists every recipient of every message,
`Bcc` included. Once that check has seen its own reset email arrive, and after the whole reset has run, since a new
request may cancel the code it was using, `probe.mail-header-injected` asks for two more resets for the same account.
The address is followed by `\r\n` in one and `\n` alone in the other, then by `Bcc: ` and an address made for the run
(`sv-bcc-…@example.test`).

Any email reaching that address is the finding (high): the app's mail account sends where a stranger tells it. The
account receiving a reset email while nothing reaches that address is credited in part: the app cut or refused the
line break and still mailed the account, for one field of one kind of mail. No email at all is said and neither found
nor credited, since an app that finds the account by the exact address it was given sends nothing. When the reset email
was never seen to arrive, the check is not asked, and V1.3.11 is said as not assessed. The run's other checks require
that every requirement be named in every configuration of the suite, and that guard caught the first version, which was
silent there.

Checked: the signed-in tests, with a fake app that mails the address as typed, one that cuts it at the line break, the
fake's own exact lookup, and a reset that sends nothing. Six guards broken one at a time, each caught. Not run end to
end against an app under `sv run`, which needs Docker.
