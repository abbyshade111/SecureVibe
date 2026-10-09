# The app's log files served to anybody who asks (9 October 2026)


ASVS V16.4.2 asks that logs are protected from unauthorized access and cannot be modified (ADR-072). The anonymous
probes now also ask, not signed in, for nine addresses where frameworks and servers commonly leave the app's log:
`/logs/`, `/log/`, `/logs/app.log`, `/log/production.log`, `/storage/logs/laravel.log`, `/error.log`, `/debug.log`,
`/npm-debug.log`, and `/var/log/app.log`.

`probe.log-file-served` is a finding (high) when one is answered 200 with at least three lines that read as a log:
starting with an ISO date and time or syslog's time, carrying the common log format's `[09/Oct/2026:12:00:01`
anywhere (it follows the client's address), or carrying a level word beside a date. HTML is never a log, so a page the
app answers every address with, even one listing dated items, is left alone, and a listing of a logs folder is the
directory-listing check's to find. It is only ever a finding: nine guesses cannot show that no log is served. Whether a
log can be modified is not tried.

Checked: the probe tests, with a Laravel log, JSON lines, syslog, and an access log each found, and the app's own
page, a page of dated items, a folder listing, two lines alone, and a log answered 404 or 403 each left alone. The
first version missed the access log, whose time does not start the line; its own test showed that. Seven guards broken
one at a time, each caught, the HTML guard only once a page of dated items was added. The test of how many requests the
anonymous probes send counts the nine.
