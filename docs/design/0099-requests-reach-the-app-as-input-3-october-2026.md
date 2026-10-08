# Requests reach the app as input (3 October 2026)

Every request the running-app checks make goes from a container on the app's fenced network: the sidecar, or a fresh
container when no sidecar could be started. The request used to go into that container as a command-line argument,
base64-encoded, for `nc -e` to write to the app. Linux refuses any single argument over 128 KiB, measured in
`busybox:1.36` on 3 October 2026: 130,000 characters were taken and 200,000 refused with "argument list too long".
Base64 adds a third, so every request over about 96 KB failed.

**What that did.** An upload larger than that never reached the app. A request with no answer is already treated
like a crash, so nothing was falsely credited, but V5.2.1 (a file over `max-bytes` refused) could never be tested
above about 96 KB, where the settings template suggests 1 MB. Each such run was reported as "the app crashed or did
not answer", which blamed the app for `sv`'s own failure.

**Now.** The request is what the container reads (`docker exec -i`, or `docker run -i`). The container writes it to
a file in a 16 MB in-memory `/tmp`, and the script `nc -e` runs reads it from there. A file is needed because `nc -e`
closes every file but the socket before it starts the script, so a request handed over any other way does not
arrive. Plain `nc`, with the request piped straight in, did deliver every size, but it is the reason `nc -e` was
chosen in the first place (see `exchange_script`): a server can drop a client that has stopped sending before a slow
route has answered. The `/tmp` is the probe container's only writable place, and nothing in it can run as a program
(`noexec`). Measured through it: 1 KB, 300 KB, and 7 MB, every byte value, each arriving with the same SHA-256 it was
sent with, and the answer coming back.

**Bodies are bytes.** `ProbeRequest::body` is `Vec<u8>`, and `body_text()` reads it as text for the checks and test
apps that read a form or JSON. No part of a request is ever in the shell command any more: the command is built from
the app's name and port alone, which a test holds (`no_part_of_a_request_is_ever_in_the_shell_command`).
