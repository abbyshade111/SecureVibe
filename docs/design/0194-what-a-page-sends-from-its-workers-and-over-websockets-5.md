# What a page sends from its workers and over WebSockets (5 October 2026)

The last part of the deep review's improvement 5. The browser driver's list of what the signed-in pages try to send
to other sites (V14.2.3, "What the signed-in pages send to other sites") read only the tab's own requests. A page
can send the same details from a worker it starts, which the browser reports as a target of its own, or over a
WebSocket, whose opening the browser does not report as a request at all. Neither was seen.

- **Every worker is watched before it runs.** The driver asks the browser to report each worker the tab starts, and
  each one those workers start, and to hold it at its start (`Target.setAutoAttach`, waiting). It watches the
  worker's requests and only then lets it go, so not even its first request is missed. A shared worker or a
  service worker belongs to no one tab, so the browser itself reports those; one from the job's own browser
  context is watched, and any other is let go.
- **Each worker once.** A service worker is reported twice, by the tab and by the browser; the second report is
  let go, so nothing it sends is listed twice. A service worker held by two reports answers neither until both let
  it go, so the driver sends its three steps together, in order, rather than waiting for each answer.
- **A WebSocket is recorded when the page opens it** (`Network.webSocketCreated`), as a `WebSocket` request with
  the address it was opened to and the page that opened it. Nothing is ever sent over one: the fence stops it
  opening, so its address is all there is to read, and the existing check looks in it as in any address.
- A request from a worker names the worker's script as its page, which is where it came from.

How it is held: `what_a_page_sends_elsewhere_from_a_worker_or_over_a_websocket_is_recorded`
(`crates/sv-run/src/docker.rs`), with a real browser: a page opens a WebSocket elsewhere and starts a worker, a
worker of that worker's own, a shared worker, and a service worker, each of which sends a request elsewhere; the
page's own request is the control, and each request must be listed once. Nine guards were undone in turn and each
was caught. One is not: letting go a worker from another browser context, since a job has only its own.
