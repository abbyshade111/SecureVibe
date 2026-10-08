# The browser's DevTools on loopback, and the driver in a world of its own (5 October 2026)

S11 of the deep review, reproduced. The browser checks run Chromium beside the app on the fenced network, with a
driver that speaks to Chromium's DevTools. The image's own start script forwards port 9222 on every address to
DevTools, so the app could ask the browser's address for DevTools and drive the browser that checks it. And the
driver ran its expressions in the page's own world, where the app's scripts can redefine `localStorage`, its
`getItem`, or `Object.keys`, so the sign-out check could be shown storage with the token gone while it was kept
(ADR-019, Later).

- **DevTools on 127.0.0.1 alone.** Chromium is started directly rather than through the image's script, so the
  forwarder never starts, and DevTools listens on loopback, where only the driver, sharing the browser's network,
  reaches it. Chromium 151 already ignores an address other than loopback for its own port; the setting is kept
  so a later version that honors it cannot open the port again.
- **A world of the driver's own.** Every expression the driver runs, for `goto`, `fill`, `act`, and `eval`, runs in
  an isolated world made afresh for it (`Page.createIsolatedWorld`): the same page, its elements and its storage,
  with none of the page's scripts. Clicks and typing still reach the page's own handlers, since they are events on
  the same elements. If the world cannot be made, the action fails; it never falls back to the page's world.

What is not done: storage is read with the page's interfaces in the driver's world, not through DevTools' storage
domains, which the review also suggested. The world of its own already keeps the app's scripts out of the reading.

How it is held: `the_app_cannot_reach_the_browser_s_devtools_or_hide_its_storage_from_the_driver`
(`crates/sv-run/src/docker.rs`), with a real browser and an app on an internal network: from the app's container,
neither DevTools port answers at the browser's address, while the driver's side does; and a page that redefines
`Storage.prototype.getItem` and `Object.keys` still has its token read. `the_browser_and_its_driver_are_fenced_and_hardened_like_the_sidecar`
holds the arguments and that every expression goes through the driver's own world, without a container backend.
Four guards were undone in turn: the image's script restored, DevTools on every address, the page's own world for
every expression, and for `eval` alone. Each was caught; the second only by the arguments, for the reason above.
