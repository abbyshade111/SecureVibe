# `sv probe` asks only public addresses (4 October 2026)

The deep review of `sv` at `eff3f17` found that `sv probe` would ask any address that was not `localhost` or
`127.*`, and that curl's globbing could turn one address into several requests (S13). Recorded as ADR-027.

- **Public addresses only.** `not_public` refuses this computer, private and shared networks, link-local ranges
  (169.254.169.254 is where cloud machines keep their credentials), the unspecified address, multicast, broadcast,
  and the ranges kept for testing and for the network's own use. An IPv6 address that carries an IPv4 one is judged
  by the IPv4 one inside it. The message names what the address is and points at `sv report --run`.
- **Looked up once, and held to.** `addresses` looks the name up through this computer's resolver; one internal
  address among the answers refuses the whole name. `Curl::held_to` then gives every curl `--resolve` for each port
  it may use (443 and 80, or the one written in the address), so curl connects only to what was checked and a
  second lookup cannot answer differently.
- **Every curl starts the same way**, in `Curl::args`: `--disable` first, the only place curl reads it, so no
  `.curlrc` adds anything; `--globoff`, so one address is one request; and `--proto =http,https`. `--disable` used
  to come after other flags, where curl ignores it; that was found while building this.
- **Not the proxy.** A proxy set on this computer is still used, so the probe keeps working on networks that need
  one. Through a proxy, `--resolve` does not apply, and that is said in ADR-027.

How it is held: three tests in `crates/sv-check/src/production.rs` and two in `crates/sv-cli/tests/probe_addresses.rs`,
which put a `curl` of the test's own on the path and read what it was asked. Seven guards undone in turn, each caught.

**Later, 5 October 2026: the IPv6 forms that carry an IPv4 address.** The second weekly review of the decision records
found that `not_public` judged an IPv6 address by the IPv4 one inside it only when written `::ffff:a.b.c.d` or
`::a.b.c.d`, though ADR-027 and the function's own comment said every such address. A 6to4 address such as
`[2002:a00:1::]` reaches 10.0.0.1 through a relay, and a NAT64 one such as `[64:ff9b::a9fe:a9fe]` reaches
169.254.169.254, where cloud machines keep their credentials, through a translator; both were let through. Low in
practice, since 6to4 relays are mostly gone and a translator should not pass a private address on, but the promise was
wider than the code. Now 6to4, NAT64's well-known prefix, and Teredo (whose client address is stored with each bit
inverted) are judged by the IPv4 address they carry; NAT64's prefix for a network's own translator (`64:ff9b:1::/48`)
is refused outright, since where it puts the IPv4 address is that network's choice; and the documentation ranges and
IPv6's old site-local range are refused. Each form with a public address inside it is still accepted. Eight guards
undone in turn, each caught by the probe's address test: 6to4, NAT64, and Teredo not judged; Teredo's bits not
inverted; a network's own translator let through; the IPv4 and the IPv6 documentation ranges let through; and the
site-local range let through.
