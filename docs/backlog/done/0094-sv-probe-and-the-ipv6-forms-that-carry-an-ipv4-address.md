# `sv probe` and the IPv6 forms that carry an IPv4 address

**Status:** done, as its markers read on 8 October 2026

Found by the second weekly review of the decision
records (ADR-027, "Later, 5 October 2026"). `not_public` (`crates/sv-check/src/production.rs`) judges an IPv6
address by the IPv4 one inside it only when written `::ffff:a.b.c.d` or `::a.b.c.d`. A 6to4 address (`2002::/16`,
the IPv4 address in its second and third groups) and a NAT64 one (`64:ff9b::/96`, in its last two) are let through
whatever IPv4 address they carry, so `[2002:a00:1::]` is not refused as 10.0.0.1, and the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are not refused either. Low in practice (6to4 relays
are mostly gone, and a NAT64 gateway should not translate a private address), but the record and the code's own
comment promise more. Fix: judge both forms by their IPv4 address, refuse the documentation ranges,
and hold each with a test; ADR-027 changes with it.
**Claimed on 5 October 2026 by session securevibe-e10**, at the owner's asking to keep working off the backlog, in
branch `claude/probe-ipv6`.
**Done the same day** (DESIGN, "`sv probe` asks only public addresses", "Later, 5 October 2026"; ADR-027, "Later"):
6to4, NAT64's well-known prefix, and Teredo are judged by the IPv4 address they carry; NAT64's prefix for a
network's own translator is refused outright; the documentation ranges and IPv6's old site-local range are refused.
Eight guards broken in turn, each caught.
