# sv probe exits 2 when it could not reach the address (observability review, part 3, G)

**Status:** open

The owner's word, 10 October 2026, asked with the three other open decisions of that day: yes (part 3, G, of backlog 0226).

`sv probe` exits 2 when it could not reach the address the owner typed, rather than 0, so it can be used in CI. A
default that changes a conclusion (ADR-029's area), so ADR-029 gains a Later entry with the build. Small.
