# The review of 1 to 4 October: a redirect read whichever way it goes (6 October 2026)

Item 19 of the review of the code merged on 1 to 4 October (BACKLOG), V3.7.2. The open-redirect rule's safe patterns
read how a destination starts, so `redirect("/home" if not nxt else nxt)` started like a path on the same site and was
taken for one, and the requirement was credited.

- **A choice is safe only when every value it can give is.** `a if c else b`, `c ? a : b`, `a or b`, `a and b`,
  `a || b`, `a && b`, and `a ?? b`, in brackets or not, are read value by value; each must match the safe pattern or be
  written out. `'/home' && next` gives the right-hand value, so the `and` forms count as choices too. Anything that is
  not a choice is read as before.
- **A `%` straight after the leading slash must be an escape** (`%2F`), not a slot that formatting fills in, so
  `"/%s" % nxt` is not taken for a path on the same site either.

Broken on purpose eight ways, each caught by a test written for it: the branches ignored, one branch of each kind of
choice dropped (Python's, the ternary, `or`, `and`, `??`), brackets not looked into, and the `%` let through. The
first run found the `or` and `??` branches carried no weight, because every example began with the variable; examples
that begin with a path on the same site now hold them, and a bracketed choice of two paths holds the bracket.

Items 18, 21, and 22 were built in this branch too, by mistake, after session securevibe-e9 had claimed and built
them; see the BACKLOG note. Its fixes are the ones in `main`.
