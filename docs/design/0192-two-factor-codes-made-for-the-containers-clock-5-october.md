# Two-factor codes made for the containers' clock (5 October 2026)

A fourth part of the deep review's improvement 5. The signed-in checks make two-factor codes, and wait for the next
time step, by the clock `Http::now` gives, and `sv run` gave this computer's. On a Mac, Docker runs in a virtual
machine whose clock can fall behind after the computer sleeps, and the app checks a code against that machine's
clock: a code made for this computer's time is refused, and a check that needs it says the sign-in did not work.

- **The containers' clock is read once,** from the fence's container (`date +%s`), between two readings of this
  computer's, and the difference from their middle is kept on the backend (`clock_offset`). A second either way is
  the reading's own uncertainty and counts as none. `DockerHttp::now` is this computer's clock moved by it.
- If the containers' clock cannot be read, nothing is moved, as before.

How it is held: `the_containers_clock_is_read_against_the_middle_of_the_reading`, and, with a real container,
`two_factor_codes_are_made_for_the_time_the_containers_read`, which asserts the reading worked and found no
difference on a computer that shares the containers' clock, and that `now` moves by a measured difference
(`crates/sv-run/src/docker.rs`). A clock really behind is not staged: changing a container's clock needs a
privilege the fence takes away. Four guards were undone in turn and each was caught.
