# A sign-in or reset code made with a random number generator that can be predicted (V6.5.3, 7 October 2026)

V6.5.3 asks that one-time codes, backup codes, and two-factor seeds be made with a generator built for secrets. The
outside tools (Bandit, Semgrep, CodeQL) report ordinary random numbers in general, under V11.5.1, wherever they are,
dice rolls and shuffles included, so a reader cannot tell the one that matters from the rest. `sv`'s own rules said
nothing. `docs/PARTIAL-CHECKS.md` proposed the narrower case: an ordinary generator whose value is named as a code.

**`ast.insecure-random-for-code`** (high, medium confidence, only ever a finding, citing V6.5.3 and V11.5.1) reads
thirteen languages for the ordinary generators: Python's `random.randint` and its kin, JavaScript's and
TypeScript's `Math.random`, Java's `new Random()` and `ThreadLocalRandom`, Kotlin's `Random.nextInt`, Go's
`math/rand` functions (`rand.Intn` and the rest; `crypto/rand` has none of their names), PHP's `rand`, `mt_rand`, and
`uniqid`, Ruby's `rand` and `Random.rand`, C#'s `new Random()` and `Random.Shared`, Dart's `Random()`, C's and
C++'s `rand()` and `random()`, and the shell's `$RANDOM`. Swift and Rust have nothing to find, and the rule says why:
their usual ways of making a random number (`Int.random(in:)`, `rand::random`) already draw from a generator built
for secrets; their exceptions (GameplayKit, `SmallRng`, `fastrand`) are not looked for. The secure ones beside them
(`secrets`, `crypto.randomInt`, `SecureRandom`, `random_int`, `RandomNumberGenerator`, `Random.secure()`) are told
apart by name: `secrets.choice` is not `random.choice`.

**What the value is for.** A random number is a fault in a sign-in code and ordinary in a dice game, and only the
names around it say which. The rule engine gained `valueNamePatterns`: per language, a pattern over the names a value
is given on its way out of its function (each variable, field, or keyword argument it is assigned to, and the
function's own name), read as words as `enclosingFunctionPatterns` reads them. A name counts when it says one-time
code by itself (`otp`, `totp`, `pin`, `passcode`), when it pairs `code`, `token`, or `secret` with a sign-in word
(verification, reset, recovery, backup, activation, magic, login, auth, confirmation, email, sms, password, unlock,
and the like) in either order, or when it is `code` alone or `generate_code` and its kin. So `verification_code`,
`reset_token`, `backup_codes`, and `generate_otp` count, and `color_code`, `status_code`, and `access_token` do not.
The proposal's `RandomStringUtils` (Java) is left out, since whether its current versions use an ordinary generator
was not confirmed.

**What it does not see.** A generator kept in a variable and used later (`rng = Random()`, then `rng.nextInt()`),
whose type a query cannot know; Go's `math/rand` imported under another name; and a code given a name that says
nothing. Finding none credits nothing.
**Break and watch.** The rule has witnesses both ways in every language it reads, and two cases guard the generator's own
name: `secrets.choice` in Python and `SecureRandom.rand` in Ruby, each using the same method name as the weak
generator. **Ten guards were broken in turn, and each was caught:**
- the names not judged at all (a quiet case reported in every one of the ten languages);
- variable and field names not read (six cases: JavaScript, PHP, Ruby, and three in Python);
- the function's name not read (seven cases, in six languages);
- keyword arguments not read (Python's `verification_code=`);
- Kotlin's declaration not read;
- `code` matched inside other words (`color_code` reported, and the `code`-alone rule turned into a miss);
- Python's module not judged (`secrets.choice` reported);
- Ruby's receiver not judged (`SecureRandom.rand` reported);
- C's and C++'s declarations not read (both of their cases);
- the shell's assignments not read (`otp=$RANDOM`).

The C, C++, and shell queries, and the reasons for Swift and Rust, were added after the full suite's first run: a
test (`every_real_rule_is_taught_every_language_it_meets_here`) holds every rule to saying something about every
language `sv` reads, and four more tests failed with it.

The Kotlin break was missed at first: its case was `fun sendOtp()`, whose name alone was enough. The case is now
`fun notify(…)` with `val otp: Int = …`, so only the declaration can find it, and the break is caught.
