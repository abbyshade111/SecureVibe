# A key made from a password with too few rounds (29 September 2026)

V11.4.4 asks that a key derived from a password is stretched: made with a function built to be slow, run enough
times that guessing the password is expensive. PBKDF2, the one most code reaches for, takes the number of rounds as
an argument, and the number written into the code is often a copy from an old tutorial (1,000, 4,096, 10,000).

`ast.weak-password-key-derivation` reports PBKDF2 whose count is a number written into the code below 210,000. That is
OWASP's lowest recommended figure for any PBKDF2 hash (210,000 for SHA-512; SHA-256 needs 600,000 and SHA-1 1,300,000),
so a count below it is too low whichever hash is used, and the rule does not need to know which one it is. A count
between 210,000 and 600,000 used with SHA-256 is too low too, and is not reported; the rule's description says so. (It is
reported where the call names SHA-256 since 5 October 2026; see below.)
The number may carry digit separators (`100_000`) or an integer suffix. A count read from a setting or a variable is
not judged. It is only ever a finding: finding none says nothing about keys made elsewhere.

It reads each language's usual call: Python's `hashlib.pbkdf2_hmac` and cryptography's `PBKDF2HMAC` (positional or
`iterations=`), Node's `crypto.pbkdf2` and `pbkdf2Sync` and the browser's `crypto.subtle.deriveKey` and `deriveBits`
(`iterations:`), Java's `PBEKeySpec`, Go's `golang.org/x/crypto/pbkdf2.Key`, PHP's `hash_pbkdf2` and
`openssl_pbkdf2`, Ruby's `OpenSSL::PKCS5.pbkdf2_hmac` and `OpenSSL::KDF.pbkdf2_hmac`, C#'s `Rfc2898DeriveBytes`,
OpenSSL's `PKCS5_PBKDF2_HMAC` in C and C++, `PBEKeySpec` in Kotlin, the `pbkdf2` crate in Rust, the `cryptography`
package's `Pbkdf2` and pointycastle's `Pbkdf2Parameters` in Dart, CommonCrypto's `CCKeyDerivationPBKDF` in Swift, and
`openssl ... -iter` in shell scripts: every language `sv` reads, which a test requires of every code rule. Each query
names the argument that holds the count, so a key length in the same call (32, 256) is never read as one.

One of those was wrong at first, and breaking the rule on purpose is what found it: the browser's `deriveBits` takes
the key's length as its third argument, and the query written for Node's `pbkdf2Sync(password, salt, count, ...)`
read `deriveBits(params, key, 256)` as 256 rounds. The positional form now needs at least five arguments, as Node's
two functions always have and `deriveBits` never does, and a test case holds it.

The test table has a case each way for every language, and cases at the boundary (209,999 reported, 210,000 not), a
safe count beside a key length, a count from a variable, and the same shape of call on something else. Broken on
purpose nineteen ways, each caught: any number counted, 210,000 read as below, any keyword taken for `iterations` in
Python and any key in JavaScript, the wrong argument position in Python and C, any function name, any Go package,
any Ruby receiver, and the five-argument guard removed; then, for the five languages added last, any number counted
in each, any `openssl` option taken for `-iter`, any Rust function, the wrong argument in Swift, and any Dart label.

**Not done here.** A single hash of a password used as an encryption key: nothing in the code says a hashed value is
a password without guessing from its name. scrypt's and Argon2's own settings. (Go's standard library and C#'s
two-argument constructor were left here too, and were added on 3 October 2026; see below.)

**Added on 3 October 2026: Go's standard library, and C#'s count left unsaid.** Go 1.24's `crypto/pbkdf2` has the
same function name as `golang.org/x/crypto/pbkdf2` and its arguments in another order: `pbkdf2.Key(sha256.New,
password, salt, 4096, 32)` against `pbkdf2.Key(password, salt, 4096, 32, sha256.New)`. A second Go pattern reads the
fourth argument when the first is a hash written as `package.Function` and the fifth is a number or a name. Neither
holds for x/crypto's order, whose fifth argument is the hash, so its key length is never read as a count; one case
holds a password read from a field, and another a hash passed in a variable, where only the hash coming first tells
the two apart.

C#'s `new Rfc2898DeriveBytes(password, salt)`, with exactly two arguments, uses 1,000 rounds of SHA-1 without the code
saying so, and is reported. The rules match a call only through what a part of it captures (`@arg`), so the pattern
captures the closing parenthesis of a list of exactly two arguments, and C#'s argument pattern accepts `)` beside a
number. A three-argument call with a count from a variable is still not judged.

Six guards broken in turn, each caught: either new pattern removed, the hash not required first, the number or name
not required last, the two arguments not required to be the only ones, and `)` not accepted. The case with the hash in
a variable was added when breaking the hash-first guard turned nothing red.

**Added on 5 October 2026: the figure tied to the hash the call names.** OWASP's figures are 600,000 rounds for
PBKDF2 with SHA-256 and 210,000 with SHA-512, so a single figure of 210,000 missed SHA-256 counts between the two.
The rule now reads the hash where the call states it, and holds a count below 600,000 against SHA-256. With SHA-512,
and wherever the hash is not named or cannot be read, the figure stays 210,000, as before: a hash passed in a
variable, a default the code does not spell out, or a hash set in another call. The rule does not guess the hash from
a default, even a well-known one such as `openssl enc`'s SHA-256, and its description and what it says it looks for
now say all of this.

Rules gained one field for it, `argumentPatternsByHash` (`crates/sv-check/src/ast.rs`): per language, a pattern over
a new `@hash` capture and the count pattern to use when it matches, in place of `argumentPatterns`. Where a query
captures more than one node as `@hash`, their texts are joined in order, which is how a shell line's `-md sha256` is
read as one. The hash is read in thirteen languages: Python's first argument or `algorithm=`, Node's fifth argument
and WebCrypto's `hash:` (also as `{ name: ... }`), Go's last argument for x/crypto and first for the standard
library, PHP's first argument for `hash_pbkdf2` and fifth for `openssl_pbkdf2`, Ruby's fifth argument or `hash:`
(a string, `Digest::SHA256`, or `Digest.new("SHA256")`), C#'s `HashAlgorithmName.SHA256` after the count, OpenSSL's
`EVP_sha256()` in C and C++, the Rust crate's type argument (`Sha256` or `Hmac<Sha256>`), Dart's
`macAlgorithm: Hmac.sha256()`, Swift's `kCCPRFHmacAlgSHA256`, and `openssl enc ... -md sha256`. Java's and Kotlin's
`PBEKeySpec` and pointycastle's `Pbkdf2Parameters` never name the hash (it is set in `SecretKeyFactory` or the
`KeyDerivator`), so there a count between the two figures is still not judged. A keyword, key, or option that holds
the text `sha256` is read as the hash only when it is the one that sets it: `label='sha256'` in Python,
`name: 'sha256'` in WebCrypto's parameters, and `-md sha256` given to `openssl pkcs12`, where it sets the digest of the
file's integrity check rather than the key's, are not.

The test table gained a case for every language: 300,000 with SHA-256 reported in each language that names the hash,
600,000 with SHA-256 and 300,000 with SHA-512 not, and 300,000 with a hash the rule cannot read not, in all fifteen. A
further test holds that the new field is refused for a language the rule has no query in, and when its pattern cannot
be compiled. Broken on purpose eight ways, each caught: the figure for a named hash ignored (every case at 300,000
with SHA-256 missed, in all thirteen languages); any text taken for SHA-256 (every SHA-512 and unreadable-hash case
reported, in all thirteen); 600,000 read as below the SHA-256 figure (the 600,000 cases reported, in every language
that names a hash); any Python keyword taken for `algorithm=`; any key taken for WebCrypto's `hash:`; any `openssl`
command taken for `enc`; only the first of the shell line's `@hash` nodes read; and the load check for a language with
no query removed.

**Not done here.** SHA-1, which needs 1,300,000 rounds, is still judged at 210,000; the field can carry it, with
cases for each language's spelling of it.
