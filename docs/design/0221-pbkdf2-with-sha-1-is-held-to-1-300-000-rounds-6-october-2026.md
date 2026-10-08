# PBKDF2 with SHA-1 is held to 1,300,000 rounds (6 October 2026)

Left over from "A key made from a password with too few rounds" (BACKLOG, proposals item 9). The rule tied its
figure to the hash where the call names it: 600,000 for SHA-256, and 210,000 for SHA-512 or a hash it cannot read.
SHA-1, which OWASP's Password Storage Cheat Sheet puts at 1,300,000, was held to 210,000. Now a count below 1,300,000 is
reported where the call names SHA-1, in each of the thirteen languages where the rule reads the hash: the same table
(`argumentPatternsByHash` in `data/ast-rules.json`), with a SHA-1 entry beside each SHA-256 one. A hash named only by
the function (Ruby's `pbkdf2_hmac_sha1`, OpenSSL's `PKCS5_PBKDF2_HMAC_SHA1`), or by leaving it out (C#'s
`Rfc2898DeriveBytes` without a `HashAlgorithmName`, which uses SHA-1), is still held to 210,000: those calls have no
argument naming the hash to read.

How it is held: cases in `the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one`, a count below 1,300,000
reported and 1,300,000 itself not, with SHA-512 at the same count as a control. Where naming SHA-1 also fires another
rule (the hash itself in C, C++, and Ruby's `Digest::SHA1`; `openssl enc`'s cipher), the positives are in
`a_pbkdf2_count_below_1_300_000_is_reported_where_the_call_names_sha_1` instead. Fifteen guards were undone in turn
(each language's SHA-1 entry, and the count's upper and lower edge), and each was caught.
