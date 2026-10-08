# Encryption that cannot show it was changed (V11.3.3)

V11.3.3 asks that encrypted data is protected against being changed: an authenticated mode such as
GCM, or an approved cipher combined with a MAC. It had been reached only through semgrep rules no
pack the adapter runs, and relaxed-nobel-27acfa's measurements showed `p/default` would not bring it
back either. It is now `sv`'s own rule, `ast.unauthenticated-encryption`, in all fourteen languages.

It looks at the calls `ast.weak-cipher` already looks at (`createCipheriv`, `openssl_encrypt`,
`Cipher.getInstance`, `AES.new`, `cipher.NewCBCEncrypter`, `EVP_aes_256_cbc`, and the rest) and
reports the modes that keep data secret without showing whether it was changed: CBC, CTR, CFB, and
OFB. ECB and the retired ciphers stay `ast.weak-cipher`'s.

**It is only ever a finding** (`findingsOnly`), at low confidence. CBC combined with a separate HMAC,
checked before decrypting, satisfies the requirement, and the HMAC is a different call, often in a
different function, which one query cannot see. So a clean run credits nothing, and a finding says in
its fix that encrypt-then-MAC code is already correct. The backlog entry thought this would need new
code; `findingsOnly` had come with the V4.4.1 WebSocket rule, so it was a data entry.

Every language has a found and a not-found case (GCM, ChaCha20-Poly1305, `AesGcm`, a digest command
for shell). Each language's pattern was broken in turn, and three were widened to take in a safe mode;
every break was caught.
