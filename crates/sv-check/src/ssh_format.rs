//! OpenSSH's own formats for an Ed25519 key, written and read here over `ed25519-dalek`, so that
//! `sv review`'s seals (ADR-043) are signatures `ssh-keygen` checks and its key a file `ssh-keygen`
//! reads, without a library that also carries RSA (the owner's decision of 6 October 2026, after
//! `ssh-key` put an RSA crate with an advisory, RUSTSEC-2023-0071, into `sv`'s lockfile).
//!
//! Only what `sv` needs, and nothing read loosely: Ed25519 alone; a private key kept plain or
//! locked as `ssh-keygen` locks one (bcrypt-pbkdf, then AES-256-CTR); a signature in OpenSSH's
//! `SSHSIG` form over SHA-512 (or SHA-256, which `ssh-keygen` can also make). Anything else is
//! refused. The layouts are OpenSSH's `PROTOCOL.key` and `PROTOCOL.sshsig`; the tests in
//! `crate::signed` have `ssh-keygen` read what is written here, and this read what it writes.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroize;

const KEY_TYPE: &str = "ssh-ed25519";
const SIG_MAGIC: &[u8] = b"SSHSIG";
const KEY_MAGIC: &[u8] = b"openssh-key-v1\0";
const PRIVATE_LABEL: &str = "OPENSSH PRIVATE KEY";
#[cfg(test)]
pub(crate) const SIGNATURE_LABEL: &str = "SSH SIGNATURE";
/// The bcrypt rounds `ssh-keygen` uses for a new key.
const ROUNDS: u32 = 16;

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicKey([u8; 32]);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

impl PublicKey {
    pub(crate) fn of(key: &SigningKey) -> PublicKey {
        PublicKey(key.verifying_key().to_bytes())
    }

    /// The key as SSH writes it on the wire: its type, then its 32 bytes.
    pub(crate) fn blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, KEY_TYPE.as_bytes());
        put_string(&mut out, &self.0);
        out
    }

    fn from_blob(blob: &[u8]) -> Result<PublicKey, &'static str> {
        let mut r = Reader(blob);
        if r.string()? != KEY_TYPE.as_bytes() {
            return Err("it is not an Ed25519 key");
        }
        let key = r.fixed::<32>()?;
        r.end()?;
        Ok(PublicKey(key))
    }

    /// The line `ssh-keygen` writes in a `.pub` file: `ssh-ed25519 <base64> <comment>`.
    pub(crate) fn to_openssh(&self, comment: &str) -> String {
        format!("{KEY_TYPE} {} {comment}", base64(&self.blob(), true))
    }

    /// The key in such a line. `None` for a key of another type, which never signs a seal `sv`
    /// accepts; `Err` for an Ed25519 key that cannot be read.
    pub(crate) fn from_openssh(line: &str) -> Result<Option<PublicKey>, &'static str> {
        let mut parts = line.split_whitespace();
        let kind = parts.next().ok_or("it names no key")?;
        let data = parts.next().ok_or("its key has no data")?;
        if kind != KEY_TYPE {
            return Ok(None);
        }
        let blob = unbase64(data).ok_or("its key is not base64")?;
        PublicKey::from_blob(&blob).map(Some)
    }

    /// `SHA256:` and the unpadded base64 of the SHA-256 of the key, as `ssh-keygen -l` shows it.
    pub(crate) fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        format!("SHA256:{}", base64(&Sha256::digest(self.blob()), false))
    }
}

/// An SSH signature (`SSHSIG`) of `message` under `namespace`, over SHA-512, in its wire form.
pub(crate) fn sign(key: &SigningKey, namespace: &str, message: &[u8]) -> Vec<u8> {
    let signed = signed_data(namespace, "sha512", message);
    let signature = key.sign(&signed).to_bytes();
    let mut sig_blob = Vec::new();
    put_string(&mut sig_blob, KEY_TYPE.as_bytes());
    put_string(&mut sig_blob, &signature);
    let mut out = SIG_MAGIC.to_vec();
    out.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut out, &PublicKey::of(key).blob());
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, b"sha512");
    put_string(&mut out, &sig_blob);
    out
}

/// What an SSH signature signs: the message's hash, framed with the namespace.
fn signed_data(namespace: &str, hash: &str, message: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let digest = match hash {
        "sha256" => sha2::Sha256::digest(message).to_vec(),
        _ => sha2::Sha512::digest(message).to_vec(),
    };
    let mut out = SIG_MAGIC.to_vec();
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, hash.as_bytes());
    put_string(&mut out, &digest);
    out
}

/// An SSH signature, read.
#[derive(Debug)]
pub(crate) struct Signature {
    pub(crate) key: PublicKey,
    namespace: Vec<u8>,
    hash: String,
    signature: [u8; 64],
}

impl Signature {
    /// The signature in `blob`, read strictly: version 1, an Ed25519 key and signature, a hash
    /// `ssh-keygen` makes, and nothing after.
    pub(crate) fn parse(blob: &[u8]) -> Result<Signature, &'static str> {
        let mut r = Reader(blob);
        if r.bytes(SIG_MAGIC.len())? != SIG_MAGIC {
            return Err("it is not an SSH signature");
        }
        if r.u32()? != 1 {
            return Err("it is an SSH signature of another version");
        }
        let key = PublicKey::from_blob(r.string()?)?;
        let namespace = r.string()?.to_vec();
        let _reserved = r.string()?;
        let hash = match r.string()? {
            b"sha512" => "sha512",
            b"sha256" => "sha256",
            _ => return Err("it uses a hash `ssh-keygen` does not make"),
        };
        let mut s = Reader(r.string()?);
        if s.string()? != KEY_TYPE.as_bytes() {
            return Err("it is not an Ed25519 signature");
        }
        let signature = s.fixed::<64>()?;
        s.end()?;
        r.end()?;
        Ok(Signature {
            key,
            namespace,
            hash: hash.to_owned(),
            signature,
        })
    }

    /// Whether it is its key's signature of `message` under `namespace`.
    pub(crate) fn verifies(&self, namespace: &str, message: &[u8]) -> bool {
        if self.namespace != namespace.as_bytes() {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(&self.key.0) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        key.verify_strict(&signed_data(namespace, &self.hash, message), &signature)
            .is_ok()
    }
}

/// A private key as it is kept.
pub(crate) enum Kept {
    Plain(SigningKey),
    Locked(LockedKey),
}

/// A private key locked with a passphrase, as `ssh-keygen` locks one.
#[derive(Clone)]
pub(crate) struct LockedKey {
    pub(crate) public: PublicKey,
    salt: Vec<u8>,
    rounds: u32,
    sealed: Vec<u8>,
}

impl LockedKey {
    /// The key, if `passphrase` unlocks it.
    pub(crate) fn unlock(&self, passphrase: &str) -> Result<SigningKey, &'static str> {
        let mut section = self.sealed.clone();
        aes_ctr(passphrase, &self.salt, self.rounds, &mut section)?;
        let key = private_section(&section, 16, &self.public);
        section.zeroize();
        key
    }
}

/// `key` in OpenSSH's private key file, locked with `passphrase` when there is one. `random`
/// fills a buffer from the system's randomness.
pub(crate) fn private_to_openssh(
    key: &SigningKey,
    comment: &str,
    passphrase: Option<&str>,
    random: &dyn Fn(&mut [u8]) -> Result<(), String>,
) -> Result<String, String> {
    let public = PublicKey::of(key);
    let block = if passphrase.is_some() { 16 } else { 8 };
    let mut check = [0u8; 4];
    random(&mut check)?;
    let mut section = Vec::new();
    section.extend_from_slice(&check);
    section.extend_from_slice(&check);
    put_string(&mut section, KEY_TYPE.as_bytes());
    put_string(&mut section, &public.0);
    let mut both = key.to_keypair_bytes();
    put_string(&mut section, &both);
    both.zeroize();
    put_string(&mut section, comment.as_bytes());
    let mut pad = 1u8;
    while section.len() % block != 0 {
        section.push(pad);
        pad += 1;
    }
    let mut out = KEY_MAGIC.to_vec();
    match passphrase {
        Some(p) => {
            let mut salt = [0u8; 16];
            random(&mut salt)?;
            aes_ctr(p, &salt, ROUNDS, &mut section)
                .map_err(|why| format!("the signing key could not be locked ({why})"))?;
            put_string(&mut out, b"aes256-ctr");
            put_string(&mut out, b"bcrypt");
            let mut options = Vec::new();
            put_string(&mut options, &salt);
            options.extend_from_slice(&ROUNDS.to_be_bytes());
            put_string(&mut out, &options);
        }
        None => {
            put_string(&mut out, b"none");
            put_string(&mut out, b"none");
            put_string(&mut out, b"");
        }
    }
    out.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut out, &public.blob());
    put_string(&mut out, &section);
    section.zeroize();
    let text = armor(PRIVATE_LABEL, &out);
    out.zeroize();
    Ok(text)
}

/// The key in an OpenSSH private key file, read strictly: one Ed25519 key, plain or locked as
/// `ssh-keygen` locks one, whose parts agree with each other.
pub(crate) fn private_from_openssh(text: &str) -> Result<Kept, &'static str> {
    let mut bytes = unarmor(PRIVATE_LABEL, text).ok_or("it is not an OpenSSH private key")?;
    let kept = read_private(&bytes);
    bytes.zeroize();
    kept
}

fn read_private(bytes: &[u8]) -> Result<Kept, &'static str> {
    let mut r = Reader(bytes);
    if r.bytes(KEY_MAGIC.len())? != KEY_MAGIC {
        return Err("it is not an OpenSSH private key");
    }
    let cipher = r.string()?;
    let kdf = r.string()?;
    let options = r.string()?;
    if r.u32()? != 1 {
        return Err("it holds more than one key");
    }
    let public = PublicKey::from_blob(r.string()?)?;
    let section = r.string()?;
    r.end()?;
    match (cipher, kdf) {
        (b"none", b"none") if options.is_empty() => {
            Ok(Kept::Plain(private_section(section, 8, &public)?))
        }
        (b"aes256-ctr", b"bcrypt") => {
            let mut o = Reader(options);
            let salt = o.string()?.to_vec();
            let rounds = o.u32()?;
            o.end()?;
            if section.len() % 16 != 0 || salt.is_empty() || rounds == 0 {
                return Err("its locked part cannot be read");
            }
            Ok(Kept::Locked(LockedKey {
                public,
                salt,
                rounds,
                sealed: section.to_vec(),
            }))
        }
        _ => Err("it is locked in a way `sv` does not read"),
    }
}

/// The key in a private section, plain: its two check numbers equal, its parts all the one key.
fn private_section(
    section: &[u8],
    block: usize,
    public: &PublicKey,
) -> Result<SigningKey, &'static str> {
    let mut r = Reader(section);
    if section.len() % block != 0 || r.u32()? != r.u32()? {
        return Err("it does not unlock with that passphrase, or it is damaged");
    }
    if r.string()? != KEY_TYPE.as_bytes() || r.fixed::<32>()? != public.0 {
        return Err("its parts are not one key");
    }
    let both = r.fixed::<64>()?;
    let _comment = r.string()?;
    for (i, b) in r.0.iter().enumerate() {
        if usize::from(*b) != i + 1 {
            return Err("it is damaged");
        }
    }
    let seed: [u8; 32] = both[..32].try_into().expect("32 of 64");
    let key = SigningKey::from_bytes(&seed);
    if PublicKey::of(&key) != *public || both[32..] != public.0 {
        return Err("its parts are not one key");
    }
    Ok(key)
}

/// AES-256-CTR over `data`, keyed by bcrypt-pbkdf of the passphrase, as OpenSSH locks a key.
fn aes_ctr(
    passphrase: &str,
    salt: &[u8],
    rounds: u32,
    data: &mut [u8],
) -> Result<(), &'static str> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let mut derived = [0u8; 48];
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase.as_bytes(), salt, rounds, &mut derived)
        .map_err(|_| "the passphrase could not be used")?;
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&derived[..32], &derived[32..])
        .map_err(|_| "the passphrase could not be used")?;
    derived.zeroize();
    cipher.apply_keystream(data);
    Ok(())
}

/// `bytes` between `-----BEGIN <label>-----` and `-----END <label>-----`, in base64 lines of 70.
pub(crate) fn armor(label: &str, bytes: &[u8]) -> String {
    let body = base64(bytes, true);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The bytes `armor` wrote, or `None`.
pub(crate) fn unarmor(label: &str, text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    let body = text
        .strip_prefix(&format!("-----BEGIN {label}-----"))?
        .strip_suffix(&format!("-----END {label}-----"))?;
    let joined: String = body.split_whitespace().collect();
    unbase64(&joined)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, padded or not.
pub(crate) fn base64(bytes: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
        if pad {
            for _ in chunk.len()..3 {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64, padded to a whole number of groups of four, or `None`.
pub(crate) fn unbase64(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (g, group) in text.chunks(4).enumerate() {
        let last = g == text.len() / 4 - 1;
        let pads = group.iter().rev().take_while(|b| **b == b'=').count();
        if pads > 2 || (pads > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (i, b) in group[..4 - pads].iter().enumerate() {
            let v = ALPHABET.iter().position(|a| a == b)? as u32;
            n |= v << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = 3 - pads;
        // Bits a padded group does not use must be zero, so each text decodes one way only.
        if bytes[keep..].iter().any(|b| *b != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Some(out)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Reads SSH's wire form, refusing anything short.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if self.0.len() < n {
            return Err("it ends too soon");
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_be_bytes(
            self.bytes(4)?.try_into().expect("four bytes"),
        ))
    }

    fn string(&mut self) -> Result<&'a [u8], &'static str> {
        let n = self.u32()? as usize;
        self.bytes(n)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        self.string()?
            .try_into()
            .map_err(|_| "a part is the wrong length")
    }

    fn end(&self) -> Result<(), &'static str> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("something follows its end")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_randomness_needed(buf: &mut [u8]) -> Result<(), String> {
        buf.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = i as u8 + 1);
        Ok(())
    }

    #[test]
    fn a_key_file_whose_parts_are_not_one_key_is_refused() {
        let a = SigningKey::from_bytes(&[7u8; 32]);
        let b = SigningKey::from_bytes(&[9u8; 32]);
        for passphrase in [None, Some("correct horse")] {
            let text = private_to_openssh(&a, "c", passphrase, &no_randomness_needed).unwrap();
            let read = |text: &str| match private_from_openssh(text) {
                Ok(Kept::Plain(key)) => Ok(key),
                Ok(Kept::Locked(locked)) => locked.unlock("correct horse"),
                Err(why) => Err(why),
            };
            assert_eq!(
                read(&text).map(|k| PublicKey::of(&k)),
                Ok(PublicKey::of(&a)),
                "the setup: it reads back"
            );
            // The key named outside the private part swapped for another's.
            let mut bytes = unarmor(PRIVATE_LABEL, &text).unwrap();
            let (pa, pb) = (PublicKey::of(&a).0, PublicKey::of(&b).0);
            let at = bytes.windows(32).position(|w| w == pa).unwrap();
            bytes[at..at + 32].copy_from_slice(&pb);
            assert!(
                read(&armor(PRIVATE_LABEL, &bytes)).is_err(),
                "{passphrase:?}"
            );
            if passphrase.is_some() {
                assert!(
                    matches!(private_from_openssh(&text), Ok(Kept::Locked(l)) if l.unlock("wrong").is_err())
                );
                continue;
            }
            // Inside the plain private part: the seed swapped for another key's, the public
            // halves left as they were.
            let mut bytes = unarmor(PRIVATE_LABEL, &text).unwrap();
            let seed = a.to_bytes();
            let at = bytes.windows(32).position(|w| w == seed).unwrap();
            bytes[at..at + 32].copy_from_slice(&b.to_bytes());
            assert!(read(&armor(PRIVATE_LABEL, &bytes)).is_err());
            // The two check numbers made to differ.
            let mut bytes = unarmor(PRIVATE_LABEL, &text).unwrap();
            let at = bytes.windows(4).position(|w| w == [1, 2, 3, 4]).unwrap();
            bytes[at] ^= 0xff;
            assert!(read(&armor(PRIVATE_LABEL, &bytes)).is_err());
        }
    }

    #[test]
    fn a_signature_is_refused_for_another_namespace_or_message_or_a_changed_byte() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let blob = sign(&key, "securevibe-review", b"the message");
        let sig = Signature::parse(&blob).unwrap();
        assert!(sig.verifies("securevibe-review", b"the message"));
        assert!(!sig.verifies("git", b"the message"));
        assert!(!sig.verifies("securevibe-review", b"the message."));
        // Signed under another namespace, it is refused under ours, though its message is ours.
        let other = Signature::parse(&sign(&key, "git", b"the message")).unwrap();
        assert!(!other.verifies("securevibe-review", b"the message"));
        // Any one byte of the signature changed.
        for i in [blob.len() - 1, blob.len() - 40] {
            let mut bent = blob.clone();
            bent[i] ^= 1;
            assert!(
                Signature::parse(&bent)
                    .is_ok_and(|s| !s.verifies("securevibe-review", b"the message"))
            );
        }
        // Something after its end, or a part cut short.
        let mut longer = blob.clone();
        longer.push(0);
        assert!(Signature::parse(&longer).is_err());
        assert!(Signature::parse(&blob[..blob.len() - 1]).is_err());
    }

    #[test]
    fn base64_is_the_standard_one_and_reads_back_one_way_only() {
        for (bytes, text) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff], "+/8="),
        ] {
            assert_eq!(base64(bytes, true), text);
            assert_eq!(unbase64(text).as_deref(), Some(bytes), "{text}");
        }
        assert_eq!(base64(b"f", false), "Zg");
        for bad in ["Zg=", "Zh==", "Zg==Zg==", "Z===", "Zm9v!A==", "Zm9"] {
            assert_eq!(unbase64(bad), None, "{bad}");
        }
    }
}
