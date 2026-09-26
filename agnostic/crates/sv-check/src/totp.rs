//! Time-based one-time passwords (RFC 6238), computed the way an authenticator app computes them.
//!
//! The seeded TOTP checks hand the app a secret and then need the codes an authenticator would show
//! for it — the current one, and ones from steps already past. Computing them here, rather than
//! waiting for them, is what lets V6.5.5 be asked without a slow mode: a code from two and a half
//! minutes ago is a calculation, not a wait.
//!
//! The HMAC and SHA-1 are the RustCrypto crates; this file only does what RFC 4226 and RFC 6238 add
//! on top, and the RFC's own test values hold it.

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// The length of a step, in seconds: what every authenticator app uses.
pub const STEP: u64 = 30;

/// The six-digit code for a secret at a step counter (RFC 4226's HOTP, which TOTP is at
/// `unix time / 30`).
pub fn code_at_step(secret: &[u8], step: u64) -> String {
    digits(secret, step, 6)
}

/// The code for a secret at a moment, in seconds since 1970.
pub fn code_at(secret: &[u8], unix: u64) -> String {
    code_at_step(secret, unix / STEP)
}

fn digits(secret: &[u8], step: u64, n: u32) -> String {
    let mut mac = <Hmac<Sha1>>::new_from_slice(secret).expect("HMAC takes a key of any length");
    mac.update(&step.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    // Dynamic truncation, RFC 4226 section 5.3.
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let value = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:0width$}", value % 10u32.pow(n), width = n as usize)
}

/// Base32 without padding (RFC 4648), the form authenticator apps and most TOTP libraries take a
/// secret in.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B: the SHA-1 test secret and its eight-digit codes.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn the_rfc_test_values_come_out() {
        for (time, eight) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(digits(RFC_SECRET, time / STEP, 8), eight, "at {time}");
            assert_eq!(
                code_at(RFC_SECRET, time),
                eight[2..],
                "six digits at {time}"
            );
        }
    }

    #[test]
    fn base32_is_the_rfc_4648_alphabet_without_padding() {
        // RFC 4648 section 10's test vectors, padding removed.
        for (text, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(text.as_bytes()), encoded, "{text:?}");
        }
    }
}
