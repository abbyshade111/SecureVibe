//! V5.2.3: compressed files sent to the upload, to the limits the owner states (ADR-046).
//!
//! The owner says which formats the app unpacks (`unpacks-archives`), the most one may unpack to
//! (`max-unpacked-bytes`), and the most files one may hold (`max-files`). For each format listed,
//! an ordinary small archive goes first, to show the upload takes that format at all; then one
//! that unpacks to just over the stated most, and, for zip, one holding one file more than the
//! stated most. Refused is credited when an ordinary file sent straight after is accepted; taken is
//! a finding, since the owner says the app unpacks it; a crash is held back by the run's own rule
//! for refusals (`RESTS_ON_A_REFUSAL`).
//!
//! The archives are written here, with no library: what unpacks to a great deal is a run of zeros,
//! and a run of zeros compresses to a few lines of code.

use super::*;
use sv_manifest::{ArchiveFormat, UploadSection};

/// The most any archive here unpacks to. A stated limit above it is not tested: one gigabyte
/// already shows whether the app counts, and more would only be a heavier load on the owner's own
/// copy of the app.
pub(super) const MOST_UNPACKED_BYTES: u64 = 1 << 30;

/// How far past the stated most an archive unpacks: enough that an app counting in large pieces
/// still passes its limit, and small beside any limit worth stating.
const OVER_BY: u64 = 1 << 20;

/// What the ordinary archives hold, so the app has a real file to find inside them.
const ORDINARY_TEXT: &[u8] = b"sv-probe-ordinary-file\n";

/// The most files a zip here holds: a zip without its 64-bit extension counts them in 16 bits.
const MOST_FILES: u64 = 0xffff;

/// Bits written least significant first, as deflate packs them.
struct Bits {
    out: Vec<u8>,
    held: u32,
    count: u32,
}

impl Bits {
    fn new() -> Self {
        Bits {
            out: Vec::new(),
            held: 0,
            count: 0,
        }
    }

    /// A number in `n` bits, lowest bit first: the header fields and extra bits.
    fn value(&mut self, value: u32, n: u32) {
        for i in 0..n {
            self.bit((value >> i) & 1);
        }
    }

    /// A Huffman code, written as deflate writes one: its first bit first.
    fn code(&mut self, code: &str) {
        for c in code.bytes() {
            self.bit(u32::from(c == b'1'));
        }
    }

    fn bit(&mut self, b: u32) {
        self.held |= b << self.count;
        self.count += 1;
        if self.count == 8 {
            self.out.push(self.held as u8);
            self.held = 0;
            self.count = 0;
        }
    }

    /// `n` zero bits at once, a whole byte at a time where it can: the bulk of a large stream.
    fn zeros(&mut self, mut n: u64) {
        while n > 0 && self.count != 0 {
            self.bit(0);
            n -= 1;
        }
        self.out.extend(std::iter::repeat_n(0u8, (n / 8) as usize));
        for _ in 0..n % 8 {
            self.bit(0);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.count > 0 {
            self.out.push(self.held as u8);
        }
        self.out
    }
}

/// A raw deflate stream (RFC 1951) that unpacks to `n` zero bytes.
///
/// One block with codes of its own. The literal/length code has three symbols: length 258 (285)
/// in one bit `0`, the zero byte in `10`, and the end of the block in `11`. The distance code has
/// one, distance 1, in one bit `0`. So the stream is a zero byte, then a copy of the last 258 bytes
/// one byte back, again and again, each copy two zero bits; and whatever is left, under 258, as
/// zero bytes. About a thousand bytes out for every one in, the most deflate allows.
pub fn deflate_zeros(n: u64) -> Vec<u8> {
    let mut b = Bits::new();
    zeros_header(&mut b);
    if n > 0 {
        b.code("10"); // the first zero byte
        let copies = (n - 1) / 258;
        b.zeros(copies * 2); // each copy: length 258 `0`, distance 1 `0`
        for _ in 0..(n - 1) % 258 {
            b.code("10");
        }
    }
    b.code("11"); // the end of the block
    b.finish()
}

/// The start of every stream [`deflate_zeros`] writes: the block's header and its three codes.
fn zeros_header(b: &mut Bits) {
    b.value(1, 1); // the last block
    b.value(2, 2); // with codes of its own
    b.value(286 - 257, 5); // literal/length lengths given: 286
    b.value(0, 5); // distance lengths given: 1
    b.value(18 - 4, 4); // code-length lengths given: 18, in the order below
    // The lengths of the code that writes the other two codes' lengths, in deflate's fixed order
    // 16 17 18 0 8 7 9 6 10 5 11 4 12 3 13 2 14 1: symbol 18 (a run of zeros) in one bit, symbols
    // 1 and 2 (a length of 1 or 2) in two.
    for len in [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2] {
        b.value(len, 3);
    }
    // Their codes: 18 is `0`, 1 is `10`, 2 is `11`. The literal/length lengths are 2 for the zero
    // byte, 255 zeros, 2 for the end of the block, 28 zeros, 1 for length 258; then the one
    // distance length, 1.
    b.code("11");
    b.code("0");
    b.value(138 - 11, 7);
    b.code("0");
    b.value(255 - 138 - 11, 7);
    b.code("11");
    b.code("0");
    b.value(28 - 11, 7);
    b.code("10");
    b.code("10");
}

/// A raw deflate stream that holds `data` as it is, in stored blocks.
fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pieces = data.chunks(0xffff).peekable();
    if pieces.peek().is_none() {
        return vec![1, 0, 0, 0xff, 0xff];
    }
    while let Some(piece) = pieces.next() {
        out.push(u8::from(pieces.peek().is_none()));
        let len = piece.len() as u16;
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend(piece);
    }
    out
}

/// The CRC-32 that zip and gzip carry, of `data`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The CRC-32 of `n` zero bytes, without going through them: feeding one zero byte is a linear
/// step on the CRC's 32 bits, so `n` of them is that step raised to the `n`th power, by squaring.
fn crc32_of_zeros(n: u64) -> u32 {
    type Matrix = [u32; 32];
    fn apply(m: &Matrix, v: u32) -> u32 {
        (0..32).fold(0, |acc, i| if v >> i & 1 == 1 { acc ^ m[i] } else { acc })
    }
    fn times(a: &Matrix, b: &Matrix) -> Matrix {
        std::array::from_fn(|i| apply(a, b[i]))
    }
    // One zero byte, as a matrix: column i is where bit i of the CRC goes.
    let mut step: Matrix = std::array::from_fn(|i| {
        let mut crc = 1u32 << i;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
        crc
    });
    let mut whole: Matrix = std::array::from_fn(|i| 1 << i);
    let mut n = n;
    while n > 0 {
        if n & 1 == 1 {
            whole = times(&step, &whole);
        }
        step = times(&step, &step);
        n >>= 1;
    }
    !apply(&whole, !0)
}

/// A gzip file (RFC 1952) around a deflate stream.
fn gzip(deflated: &[u8], crc: u32, size: u64) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend(deflated);
    out.extend(crc.to_le_bytes());
    out.extend((size as u32).to_le_bytes());
    out
}

/// One file inside a zip.
struct Entry {
    name: String,
    method: u16,
    data: Vec<u8>,
    crc: u32,
    size: u32,
}

/// A zip file of `entries`, each with its local header, its data, and its line in the central
/// directory at the end.
fn zip(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for e in entries {
        let at = out.len() as u32;
        let header = |signature: u32, central: bool| {
            let mut h = Vec::new();
            h.extend(signature.to_le_bytes());
            if central {
                h.extend(20u16.to_le_bytes()); // made by
            }
            h.extend(20u16.to_le_bytes()); // needed to unpack
            h.extend(0u16.to_le_bytes()); // flags
            h.extend(e.method.to_le_bytes());
            h.extend(0u16.to_le_bytes()); // time
            h.extend(0x21u16.to_le_bytes()); // date: 1 January 1980
            h.extend(e.crc.to_le_bytes());
            h.extend((e.data.len() as u32).to_le_bytes());
            h.extend(e.size.to_le_bytes());
            h.extend((e.name.len() as u16).to_le_bytes());
            h.extend(0u16.to_le_bytes()); // extra field
            if central {
                h.extend(0u16.to_le_bytes()); // comment
                h.extend(0u16.to_le_bytes()); // disk
                h.extend(0u16.to_le_bytes()); // internal attributes
                h.extend(0u32.to_le_bytes()); // external attributes
                h.extend(at.to_le_bytes());
            }
            h.extend(e.name.as_bytes());
            h
        };
        out.extend(header(0x0403_4b50, false));
        out.extend(&e.data);
        directory.extend(header(0x0201_4b50, true));
    }
    let directory_at = out.len() as u32;
    let count = entries.len() as u16;
    out.extend(&directory);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend((directory.len() as u32).to_le_bytes());
    out.extend(directory_at.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

/// A small archive of `format` holding one ordinary text file.
pub fn ordinary(format: &str) -> Vec<u8> {
    let crc = crc32(ORDINARY_TEXT);
    let size = ORDINARY_TEXT.len() as u32;
    match format {
        "gzip" => gzip(&deflate_stored(ORDINARY_TEXT), crc, size.into()),
        _ => zip(&[Entry {
            name: "sv-probe.txt".to_owned(),
            method: 0,
            data: ORDINARY_TEXT.to_vec(),
            crc,
            size,
        }]),
    }
}

/// An archive of `format` holding one file of `n` zero bytes, compressed.
pub fn unpacks_to(format: &str, n: u64) -> Vec<u8> {
    let deflated = deflate_zeros(n);
    let crc = crc32_of_zeros(n);
    match format {
        "gzip" => gzip(&deflated, crc, n),
        _ => zip(&[Entry {
            name: "sv-probe-zeros.txt".to_owned(),
            method: 8,
            data: deflated,
            crc,
            size: n as u32,
        }]),
    }
}

/// A zip whose headers say its one file unpacks to `stated` bytes, while its data unpacks to `n`
/// zero bytes, with the CRC of what really comes out. An app that checks only what a zip states
/// lets it through; one that counts what it unpacks does not; and a reader that stops at the
/// stated size and then checks the CRC, as Python's `zipfile` does, unpacks nothing from it and
/// fails it.
pub fn stating_less(n: u64, stated: u32) -> Vec<u8> {
    zip(&[Entry {
        name: "sv-probe-zeros.txt".to_owned(),
        method: 8,
        data: deflate_zeros(n),
        crc: crc32_of_zeros(n),
        size: stated,
    }])
}

/// What a zip whose stated sizes are false says its file unpacks to: an ordinary small file, and
/// never more than half the stated most, so the stated size alone is never what is refused.
const STATED_BYTES: u64 = 1024;

/// A zip holding `n` empty files.
pub fn holding_files(n: u64) -> Vec<u8> {
    let entries: Vec<Entry> = (0..n)
        .map(|i| Entry {
            name: format!("sv-probe-{i}.txt"),
            method: 0,
            data: Vec::new(),
            crc: 0,
            size: 0,
        })
        .collect();
    zip(&entries)
}

/// The file name an archive of `format` is sent under.
fn file_name(format: &str, what: &str) -> String {
    match format {
        "gzip" => format!("sv-probe-{what}.txt.gz"),
        _ => format!("sv-probe-{what}.zip"),
    }
}

/// One archive just over one stated limit: what it is, and the bytes that are sent.
struct OverLimit {
    what: String,
    id: String,
    bytes: Vec<u8>,
}

/// The archives just over the stated limits for one format, and for each limit that cannot be
/// tested inside this check's own caps, why not.
fn over_limits(format: ArchiveFormat, upload: &UploadSection) -> (Vec<OverLimit>, Vec<String>) {
    let f = format.name();
    let mut sent = Vec::new();
    let mut not = Vec::new();
    if let Some(most) = upload.max_unpacked_bytes {
        let n = most.saturating_add(OVER_BY);
        if n > MOST_UNPACKED_BYTES {
            not.push(format!(
                "`max-unpacked-bytes` is {most}, and a {f} just over it would unpack to more than \
                 the {MOST_UNPACKED_BYTES} bytes this check ever sends"
            ));
        } else {
            sent.push(OverLimit {
                what: format!("A {f} that unpacks to {n} bytes (the stated most is {most})"),
                id: format!("upload-archive-{f}-unpacked"),
                bytes: unpacks_to(f, n),
            });
            // The same zip, saying in its headers that it is small: an app that checks only what a
            // zip states lets this one through (backlog 0029, part 15; ADR-046, later).
            let stated = STATED_BYTES.min(most / 2);
            if format == ArchiveFormat::Zip && stated > 0 {
                sent.push(OverLimit {
                    what: format!(
                        "A zip that says it unpacks to {stated} bytes and really unpacks to {n} \
                         (the stated most is {most})"
                    ),
                    id: "upload-archive-zip-stating-less".to_owned(),
                    bytes: stating_less(n, stated as u32),
                });
            }
        }
    }
    if let (Some(most), ArchiveFormat::Zip) = (upload.max_files, format) {
        let n = most.saturating_add(1);
        if n > MOST_FILES {
            not.push(format!(
                "`max-files` is {most}, and a zip holds at most {MOST_FILES} files without the \
                 extension this check does not write"
            ));
        } else {
            sent.push(OverLimit {
                what: format!("A zip holding {n} files (the stated most is {most})"),
                id: "upload-archive-zip-files".to_owned(),
                bytes: holding_files(n),
            });
        }
    }
    (sent, not)
}

/// V5.2.3: for each format the owner says the app unpacks, an ordinary archive, then one just over
/// each stated limit. Last of the uploads, and with a sign-in of its own, so an app that unpacks
/// one and falls over takes no other upload check with it.
pub(super) fn archive_checks(
    http: &mut dyn Http,
    users: &UsersSection,
    accounts: &Accounts,
    confirm: Option<&str>,
    out: &mut Outcome,
) {
    let Some(upload) = &users.upload else {
        return;
    };
    let Some(formats) = &upload.unpacks_archives else {
        out.not_assessed.push((
            "V5.2.3".to_owned(),
            "Whether the app checks a compressed file before it unpacks it: if it unpacks any, \
             list them as `unpacks-archives = [\"zip\", \"gzip\"]` on the `upload` entry in \
             stackvet.toml, with `max-unpacked-bytes` and `max-files`, and an archive just over \
             each will be sent. If it unpacks none, `unpacks-archives = []` says so."
                .to_owned(),
        ));
        return;
    };
    let mut formats = formats.clone();
    formats.sort();
    formats.dedup();
    if formats.is_empty() {
        out.steps
            .push("sent no compressed file: stackvet.toml says the app unpacks none".to_owned());
        return;
    }
    if upload.max_unpacked_bytes.is_none() && upload.max_files.is_none() {
        out.not_assessed.push((
            "V5.2.3".to_owned(),
            "stackvet.toml says the app unpacks compressed files, and states no limit for them: \
             add `max-unpacked-bytes` (the most one may unpack to) and `max-files` (the most files \
             one may hold) to the `upload` entry. `sv` sets no limit of its own."
                .to_owned(),
        ));
        return;
    }
    let Some(signed_in) =
        confirm.and_then(|_| sign_in(http, users, "a-archives", &accounts.a, &mut out.steps))
    else {
        out.not_assessed.push((
            "V5.2.3".to_owned(),
            "Compressed files were to be sent with a sign-in of their own, and the sign-in did not \
             work, so none was sent."
                .to_owned(),
        ));
        return;
    };
    let session = &signed_in.session;
    let token = Token {
        page: users.private.first().map(String::as_str),
        session,
        wanted: upload.form.values().any(|v| v.contains("{csrf}")),
    };
    for format in formats {
        let f = format.name();
        let (over, untested) = over_limits(format, upload);
        for why in untested {
            out.not_assessed
                .push(("V5.2.3".to_owned(), format!("{why}.")));
        }
        if over.is_empty() {
            if format == ArchiveFormat::Gzip && upload.max_unpacked_bytes.is_none() {
                out.steps.push(
                    "sent no gzip: a gzip holds one file, so `max-files` does not apply to it, \
                     and no `max-unpacked-bytes` is stated"
                        .to_owned(),
                );
                // Not silence: nothing was sent because no stated limit applies, which leaves the
                // question open, and the report says why (found by the guard per check, 8 October
                // 2026).
                out.not_assessed.push((
                    "V5.2.3".to_owned(),
                    "stackvet.toml says the app unpacks gzip files and states only `max-files`, \
                     which a gzip, holding one file, cannot be over: add `max-unpacked-bytes` (the \
                     most one may unpack to) and a gzip just over it will be sent."
                        .to_owned(),
                ));
            }
            continue;
        }
        let name = file_name(f, "ordinary");
        let id = format!("upload-archive-{f}-ordinary");
        let ordinary = send_bytes(http, upload, (&id, &name, &ordinary(f)), session, &token);
        if refused(&ordinary) {
            out.not_assessed.push((
                "V5.2.3".to_owned(),
                format!(
                    "An ordinary small {f} was not accepted at {} ({}), so nothing here can tell a \
                     {f} refused for unpacking too far from one refused for being a {f} at all.",
                    upload.path,
                    status(&ordinary)
                ),
            ));
            continue;
        }
        out.steps
            .push(format!("uploaded an ordinary small {f} to {}", upload.path));
        for archive in over {
            if archive.bytes.len() as u64 > MOST_UPLOAD_BYTES
                || upload
                    .max_bytes
                    .is_some_and(|most| archive.bytes.len() as u64 > most)
            {
                out.not_assessed.push((
                    "V5.2.3".to_owned(),
                    format!(
                        "{} would itself be {} bytes, more than `max-bytes` or the {} this check \
                         sends, so a refusal could not be told from a refusal of its size.",
                        archive.what,
                        archive.bytes.len(),
                        MOST_UPLOAD_BYTES
                    ),
                ));
                continue;
            }
            let name = file_name(f, archive.id.trim_start_matches("upload-archive-"));
            let answer = send_bytes(
                http,
                upload,
                (&archive.id, &name, &archive.bytes),
                session,
                &token,
            );
            let was_refused = refused(&answer);
            out.steps.push(format!(
                "sent {} ({} bytes as sent): {}",
                lower_first(&archive.what),
                archive.bytes.len(),
                if was_refused { "refused" } else { "accepted" }
            ));
            if !was_refused {
                out.findings.push(finding(
                    &ARCHIVE_UNCHECKED,
                    "A compressed file past the stated limits was accepted",
                    Severity::Medium,
                    format!(
                        "stackvet.toml says the app unpacks {f} files. {} was accepted at {} \
                         ({}), where an app that checks first refuses it.",
                        archive.what,
                        upload.path,
                        status(&answer)
                    ),
                ));
            } else if upload.max_bytes.is_none() {
                out.not_assessed.push((
                    "V5.2.3".to_owned(),
                    format!(
                        "{} was refused, but with no `max-bytes` stated nothing here can tell a \
                         refusal of what it unpacks to from a refusal of its own size ({} bytes).",
                        archive.what,
                        archive.bytes.len()
                    ),
                ));
            } else if refusal_stands(
                http,
                upload,
                session,
                &token,
                archive.id.trim_start_matches("upload-"),
                "V5.2.3",
                &archive.what,
                out,
            ) {
                out.verified.push(
                    crate::Verified::new(
                        ARCHIVE_UNCHECKED.rule_id,
                        ARCHIVE_UNCHECKED.requirement_ids,
                        format!(
                            "{}, refused where an ordinary {f} and an ordinary file after it were \
                         accepted",
                            lower_first(&archive.what)
                        ),
                    )
                    // One archive on the one upload route stackvet.toml names (ADR-053, Later).
                    .in_part(),
                );
            }
        }
    }
}

/// The sentence's first letter in lower case, to put it inside another sentence.
fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|first| first.to_lowercase().chain(c).collect())
        .unwrap_or_default()
}

/// How many zero bytes a stream written by [`deflate_zeros`] unpacks to, read back the way it was
/// written, or `None` for any other stream. The fake app's way of counting what such an archive
/// really holds, as an app that counts while it unpacks does, without a deflate library.
#[cfg(test)]
pub(super) fn zeros_in(deflated: &[u8]) -> Option<u64> {
    let mut header = Bits::new();
    zeros_header(&mut header);
    let header_bits = header.out.len() * 8 + header.count as usize;
    let header = header.finish();
    let bit = |i: usize| Some((deflated.get(i / 8)? >> (i % 8)) & 1);
    for i in 0..header_bits {
        if bit(i)? != (header[i / 8] >> (i % 8)) & 1 {
            return None;
        }
    }
    let (mut at, mut total) = (header_bits, 0u64);
    loop {
        match (bit(at)?, bit(at + 1)?) {
            // A copy of 258 bytes, one back: there must be a byte before it to copy.
            (0, 0) if total > 0 => total += 258,
            (1, 0) => total += 1,
            (1, 1) => return Some(total),
            _ => return None,
        }
        at += 2;
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_app::*;
    use super::*;
    use sv_manifest::ArchiveFormat::{Gzip, Zip};

    fn with_archives(
        formats: Option<Vec<ArchiveFormat>>,
        unpacked: Option<u64>,
        files: Option<u64>,
        max_bytes: Option<u64>,
    ) -> UsersSection {
        let mut u = users();
        u.upload = Some(UploadSection {
            path: "/upload".into(),
            field: "file".into(),
            form: [("csrf_token".to_owned(), "{csrf}".to_owned())].into(),
            serves_at: Some("/files/{name}".into()),
            max_bytes,
            unpacks_archives: formats,
            max_unpacked_bytes: unpacked,
            max_files: files,
        });
        u
    }

    /// The fake app's own limits, stated as the owner would.
    fn stated() -> UsersSection {
        with_archives(
            Some(vec![Zip, Gzip]),
            Some(ARCHIVE_UNPACK_LIMIT),
            Some(ARCHIVE_FILE_LIMIT),
            Some(UPLOAD_LIMIT as u64),
        )
    }

    fn credits(o: &Outcome) -> Vec<&str> {
        o.verified
            .iter()
            .filter(|v| v.check_id == ARCHIVE_UNCHECKED.rule_id)
            .map(|v| v.scope.as_str())
            .collect()
    }

    fn found(o: &Outcome) -> Vec<&str> {
        o.findings
            .iter()
            .filter(|f| f.rule_id == ARCHIVE_UNCHECKED.rule_id)
            .map(|f| f.description.as_str())
            .collect()
    }

    fn unassessed(o: &Outcome) -> Vec<&str> {
        o.not_assessed
            .iter()
            .filter(|(r, _)| r.contains("V5.2.3"))
            .map(|(_, why)| why.as_str())
            .collect()
    }

    #[test]
    fn an_app_that_checks_both_limits_is_credited_for_each_archive() {
        let o = run_against(Flaws::default(), &stated());
        let c = credits(&o);
        assert_eq!(c.len(), 4, "{c:?} / {:?}", unassessed(&o));
        assert!(
            c.iter()
                .any(|s| s.starts_with("a zip that unpacks to 2097152 bytes")),
            "{c:?}"
        );
        assert!(
            c.iter().any(|s| s.starts_with(
                "a zip that says it unpacks to 1024 bytes and really unpacks to 2097152 (the \
                 stated most is 1048576), refused"
            )),
            "{c:?}"
        );
        assert!(
            c.iter()
                .any(|s| s.starts_with("a gzip that unpacks to 2097152 bytes")),
            "{c:?}"
        );
        assert!(
            c.iter()
                .any(|s| s.starts_with("a zip holding 11 files (the stated most is 10)")),
            "{c:?}"
        );
        assert!(found(&o).is_empty() && unassessed(&o).is_empty());
        // Archives on the one upload route stackvet.toml names (ADR-053, Later).
        assert!(credited_in_part(&o, ARCHIVE_UNCHECKED.rule_id));
        assert!(
            o.steps
                .iter()
                .any(|s| s == "uploaded an ordinary small zip to /upload")
        );
        assert!(
            o.steps
                .iter()
                .any(|s| s == "uploaded an ordinary small gzip to /upload")
        );
    }

    #[test]
    fn an_app_that_does_not_add_up_what_an_archive_unpacks_to_is_found() {
        let o = run_against(
            Flaws {
                archive_size_unchecked: true,
                ..Default::default()
            },
            &stated(),
        );
        let f = found(&o);
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f.iter().all(|e| {
            e.contains("unpacks to 2097152 bytes (the stated most is 1048576) was accepted")
                || e.contains("really unpacks to 2097152 (the stated most is 1048576) was accepted")
        }));
        assert!(
            f.iter()
                .any(|e| e.starts_with("stackvet.toml says the app unpacks gzip"))
        );
        assert_eq!(
            credits(&o),
            vec![
                "a zip holding 11 files (the stated most is 10), refused where an ordinary zip and an ordinary file after it were accepted"
            ]
        );
    }

    #[test]
    fn an_app_that_trusts_what_a_zip_says_it_unpacks_to_is_found_by_the_zip_that_says_less() {
        let o = run_against(
            Flaws {
                archive_trusts_stated_sizes: true,
                ..Default::default()
            },
            &stated(),
        );
        let f = found(&o);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].contains(
                "A zip that says it unpacks to 1024 bytes and really unpacks to 2097152 (the \
                 stated most is 1048576) was accepted at /upload (201)"
            ),
            "{f:?}"
        );
        // Every archive that says truly what it holds is still refused, and credited.
        assert_eq!(credits(&o).len(), 3, "{:?}", credits(&o));
        assert!(
            o.steps.iter().any(|s| s.starts_with(
                "sent a zip that says it unpacks to 1024 bytes and really unpacks to 2097152"
            ) && s.ends_with("accepted")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn a_stated_most_too_small_to_say_less_sends_no_zip_that_says_less() {
        // Half of a stated most of 1 byte is nothing, so a zip saying less than the most cannot be
        // written; the zip just over the most is still sent.
        let tiny = with_archives(Some(vec![Zip]), Some(1), None, Some(UPLOAD_LIMIT as u64));
        let o = run_against(Flaws::default(), &tiny);
        assert!(
            !o.steps.iter().any(|s| s.contains("says it unpacks to")),
            "{:?}",
            o.steps
        );
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("sent a zip that unpacks to 1048577 bytes")),
            "{:?}",
            o.steps
        );
    }

    #[test]
    fn the_fake_apps_reader_counts_what_sv_compresses_and_nothing_else() {
        for n in [0u64, 1, 2, 257, 258, 259, 516, 2_097_152] {
            assert_eq!(zeros_in(&deflate_zeros(n)), Some(n), "{n} zeros");
        }
        assert_eq!(zeros_in(&deflate_stored(b"not zeros")), None);
        assert_eq!(zeros_in(&[]), None);
        // A stream cut short is not read as a smaller one.
        let whole = deflate_zeros(100_000);
        assert_eq!(zeros_in(&whole[..whole.len() / 2]), None);
        // A copy with no byte before it to copy is not a stream deflate allows.
        let mut b = Bits::new();
        zeros_header(&mut b);
        b.code("0");
        b.code("0");
        b.code("11");
        assert_eq!(zeros_in(&b.finish()), None);
    }

    #[test]
    fn a_zip_that_says_less_unpacks_to_more_and_pythons_zipfile_refuses_it() {
        let n = 2_097_152;
        let zip = stating_less(n, 1024);
        // What its headers say, and what its data really unpacks to, read past the stated size.
        assert_eq!(python(READ_PAST_STATED, &zip), format!("1024 {n}"));
        // `zipfile` stops at the stated size and then checks the CRC, so it fails it.
        assert!(
            python_fails(READ_ZIP, &zip),
            "Python's zipfile read a zip whose stated size is false"
        );
    }

    #[test]
    fn an_app_that_does_not_count_a_zips_files_is_found() {
        let o = run_against(
            Flaws {
                archive_files_unchecked: true,
                ..Default::default()
            },
            &stated(),
        );
        let f = found(&o);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].contains("A zip holding 11 files (the stated most is 10) was accepted at /upload"),
            "{f:?}"
        );
        assert_eq!(credits(&o).len(), 3);
    }

    #[test]
    fn a_crash_on_an_archive_is_neither_a_pass_nor_a_finding() {
        let o = run_against(
            Flaws {
                archive_crashes: true,
                ..Default::default()
            },
            &stated(),
        );
        assert!(credits(&o).is_empty(), "{:?}", credits(&o));
        assert!(found(&o).is_empty());
        let u = unassessed(&o);
        assert!(
            u.iter().any(|w| w.contains("crashed or did not answer")),
            "{u:?}"
        );
    }

    #[test]
    fn an_upload_that_takes_no_archive_at_all_says_so_and_credits_nothing() {
        let o = run_against(
            Flaws {
                refuses_archives: true,
                ..Default::default()
            },
            &stated(),
        );
        assert!(credits(&o).is_empty() && found(&o).is_empty());
        let u = unassessed(&o);
        assert_eq!(u.len(), 2, "{u:?}");
        assert!(
            u[0].starts_with("An ordinary small zip was not accepted at /upload (415)"),
            "{u:?}"
        );
        assert!(
            u[1].starts_with("An ordinary small gzip was not accepted"),
            "{u:?}"
        );
    }

    #[test]
    fn nothing_is_sent_until_the_owner_says_what_the_app_unpacks() {
        // Not said: asked for, and nothing sent. The app takes anything, so a sent archive would
        // have been found.
        let flaws = Flaws {
            archive_size_unchecked: true,
            archive_files_unchecked: true,
            ..Default::default()
        };
        let o = run_against(
            flaws,
            &with_archives(
                None,
                Some(ARCHIVE_UNPACK_LIMIT),
                Some(ARCHIVE_FILE_LIMIT),
                Some(UPLOAD_LIMIT as u64),
            ),
        );
        assert!(found(&o).is_empty() && credits(&o).is_empty());
        assert!(
            unassessed(&o)[0].contains("`unpacks-archives = []` says so"),
            "{:?}",
            unassessed(&o)
        );
        // Said to be none: nothing sent, nothing asked.
        let o = run_against(
            flaws,
            &with_archives(
                Some(vec![]),
                Some(ARCHIVE_UNPACK_LIMIT),
                Some(ARCHIVE_FILE_LIMIT),
                Some(UPLOAD_LIMIT as u64),
            ),
        );
        assert!(found(&o).is_empty() && unassessed(&o).is_empty());
        assert!(
            o.steps
                .iter()
                .any(|s| s == "sent no compressed file: stackvet.toml says the app unpacks none")
        );
        // Only gzip, which is not sent as zip.
        let o = run_against(
            flaws,
            &with_archives(
                Some(vec![Gzip]),
                Some(ARCHIVE_UNPACK_LIMIT),
                Some(ARCHIVE_FILE_LIMIT),
                Some(UPLOAD_LIMIT as u64),
            ),
        );
        assert_eq!(found(&o).len(), 1);
        assert!(found(&o)[0].contains("unpacks gzip"));
        // Only gzip and only a count of files, which a gzip cannot be over.
        let o = run_against(
            flaws,
            &with_archives(
                Some(vec![Gzip]),
                None,
                Some(ARCHIVE_FILE_LIMIT),
                Some(UPLOAD_LIMIT as u64),
            ),
        );
        assert!(found(&o).is_empty());
        assert!(
            o.steps
                .iter()
                .any(|s| s.starts_with("sent no gzip: a gzip holds one file"))
        );
        // Not silence: the question is open, and the report says what would settle it.
        assert!(
            unassessed(&o)
                .iter()
                .any(|u| u.contains("add `max-unpacked-bytes`")),
            "{:?}",
            unassessed(&o)
        );
        // No limits at all: asked for.
        let o = run_against(
            flaws,
            &with_archives(Some(vec![Zip]), None, None, Some(UPLOAD_LIMIT as u64)),
        );
        assert!(found(&o).is_empty());
        assert!(
            unassessed(&o)[0].contains("states no limit"),
            "{:?}",
            unassessed(&o)
        );
    }

    #[test]
    fn a_limit_past_the_checks_own_caps_is_said_and_not_tested() {
        let o = run_against(
            Flaws::default(),
            &with_archives(
                Some(vec![Zip]),
                Some(MOST_UNPACKED_BYTES),
                Some(MOST_FILES),
                Some(UPLOAD_LIMIT as u64),
            ),
        );
        let u = unassessed(&o);
        assert_eq!(u.len(), 2, "{u:?}");
        assert!(
            u[0].contains("more than the 1073741824 bytes this check ever sends"),
            "{u:?}"
        );
        assert!(u[1].contains("a zip holds at most 65535 files"), "{u:?}");
        assert!(credits(&o).is_empty());
        // An archive larger than `max-bytes` is not sent: a refusal could be of its size.
        let o = run_against(
            Flaws::default(),
            &with_archives(
                Some(vec![Zip]),
                Some(ARCHIVE_UNPACK_LIMIT),
                None,
                Some(1000),
            ),
        );
        let u = unassessed(&o);
        assert!(
            u.iter().any(|w| w.contains("more than `max-bytes`")),
            "{u:?}"
        );
        assert!(credits(&o).is_empty());
    }

    #[test]
    fn a_refusal_that_was_a_full_quota_is_not_credited() {
        let users = stated();
        let acc = accounts();
        let fresh = |quota: Option<usize>| {
            let mut app = FakeApp::new(Flaws::default());
            for (account, admin) in [(&acc.a, false), (&acc.b, false)] {
                app.users
                    .insert(account.user.clone(), (account.password.clone(), admin));
            }
            let admin = acc.admin.clone().unwrap();
            app.users.insert(admin.user, (admin.password, true));
            app.upload_quota = quota;
            app
        };
        // The setup: how many files a correct app holds at the end, six of them from here (two
        // ordinary archives, and an ordinary file after each of the four refusals; the ordinary
        // zip is the first).
        let mut app = fresh(None);
        let o = run(&mut app, &users, &acc, true, &Default::default());
        assert_eq!(credits(&o).len(), 4);
        let held = app.uploads.len();
        // Full straight after the ordinary zip: every archive past the limits is refused, and so
        // is the ordinary file after it, so nothing is credited.
        let mut app = fresh(Some(held - 5));
        let o = run(&mut app, &users, &acc, true, &Default::default());
        assert!(
            o.steps
                .iter()
                .any(|s| s == "uploaded an ordinary small zip to /upload")
        );
        assert!(credits(&o).is_empty(), "{:?}", credits(&o));
        let u = unassessed(&o);
        assert!(
            u.iter()
                .filter(|w| w.contains("but so was an ordinary GIF"))
                .count()
                == 3,
            "{u:?}"
        );
    }

    #[test]
    fn without_max_bytes_a_refusal_is_not_credited_and_an_acceptance_is_still_found() {
        let none = with_archives(Some(vec![Zip]), Some(ARCHIVE_UNPACK_LIMIT), None, None);
        let o = run_against(Flaws::default(), &none);
        assert!(credits(&o).is_empty());
        assert!(
            unassessed(&o)
                .iter()
                .any(|w| w.contains("with no `max-bytes` stated")),
            "{:?}",
            unassessed(&o)
        );
        let o = run_against(
            Flaws {
                archive_size_unchecked: true,
                ..Default::default()
            },
            &none,
        );
        // The zip just over the limit, and the same zip saying it is small.
        assert_eq!(found(&o).len(), 2);
    }

    /// Python's own readers, as an outside judge of what is written here: each archive is unpacked
    /// by them and what comes out is counted. A test that cannot find Python says so and fails.
    fn python(script: &str, data: &[u8]) -> String {
        use std::io::Write;
        let mut child = std::process::Command::new("python3")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("python3 is needed to check the archives");
        child.stdin.take().unwrap().write_all(data).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "python3 refused the archive: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// Whether Python fails `script` on `data`. A test that cannot find Python says so and fails.
    fn python_fails(script: &str, data: &[u8]) -> bool {
        use std::io::Write;
        let mut child = std::process::Command::new("python3")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("python3 is needed to check the archives");
        child.stdin.take().unwrap().write_all(data).unwrap();
        !child.wait_with_output().unwrap().status.success()
    }

    /// The first file of a zip: the size its headers state, and how many bytes its data really
    /// unpacks to, inflated with `zlib` straight from the local header, past the stated size.
    const READ_PAST_STATED: &str = "import sys,io,zipfile,zlib,struct\n\
        d=sys.stdin.buffer.read();i=zipfile.ZipFile(io.BytesIO(d)).infolist()[0]\n\
        o=i.header_offset;n,e=struct.unpack('<HH',d[o+26:o+30]);s=o+30+n+e\n\
        x=zlib.decompressobj(-15);t=0;r=d[s:s+i.compress_size]\n\
        while r:\n\
        \x20b=x.decompress(r,1<<20);t+=len(b);r=x.unconsumed_tail\n\
        t+=len(x.flush())\n\
        print(i.file_size,t)";

    /// Unpacks a zip with `zipfile`, which checks every file's CRC, and says how many files it
    /// held, how many bytes they came to, and whether every byte was zero (or the text).
    const READ_ZIP: &str = "import sys,io,zipfile\n\
        z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()))\n\
        assert z.testzip() is None\n\
        n=0;k=0;zero=True\n\
        for i in z.infolist():\n\
        \x20with z.open(i) as f:\n\
        \x20\x20while True:\n\
        \x20\x20\x20b=f.read(1<<20)\n\
        \x20\x20\x20if not b: break\n\
        \x20\x20\x20n+=len(b);zero=zero and not b.strip(b'\\0')\n\
        \x20k+=1\n\
        print(k,n,zero)";

    /// Unpacks a gzip with `gzip`, which checks the CRC and the length at its end.
    const READ_GZIP: &str = "import sys,io,gzip\n\
        f=gzip.GzipFile(fileobj=io.BytesIO(sys.stdin.buffer.read()))\n\
        n=0;zero=True\n\
        while True:\n\
        \x20b=f.read(1<<20)\n\
        \x20if not b: break\n\
        \x20n+=len(b);zero=zero and not b.strip(b'\\0')\n\
        print(1,n,zero)";

    #[test]
    fn the_crc_of_zeros_is_the_crc_of_that_many_zero_bytes() {
        for n in [0u64, 1, 2, 7, 8, 255, 256, 1000, 65_537] {
            assert_eq!(crc32_of_zeros(n), crc32(&vec![0; n as usize]), "{n} zeros");
        }
        assert_eq!(
            crc32(b"123456789"),
            0xcbf4_3926,
            "the check value of CRC-32"
        );
    }

    #[test]
    fn each_archive_unpacks_to_exactly_what_it_says_in_pythons_own_readers() {
        for n in [0u64, 1, 2, 257, 258, 259, 516, 1_000_003] {
            assert_eq!(
                python(READ_ZIP, &unpacks_to("zip", n)),
                format!("1 {n} True"),
                "a zip of {n} zeros"
            );
            assert_eq!(
                python(READ_GZIP, &unpacks_to("gzip", n)),
                format!("1 {n} True"),
                "a gzip of {n} zeros"
            );
        }
        assert_eq!(python(READ_ZIP, &holding_files(37)), "37 0 True");
        assert_eq!(python(READ_ZIP, &ordinary("zip")), "1 23 False");
        assert_eq!(python(READ_GZIP, &ordinary("gzip")), "1 23 False");
    }

    /// The largest an archive here is ever made: a gigabyte, in a megabyte or so, and still read
    /// back whole and right.
    #[test]
    fn a_gigabyte_of_zeros_fits_in_about_a_megabyte_and_unpacks_whole() {
        let zip = unpacks_to("zip", MOST_UNPACKED_BYTES);
        let gz = unpacks_to("gzip", MOST_UNPACKED_BYTES);
        assert!(zip.len() < 1_100_000, "{} bytes", zip.len());
        assert!(gz.len() < 1_100_000, "{} bytes", gz.len());
        assert_eq!(
            python(READ_GZIP, &gz),
            format!("1 {MOST_UNPACKED_BYTES} True")
        );
    }
}
