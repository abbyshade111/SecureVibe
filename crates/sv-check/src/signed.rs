//! Seals as SSH signatures, so a computer that holds only the owner's public key can check a seal
//! and cannot make one (ADR-043, the owner's decision of 6 October 2026).
//!
//! A seal made with `review-key` (`crate::seal`) is a keyed hash: checking it takes the key that
//! made it, so it counts only on the computer holding that key, and giving CI the key would let CI
//! make seals too. A signature splits the key in two. `sv review` makes a signing key of its own,
//! `review-signing-key`, in OpenSSH's own format so `ssh-keygen` reads it (`crate::ssh_format`, which
//! writes and reads SSH's formats over `ed25519-dalek`), with a passphrase if the
//! owner wants one, and signs each answer with it. Its public half goes on a list of trusted keys
//! in OpenSSH's `allowed_signers` format, one line per app, the app's id as the principal:
//! `allowed_signers` beside the key on the owner's computer, or the variable `SV_TRUSTED_SEALS`
//! anywhere else (CI, the container), which the owner sets from a repository variable.
//!
//! A seal is written `v3:<app id>:<signature>`, the signature being an SSH signature under the namespace
//! `securevibe-review`, in hex like every other part of a seal so a notes file's
//! `Sealed by sv review:` line reads it as one.
//!
//! What it still cannot show, said where the seal is: that a person, not a tool running as them,
//! was at the keyboard, unless the key has a passphrase; and that a trusted key is the owner's,
//! since whoever can change the list can add one. So the report names the key it trusted and
//! where the list came from, and the owner can compare it with what `sv review` showed.

use std::path::{Path, PathBuf};

use crate::seal::{App, Unrecorded};
use crate::ssh_format::{self, Kept, LockedKey, PublicKey};

/// The signing key's file, beside the review key.
pub const SIGNING_KEY_FILE: &str = "review-signing-key";

/// The list of trusted keys on this computer, beside the signing key.
pub const TRUSTED_FILE: &str = "allowed_signers";

/// The variable that holds the list of trusted keys on a computer with no list of its own.
pub const TRUSTED_VARIABLE: &str = "SV_TRUSTED_SEALS";

/// The namespace every seal is signed under, so a signature made for anything else never counts.
pub const NAMESPACE: &str = sv_frameworks::names::SIGNATURE_NAMESPACE;

/// What a signed seal is made over, apart from anything `review-key` seals.
const DOMAIN: &str = "sv review seal v3\n";

/// The comment on the key and on the lines `sv review` writes in a list of trusted keys.
const COMMENT: &str = "sv review";

/// A signing key ready to sign. Never printed: `Debug` shows only its fingerprint.
#[derive(Clone)]
pub struct SigningKey {
    key: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", self.fingerprint())
    }
}

/// The signing key as it is kept: ready, or locked with a passphrase.
#[derive(Debug)]
pub enum Stored {
    Ready(SigningKey),
    Locked(Locked),
}

/// A signing key locked with a passphrase. Never printed: `Debug` shows only its fingerprint.
pub struct Locked {
    key: LockedKey,
}

impl std::fmt::Debug for Locked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Locked({})", self.fingerprint())
    }
}

impl Locked {
    /// The key, unlocked with `passphrase`. `Err` says why not, for the owner.
    pub fn unlock(&self, passphrase: &str) -> Result<SigningKey, String> {
        self.key
            .unlock(passphrase)
            .map(|key| SigningKey { key })
            .map_err(|_| "that is not the passphrase of this computer's signing key".to_owned())
    }

    /// The key's fingerprint, as `SigningKey::fingerprint`.
    pub fn fingerprint(&self) -> String {
        self.key.public.fingerprint()
    }
}

impl SigningKey {
    /// The signing key in `folder`: `Ok(None)` when there is none, `Err` when there is something
    /// there that cannot be used as one.
    pub fn load_from(folder: &Path) -> Result<Option<Stored>, String> {
        let path = folder.join(SIGNING_KEY_FILE);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{} could not be read ({e})", path.display())),
        };
        if !meta.file_type().is_file() {
            return Err(format!(
                "{} is not a plain file, so it is not used as the signing key",
                path.display()
            ));
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{} could not be read ({e})", path.display()))?;
        let kept = ssh_format::private_from_openssh(&text).map_err(|why| {
            format!(
                "{} does not hold a signing key `sv review` can use: {why}",
                path.display()
            )
        })?;
        Ok(Some(match kept {
            Kept::Plain(key) => Stored::Ready(SigningKey { key }),
            Kept::Locked(key) => Stored::Locked(Locked { key }),
        }))
    }

    /// A new key from the system's randomness, written to `folder`, locked with `passphrase` when
    /// there is one: the folder readable by its owner only, the file made with a call that fails
    /// on anything already there. Its public half is written beside it, as `ssh-keygen` does.
    pub fn make_in(folder: &Path, passphrase: Option<&str>) -> Result<SigningKey, String> {
        let mut seed = random(32)?;
        let key = ed25519_dalek::SigningKey::from_bytes(
            &<[u8; 32]>::try_from(seed.as_slice()).expect("32 bytes"),
        );
        zeroize::Zeroize::zeroize(&mut seed);
        let text = ssh_format::private_to_openssh(&key, COMMENT, passphrase, &random)?;
        make_folder(folder)?;
        let path = folder.join(SIGNING_KEY_FILE);
        write_new(&path, text.as_bytes(), 0o600)?;
        let public = PublicKey::of(&key).to_openssh(COMMENT);
        let public_path = folder.join(format!("{SIGNING_KEY_FILE}.pub"));
        std::fs::write(&public_path, format!("{public}\n"))
            .map_err(|e| format!("{} could not be written ({e})", public_path.display()))?;
        Ok(SigningKey { key })
    }

    /// The key's SHA-256 fingerprint, as `ssh-keygen -l` shows it: safe to print, and what the
    /// report names the key by.
    pub fn fingerprint(&self) -> String {
        PublicKey::of(&self.key).fingerprint()
    }

    /// The line that trusts this key to seal for `app`, in OpenSSH's `allowed_signers` format.
    /// It holds the public half only, which is made to be shared.
    pub fn trusted_line(&self, app: &App) -> Result<String, String> {
        Ok(format!(
            "{} namespaces=\"{NAMESPACE}\" {}",
            app.id(),
            PublicKey::of(&self.key).to_openssh(COMMENT)
        ))
    }

    /// This key, signing for one app only.
    pub fn for_app(&self, app: &App) -> Signer {
        Signer {
            key: self.clone(),
            app: app.clone(),
        }
    }
}

/// A signing key, signing for one app. Never printed: `Debug` shows only the fingerprint and app.
#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
    app: App,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Signer({}, app {})",
            self.key.fingerprint(),
            self.app.id()
        )
    }
}

impl Signer {
    /// The app it signs for.
    pub fn app(&self) -> &App {
        &self.app
    }

    /// The key it signs with.
    pub fn key(&self) -> &SigningKey {
        &self.key
    }

    /// The seal for an entry of this app with these fields.
    pub fn seal(&self, fields: &[&str]) -> Result<String, String> {
        let bytes = ssh_format::sign(&self.key.key, NAMESPACE, &message(self.app.id(), fields));
        Ok(format!("v3:{}:{}", self.app.id(), crate::seal::hex(&bytes)))
    }
}

/// What a seal for `app_id` over `fields` signs: the domain, then the app's id and each field,
/// each with its length first, as `review-key`'s seals frame them.
fn message(app_id: &str, fields: &[&str]) -> Vec<u8> {
    let mut all = Vec::with_capacity(fields.len() + 1);
    all.push(app_id);
    all.extend_from_slice(fields);
    crate::seal::framed(DOMAIN, &all)
}

/// `n` bytes of the system's randomness.
pub(crate) fn random(n: usize) -> Result<Vec<u8>, String> {
    // The operating system's own source through the `getrandom` crate: its random-number call on
    // Linux and on a Mac, and Windows' own on Windows, where there is no /dev/urandom to open
    // (backlog 0120).
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf)
        .map_err(|e| format!("the system's randomness could not be read ({e})"))?;
    if n >= 16 && buf.iter().all(|b| *b == 0) {
        return Err("the system's randomness gave only zeros".to_owned());
    }
    Ok(buf)
}

/// Where a list of trusted keys came from, as the report says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListFrom {
    /// `allowed_signers` in this computer's configuration folder.
    ThisComputer,
    /// The variable `SV_TRUSTED_SEALS`.
    Variable,
}

impl ListFrom {
    /// The list, named for the owner.
    pub fn named(self) -> &'static str {
        match self {
            ListFrom::ThisComputer => "this computer's list of trusted keys",
            ListFrom::Variable => "the list of trusted keys in SV_TRUSTED_SEALS",
        }
    }
}

/// One line of a list of trusted keys.
#[derive(Debug, Clone)]
struct Trusted {
    /// The app ids it may seal for. Each is matched whole: a pattern in OpenSSH's sense never
    /// matches here, which is stricter, never looser.
    principals: Vec<String>,
    key: PublicKey,
}

/// A list of trusted keys, read.
#[derive(Debug, Clone)]
pub struct TrustedList {
    from: ListFrom,
    lines: Vec<Trusted>,
}

impl TrustedList {
    /// The list in `text`. `Err` names the first line that cannot be used, so that no list is ever
    /// read in part: a line `sv` misread could trust a key the owner did not mean to.
    pub fn parse(text: &str, from: ListFrom) -> Result<TrustedList, String> {
        let mut lines = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match trusted(line) {
                Ok(Some(t)) => lines.push(t),
                Ok(None) => {}
                Err(why) => return Err(format!("line {} of {}: {why}", n + 1, from.named())),
            }
        }
        Ok(TrustedList { from, lines })
    }

    /// Where it came from.
    pub fn from(&self) -> ListFrom {
        self.from
    }

    /// Whether it trusts this key to seal for this app.
    pub(crate) fn trusts(&self, key: &PublicKey, app_id: &str) -> bool {
        self.lines
            .iter()
            .any(|t| t.key == *key && t.principals.iter().any(|p| p == app_id))
    }

    fn knows(&self, key: &PublicKey) -> bool {
        self.lines.iter().any(|t| t.key == *key)
    }
}

/// One line, split as OpenSSH's `allowed_signers` is: principals, options, then the key. `None`
/// for a line limited to other namespaces, or trusting a key of a kind other than Ed25519, which
/// never signs a seal `sv` accepts: either says nothing about `sv`'s seals.
fn trusted(line: &str) -> Result<Option<Trusted>, String> {
    let (principals, rest) = line
        .split_once(char::is_whitespace)
        .ok_or("it names no key")?;
    let rest = rest.trim_start();
    let is_key = |s: &str| s.starts_with("ssh-") || s.starts_with("ecdsa-") || s.starts_with("sk-");
    let (options, key) = if is_key(rest) {
        ("", rest)
    } else {
        // The options run to the first space outside double quotes.
        let mut quoted = false;
        let end = rest
            .char_indices()
            .find(|&(_, c)| {
                if c == '"' {
                    quoted = !quoted;
                }
                c.is_whitespace() && !quoted
            })
            .map(|(i, _)| i)
            .ok_or("it names no key")?;
        (&rest[..end], rest[end..].trim_start())
    };
    let mut ours = true;
    for option in split_options(options)? {
        let (name, value) = option.split_once('=').unwrap_or((option, ""));
        if name.eq_ignore_ascii_case("namespaces") {
            let value = value.trim_matches('"');
            ours = value.split(',').any(|n| n.trim() == NAMESPACE);
        } else {
            return Err(format!(
                "it uses the option `{name}`, which `sv` does not read, so the line is not trusted \
                 in part"
            ));
        }
    }
    let key = match PublicKey::from_openssh(key) {
        Ok(Some(key)) => key,
        Ok(None) => return Ok(None),
        Err(why) => return Err(format!("its key cannot be read: {why}")),
    };
    let principals: Vec<String> = principals
        .split(',')
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    if principals.is_empty() {
        return Err("it names no app".to_owned());
    }
    Ok(ours.then_some(Trusted { principals, key }))
}

/// The options of a line, split at each comma outside double quotes.
fn split_options(options: &str) -> Result<Vec<&str>, String> {
    if options.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (i, c) in options.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&options[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if quoted {
        return Err("a quote in its options is never closed".to_owned());
    }
    out.push(&options[start..]);
    Ok(out)
}

/// The list of trusted keys a computer checks signed seals against.
#[derive(Debug, Clone)]
pub enum Trust {
    /// No list: nothing signed can be checked, so nothing signed counts.
    None,
    List(TrustedList),
    /// Something is where the list should be and cannot be read: nothing signed counts, safely.
    Broken(String),
}

impl Trust {
    /// The list SV_TRUSTED_SEALS holds, when it is set and not empty; otherwise the one in
    /// `folder`.
    pub fn load(folder: Option<&Path>, variable: Option<std::ffi::OsString>) -> Trust {
        if let Some(text) = variable {
            let Some(text) = text.to_str().map(str::to_owned) else {
                return Trust::Broken(format!("{TRUSTED_VARIABLE} is not text"));
            };
            if !text.trim().is_empty() {
                return match TrustedList::parse(&text, ListFrom::Variable) {
                    Ok(list) => Trust::List(list),
                    Err(why) => Trust::Broken(why),
                };
            }
        }
        let Some(folder) = folder else {
            return Trust::None;
        };
        Trust::in_folder(folder)
    }

    /// The list in `folder` alone.
    pub fn in_folder(folder: &Path) -> Trust {
        let path = folder.join(TRUSTED_FILE);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if !meta.file_type().is_file() => {
                return Trust::Broken(format!(
                    "{} is not a plain file, so it is not used as the list of trusted keys",
                    path.display()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Trust::None,
            Err(e) => return Trust::Broken(format!("{} could not be read ({e})", path.display())),
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => match TrustedList::parse(&text, ListFrom::ThisComputer) {
                Ok(list) => Trust::List(list),
                Err(why) => Trust::Broken(why),
            },
            Err(e) => Trust::Broken(format!("{} could not be read ({e})", path.display())),
        }
    }

    /// Whether a seal `v3:<app_id>:<signature>` holds for these fields. `here` is the app being
    /// checked, by its folder on this computer; on this computer's own list a seal must have been
    /// made for it, since that list names every app sealed here. On SV_TRUSTED_SEALS the list's
    /// own lines say which apps count, since the folder on CI is never the one it was sealed in.
    pub(crate) fn check(
        &self,
        here: Result<&App, &str>,
        app_id: &str,
        signature: &[u8],
        fields: &[&str],
    ) -> Result<(String, ListFrom), Unrecorded> {
        let list = match self {
            Trust::None => return Err(Unrecorded::NoTrustedList),
            Trust::Broken(why) => return Err(Unrecorded::TrustBroken(why.clone())),
            Trust::List(list) => list,
        };
        let sig = ssh_format::Signature::parse(signature).map_err(|_| Unrecorded::Malformed)?;
        let key = sig.key;
        let named = key.fingerprint();
        if list.from == ListFrom::ThisComputer {
            let here = here.map_err(|why| Unrecorded::TrustBroken(why.to_owned()))?;
            if here.id() != app_id {
                return Err(Unrecorded::OtherApp);
            }
        }
        if !list.trusts(&key, app_id) {
            return Err(if list.knows(&key) {
                Unrecorded::TrustedForAnotherApp(named, list.from)
            } else {
                Unrecorded::NotTrusted(named, list.from)
            });
        }
        if !sig.verifies(NAMESPACE, &message(app_id, fields)) {
            return Err(Unrecorded::Mismatch);
        }
        Ok((named, list.from))
    }
}

/// Adds the line that trusts `key` for `app` to this computer's list in `folder`, unless it is
/// there. `true` when it was added now.
pub fn trust_here(folder: &Path, key: &SigningKey, app: &App) -> Result<bool, String> {
    let public = PublicKey::of(&key.key);
    if let Trust::List(list) = Trust::in_folder(folder)
        && list.trusts(&public, app.id())
    {
        return Ok(false);
    }
    if let Trust::Broken(why) = Trust::in_folder(folder) {
        return Err(why);
    }
    make_folder(folder)?;
    let path = folder.join(TRUSTED_FILE);
    let line = key.trusted_line(app)?;
    use std::io::Write;
    let mut open = std::fs::OpenOptions::new();
    open.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut file = open
        .open(&path)
        .map_err(|e| format!("{} could not be opened ({e})", path.display()))?;
    file.write_all(format!("{line}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{} could not be written ({e})", path.display()))?;
    Ok(true)
}

fn make_folder(folder: &Path) -> Result<(), String> {
    let mut make = std::fs::DirBuilder::new();
    make.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        make.mode(0o700);
    }
    make.create(folder)
        .map_err(|e| format!("{} could not be made ({e})", folder.display()))
}

fn write_new(path: &PathBuf, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    use std::io::Write;
    let mut file = open
        .open(path)
        .map_err(|e| format!("{} could not be made ({e})", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{} could not be written ({e})", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{Checker, KeyLock, Sealed};

    /// A folder of the test's own, removed when it ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "sv-signed-{name}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::remove_dir_all(&dir).ok();
            for sub in ["keys", "app", "copy", "other-keys"] {
                std::fs::create_dir_all(dir.join(sub)).unwrap();
            }
            Scratch(dir)
        }
        fn keys(&self) -> PathBuf {
            self.0.join("keys")
        }
        fn app(&self) -> App {
            App::of(&self.0.join("app")).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    const FIELDS: &[&str] = &["finding-review", "ast.open-redirect", "app.py", "owner"];

    /// A key made in the scratch folder and trusted there for its app, and the seal it makes.
    fn sealed(s: &Scratch) -> (SigningKey, String) {
        let key = SigningKey::make_in(&s.keys(), None).unwrap();
        assert!(trust_here(&s.keys(), &key, &s.app()).unwrap());
        assert!(
            !trust_here(&s.keys(), &key, &s.app()).unwrap(),
            "a line already there is not added again"
        );
        let seal = key.for_app(&s.app()).seal(FIELDS).unwrap();
        (key, seal)
    }

    /// A seal made for `app`.
    fn copy_seal(key: &SigningKey, app: &App) -> String {
        key.for_app(app).seal(FIELDS).unwrap()
    }

    /// The list `text` holds, as SV_TRUSTED_SEALS gives it, checking the app in `folder`.
    fn given(text: &str, folder: &Path) -> Checker {
        Checker::no_key().trusting(
            Trust::load(None, Some(text.into())),
            Some(App::of(folder).unwrap()),
        )
    }

    #[test]
    fn a_signed_seal_counts_where_a_list_trusts_its_key_for_the_app_and_nowhere_else() {
        let s = Scratch::new("counts");
        let (key, seal) = sealed(&s);
        assert!(seal.starts_with(&format!("v3:{}:", s.app().id())), "{seal}");
        // On this computer, against its own list.
        let here = Checker::in_folder(Some(&s.keys()), &s.0.join("app"));
        assert_eq!(
            here.recorded(Some(&seal), FIELDS),
            Ok(Sealed::Signed {
                key: key.fingerprint(),
                from: ListFrom::ThisComputer,
                lock: KeyLock::NoPassphrase
            })
        );
        // Any field changed, or a field's text moved into the next, breaks it.
        for changed in [
            &["finding-review", "ast.open-redirect", "app.py", "Owner"][..],
            &["finding-review", "ast.open-redirect", "app.pyowner", ""][..],
            &["finding-review", "ast.open-redirect", "app.py"][..],
        ] {
            assert_eq!(
                here.recorded(Some(&seal), changed),
                Err(Unrecorded::Mismatch),
                "{changed:?}"
            );
        }
        // One hex digit of the signature changed.
        let mut bent = seal.clone();
        let last = bent.pop().unwrap();
        bent.push(if last == '0' { '1' } else { '0' });
        assert_eq!(
            here.recorded(Some(&bent), FIELDS),
            Err(Unrecorded::Mismatch)
        );
        // On a computer given only the public list, with the app in another folder: it counts,
        // and says where the list came from.
        let line = std::fs::read_to_string(s.keys().join(TRUSTED_FILE)).unwrap();
        let ci = given(&line, &s.0.join("copy"));
        assert_eq!(
            ci.recorded(Some(&seal), FIELDS),
            Ok(Sealed::Signed {
                key: key.fingerprint(),
                from: ListFrom::Variable,
                lock: KeyLock::NotHere
            })
        );
        assert!(ci.check(Some(&seal), FIELDS).is_ok());
        // The same copy of the app on this computer is another app: its list names the folder
        // the seal was made in, and a seal counts only there.
        let copied = Checker::in_folder(Some(&s.keys()), &s.0.join("copy"));
        assert_eq!(
            copied.recorded(Some(&seal), FIELDS),
            Err(Unrecorded::OtherApp)
        );
        // This computer's list, trusting the key for the copy too: a seal whose app id is swapped
        // for the copy's breaks there, since the signature covers it.
        let copy = App::of(&s.0.join("copy")).unwrap();
        trust_here(&s.keys(), &key, &copy).unwrap();
        let swapped = seal.replacen(s.app().id(), copy.id(), 1);
        let copied = Checker::in_folder(Some(&s.keys()), &s.0.join("copy"));
        assert!(
            copied
                .recorded(Some(&copy_seal(&key, &copy)), FIELDS)
                .is_ok(),
            "the setup: the copy's own seal counts in the copy"
        );
        assert_eq!(
            copied.recorded(Some(&swapped), FIELDS),
            Err(Unrecorded::Mismatch)
        );
        // This computer's list, its line limited to another namespace: it trusts nothing for `sv`.
        let list = std::fs::read_to_string(s.keys().join(TRUSTED_FILE)).unwrap();
        std::fs::write(s.keys().join(TRUSTED_FILE), list.replace(NAMESPACE, "git")).unwrap();
        assert_eq!(
            here.recorded(Some(&seal), FIELDS),
            Ok(Sealed::Signed {
                key: key.fingerprint(),
                from: ListFrom::ThisComputer,
                lock: KeyLock::NoPassphrase
            }),
            "the setup: a checker reads the list when it is made"
        );
        assert_eq!(
            Checker::in_folder(Some(&s.keys()), &s.0.join("app")).recorded(Some(&seal), FIELDS),
            Err(Unrecorded::NotTrusted(
                key.fingerprint(),
                ListFrom::ThisComputer
            ))
        );
        // No list here: nothing signed can be checked, and it says what to do.
        let none = Checker::in_folder(Some(&s.0.join("other-keys")), &s.0.join("app"));
        assert_eq!(
            none.recorded(Some(&seal), FIELDS),
            Err(Unrecorded::NoTrustedList)
        );
        let err = none.check(Some(&seal), FIELDS).unwrap_err();
        assert!(err.contains(TRUSTED_VARIABLE), "{err}");
        assert!(err.contains("only as a proposal"), "{err}");
    }

    #[test]
    fn a_key_the_list_does_not_trust_for_this_app_seals_nothing() {
        let s = Scratch::new("untrusted");
        let (key, seal) = sealed(&s);
        let app = s.app();
        let theirs = SigningKey::make_in(&s.0.join("other-keys"), None).unwrap();
        let their_line = theirs.trusted_line(&app).unwrap();
        // A key anyone can make, signing a seal of the right form: not on the list.
        let forged = theirs.for_app(&app).seal(FIELDS).unwrap();
        let here = Checker::in_folder(Some(&s.keys()), &s.0.join("app"));
        assert_eq!(
            here.recorded(Some(&forged), FIELDS),
            Err(Unrecorded::NotTrusted(
                theirs.fingerprint(),
                ListFrom::ThisComputer
            ))
        );
        let err = here.check(Some(&forged), FIELDS).unwrap_err();
        assert!(err.contains(&theirs.fingerprint()), "{err}");
        // Given a list that trusts only the other key, the owner's seal does not count either.
        let elsewhere = given(&their_line, &s.0.join("copy"));
        assert_eq!(
            elsewhere.recorded(Some(&seal), FIELDS),
            Err(Unrecorded::NotTrusted(
                key.fingerprint(),
                ListFrom::Variable
            ))
        );
        // Trusted for another app only.
        let shop = App::of(&s.0.join("copy")).unwrap();
        let for_shop = given(&key.trusted_line(&shop).unwrap(), &s.0.join("copy"));
        assert_eq!(
            for_shop.recorded(Some(&seal), FIELDS),
            Err(Unrecorded::TrustedForAnotherApp(
                key.fingerprint(),
                ListFrom::Variable
            ))
        );
        // Trusted for both apps, a seal whose app id is swapped for the other's breaks: the
        // signature covers it.
        let both = format!(
            "{}\n{}\n",
            key.trusted_line(&app).unwrap(),
            key.trusted_line(&shop).unwrap()
        );
        let swapped = seal.replacen(app.id(), shop.id(), 1);
        assert_ne!(swapped, seal);
        assert_eq!(
            given(&both, &s.0.join("copy")).recorded(Some(&swapped), FIELDS),
            Err(Unrecorded::Mismatch)
        );
        // Trusted only for another namespace (a key the person signs git commits with, say): the
        // line says nothing about `sv`'s seals.
        let git_only = key.trusted_line(&app).unwrap().replace(NAMESPACE, "git");
        assert_eq!(
            given(&git_only, &s.0.join("copy")).recorded(Some(&seal), FIELDS),
            Err(Unrecorded::NotTrusted(
                key.fingerprint(),
                ListFrom::Variable
            ))
        );
        // A line with no namespaces trusts the key for every one, as OpenSSH reads it.
        let any = key
            .trusted_line(&app)
            .unwrap()
            .replace(&format!(" namespaces=\"{NAMESPACE}\""), "");
        assert!(
            given(&any, &s.0.join("copy"))
                .recorded(Some(&seal), FIELDS)
                .is_ok()
        );
        // Signed by the trusted key under another namespace, over the same message: refused.
        let bytes = ssh_format::sign(&key.key, "git", &message(app.id(), FIELDS));
        let other_namespace = format!("v3:{}:{}", app.id(), crate::seal::hex(&bytes));
        assert_eq!(
            here.recorded(Some(&other_namespace), FIELDS),
            Err(Unrecorded::Mismatch)
        );
    }

    #[test]
    fn a_list_sv_cannot_read_in_full_trusts_nothing() {
        let s = Scratch::new("broken");
        let (key, seal) = sealed(&s);
        let good = key.trusted_line(&s.app()).unwrap();
        for bad in [
            format!("{good}\nnot a line at all\n"),
            format!(
                "{good}\n{}",
                good.replace("namespaces=", "cert-authority,namespaces=")
            ),
            format!("{} valid-before=\"20300101\",{}", s.app().id(), &good[17..]),
            format!("{}\n", good.replace("namespaces=\"", "namespaces=")),
        ]
        .into_iter()
        .enumerate()
        {
            // Named by its place in the list: the line itself holds a key, and is never printed.
            let (which, bad) = bad;
            let checker = given(&bad, &s.0.join("app"));
            assert!(
                matches!(
                    checker.recorded(Some(&seal), FIELDS),
                    Err(Unrecorded::TrustBroken(_))
                ),
                "list {which}"
            );
        }
        // The list on this computer, made unreadable as one: nothing counts, and `sv review`
        // refuses to add to it.
        std::fs::write(s.keys().join(TRUSTED_FILE), "garbage\n").unwrap();
        let here = Checker::in_folder(Some(&s.keys()), &s.0.join("app"));
        assert!(matches!(
            here.recorded(Some(&seal), FIELDS),
            Err(Unrecorded::TrustBroken(_))
        ));
        assert!(trust_here(&s.keys(), &key, &s.app()).is_err());
        // A seal whose signature is not one is malformed, whatever the list says.
        let short = format!("v3:{}:00", s.app().id());
        assert_eq!(
            Checker::in_folder(Some(&s.0.join("other-keys")), &s.0.join("app"))
                .trusting(Trust::load(None, Some(good.into())), None)
                .recorded(Some(&short), FIELDS),
            Err(Unrecorded::Malformed)
        );
    }

    #[test]
    fn the_signing_key_is_made_private_once_locked_when_asked_and_never_shown() {
        let s = Scratch::new("key");
        // A folder not there yet, as on a computer where `sv review` has never run.
        let keys = s.0.join("fresh").join("stackvet");
        assert!(SigningKey::load_from(&keys).unwrap().is_none());
        let made = SigningKey::make_in(&keys, None).unwrap();
        let path = keys.join(SIGNING_KEY_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
            "the setup: kept in OpenSSH's own format"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&keys), 0o700);
            assert_eq!(mode(&path), 0o600);
        }
        assert!(
            SigningKey::make_in(&keys, None).is_err(),
            "a key already there is never replaced"
        );
        assert!(matches!(
            SigningKey::load_from(&keys).unwrap(),
            Some(Stored::Ready(k)) if k.fingerprint() == made.fingerprint()
        ));
        // Nothing printed about it shows the private half.
        let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(body.len() > 100, "the setup: the private half is findable");
        // Named, not printed, when one fails: what it holds may be the key.
        for (what, shown) in [
            ("Debug", format!("{made:?}")),
            ("Debug for an app", format!("{:?}", made.for_app(&s.app()))),
            ("the trusted line", made.trusted_line(&s.app()).unwrap()),
            ("the fingerprint", made.fingerprint()),
        ] {
            assert!(!shown.contains(&body[..40]), "{what}");
            assert!(!shown.contains(&body[body.len() - 40..]), "{what}");
        }
        assert!(made.fingerprint().starts_with("SHA256:"));

        // Locked with a passphrase: only the passphrase unlocks it, and it signs the same.
        let locked_folder = s.0.join("other-keys");
        let locked = SigningKey::make_in(&locked_folder, Some("correct horse")).unwrap();
        let Some(Stored::Locked(stored)) = SigningKey::load_from(&locked_folder).unwrap() else {
            panic!("a key made with a passphrase is kept locked");
        };
        assert_eq!(stored.fingerprint(), locked.fingerprint());
        assert!(!format!("{stored:?}").contains("correct horse"));
        assert!(stored.unlock("wrong horse").is_err());
        let unlocked = stored.unlock("correct horse").unwrap();
        assert_eq!(unlocked.fingerprint(), locked.fingerprint());
        let seal = unlocked.for_app(&s.app()).seal(FIELDS).unwrap();
        let line = locked.trusted_line(&s.app()).unwrap();
        assert!(
            given(&line, &s.0.join("app"))
                .recorded(Some(&seal), FIELDS)
                .is_ok()
        );

        // Something there that is not a signing key is refused, never quietly replaced.
        std::fs::write(&path, "not a key\n").unwrap();
        assert!(SigningKey::load_from(&keys).is_err());
        assert!(SigningKey::make_in(&keys, None).is_err());
    }

    #[test]
    fn a_key_file_changed_by_hand_is_refused_not_used() {
        // Each change leaves a file `sv` could misread as some key: its padding, its secret half
        // swapped for another key's, or the public half kept beside the secret one changed.
        let s = Scratch::new("doctored");
        let keys = s.0.join("made");
        let made = SigningKey::make_in(&keys, None).unwrap();
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let path = keys.join(SIGNING_KEY_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        let bytes = ssh_format::unarmor("OPENSSH PRIVATE KEY", &text).unwrap();
        let public = PublicKey::of(&made.key).blob();
        let public = &public[public.len() - 32..];
        let seed = made.key.to_bytes();
        let changes: Vec<(&str, Vec<u8>)> = vec![
            ("padding", {
                let mut b = bytes.clone();
                let last = b.len() - 1;
                b[last] ^= 0x40;
                b
            }),
            ("secret half", {
                let mut b = bytes.clone();
                let at = b.windows(32).position(|w| w == seed).unwrap();
                b[at..at + 32].copy_from_slice(&other.to_bytes());
                b
            }),
            ("public half beside the secret one", {
                let mut b = bytes.clone();
                let at = b.windows(32).rposition(|w| w == public).unwrap();
                b[at..at + 32].copy_from_slice(&other.verifying_key().to_bytes());
                b
            }),
        ];
        assert!(
            matches!(SigningKey::load_from(&keys), Ok(Some(Stored::Ready(_)))),
            "the setup: the file as made is read"
        );
        for (what, changed) in changes {
            assert_ne!(changed, bytes, "the setup: {what} was changed");
            std::fs::remove_file(&path).unwrap();
            std::fs::write(&path, ssh_format::armor("OPENSSH PRIVATE KEY", &changed)).unwrap();
            assert!(SigningKey::load_from(&keys).is_err(), "{what}");
        }
    }

    /// A seal is an SSH signature `ssh-keygen` checks on its own, with the same list: anyone can
    /// check it without `sv`.
    #[test]
    fn ssh_keygen_checks_a_seal_with_the_same_list() {
        let s = Scratch::new("ssh-keygen");
        let (_, seal) = sealed(&s);
        let found = std::process::Command::new("ssh-keygen")
            .arg("-?")
            .output()
            .is_ok();
        if !found {
            eprintln!("ssh-keygen is not on this computer; the seal was not checked with it");
            return;
        }
        let hex = seal.rsplit_once(':').unwrap().1;
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let sig_path = s.0.join("seal.sig");
        std::fs::write(
            &sig_path,
            ssh_format::armor(ssh_format::SIGNATURE_LABEL, &bytes),
        )
        .unwrap();
        let verify = |fields: &[&str]| {
            use std::io::Write;
            let mut child = std::process::Command::new("ssh-keygen")
                .args(["-Y", "verify", "-f"])
                .arg(s.keys().join(TRUSTED_FILE))
                .args(["-I", s.app().id(), "-n", NAMESPACE, "-s"])
                .arg(&sig_path)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&message(s.app().id(), fields))
                .unwrap();
            child.wait_with_output().unwrap()
        };
        let good = verify(FIELDS);
        assert!(
            good.status.success(),
            "{}{}",
            String::from_utf8_lossy(&good.stdout),
            String::from_utf8_lossy(&good.stderr)
        );
        assert!(!verify(&FIELDS[..3]).status.success());
    }
}

#[cfg(test)]
mod with_ssh_keygen {
    //! The formats `crate::ssh_format` writes and reads, against `ssh-keygen` itself: it reads the
    //! key `sv review` makes, plain or locked, and `sv` reads the keys it makes and checks the
    //! signatures it makes. Where `ssh-keygen` is not on the computer, each says so and stops.
    use super::*;
    use std::process::Command;

    fn found() -> bool {
        let there = Command::new("ssh-keygen").arg("-?").output().is_ok();
        if !there {
            eprintln!("ssh-keygen is not on this computer; nothing was checked with it");
        }
        there
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-keygen-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        dir
    }

    /// The type and data of a public key line, without its comment.
    fn key_of(line: &str) -> String {
        line.split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn ssh_keygen_reads_the_key_sv_review_makes_plain_or_locked() {
        if !found() {
            return;
        }
        let dir = scratch("reads-ours");
        for passphrase in [None, Some("correct horse")] {
            let folder = dir.join(if passphrase.is_some() {
                "locked"
            } else {
                "plain"
            });
            let key = SigningKey::make_in(&folder, passphrase).unwrap();
            let ours =
                std::fs::read_to_string(folder.join(format!("{SIGNING_KEY_FILE}.pub"))).unwrap();
            let derived = Command::new("ssh-keygen")
                .arg("-y")
                .arg("-P")
                .arg(passphrase.unwrap_or(""))
                .arg("-f")
                .arg(folder.join(SIGNING_KEY_FILE))
                .output()
                .unwrap();
            assert!(
                derived.status.success(),
                "locked: {}: {}",
                passphrase.is_some(),
                String::from_utf8_lossy(&derived.stderr)
            );
            assert_eq!(
                key_of(&String::from_utf8_lossy(&derived.stdout)),
                key_of(&ours),
                "locked: {}",
                passphrase.is_some()
            );
            let listed = Command::new("ssh-keygen")
                .arg("-l")
                .arg("-f")
                .arg(folder.join(format!("{SIGNING_KEY_FILE}.pub")))
                .output()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&listed.stdout).contains(&key.fingerprint()),
                "{}",
                String::from_utf8_lossy(&listed.stdout)
            );
            if passphrase.is_some() {
                // The wrong passphrase does not open it for `ssh-keygen` either.
                let wrong = Command::new("ssh-keygen")
                    .args(["-y", "-P", "wrong horse", "-f"])
                    .arg(folder.join(SIGNING_KEY_FILE))
                    .output()
                    .unwrap();
                assert!(!wrong.status.success());
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sv_reads_the_keys_ssh_keygen_makes_and_checks_its_signatures() {
        if !found() {
            return;
        }
        let dir = scratch("reads-theirs");
        std::fs::create_dir_all(&dir).unwrap();
        for passphrase in ["", "correct horse"] {
            let folder = dir.join(if passphrase.is_empty() {
                "plain"
            } else {
                "locked"
            });
            std::fs::create_dir_all(&folder).unwrap();
            let made = Command::new("ssh-keygen")
                .args([
                    "-q", "-t", "ed25519", "-C", "theirs", "-N", passphrase, "-f",
                ])
                .arg(folder.join(SIGNING_KEY_FILE))
                .output()
                .unwrap();
            assert!(
                made.status.success(),
                "{}",
                String::from_utf8_lossy(&made.stderr)
            );
            let public =
                std::fs::read_to_string(folder.join(format!("{SIGNING_KEY_FILE}.pub"))).unwrap();
            let key = match SigningKey::load_from(&folder).unwrap() {
                Some(Stored::Ready(key)) if passphrase.is_empty() => key,
                Some(Stored::Locked(locked)) if !passphrase.is_empty() => {
                    assert!(locked.unlock("wrong horse").is_err());
                    locked.unlock(passphrase).unwrap()
                }
                other => panic!("locked: {}: {other:?}", !passphrase.is_empty()),
            };
            assert_eq!(
                PublicKey::of(&key.key).to_openssh("theirs").trim(),
                public.trim()
            );
            if !passphrase.is_empty() {
                continue;
            }
            // A signature `ssh-keygen` makes with it, over a seal's message, checks here.
            let app = App::named_for_tests("theirs");
            let fields = ["finding-review", "ast.open-redirect", "app.py", "owner"];
            let message_path = folder.join("message");
            std::fs::write(&message_path, message(app.id(), &fields)).unwrap();
            let signed = Command::new("ssh-keygen")
                .args(["-Y", "sign", "-n", NAMESPACE, "-f"])
                .arg(folder.join(SIGNING_KEY_FILE))
                .arg(&message_path)
                .output()
                .unwrap();
            assert!(
                signed.status.success(),
                "{}",
                String::from_utf8_lossy(&signed.stderr)
            );
            let armored = std::fs::read_to_string(folder.join("message.sig")).unwrap();
            let bytes = ssh_format::unarmor(ssh_format::SIGNATURE_LABEL, &armored).unwrap();
            let seal = format!("v3:{}:{}", app.id(), crate::seal::hex(&bytes));
            let checker = crate::seal::Checker::no_key().trusting(
                Trust::load(None, Some(key.trusted_line(&app).unwrap().into())),
                None,
            );
            assert!(checker.recorded(Some(&seal), &fields).is_ok());
            assert!(checker.recorded(Some(&seal), &fields[..3]).is_err());
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
