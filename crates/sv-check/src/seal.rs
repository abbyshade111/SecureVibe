//! The seal `sv review` puts on what a person records, so an entry the AI coding tool wrote can be
//! told from one a person typed (deep review R1).
//!
//! The owner's decision, 4 October 2026. An entry in securevibe.toml that sets a finding aside, or
//! confirms what the AI coding tool said, names who decided in `by`, and `sv` only reads that name:
//! the tool rewrites code until a warning stops, and writing `by = "owner"` is the easiest rewrite
//! of all. So an entry counts only when `sv review` recorded it. That command runs only in a
//! terminal a person is typing in, and seals each entry with a key kept in the person's own
//! configuration folder, outside the app's folder, where the tool works.
//!
//! What a seal can and cannot show, said in every report:
//!
//! - **On the computer that holds the key** it is checked. One that does not match (the entry was
//!   changed afterwards, or the seal was made up) does not count, and nor does one made with another
//!   computer's key: this computer cannot check it, and a made-up seal naming a key that is not here
//!   is exactly what the tool would write.
//! - **On a computer with no key at all** (CI, a teammate who never ran `sv review`) nothing can be
//!   checked, so nothing sealed counts there either. The owner decided this on 6 October 2026, after
//!   a review found that a well-formed seal the AI coding tool wrote counted on such a computer as
//!   the owner's record (item 8 of the review of 1 to 4 October). The report says the entry carries
//!   a seal this computer cannot check, and what to do: run `sv review` once on this computer, or
//!   read the report on the computer that sealed it.
//! - **A seal names the app it was made for**, by the folder the app is in on this computer, so an
//!   answer sealed for one app and copied into another does not count there (item 11, the owner's
//!   decision the same day). An app moved to another folder has its answers sealed again with
//!   `sv review`, which asks about every entry whose seal does not hold.
//! - **Nothing here stops a tool that sets out to fake it**: it runs as the person, so it could read
//!   the key or fake a terminal. What the seal stops is the easy path, one line in a file the tool
//!   is already editing.
//!
//! The seal is HMAC-SHA-256 over the app's id and the entry's fields, under a 32-byte key from the
//! system's randomness. It is written as `v2:<key id>:<app id>:<64 hex>`, the key id being 16 hex
//! characters of a SHA-256 of the key, so a seal says which key made it without giving the key away,
//! and the app id 16 hex characters of a SHA-256 of the app's folder. A seal written as
//! `v1:<key id>:<64 hex>` was made before seals named their app and no longer counts.

use std::path::{Path, PathBuf};

/// A key folder a test running `sv` inside its own process sets once, so what it seals does not
/// depend on whether the computer running the tests has a review key of its own. Nothing outside
/// such a test sets it: there is no option or variable that reaches it.
static FOLDER_FOR_TESTS: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Sets that folder, the first time it is called in a process, and returns the one in use.
#[doc(hidden)]
pub fn key_folder_for_tests(folder: PathBuf) -> &'static Path {
    FOLDER_FOR_TESTS.get_or_init(|| folder)
}

/// The key's file, in the folder `Key::folder` names.
pub const KEY_FILE: &str = "review-key";

/// The file of the key `sv report` seals its report folders with, beside the review key and kept
/// apart from it (deep review R9, ADR-034). Apart, because the review key exists only where a person
/// has run `sv review`, and its presence is what tells `sv review` a person has recorded answers
/// on this computer; `sv report` making it would say so where nobody has.
pub const REPORT_KEY_FILE: &str = "report-key";

const DOMAIN: &str = "sv review seal v2\n";

/// What a report folder's seal is made over, apart from anything the review key seals.
const REPORT_DOMAIN: &str = "sv report seal v1\n";

/// One computer's sealing key. Never printed: `Debug` shows only its id.
#[derive(Clone)]
pub struct Key {
    bytes: [u8; 32],
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.id())
    }
}

impl Key {
    /// A new key from the system's randomness.
    pub fn random() -> Result<Key, String> {
        use std::io::Read;
        let mut read = Vec::with_capacity(32);
        std::fs::File::open("/dev/urandom")
            .and_then(|f| f.take(32).read_to_end(&mut read))
            .map_err(|e| format!("the system's randomness could not be read ({e})"))?;
        let bytes = <[u8; 32]>::try_from(read)
            .map_err(|_| "the system's randomness gave too little".to_owned())?;
        if bytes.iter().all(|b| *b == 0) {
            return Err("the system's randomness gave only zeros".to_owned());
        }
        Ok(Key { bytes })
    }

    /// Where the key is kept: `$XDG_CONFIG_HOME/stackvet`, or `~/.config/stackvet`. `None` when
    /// neither can be told. Until the rename (ADR-062) the folder was `securevibe`: while the new
    /// folder does not exist and the old one does, the old one is used, and `old_folder_in_use`
    /// says so, for the command to tell the person; nothing moves a key.
    pub fn folder() -> Option<PathBuf> {
        if let Some(folder) = FOLDER_FOR_TESTS.get() {
            return Some(folder.clone());
        }
        let config = Self::config_root()?;
        let new = config.join(sv_frameworks::names::CONFIG_DIR);
        let old = config.join(sv_frameworks::names::OLD_CONFIG_DIR);
        if !new.is_dir() && old.is_dir() {
            return Some(old);
        }
        Some(new)
    }

    /// The old config folder and the new one, when the old is the one in use (`folder`): the
    /// command says so once and names the move. `None` when the new folder is in use, or neither
    /// can be told.
    pub fn old_folder_in_use() -> Option<(PathBuf, PathBuf)> {
        if FOLDER_FOR_TESTS.get().is_some() {
            return None;
        }
        let config = Self::config_root()?;
        let new = config.join(sv_frameworks::names::CONFIG_DIR);
        let old = config.join(sv_frameworks::names::OLD_CONFIG_DIR);
        (!new.is_dir() && old.is_dir()).then_some((old, new))
    }

    /// `$XDG_CONFIG_HOME`, or `~/.config`, when either can be told.
    fn config_root() -> Option<PathBuf> {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .filter(|p| p.is_absolute())
                    .map(|home| home.join(".config"))
            })?;
        Some(config)
    }

    /// The key in `folder`: `Ok(None)` when there is none, `Err` when there is something there
    /// that cannot be used as one.
    pub fn load_from(folder: &Path) -> Result<Option<Key>, String> {
        Key::load_named(folder, KEY_FILE)
    }

    /// The key in `file` in `folder`, as `load_from` reads the review key.
    pub fn load_named(folder: &Path, file: &str) -> Result<Option<Key>, String> {
        let what = file.replace('-', " ");
        let path = folder.join(file);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{} could not be read ({e})", path.display())),
        };
        if !meta.file_type().is_file() {
            return Err(format!(
                "{} is not a plain file, so it is not used as the {what}",
                path.display()
            ));
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{} could not be read ({e})", path.display()))?;
        let bytes = unhex(text.trim())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| format!("{} does not hold a {what}", path.display()))?;
        Ok(Some(Key { bytes }))
    }

    /// The key in `folder`, made there first if there is none: the folder readable by its owner
    /// only, the file made with a call that fails on anything already there. `true` when it was
    /// made now.
    pub fn load_or_make_in(folder: &Path) -> Result<(Key, bool), String> {
        Key::load_or_make_named(folder, KEY_FILE)
    }

    /// The key in `file` in `folder`, made as `load_or_make_in` makes the review key.
    pub fn load_or_make_named(folder: &Path, file: &str) -> Result<(Key, bool), String> {
        if let Some(key) = Key::load_named(folder, file)? {
            return Ok((key, false));
        }
        let key = Key::random()?;
        let mut make = std::fs::DirBuilder::new();
        make.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            make.mode(0o700);
        }
        make.create(folder)
            .map_err(|e| format!("{} could not be made ({e})", folder.display()))?;
        let path = folder.join(file);
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        {
            use std::io::Write;
            let mut file = open
                .open(&path)
                .map_err(|e| format!("{} could not be made ({e})", path.display()))?;
            file.write_all(format!("{}\n", hex(&key.bytes)).as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| format!("{} could not be written ({e})", path.display()))?;
        }
        Ok((key, true))
    }

    /// Sixteen hex characters naming the key, safe to print and to write beside a seal.
    pub fn id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"sv review key id\n");
        h.update(self.bytes);
        hex(&h.finalize()[..8])
    }

    fn mac_in(&self, domain: &str, fields: &[&str]) -> Vec<u8> {
        use hmac::{Hmac, KeyInit, Mac};
        let mut mac =
            <Hmac<sha2::Sha256>>::new_from_slice(&self.bytes).expect("HMAC takes any key");
        mac.update(&framed(domain, fields));
        mac.finalize().into_bytes().to_vec()
    }

    /// This key, sealing for one app only.
    pub fn for_app(&self, app: &App) -> AppKey {
        AppKey {
            key: self.clone(),
            app: app.clone(),
        }
    }

    /// The seal for a report folder whose files are these fields, written as a review seal is.
    pub fn report_seal(&self, fields: &[&str]) -> String {
        format!(
            "v1:{}:{}",
            self.id(),
            hex(&self.mac_in(REPORT_DOMAIN, fields))
        )
    }

    /// Whether `seal` is this key's seal of a report folder whose files are these fields. `Err`
    /// says why not, as the end of a sentence beginning "sv cannot show it wrote this report:".
    pub fn report_seal_holds(&self, seal: &str, fields: &[&str]) -> Result<(), String> {
        let (key_id, mac) = parse(seal.trim()).ok_or("its marker holds no seal sv writes")?;
        if key_id != self.id() {
            return Err(format!(
                "its seal was made with a key that is not this computer's ({key_id}), and a \
                 made-up seal would look the same"
            ));
        }
        let expected = self.mac_in(REPORT_DOMAIN, fields);
        let same = expected.len() == mac.len()
            && expected.iter().zip(&mac).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0;
        if same {
            Ok(())
        } else {
            Err(
                "its seal does not match its files: they were changed after sv wrote them, or \
                 the seal was not made by sv"
                    .to_owned(),
            )
        }
    }
}

/// The app a seal is made for: sixteen hex characters of a SHA-256 of the folder it is in, with
/// every link followed, so the same app reached by another path is the same app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    id: String,
}

impl App {
    /// The app in `folder`, which must exist.
    pub fn of(folder: &Path) -> Result<App, String> {
        let real = std::fs::canonicalize(folder).map_err(|e| {
            format!(
                "the app's folder, {}, could not be found ({e})",
                folder.display()
            )
        })?;
        #[cfg(unix)]
        let bytes = {
            use std::os::unix::ffi::OsStrExt;
            real.as_os_str().as_bytes().to_vec()
        };
        #[cfg(not(unix))]
        let bytes = real.to_string_lossy().as_bytes().to_vec();
        Ok(App::from_bytes(&bytes))
    }

    /// An app named by these words alone, for a test that has no folder.
    #[doc(hidden)]
    pub fn named_for_tests(name: &str) -> App {
        App::from_bytes(format!("test app {name}").as_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> App {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"sv app folder\n");
        h.update(bytes);
        App {
            id: hex(&h.finalize()[..8]),
        }
    }

    /// The sixteen hex characters a seal names it by.
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// This computer's key, sealing for one app. Never printed: `Debug` shows only the two ids.
#[derive(Clone)]
pub struct AppKey {
    key: Key,
    app: App,
}

impl std::fmt::Debug for AppKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppKey({}, app {})", self.key.id(), self.app.id)
    }
}

impl AppKey {
    /// The key's id, as `Key::id`.
    pub fn id(&self) -> String {
        self.key.id()
    }

    /// The app it seals for.
    pub fn app(&self) -> &App {
        &self.app
    }

    fn mac(&self, fields: &[&str]) -> Vec<u8> {
        let mut all = Vec::with_capacity(fields.len() + 1);
        all.push(self.app.id.as_str());
        all.extend_from_slice(fields);
        self.key.mac_in(DOMAIN, &all)
    }

    /// The seal for an entry of this app with these fields.
    pub fn seal(&self, fields: &[&str]) -> String {
        format!(
            "v2:{}:{}:{}",
            self.key.id(),
            self.app.id,
            hex(&self.mac(fields))
        )
    }
}

/// Where a seal that counts was checked: only ever on this computer, with its key (item 8 of the
/// review of 1 to 4 October; ADR-026).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sealed {
    /// Checked with this computer's review key.
    Here,
    /// A signature, checked against a list of trusted keys that names its key for this app
    /// (ADR-043): the key's fingerprint, and where the list came from.
    Signed {
        key: String,
        from: crate::signed::ListFrom,
    },
}

/// What this computer can check one app's `review-key` seals with.
#[derive(Debug, Clone)]
pub enum Hmac {
    /// No key here: nothing sealed with one can be checked, so nothing sealed with one counts.
    NoKey,
    /// This computer's key, for the app being checked.
    Key(AppKey),
    /// Something is where the key should be, or the app's folder cannot be told: no seal counts,
    /// safely.
    Broken(String),
}

/// What this computer can check one app's seals with: its review key, for seals made with one
/// (`v2:`), and a list of trusted keys, for signed seals (`v3:`, ADR-043).
#[derive(Debug, Clone)]
pub struct Checker {
    hmac: Hmac,
    trust: crate::signed::Trust,
    /// The app being checked, by its folder here, or why it cannot be told.
    app: Result<App, String>,
}

impl Checker {
    /// What this computer has, from the folder `Key::folder` names and SV_TRUSTED_SEALS, for the
    /// app in `app_folder`.
    pub fn for_app(app_folder: &Path) -> Checker {
        let folder = Key::folder();
        let mut checker = Checker::in_folder(folder.as_deref(), app_folder);
        checker.trust = crate::signed::Trust::load(
            folder.as_deref(),
            std::env::var_os(crate::signed::TRUSTED_VARIABLE),
        );
        checker
    }

    /// What a key folder holds for the app in `app_folder`, or nothing when there is no folder to
    /// look in. SV_TRUSTED_SEALS is not read.
    pub fn in_folder(folder: Option<&Path>, app_folder: &Path) -> Checker {
        let app = App::of(app_folder);
        let hmac = match folder.map(Key::load_from) {
            None | Some(Ok(None)) => Hmac::NoKey,
            Some(Ok(Some(key))) => match &app {
                Ok(app) => Hmac::Key(key.for_app(app)),
                Err(why) => Hmac::Broken(why.clone()),
            },
            Some(Err(why)) => Hmac::Broken(why),
        };
        Checker {
            hmac,
            trust: folder.map_or(crate::signed::Trust::None, crate::signed::Trust::in_folder),
            app,
        }
    }

    /// No review key and no list of trusted keys: nothing sealed counts.
    pub fn no_key() -> Checker {
        Checker {
            hmac: Hmac::NoKey,
            trust: crate::signed::Trust::None,
            app: Err("no app was named".to_owned()),
        }
    }

    /// This review key, for its app, and no list of trusted keys.
    pub fn key(key: AppKey) -> Checker {
        Checker {
            app: Ok(key.app.clone()),
            hmac: Hmac::Key(key),
            trust: crate::signed::Trust::None,
        }
    }

    /// A review key that cannot be used, for this reason.
    pub fn broken(why: impl Into<String>) -> Checker {
        Checker {
            hmac: Hmac::Broken(why.into()),
            ..Checker::no_key()
        }
    }

    /// The same, checking signed seals against `trust`, for the app in `app` here.
    pub fn trusting(self, trust: crate::signed::Trust, app: Option<App>) -> Checker {
        Checker {
            trust,
            app: app.map_or(self.app, Ok),
            ..self
        }
    }

    /// The review key it checks `v2:` seals with.
    pub fn hmac(&self) -> &Hmac {
        &self.hmac
    }

    /// Whether an entry with these fields and this seal counts, and where its seal was checked.
    /// `Err` says why not, in words for the owner, as the end of a sentence about the entry.
    pub fn check(&self, seal: Option<&str>, fields: &[&str]) -> Result<Sealed, String> {
        self.recorded(seal, fields).map_err(|why| {
            format!(
                "{}, so {}",
                why.why(),
                match why {
                    Unrecorded::NoSeal | Unrecorded::Malformed => {
                        "it is a proposal and the finding or answer it is about stays as it was"
                    }
                    _ => "here it counts only as a proposal",
                }
            )
        })
    }

    /// The same, with why not as a reason the caller words the consequence of.
    pub fn recorded(&self, seal: Option<&str>, fields: &[&str]) -> Result<Sealed, Unrecorded> {
        let seal = seal
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(Unrecorded::NoSeal)?;
        let (key_id, app_id, mac) = match parse_review(seal).ok_or(Unrecorded::Malformed)? {
            Parsed::BeforeApps => return Err(Unrecorded::BeforeApps),
            Parsed::Signed { app, signature } => {
                let (key, from) = self.trust.check(
                    self.app.as_ref().map_err(String::as_str),
                    app,
                    &signature,
                    fields,
                )?;
                return Ok(Sealed::Signed { key, from });
            }
            Parsed::Current { key, app, mac } => (key, app, mac),
        };
        match &self.hmac {
            Hmac::NoKey => Err(Unrecorded::NoKeyHere),
            Hmac::Broken(why) => Err(Unrecorded::KeyBroken(why.clone())),
            Hmac::Key(key) if key.id() != key_id => Err(Unrecorded::OtherKey(key_id.to_owned())),
            Hmac::Key(key) if key.app.id != app_id => Err(Unrecorded::OtherApp),
            Hmac::Key(key) => {
                // Compared in full, whatever differs first: the time taken says nothing useful.
                let expected = key.mac(fields);
                let same = expected.len() == mac.len()
                    && expected.iter().zip(&mac).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0;
                if same {
                    Ok(Sealed::Here)
                } else {
                    Err(Unrecorded::Mismatch)
                }
            }
        }
    }
}

/// Why an entry does not count as recorded through `sv review`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unrecorded {
    NoSeal,
    Malformed,
    /// Sealed, but this computer has no review key to check the seal with.
    NoKeyHere,
    KeyBroken(String),
    OtherKey(String),
    /// Sealed with this computer's key for an app in another folder.
    OtherApp,
    /// Sealed before seals named the app they were made for.
    BeforeApps,
    Mismatch,
    /// Signed, but this computer has no list of trusted keys to check it against.
    NoTrustedList,
    /// Signed, and the list of trusted keys here cannot be read.
    TrustBroken(String),
    /// Signed with a key the list does not name: its fingerprint, and the list.
    NotTrusted(String, crate::signed::ListFrom),
    /// Signed with a key the list names, but for other apps only.
    TrustedForAnotherApp(String, crate::signed::ListFrom),
}

impl Unrecorded {
    /// Why, as a clause about the entry: "it was not recorded through `sv review`, …".
    pub fn why(&self) -> String {
        match self {
            Unrecorded::NoSeal => "it was not recorded through `sv review`, which a person runs in \
                                   their own terminal"
                .to_owned(),
            Unrecorded::Malformed => "its `seal` is not one `sv review` writes".to_owned(),
            Unrecorded::NoKeyHere => "it carries a seal this computer cannot check: there is no \
                                      review key here to check it with, and a made-up seal would \
                                      look the same. To count it, run `sv review` once on this \
                                      computer, or once on the computer it was sealed on, which \
                                      signs it again so that any computer given your list of \
                                      trusted keys can check it"
                .to_owned(),
            Unrecorded::KeyBroken(why) => format!(
                "this computer's review key cannot be used ({why}), and no seal can be checked here"
            ),
            Unrecorded::OtherKey(id) => format!(
                "it was sealed with a key that is not this computer's ({id}). This computer cannot \
                 check that seal, and a made-up one would look the same"
            ),
            Unrecorded::OtherApp => "it was sealed through `sv review` for an app in another \
                                     folder, and a seal counts only in the app it was made for. If \
                                     this app was moved or copied here, run `sv review` in it to \
                                     record the answer again"
                .to_owned(),
            Unrecorded::BeforeApps => "it was sealed before seals named the app they were made for \
                                       (6 October 2026). Run `sv review` once in this app to seal it \
                                       again"
                .to_owned(),
            Unrecorded::Mismatch => "its seal does not match what it says: it was changed after \
                                     `sv review` recorded it, or the seal was not made by `sv review`"
                .to_owned(),
            Unrecorded::NoTrustedList => format!(
                "it is signed, but this computer has no list of trusted keys to check the \
                 signature against, and a made-up one would look the same. To count it, run \
                 `sv review` once on this computer, or set {} to the line `sv review` showed you \
                 (on CI, from a repository variable)",
                crate::signed::TRUSTED_VARIABLE
            ),
            Unrecorded::TrustBroken(why) => format!(
                "it is signed, but the list of trusted keys cannot be used ({why}), and no \
                 signature can be checked here"
            ),
            Unrecorded::NotTrusted(key, from) => format!(
                "it is signed with a key ({key}) that {} does not name, and anyone can make a key \
                 and sign with it",
                from.named()
            ),
            Unrecorded::TrustedForAnotherApp(key, from) => format!(
                "it is signed with a key ({key}) that {} trusts for another app only, and a \
                 seal counts only in the app it was made for",
                from.named()
            ),
        }
    }
}

/// The key id and the MAC of a seal written as `v1:<16 hex>:<64 hex>`.
fn parse(seal: &str) -> Option<(&str, Vec<u8>)> {
    let mut parts = seal.split(':');
    let (Some("v1"), Some(id), Some(mac), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if id.len() != 16 || unhex(id).is_none() || mac.len() != 64 {
        return None;
    }
    Some((id, unhex(mac)?))
}

/// A review seal, as `parse_review` reads it.
enum Parsed<'a> {
    /// `v1:<16 hex>:<64 hex>`, written before seals named their app.
    BeforeApps,
    /// `v2:<16 hex>:<16 hex>:<64 hex>`.
    Current {
        key: &'a str,
        app: &'a str,
        mac: Vec<u8>,
    },
    /// `v3:<16 hex>:<hex>`, a signature (ADR-043).
    Signed { app: &'a str, signature: Vec<u8> },
}

fn parse_review(seal: &str) -> Option<Parsed<'_>> {
    if parse(seal).is_some() {
        return Some(Parsed::BeforeApps);
    }
    let id = |t: &str| t.len() == 16 && unhex(t).is_some();
    if let Some(rest) = seal.strip_prefix("v3:") {
        let (app, signature) = rest.split_once(':')?;
        if !id(app) || signature.is_empty() {
            return None;
        }
        return Some(Parsed::Signed {
            app,
            signature: unhex(signature)?,
        });
    }
    let mut parts = seal.split(':');
    let (Some("v2"), Some(key), Some(app), Some(mac), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    if !id(key) || !id(app) || mac.len() != 64 {
        return None;
    }
    Some(Parsed::Current {
        key,
        app,
        mac: unhex(mac)?,
    })
}

/// What a seal is made over: the domain, then each field with its length first, so moving text
/// from one field to the next changes the seal.
pub(crate) fn framed(domain: &str, fields: &[&str]) -> Vec<u8> {
    let mut out = domain.as_bytes().to_vec();
    for field in fields {
        out.extend_from_slice(format!("{}:", field.len()).as_bytes());
        out.extend_from_slice(field.as_bytes());
        out.push(b'\n');
    }
    out
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// The fields a `[[finding-review]]` entry is sealed over: everything it says, so changing any of
/// it, the reason included, breaks the seal.
pub fn finding_review_fields(entry: &sv_manifest::FindingReview) -> Vec<String> {
    vec![
        "finding-review".to_owned(),
        entry.rule.trim().to_owned(),
        entry.file.trim().to_owned(),
        entry.fingerprint.trim().to_owned(),
        entry.verdict.trim().to_owned(),
        entry.why.trim().to_owned(),
        entry.by.as_deref().unwrap_or("").trim().to_owned(),
        entry.on.as_deref().unwrap_or("").trim().to_owned(),
    ]
}

/// The fields a confirmation is sealed over: what it is under (`design` or `checked-by-hand`), the
/// requirement, and everything the confirmation says: `by`, `on`, `how`, `answer`, `where`, and
/// `result`, in that order.
pub fn confirmation_fields(
    section: &str,
    requirement: &str,
    says: [Option<&str>; 6],
) -> Vec<String> {
    let mut fields = vec![
        "confirmed".to_owned(),
        section.to_owned(),
        requirement.trim().to_owned(),
    ];
    fields.extend(says.iter().map(|v| v.unwrap_or("").trim().to_owned()));
    fields
}

/// The same, for a confirmation as securevibe.toml gives it.
pub fn manifest_confirmation_fields(
    section: &str,
    requirement: &str,
    c: &sv_manifest::Confirmed,
) -> Vec<String> {
    confirmation_fields(
        section,
        requirement,
        [
            c.by.as_deref(),
            c.on.as_deref(),
            c.how.as_deref(),
            c.answer.as_deref(),
            c.r#where.as_deref(),
            c.result.as_deref(),
        ],
    )
}

/// The fields an answer under `[design]` is sealed over.
pub fn design_answer_fields(requirement: &str, a: &sv_manifest::DesignAnswer) -> Vec<String> {
    let field = |v: Option<&str>| v.unwrap_or("").trim().to_owned();
    vec![
        "design-answer".to_owned(),
        requirement.trim().to_owned(),
        a.answer.trim().to_owned(),
        field(a.r#where.as_deref()),
        field(a.by.as_deref()),
    ]
}

/// The fields a result under `[checked-by-hand]` is sealed over.
pub fn hand_check_fields(requirement: &str, h: &sv_manifest::HandCheck) -> Vec<String> {
    let field = |v: Option<&str>| v.unwrap_or("").trim().to_owned();
    vec![
        "checked-by-hand-result".to_owned(),
        requirement.trim().to_owned(),
        h.result.trim().to_owned(),
        field(h.on.as_deref()),
        field(h.by.as_deref()),
        field(h.how.as_deref()),
    ]
}

/// The fields a section of the security notes is sealed over: its requirement and its answer, as
/// the report reads it.
pub fn notes_fields(requirement: &str, prose: &str) -> Vec<String> {
    vec![
        "security-notes".to_owned(),
        requirement.trim().to_owned(),
        prose.trim().to_owned(),
    ]
}

/// What the reports add after "you answered yes" for an answer recorded through `sv review`.
pub fn recorded_where(sealed: &Sealed) -> String {
    match sealed {
        Sealed::Here => ", recorded through `sv review` on this computer".to_owned(),
        Sealed::Signed { key, from } => format!(
            ", recorded through `sv review` and signed with key {key}, which {} trusts for this app",
            from.named()
        ),
    }
}

/// Whether an owner's answer counts as theirs, checked where this runs: the seal, or why not.
pub fn owner_recorded(
    checker: &Checker,
    seal: Option<&str>,
    fields: &[String],
) -> Result<Sealed, String> {
    checker
        .recorded(seal, &as_strs(fields))
        .map_err(|why| why.why())
}

/// The fields as the sealing functions take them.
pub fn as_strs(fields: &[String]) -> Vec<&str> {
    fields.iter().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_report_seal_never_stands_for_a_review_seal_or_the_other_way() {
        let key = super::Key::random().unwrap();
        let fields = ["security-notes", "V6.1.1", "Only staff see bookings."];
        let review = key.for_app(&app()).seal(&fields);
        let report = key.report_seal(&fields);
        assert_ne!(review, report);
        // Made by the same key over the same fields, each fails where the other is checked.
        assert!(key.report_seal_holds(&report, &fields).is_ok());
        assert!(key.report_seal_holds(&review, &fields).is_err());
        let checker = super::Checker::key(key.for_app(&app()));
        assert!(checker.check(Some(&review), &fields).is_ok());
        assert!(checker.check(Some(&report), &fields).is_err());
    }

    use super::*;

    /// Four keys from the system's randomness, the same ones throughout the run.
    fn key(n: usize) -> Key {
        static KEYS: std::sync::OnceLock<Vec<Key>> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| (0..4).map(|_| Key::random().unwrap()).collect())[n].clone()
    }

    /// The app the tests seal for, and another.
    fn app() -> App {
        App::named_for_tests("bookings")
    }

    fn other_app() -> App {
        App::named_for_tests("shop")
    }

    /// Key `n`, sealing for `app()`.
    fn sealer(n: usize) -> AppKey {
        key(n).for_app(&app())
    }

    const FIELDS: &[&str] = &["finding-review", "ast.open-redirect", "app.py", "owner"];

    #[test]
    fn a_seal_holds_on_the_computer_that_made_it_and_nowhere_it_was_changed() {
        let k = sealer(0);
        let seal = k.seal(FIELDS);
        let here = Checker::key(k.clone());
        assert_eq!(here.check(Some(&seal), FIELDS), Ok(Sealed::Here));
        // Any field changed, or text moved from one field to the next, breaks it.
        for changed in [
            &["finding-review", "ast.open-redirect", "app.py", "Owner"][..],
            &["finding-review", "ast.open-redirect", "app.pyowner", ""][..],
            &["finding-review", "ast.open-redirect", "app.py"][..],
        ] {
            assert!(here.check(Some(&seal), changed).is_err(), "{changed:?}");
        }
        // Even across a line break inside a field, as a reason written over two lines has.
        let two = k.seal(&["a reason\nover two", "lines"]);
        assert!(
            here.check(Some(&two), &["a reason", "over two\nlines"])
                .is_err()
        );
        // One hex digit of the seal changed.
        let mut bent = seal.clone();
        let last = bent.pop().unwrap();
        bent.push(if last == '0' { '1' } else { '0' });
        let err = here.check(Some(&bent), FIELDS).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn no_seal_or_a_malformed_one_is_a_proposal_wherever_it_is_read() {
        for checker in [Checker::no_key(), Checker::key(sealer(1))] {
            for seal in [
                None,
                Some(""),
                Some("  "),
                Some("owner"),
                Some("v1:abc:def"),
            ] {
                let err = checker.check(seal, FIELDS).unwrap_err();
                assert!(err.contains("proposal"), "{seal:?}: {err}");
            }
            let other = format!("v3{}", &sealer(1).seal(FIELDS)[2..]);
            assert!(checker.check(Some(&other), FIELDS).is_err());
            // One part short, or the app's id not hex.
            let seal = sealer(1).seal(FIELDS);
            let (head, mac) = seal.rsplit_once(':').unwrap();
            let (head, _) = head.rsplit_once(':').unwrap();
            assert_eq!(
                checker.recorded(Some(&format!("{head}:{mac}")), FIELDS),
                Err(Unrecorded::Malformed)
            );
            assert_eq!(
                checker.recorded(Some(&format!("{head}:zzzzzzzzzzzzzzzz:{mac}")), FIELDS),
                Err(Unrecorded::Malformed)
            );
        }
    }

    #[test]
    fn a_seal_counts_only_where_this_computers_key_checks_it() {
        let seal = sealer(2).seal(FIELDS);
        let err = Checker::key(sealer(3))
            .check(Some(&seal), FIELDS)
            .unwrap_err();
        assert!(err.contains("not this computer's"), "{err}");
        // A computer with no key cannot tell the owner's seal from one the AI coding tool wrote,
        // so it counts nothing sealed, and says what to do (item 8 of the review of 1 to 4 October).
        assert_eq!(
            Checker::no_key().recorded(Some(&seal), FIELDS),
            Err(Unrecorded::NoKeyHere)
        );
        let err = Checker::no_key().check(Some(&seal), FIELDS).unwrap_err();
        for says in [
            "cannot check",
            "run `sv review` once on this computer",
            "the computer it was sealed on",
            "only as a proposal",
        ] {
            assert!(err.contains(says), "{says}: {err}");
        }
        let err = Checker::broken("it is a folder")
            .check(Some(&seal), FIELDS)
            .unwrap_err();
        assert!(err.contains("it is a folder"), "{err}");
    }

    #[test]
    fn a_seal_counts_only_in_the_app_it_was_made_for() {
        // Item 11 of the review of 1 to 4 October: the same key, the same fields, another app.
        let seal = sealer(0).seal(FIELDS);
        let there = Checker::key(key(0).for_app(&other_app()));
        assert_eq!(
            there.recorded(Some(&seal), FIELDS),
            Err(Unrecorded::OtherApp)
        );
        let err = there.check(Some(&seal), FIELDS).unwrap_err();
        assert!(err.contains("another folder"), "{err}");
        assert!(err.contains("run `sv review` in it"), "{err}");
        // The app's id swapped into the seal does not make it count: the MAC covers it.
        let forged = seal.replacen(app().id(), other_app().id(), 1);
        assert_ne!(forged, seal);
        assert_eq!(
            there.recorded(Some(&forged), FIELDS),
            Err(Unrecorded::Mismatch)
        );
        // Sealed for the other app, it counts there and not here.
        let theirs = key(0).for_app(&other_app()).seal(FIELDS);
        assert_eq!(there.check(Some(&theirs), FIELDS), Ok(Sealed::Here));
        assert_eq!(
            Checker::key(sealer(0)).recorded(Some(&theirs), FIELDS),
            Err(Unrecorded::OtherApp)
        );
    }

    #[test]
    fn a_seal_made_before_seals_named_their_app_is_asked_about_again() {
        // How a seal was written before 6 October 2026: the key's MAC over the fields alone.
        let k = key(0);
        let old = format!(
            "v1:{}:{}",
            k.id(),
            hex(&k.mac_in("sv review seal v1\n", FIELDS))
        );
        for checker in [Checker::no_key(), Checker::key(sealer(0))] {
            assert_eq!(
                checker.recorded(Some(&old), FIELDS),
                Err(Unrecorded::BeforeApps)
            );
        }
        let err = Checker::key(sealer(0))
            .check(Some(&old), FIELDS)
            .unwrap_err();
        assert!(err.contains("Run `sv review` once in this app"), "{err}");
    }

    #[test]
    fn an_app_is_its_folder_however_it_is_reached() {
        let dir = std::env::temp_dir().join(format!("sv-seal-app-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("one")).unwrap();
        std::fs::create_dir_all(dir.join("two")).unwrap();
        let one = App::of(&dir.join("one")).unwrap();
        assert_eq!(one.id().len(), 16);
        assert_eq!(
            App::of(&dir.join("two").join("..").join("one")).unwrap(),
            one
        );
        assert_ne!(App::of(&dir.join("two")).unwrap(), one);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("one"), dir.join("link")).unwrap();
            assert_eq!(App::of(&dir.join("link")).unwrap(), one);
        }
        // A folder that is not there cannot be sealed for, and no seal counts in it.
        assert!(App::of(&dir.join("none")).is_err());
        let keys = dir.join("keys");
        Key::load_or_make_in(&keys).unwrap();
        let checker = Checker::in_folder(Some(&keys), &dir.join("none"));
        assert!(matches!(checker.hmac(), Hmac::Broken(_)), "{checker:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_key_is_made_private_once_and_read_back_the_same() {
        let dir = std::env::temp_dir().join(format!("sv-seal-key-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let folder = dir.join("securevibe");
        assert!(Key::load_from(&folder).unwrap().is_none());
        let (made, new) = Key::load_or_make_in(&folder).unwrap();
        assert!(new);
        let (again, new) = Key::load_or_make_in(&folder).unwrap();
        assert!(!new);
        assert_eq!(made.id(), again.id());
        assert!(made.bytes.iter().any(|b| *b != 0));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&folder), 0o700);
            assert_eq!(mode(&folder.join(KEY_FILE)), 0o600);
        }
        // The key never shows in what is printed about it.
        let shown = format!("{made:?}");
        assert!(!shown.contains(&hex(&made.bytes)), "{shown}");
        assert!(
            matches!(Checker::in_folder(Some(&folder), &dir).hmac(), Hmac::Key(k) if k.id() == made.id())
        );
        let shown = format!("{:?}", made.for_app(&app()));
        assert!(!shown.contains(&hex(&made.bytes)), "{shown}");
        assert!(matches!(
            Checker::in_folder(Some(&dir.join("none")), &dir).hmac(),
            Hmac::NoKey
        ));
        assert!(matches!(Checker::in_folder(None, &dir).hmac(), Hmac::NoKey));
        // Something that is not a key is refused, never quietly replaced, and no seal counts.
        std::fs::write(folder.join(KEY_FILE), "not a key\n").unwrap();
        assert!(Key::load_from(&folder).is_err());
        assert!(Key::load_or_make_in(&folder).is_err());
        let broken = Checker::in_folder(Some(&folder), &dir);
        assert!(matches!(broken.hmac(), Hmac::Broken(_)), "{broken:?}");
        let seal = made.for_app(&App::of(&dir).unwrap()).seal(FIELDS);
        assert!(broken.check(Some(&seal), FIELDS).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_field_of_an_owners_answer_is_sealed() {
        let design = sv_manifest::DesignAnswer {
            answer: "no".into(),
            r#where: Some("app.py".into()),
            by: Some("owner".into()),
            ..Default::default()
        };
        let base = design_answer_fields("V8.3.1", &design);
        for changed in [
            design_answer_fields("V2.2.2", &design),
            design_answer_fields(
                "V8.3.1",
                &sv_manifest::DesignAnswer {
                    answer: "yes".into(),
                    ..design.clone()
                },
            ),
            design_answer_fields(
                "V8.3.1",
                &sv_manifest::DesignAnswer {
                    r#where: Some("auth.py".into()),
                    ..design.clone()
                },
            ),
            design_answer_fields(
                "V8.3.1",
                &sv_manifest::DesignAnswer {
                    by: Some("ai-tool".into()),
                    ..design.clone()
                },
            ),
        ] {
            assert_ne!(changed, base);
        }
        let hand = sv_manifest::HandCheck {
            result: "problem".into(),
            on: Some("2026-10-04".into()),
            by: Some("owner".into()),
            how: Some("Two browsers booked one slot.".into()),
            ..Default::default()
        };
        let base = hand_check_fields("V2.3.4", &hand);
        for changed in [
            hand_check_fields("V12.2.2", &hand),
            hand_check_fields(
                "V2.3.4",
                &sv_manifest::HandCheck {
                    result: "done".into(),
                    ..hand.clone()
                },
            ),
            hand_check_fields(
                "V2.3.4",
                &sv_manifest::HandCheck {
                    on: Some("2026-10-03".into()),
                    ..hand.clone()
                },
            ),
            hand_check_fields(
                "V2.3.4",
                &sv_manifest::HandCheck {
                    by: Some("ai-tool".into()),
                    ..hand.clone()
                },
            ),
            hand_check_fields(
                "V2.3.4",
                &sv_manifest::HandCheck {
                    how: Some("One browser booked it.".into()),
                    ..hand.clone()
                },
            ),
        ] {
            assert_ne!(changed, base);
        }
    }
}
