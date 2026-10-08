//! Every name the product carries, in one place (ADR-062).
//!
//! The product was SecureVibe until 8 October 2026 and is StackVet since; the command is `sv`
//! and stays `sv`. A name a user's files carry (the manifest, the report folder and its marker,
//! the config folder, the markers in `AGENTS.md`, the labels on containers) is kept here twice:
//! the name `sv` writes now, and the old one, which `sv` goes on reading until the window this
//! record names has ended (`WINDOW_ENDS`), and says so each time it does. One name has no old
//! form: the signature namespace, which every seal already written carries, and which a signature
//! verifies only under.
//!
//! Nothing outside this module spells a product name. A crate that needs one reads it from here,
//! so the next rename, if there is one, touches one file.

/// The product, as a person reads it.
pub const PRODUCT: &str = "StackVet";
/// The product's name until 8 October 2026, kept for what still carries it: the paper, the `v1`
/// branch, and the old forms below.
pub const OLD_PRODUCT: &str = "SecureVibe";
/// The command, which does not change.
pub const COMMAND: &str = "sv";

/// The manifest in the app's folder, written by `sv init` and read by every command.
pub const MANIFEST: &str = "stackvet.toml";
pub const OLD_MANIFEST: &str = "securevibe.toml";

/// Where `sv report` writes when not told otherwise.
pub const REPORT_DIR: &str = "stackvet-report";
pub const OLD_REPORT_DIR: &str = "securevibe-report";
/// The file `sv report` writes into every folder it writes a report to, so no walk of the app reads
/// the report as the app's own code.
pub const REPORT_MARKER: &str = ".stackvet-report";
pub const OLD_REPORT_MARKER: &str = ".securevibe-report";
/// The lock `sv report` holds on the folder while it writes.
pub const REPORT_LOCK: &str = ".stackvet-report.lock";
pub const OLD_REPORT_LOCK: &str = ".securevibe-report.lock";

/// The end of a bundle's default name, after the app's own.
pub const BUNDLE_SUFFIX: &str = "stackvet-bundle.zip";
pub const OLD_BUNDLE_SUFFIX: &str = "securevibe-bundle.zip";
/// The comment every bundle ends with, which any zip program shows and which `sv bundle` reads to
/// know a zip is its own before replacing it.
pub const BUNDLE_COMMENT: &str = "Made by StackVet (sv bundle). See README.txt inside.";
pub const OLD_BUNDLE_COMMENT: &str = "Made by SecureVibe (sv bundle). See README.txt inside.";

/// The folder under the config folder (`$XDG_CONFIG_HOME`, or `~/.config`) that holds this
/// computer's signing key, its report key, and the trusted keys. The old one is read when the new
/// one is absent, and nothing moves a key: a person does that, told how.
pub const CONFIG_DIR: &str = "stackvet";
pub const OLD_CONFIG_DIR: &str = "securevibe";

/// The MCP server's name, and the prefix of its tools' names. The old tool names are answered for
/// the window, so an AI coding tool that learned them keeps working.
pub const MCP_SERVER: &str = "stackvet";
pub const OLD_MCP_SERVER: &str = "securevibe";
pub const MCP_TOOL_PREFIX: &str = "stackvet_";
pub const OLD_MCP_TOOL_PREFIX: &str = "securevibe_";

/// The labels on everything `sv run` starts, so leftovers of a run stopped outright are found and
/// removed (ADR-025); the leftover cleanup reads the old label too.
pub const OWNER_LABEL: &str = "org.stackvet.owner";
pub const OLD_OWNER_LABEL: &str = "org.securevibe.owner";
pub const RUN_LABEL: &str = "org.stackvet.run";
pub const OLD_RUN_LABEL: &str = "org.securevibe.run";
/// The label on the volumes the install step fills (ADR-052). Nothing removes them automatically,
/// so the old label needs no reading: `docker volume ls --filter label=` with either lists them.
pub const VOLUME_LABEL: &str = "stackvet.deps";
pub const OLD_VOLUME_LABEL: &str = "securevibe.deps";

/// The markers around the coding rules `sv rules` writes into `AGENTS.md` or `CLAUDE.md`, which it
/// replaces between and leaves everything else as it was. A block under the old markers is found
/// and rewritten under the new.
pub const RULES_BEGIN: &str = "<!-- stackvet:coding-rules:begin -->";
pub const RULES_END: &str = "<!-- stackvet:coding-rules:end -->";
pub const OLD_RULES_BEGIN: &str = "<!-- securevibe:coding-rules:begin -->";
pub const OLD_RULES_END: &str = "<!-- securevibe:coding-rules:end -->";

/// The namespace every seal `sv review` writes is signed under (ADR-043). **It does not change
/// with the name**: an SSH signature verifies only under the namespace it was made with, and every
/// seal already in owners' files carries this one. A wire format, named after the product that
/// made it, as such things are.
pub const SIGNATURE_NAMESPACE: &str = "securevibe-review";

/// The published image. The old one is left as it is, with no further pushes.
pub const IMAGE: &str = "ghcr.io/abbyshade111/stackvet-sv";
pub const OLD_IMAGE: &str = "ghcr.io/abbyshade111/securevibe-sv";

/// Not before this day does a Later entry on ADR-062 end the reading of the old names.
pub const WINDOW_ENDS: &str = "1 January 2027";

/// What the report says when it read something under its old name, so nobody is surprised when the
/// window ends. `what` is the thing by its old name; `new` is the name to give it.
pub fn read_under_old_name(what: &str, new: &str) -> String {
    format!(
        "`{what}` was read under its old name. {PRODUCT} was called {OLD_PRODUCT} until 8 October \
         2026; rename it to `{new}` when you choose. The old name is read until {WINDOW_ENDS} at \
         the earliest."
    )
}
