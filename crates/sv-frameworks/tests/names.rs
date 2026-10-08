//! The names the product carries (ADR-062): each old form differs from its new, the command and
//! the signature namespace do not change, and the sentence for an old name read says what to do.

use sv_frameworks::names::*;

#[test]
fn every_renamed_thing_has_a_new_name_and_keeps_its_old_one_apart() {
    for (new, old) in [
        (PRODUCT, OLD_PRODUCT),
        (MANIFEST, OLD_MANIFEST),
        (REPORT_DIR, OLD_REPORT_DIR),
        (REPORT_MARKER, OLD_REPORT_MARKER),
        (REPORT_LOCK, OLD_REPORT_LOCK),
        (BUNDLE_SUFFIX, OLD_BUNDLE_SUFFIX),
        (BUNDLE_COMMENT, OLD_BUNDLE_COMMENT),
        (CONFIG_DIR, OLD_CONFIG_DIR),
        (MCP_SERVER, OLD_MCP_SERVER),
        (MCP_TOOL_PREFIX, OLD_MCP_TOOL_PREFIX),
        (OWNER_LABEL, OLD_OWNER_LABEL),
        (RUN_LABEL, OLD_RUN_LABEL),
        (VOLUME_LABEL, OLD_VOLUME_LABEL),
        (RULES_BEGIN, OLD_RULES_BEGIN),
        (RULES_END, OLD_RULES_END),
        (IMAGE, OLD_IMAGE),
    ] {
        assert_ne!(new, old);
        assert!(!new.to_lowercase().contains("securevibe"), "{new}");
        assert!(old.to_lowercase().contains("securevibe"), "{old}");
        assert!(new.to_lowercase().contains("stackvet"), "{new}");
    }
}

#[test]
fn the_command_and_the_signature_namespace_do_not_change() {
    assert_eq!(COMMAND, "sv");
    // Every seal already written carries this namespace, and a signature verifies only under the
    // namespace it was made with. Changing it would make every existing seal fail.
    assert_eq!(SIGNATURE_NAMESPACE, "securevibe-review");
}

#[test]
fn the_sentence_for_an_old_name_names_the_new_one_and_the_window() {
    let said = read_under_old_name(OLD_MANIFEST, MANIFEST);
    assert!(
        said.contains("`securevibe.toml` was read under its old name"),
        "{said}"
    );
    assert!(said.contains("rename it to `stackvet.toml`"), "{said}");
    assert!(said.contains(WINDOW_ENDS), "{said}");
}
