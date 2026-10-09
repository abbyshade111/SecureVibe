//! A path in what the MCP server tells an AI coding tool to have the person run, quoted the way the
//! person's own shell reads it (backlog 0120).

use super::quoted_for;

#[test]
fn a_windows_path_is_plain_and_one_with_a_space_is_in_double_quotes() {
    assert_eq!(
        quoted_for(r"C:\Users\me\sv.exe", true),
        r"C:\Users\me\sv.exe"
    );
    assert_eq!(
        quoted_for(r"C:\Program Files\sv\sv.exe", true),
        r#""C:\Program Files\sv\sv.exe""#
    );
    // A double quote inside is doubled, as the Command Prompt reads it.
    assert_eq!(quoted_for(r#"C:\a"b"#, true), r#""C:\a""b""#);
    // No single quote: on Windows it would be read as part of the name.
    assert!(!quoted_for(r"C:\My Apps\notes", true).contains('\''));
}

#[test]
fn a_unix_path_is_as_before() {
    assert_eq!(quoted_for("/usr/local/bin/sv", false), "/usr/local/bin/sv");
    assert_eq!(quoted_for("/my apps/notes", false), "'/my apps/notes'");
    assert_eq!(quoted_for("/it's", false), r"'/it'\''s'");
    // A backslash is no separator on Unix, so a name holding one is quoted.
    assert_eq!(quoted_for(r"/a\b", false), r"'/a\b'");
}
