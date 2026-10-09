//! The `file://` form of a path on Windows, tested on every system (backlog 0120). Until 9 October
//! 2026 `C:\a\report.json` was written `file://C%3A%5Ca%5Creport.json`, which no AI coding tool
//! reads as a file, and no `file://` URI could be read back there at all.

use super::resources::{file_uri_of, path_text_from_uri, plain_in_uri};

#[test]
fn a_windows_drive_path_is_written_as_rfc_8089_writes_it_and_read_back_exactly() {
    for (path, uri) in [
        (r"C:\a\b\report.json", "file:///C:/a/b/report.json"),
        (
            r"D:\with space\and%percent\report.html",
            "file:///D:/with%20space/and%25percent/report.html",
        ),
        (r"c:\hash#and\x", "file:///c:/hash%23and/x"),
        (r"C:\ünï\r", "file:///C:/%C3%BCn%C3%AF/r"),
        (r"C:\", "file:///C:/"),
    ] {
        assert_eq!(file_uri_of(path, true).as_deref(), Some(uri), "{path}");
        assert_eq!(
            path_text_from_uri(uri, true).as_deref(),
            Some(path),
            "{uri}"
        );
        // The only byte outside the plain set left unescaped is the drive's colon.
        assert!(
            uri[8..]
                .bytes()
                .enumerate()
                .all(|(i, b)| plain_in_uri(b) || b == b'%' || (i == 1 && b == b':')),
            "{uri}"
        );
    }
}

#[test]
fn a_windows_network_share_is_named_by_its_host() {
    let path = r"\\server\share\app\report.json";
    let uri = "file://server/share/app/report.json";
    assert_eq!(file_uri_of(path, true).as_deref(), Some(uri));
    assert_eq!(path_text_from_uri(uri, true).as_deref(), Some(path));
}

#[test]
fn what_names_no_windows_place_is_refused() {
    for path in [r"relative\report.json", "/unix/path", "C:", r"C:relative"] {
        assert_eq!(file_uri_of(path, true), None, "{path}");
    }
    for uri in [
        "file:///no/drive",
        "file:///",
        "file://",
        "file:///C:/a%5C..%5Cb",
        "http://example.com/x",
    ] {
        assert_eq!(path_text_from_uri(uri, true), None, "{uri}");
    }
}

#[test]
fn the_unix_form_is_unchanged() {
    assert_eq!(
        file_uri_of("/a/b c/report.json", false).as_deref(),
        Some("file:///a/b%20c/report.json")
    );
    assert_eq!(
        path_text_from_uri("file:///a/b%20c/report.json", false).as_deref(),
        Some("/a/b c/report.json")
    );
    // A backslash is an ordinary byte in a Unix name, written and read back as itself.
    assert_eq!(
        path_text_from_uri(&file_uri_of(r"/a\b", false).unwrap(), false).as_deref(),
        Some(r"/a\b")
    );
}
