//! The tests of `production.rs` that were `mod curl_tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

use super::*;
use std::net::IpAddr;

struct Answers(Vec<&'static str>, usize);

impl Resolve for Answers {
    fn addresses(&mut self, _host: &str) -> Result<Vec<IpAddr>, String> {
        self.1 += 1;
        Ok(self.0.iter().map(|a| a.parse().unwrap()).collect())
    }
}

#[test]
fn an_address_on_this_computer_or_its_network_is_refused_however_it_is_written() {
    for (typed, says) in [
        ("https://10.0.0.1", "private network"),
        ("https://172.16.5.4:8443/x", "private network"),
        ("https://192.168.1.1", "private network"),
        ("https://169.254.169.254/latest/meta-data", "link-local"),
        ("https://100.64.0.1", "address translation"),
        ("https://0.0.0.0", "no particular computer"),
        ("https://127.0.0.2", "this computer"),
        ("https://[::1]", "this computer"),
        ("https://[::]", "no particular computer"),
        ("https://[fd00::1]", "private network"),
        ("https://[fe80::1]:443", "link-local"),
        ("https://[::ffff:10.1.2.3]", "private network"),
        ("https://[::ffff:127.0.0.1]", "this computer"),
        ("https://224.0.0.1", "does not reach one computer"),
        ("https://255.255.255.255", "does not reach one computer"),
        ("https://app.localhost", "this machine"),
        ("https://localhost.", "this machine"),
        // IPv6 forms that carry an IPv4 address, judged by it (ADR-027, "Later").
        ("https://[2002:a00:1::]", "private network"),
        ("https://[2002:7f00:1::1]", "this computer"),
        ("https://[2002:a9fe:a9fe::]", "link-local"),
        ("https://[64:ff9b::10.0.0.1]", "private network"),
        ("https://[64:ff9b::a9fe:a9fe]", "link-local"),
        (
            "https://[2001:0:4136:e378:8000:63bf:f5ff:fffe]",
            "private network",
        ),
        ("https://[64:ff9b:1::5db8:d70e]", "translator"),
        // The ranges kept for documentation, and IPv6's old site-local one.
        ("https://192.0.2.10", "documentation"),
        ("https://198.51.100.7", "documentation"),
        ("https://203.0.113.9", "documentation"),
        ("https://[2001:db8::1]", "documentation"),
        ("https://[fec0::1]", "private network"),
    ] {
        let refused = read_target(typed).expect_err(typed);
        assert!(refused.contains(says), "{typed}: {refused}");
    }
    // The control: public addresses, typed as numbers, are still accepted, and so are the
    // forms above when the IPv4 address they carry is public.
    for typed in [
        "https://93.184.215.14",
        "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]:8443",
        "https://[2002:5db8:d70e::1]",
        "https://[64:ff9b::5db8:d70e]",
        "https://[2001:0:4136:e378:8000:63bf:a247:28f1]",
    ] {
        let target = read_target(typed).expect(typed);
        assert!(
            addresses(&target, &mut Answers(vec![], 0)).is_ok(),
            "{typed}"
        );
    }
    // Globs and brackets that are not an address are refused rather than handed to curl.
    for typed in [
        "https://app{1,2}.example.test",
        "https://a[1-9].example.test",
        "https://a.example.test]",
    ] {
        assert!(read_target(typed).is_err(), "{typed}");
    }
}

#[test]
fn a_name_that_looks_up_to_an_internal_address_is_refused_and_curl_is_held_to_what_was_checked() {
    let target = read_target("https://app.example.test").unwrap();
    // Any internal address among the answers refuses the whole name, and says which.
    for answers in [
        vec!["10.0.0.7"],
        vec!["93.184.215.14", "127.0.0.1"],
        vec!["::ffff:192.168.0.9"],
    ] {
        let mut dns = Answers(answers.clone(), 0);
        let refused = addresses(&target, &mut dns).expect_err("refused");
        assert!(
            refused.contains("app.example.test looks up to"),
            "{refused}"
        );
        assert_eq!(dns.1, 1, "looked up once");
    }
    let mut dns = Answers(vec![], 0);
    assert!(
        addresses(&target, &mut dns)
            .unwrap_err()
            .contains("no address")
    );
    // Public answers are kept, and curl is told to use exactly those, on both ports it uses.
    let mut dns = Answers(
        vec!["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
        0,
    );
    let found = addresses(&target, &mut dns).unwrap();
    assert_eq!(found.len(), 2);
    let curl = Curl::held_to(&target, &found);
    let args = curl.args(&["--head", "https://app.example.test/"]);
    let held = "app.example.test:443:93.184.215.14,[2606:2800:21f:cb07:6820:80da:af6b:8b2c]";
    assert!(
        args.windows(2).any(|w| w == ["--resolve", held]),
        "{args:?}"
    );
    assert!(
        args.iter().any(|a| a.starts_with("app.example.test:80:")),
        "{args:?}"
    );
    // A port in the address is the one held.
    let with_port = read_target("https://app.example.test:8443/").unwrap();
    let curl = Curl::held_to(&with_port, &found);
    let args = curl.args(&[]);
    assert!(
        args.iter().any(|a| a.starts_with("app.example.test:8443:")),
        "{args:?}"
    );
    assert!(
        !args.iter().any(|a| a.starts_with("app.example.test:443:")),
        "{args:?}"
    );
}

#[test]
fn every_curl_reads_no_config_globs_nothing_and_speaks_only_http() {
    let target = read_target("https://app.example.test").unwrap();
    let curl = Curl::held_to(&target, &["93.184.215.14".parse().unwrap()]);
    let args = curl.args(&["--head", "https://app.example.test/"]);
    // `--disable` counts only as curl's very first argument.
    assert_eq!(args[0], "--disable");
    assert!(args.contains(&"--globoff"), "{args:?}");
    assert!(
        args.windows(2).any(|w| w == ["--proto", "=http,https"]),
        "{args:?}"
    );
    assert_eq!(args.iter().filter(|a| **a == "--disable").count(), 1);
    assert_eq!(args.last(), Some(&"https://app.example.test/"));
}

#[test]
fn the_cap_is_a_property_of_the_fetcher_not_of_the_caller() {
    // A caller that loops must not be able to turn this into a scan, so the count lives with
    // the thing that makes the requests.
    let mut c = Curl::held_to(&tests_support::target(), &[]);
    c.made = MOST_REQUESTS;
    let answer = c.get("https://example.test/", true);
    assert!(!answer.reached());
    assert!(
        answer.failure.unwrap().contains("at most"),
        "and it says why rather than looking like a network error"
    );
    assert!(
        matches!(c.old_tls("https://example.test/"), OldTls::CannotTell(why) if why.contains("at most")),
        "the old TLS handshake counts against the same cap"
    );
}

#[test]
fn curls_answer_to_old_tls_is_read_for_what_it_says() {
    // The messages are the ones curl printed on 3 October 2026.
    assert_eq!(old_tls_from(Some(0), ""), OldTls::Accepted);
    for refused in [
        "curl: (35) LibreSSL/3.3.6: error:1404B42E:SSL routines:ST_CONNECT:tlsv1 alert protocol version",
        "curl: (35) TLS connect error: error:0A00042E:SSL routines::tlsv1 alert protocol version",
        "curl: (35) LibreSSL/3.3.6: error:1400410A:SSL routines:CONNECT_CR_SRVR_HELLO:wrong ssl version",
    ] {
        assert!(
            matches!(old_tls_from(Some(35), refused), OldTls::Refused(ref s) if !s.starts_with("curl: ")),
            "{refused}"
        );
    }
    // This machine's own library declining, and a dropped connection, are not the site's answer.
    for not_an_answer in [
        "curl: (35) TLS connect error: error:0A00014D:SSL routines::legacy sigalg disallowed or unsupported",
        "curl: (35) TLS connect error: error:0A0000BF:SSL routines::no protocols available",
        "curl: (35) Recv failure: Connection reset by peer",
        "curl: (59) failed setting cipher list: DEFAULT@SECLEVEL=0",
        // Written for this test rather than seen: a timeout.
        "curl: (28) Operation timed out after 15001 milliseconds",
    ] {
        assert!(
            matches!(old_tls_from(Some(35), not_an_answer), OldTls::CannotTell(_)),
            "{not_an_answer}"
        );
    }
    assert!(
        matches!(old_tls_from(Some(35), ""), OldTls::CannotTell(why) if why.contains("said nothing"))
    );
    assert!(
        matches!(old_tls_from(None, ""), OldTls::CannotTell(_)),
        "killed by a signal"
    );
}

#[test]
fn openssl_is_asked_to_offer_old_tls_and_libressl_is_not() {
    let lowered = vec!["--ciphers", "DEFAULT@SECLEVEL=0"];
    // `curl --version`'s first line, as each printed it on 3 October 2026.
    assert_eq!(
        old_tls_library_args(
            "curl 8.12.1 (Darwin) libcurl/8.12.1 OpenSSL/3.0.17 (SecureTransport) zlib/1.2.13\nRelease-Date: x"
        ),
        lowered
    );
    assert!(
            old_tls_library_args(
                "curl 8.7.1 (x86_64-apple-darwin23.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6 zlib/1.2.12"
            )
            .is_empty()
        );
    assert!(
        old_tls_library_args("").is_empty(),
        "curl that did not answer"
    );
}

#[test]
fn curls_headers_are_read_and_the_last_response_is_the_one_kept() {
    // curl prints every response when it follows anything, and the first one's headers are not
    // the answer. Keeping them would read a redirect's Location as the final page's.
    let answer = parse_head(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.test/\r\n\r\n\
             HTTP/2 200 \r\nStrict-Transport-Security: max-age=1\r\nSet-Cookie: a=b\r\n\r\n",
    );
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.header("strict-transport-security"),
        Some("max-age=1")
    );
    assert_eq!(
        answer.header("location"),
        None,
        "the redirect's header must not survive"
    );
}

#[test]
fn header_names_are_read_whatever_case_they_arrive_in() {
    let answer = parse_head("HTTP/2 200 \r\nSTRICT-Transport-Security: max-age=1\r\n");
    assert_eq!(
        answer.header("strict-transport-security"),
        Some("max-age=1")
    );
}
