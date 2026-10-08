//! Whether a container image name is one Docker reads as a name, before it is put on Docker's
//! command line (the review of 8 October 2026, item 6).
//!
//! `image` under `[stack.run]` is written by whoever wrote the app's manifest, and `sv` passes it
//! to `docker run` and `docker create` as one argument, where the image goes. A value that is not
//! a name is refused here, with its reason, rather than handed to Docker: one that begins with a
//! dash would be read as an option (`--privileged`), one with a space or a control character is
//! nothing Docker would find, and either would only come back as Docker's own error, or not at
//! all. The grammar is Docker's own (`distribution/reference`, read 8 October 2026):
//!
//! ```text
//! reference      := name [ ":" tag ] [ "@" digest ]
//! name           := [ domain "/" ] path-component { "/" path-component }
//! domain         := host [ ":" port ]          host := domain-name | IPv4 | "[" IPv6 "]"
//! domain-name    := component { "." component }  component := [A-Za-z0-9] ( [A-Za-z0-9-]* [A-Za-z0-9] )?
//! path-component := [a-z0-9]+ { separator [a-z0-9]+ }   separator := "." | "_" | "__" | "-"+
//! tag            := [A-Za-z0-9_] [A-Za-z0-9_.-]{0,127}
//! digest         := algorithm ":" hex{32,}     algorithm := [A-Za-z] [A-Za-z0-9]* { [+.-_] ... }
//! ```
//!
//! The first component is a domain, as Docker decides it, when it holds a `.` or a `:`, is
//! `localhost`, or has an upper-case letter. A name is at most 255 characters.

/// Why `image` is not a name Docker reads, in plain words, or `None` when it is one.
pub fn problem(image: &str) -> Option<String> {
    if image.is_empty() {
        return Some("it is empty".to_owned());
    }
    if let Some(c) = image.chars().find(|c| c.is_whitespace() || c.is_control()) {
        return Some(format!(
            "it holds {}, which no image name does",
            match c {
                '\n' | '\r' => "a line break".to_owned(),
                c if c.is_whitespace() => "a space".to_owned(),
                c => format!("the control character U+{:04X}", c as u32),
            }
        ));
    }
    if image.starts_with('-') {
        return Some(
            "it begins with a dash, which Docker would read as an option rather than an image"
                .to_owned(),
        );
    }
    let (rest, digest) = match image.rsplit_once('@') {
        Some((rest, digest)) => (rest, Some(digest)),
        None => (image, None),
    };
    if let Some(digest) = digest
        && let Some(why) = digest_problem(digest)
    {
        return Some(format!("its digest `{digest}` {why}"));
    }
    // A `:` after the last `/` starts the tag; one before it is a port in the domain.
    let (name, tag) = match rest.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => (name, Some(tag)),
        _ => (rest, None),
    };
    if let Some(tag) = tag
        && let Some(why) = tag_problem(tag)
    {
        return Some(format!("its tag `{tag}` {why}"));
    }
    if name.is_empty() {
        return Some("it has no name before its tag or digest".to_owned());
    }
    if name.len() > 255 {
        return Some(format!(
            "its name is {} characters long, and Docker allows 255",
            name.len()
        ));
    }
    let mut components: Vec<&str> = name.split('/').collect();
    let first = components[0];
    let is_domain = components.len() > 1
        && (first.contains(['.', ':'])
            || first == "localhost"
            || first.chars().any(|c| c.is_ascii_uppercase()));
    if is_domain {
        if let Some(why) = domain_problem(first) {
            return Some(format!("its registry `{first}` {why}"));
        }
        components.remove(0);
    }
    for component in components {
        if let Some(why) = path_component_problem(component) {
            return Some(format!("its part `{component}` {why}"));
        }
    }
    None
}

fn path_component_problem(component: &str) -> Option<&'static str> {
    if component.is_empty() {
        return Some("is empty (two slashes in a row, or a slash at an end)");
    }
    let bytes = component.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return Some("must begin and end with a lower-case letter or a digit");
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if alnum(b) {
            i += 1;
        } else if b == b'.' || b == b'_' {
            // `__` is one separator; `._`, `_.`, `..` are not.
            let next = bytes.get(i + 1).copied();
            if b == b'_' && next == Some(b'_') {
                i += 2;
            } else {
                i += 1;
            }
            if !bytes.get(i).copied().is_some_and(alnum) {
                return Some("has two separators in a row, which Docker refuses");
            }
        } else if b == b'-' {
            while bytes.get(i) == Some(&b'-') {
                i += 1;
            }
            if !bytes.get(i).copied().is_some_and(alnum) {
                return Some("has a dash followed by a separator, which Docker refuses");
            }
        } else {
            return Some(
                "holds a character that is not a lower-case letter, a digit, `.`, `_`, or `-` (an \
                 upper-case letter is allowed only in the registry's name)",
            );
        }
    }
    None
}

fn domain_problem(domain: &str) -> Option<&'static str> {
    let (host, port) = if let Some(rest) = domain.strip_prefix('[') {
        // An IPv6 address in brackets, with an optional port after them.
        let Some((address, after)) = rest.split_once(']') else {
            return Some("opens a bracket it does not close");
        };
        if address.is_empty() || !address.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return Some("is not an IPv6 address inside its brackets");
        }
        match after.strip_prefix(':') {
            Some(port) => ("", Some(port)),
            None if after.is_empty() => ("", None),
            None => return Some("has something after its closing bracket that is not a port"),
        }
    } else {
        match domain.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (domain, None),
        }
    };
    if let Some(port) = port
        && (port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return Some("has a port that is not a number");
    }
    for label in host.split('.').filter(|_| !host.is_empty()) {
        let bytes = label.as_bytes();
        let ok = !bytes.is_empty()
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-';
        if !ok {
            return Some(
                "has a part that is not letters, digits, and dashes between them, as a host name is",
            );
        }
    }
    None
}

fn tag_problem(tag: &str) -> Option<&'static str> {
    if tag.is_empty() {
        return Some("is empty");
    }
    if tag.len() > 128 {
        return Some("is longer than the 128 characters Docker allows");
    }
    let bytes = tag.as_bytes();
    if !(bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_') {
        return Some("must begin with a letter, a digit, or an underscore");
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Some("holds a character that is not a letter, a digit, `_`, `.`, or `-`");
    }
    None
}

fn digest_problem(digest: &str) -> Option<&'static str> {
    let Some((algorithm, encoded)) = digest.split_once(':') else {
        return Some("has no `:` between its algorithm and its value");
    };
    let bytes = algorithm.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return Some("names no algorithm");
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-' | b'_'))
    {
        return Some("names an algorithm with a character it cannot have");
    }
    if encoded.len() < 32 || !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some("has a value that is not at least 32 hexadecimal digits");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::problem;

    #[test]
    fn the_names_docker_reads_pass() {
        for image in [
            "python:3.12-slim",
            "node:22",
            "python",
            "ghcr.io/abbyshade111/securevibe-sv:latest",
            "localhost:5000/app",
            "registry.example.com:443/team/app:1.0",
            "docker.io/library/nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "my__app.v2-x_y:tag_1.2-3",
            "[::1]:5000/app",
            "Example.com/app",
        ] {
            assert_eq!(problem(image), None, "{image}");
        }
    }

    #[test]
    fn what_docker_would_read_as_something_else_is_refused_with_its_reason() {
        for (image, reason) in [
            ("--privileged", "begins with a dash"),
            ("-v", "begins with a dash"),
            ("python:3.12 --privileged", "a space"),
            ("python\n", "a line break"),
            ("python\u{7}", "control character"),
            ("", "is empty"),
            ("Python:3.12", "lower-case"),
            ("app/", "is empty"),
            ("a//b", "is empty"),
            ("app..x", "two separators"),
            ("app-_x", "dash followed"),
            ("app:", "its tag `` is empty"),
            ("app:-1", "must begin with"),
            ("app@sha256:abc", "32 hexadecimal"),
            ("app@sha256", "no `:`"),
            ("[::1/app", "opens a bracket"),
            ("example.com:x/app", "port that is not a number"),
            ("-example.com/app", "begins with a dash"),
            ("ex_ample.com/app", "host name"),
            (":tag", "no name before"),
        ] {
            let why = problem(image).unwrap_or_else(|| panic!("{image:?} should be refused"));
            assert!(why.contains(reason), "{image:?}: {why}");
        }
        let long = format!("{}/app", "a".repeat(260));
        assert!(problem(&long).unwrap().contains("255"));
    }
}
