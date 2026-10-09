//! Taking the script out of a page: `<script>` elements, `on…=` handlers, and `javascript:` URLs,
//! read the way a browser's tokenizer reads tags. Moved out of `ast.rs` unchanged on 9 October 2026
//! (architecture assessment, item 11).

use super::*;

/// A piece of script taken out of a page, and where it sat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// The language to parse it as: `javascript`, or `typescript` when the page says so.
    pub language: &'static str,
    pub code: String,
    /// How many lines came before it, so a finding can name the line in the page rather than in
    /// the fragment. A reader given line 3 of something they cannot see is worse off than one
    /// given nothing.
    pub line_offset: usize,
}

/// What a page holds, and what could not be taken out of it.
#[derive(Debug, Default)]
pub struct HtmlScan {
    pub fragments: Vec<Fragment>,
    /// Something code-shaped that the extractor did not take. While this is true the page is still
    /// unread, and every rule stays silent about the whole app.
    ///
    /// One function decides both halves on purpose. When "does this page hold code" and "what code
    /// does this page hold" are answered by two pieces of code, they drift, and the direction they
    /// drift in is a page declared read whose code nobody extracted.
    pub left_behind: Option<String>,
}

/// Takes the script out of a page.
///
/// Handles the three places code really lives in markup: a `<script>` element, an `on…=` handler
/// attribute, and a `javascript:` URL in any attribute. A `<script src=…>` with nothing between its
/// tags holds no code — the file it names is parsed like any other. Anything else code-shaped is
/// left behind by name rather than ignored.
///
/// Tags are read the way a browser's tokenizer reads them (WHATWG HTML, "tokenization"), because a
/// page is written for a browser and anything this reads differently is a place to hide in. An
/// unquoted value ends at whitespace or `>`; `/` separates attributes as a space does; a comment and
/// the body of a `<textarea>` hold no tags.
pub fn html_fragments(source: &str) -> HtmlScan {
    page_fragments(source, false)
}

/// `html_fragments`, with every `<script>` read as TypeScript when `typescript_scripts` is set: an
/// Astro page's scripts are, whatever their tag says, since Astro compiles them as TypeScript.
pub(super) fn page_fragments(source: &str, typescript_scripts: bool) -> HtmlScan {
    let mut out = HtmlScan::default();
    let markup = match read_markup(source) {
        Ok(markup) => markup,
        Err(reason) => {
            out.left_behind = Some(reason);
            return out;
        }
    };
    let line_of = |at: usize| source[..at].matches('\n').count();

    // Script elements.
    let mut accounted = 0usize;
    for script in &markup.scripts {
        let body = &source[script.body.clone()];
        accounted += count_schemes(body);
        if !body.trim().is_empty() {
            out.fragments.push(Fragment {
                language: if typescript_scripts {
                    "typescript"
                } else {
                    script.language
                },
                code: body.to_owned(),
                line_offset: line_of(script.body.start),
            });
        }
    }

    // Attributes: a handler is a statement, which parses as JavaScript on its own, and a URL may be
    // a program.
    for attribute in &markup.attributes {
        let raw = &source[attribute.value.clone()];
        accounted += count_schemes(raw);
        let (value, unread_reference) = decode_character_references(raw);
        let handler = is_handler(&attribute.name);
        let program = javascript_url_program(&value);
        if unread_reference && (handler || program.is_some()) {
            // A named reference this does not know may be one a browser turns into a character of
            // the program, and a guessed program is worse than a page named as unread.
            out.left_behind =
                Some("a character reference inside code that this does not decode".to_owned());
            return out;
        }
        if handler {
            if !value.trim().is_empty() {
                out.fragments.push(Fragment {
                    language: "javascript",
                    code: value,
                    line_offset: line_of(attribute.value.start),
                });
            }
        } else if let Some(program) = program {
            out.fragments.push(Fragment {
                language: "javascript",
                code: percent_decode(&program),
                line_offset: line_of(attribute.value.start),
            });
        } else if looks_like_a_disguised_scheme(&value) {
            out.left_behind = Some(
                "a value that is nearly a `javascript:` URL, spelled with a character a browser \
                 does not remove"
                    .to_owned(),
            );
            return out;
        }
    }

    // Every occurrence has to be accounted for. One outside every attribute value and script body
    // read above sits somewhere this does not model — text, a comment, a template language's own
    // syntax — and the page keeps its silence rather than pretend.
    if count_schemes(source) > accounted {
        out.left_behind = Some(
            "a `javascript:` outside any attribute or script this read, so what it belongs to is \
             a guess"
                .to_owned(),
        );
        return out;
    }

    // Finally: anything taken out has to be code the grammar can actually read. A fragment that
    // does not parse yields no findings, which is indistinguishable from a fragment that was clean
    // — so a page holding a `<script>` full of a template language, or a URL this decoded wrongly,
    // is left unread rather than counted as examined.
    //
    // This catches less than it looks like it does, and the reason is worth knowing: the JavaScript
    // grammar includes JSX, so a Vue or React template parses cleanly and reaches the rules as
    // markup rather than being refused. Handlebars, ERB and Jinja do not.
    if let Some(bad) = out
        .fragments
        .iter()
        .find(|f| !parses_cleanly(f.language, &f.code))
    {
        out.left_behind = Some(format!(
            "something taken out of this page is not {} the grammar can read",
            bad.language
        ));
    }
    out
}

/// An attribute of a start tag: its name in lower case, and where its value sits in the page.
pub(super) struct Attribute {
    pub(super) name: String,
    pub(super) value: std::ops::Range<usize>,
}

/// A `<script>` element's body, and the language its tag says it holds.
pub(super) struct Script {
    pub(super) language: &'static str,
    pub(super) body: std::ops::Range<usize>,
}

#[derive(Default)]
pub(super) struct Markup {
    pub(super) attributes: Vec<Attribute>,
    pub(super) scripts: Vec<Script>,
}

/// Elements whose body is text to a browser, not tags. A `<textarea>` holding `<a onclick=…>` shows
/// those characters; it does not make a link.
pub(super) const RAW_TEXT: [&str; 5] = ["script", "style", "textarea", "title", "xmp"];

/// ASCII whitespace as the HTML tokenizer means it.
pub(super) fn is_html_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// Every start tag's attributes, and every script body, read the way a browser's tokenizer does.
///
/// Every delimiter here is ASCII, so byte positions are always character boundaries, and the page
/// is lowered with `to_ascii_lowercase` for the same reason: full Unicode lowering can change a
/// string's length and move every position after it.
pub(super) fn read_markup(source: &str) -> Result<Markup, String> {
    let bytes = source.as_bytes();
    let lower = source.to_ascii_lowercase();
    let len = bytes.len();
    let mut markup = Markup::default();
    let mut at = 0usize;
    while let Some(found) = source[at..].find('<') {
        let open = at + found;
        if lower[open..].starts_with("<!--") {
            // A comment ends at the first `-->`; one never closed runs to the end of the page.
            match lower[open + 4..].find("-->") {
                Some(i) => at = open + 4 + i + 3,
                None => break,
            }
            continue;
        }
        let next = bytes.get(open + 1).copied();
        if matches!(next, Some(b'!' | b'?' | b'/')) {
            // A declaration, a processing instruction, or an end tag: nothing a browser runs.
            match source[open..].find('>') {
                Some(i) => at = open + i + 1,
                None => break,
            }
            continue;
        }
        if !next.is_some_and(|b| b.is_ascii_alphabetic()) {
            // A `<` that starts no tag is text.
            at = open + 1;
            continue;
        }

        let mut i = open + 1;
        while i < len && !is_html_space(bytes[i]) && bytes[i] != b'/' && bytes[i] != b'>' {
            i += 1;
        }
        let name = lower[open + 1..i].to_owned();
        let first_attribute = markup.attributes.len();
        loop {
            while i < len && (is_html_space(bytes[i]) || bytes[i] == b'/') {
                i += 1;
            }
            if i >= len {
                return Err(format!("a `<{name}` tag that is never closed"));
            }
            if bytes[i] == b'>' {
                i += 1;
                break;
            }
            // A name may begin with `=`; after its first character, `=` ends it.
            let name_start = i;
            i += 1;
            while i < len && !is_html_space(bytes[i]) && !matches!(bytes[i], b'/' | b'>' | b'=') {
                i += 1;
            }
            let attribute_name = lower[name_start..i].to_owned();
            let mut j = i;
            while j < len && is_html_space(bytes[j]) {
                j += 1;
            }
            if j >= len || bytes[j] != b'=' {
                // No value; what follows is the next attribute.
                i = j;
                continue;
            }
            j += 1;
            while j < len && is_html_space(bytes[j]) {
                j += 1;
            }
            let value = match bytes.get(j) {
                Some(&quote @ (b'"' | b'\'')) => {
                    let Some(close) = source[j + 1..].find(quote as char) else {
                        return Err(format!("a `<{name}` tag with a quote that is never closed"));
                    };
                    i = j + 1 + close + 1;
                    j + 1..j + 1 + close
                }
                _ => {
                    // Unquoted: the value ends at whitespace or at the end of the tag, and every
                    // other character — quotes, `=`, `/` — is part of it.
                    let start = j;
                    while j < len && !is_html_space(bytes[j]) && bytes[j] != b'>' {
                        j += 1;
                    }
                    i = j;
                    start..j
                }
            };
            markup.attributes.push(Attribute {
                name: attribute_name,
                value,
            });
        }
        at = i;

        if !RAW_TEXT.contains(&name.as_str()) {
            continue;
        }
        // The body runs to the first end tag of the same name, and only a real one: `</scripts`
        // does not end a script.
        let closing = format!("</{name}");
        let mut search = at;
        let close = loop {
            match lower[search..].find(&closing) {
                Some(i) => {
                    let after = search + i + closing.len();
                    if bytes
                        .get(after)
                        .is_none_or(|&b| is_html_space(b) || b == b'/' || b == b'>')
                    {
                        break Some(search + i);
                    }
                    search = after;
                }
                None => break None,
            }
        };
        let Some(close) = close else {
            if name == "script" {
                return Err("a `<script>` with no `</script>` after it".to_owned());
            }
            // The rest of the page is that element's text.
            break;
        };
        if name == "script" {
            // `lang="ts"` is how a Vue component says so; `type="text/typescript"` is the older way.
            let typescript = markup.attributes[first_attribute..].iter().any(|a| {
                let value = lower[a.value.clone()].trim();
                (a.name == "lang" && value == "ts") || value.contains("typescript")
            });
            markup.scripts.push(Script {
                language: if typescript {
                    "typescript"
                } else {
                    "javascript"
                },
                body: at..close,
            });
        }
        at = close;
    }
    Ok(markup)
}

/// Whether an attribute is an event handler, whose value a browser runs as a statement.
pub(super) fn is_handler(name: &str) -> bool {
    name.strip_prefix("on")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphabetic()))
}

/// How many times the scheme is written, plainly, in some text.
pub(super) fn count_schemes(text: &str) -> usize {
    text.to_ascii_lowercase().matches("javascript:").count()
}

/// The program in a `javascript:` URL, if that is what this attribute value is.
///
/// A browser's URL parser (WHATWG URL) first strips leading and trailing control characters and
/// spaces, then removes every tab and newline anywhere in the value, and only then reads the
/// scheme. So `java&#9;script:` runs, and so does `javascript:go(\n)` as `go()`. This does the same
/// two steps, in that order, and nothing more.
pub(super) fn javascript_url_program(value: &str) -> Option<String> {
    let trimmed = value.trim_matches(|c: char| c <= ' ');
    let cleaned: String = trimmed
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let head = cleaned.get(.."javascript:".len())?;
    head.eq_ignore_ascii_case("javascript:")
        .then(|| cleaned["javascript:".len()..].to_owned())
}

/// Whether a value that is not a `javascript:` URL is nearly one.
///
/// A browser removes tabs and newlines from inside a scheme and nothing else, so `java\u{1}script:`
/// does not run. That is this reading of the URL specification, though, and the cost of being wrong
/// about it is a false clean: a value that becomes the scheme once every control character is taken
/// out keeps the page unread rather than be passed on the strength of a reading.
pub(super) fn looks_like_a_disguised_scheme(value: &str) -> bool {
    let collapsed: String = value
        .chars()
        .take(64)
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    collapsed.len() >= "javascript:".len()
        && collapsed.is_char_boundary("javascript:".len())
        && collapsed[.."javascript:".len()].eq_ignore_ascii_case("javascript:")
}

/// Turns `%20` back into a space, and leaves anything that is not a complete escape alone.
pub(super) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // A decode that does not produce text is a decode this had no business doing.
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// Whether the grammar can read this fragment without falling over.
///
/// `has_error` is the whole point. Tree-sitter always returns a tree, so a fragment of something
/// that is not this language parses into a wreck that matches no rule and reports nothing — which
/// reads exactly like a fragment that was clean.
pub(super) fn parses_cleanly(language: &str, code: &str) -> bool {
    let Some(grammar) = grammar(language) else {
        return false;
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return false;
    }
    match parser.parse(code, None) {
        Some(tree) => !tree.root_node().has_error(),
        None => false,
    }
}

/// Puts back the character references a browser decodes in an attribute value.
///
/// Numeric references (`&#9;`, `&#x6A;`, with or without the `;`) are decoded exactly. Named ones
/// are decoded for every name that stands for an ASCII character, which covers every name that can
/// spell a scheme or a statement. The second half of the answer says whether a named reference was
/// left as written: most such names are ones a browser leaves alone too, but a few hundred stand for
/// a letter JavaScript accepts in a name, so where it matters the caller treats it as unread.
///
/// Not modeled: the legacy references a browser still decodes without a `;` (`&amp`, `&lt`) — left
/// as written, where they make a statement the grammar refuses rather than a different statement.
pub(super) fn decode_character_references(text: &str) -> (String, bool) {
    let mut out = String::with_capacity(text.len());
    let mut unread = false;
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let after = &rest[1..];
        if let Some(number) = after.strip_prefix('#') {
            let (digits, radix) = match number.strip_prefix(['x', 'X']) {
                Some(hex) => (hex, 16),
                None => (number, 10),
            };
            let count = digits
                .bytes()
                .take_while(|b| {
                    if radix == 16 {
                        b.is_ascii_hexdigit()
                    } else {
                        b.is_ascii_digit()
                    }
                })
                .count();
            if count > 0 {
                // Zero, a surrogate, or past the end of Unicode is U+FFFD to a browser.
                let decoded = u32::from_str_radix(&digits[..count], radix)
                    .ok()
                    .filter(|&n| n != 0)
                    .and_then(char::from_u32)
                    .unwrap_or('\u{FFFD}');
                out.push(decoded);
                rest = &digits[count..];
                rest = rest.strip_prefix(';').unwrap_or(rest);
                continue;
            }
        } else {
            let length = after
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric())
                .count();
            if length > 0 && after[length..].starts_with(';') {
                if let Some(decoded) = named_reference(&after[..length]) {
                    out.push(decoded);
                    rest = &after[length + 1..];
                    continue;
                }
                unread = true;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    (out, unread)
}

/// The named references that stand for an ASCII character, plus the no-break space.
pub(super) fn named_reference(name: &str) -> Option<char> {
    Some(match name {
        "lt" | "LT" => '<',
        "gt" | "GT" => '>',
        "quot" | "QUOT" => '"',
        "apos" => '\'',
        "amp" | "AMP" => '&',
        "Tab" => '\t',
        "NewLine" => '\n',
        "colon" => ':',
        "lpar" => '(',
        "rpar" => ')',
        "sol" => '/',
        "bsol" => '\\',
        "semi" => ';',
        "comma" => ',',
        "period" => '.',
        "excl" => '!',
        "quest" => '?',
        "num" => '#',
        "percnt" => '%',
        "equals" => '=',
        "plus" => '+',
        "lsqb" | "lbrack" => '[',
        "rsqb" | "rbrack" => ']',
        "lcub" | "lbrace" => '{',
        "rcub" | "rbrace" => '}',
        "grave" | "DiacriticalGrave" => '`',
        "ast" | "midast" => '*',
        "dollar" => '$',
        "commat" => '@',
        "Hat" => '^',
        "lowbar" | "UnderBar" => '_',
        "verbar" | "vert" | "VerticalLine" => '|',
        "nbsp" | "NonBreakingSpace" => '\u{A0}',
        _ => return None,
    })
}
