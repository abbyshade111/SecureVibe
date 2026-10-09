//! The code inside files that are not code: a Jupyter notebook's cells, and the templates of Astro,
//! EJS, Svelte, and Vue. Moved out of `ast.rs` unchanged on 9 October 2026 (architecture assessment,
//! item 11).

use super::*;

/// Reads a Jupyter notebook's code cells as Python (ADR-054), each line at the line it is on in the
/// notebook, so a finding sends the reader to the right place in the file.
///
/// A notebook whose kernel is another language is that language unread. A notebook that is not JSON
/// `sv` can read is a file not opened. Lines Python cannot read, IPython's `%magic` and `!command`
/// lines and its `%%` cell magics, are blanked before the parse, and every rule whose call could be
/// named in them is kept from claiming the app clean, as for a page not fully read: `!rm -rf {path}`
/// runs a shell command no rule looked at. A few magics that run nothing of the app's own
/// (`NOTEBOOK_SETTINGS`) are only blanked.
pub(super) fn read_notebook(rules: &AstRules, relative: &str, source: &str, scan: &mut AstScan) {
    let notebook = match notebook_python(source) {
        Ok(notebook) => notebook,
        Err(NotebookUnread::Language(language)) => {
            scan.unread_languages.insert(language);
            return;
        }
        Err(NotebookUnread::NotRead(why)) => {
            scan.unread_files.push((relative.to_owned(), why));
            hold_back(rules, scan, "python", relative, None);
            return;
        }
    };
    let read = read_file(rules, "python", relative, &notebook.code);
    scan.files_parsed += 1;
    *scan
        .parsed_by_language
        .entry("python".to_owned())
        .or_default() += 1;
    if read.parse_error || !notebook.unread.is_empty() {
        scan.unparsed_files.push(relative.to_owned());
        let held = if read.parse_error {
            source
        } else {
            &notebook.unread
        };
        hold_back(rules, scan, "python", relative, Some(held));
    }
    scan.findings.extend(read.findings);
    note_broken(scan, read.broken);
}

/// Line magics that change only how the notebook shows or reloads things, and run none of the app's
/// code: blanked, and not counted as unread.
pub(super) const NOTEBOOK_SETTINGS: &[&str] = &[
    "matplotlib",
    "load_ext",
    "reload_ext",
    "autoreload",
    "config",
];

/// A notebook's Python, and the lines in it Python cannot read.
#[derive(Debug, PartialEq)]
pub(super) struct NotebookCode {
    /// The code cells' Python, each line where it is in the notebook, with blank lines between.
    pub(super) code: String,
    /// The `%` and `!` lines and `%%` cells taken out of it, one after another.
    pub(super) unread: String,
}

#[derive(Debug, PartialEq)]
pub(super) enum NotebookUnread {
    /// The notebook's kernel is this language, not Python.
    Language(String),
    /// The notebook could not be read, and why.
    NotRead(String),
}

/// The Python in a notebook's code cells.
///
/// Notebooks as Jupyter saves them list each cell's source a line to a JSON string, one string to a
/// line of the file, so each line is found in the file, in order, and put on that line. When one
/// cannot be (a notebook written on a single line, or by a tool that escapes text differently), the
/// cells are read one after another instead, and a finding's line counts the code cells' lines.
pub(super) fn notebook_python(source: &str) -> Result<NotebookCode, NotebookUnread> {
    let not_read = |why: &str| NotebookUnread::NotRead(why.to_owned());
    let doc: serde_json::Value = serde_json::from_str(source)
        .map_err(|_| not_read("not a notebook `sv` could read: its JSON did not parse"))?;
    let language = doc
        .pointer("/metadata/language_info/name")
        .or_else(|| doc.pointer("/metadata/kernelspec/language"))
        .and_then(|l| l.as_str());
    if let Some(language) = language
        && !language.eq_ignore_ascii_case("python")
    {
        return Err(NotebookUnread::Language(language.to_lowercase()));
    }
    let cells = doc
        .get("cells")
        .and_then(|c| c.as_array())
        .ok_or_else(|| not_read("not a notebook `sv` could read: it has no list of cells"))?;

    // Each code cell's lines, as the notebook stores them (a list of strings, or one string).
    let mut stored: Vec<Vec<String>> = Vec::new();
    for cell in cells {
        if cell.get("cell_type").and_then(|t| t.as_str()) != Some("code") {
            continue;
        }
        let lines = match cell.get("source") {
            Some(serde_json::Value::Array(parts)) => parts
                .iter()
                .map(|p| p.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>(),
            Some(serde_json::Value::String(text)) => {
                Some(text.split_inclusive('\n').map(str::to_owned).collect())
            }
            None => Some(Vec::new()),
            _ => None,
        }
        .ok_or_else(|| not_read("not a notebook `sv` could read: a cell's source is not text"))?;
        stored.push(lines);
    }

    // Each line as Python reads it: the line, or nothing with the line put among the unread.
    let mut unread = String::new();
    let mut python: Vec<Vec<String>> = Vec::new();
    for lines in &stored {
        let first = lines.first().map(|l| l.trim_start()).unwrap_or("");
        let whole_cell_unread = first.starts_with("%%");
        let mut out = Vec::new();
        for line in lines {
            let text = line.strip_suffix('\n').unwrap_or(line);
            let trimmed = text.trim_start();
            let magic = trimmed.starts_with('%') || trimmed.starts_with('!');
            if whole_cell_unread || magic {
                let name = trimmed
                    .trim_start_matches(['%', '!'])
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or("");
                let setting = trimmed.starts_with('%')
                    && !trimmed.starts_with("%%")
                    && NOTEBOOK_SETTINGS.contains(&name);
                if !setting {
                    unread.push_str(text);
                    unread.push('\n');
                }
                out.push(String::new());
            } else {
                out.push(text.to_owned());
            }
        }
        python.push(out);
    }

    // Where each stored line is in the file: its JSON string, found after the one before it.
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(source.match_indices('\n').map(|(i, _)| i + 1))
        .collect();
    let line_of = |at: usize| line_starts.partition_point(|&s| s <= at) - 1;
    let mut placed: Vec<(usize, &str)> = Vec::new();
    let mut cursor = 0;
    let mut last_line = None;
    'place: {
        for (lines, out) in stored.iter().zip(&python) {
            for (line, text) in lines.iter().zip(out) {
                let Ok(encoded) = serde_json::to_string(line) else {
                    break 'place;
                };
                let Some(found) = source[cursor..].find(&encoded) else {
                    break 'place;
                };
                let at = cursor + found;
                let n = line_of(at);
                if last_line.is_some_and(|l| n <= l) {
                    break 'place;
                }
                placed.push((n, text));
                last_line = Some(n);
                cursor = at + encoded.len();
            }
        }
        let mut code = vec![""; line_starts.len()];
        for (n, text) in placed {
            code[n] = text;
        }
        return Ok(NotebookCode {
            code: code.join("\n"),
            unread,
        });
    }
    // One cell after another, with a blank line between.
    let code = python
        .iter()
        .map(|out| out.join("\n"))
        .collect::<Vec<_>>()
        .join("\n\n");
    Ok(NotebookCode { code, unread })
}

/// Whether a `.svelte` or `.vue` page's markup, outside its `<script>` and `<style>` elements and its
/// comments, holds code the template runs. Svelte reads every `{` in its markup as the start of an
/// expression; Vue runs `{{ … }}` and the values of attributes named `@…`, `:…`, and `v-…`. Other
/// pages are left to `html_fragments`. Kept apart from `template_code`, which takes the code out, as
/// a check on it.
pub(super) fn template_holds_code(relative: &str, source: &str) -> bool {
    let lower = relative.to_lowercase();
    if lower.ends_with(".ejs") {
        // Any tag but a comment, `<%#`, or a literal `<%`, written `<%%`.
        static EJS: OnceLock<regex::Regex> = OnceLock::new();
        let ejs = EJS.get_or_init(|| regex::Regex::new(r"<%[^#%]").expect("a fixed pattern"));
        return ejs.is_match(source);
    }
    if lower.ends_with(".astro") {
        let markup = match astro_frontmatter(source) {
            None => source.to_owned(),
            Some(Err(_)) => return true,
            Some(Ok((body, span))) => {
                if !source[body].trim().is_empty() {
                    return true;
                }
                blank_out(source, &[span])
            }
        };
        let Ok(ranges) = outside_code_elements(&markup) else {
            return true;
        };
        // Any `{` but one opening a comment, `{/* … */}`.
        static EXPRESSION: OnceLock<regex::Regex> = OnceLock::new();
        let expression = EXPRESSION.get_or_init(|| {
            regex::Regex::new(r"\{\s*(?:[^/\s]|/[^*]|$)").expect("a fixed pattern")
        });
        return ranges.into_iter().any(|r| expression.is_match(&markup[r]));
    }
    let svelte = lower.ends_with(".svelte");
    if !svelte && !lower.ends_with(".vue") {
        return false;
    }
    let Ok(ranges) = outside_code_elements(source) else {
        return true;
    };
    let markup: String = ranges.into_iter().map(|r| &source[r]).collect();
    if svelte {
        return markup.contains('{');
    }
    static VUE: OnceLock<regex::Regex> = OnceLock::new();
    let vue = VUE.get_or_init(|| {
        regex::Regex::new(r#"\{\{|[\s<]([@:]|v-)[A-Za-z0-9_.:\[\]-]*\s*="#)
            .expect("a fixed pattern")
    });
    vue.is_match(&markup)
}

/// A piece of code a Svelte or Vue template runs, written as a statement the grammar reads, and
/// where in the page it starts.
#[derive(Debug)]
pub(super) struct TemplatePiece {
    pub(super) code: String,
    pub(super) at: usize,
}

/// The code a Svelte or Vue page's template runs.
#[derive(Debug, Default)]
pub(super) struct Template {
    pub(super) pieces: Vec<TemplatePiece>,
    /// Where Svelte's `{…}` sit, braces included.
    pub(super) spans: Vec<std::ops::Range<usize>>,
}

/// The code in a `.svelte` or `.vue` page's template, or why it could not all be taken out; `None`
/// for any other page.
pub(super) fn template_code(relative: &str, source: &str) -> Option<Result<Template, String>> {
    let lower = relative.to_ascii_lowercase();
    if lower.ends_with(".svelte") {
        Some(svelte_template(source))
    } else if lower.ends_with(".vue") {
        Some(vue_template(source))
    } else if lower.ends_with(".astro") {
        Some(astro_template(source))
    } else if lower.ends_with(".ejs") {
        Some(ejs_template(source))
    } else {
        None
    }
}

/// An Astro page's `---` header: where its code is, and where the header is with both fences. `None`
/// for a page with none; an error for a header that is never closed.
#[allow(clippy::type_complexity)]
pub(super) fn astro_frontmatter(
    source: &str,
) -> Option<Result<(std::ops::Range<usize>, std::ops::Range<usize>), String>> {
    let start = source.len() - source.trim_start().len();
    let rest = source[start..].strip_prefix("---")?;
    if !rest.starts_with(['\n', '\r']) {
        return None;
    }
    let body = start + 3;
    let Some(j) = source[body..].find("\n---") else {
        return Some(Err("a `---` header with no `---` to close it".to_owned()));
    };
    let end = body + j;
    Some(Ok((body..end, start..end + 4)))
}

/// The code in an Astro page: its `---` header, read as TypeScript where it is, and every `{…}` in
/// its markup outside its scripts, styles, and comments, which Astro runs as an expression (a `{…}`
/// may hold JSX: `{items.map((i) => <li>{i}</li>)}`). The page's scripts are read by `html_fragments`.
pub(super) fn astro_template(source: &str) -> Result<Template, String> {
    let mut out = Template::default();
    let markup = match astro_frontmatter(source) {
        None => source.to_owned(),
        Some(result) => {
            let (body, span) = result?;
            if !source[body.clone()].trim().is_empty() {
                out.pieces.push(TemplatePiece {
                    code: source[body.clone()].to_owned(),
                    at: body.start,
                });
            }
            out.spans.push(span.clone());
            blank_out(source, &[span])
        }
    };
    let mut next = 0;
    for range in outside_code_elements(&markup)? {
        let mut at = range.start.max(next);
        while at < range.end {
            let Some(i) = markup[at..range.end].find('{') else {
                break;
            };
            let open = at + i;
            let close = closing_brace(&markup, open)
                .ok_or_else(|| "a `{` with no `}` to close it".to_owned())?;
            let inner = source[open + 1..close].trim();
            let comment = inner.starts_with("/*") && inner.ends_with("*/");
            if !inner.is_empty() && !comment {
                let code = match inner.strip_prefix("...") {
                    // A spread of attributes, `<Card {...props} />`.
                    Some(e) => format!("({{...{e}}});"),
                    None => format!("({inner});"),
                };
                out.pieces.push(TemplatePiece { code, at: open + 1 });
            }
            out.spans.push(open..close + 1);
            at = close + 1;
        }
        next = at;
    }
    Ok(out)
}

/// The code in an EJS page's tags, as the one JavaScript program EJS compiles them into, each line
/// where it is in the page: `<% code %>` as it is, `<%= value %>` and `<%- value %>` as the value
/// they write out, and `<%# … %>` not at all. Each tag starts a statement, as in EJS's own output, so
/// `<% if (a) { %> … <% } %>` reads as `if (a) { … }`.
///
/// EJS ends each `<% %>` with a line break, and the program here cannot add lines without moving
/// every line after it, so a `//` comment in one with another tag after it on the same line would
/// hide that tag's code. Such a page is not read in full.
pub(super) fn ejs_template(source: &str) -> Result<Template, String> {
    fn blank(into: &mut String, text: &str) {
        into.extend(text.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
    }
    let mut out = Template::default();
    let mut program = String::with_capacity(source.len());
    let mut any = false;
    let mut comment_open_on = None;
    let line_of = |at: usize| source[..at].matches('\n').count();
    let mut at = 0;
    while let Some(i) = source[at..].find("<%") {
        let open = at + i;
        blank(&mut program, &source[at..open]);
        let after = &source[open + 2..];
        if after.starts_with('%') {
            // `<%%`, a literal `<%` in the page.
            blank(&mut program, "<%%");
            at = open + 3;
            continue;
        }
        if comment_open_on == Some(line_of(open)) {
            return Err(
                "a `//` comment in a `<% %>` with another tag after it on its line".to_owned(),
            );
        }
        let mark = after.chars().next().filter(|c| "=-#_".contains(*c));
        let body_start = open + 2 + mark.map_or(0, |_| 1);
        let Some(j) = source[body_start..].find("%>") else {
            return Err("a `<%` with no `%>` to close it".to_owned());
        };
        let mut body_end = body_start + j;
        // `-%>` and `_%>` trim the white space after the tag.
        if body_end > body_start && source[..body_end].ends_with(['-', '_']) {
            body_end -= 1;
        }
        let close = body_start + j + 2;
        let body = &source[body_start..body_end];
        let opener = &source[open..body_start];
        let closer = &source[body_end..close];
        match mark {
            Some('#') => blank(&mut program, &source[open..close]),
            Some('=') | Some('-') => {
                // `<%=` is three characters: `;(` and a space.
                program.push_str(";( ");
                program.push_str(body);
                program.push(')');
                blank(&mut program, &closer[1..]);
                any = true;
            }
            _ => {
                program.push(';');
                blank(&mut program, &opener[1..]);
                program.push_str(body);
                blank(&mut program, closer);
                any = true;
                comment_open_on = body
                    .rsplit('\n')
                    .next()
                    .filter(|l| l.contains("//"))
                    .map(|_| line_of(close));
            }
        }
        out.spans.push(open..close);
        at = close;
    }
    blank(&mut program, &source[at..]);
    if any {
        out.pieces.push(TemplatePiece {
            code: program,
            at: 0,
        });
    }
    Ok(out)
}

/// Every `{…}` in a Svelte page outside its scripts, styles, and comments: Svelte reads each as an
/// expression or a block (`{#if …}`, `{#each … as …}`, `{@html …}`), in text and attributes alike.
pub(super) fn svelte_template(source: &str) -> Result<Template, String> {
    let mut out = Template::default();
    let mut next = 0;
    for range in outside_code_elements(source)? {
        let mut at = range.start.max(next);
        while at < range.end {
            let Some(i) = source[at..range.end].find('{') else {
                break;
            };
            let open = at + i;
            let close = closing_brace(source, open)
                .ok_or_else(|| "a `{` with no `}` to close it".to_owned())?;
            if let Some(code) = svelte_statements(&source[open + 1..close])? {
                out.pieces.push(TemplatePiece { code, at: open + 1 });
            }
            out.spans.push(open..close + 1);
            at = close + 1;
        }
        next = at;
    }
    Ok(out)
}

/// What one Svelte `{…}` runs, as statements; `None` for one that runs nothing (`{/if}`, `{:else}`).
/// A pattern that names values (`{#each items as item}`) is written as an arrow function's
/// parameters, so it is read where a default value in it could run code.
pub(super) fn svelte_statements(inner: &str) -> Result<Option<String>, String> {
    let t = inner.trim_start();
    // The rest after a block's keyword, when the keyword is followed by a space or nothing.
    let after = |keyword: &str| {
        t.strip_prefix(keyword)
            .filter(|r| r.is_empty() || r.starts_with(char::is_whitespace))
            .map(str::trim)
    };
    if t.starts_with('/') || t.trim_end() == ":else" {
        return Ok(None);
    }
    if let Some(e) = after("#if")
        .or_else(|| after(":else if"))
        .or_else(|| after("#key"))
        .or_else(|| after("@html"))
        .or_else(|| after("@render"))
        .or_else(|| after("@attach"))
    {
        return Ok(Some(format!("({e});")));
    }
    if let Some(rest) = after("#each") {
        let Some((list, binding)) = split_top(rest, " as ") else {
            return Ok(Some(format!("({rest});")));
        };
        let mut code = format!("({list});");
        let (params, key) = match trailing_group(binding) {
            Some((params, key)) => (params, Some(key)),
            None => (binding, None),
        };
        code.push_str(&format!(" (({params}) => 0);"));
        if let Some(key) = key {
            code.push_str(&format!(" ({key});"));
        }
        return Ok(Some(code));
    }
    if let Some(rest) = after("#await") {
        let (promise, pattern) =
            match split_top(rest, " then ").or_else(|| split_top(rest, " catch ")) {
                Some((promise, pattern)) => (promise, pattern.trim()),
                None => (rest, ""),
            };
        let mut code = format!("({promise});");
        if !pattern.is_empty() {
            code.push_str(&format!(" (({pattern}) => 0);"));
        }
        return Ok(Some(code));
    }
    if let Some(pattern) = after(":then").or_else(|| after(":catch")) {
        return Ok((!pattern.is_empty()).then(|| format!("(({pattern}) => 0);")));
    }
    if let Some(declaration) = after("@const") {
        return Ok(Some(format!("const {declaration};")));
    }
    if let Some(e) = after("@debug") {
        return Ok((!e.is_empty()).then(|| format!("({e});")));
    }
    if let Some(snippet) = after("#snippet") {
        return Ok(Some(format!("function {snippet} {{}}")));
    }
    if let Some(e) = t.strip_prefix("...") {
        return Ok(Some(format!("({{...{e}}});")));
    }
    if t.starts_with(['#', ':', '@']) {
        let word: String = t.chars().take_while(|c| !c.is_whitespace()).collect();
        return Err(format!("a `{{{word}` block this does not know"));
    }
    Ok(Some(format!("({inner});")))
}

/// Every directive value and every `{{ … }}` in a Vue page. Vue runs the value of each attribute
/// named `@…` or `v-on:…` as a handler, `v-for`'s as a loop, `#…` and `v-slot`'s as a slot's
/// parameters, and the value of every other `:…`, `.…`, and `v-…` attribute as an expression.
pub(super) fn vue_template(source: &str) -> Result<Template, String> {
    static LANG: OnceLock<regex::Regex> = OnceLock::new();
    let lang = LANG.get_or_init(|| {
        regex::Regex::new(r#"<template\b[^>]*\slang\s*=\s*["']?([a-z0-9-]+)"#)
            .expect("a fixed pattern")
    });
    if let Some(found) = lang.captures(&source.to_ascii_lowercase())
        && &found[1] != "html"
    {
        return Err(format!(
            "a template written in {}, which this does not read",
            &found[1]
        ));
    }
    let mut out = Template::default();
    for attribute in &read_markup(source)?.attributes {
        let name = attribute.name.as_str();
        let directive = name.starts_with(['@', ':', '#', '.']) || name.starts_with("v-");
        if !directive {
            continue;
        }
        if name.contains('[') {
            return Err("a directive whose name is worked out when the page runs".to_owned());
        }
        let (value, unread) = decode_character_references(&source[attribute.value.clone()]);
        if unread {
            return Err("a character reference inside code that this does not decode".to_owned());
        }
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let code = if name.starts_with('@') || name.starts_with("v-on:") {
            format!("(function ($event) {{ {value} ;}});")
        } else if name == "v-for" {
            let (alias, list) = split_top(value, " in ")
                .or_else(|| split_top(value, " of "))
                .ok_or_else(|| "a `v-for` with no `in` or `of`".to_owned())?;
            let alias = alias.trim();
            let alias = alias
                .strip_prefix('(')
                .and_then(|a| a.strip_suffix(')'))
                .unwrap_or(alias);
            format!("(({alias}) => 0); ({list});")
        } else if name.starts_with('#') || name.starts_with("v-slot") {
            format!("(({value}) => 0);")
        } else {
            format!("({value});")
        };
        out.pieces.push(TemplatePiece {
            code,
            at: attribute.value.start,
        });
    }
    for range in outside_code_elements(source)? {
        let mut at = range.start;
        while at < range.end {
            let Some(i) = source[at..range.end].find("{{") else {
                break;
            };
            let open = at + i + 2;
            // Vue's own reading: the expression ends at the first `}}`.
            let close = source[open..]
                .find("}}")
                .map(|j| open + j)
                .ok_or_else(|| "a `{{` with no `}}` after it".to_owned())?;
            let (inner, unread) = decode_character_references(&source[open..close]);
            if unread {
                return Err(
                    "a character reference inside code that this does not decode".to_owned(),
                );
            }
            out.pieces.push(TemplatePiece {
                code: format!("({inner});"),
                at: open,
            });
            at = close + 2;
        }
    }
    out.pieces.sort_by_key(|p| p.at);
    Ok(out)
}

/// The parts of a page outside its `<script>` and `<style>` elements and its comments.
pub(super) fn outside_code_elements(source: &str) -> Result<Vec<std::ops::Range<usize>>, String> {
    // ASCII lowering keeps every byte where it was; every position found is at an ASCII byte.
    let lower = source.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = Vec::new();
    let (mut start, mut at) = (0, 0);
    while let Some(i) = lower[at..].find('<') {
        let open = at + i;
        let rest = &lower[open..];
        let end = if let Some(comment) = rest.strip_prefix("<!--") {
            Some(
                comment
                    .find("-->")
                    .map_or(lower.len(), |j| open + 4 + j + 3),
            )
        } else if let Some(name) = ["script", "style"].into_iter().find(|n| {
            rest[1..].starts_with(n)
                && bytes
                    .get(open + 1 + n.len())
                    .is_none_or(|&b| is_html_space(b) || b == b'>' || b == b'/')
        }) {
            let close = format!("</{name}");
            let Some(j) = rest.find(&close) else {
                return Err(format!("a `<{name}>` with no `</{name}>` after it"));
            };
            Some(
                lower[open + j..]
                    .find('>')
                    .map_or(lower.len(), |k| open + j + k + 1),
            )
        } else {
            None
        };
        match end {
            Some(end) => {
                out.push(start..open);
                start = end;
                at = end;
            }
            None => at = open + 1,
        }
        if at >= lower.len() {
            break;
        }
    }
    out.push(start.min(source.len())..source.len());
    Ok(out)
}

/// Where the `}` that closes the `{` at `open` is, reading the JavaScript between them: braces in a
/// string do not count, and a template string's `${…}` does.
pub(super) fn closing_brace(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    // What is open, innermost last: `{` a brace, `` ` `` a template string.
    let mut stack = vec![b'{'];
    let mut i = open + 1;
    while i < bytes.len() {
        let b = bytes[i];
        if stack.last() == Some(&b'`') {
            match b {
                b'\\' => i += 1,
                b'`' => {
                    stack.pop();
                }
                b'$' if bytes.get(i + 1) == Some(&b'{') => {
                    stack.push(b'{');
                    i += 1;
                }
                _ => {}
            }
        } else {
            match b {
                b'\'' | b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    if i >= bytes.len() {
                        return None;
                    }
                }
                b'`' | b'{' => stack.push(b),
                b'}' => {
                    stack.pop();
                    if stack.is_empty() {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// The text before and after the first `separator` that sits outside every bracket and string.
pub(super) fn split_top<'a>(text: &'a str, separator: &str) -> Option<(&'a str, &'a str)> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            quote @ (b'\'' | b'"' | b'`') => {
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if depth == 0 && text.is_char_boundary(i) && text[i..].starts_with(separator) => {
                return Some((&text[..i], &text[i + separator.len()..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// A Svelte `{#each}` binding's key: the `(…)` it ends with, after a space, and what comes before.
pub(super) fn trailing_group(binding: &str) -> Option<(&str, &str)> {
    let binding = binding.trim_end();
    if !binding.ends_with(')') {
        return None;
    }
    let bytes = binding.as_bytes();
    let mut depth = 0i32;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    let before = &binding[..i];
                    return (before.ends_with(char::is_whitespace) && !before.trim().is_empty())
                        .then(|| (before.trim_end(), &binding[i + 1..binding.len() - 1]));
                }
            }
            _ => {}
        }
    }
    None
}

/// The page with every byte of these spans replaced by `_`, except line breaks, so every position
/// and line number stays where it was.
pub(super) fn blank_out(source: &str, spans: &[std::ops::Range<usize>]) -> String {
    let mut out = String::with_capacity(source.len());
    let mut at = 0;
    for span in spans {
        out.push_str(&source[at..span.start]);
        for c in source[span.clone()].chars() {
            if c == '\n' {
                out.push('\n');
            } else {
                out.extend(std::iter::repeat_n('_', c.len_utf8()));
            }
        }
        at = span.end;
    }
    out.push_str(&source[at..]);
    out
}

/// The pieces as one program, each on the line of the page it came from, so a finding's line is
/// the page's.
pub(super) fn joined(source: &str, pieces: &[TemplatePiece]) -> String {
    let mut code = String::new();
    let mut line = 0;
    for piece in pieces {
        let target = source[..piece.at].matches('\n').count();
        while line < target {
            code.push('\n');
            line += 1;
        }
        code.push_str(&piece.code);
        code.push(' ');
        line += piece.code.matches('\n').count();
    }
    code
}
