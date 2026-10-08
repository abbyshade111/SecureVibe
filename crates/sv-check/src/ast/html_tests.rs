//! `ast.html-from-value` (gap analysis item 11, cross-site scripting): a value put on the page as
//! HTML without escaping. Its own file, so the rule's cases do not land at the end of `tests.rs`.

use super::*;
use std::path::PathBuf;

const RULE: &str = "ast.html-from-value";

fn rules() -> &'static AstRules {
    static RULES: OnceLock<AstRules> = OnceLock::new();
    RULES.get_or_init(|| {
        AstRules::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json"))
            .expect("rules load")
    })
}

/// Whether the rule reports `source`, read as `file`. A file the parser could not read fails the
/// test rather than reading as clean.
fn reported(language: &str, file: &str, source: &str) -> bool {
    let read = read_file(rules(), language, file, source);
    assert!(!read.parse_error, "{file} did not parse: {source}");
    assert!(
        read.broken.is_empty(),
        "a query did not compile: {:?}",
        read.broken
    );
    read.findings.iter().any(|f| f.rule_id == RULE)
}

#[test]
fn a_value_put_on_the_page_as_html_is_reported_and_text_or_an_escaped_value_is_not() {
    #[rustfmt::skip]
    let cases: &[(&str, &str, &str, bool)] = &[
        // React. JSX is read in `.js`, `.jsx`, and `.tsx` files.
        ("javascript", "src/Bio.jsx", "export const Bio = ({ bio }) => <div dangerouslySetInnerHTML={{ __html: bio }} />;", true),
        ("typescript", "src/Bio.tsx", "export const Bio = ({ bio }: P) => <div dangerouslySetInnerHTML={{ __html: bio }} />;", true),
        ("typescript", "src/Bio.tsx", "export const Bio = ({ bio }: P) => <div dangerouslySetInnerHTML={{ __html: marked(bio) }} />;", true),
        ("javascript", "src/Bio.jsx", "export const Bio = () => <div dangerouslySetInnerHTML={{ __html: '<b>Hi</b>' }} />;", false),
        ("typescript", "src/Bio.tsx", "export const Bio = ({ bio }: P) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(marked(bio)) }} />;", false),
        ("typescript", "src/Bio.tsx", "export const Bio = ({ bio }: P) => <div>{bio}</div>;", false),
        ("typescript", "src/Bio.tsx", "export const Bio = ({ bio }: P) => <div title={bio} data-x={{ __html: bio }} />;", false),
        // The browser's own ways in.
        ("javascript", "src/app.js", "el.innerHTML = comment.text;", true),
        ("javascript", "src/app.js", "document.getElementById('out').innerHTML += `<li>${item.name}</li>`;", true),
        ("typescript", "src/app.ts", "el.outerHTML = html;", true),
        ("javascript", "src/app.js", "list.insertAdjacentHTML('beforeend', '<li>' + name + '</li>');", true),
        ("javascript", "src/app.js", "document.write(location.hash.slice(1));", true),
        ("javascript", "src/app.js", "el.innerHTML = '';", false),
        ("javascript", "src/app.js", "el.textContent = comment.text;", false),
        ("javascript", "src/app.js", "el.innerHTML = `<li>${escapeHtml(item.name)}</li>`;", false),
        ("javascript", "src/app.js", "list.insertAdjacentHTML('beforeend', '<li>' + escapeHtml(name) + '</li>');", false),
        ("javascript", "src/app.js", "list.insertAdjacentHTML('beforeend', '<li>' + escapeHtml(name) + '</li>' + note);", true),
        ("javascript", "src/app.js", "const ROW = '<tr></tr>';\nel.innerHTML = ROW;", false),
        // A server sending HTML it joined by hand.
        ("javascript", "server.js", "app.get('/hi', (req, res) => { res.send('<h1>Hello ' + req.query.name + '</h1>'); });", true),
        ("typescript", "server.ts", "app.get('/hi', (req, res) => { res.send(`<h1>Hello ${req.query.name}</h1>`); });", true),
        ("javascript", "server.js", "app.get('/hi', (req, res) => { res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`); });", false),
        ("javascript", "server.js", "app.get('/hi', (req, res) => { res.send({ name: req.query.name }); });", false),
        ("javascript", "server.js", "app.get('/hi', (req, res) => { res.send('Hello ' + req.query.name); });", false),
        ("javascript", "server.js", "socket.send('<b>' + msg + '</b>');", false),
        ("javascript", "server.js", "stream.write('<b>' + msg + '</b>');", false),
        // Python's marks that tell the template not to escape.
        ("python", "app.py", "from markupsafe import Markup\ndef hi():\n    return Markup('<h1>Hello ' + request.args['name'] + '</h1>')\n", true),
        ("python", "app.py", "def hi():\n    return Markup(f\"<h1>Hello {request.args['name']}</h1>\")\n", true),
        ("python", "views.py", "from django.utils.safestring import mark_safe\ndef bio(user):\n    return mark_safe(user.bio)\n", true),
        ("python", "views.py", "def bio(user):\n    return safestring.mark_safe(user.bio)\n", true),
        ("python", "app.py", "def hi():\n    return Markup('<b>{}</b>').format(name)\n", false),
        ("python", "app.py", "def hi():\n    return Markup(f\"<h1>Hello {escape(request.args['name'])}</h1>\")\n", false),
        ("python", "app.py", "def hi():\n    return Markup('<h1>' + escape(name) + '</h1>')\n", false),
        ("python", "views.py", "def bio(user):\n    return mark_safe(bleach.clean(user.bio))\n", false),
        ("python", "app.py", "def page():\n    return Markup(render_template('part.html', name=name))\n", false),
        // Go: a value marked as safe HTML for a template.
        ("go", "main.go", "package main\nfunc bio(u User) template.HTML { return template.HTML(u.Bio) }\n", true),
        ("go", "main.go", "package main\nfunc bio(u User) template.HTML { return template.HTML(\"<b>\" + u.Name + \"</b>\") }\n", true),
        ("go", "main.go", "package main\nfunc bio(u User) template.HTML { return template.HTML(\"<b>\" + template.HTMLEscapeString(u.Name) + \"</b>\") }\n", false),
        ("go", "main.go", "package main\nfunc bio() template.HTML { return template.HTML(\"<b>hi</b>\") }\n", false),
        ("go", "main.go", "package main\nfunc page(w http.ResponseWriter) { t := html.HTML(x); _ = t }\n", false),
        // Ruby: Rails' marks that tell the view not to escape.
        ("ruby", "app/helpers/bio_helper.rb", "def bio(user)\n  raw(user.bio)\nend\n", true),
        ("ruby", "app/helpers/bio_helper.rb", "def bio(user)\n  \"<b>#{user.name}</b>\".html_safe\nend\n", true),
        ("ruby", "app/helpers/bio_helper.rb", "def bio(user)\n  user.bio.html_safe\nend\n", true),
        ("ruby", "app/helpers/bio_helper.rb", "def bio(user)\n  raw(sanitize(user.bio))\nend\n", false),
        ("ruby", "app/helpers/bio_helper.rb", "def bio\n  \"<b>Hi</b>\".html_safe\nend\n", false),
        ("ruby", "app/helpers/bio_helper.rb", "def bio(user)\n  user.html_safe?\nend\n", false),
    ];
    let mut wrong = Vec::new();
    for (language, file, source, expected) in cases {
        if reported(language, file, source) != *expected {
            wrong.push(format!(
                "{file} ({language}): expected {expected}: {source}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_rule_credits_nothing_and_its_finding_cites_output_encoding() {
    let rule = rules()
        .compiled
        .iter()
        .find(|c| c.rule.id == RULE)
        .expect("the rule is in the data file");
    assert!(
        rule.rule.findings_only,
        "finding none must credit nothing: HTML built in one place and sent in another is not read"
    );
    assert_eq!(rule.rule.requirement_ids, ["V1.2.1"]);
    let read = read_file(
        rules(),
        "javascript",
        "src/app.js",
        "el.innerHTML = c.text;",
    );
    let found = read
        .findings
        .iter()
        .find(|f| f.rule_id == RULE)
        .expect("the setup: the rule reports this line");
    assert_eq!(found.location.line, 1);
    assert_eq!(found.requirement_ids, ["V1.2.1"]);
}

/// The JSX patterns are added for `.tsx` files only: TypeScript's own grammar has none, so in the
/// `typescript` query they would stop the rule reading every `.ts` file.
#[test]
fn a_jsx_query_is_added_to_tsx_files_and_a_ts_file_is_still_read() {
    let source = "el.innerHTML = html;";
    assert!(reported("typescript", "src/app.ts", source));
    assert!(reported("typescript", "src/app.tsx", source));
    let jsx = "export const B = ({ b }: P) => <div dangerouslySetInnerHTML={{ __html: b }} />;";
    assert!(reported("typescript", "src/B.tsx", jsx));

    // A jsxQuery with no typescript query to add it to is refused at load.
    let dir = std::env::temp_dir().join(format!("sv-jsx-query-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("rules.json");
    std::fs::write(
        &path,
        r#"{"rules": [{"id": "x", "title": "", "severity": "low", "confidence": "low",
            "requirementIds": [], "cwe": [], "description": "", "impact": "", "fix": "",
            "queries": {"javascript": "(identifier) @hit"},
            "jsxQuery": "(jsx_attribute) @hit"}]}"#,
    )
    .unwrap();
    let refused = AstRules::load(&path).err().map(|e| format!("{e:#}"));
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        refused
            .as_deref()
            .is_some_and(|e| e.contains("jsxQuery and no typescript query")),
        "{refused:?}"
    );
}
