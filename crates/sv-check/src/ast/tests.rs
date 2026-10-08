//! The tests of `ast.rs` that were `mod tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

#[test]
fn a_pattern_of_names_is_read_as_its_names_and_anything_else_as_more() {
    let names = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        calls_named("^(system|popen)$"),
        Some((names(&["system", "popen"]), false))
    );
    assert_eq!(calls_named("^Command$"), Some((names(&["Command"]), false)));
    assert_eq!(
        calls_named("^(query|\\$queryRawUnsafe)$"),
        Some((names(&["query", "$queryRawUnsafe"]), false))
    );
    assert_eq!(
        calls_named("^(Command|\"(/bin/)?(sh|bash)\")$"),
        Some((names(&["Command"]), true))
    );
    assert_eq!(calls_named("^(EVP_des\\w*|DES_\\w+)$"), None);
    // Two groups, not one: neither half is read as a name.
    assert_eq!(calls_named("^(a)|(b)$"), None);
    assert_eq!(calls_named("system"), None);
}

use super::*;
use std::path::PathBuf;

#[test]
fn astro_and_ejs_code_is_read_at_its_own_lines() {
    // ADR-054, Later: the code in an Astro page and in an EJS page is read, each `eval` on line 4
    // of its page, found there, with the page fully read.
    let rules = rules();
    let read = |name: &str, source: &str| {
        let mut scan = AstScan::default();
        read_page(rules, name, source, &mut scan);
        scan
    };
    let head = "---\nimport Card from './Card.astro';\nconst items: string[] = [];\n";
    // A header two lines long with its closing fence, so the markup starts on line 4.
    let short = "---\nconst items: string[] = [];\n---\n";
    for (name, page) in [
            // The header, as TypeScript.
            (
                "Header.astro",
                format!("{head}const x: string = eval(Astro.url.search);\n---\n<p>{{x}}</p>\n"),
            ),
            // A `{…}` in the markup, with JSX in it.
            (
                "Expression.astro",
                format!("{short}<ul>{{items.map((i) => <li>{{eval(i)}}</li>)}}</ul>\n"),
            ),
            ("Attribute.astro", format!("{short}<a href={{eval(next)}}>x</a>\n")),
            ("Spread.astro", format!("{short}<Card {{...eval(p)}} />\n")),
            // A script, which Astro compiles as TypeScript.
            (
                "Script.astro",
                "<p>x</p>\n<script>\n  const n: number = 1;\n  eval(location.hash);\n</script>\n"
                    .to_owned(),
            ),
            // No header at all.
            ("Bare.astro", "<main>\n  <h1>Hi</h1>\n</main>\n{eval(x)}\n".to_owned()),
            ("Code.ejs", "<html>\n<body>\n<p>x</p>\n<% eval(code) %>\n</body>\n".to_owned()),
            ("Escaped.ejs", "<ul>\n<li>a</li>\n<li>b</li>\n<%= eval(name) %>\n</ul>\n".to_owned()),
            ("Raw.ejs", "<ul>\n<li>a</li>\n<li>b</li>\n<%- eval(body) -%>\n</ul>\n".to_owned()),
            // One program across the tags, as EJS compiles it.
            (
                "Block.ejs",
                "<% if (user) { %>\n  <p>Hi</p>\n<% } else { %>\n  <p><%= eval(guest) %></p>\n<% } %>\n"
                    .to_owned(),
            ),
            (
                "Loop.ejs",
                "<ul>\n<% items.forEach(function (item) { %>\n  <li><%= item %></li>\n<% eval(item) }) %>\n</ul>\n"
                    .to_owned(),
            ),
            // A tag in a page's script is blanked there, and the script around it read.
            (
                "Script.ejs",
                "<p>x</p>\n<script>\n  var data = <%- JSON.stringify(data) %>;\n  eval(location.hash);\n</script>\n"
                    .to_owned(),
            ),
        ] {
            let scan = read(name, &page);
            assert!(scan.unparsed_files.is_empty(), "{name}: {page}");
            assert!(scan.unread_languages.is_empty(), "{name}: {page}");
            let found: Vec<_> = scan
                .findings
                .iter()
                .map(|f| (f.rule_id.as_str(), f.location.line))
                .collect();
            assert_eq!(found, [("ast.dynamic-code-execution", 4)], "{name}: {page}");
        }

    // What runs nothing is read as nothing: an EJS comment, a literal `<%`, and an Astro comment.
    for (name, page) in [
        ("Comment.ejs", "<%# eval(x) %>\n<p><%%= not code %></p>\n"),
        ("Comment.astro", "---\n---\n<p>{/* eval(x) */}</p>\n"),
        (
            "Plain.astro",
            "---\nconst title = 'Hi';\n---\n<h1>{title}</h1>\n",
        ),
        (
            "Plain.ejs",
            "<h1><%= title %></h1>\n<% if (a) { %>x<% } %>\n",
        ),
    ] {
        let scan = read(name, page);
        assert!(scan.unparsed_files.is_empty(), "{name}: {page}");
        assert!(scan.unread_languages.is_empty(), "{name}: {page}");
        assert!(scan.findings.is_empty(), "{name}: {:?}", scan.findings);
    }

    // What cannot all be taken out leaves the page not fully read.
    for (name, page) in [
        ("Open.ejs", "<p><% eval(x) </p>\n"),
        // EJS ends the first tag's line, so its comment does not hide `eval`; here it would.
        ("Comment.ejs", "<% let a = 1 // note %><% eval(x) %>\n"),
        ("Open.astro", "---\nconst a = 1;\n<p>{a}</p>\n"),
        ("Brace.astro", "---\n---\n<p>{eval(x)</p>\n"),
    ] {
        let scan = read(name, page);
        assert_eq!(scan.unparsed_files, [name], "{name}: {page}");
    }
}

#[test]
fn template_code_is_read_as_code() {
    // H2 of the deep review: `on:click={() => eval(code)}` in a Svelte page gave no finding, and
    // the page counted as read. Each place a Svelte or Vue template runs code, holding `eval`, on
    // line 4 of the page; each must be found there, with the page fully read.
    let rules = rules();
    let read = |name: &str, source: &str| {
        let mut scan = AstScan::default();
        read_page(rules, name, source, &mut scan);
        scan
    };
    let script = "<script>\n  let count = 0;\n</script>\n";
    let ts = "<script lang=\"ts\">\n  let count: number = 0;\n</script>\n";
    let vue = |markup: &str| format!("{script}<template>{markup}\n</template>\n");
    for (name, page) in [
        (
            "Click.svelte",
            format!("{script}<button on:click={{() => eval(code)}}>Go</button>\n"),
        ),
        // Svelte 5's handlers are plain attributes; the space in the arrow must not end it.
        (
            "Click5.svelte",
            format!("{script}<button onclick={{() => eval(code)}}>Go</button>\n"),
        ),
        ("Text.svelte", format!("{script}<p>{{eval(note)}}</p>\n")),
        (
            "Quoted.svelte",
            format!("{script}<p class=\"note {{eval(kind)}}\">x</p>\n"),
        ),
        (
            "If.svelte",
            format!("{script}{{#if eval(x)}}<p>x</p>{{/if}}\n"),
        ),
        (
            "ElseIf.svelte",
            format!("{script}{{#if a}}a{{:else if eval(x)}}b{{/if}}\n"),
        ),
        (
            "Each.svelte",
            format!("{script}{{#each eval(list) as item}}<p>{{item}}</p>{{/each}}\n"),
        ),
        (
            "Key.svelte",
            format!("{script}{{#each list as item, i (eval(item))}}<p>{{i}}</p>{{/each}}\n"),
        ),
        (
            "Await.svelte",
            format!("{script}{{#await eval(p) then v}}<p>{{v}}</p>{{/await}}\n"),
        ),
        ("Html.svelte", format!("{script}{{@html eval(body)}}\n")),
        ("Const.svelte", format!("{script}{{@const x = eval(y)}}\n")),
        (
            "Spread.svelte",
            format!("{script}<a {{...eval(p)}}>x</a>\n"),
        ),
        (
            "Typed.svelte",
            format!("{ts}<p>{{eval(note as string)}}</p>\n"),
        ),
        (
            "Click.vue",
            vue("<button @click=\"eval(code)\">Go</button>"),
        ),
        (
            "On.vue",
            vue("<button v-on:click=\"eval(code)\">Go</button>"),
        ),
        ("Bind.vue", vue("<a :href=\"eval(next)\">Back</a>")),
        ("If.vue", vue("<p v-if=\"eval(x)\">x</p>")),
        ("For.vue", vue("<p v-for=\"(item, i) in eval(list)\">x</p>")),
        ("Html.vue", vue("<p v-html=\"eval(body)\"></p>")),
        ("Text.vue", vue("<p>{{ eval(note) }}</p>")),
        (
            "Escaped.vue",
            vue("<p :title=\"eval(&quot;x&quot; + y)\">x</p>"),
        ),
        ("Slot.vue", vue("<p #item=\"{ x = eval(y) }\">x</p>")),
    ] {
        let scan = read(name, &page);
        assert!(scan.unparsed_files.is_empty(), "{name}: {page}");
        assert!(scan.unread_languages.is_empty(), "{name}: {page}");
        let found: Vec<_> = scan
            .findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.location.line))
            .collect();
        assert_eq!(found, [("ast.dynamic-code-execution", 4)], "{name}: {page}");
    }

    // Template code with nothing to find is read too, braces in strings and template strings
    // included, and a page of markup has nothing taken out of it.
    for (name, page) in [
        (
            "Strings.svelte",
            format!("{script}<p title={{\"}}\"}}>{{`a ${{ {{b: 1}}.b }} }}`}}</p>\n"),
        ),
        (
            "Plain.svelte",
            format!("{script}<h1>Notes</h1>\n<style>h1 {{ color: red }}</style>\n"),
        ),
        (
            "Comment.svelte",
            format!("{script}<!-- {{ not code -->\n<p>x</p>\n"),
        ),
        ("Plain.vue", vue("<a href=\"/x\" class=\"b\">x</a>")),
        (
            "Obj.vue",
            vue("<p :class=\"{ a: b, c: d }\" @click=\"n++; go()\">x</p>"),
        ),
        ("index.html", "<p>Use {name} here</p>\n".to_owned()),
    ] {
        let scan = read(name, &page);
        assert!(
            scan.unparsed_files.is_empty() && scan.findings.is_empty(),
            "{name}: {:?} {:?}",
            scan.unparsed_files,
            scan.findings
        );
    }

    // What cannot be taken out, or is not code the grammar reads, leaves the page named as not
    // fully read, and holds back each rule whose call is named in it. Its script is still read.
    for (name, page) in [
        ("Open.svelte", format!("{script}<p>{{eval(x)</p>\n")),
        ("Unknown.svelte", format!("{script}{{#nope eval(x)}}\n")),
        ("Garbled.svelte", format!("{script}<p>{{eval(x) y}}</p>\n")),
        ("Garbled.vue", vue("<p :title=\"eval(x) y\">x</p>")),
        ("Dynamic.vue", vue("<p :[eval(k)]=\"v\">x</p>")),
        (
            "Pug.vue",
            format!("{script}<template lang=\"pug\">\np(@click=\"eval(x)\")\n</template>\n"),
        ),
        ("OpenText.vue", vue("<p>{{ eval(x) </p>")),
        // One piece read and one not: the page is still not fully read.
        (
            "Mixed.svelte",
            format!("{script}<p>{{count}}</p><p>{{eval(x) y}}</p>\n"),
        ),
        // Vue reads a `<textarea>`'s body as text, so nothing is taken out of it, while the older
        // test of the page sees an `@click`. While the two disagree the page is not counted read.
        (
            "Textarea.vue",
            vue("<textarea><b @click=\"eval(x)\"></b></textarea>"),
        ),
    ] {
        let scan = read(name, &page);
        assert_eq!(scan.unparsed_files, [name], "{name}: {page}");
        assert!(
            scan.held_back.contains_key("ast.dynamic-code-execution"),
            "{name}: {:?}",
            scan.held_back
        );
        assert!(scan.files_parsed >= 1, "{name}: its script is still read");
    }
}

/// The rules, loaded once for the whole test binary: each query is compiled the first time a
/// test needs it and kept, where loading them anew for every case made the 46 tests here spend
/// most of their time compiling the same queries again (8 October 2026).
fn rules() -> &'static AstRules {
    static RULES: std::sync::OnceLock<AstRules> = std::sync::OnceLock::new();
    RULES.get_or_init(|| {
        AstRules::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json"))
            .expect("rules load")
    })
}

fn scan(language: &str, source: &str) -> Vec<Finding> {
    scan_file(rules(), language, &format!("src/app.{language}"), source)
}

/// The one finding `rule` makes in `source`, read as `file`.
fn only_finding(rule: &str, language: &str, file: &str, source: &str) -> Finding {
    let found: Vec<Finding> = scan_file(rules(), language, file, source)
        .into_iter()
        .filter(|f| f.rule_id == rule)
        .collect();
    assert_eq!(found.len(), 1, "{rule} in {source}: {found:?}");
    found.into_iter().next().unwrap()
}

#[test]
fn a_path_made_of_the_app_s_own_stored_values_says_so() {
    // A1's leftover 2, from the owner's study: an attachment's file name is the id the app gave
    // it when it was saved, read back from the database. The finding stays, and says so; a path
    // with anything else in it does not.
    let rule = "ast.file-path-from-value";
    const SAYS: &str = "read back from the app's own database";
    let head = "import os\nfrom flask import request, send_file\nUPLOAD_DIR = 'uploads'\n";
    let read_back = [
        "def get(aid):\n    row = db().execute('SELECT id FROM files WHERE id = ?', (aid,)).fetchone()\n    return send_file(os.path.join(UPLOAD_DIR, row['id']))\n",
        "def get(aid):\n    row = db().execute('SELECT id FROM files WHERE id = ?', (aid,)).fetchone()\n    path = os.path.join(UPLOAD_DIR, row['id'])\n    return send_file(path)\n",
        "def all_files():\n    for row in db().execute('SELECT id FROM files').fetchall():\n        open(os.path.join(UPLOAD_DIR, f\"{row['id']}.pdf\"))\n",
        "def get(aid):\n    attachment = Attachment.query.get_or_404(aid)\n    return send_file(os.path.join(UPLOAD_DIR, attachment.stored_name))\n",
    ];
    for body in read_back {
        let finding = only_finding(rule, "python", "app.py", &format!("{head}{body}"));
        assert!(
            finding
                .description
                .contains("read back from the app's own database"),
            "{body}: {}",
            finding.description
        );
    }
    let typed = [
        // What a person sent.
        "def get():\n    return send_file(os.path.join(UPLOAD_DIR, request.args['f']))\n",
        // A stored value and what a person sent, together.
        "def get(aid):\n    row = db().execute('SELECT id FROM files WHERE id = ?', (aid,)).fetchone()\n    return send_file(os.path.join(UPLOAD_DIR, row['id'], request.args['f']))\n",
        // A name set from the database in one place and from the request in another.
        "def get(aid):\n    row = db().execute('SELECT id FROM files').fetchone()\n    return send_file(os.path.join(UPLOAD_DIR, row['id']))\n\ndef put():\n    row = request.get_json()\n    open(os.path.join(UPLOAD_DIR, row['id']), 'w')\n",
        // `get` is a dictionary's, not a database's.
        "def get():\n    name = request.args.get('f')\n    return send_file(os.path.join(UPLOAD_DIR, name))\n",
    ];
    for body in typed {
        let found: Vec<Finding> = scan_file(rules(), "python", "app.py", &format!("{head}{body}"))
            .into_iter()
            .filter(|f| f.rule_id == rule)
            .collect();
        assert!(!found.is_empty(), "{body}: the control found nothing");
        assert!(
            found.iter().all(|f| !f.description.contains(SAYS)),
            "{body}: {found:?}"
        );
    }
    // The same in JavaScript, through an ORM's read.
    let finding = only_finding(
        rule,
        "javascript",
        "app.js",
        "const path = require('path');\nconst UPLOAD_DIR = 'uploads';\napp.get('/f/:id', async (req, res) => {\n  const file = await prisma.attachment.findUnique({ where: { id: req.params.id } });\n  res.sendFile(path.join(UPLOAD_DIR, file.storedName));\n});\n",
    );
    assert!(finding.description.contains(SAYS), "{finding:?}");
}

#[test]
fn a_destination_every_caller_fills_with_the_apps_own_route_says_so() {
    // family-hub item 7: `redirect(destination)`, where every caller passed
    // `url_for("home.index")`, and the AI tool removed the parameter to clear the finding. The
    // finding stays in every case; only what it says changes.
    const SAYS: &str = "passes the app's own route or a path on this site";
    let scan_app = |name: &str, files: &[(&str, &str)]| {
        let dir =
            std::env::temp_dir().join(format!("sv-ast-callers-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        for (file, text) in files {
            std::fs::write(dir.join(file), text).unwrap();
        }
        let scan = scan_dir(rules(), &dir);
        std::fs::remove_dir_all(&dir).ok();
        let found: Vec<Finding> = scan
            .findings
            .into_iter()
            .filter(|f| f.rule_id == "ast.open-redirect")
            .collect();
        assert_eq!(found.len(), 1, "{name}: the finding stays: {found:?}");
        found.into_iter().next().unwrap()
    };
    let signin = "from flask import redirect, session\n\n\
                      def finish_sign_in(user, destination):\n    \
                      session['uid'] = user.id\n    \
                      return redirect(destination)\n";
    let views = |calls: &str| {
        format!("from flask import url_for, request\nfrom signin import finish_sign_in\n\n{calls}")
    };

    // Every caller passes the app's own route, by position or by name: said, with each call.
    let finding = scan_app(
        "all-own",
        &[
            ("signin.py", signin),
            (
                "views.py",
                &views(
                    "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n\n\
                         def join(user):\n    return finish_sign_in(user, destination='/welcome')\n",
                ),
            ),
        ],
    );
    assert!(
        finding.description.contains(SAYS),
        "{}",
        finding.description
    );
    for part in [
        "`destination`, a parameter of `finish_sign_in`",
        "each of its 2 calls",
        "`views.py` line 5",
        "`views.py` line 8",
        "is not a fix",
    ] {
        assert!(
            finding.description.contains(part),
            "{part}: {}",
            finding.description
        );
    }

    // A default the callers leave alone, and a method called on its object.
    let defaulted = scan_app(
        "default",
        &[(
            "app.py",
            "from flask import redirect, url_for\n\n\
                 def finish(user, destination=url_for('home.index')):\n    return redirect(destination)\n\n\
                 def login(user):\n    return finish(user)\n",
        )],
    );
    assert!(
        defaulted.description.contains("its one call"),
        "{}",
        defaulted.description
    );
    let method = scan_app(
        "method",
        &[(
            "app.py",
            "from flask import redirect, url_for\n\n\
                 class Auth:\n    def go(self, destination):\n        return redirect(destination)\n\n\
                 def login(auth):\n    return auth.go(url_for('home.index'))\n",
        )],
    );
    assert!(method.description.contains(SAYS), "{}", method.description);

    // Not said: a caller passes what came in the request; the function is handed to something
    // else to call; nobody calls it; it gives the parameter another value; a call spreads its
    // arguments; the parameter can only be passed by name and the caller leaves it out.
    for (name, files) in [
            (
                "one-from-request",
                vec![
                    ("signin.py", signin.to_owned()),
                    (
                        "views.py",
                        views(
                            "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n\n\
                             def back(user):\n    return finish_sign_in(user, request.args.get('next'))\n",
                        ),
                    ),
                ],
            ),
            (
                "handed-on",
                vec![
                    ("signin.py", signin.to_owned()),
                    (
                        "views.py",
                        views(
                            "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n\n\
                             HOOKS = [finish_sign_in]\n",
                        ),
                    ),
                ],
            ),
            ("no-callers", vec![("signin.py", signin.to_owned())]),
            (
                "reassigned",
                vec![
                    (
                        "signin.py",
                        signin.replace(
                            "    return redirect(destination)",
                            "    destination = request.args.get('next') or destination\n    \
                             return redirect(destination)",
                        ),
                    ),
                    (
                        "views.py",
                        views(
                            "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n",
                        ),
                    ),
                ],
            ),
            (
                "spread",
                vec![
                    ("signin.py", signin.to_owned()),
                    (
                        "views.py",
                        views(
                            "def login(user):\n    return finish_sign_in(user, url_for('home.index'))\n\n\
                             def other(pair):\n    return finish_sign_in(*pair)\n",
                        ),
                    ),
                ],
            ),
            // The default is the app's own route, but a spread may fill the parameter with anything.
            (
                "spread-over-default",
                vec![(
                    "app.py",
                    "from flask import redirect, url_for\n\n\
                     def finish(user, destination=url_for('home.index')):\n    return redirect(destination)\n\n\
                     def login(args):\n    return finish(*args)\n"
                        .to_owned(),
                )],
            ),
            (
                "by-name-only",
                vec![(
                    "app.py",
                    "from flask import redirect, url_for\n\n\
                     def finish(user, *, destination):\n    return redirect(destination)\n\n\
                     def login(user):\n    return finish(user, url_for('home.index'))\n"
                        .to_owned(),
                )],
            ),
        ] {
            let files: Vec<(&str, &str)> = files.iter().map(|(f, t)| (*f, t.as_str())).collect();
            let finding = scan_app(name, &files);
            assert!(
                !finding.description.contains(SAYS),
                "{name}: {}",
                finding.description
            );
        }
}

#[test]
fn a_destination_that_passed_through_a_checking_function_names_it() {
    // A1's leftover 3: `safe_next` sends anything but a path on this site to the home page. No
    // rule can read every such function; one named so usually does what it says, so the finding
    // stays and names it.
    let rule = "ast.open-redirect";
    const SAYS: &str = "first, whose name says it checks it";
    let head = "from flask import redirect, request\n";
    let checked = [
        "def done():\n    return redirect(safe_next(request.args.get('next')))\n",
        "def done():\n    next_url = safe_next(request.args.get('next'))\n    return redirect(next_url)\n",
    ];
    for body in checked {
        let finding = only_finding(rule, "python", "app.py", &format!("{head}{body}"));
        assert!(
            finding
                .description
                .contains("passed through `safe_next` first"),
            "{body}: {}",
            finding.description
        );
    }
    // Checked by one function in one place and another in another: both are named.
    let both = "def done():\n    next_url = safe_next(request.args.get('next'))\n    return redirect(next_url)\n\ndef other():\n    next_url = clean_url(request.args.get('next'))\n    return redirect(next_url)\n";
    let found: Vec<Finding> = scan_file(rules(), "python", "app.py", &format!("{head}{both}"))
        .into_iter()
        .filter(|f| f.rule_id == rule)
        .collect();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found.iter().all(|f| f
            .description
            .contains("passed through `clean_url` or `safe_next` first")),
        "{found:?}"
    );
    let unchecked = [
        "def done():\n    return redirect(request.args.get('next'))\n",
        // Checked in one place and not in another: which one reaches the call is not known.
        "def done():\n    next_url = safe_next(request.args.get('next'))\n    return redirect(next_url)\n\ndef other():\n    next_url = request.args.get('next')\n    return redirect(next_url)\n",
        // A function named for something else.
        "def done():\n    return redirect(build_url(request.args.get('next')))\n",
    ];
    for body in unchecked {
        let found: Vec<Finding> = scan_file(rules(), "python", "app.py", &format!("{head}{body}"))
            .into_iter()
            .filter(|f| f.rule_id == rule)
            .collect();
        assert!(!found.is_empty(), "{body}: the control found nothing");
        assert!(
            found.iter().all(|f| !f.description.contains(SAYS)),
            "{body}: {found:?}"
        );
    }
    let finding = only_finding(
        rule,
        "javascript",
        "app.js",
        "app.get('/done', (req, res) => {\n  res.redirect(isSafeRedirect(req.query.next));\n});\n",
    );
    assert!(
        finding
            .description
            .contains("passed through `isSafeRedirect` first"),
        "{finding:?}"
    );
}

fn ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

#[test]
fn the_words_in_a_file_rule_out_only_what_a_name_pattern_can_match() {
    let words: Vec<&str> =
        names_in("x = a.eval(q)\nclickhouse-client --query \"$Q\" && ok? go!").collect();
    for w in [
        "x",
        "a",
        "eval",
        "q",
        "clickhouse-client",
        "clickhouse",
        "client",
        "query",
        "$Q",
        "ok?",
        "go!",
    ] {
        assert!(words.contains(&w), "{w}: {words:?}");
    }
    assert!(names_only("^(eval|Function)$"));
    assert!(names_only("^(query|\\$queryRawUnsafe)$"));
    for wider in [
        "^(Command|\"(/bin/|/usr/bin/)?(sh|bash)\")$",
        "^(cat|\\.)$",
        "(^|\\.)(pbkdf2_hmac)$",
        "(^|::)(pbkdf2)$",
        "^ev.l$",
        "^[a-z]+$",
        "^exists\\?$",
    ] {
        assert!(!names_only(wider), "{wider}");
    }
    // The real rules: most name patterns are words, so a broken file holds back only what it
    // names; the shell's are not, and are always held back.
    let rules = rules();
    let by_rule = |id: &str, language: &str| {
        let c = rules.compiled.iter().find(|c| c.rule.id == id).unwrap();
        names_only(c.function[language].as_str())
    };
    assert!(by_rule("ast.dynamic-code-execution", "javascript"));
    assert!(by_rule("ast.sql-built-by-hand", "typescript"));
    assert!(by_rule("ast.sql-built-by-hand", "python"));
    assert!(!by_rule("ast.shell-command", "shell"));
    assert!(!by_rule("ast.weak-password-key-derivation", "python"));
}

#[test]
fn every_query_in_the_data_file_compiles() {
    // A query tree-sitter cannot compile is a rule that silently never fires, which looks exactly
    // like a rule finding nothing. Queries compile on first use, so loading proves nothing about
    // them; this compiles every one, in every language, so a rule written wrong fails here and
    // not on the first app in that language.
    let rules = rules();
    assert!(rules.len() >= 4, "only {} rules loaded", rules.len());
    assert!(rules.languages().contains("python"));
    rules.compile_all().expect("every query compiles");
}

#[test]
fn a_query_that_will_not_compile_stops_the_rule_claiming_a_clean_result() {
    // Loading accepts it, because compiling happens on first use. Meeting a Python file then
    // names the rule as one that could not run, and the clean-result gate stays shut.
    let rules = rules_from(ONE_RULE).expect("loads: nothing checks the query text at load");
    assert!(rules.compile_all().is_err());
    let read = read_file(&rules, "python", "src/app.py", "x = 1\n");
    assert_eq!(read.broken.len(), 1, "{:?}", read.broken);
    assert_eq!(read.broken[0].rule_id, "test.rule");
    assert_eq!(read.broken[0].language, "python");
    assert!(read.findings.is_empty());

    let dir = std::env::temp_dir().join(format!("sv-ast-broken-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "x = 1\n").unwrap();
    std::fs::write(dir.join("b.py"), "y = 2\n").unwrap();
    let scan = scan_dir(&rules, &dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(scan.files_parsed, 2);
    assert_eq!(
        scan.broken_queries.len(),
        1,
        "named once, not once per file"
    );
    assert!(scan.verified.is_empty(), "{:?}", scan.verified);
}

/// Writes a rule file to a scratch path so load-time refusals can be exercised.
fn rules_from(json: &str) -> anyhow::Result<AstRules> {
    let dir = std::env::temp_dir().join(format!("sv-ast-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("rules-{}.json", json.len()));
    std::fs::write(&path, json).unwrap();
    let loaded = AstRules::load(&path);
    std::fs::remove_file(&path).ok();
    loaded
}

const ONE_RULE: &str = r#"{"rules":[{
        "id":"test.rule","title":"t","severity":"high","confidence":"high",
        "requirementIds":[],"cwe":[],"description":"d","impact":"i","fix":"f",
        "queries":{"python":"QUERY"}}]}"#;

#[test]
fn a_query_using_a_text_predicate_is_refused_at_load() {
    // The predicate that started this: tree-sitter's Rust binding parses `#match?` and then does
    // not apply it, so a rule written with one matches every call in the file while looking exactly
    // right. Every rule here did that, and the tests caught it only because they asserted what was
    // NOT a finding. Refusing the query is what stops it coming back.
    let refused = rules_from(&ONE_RULE.replace(
        "QUERY",
        "(call function: (identifier) @fn) @hit (#match? @fn \\\"^eval$\\\")",
    ));
    let error = match refused {
        Ok(_) => panic!("a text predicate must be refused"),
        Err(e) => format!("{e:#}"),
    };
    assert!(error.contains("does not apply"), "{error}");
}

#[test]
fn a_rule_naming_a_language_with_no_grammar_is_refused_at_load() {
    // Quietly dropping it would leave a rule that claims to cover a language and never runs.
    // Objective-C stands in for that here. This test has named Ruby, then C#, then C++, each until
    // the language got a grammar, which is the right way round for a test like this to break.
    let refused = rules_from(&ONE_RULE.replace("\"python\"", "\"objc\""));
    let error = match refused {
        Ok(_) => panic!("an unknown language must be refused"),
        Err(e) => format!("{e:#}"),
    };
    assert!(error.contains("no grammar"), "{error}");
}

#[test]
fn a_query_tree_sitter_cannot_compile_is_refused_by_compile_all() {
    let rules = rules_from(&ONE_RULE.replace("QUERY", "(this is not a query"))
        .expect("loading reads the text; compiling waits for a file in that language");
    let error = match rules.compile_all() {
        Ok(_) => panic!("a broken query must be refused"),
        Err(e) => format!("{e:#}"),
    };
    assert!(error.contains("cannot compile"), "{error}");
    assert!(error.contains("test.rule"), "{error}");
}

fn one_rule(extra: &str) -> String {
    format!(
        r#"{{"rules": [{{"id": "t", "title": "t", "severity": "high", "confidence": "high",
                "requirementIds": ["V1.3.2"], "cwe": [], "description": "", "impact": "", "fix": "",
                "queries": {{"python": "(call) @hit"}} {extra} }}]}}"#
    )
}

#[test]
fn nothing_to_find_is_refused_beside_a_query_without_a_reason_or_without_a_grammar() {
    let both = one_rule(r#", "nothingToFind": {"python": "Python has no such thing."}"#);
    let err = rules_from(&both).err().expect("refused").to_string();
    assert!(err.contains("also says there is nothing to find"), "{err}");

    let no_reason = one_rule(r#", "nothingToFind": {"go": "  "}"#);
    let err = rules_from(&no_reason).err().expect("refused").to_string();
    assert!(err.contains("without saying why"), "{err}");

    let no_grammar = one_rule(r#", "nothingToFind": {"objc": "Objective-C has none."}"#);
    let err = rules_from(&no_grammar).err().expect("refused").to_string();
    assert!(err.contains("no grammar"), "{err}");

    let fine = one_rule(r#", "nothingToFind": {"go": "Go has no eval."}"#);
    assert!(rules_from(&fine).is_ok());
}

#[test]
fn a_pattern_for_a_language_the_rule_has_no_query_in_is_refused_at_load() {
    // It would never run, and the rule would read as if it had been taught that language.
    let refused = rules_from(
        &ONE_RULE
            .replace(
                "\"queries\"",
                "\"argumentPatterns\":{\"go\":\"md5\"},\"queries\"",
            )
            .replace("QUERY", "(call) @hit"),
    );
    let error = match refused {
        Ok(_) => panic!("a pattern with no query must be refused"),
        Err(e) => format!("{e:#}"),
    };
    assert!(error.contains("no go query"), "{error}");
}

#[test]
fn a_figure_for_a_named_hash_is_refused_where_the_rule_has_no_query_or_an_unusable_pattern() {
    let without_query = rules_from(&one_rule(
        r#", "argumentPatternsByHash": {"go": {"sha256": "^1$"}}"#,
    ));
    let error = format!("{:#}", without_query.err().expect("no go query"));
    assert!(error.contains("no go query"), "{error}");
    let unusable = rules_from(&one_rule(
        r#", "argumentPatternsByHash": {"python": {"sha256": "("}}"#,
    ));
    let error = format!("{:#}", unusable.err().expect("an unusable pattern"));
    assert!(error.contains("unusable argumentPatternsByHash"), "{error}");
    // And a usable one loads, so the two refusals above are about what they say.
    assert!(
        rules_from(&one_rule(
            r#", "argumentPatternsByHash": {"python": {"sha256": "^1$"}}"#
        ))
        .is_ok()
    );
}

#[test]
fn python_eval_of_a_request_value_is_found() {
    let findings = scan(
        "python",
        "from flask import request\n\ndef run():\n    return eval(request.args['code'])\n",
    );
    assert!(
        ids(&findings).contains(&"ast.dynamic-code-execution"),
        "{findings:?}"
    );
    assert_eq!(findings[0].location.line, 4);
}

#[test]
fn python_eval_of_a_literal_is_not_reported() {
    // `eval("1 + 1")` cannot be made to run anything the author did not write. Reporting it beside
    // a real one, at the same seriousness, is how a rule teaches people to skip its findings.
    let findings = scan("python", "x = eval('1 + 1')\n");
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn javascript_eval_and_new_function_are_both_found() {
    let findings = scan(
        "javascript",
        "const f = new Function(req.body.src);\neval(req.query.x);\n",
    );
    assert_eq!(findings.len(), 2, "{findings:?}");
}

#[test]
fn a_template_string_with_nothing_in_it_is_a_literal() {
    // The distinction the whole literal check turns on.
    let interpolated = scan(
        "javascript",
        "db.query(`SELECT * FROM t WHERE id = ${id}`);\n",
    );
    assert!(
        ids(&interpolated).contains(&"ast.sql-built-by-hand"),
        "{interpolated:?}"
    );
    let constant = scan("javascript", "db.query(`SELECT * FROM t`);\n");
    assert!(
        constant.is_empty(),
        "a constant query is not a finding: {constant:?}"
    );
}

#[test]
fn python_sql_built_with_an_f_string_is_found() {
    let findings = scan(
        "python",
        "def get(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
    );
    assert!(
        ids(&findings).contains(&"ast.sql-built-by-hand"),
        "{findings:?}"
    );
}

#[test]
fn python_sql_with_bound_parameters_is_not_a_finding() {
    // The correct way to do it must not be reported, or the rule is worse than nothing.
    let findings = scan(
        "python",
        "cur.execute('SELECT * FROM users WHERE name = ?', (name,))\n",
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_shell_command_built_from_a_value_is_found() {
    let python = scan("python", "import os\nos.system('rm -rf ' + path)\n");
    assert!(ids(&python).contains(&"ast.shell-command"), "{python:?}");

    let js = scan(
        "javascript",
        "const { exec } = require('child_process');\nexec(`ls ${dir}`);\n",
    );
    assert!(ids(&js).contains(&"ast.shell-command"), "{js:?}");
}

#[test]
fn a_fixed_shell_command_is_not_reported() {
    let findings = scan("python", "import os\nos.system('ls -la')\n");
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn python_pickle_and_unsafe_yaml_are_found() {
    let findings = scan(
        "python",
        "import pickle, yaml\n\ndef load(blob, text):\n    a = pickle.loads(blob)\n    b = yaml.load(text)\n    return a, b\n",
    );
    assert!(
        ids(&findings).contains(&"ast.unsafe-deserialization"),
        "{findings:?}"
    );
    assert_eq!(findings.len(), 2, "both calls are findings: {findings:?}");
}

#[test]
fn yaml_safe_load_is_not_reported() {
    let findings = scan("python", "import yaml\nd = yaml.safe_load(text)\n");
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_comment_mentioning_a_dangerous_call_is_not_a_finding() {
    // The reason this parses rather than greps. A regex over the text reports both of these.
    let findings = scan("python", "# never use eval(user_input) here\nx = 1\n");
    assert!(findings.is_empty(), "{findings:?}");
    let in_string = scan("python", "message = 'do not call eval(x)'\n");
    assert!(in_string.is_empty(), "{in_string:?}");
}

#[test]
fn a_call_split_over_several_lines_is_still_found() {
    // The other reason: a regex anchored to one line misses this, and reformatting an app should
    // not change whether it has a vulnerability.
    let findings = scan(
        "python",
        "cur.execute(\n    f\"SELECT * FROM t WHERE id = {user_id}\"\n)\n",
    );
    assert!(
        ids(&findings).contains(&"ast.sql-built-by-hand"),
        "{findings:?}"
    );
}

#[test]
fn a_language_with_no_grammar_yields_nothing_rather_than_pretending() {
    // Objective-C is read by `sv-scan` — it counts towards what an app is written in, through
    // `.m`/`.mm` — and has no grammar here, which is the combination that has to stay silent
    // rather than guess.
    assert!(scan_file(rules(), "objc", "app.m", "system(argv[1]);").is_empty());
    assert!(!is_supported("objc"));
    assert!(is_supported("python") && is_supported("typescript") && is_supported("cpp"));
}

#[test]
fn the_three_new_grammars_read_their_own_languages() {
    // The point of adding them. Each snippet is the shape somebody would really write.
    for (language, file, source, expected) in [
        (
            "ruby",
            "app.rb",
            "db.execute(\"select * from t where n = \" + name)",
            "ast.sql-built-by-hand",
        ),
        (
            "ruby",
            "app.rb",
            "Marshal.load(params[:blob])",
            "ast.unsafe-deserialization",
        ),
        (
            "php",
            "app.php",
            "<?php $db->query(\"select * from t where n = \" . $name);",
            "ast.sql-built-by-hand",
        ),
        (
            "php",
            "app.php",
            "<?php unserialize($_GET[\"blob\"]);",
            "ast.unsafe-deserialization",
        ),
        (
            "java",
            "App.java",
            "class A { void f(String n) { stmt.executeQuery(\"select * from t where n = \" + n); } }",
            "ast.sql-built-by-hand",
        ),
        (
            "java",
            "App.java",
            "class A { void f() { new ObjectInputStream(in).readObject(); } }",
            "ast.unsafe-deserialization",
        ),
    ] {
        let findings = scan_file(rules(), language, file, source);
        assert!(
            ids(&findings).contains(&expected),
            "{language}: expected {expected}, got {:?}",
            ids(&findings)
        );
    }
}

#[test]
fn ruby_backticks_are_a_shell_command_and_a_fixed_one_is_not_reported() {
    // The backtick form has no method name to match, so it is its own pattern. `ls` cannot be
    // made to run anything else; `ls #{dir}` can, and the literal check is what tells them
    // apart — the same rule the rest of this file runs on.
    let dangerous = scan_file(rules(), "ruby", "app.rb", "`ls #{params[:dir]}`");
    assert!(
        ids(&dangerous).contains(&"ast.shell-command-backticks"),
        "{dangerous:?}"
    );
    let fixed = scan_file(rules(), "ruby", "app.rb", "`ls -la`");
    assert!(
        !ids(&fixed).contains(&"ast.shell-command-backticks"),
        "a fixed command cannot be made to run anything else: {fixed:?}"
    );
}

#[test]
fn what_comes_out_of_a_page_and_what_is_left_behind() {
    // One function answers both halves on purpose. When "does this page hold code" and "what
    // code does this page hold" are decided separately they drift, and the direction they
    // drift in is a page declared read whose code nobody extracted.
    let markup = html_fragments("<html><body><h1>Notes</h1></body></html>");
    assert!(markup.fragments.is_empty() && markup.left_behind.is_none());

    let external = html_fragments("<html><script src=\"app.js\"></script></html>");
    assert!(
        external.fragments.is_empty() && external.left_behind.is_none(),
        "the file it names is parsed like any other: {external:?}"
    );

    let whitespace = html_fragments("<html><script src=\"a.js\">\n  \n</script></html>");
    assert!(whitespace.fragments.is_empty() && whitespace.left_behind.is_none());

    let inline = html_fragments("<html><script>eval(x)</script></html>");
    assert_eq!(inline.fragments.len(), 1);
    assert_eq!(inline.fragments[0].language, "javascript");
    assert_eq!(inline.fragments[0].code, "eval(x)");
    assert!(inline.left_behind.is_none());

    let shouting = html_fragments("<html><SCRIPT>eval(x)</SCRIPT></html>");
    assert_eq!(
        shouting.fragments.len(),
        1,
        "tags match whatever their case"
    );
    assert_eq!(
        shouting.fragments[0].code, "eval(x)",
        "and the code comes out with its own case intact"
    );

    let typed = html_fragments("<script lang=\"ts\">const x: string = y</script>");
    assert_eq!(typed.fragments[0].language, "typescript");

    let handler = html_fragments("<button onclick=\"go(location.hash)\">go</button>");
    assert_eq!(handler.fragments.len(), 1);
    assert_eq!(handler.fragments[0].code, "go(location.hash)");

    let entities = html_fragments("<button onclick=\"go(&quot;a&quot; &amp; b)\">go</button>");
    assert_eq!(
        entities.fragments[0].code, "go(\"a\" & b)",
        "an entity can hide a quote, and must be put back before parsing"
    );

    let unclosed = html_fragments("<html><script>eval(x)");
    assert!(
        unclosed.left_behind.is_some(),
        "a script with no end cannot be bounded, so the page stays unread"
    );

    let url = html_fragments("<a href=\"javascript:go()\">go</a>");
    assert_eq!(url.fragments.len(), 1, "{url:?}");
    assert_eq!(url.fragments[0].code, "go()");
    assert!(url.left_behind.is_none());

    let shouting_url = html_fragments("<a href=\"JavaScript: go()\">go</a>");
    assert_eq!(
        shouting_url.fragments[0].code, " go()",
        "the scheme is matched whatever its case, and a browser skips the space"
    );

    let escaped_url = html_fragments("<a href=\"javascript:go(%22x%22)\">go</a>");
    assert_eq!(
        escaped_url.fragments[0].code, "go(\"x\")",
        "a percent escape has to come back before the grammar sees it"
    );

    let unquoted = html_fragments("<a href=javascript:go()>go</a>");
    assert_eq!(
        unquoted.fragments[0].code, "go()",
        "an unquoted value ends at the end of the tag: {unquoted:?}"
    );

    let split_scheme = html_fragments("<a href=\"java\tscript:go()\">go</a>");
    assert_eq!(
        split_scheme.fragments[0].code, "go()",
        "a browser removes the tab before it reads the scheme, and so does this: {split_scheme:?}"
    );

    let not_code = html_fragments(
        "<script type=\"text/x-template\">{{#each i}}<li>{{this}}</li>{{/each}}</script>",
    );
    assert!(
        not_code.left_behind.is_some(),
        "a fragment the grammar cannot read reports nothing, which must not read as clean: \
             {not_code:?}"
    );

    // And the limit of that, measured rather than assumed: the JavaScript grammar includes JSX,
    // so a Vue template parses cleanly and is not refused. It reaches the rules as markup.
    let jsx_shaped =
        html_fragments("<script type=\"text/x-template\"><div v-if=\"a\">x</div></script>");
    assert!(jsx_shaped.left_behind.is_none(), "{jsx_shaped:?}");

    let two = html_fragments("<script src=\"a.js\"></script><script>eval(x)</script>");
    assert_eq!(
        two.fragments.len(),
        1,
        "the second one is the one with code"
    );
}

#[test]
fn a_page_is_read_the_way_a_browser_reads_it() {
    // Each of these runs in a browser. Before this reading, the first four were a page counted
    // as read with nothing taken out of it: a false clean.
    for (page, code) in [
        (
            "<button onclick=eval(location.hash)>x</button>",
            "eval(location.hash)",
        ),
        (
            "<img/onerror=\"eval(location.hash)\" src=x>",
            "eval(location.hash)",
        ),
        (
            "<a href=\"java&#9;script:eval(location.hash)\">go</a>",
            "eval(location.hash)",
        ),
        ("<a href=\"java&Tab;script:go()\">go</a>", "go()"),
        ("<a href=\"&#x6A;avascript&colon;go()\">go</a>", "go()"),
        ("<a href=\"&#106avascript:go()\">go</a>", "go()"),
        ("<a href=\"\u{1} javascript:go()\">go</a>", "go()"),
        ("<a href=\"javascript:go(\n)\">go</a>", "go()"),
        ("<body onload=init()>", "init()"),
        ("<a href='javascript:go()'>go</a>", "go()"),
        ("<a href = javascript:go()>go</a>", "go()"),
        ("<a title=\"x>y\" onclick=\"go()\">go</a>", "go()"),
        ("<script data-note=\"a>b\">go()</script>", "go()"),
    ] {
        let scan = html_fragments(page);
        assert!(scan.left_behind.is_none(), "{page:?} is read: {scan:?}");
        let codes: Vec<&str> = scan.fragments.iter().map(|f| f.code.as_str()).collect();
        assert_eq!(codes, vec![code], "{page:?}");
    }

    // Where an unquoted value ends is not a guess: at whitespace, and what follows is the next
    // attribute. `b` is a name with no value, not the rest of the program.
    let split = html_fragments("<a href=javascript:a b>go</a>");
    assert_eq!(split.fragments.len(), 1, "{split:?}");
    assert_eq!(split.fragments[0].code, "a");

    // And the other side: things that look like code and are not.
    for page in [
        "<a title=\"use javascript: sparingly\">x</a>",
        "<textarea><a onclick=go(1 2)></textarea>",
        "<title><a onclick=go(1 2)></title>",
        "<script>location = \"javascript:void(0)\"</script>",
    ] {
        let scan = html_fragments(page);
        assert!(scan.left_behind.is_none(), "{page:?}: {scan:?}");
        assert!(
            scan.fragments.iter().all(|f| f.code != "go(1 2)"),
            "{page:?} holds no code a browser runs: {scan:?}"
        );
    }

    // What still keeps a page unread, each for its own reason.
    for (page, why) in [
        ("<p>try javascript:go() in the bar</p>", "text"),
        ("<!-- <a href=javascript:go()> -->", "a comment"),
        (
            "<a href=\"java\u{1}script:go()\">go</a>",
            "a control character in the scheme",
        ),
        (
            "<a onclick=\"&alpha;()\">go</a>",
            "a reference this does not decode",
        ),
        // The one above is also refused by the grammar, so on its own it does not show the
        // reference check does anything. This one parses with the reference left as written —
        // `x & alpha; (1)` — while a browser runs `xα(1)`, a different program.
        (
            "<a onclick=\"x&alpha;(1)\">go</a>",
            "a reference this does not decode, in code that parses without it",
        ),
        ("<a href=\"javascript:go()>go</a>", "a quote never closed"),
        ("<a href=javascript:go()", "a tag never closed"),
        ("<script>go()</scripts>", "a script never closed"),
    ] {
        let scan = html_fragments(page);
        assert!(scan.left_behind.is_some(), "{why}: {page:?} {scan:?}");
    }
}

#[test]
fn an_unquoted_handler_reaches_the_rules() {
    // The whole chain, not only the extraction: the page this was written for is the one where
    // a handler with no quotes was a page declared read and clean.
    let page =
        "<html>\n<body>\n<button onclick=eval(location.hash)>go</button>\n</body>\n</html>\n";
    let extracted = html_fragments(page);
    assert!(extracted.left_behind.is_none(), "{extracted:?}");
    let fragment = &extracted.fragments[0];
    let findings = scan_file(rules(), fragment.language, "index.html", &fragment.code);
    assert_eq!(ids(&findings), vec!["ast.dynamic-code-execution"]);
    assert_eq!(findings[0].location.line + fragment.line_offset, 3);
}

#[test]
fn a_finding_in_a_page_names_the_line_in_the_page() {
    // A reader sent to line 3 of a fragment they cannot see is worse off than one given
    // nothing at all.
    let page = "<html>\n<body>\n<h1>Notes</h1>\n<script>\neval(location.hash)\n</script>\n</body>\n</html>\n";
    let extracted = html_fragments(page);
    assert_eq!(extracted.fragments.len(), 1);
    let fragment = &extracted.fragments[0];
    let findings = scan_file(rules(), fragment.language, "index.html", &fragment.code);
    assert_eq!(ids(&findings), vec!["ast.dynamic-code-execution"]);
    assert_eq!(
        findings[0].location.line + fragment.line_offset,
        5,
        "`eval` is on line 5 of the page"
    );
}

#[test]
fn the_four_newest_grammars_read_their_own_languages() {
    for (language, file, source, expected) in [
        (
            "csharp",
            "App.cs",
            "class A { void F(string n) { cmd.ExecuteReader(\"select * from t where n = \" + n); } }",
            "ast.sql-built-by-hand",
        ),
        (
            "csharp",
            "App.cs",
            "class A { void F() { BinaryFormatter.Deserialize(stream); } }",
            "ast.unsafe-deserialization",
        ),
        (
            "kotlin",
            "App.kt",
            "fun f(n: String) { db.rawQuery(\"select * from t where n = \" + n, null) }",
            "ast.sql-built-by-hand",
        ),
        (
            "rust",
            "app.rs",
            "fn f(n: &str) { conn.execute(&format!(\"select * from t where n = {n}\"), []); }",
            "ast.sql-built-by-hand",
        ),
        (
            "c",
            "app.c",
            "void f(char *d) { char b[99]; sprintf(b, \"ls %s\", d); system(b); }",
            "ast.shell-command",
        ),
        (
            "cpp",
            "app.cpp",
            "void f(const std::string &d) { std::string cmd = \"ls \" + d; system(cmd.c_str()); }",
            "ast.shell-command",
        ),
        (
            "cpp",
            "app.cpp",
            "void f(sqlite3 *db, const std::string &name) { std::string q = \"select * from t where n = '\" + name + \"'\"; sqlite3_exec(db, q.c_str(), nullptr, nullptr, nullptr); }",
            "ast.sql-built-by-hand",
        ),
    ] {
        let findings = scan_file(rules(), language, file, source);
        assert!(
            ids(&findings).contains(&expected),
            "{language}: expected {expected}, got {:?}",
            ids(&findings)
        );
    }
}

#[test]
fn a_kotlin_string_template_is_not_a_literal_but_an_escaped_dollar_is() {
    // Kotlin's grammar gives an interpolated string no node of its own: `"select $n"` is three
    // plain `string_content` children with the `$` standing alone as one of them, and that last
    // part is the whole discriminator. Measured rather than guessed: counting the children
    // instead would report an escaped `\$`, which leaves two of them either side of an
    // `escape_sequence`.
    let built = scan_file(
        rules(),
        "kotlin",
        "App.kt",
        "fun f(n: String) { db.execSQL(\"select * from t where n = $n\") }",
    );
    assert!(
        ids(&built).contains(&"ast.sql-built-by-hand"),
        "a Kotlin template is a built string: {built:?}"
    );

    let escaped = scan_file(
        rules(),
        "kotlin",
        "App.kt",
        "fun f() { db.execSQL(\"select * from prices where label = 'cost \\$5'\") }",
    );
    assert!(
        !ids(&escaped).contains(&"ast.sql-built-by-hand"),
        "an escaped dollar is written out, not substituted: {escaped:?}"
    );

    let plain = scan_file(
        rules(),
        "kotlin",
        "App.kt",
        "fun f() { db.execSQL(\"select 1\") }",
    );
    assert!(!ids(&plain).contains(&"ast.sql-built-by-hand"), "{plain:?}");
}

#[test]
fn a_csharp_json_deserialise_is_not_reported() {
    // `Deserialize` is what every JSON library is called with. Only the receiver makes it the
    // dangerous one, and reporting the safe case would teach somebody to skip the rule.
    let safe = scan_file(
        rules(),
        "csharp",
        "App.cs",
        "class A { void F() { JsonSerializer.Deserialize(body); } }",
    );
    assert!(
        !ids(&safe).contains(&"ast.unsafe-deserialization"),
        "{safe:?}"
    );
}

#[test]
fn a_php_string_that_interpolates_a_variable_is_not_a_literal() {
    // PHP puts a bare `$name` inside a double-quoted string with no wrapper node, so the string
    // looks exactly like a written-out one to a check that only knows about `${…}` and `#{…}`.
    // Missing this reports every PHP query built the most natural way as a constant, which is
    // the case the rule exists for.
    let built = scan_file(
        rules(),
        "php",
        "app.php",
        "<?php $db->query(\"select * from t where n = $name\");",
    );
    assert!(
        ids(&built).contains(&"ast.sql-built-by-hand"),
        "an interpolated PHP string is a built string: {built:?}"
    );
    let fixed = scan_file(
        rules(),
        "php",
        "app.php",
        "<?php $db->query(\"select * from t where n = ?\");",
    );
    assert!(
        !ids(&fixed).contains(&"ast.sql-built-by-hand"),
        "a written-out query is not a finding: {fixed:?}"
    );
}

#[test]
fn the_usual_query_calls_of_each_language_are_read_and_their_safe_forms_are_not_reported() {
    // H1 of the deep review: nine real injections through the libraries people use gave no
    // finding, while V1.2.4 was marked checked. Each is here, with the same call written safely.
    let sql = "ast.sql-built-by-hand";
    let cases: &[(&str, &str, &str, bool)] = &[
        // better-sqlite3 and node-sqlite3.
        (
            "javascript",
            "app.js",
            "function f(db, n) { return db.prepare(`SELECT * FROM t WHERE n = '${n}'`).all(); }",
            true,
        ),
        (
            "javascript",
            "app.js",
            "function f(db, n) { return db.prepare('SELECT * FROM t WHERE n = ?').all(n); }",
            false,
        ),
        (
            "javascript",
            "app.js",
            "function f(db, n) { db.all(\"SELECT * FROM t WHERE n = '\" + n + \"'\", cb); }",
            true,
        ),
        (
            "javascript",
            "app.js",
            "function f(db, n) { db.all('SELECT * FROM t WHERE n = ?', [n], cb); }",
            false,
        ),
        (
            "javascript",
            "app.js",
            "function f(db, id) { db.run(`DELETE FROM t WHERE id = ${id}`); }",
            true,
        ),
        (
            "javascript",
            "app.js",
            "function f(db, sql) { db.exec(sql); }",
            true,
        ),
        // Prisma's unsafe call, and its safe tagged template.
        (
            "typescript",
            "app.ts",
            "async function f(p: any, n: string) { return p.$queryRawUnsafe(`SELECT * FROM t WHERE n = '${n}'`); }",
            true,
        ),
        (
            "typescript",
            "app.ts",
            "async function f(p: any, n: string) { return p.$queryRaw`SELECT * FROM t WHERE n = ${n}`; }",
            false,
        ),
        // PHP: mysqli takes the connection first, and PDO's prepare.
        (
            "php",
            "app.php",
            "<?php function f($conn, $n) { return mysqli_query($conn, \"SELECT * FROM t WHERE n = '$n'\"); }",
            true,
        ),
        (
            "php",
            "app.php",
            "<?php function f($conn) { return mysqli_query($conn, \"SELECT * FROM t\"); }",
            false,
        ),
        (
            "php",
            "app.php",
            "<?php function f($pdo, $n) { return $pdo->prepare(\"SELECT * FROM t WHERE n = '\" . $n . \"'\"); }",
            true,
        ),
        (
            "php",
            "app.php",
            "<?php function f($pdo) { return $pdo->prepare(\"SELECT * FROM t WHERE n = ?\"); }",
            false,
        ),
        // Java: JDBC's prepareStatement and Spring's JdbcTemplate.
        (
            "java",
            "A.java",
            "class A { void f(Connection c, String n) throws Exception { c.prepareStatement(\"SELECT * FROM t WHERE n = '\" + n + \"'\"); } }",
            true,
        ),
        (
            "java",
            "A.java",
            "class A { void f(Connection c) throws Exception { c.prepareStatement(\"SELECT * FROM t WHERE n = ?\"); } }",
            false,
        ),
        (
            "java",
            "A.java",
            "class A { void f(JdbcTemplate j, String n) { j.queryForList(\"SELECT * FROM t WHERE n = '\" + n + \"'\"); } }",
            true,
        ),
        (
            "java",
            "A.java",
            "class A { void f(JdbcTemplate j, String n) { j.update(\"UPDATE t SET n = '\" + n + \"'\"); } }",
            true,
        ),
        (
            "java",
            "A.java",
            "class A { void f(Map<String, String> m, String k, String v) { m.update(k + v); } }",
            false,
        ),
        // C#: a command built with `new`, and Dapper.
        (
            "csharp",
            "A.cs",
            "class A { void F(SqlConnection c, string n) { var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = '\" + n + \"'\", c); } }",
            true,
        ),
        (
            "csharp",
            "A.cs",
            "class A { void F(SqlConnection c) { var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = @n\", c); } }",
            false,
        ),
        (
            "csharp",
            "A.cs",
            "class A { void F(IDbConnection c, string n) { c.Query<T>($\"SELECT * FROM t WHERE n = '{n}'\"); } }",
            true,
        ),
        (
            "csharp",
            "A.cs",
            "class A { void F(Runner r, string n) { r.Execute(n + \"!\"); } }",
            false,
        ),
        // Ruby: Active Record's `where` with interpolation, and with a placeholder or a hash.
        (
            "ruby",
            "app.rb",
            "def f(n)\n  User.where(\"name = '#{n}'\")\nend\n",
            true,
        ),
        (
            "ruby",
            "app.rb",
            "def f(n)\n  User.where(\"name = ?\", n)\nend\n",
            false,
        ),
        (
            "ruby",
            "app.rb",
            "def f(n)\n  User.where(name: n)\nend\n",
            false,
        ),
        // pandas.
        (
            "python",
            "app.py",
            "def f(con, n):\n    return pd.read_sql(f\"SELECT * FROM t WHERE n = '{n}'\", con)\n",
            true,
        ),
        (
            "python",
            "app.py",
            "def f(con, n):\n    return pd.read_sql(\"SELECT * FROM t WHERE n = ?\", con, params=(n,))\n",
            false,
        ),
        // The common names stay quiet when what they are given is not a query.
        (
            "javascript",
            "app.js",
            "function f(cache, key) { return cache.get(key); }",
            false,
        ),
        (
            "javascript",
            "app.js",
            "function f(re, s) { return re.exec(s); }",
            false,
        ),
        (
            "javascript",
            "app.js",
            "app.get('/notes', (req, res) => res.send('ok'));",
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (language, file, code, expected) in cases {
        assert!(
            parses_cleanly(language, code),
            "the fixture must parse, or a pass proves nothing: {code}"
        );
        let found = ids(&scan_file(rules(), language, file, code)).contains(&sql);
        if found != *expected {
            wrong.push(format!("{language}: expected {expected}: {code}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn next_js_and_modern_node_redirects_and_file_calls_are_read() {
    // H5 of the deep review: each of these went unreported while TypeScript was claimed checked.
    let redirect = "ast.open-redirect";
    let file = "ast.file-path-from-value";
    let cases: &[(&str, &str, &str, &str, bool)] = &[
        // Next.js's `redirect` from `next/navigation`, and `NextResponse.redirect`.
        (
            redirect,
            "typescript",
            "page.tsx",
            "export default function P({ searchParams }: any) { redirect(searchParams.next); }",
            true,
        ),
        (
            redirect,
            "typescript",
            "page.tsx",
            "export default function P() { redirect('/login'); }",
            false,
        ),
        (
            redirect,
            "typescript",
            "middleware.ts",
            "export function middleware(req: any) { return NextResponse.redirect(req.nextUrl.searchParams.get('to')); }",
            true,
        ),
        (
            redirect,
            "typescript",
            "middleware.ts",
            "export function middleware(req: any) { return NextResponse.redirect(new URL('/login', req.url)); }",
            false,
        ),
        (
            redirect,
            "typescript",
            "middleware.ts",
            "export function middleware(req: any) { return NextResponse.redirect(new URL('//evil.test', req.url)); }",
            true,
        ),
        // The browser's own way.
        (
            "ast.open-redirect",
            "javascript",
            "app.js",
            "const to = new URLSearchParams(location.search).get('to'); window.location = to;",
            true,
        ),
        (
            redirect,
            "javascript",
            "app.js",
            "function go(u) { window.location.href = u; }",
            true,
        ),
        (
            redirect,
            "javascript",
            "app.js",
            "function go(u) { location.href = u; }",
            true,
        ),
        (
            redirect,
            "javascript",
            "app.js",
            "function go(u) { location.assign(u); }",
            true,
        ),
        (
            redirect,
            "javascript",
            "app.js",
            "function go(u) { window.location.replace(u); }",
            true,
        ),
        (
            redirect,
            "javascript",
            "app.js",
            "window.location.href = '/home';",
            false,
        ),
        (
            redirect,
            "javascript",
            "app.js",
            "function f(s, a) { return s.replace(a, ''); }",
            false,
        ),
        (
            redirect,
            "javascript",
            "app.js",
            "function f(el, u) { el.href = u; }",
            false,
        ),
        // `fs/promises`, imported by name or reached through `fs.promises`.
        (
            file,
            "javascript",
            "app.mjs",
            "import { readFile } from 'fs/promises';\nexport async function f(req) { return readFile(req.query.name); }",
            true,
        ),
        (
            file,
            "typescript",
            "app.ts",
            "import { writeFile } from 'node:fs/promises';\nexport async function f(n: string) { await writeFile(n, 'x'); }",
            true,
        ),
        (
            file,
            "javascript",
            "app.js",
            "async function f(req) { return fs.promises.readFile(req.params.p); }",
            true,
        ),
        (
            file,
            "javascript",
            "app.mjs",
            "import { readFile } from 'fs/promises';\nexport async function f() { return readFile(path.join(__dirname, 'a.html')); }",
            false,
        ),
        (
            file,
            "javascript",
            "app.mjs",
            "import { readFile } from 'fs/promises';\nexport async function f() { return readFile('config.json'); }",
            false,
        ),
        (
            file,
            "javascript",
            "app.js",
            "function f(url) { return download(url); }",
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (rule, language, name, code, expected) in cases {
        let parses = parses_cleanly(
            if name.ends_with(".tsx") {
                "tsx"
            } else {
                language
            },
            code,
        );
        assert!(
            parses,
            "the fixture must parse, or a pass proves nothing: {code}"
        );
        let found = ids(&scan_file(rules(), language, name, code)).contains(rule);
        if found != *expected {
            wrong.push(format!("{rule}, expected {expected}: {code}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_ruby_load_on_something_that_is_not_a_deserialiser_is_not_reported() {
    // `load` is far too common a method name to report on its own. The receiver is what makes
    // it a deserialization, and over-reporting here would teach somebody to skip the rule.
    // A lower-case receiver is an `identifier`, which the query's own shape excludes.
    let findings = scan_file(rules(), "ruby", "app.rb", "config.load(path)");
    assert!(
        !ids(&findings).contains(&"ast.unsafe-deserialization"),
        "{findings:?}"
    );
    // A capitalized one is a `constant`, which the query does match — so only the receiver
    // pattern stops it. Without this case the pattern could be deleted and every test here
    // would still pass, because the one above was being excluded by the node kind instead.
    let other_constant = scan_file(rules(), "ruby", "app.rb", "Settings.load(path)");
    assert!(
        !ids(&other_constant).contains(&"ast.unsafe-deserialization"),
        "a constant that is not a deserializer must not be reported: {other_constant:?}"
    );
    let real = scan_file(rules(), "ruby", "app.rb", "YAML.load(untrusted)");
    assert!(
        ids(&real).contains(&"ast.unsafe-deserialization"),
        "{real:?}"
    );
}

/// One found case and one not-found case for every language each of these rules has a query in.
    ///
    /// Each `false` line is the correct way to do the same thing, or the idiom a careless rule would
    /// report — the negative half is what stops a query that matches every call from passing.
    #[rustfmt::skip]
    const WITNESSES: &[(&str, &str, &str, bool)] = &[
        // Paths.
        ("ast.file-path-from-value", "python", "open(os.path.join(UPLOADS, request.args['name']))", true),
        ("ast.file-path-from-value", "python", "open(os.path.join(UPLOADS, secure_filename(f.filename)))", false),
        ("ast.file-path-from-value", "python", "open(os.path.join(os.path.dirname(__file__), 'schema.sql'))", false),
        ("ast.file-path-from-value", "python", "return send_file(request.args['path'])", true),
        ("ast.file-path-from-value", "python", "open('config.toml')", false),
        ("ast.file-path-from-value", "javascript", "fs.readFileSync(req.query.file)", true),
        ("ast.file-path-from-value", "javascript", "res.sendFile(path.join(__dirname, 'public', 'index.html'))", false),
        ("ast.file-path-from-value", "javascript", "res.sendFile(path.join(__dirname, req.params.name))", true),
        ("ast.file-path-from-value", "typescript", "await fs.readFile(`uploads/${req.params.name}`)", true),
        ("ast.file-path-from-value", "typescript", "fs.readFileSync('package.json')", false),
        ("ast.file-path-from-value", "go", "f, err := os.Open(r.URL.Query().Get(\"f\"))", true),
        ("ast.file-path-from-value", "go", "f, err := os.Open(\"config.json\")", false),
        ("ast.file-path-from-value", "php", "<?php echo file_get_contents($_GET['page']);", true),
        ("ast.file-path-from-value", "php", "<?php echo file_get_contents('about.html');", false),
        ("ast.file-path-from-value", "ruby", "File.read(params[:name])", true),
        ("ast.file-path-from-value", "ruby", "File.read('config.yml')", false),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { new FileInputStream(n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f() { new FileInputStream(\"app.properties\"); } }", false),
        ("ast.file-path-from-value", "csharp", "class A { void F(string n) { var t = File.ReadAllText(n); } }", true),
        ("ast.file-path-from-value", "csharp", "class A { void F() { var t = File.ReadAllText(\"a.json\"); } }", false),
        // A bare constant is the app's own configuration, not a request value.
        ("ast.file-path-from-value", "python", "with open(CONFIG_PATH) as f: pass", false),
        ("ast.file-path-from-value", "javascript", "fs.readFileSync(CERT_FILE)", false),
        ("ast.file-path-from-value", "ruby", "File.read(SETTINGS_FILE)", false),
        ("ast.file-path-from-value", "php", "<?php $s = file_get_contents(SETTINGS_FILE);", false),
        ("ast.file-path-from-value", "python", "with open(CONFIG_PATH + name) as f: pass", true),
        // The same method name on something that is not the file system.
        ("ast.file-path-from-value", "javascript", "const entry = zip.readFile(req.query.name)", false),
        ("ast.file-path-from-value", "go", "conn, err := pool.Open(r.FormValue(\"db\"))", false),
        ("ast.file-path-from-value", "ruby", "log = Logger.new(path)", false),
        ("ast.file-path-from-value", "csharp", "class A { void F(string n) { var t = Cache.Open(n); } }", false),
        // Hashes.
        ("ast.weak-hash-function", "python", "digest = hashlib.md5(password.encode()).hexdigest()", true),
        ("ast.weak-hash-function", "python", "etag = hashlib.md5(body, usedforsecurity=False).hexdigest()", false),
        ("ast.weak-hash-function", "python", "digest = hashlib.sha256(data).hexdigest()", false),
        ("ast.weak-hash-function", "javascript", "crypto.createHash('md5').update(pw).digest('hex')", true),
        ("ast.weak-hash-function", "javascript", "crypto.createHash('sha256').update(pw).digest('hex')", false),
        ("ast.weak-hash-function", "typescript", "crypto.createHash(\"SHA1\").update(x)", true),
        ("ast.weak-hash-function", "typescript", "crypto.createHash(\"sha512\").update(x)", false),
        ("ast.weak-hash-function", "go", "sum := md5.Sum([]byte(pw))", true),
        ("ast.weak-hash-function", "go", "sum := sha256.Sum256([]byte(pw))", false),
        ("ast.weak-hash-function", "php", "<?php $h = md5($password);", true),
        ("ast.weak-hash-function", "php", "<?php $h = password_hash($password, PASSWORD_DEFAULT);", false),
        ("ast.weak-hash-function", "ruby", "Digest::MD5.hexdigest(password)", true),
        ("ast.weak-hash-function", "ruby", "Digest::SHA256.hexdigest(password)", false),
        ("ast.weak-hash-function", "java", "class A { void f() throws Exception { MessageDigest.getInstance(\"MD5\"); } }", true),
        ("ast.weak-hash-function", "java", "class A { void f() throws Exception { MessageDigest.getInstance(\"SHA-256\"); } }", false),
        ("ast.weak-hash-function", "csharp", "class A { void F() { using var h = MD5.Create(); } }", true),
        ("ast.weak-hash-function", "csharp", "class A { void F() { using var h = SHA256.Create(); } }", false),
        ("ast.weak-hash-function", "kotlin", "fun f() { val d = MessageDigest.getInstance(\"SHA-1\") }", true),
        ("ast.weak-hash-function", "kotlin", "fun f() { val d = MessageDigest.getInstance(\"SHA-256\") }", false),
        ("ast.weak-hash-function", "go", "h := sha256.New()", false),
        // Ciphers.
        ("ast.weak-cipher", "python", "cipher = AES.new(key, AES.MODE_ECB)", true),
        ("ast.weak-cipher", "python", "cipher = AES.new(key, AES.MODE_GCM)", false),
        ("ast.weak-cipher", "python", "c = Cipher(algorithms.AES(key), modes.ECB())", true),
        ("ast.weak-cipher", "python", "c = Cipher(algorithms.AES(key), modes.GCM(iv))", false),
        ("ast.weak-cipher", "javascript", "crypto.createCipheriv('aes-128-ecb', key, null)", true),
        ("ast.weak-cipher", "javascript", "crypto.createCipheriv('aes-256-gcm', key, iv)", false),
        ("ast.weak-cipher", "typescript", "crypto.createCipheriv(\"des-ede3-cbc\", key, iv)", true),
        ("ast.weak-cipher", "typescript", "crypto.createCipheriv(\"chacha20-poly1305\", key, iv)", false),
        ("ast.weak-cipher", "go", "block, err := des.NewTripleDESCipher(key)", true),
        ("ast.weak-cipher", "go", "block, err := aes.NewCipher(key)", false),
        ("ast.weak-cipher", "php", "<?php openssl_encrypt($data, 'aes-128-ecb', $key);", true),
        ("ast.weak-cipher", "php", "<?php openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);", false),
        ("ast.weak-cipher", "ruby", "c = OpenSSL::Cipher.new('des-ede3-cbc')", true),
        ("ast.weak-cipher", "ruby", "c = OpenSSL::Cipher.new('aes-256-gcm')", false),
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES\"); } }", true),
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES/GCM/NoPadding\"); } }", false),
        ("ast.weak-cipher", "csharp", "class A { void F(Aes a) { a.Mode = CipherMode.ECB; } }", true),
        ("ast.weak-cipher", "csharp", "class A { void F(Aes a) { a.Mode = CipherMode.CBC; } }", false),
        ("ast.weak-cipher", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\") }", true),
        ("ast.weak-cipher", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/GCM/NoPadding\") }", false),
        // Generating a key names the algorithm and no mode: "AES" here is not ECB.
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { KeyGenerator.getInstance(\"AES\"); } }", false),
        ("ast.weak-cipher", "kotlin", "fun f() { val k = KeyGenerator.getInstance(\"AES\") }", false),
        // Redirects.
        ("ast.open-redirect", "python", "return redirect(request.args.get('next'))", true),
        ("ast.open-redirect", "python", "return redirect(url_for('index'))", false),
        ("ast.open-redirect", "python", "return redirect('/login')", false),
        ("ast.open-redirect", "javascript", "res.redirect(req.query.returnTo)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/dashboard')", false),
        ("ast.open-redirect", "typescript", "res.redirect(req.body.next as string)", true),
        ("ast.open-redirect", "typescript", "res.redirect(`/items`)", false),
        ("ast.open-redirect", "go", "http.Redirect(w, r, r.URL.Query().Get(\"next\"), http.StatusFound)", true),
        ("ast.open-redirect", "go", "http.Redirect(w, r, \"/login\", http.StatusFound)", false),
        ("ast.open-redirect", "javascript", "router.redirect(from, to)", false),
        ("ast.open-redirect", "go", "cache.Redirect(w, r, next, 302)", false),
        ("ast.open-redirect", "php", "<?php header('Location: ' . $_GET['next']);", true),
        ("ast.open-redirect", "php", "<?php header('Content-Type: ' . $type);", false),
        ("ast.open-redirect", "ruby", "redirect_to params[:return_to]", true),
        ("ast.open-redirect", "ruby", "redirect_to root_path", false),
        ("ast.open-redirect", "java", "class A { void f(HttpServletResponse r, String u) throws Exception { r.sendRedirect(u); } }", true),
        ("ast.open-redirect", "java", "class A { void f(HttpServletResponse r) throws Exception { r.sendRedirect(\"/home\"); } }", false),
        ("ast.open-redirect", "csharp", "class C { IActionResult F(string returnUrl) { return Redirect(returnUrl); } }", true),
        ("ast.open-redirect", "csharp", "class C { IActionResult F() { return Redirect(Url.Action(\"Index\")); } }", false),
        // Dart and Swift, and the gaps the per-language rule showed in the others. Every rule has
        // both halves in both languages, or says there is nothing to find in it.
        ("ast.dynamic-code-execution", "dart", "void f(String u) { Isolate.spawnUri(Uri.parse(u), [], null); }", true),
        ("ast.dynamic-code-execution", "dart", "void f(String p) { Isolate.spawnUri(Uri.file(p), [], null); }", true),
        ("ast.dynamic-code-execution", "dart", "void f() { Isolate.spawnUri(Uri.parse('worker.dart'), [], null); }", false),
        ("ast.dynamic-code-execution", "dart", "void f() { Isolate.spawn(worker, null); }", false),
        ("ast.dynamic-code-execution", "swift", "func f(code: String) { ctx.evaluateScript(code) }", true),
        ("ast.dynamic-code-execution", "swift", "func f(s: String) { let e = NSExpression(format: s) }", true),
        ("ast.dynamic-code-execution", "swift", "func f() { ctx.evaluateScript(\"1 + 1\") }", false),
        ("ast.dynamic-code-execution", "swift", "func f(x: Int) { let e = NSExpression(format: \"%d + 1\", x) }", false),
        ("ast.dynamic-code-execution", "csharp", "class A { async void F(string c) { await CSharpScript.EvaluateAsync(c); } }", true),
        ("ast.dynamic-code-execution", "csharp", "class A { async void F() { await CSharpScript.EvaluateAsync(\"1 + 1\"); } }", false),
        ("ast.dynamic-code-execution", "kotlin", "fun f(code: String) { engine.eval(code) }", true),
        ("ast.dynamic-code-execution", "kotlin", "fun f() { engine.eval(\"1 + 1\") }", false),
        // A1 of the deep review: a name the file binds once to fixed text is that text. Quiet: a
        // module constant, the prompt test's SCHEMA and its table of fixed queries, a name bound once,
        // a chain of constants. Still reported: the name reassigned, built with `+=`, taken as a
        // parameter, used as a loop variable, a constant joined with a value, a table with a spread.
        ("ast.sql-built-by-hand", "python", "QUERY = \"SELECT * FROM notes WHERE user_id = ?\"\ndef f(db, uid):\n    db.execute(QUERY, (uid,))\n", false),
        ("ast.sql-built-by-hand", "python", "SCHEMA = \"\"\"CREATE TABLE notes (id INTEGER)\"\"\"\ndef f(db):\n    db.executescript(SCHEMA)\n", false),
        ("ast.sql-built-by-hand", "python", "SORT_ORDERS = {\"newest\": \"SELECT * FROM n ORDER BY t DESC\", \"oldest\": \"SELECT * FROM n ORDER BY t\"}\ndef f(db, key, uid):\n    sql = SORT_ORDERS.get(key, SORT_ORDERS[\"newest\"])\n    db.execute(sql, (uid,))\n", false),
        ("ast.sql-built-by-hand", "python", "def f(db, key):\n    sql = \"SELECT 1\"\n    db.execute(sql)\n", false),
        ("ast.sql-built-by-hand", "python", "BASE = \"SELECT * FROM n\"\nWHERE = BASE + \" WHERE id = ?\"\ndef f(db, i):\n    db.execute(WHERE, (i,))\n", false),
        ("ast.sql-built-by-hand", "python", "def f(db, name):\n    sql = \"SELECT 1\"\n    sql = \"SELECT * FROM t WHERE n = '\" + name + \"'\"\n    db.execute(sql)\n", true),
        ("ast.sql-built-by-hand", "python", "def f(db, name):\n    sql = \"SELECT * FROM t WHERE n = \"\n    sql += name\n    db.execute(sql)\n", true),
        ("ast.sql-built-by-hand", "python", "def f(db, sql):\n    db.execute(sql)\ndef g(db):\n    sql = \"SELECT 1\"\n", true),
        ("ast.sql-built-by-hand", "python", "def f(db, names):\n    for sql in names:\n        db.execute(sql)\nsql = \"SELECT 1\"\n", true),
        ("ast.sql-built-by-hand", "python", "QUERY = \"SELECT * FROM t WHERE n = \"\ndef f(db, request):\n    db.execute(QUERY + request.args[\"n\"])\n", true),
        ("ast.sql-built-by-hand", "python", "TABLE = {**OTHER, \"a\": \"SELECT 1\"}\ndef f(db, k):\n    db.execute(TABLE[k])\n", true),
        ("ast.sql-built-by-hand", "python", "SORT_ORDERS = {\"newest\": \"SELECT 1\"}\ndef f(db, key, request):\n    db.execute(SORT_ORDERS.get(key, request.args[\"sql\"]))\n", true),
        // Backlog 215 (the Haiku 5.5 trial): Python names judged in their own function, a guard on a fixed
        // list that leaves, a choice between fixed values, fixed pieces joined, and an f-string whose every
        // piece is fixed. Quiet: the trial's own shapes, each beside a second function that rebinds the same
        // names from the request. Still reported: each guard undone, one way at a time.
        ("ast.sql-built-by-hand", "python", "SORT_COLUMNS = {\"title\": \"title\", \"created\": \"created_at\"}\ndef search(db, request, uid):\n    words = request.args.get(\"q\", \"\").split()[:10]\n    sort = SORT_COLUMNS.get(request.args.get(\"sort\", \"created\"), \"created_at\")\n    clauses = [\"owner_id = ?\"]\n    params = [uid]\n    for word in words:\n        clauses.append(\"(title LIKE ? OR method LIKE ?)\")\n        params += [word, word]\n    return db.execute(f\"SELECT id FROM recipes WHERE {' AND '.join(clauses)} ORDER BY {sort}\", params).fetchall()\ndef other(db, request):\n    sort = request.args.get(\"sort\")\n    clauses = []\n    direction = request.args.get(\"d\")\n    return sort, clauses, direction\n", false),
        ("ast.sql-built-by-hand", "python", "SORTABLE_COLUMNS = {\"id\", \"title\", \"created_at\"}\ndef search(db, request, uid):\n    sort = request.args.get(\"sort\", \"title\")\n    if sort not in SORTABLE_COLUMNS:\n        abort(400)\n    direction = \"DESC\" if request.args.get(\"dir\") == \"desc\" else \"ASC\"\n    return db.execute(f\"SELECT id FROM recipes WHERE owner_id = ? ORDER BY {sort} {direction}, id\", (uid,)).fetchall()\ndef other(db, request):\n    sort = request.args.get(\"sort\")\n    clauses = []\n    direction = request.args.get(\"d\")\n    return sort, clauses, direction\n", false),
        ("ast.sql-built-by-hand", "python", "def search(db, request, uid):\n    sort = request.args.get(\"sort\", \"title\")\n    if sort not in (\"title\", \"created_at\"):\n        return \"unknown column\", 400\n    return db.execute(\"SELECT id FROM recipes WHERE owner_id = ? ORDER BY \" + sort, (uid,)).fetchall()\ndef other(db, request):\n    sort = request.args.get(\"sort\")\n    clauses = []\n    direction = request.args.get(\"d\")\n    return sort, clauses, direction\n", false),
        ("ast.sql-built-by-hand", "python", "ALLOWED = (\"title\", \"created_at\")\ndef search(db, request, uid):\n    sort = request.args[\"sort\"]\n    if sort not in ALLOWED:\n        raise ValueError(\"bad sort\")\n    return db.execute(\"SELECT id FROM recipes ORDER BY \" + sort + (\" DESC\" if request.args.get(\"d\") else \" ASC\"))\ndef other(db, request):\n    sort = request.args.get(\"sort\")\n    clauses = []\n    direction = request.args.get(\"d\")\n    return sort, clauses, direction\n", false),
        ("ast.sql-built-by-hand", "python", "def search(db, request):\n    sort = request.args.get(\"sort\", \"title\")\n    return db.execute(f\"SELECT id FROM recipes ORDER BY {sort}\")\n", true),
        ("ast.sql-built-by-hand", "python", "SORTABLE = {\"title\", \"created_at\"}\ndef search(db, request):\n    sort = request.args.get(\"sort\", \"title\")\n    if sort not in SORTABLE:\n        log(\"unknown sort\")\n    return db.execute(f\"SELECT id FROM recipes ORDER BY {sort}\")\n", true),
        ("ast.sql-built-by-hand", "python", "def search(db, request, allowed):\n    sort = request.args.get(\"sort\", \"title\")\n    if sort not in allowed:\n        abort(400)\n    return db.execute(f\"SELECT id FROM recipes ORDER BY {sort}\")\n", true),
        ("ast.sql-built-by-hand", "python", "SORTABLE = {\"title\", \"created_at\"}\ndef search(db, request):\n    sort = request.args.get(\"sort\", \"title\")\n    if sort not in SORTABLE:\n        abort(400)\n    sort = request.args[\"other\"]\n    return db.execute(f\"SELECT id FROM recipes ORDER BY {sort}\")\n", true),
        ("ast.sql-built-by-hand", "python", "def search(db, request):\n    direction = \"DESC\" if request.args.get(\"d\") == \"desc\" else request.args[\"d\"]\n    return db.execute(f\"SELECT id FROM recipes ORDER BY title {direction}\")\n", true),
        ("ast.sql-built-by-hand", "python", "def search(db, request):\n    clauses = [\"owner_id = 1\"]\n    clauses.append(\"title = '\" + request.args[\"q\"] + \"'\")\n    return db.execute(f\"SELECT id FROM recipes WHERE {' AND '.join(clauses)}\")\n", true),
        ("ast.sql-built-by-hand", "python", "def search(db, request):\n    clauses = [\"owner_id = 1\"]\n    add_filters(clauses, request)\n    return db.execute(f\"SELECT id FROM recipes WHERE {' AND '.join(clauses)}\")\n", true),
        ("ast.sql-built-by-hand", "python", "def search(db, request, sep):\n    clauses = [\"owner_id = 1\", \"deleted = 0\"]\n    return db.execute(f\"SELECT id FROM recipes WHERE {sep.join(clauses)}\")\n", true),
        ("ast.sql-built-by-hand", "python", "def search(db, request):\n    global sort\n    sort = \"title\"\n    return db.execute(f\"SELECT id FROM recipes ORDER BY {sort}\")\n", true),
        // One piece of an f-string guarded and the other the request's: still reported.
        ("ast.sql-built-by-hand", "python", "SORTABLE = {\"title\", \"created_at\"}\ndef search(db, request):\n    sort = request.args.get(\"sort\", \"title\")\n    if sort not in SORTABLE:\n        abort(400)\n    direction = request.args[\"d\"]\n    return db.execute(f\"SELECT id FROM recipes ORDER BY {sort} {direction}\")\n", true),
        // A command list the function grows: fixed when only fixed text is added, reported when a value is.
        ("ast.shell-command-shell-true", "python", "def run(request):\n    cmd = [\"ls\"]\n    cmd.append(request.args[\"d\"])\n    subprocess.call(cmd, shell=True)\n", true),
        ("ast.shell-command-shell-true", "python", "def run(request):\n    cmd = [\"ls\"]\n    cmd.append(\"-la\")\n    subprocess.call(cmd, shell=True)\n", false),
        // A module's list may be appended to from any function: joined, it is still reported.
        ("ast.sql-built-by-hand", "python", "CLAUSES = [\"owner_id = 1\"]\ndef add(request):\n    CLAUSES.append(\"title = '\" + request.args[\"q\"] + \"'\")\ndef search(db):\n    return db.execute(f\"SELECT id FROM recipes WHERE {' AND '.join(CLAUSES)}\")\n", true),
        ("ast.sql-built-by-hand", "javascript", "const LIST = 'SELECT * FROM notes WHERE user_id = ?';\nfunction f(db, uid) { return db.query(LIST, [uid]); }", false),
        ("ast.sql-built-by-hand", "javascript", "let sql = 'SELECT 1';\nfunction f(db, x) { sql = sql + x; return db.query(sql); }", true),
        // Item 24 of the review of 1 to 4 October: a parameter written without brackets, or
        // unpacked from an object or a list, was not counted as a parameter, so a constant of the
        // same name made it look fixed.
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = sql => db.query(sql);", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = ({ sql }) => db.query(sql);", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = ({ q: sql }) => db.query(sql);", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nfunction f([sql]) { return db.query(sql); }", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nfunction f({ sql } = {}) { return db.query(sql); }", true),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = () => db.query(sql);", false),
        ("ast.sql-built-by-hand", "javascript", "const sql = 'SELECT 1';\nconst f = ({ q: other }) => db.query(sql);", false),
        ("ast.sql-built-by-hand", "go", "package main\nconst q = \"SELECT * FROM notes WHERE user_id = $1\"\nfunc f(ctx context.Context, db *sql.DB, uid int) { db.QueryContext(ctx, q, uid) }", false),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(ctx context.Context, db *sql.DB, name string) { db.QueryContext(ctx, \"SELECT * FROM t WHERE n = '\"+name+\"'\") }", true),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(db *sql.DB) { db.Query(\"SELECT 1\") }", false),
        // The review of 1 to 4 October, item 18: query calls these languages' code uses as often as
        // the ones the rule read.
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(ctx context.Context, db *sql.DB, n string) { db.QueryRowContext(ctx, \"SELECT * FROM t WHERE n = '\"+n+\"'\") }", true),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(db *sql.DB, n string) { db.Prepare(\"SELECT * FROM t WHERE n = '\"+n+\"'\") }", true),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(ctx context.Context, db *sql.DB, n string) { db.PrepareContext(ctx, \"SELECT * FROM t WHERE n = '\"+n+\"'\") }", true),
        ("ast.sql-built-by-hand", "go", "package main\nfunc f(ctx context.Context, db *sql.DB, n string) { db.QueryRowContext(ctx, \"SELECT * FROM t WHERE n = $1\", n) }", false),
        ("ast.sql-built-by-hand", "kotlin", "fun f(c: Connection, n: String) { val s = c.prepareStatement(\"SELECT * FROM t WHERE n = '\" + n + \"'\") }", true),
        ("ast.sql-built-by-hand", "kotlin", "fun f(c: Connection) { val s = c.prepareStatement(\"SELECT * FROM t WHERE n = ?\") }", false),
        ("ast.sql-built-by-hand", "csharp", "class A { void F(SqlCommand cmd, string n) { cmd.CommandText = \"SELECT * FROM t WHERE n = '\" + n + \"'\"; cmd.ExecuteReader(); } }", true),
        ("ast.sql-built-by-hand", "csharp", "class A { void F(string n) { var cmd = new SqlCommand { CommandText = \"SELECT * FROM t WHERE n = '\" + n + \"'\" }; } }", true),
        ("ast.sql-built-by-hand", "csharp", "class A { void F(SqlCommand cmd) { cmd.CommandText = \"SELECT * FROM t WHERE n = @n\"; cmd.ExecuteReader(); } }", false),
        ("ast.sql-built-by-hand", "csharp", "class A { void F(Label l, string n) { l.Text = \"Hello \" + n; } }", false),
        // Same-site paths: one slash and then an ordinary path character cannot leave the site.
        ("ast.open-redirect", "python", "return redirect(f\"/notes/{note_id}\")", false),
        ("ast.open-redirect", "python", "return redirect(\"/notes/\" + str(note_id))", false),
        // Item 19 of the review of 1 to 4 October: a destination was judged by how it starts, so a
        // choice whose first value is a path on the same site was taken for one, and so was a path
        // whose first character after the slash is a `%` that formatting fills in.
        ("ast.open-redirect", "python", "return redirect(\"/home\" if not nxt else nxt)", true),
        ("ast.open-redirect", "python", "return redirect(nxt or \"/home\")", true),
        ("ast.open-redirect", "python", "return redirect(\"/notes/\" + str(i) or nxt)", true),
        ("ast.open-redirect", "python", "return redirect(\"/home\" and nxt)", true),
        ("ast.open-redirect", "python", "return redirect((\"/home\" if ok else nxt))", true),
        ("ast.open-redirect", "python", "return redirect((\"/home\" if ok else \"/notes\"))", false),
        ("ast.open-redirect", "python", "return redirect((\"/home\" if ok else request.args[\"next\"]))", true),
        ("ast.open-redirect", "python", "return redirect(\"/%s\" % nxt)", true),
        ("ast.open-redirect", "python", "return redirect(\"/home\" if ok else \"/notes\")", false),
        ("ast.open-redirect", "python", "return redirect(\"/home\" if ok else url_for(\"index\"))", false),
        ("ast.open-redirect", "python", "return redirect(\"/notes/%d\" % note_id)", false),
        ("ast.open-redirect", "python", "return redirect(\"/caf%C3%A9/\" + slug)", false),
        ("ast.open-redirect", "javascript", "res.redirect(req.query.next ?? '/home')", true),
        ("ast.open-redirect", "javascript", "res.redirect(req.query.next || '/home')", true),
        ("ast.open-redirect", "javascript", "res.redirect('/home' && req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/notes/' + id || req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/notes/' + id ?? req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/notes/' + id || '/home')", false),
        ("ast.open-redirect", "javascript", "res.redirect(ok ? '/a' : req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect(ok ? '/a' : '/b/' + id)", false),
        ("ast.open-redirect", "python", "return redirect(\"/\" + next_url)", true),
        ("ast.open-redirect", "python", "return redirect(f\"/{next_url}\")", true),
        ("ast.open-redirect", "python", "return redirect(\"//\" + host)", true),
        ("ast.open-redirect", "javascript", "res.redirect(`/users/${id}`)", false),
        ("ast.open-redirect", "javascript", "res.redirect(`/${req.query.next}`)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/\\t/' + host)", true),
        // Python's subprocess handed a built command with shell=True, which `ast.shell-command`'s
        // names never reached (found testing the prompt library, 4 October 2026). Every function the
        // rule names, then the safe forms: a list and no shell, a fixed string, and shell=True with
        // the keyword it must be.
        ("ast.shell-command-shell-true", "python", "subprocess.run(f'notes-export \"{title}\" out.pdf', shell=True)", true),
        ("ast.shell-command-shell-true", "python", "subprocess.call('ls ' + folder, shell=True)", true),
        ("ast.shell-command-shell-true", "python", "subprocess.check_call(cmd, shell=True)", true),
        ("ast.shell-command-shell-true", "python", "out = subprocess.check_output('grep %s log' % word, shell=True)", true),
        ("ast.shell-command-shell-true", "python", "p = subprocess.Popen(command, shell=True, stdout=PIPE)", true),
        ("ast.shell-command-shell-true", "python", "run(f'convert {name}', check=True, shell=True)", true),
        ("ast.shell-command-shell-true", "python", "subprocess.run(['notes-export', title, 'out.pdf'])", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(['notes-export', title, 'out.pdf'], check=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(cmd, check=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run('ls -la', shell=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(cmd, shell=False)", false),
        ("ast.shell-command-shell-true", "python", "pool.map(cmd, shell=True)", false),
        ("ast.shell-command-shell-true", "javascript", "spawn(`recipe-pdf \"${title}\" out.pdf`, { shell: true })", true),
        ("ast.shell-command-shell-true", "javascript", "cp.execFile('recipe-pdf', [title, file], { shell: true }, done)", true),
        ("ast.shell-command-shell-true", "javascript", "child_process.spawnSync(cmd, { cwd: dir, shell: true })", true),
        ("ast.shell-command-shell-true", "javascript", "execFile('recipe-pdf', [title, file], done)", false),
        ("ast.shell-command-shell-true", "javascript", "spawn('ls -la', { shell: true })", false),
        // A fixed list of arguments is as fixed as a fixed string (the review of 1 to 4 October,
        // item 22): Python's grammar calls it a `list` or a `tuple`, JavaScript's an `array`.
        ("ast.shell-command-shell-true", "python", "subprocess.run(['ls', '-la'], shell=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(('ls', '-la'), shell=True)", false),
        ("ast.shell-command-shell-true", "python", "subprocess.run(['ls', folder], shell=True)", true),
        ("ast.shell-command-shell-true", "javascript", "spawn('ls', ['-la'], { shell: true })", false),
        ("ast.shell-command-shell-true", "typescript", "spawn('ls', ['-la'], { shell: true })", false),
        ("ast.shell-command-shell-true", "javascript", "spawn('ls', ['-la', dir], { shell: true })", true),
        ("ast.shell-command-shell-true", "javascript", "spawn(cmd, { shell: false })", false),
        ("ast.shell-command-shell-true", "javascript", "spawn(cmd, { detached: true })", false),
        ("ast.shell-command-shell-true", "typescript", "spawn(`convert ${name}`, { shell: true })", true),
        ("ast.shell-command-shell-true", "typescript", "execFile('convert', [name], { timeout: 5000 })", false),
        ("ast.shell-command-shell-true", "dart", "void f(String dir) { Process.run('ls', [dir], runInShell: true); }", true),
        ("ast.shell-command-shell-true", "dart", "void f() { Process.run('ls', ['-la'], runInShell: true); }", false),
        ("ast.shell-command-shell-true", "dart", "void f(String dir) { Process.run('ls', [dir]); }", false),
        ("ast.shell-command-shell-true", "dart", "void f(String dir) { Process.run('ls', [dir], includeParentEnvironment: true); }", false),
        ("ast.shell-command", "dart", "void f(String cmd) { Process.run('sh', ['-c', cmd]); }", true),
        ("ast.shell-command", "dart", "void f(String dir) { Process.run(\"/bin/bash\", [\"-c\", \"ls $dir\"]); }", true),
        ("ast.shell-command", "dart", "void f(String exe) { Process.start(exe, []); }", true),
        ("ast.shell-command", "dart", "void f() { Process.run('sh', ['-c', 'ls -la']); }", false),
        ("ast.shell-command", "dart", "void f(String branch) { Process.run('git', ['log', branch]); }", false),
        ("ast.shell-command", "dart", "void f(String cmd) { Pool.run('sh', ['-c', cmd]); }", false),
        ("ast.shell-command", "dart", "void f() { Process.run('sh', <String>['-c', 'ls -la']); }", false),
        ("ast.shell-command", "dart", "void f() { Process.runSync('/bin/sh', <String>['-c', 'date']); }", false),
        ("ast.shell-command", "swift", "func f() { task.arguments = [\"-c\", \"ls \" + \"-la\"] }", false),
        ("ast.shell-command", "swift", "func f(cmd: String) { task.arguments = [\"-c\", cmd] }", true),
        ("ast.shell-command", "swift", "func f(cmd: String) { let p = Process.launchedProcess(launchPath: \"/bin/sh\", arguments: [\"-c\", cmd]) }", true),
        ("ast.shell-command", "swift", "func f(cmd: String) { system(cmd) }", true),
        ("ast.shell-command", "swift", "func f() { task.arguments = [\"-c\", \"ls -la\"] }", false),
        ("ast.shell-command", "swift", "func f(name: String) { task.arguments = [\"log\", name] }", false),
        ("ast.shell-command", "swift", "func f() { system(\"ls\") }", false),
        ("ast.shell-command", "go", "func f(c string) { exec.Command(\"sh\", \"-c\", c).Run() }", true),
        ("ast.shell-command", "go", "func f(ctx context.Context, c string) { exec.CommandContext(ctx, \"bash\", \"-c\", c).Run() }", true),
        ("ast.shell-command", "go", "func f(name string) { exec.Command(name).Run() }", true),
        ("ast.shell-command", "go", "func f() { exec.Command(\"sh\", \"-c\", \"ls -la\").Run() }", false),
        ("ast.shell-command", "go", "func f(b string) { exec.Command(\"git\", \"log\", b).Run() }", false),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery(\"select * from notes where name = '$n'\");", true),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery('select * from notes where name = ' + n);", true),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery('select * from notes where name = ?', [n]);", false),
        ("ast.sql-built-by-hand", "dart", "Future f(String t) => db.query(t, where: 'id = ?', whereArgs: [1]);", false),
        ("ast.sql-built-by-hand", "dart", "Future f() => db.rawQuery('select * ' + 'from notes');", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) { sqlite3_exec(db, \"delete from notes where name = '\\(n)'\", nil, nil, nil) }", true),
        ("ast.sql-built-by-hand", "swift", "func f(q: String) throws { try db.execute(sql: q) }", true),
        ("ast.sql-built-by-hand", "swift", "func f() { sqlite3_exec(db, \"create table notes (name text)\", nil, nil, nil) }", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) throws { try db.execute(literal: \"insert into notes values (\\(n))\") }", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) throws { try db.execute(sql: \"insert into notes values (?)\", arguments: [n]) }", false),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) { let o = NSKeyedUnarchiver.unarchiveObject(with: d) }", true),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) throws { let o = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(d) }", true),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) throws { let o = try NSKeyedUnarchiver.unarchivedObject(ofClass: Note.self, from: d) }", false),
        ("ast.unsafe-deserialization", "javascript", "const obj = serialize.unserialize(req.cookies.profile)", true),
        ("ast.unsafe-deserialization", "javascript", "const obj = JSON.parse(req.cookies.profile)", false),
        ("ast.unsafe-deserialization", "typescript", "const obj = unserialize(req.body.data as string)", true),
        ("ast.unsafe-deserialization", "typescript", "const obj = JSON.parse(req.body.data as string)", false),
        ("ast.shell-command-backticks", "php", "<?php $out = `ls {$_GET['dir']}`;", true),
        ("ast.shell-command-backticks", "php", "<?php $out = `cat $file`;", true),
        ("ast.shell-command-backticks", "php", "<?php $out = `ls -la`;", false),
        ("ast.shell-command-backticks", "php", "<?php echo `whoami`;", false),
        ("ast.file-path-from-value", "dart", "Future f(Request r) => File(r.url.queryParameters['f']!).readAsString();", true),
        ("ast.file-path-from-value", "dart", "Future f(String name) => File('uploads/$name').readAsString();", true),
        ("ast.file-path-from-value", "dart", "Future f() => File('config.json').readAsString();", false),
        ("ast.file-path-from-value", "swift", "func f(p: String) { let d = FileManager.default.contents(atPath: p) }", true),
        ("ast.file-path-from-value", "swift", "func f(p: String) throws { let s = try String(contentsOfFile: p) }", true),
        ("ast.file-path-from-value", "swift", "func f() throws { let s = try String(contentsOfFile: \"/etc/app.conf\") }", false),
        ("ast.file-path-from-value", "swift", "func f(n: Int) { let s = String(describing: n) }", false),
        ("ast.file-path-from-value", "swift", "func f() throws { let d = try Data(contentsOf: URL(fileURLWithPath: \"/etc/app.conf\")) }", false),
        ("ast.file-path-from-value", "kotlin", "fun f(name: String) { val t = File(name).readText() }", true),
        ("ast.file-path-from-value", "kotlin", "fun f() { val t = File(\"app.conf\").readText() }", false),
        ("ast.file-path-from-value", "rust", "fn f(p: &str) { let t = fs::read_to_string(p); }", true),
        ("ast.file-path-from-value", "rust", "fn f(p: String) { let t = File::open(&p); }", true),
        ("ast.file-path-from-value", "rust", "fn f() { let t = File::open(\"app.toml\"); }", false),
        ("ast.file-path-from-value", "rust", "fn f(p: &str) { let t = Path::new(p); }", false),
        ("ast.file-path-from-value", "rust", "fn f() { let t = File::open(env!(\"CARGO_MANIFEST_DIR\")); }", false),
        ("ast.file-path-from-value", "rust", "fn f() { let t = fs::read_to_string(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/data.json\")); }", false),
        ("ast.file-path-from-value", "rust", "fn f() { let t = File::open(std::env!(\"OUT_DIR\")); }", false),
        ("ast.file-path-from-value", "rust", "fn f(dir: &str) { let t = File::open(format!(\"{}/data.json\", dir)); }", true),
        ("ast.file-path-from-value", "c", "void f(const char *p) { FILE *fp = fopen(p, \"r\"); }", true),
        ("ast.file-path-from-value", "c", "void f(void) { FILE *fp = fopen(\"/etc/app.conf\", \"r\"); }", false),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &p) { FILE *fp = fopen(p.c_str(), \"r\"); }", true),
        ("ast.file-path-from-value", "cpp", "void f() { FILE *fp = fopen(\"/etc/app.conf\", \"r\"); }", false),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => md5.convert(b).toString();", true),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => sha1.convert(b).toString();", true),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => sha256.convert(b).toString();", false),
        ("ast.weak-hash-function", "swift", "func f(d: Data) { let h = Insecure.MD5.hash(data: d) }", true),
        ("ast.weak-hash-function", "swift", "func f(p: UnsafeRawPointer, n: CC_LONG) { CC_SHA1(p, n, &out) }", true),
        ("ast.weak-hash-function", "swift", "func f(d: Data) { let h = SHA256.hash(data: d) }", false),
        ("ast.weak-hash-function", "swift", "func f(p: UnsafeRawPointer, n: CC_LONG) { CC_SHA256(p, n, &out) }", false),
        ("ast.weak-hash-function", "rust", "fn f(b: &[u8]) { let d = md5::compute(b); }", true),
        ("ast.weak-hash-function", "rust", "fn f() { let h = Sha1::new(); }", true),
        ("ast.weak-hash-function", "rust", "fn f() { let h = Sha256::new(); }", false),
        ("ast.weak-hash-function", "c", "void f(const unsigned char *d, size_t n, unsigned char *o) { MD5(d, n, o); }", true),
        ("ast.weak-hash-function", "c", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha1(), NULL); }", true),
        ("ast.weak-hash-function", "c", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha256(), NULL); }", false),
        ("ast.weak-hash-function", "cpp", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha1(), nullptr); }", true),
        ("ast.weak-hash-function", "cpp", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha256(), nullptr); }", false),
        ("ast.weak-cipher", "dart", "final e = Encrypter(AES(key, mode: AESMode.ecb));", true),
        ("ast.weak-cipher", "dart", "final c = ECBBlockCipher(AESEngine());", true),
        ("ast.weak-cipher", "dart", "final e = Encrypter(AES(key, mode: AESMode.gcm));", false),
        ("ast.weak-cipher", "swift", "func f() { let s = CCCrypt(op, CCAlgorithm(kCCAlgorithmDES), 0, k, n, nil, i, m, o, l, &w) }", true),
        ("ast.weak-cipher", "swift", "func f() throws { let a = try AES(key: k, blockMode: ECB()) }", true),
        ("ast.weak-cipher", "swift", "func f() throws { let b = try AES.GCM.seal(d, using: key) }", false),
        ("ast.weak-cipher", "swift", "func f() { let s = CCCrypt(op, CCAlgorithm(kCCAlgorithmAES), 0, k, n, iv, i, m, o, l, &w) }", false),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, k, NULL); }", true),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_des_ede3_cbc(), NULL, k, iv); }", true),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, iv); }", false),
        ("ast.weak-cipher", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), nullptr, k, nullptr); }", true),
        ("ast.weak-cipher", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, k, iv); }", false),
        ("ast.open-redirect", "dart", "Response f(Request r) => Response.found(r.url.queryParameters['next']!);", true),
        ("ast.open-redirect", "dart", "void f(HttpRequest r, String next) { r.response.redirect(Uri.parse(next)); }", true),
        ("ast.open-redirect", "dart", "Response f() => Response.found('/login');", false),
        ("ast.open-redirect", "dart", "void f(HttpRequest r) { r.response.redirect(Uri.parse('/home')); }", false),
        ("ast.open-redirect", "swift", "func f(req: Request, next: String) -> Response { return req.redirect(to: next) }", true),
        ("ast.open-redirect", "swift", "func f(req: Request) -> Response { return req.redirect(to: \"/login\") }", false),
        ("ast.open-redirect", "swift", "func f(req: Request, next: String) -> Response { return req.redirect(to: \"/r/\\(next)\") }", true),
        ("ast.open-redirect", "kotlin", "fun f(next: String) { call.respondRedirect(next) }", true),
        ("ast.open-redirect", "kotlin", "fun f() { call.respondRedirect(\"/login\") }", false),
        ("ast.open-redirect", "rust", "async fn f(q: Query<Next>) -> Redirect { Redirect::to(&q.next) }", true),
        ("ast.open-redirect", "rust", "async fn f() -> Redirect { Redirect::to(\"/login\") }", false),
        // Shell scripts.
        ("ast.dynamic-code-execution", "shell", "eval \"$1\"", true),
        ("ast.dynamic-code-execution", "shell", "eval \"set -- $ARGS\"", true),
        ("ast.dynamic-code-execution", "shell", "eval 'export PATH=/opt/bin:$PATH'", false),
        ("ast.dynamic-code-execution", "shell", "eval \"$(ssh-agent -s)\"", false),
        ("ast.shell-command", "shell", "sh -c \"ls $dir\"", true),
        ("ast.shell-command", "shell", "/bin/bash -c \"$1\"", true),
        ("ast.shell-command", "shell", "bash -c 'ls -la'", false),
        ("ast.shell-command", "shell", "sh -c \"echo \\$HOME\"", false),
        ("ast.shell-command", "shell", "ls -c \"$dir\"", false),
        // A bare word, a `${…}`, a `$(…)`, and quoting mixed within one argument.
        ("ast.shell-command", "shell", "bash -c date", false),
        ("ast.sql-built-by-hand", "shell", "psql -c VACUUM", false),
        ("ast.shell-command", "shell", "sh -c \"ls \"'-la'", false),
        ("ast.sql-built-by-hand", "shell", "psql -c 'select '\"count(*)\"' from notes'", false),
        ("ast.dynamic-code-execution", "shell", "eval \"${CMD}\"", true),
        ("ast.shell-command", "shell", "sh -c \"rm -rf ${dir}\"", true),
        ("ast.shell-command", "shell", "sh -c \"ls $(cat dirs.txt)\"", true),
        ("ast.dynamic-code-execution", "shell", "eval \"$(cat script.txt)\"", true),
        ("ast.sql-built-by-hand", "shell", "psql -c \"select * from notes where name = '$1'\"", true),
        ("ast.sql-built-by-hand", "shell", "sqlite3 app.db \"delete from notes where id = $ID\"", true),
        ("ast.sql-built-by-hand", "shell", "psql -c 'select count(*) from notes'", false),
        ("ast.sql-built-by-hand", "shell", "psql -h \"$HOST\" -d notes", false),
        ("ast.file-path-from-value", "shell", "cat \"/srv/files/$QUERY_STRING\"", true),
        ("ast.file-path-from-value", "shell", "rm -f /tmp/upload${PATH_INFO}", true),
        ("ast.file-path-from-value", "shell", "cat \"$CONFIG_FILE\"", false),
        ("ast.file-path-from-value", "shell", "echo \"$QUERY_STRING\"", false),
        ("ast.file-path-from-value", "shell", "file=\"${QUERY_STRING#name=}\"\ncat \"/srv/files/$file\"\n", true),
        ("ast.file-path-from-value", "shell", "serve() {\n  local name\n  name=$(printf '%s' \"$PATH_INFO\" | tr -d '.')\n  rm -f \"/tmp/uploads/$name\"\n}\n", true),
        ("ast.file-path-from-value", "shell", "parse() {\n  target=\"$QUERY_STRING\"\n}\nserve() {\n  cat \"$target\"\n}\n", true),
        ("ast.file-path-from-value", "shell", "file=\"$CONFIG_DIR/app.conf\"\ncat \"$file\"\n", false),
        ("ast.file-path-from-value", "shell", "name=\"$QUERY_STRING\"\necho \"$name\"\n", false),
        ("ast.file-path-from-value", "shell", "log=\"/var/log/QUERY_STRING.log\"\ncat \"$log\"\n", false),
        ("ast.weak-hash-function", "shell", "md5sum release.tar.gz", true),
        ("ast.weak-hash-function", "shell", "openssl dgst -sha1 release.tar.gz", true),
        ("ast.weak-hash-function", "shell", "sha256sum -c release.sha256", false),
        ("ast.weak-hash-function", "shell", "openssl dgst -sha256 release.tar.gz", false),
        ("ast.weak-cipher", "shell", "openssl enc -des3 -in secrets.txt -out secrets.enc", true),
        ("ast.weak-cipher", "shell", "openssl enc -aes-128-ecb -in a -out b", true),
        ("ast.weak-cipher", "shell", "openssl enc -aes-256-cbc -pbkdf2 -in a -out b", false),
        ("ast.open-redirect", "shell", "echo \"Location: $QUERY_STRING\"", true),
        ("ast.open-redirect", "shell", "printf 'Location: %s\\r\\n\\r\\n' \"$next\"", true),
        ("ast.open-redirect", "shell", "echo \"Location: /login\"", false),
        ("ast.open-redirect", "shell", "echo \"Content-Type: $type\"", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sh", true),
        ("ast.download-piped-to-shell", "shell", "wget -qO- https://example.com/install | sudo bash -s -- -y", true),
        ("ast.download-piped-to-shell", "shell", "bash <(curl -s https://example.com/setup.sh)", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://example.com/key.gpg | sudo tee /etc/apt/keyrings/example.gpg", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsSLo install.sh https://example.com/install.sh && sha256sum -c install.sha256 && sh install.sh", false),
        ("ast.download-piped-to-shell", "shell", "cat notes.txt | sh", false),
        // The interpreter runs the download only when it takes its program from standard input
        // (cato-pipeline's finding, 28 September 2026). These still run it:
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | bash", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sh -s", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | bash -x -s -- --yes", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sh -s stable", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | python3", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | python3 -", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | python3 -u", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | node -", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | perl", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sudo -E sh", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | /usr/bin/bash", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | FOO=1 bash", true),
        // And these read it as data, with the program given another way:
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | python3 -c 'import sys, json; print(json.load(sys.stdin)[\"id\"])'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | python3 -m json.tool", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | python3 parse.py", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | /usr/bin/python3 -I -c 'print(1)'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | sh -c 'wc -l'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | bash -ec 'wc -l'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | bash count.sh", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | perl -ne 'print if /id/'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | ruby -e 'puts STDIN.read.size'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | node -e 'process.stdin.pipe(process.stdout)'", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://api.example.com/x | sudo python3 parse.py", false),
        // An interpreter's name as an argument to something else is not the interpreter.
        ("ast.download-piped-to-shell", "shell", "curl -fsS https://example.com/langs.txt | grep -i python", false),
        // The last three a rule had not been taught.
        ("ast.shell-command", "rust", "fn f(c: &str) { Command::new(\"sh\").arg(\"-c\").arg(c).output(); }", true),
        ("ast.shell-command", "rust", "fn f(c: &str) { Command::new(\"/bin/bash\").args([\"-c\", c]).status(); }", true),
        ("ast.shell-command", "rust", "fn f(c: &str) { std::process::Command::new(\"sh\").args(&[\"-c\", c]).spawn(); }", true),
        ("ast.shell-command", "rust", "fn f(exe: &str) { Command::new(exe).spawn(); }", true),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"sh\").arg(\"-c\").arg(\"ls -la\").output(); }", false),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"sh\").args([\"-c\", \"ls -la\"]).output(); }", false),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"bash\").args(&[\"-c\", \"date\"]).output(); }", false),
        ("ast.shell-command", "rust", "fn f(b: &str) { Command::new(\"git\").arg(\"log\").arg(b).output(); }", false),
        ("ast.shell-command", "rust", "fn f(b: &str) { Command::new(\"git\").args([\"log\", b]).output(); }", false),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::des_ede3_cbc(); }", true),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::aes_128_ecb(); }", true),
        ("ast.weak-cipher", "rust", "fn f(k: &[u8]) { let c = TdesEde3::new_from_slice(k); }", true),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let e = ecb::Encryptor::<Aes128>::new(k); }", true),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::aes_256_gcm(); }", false),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let e = cbc::Encryptor::<Aes128>::new(k, iv); }", false),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let c = Aes256Gcm::new(k); }", false),
        ("ast.open-redirect", "c", "void f(const char *u) { printf(\"Location: %s\\r\\n\\r\\n\", u); }", true),
        ("ast.open-redirect", "c", "void f(const char *u) { fprintf(stdout, \"Location: %s\\n\\n\", u); }", true),
        ("ast.open-redirect", "c", "void f(void) { printf(\"Location: /login\\n\\n\"); }", false),
        ("ast.open-redirect", "c", "void f(void) { printf(\"Location: %s\\n\\n\", \"/login\"); }", false),
        ("ast.open-redirect", "c", "void f(const char *t) { printf(\"Content-Type: %s\\n\\n\", t); }", false),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { printf(\"Location: %s\\r\\n\\r\\n\", u.c_str()); }", true),
        ("ast.open-redirect", "cpp", "void f() { printf(\"Location: /login\\n\\n\"); }", false),
        ("ast.sql-built-by-hand", "c", "void f(sqlite3 *db, const char *q) { sqlite3_exec(db, q, 0, 0, 0); }", true),
        ("ast.sql-built-by-hand", "c", "void f(sqlite3 *db) { sqlite3_exec(db, \"SELECT 1\", 0, 0, 0); }", false),
        ("ast.sql-built-by-hand", "c", "void f(PGconn *c, const char *q) { PQexec(c, q); }", true),
        ("ast.sql-built-by-hand", "c", "void f(MYSQL *c) { mysql_query(c, \"SELECT 1\"); }", false),
        ("ast.shell-command", "cpp", "void f(const std::string &c) { std::system(c.c_str()); }", true),
        ("ast.shell-command", "cpp", "void f(const char *c) { ::system(c); }", true),
        ("ast.shell-command", "cpp", "void f() { std::system(\"ls -l\"); }", false),
        ("ast.shell-command", "cpp", "void f(const std::string &m) { Logger::system(m); }", false),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &p) { FILE *fp = std::fopen(p.c_str(), \"r\"); }", true),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &p) { std::remove(p.c_str()); }", true),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &p) { std::filesystem::remove(p); }", true),
        ("ast.file-path-from-value", "cpp", "void f(const char *p) { ::unlink(p); }", true),
        ("ast.file-path-from-value", "cpp", "void f(const std::string &k) { Cache::remove(k); }", false),
        ("ast.sql-built-by-hand", "cpp", "void f(sqlite3 *db, const std::string &q) { ::sqlite3_exec(db, q.c_str(), nullptr, nullptr, nullptr); }", true),
        ("ast.sql-built-by-hand", "cpp", "void f(sqlite3 *db) { ::sqlite3_exec(db, \"SELECT 1\", nullptr, nullptr, nullptr); }", false),
        ("ast.weak-hash-function", "cpp", "void f(const unsigned char *d, size_t n, unsigned char *o) { ::MD5(d, n, o); }", true),
        ("ast.weak-hash-function", "cpp", "void f(const std::string &d) { Hasher::MD5(d); }", false),
        ("ast.weak-cipher", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, ::EVP_des_ede3_cbc(), nullptr, k, iv); }", true),
        ("ast.unauthenticated-encryption", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, ::EVP_aes_256_cbc(), nullptr, k, iv); }", true),
        ("ast.digest-compared-with-equals", "cpp", "bool f(const unsigned char *mac, const unsigned char *expected) { return std::memcmp(mac, expected, 32) == 0; }", true),
        ("ast.digest-compared-with-equals", "cpp", "bool f(const char *buf, const char *other) { return std::memcmp(buf, other, 8) == 0; }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f(const char *pw, const unsigned char *s, unsigned char *o) { ::PKCS5_PBKDF2_HMAC(pw, 8, s, 16, 1000, EVP_sha256(), 32, o); }", true),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { std::printf(\"Location: %s\\r\\n\\r\\n\", u.c_str()); }", true),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { std::cout << \"Location: \" << u << \"\\r\\n\\r\\n\"; }", true),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { cout << \"Location: \" << u; }", true),
        ("ast.open-redirect", "cpp", "void f() { std::cout << \"Location: /login\\r\\n\\r\\n\"; }", false),
        ("ast.open-redirect", "cpp", "void f() { std::cout << \"Location: \" << \"/login\"; }", false),
        ("ast.open-redirect", "cpp", "void f(const std::string &n) { std::cout << \"Hello: \" << n; }", false),
        ("ast.open-redirect", "cpp", "void f(const std::string &u) { std::cerr << \"Location: \" << u; }", false),
        // Two false alarms from the owner's first build (27 September 2026): a regular expression's
        // `exec` read as a shell command, and a test client's `.query({...})` read as SQL.
        ("ast.shell-command", "javascript", "const m = re.exec(code);", false),
        ("ast.shell-command", "javascript", "const m = /id=(\\d+)/.exec(line);", false),
        ("ast.shell-command", "javascript", "child_process.exec('ls ' + dir);", true),
        ("ast.shell-command", "javascript", "cp.execSync(`rm -rf ${target}`);", true),
        ("ast.shell-command", "javascript", "require('child_process').exec(cmd);", true),
        ("ast.shell-command", "javascript", "const { exec } = require('child_process'); exec(cmd);", true),
        ("ast.shell-command", "typescript", "const m: RegExpExecArray | null = pattern.exec(input);", false),
        ("ast.shell-command", "typescript", "childProcess.exec(`git log ${ref}`);", true),
        ("ast.sql-built-by-hand", "javascript", "await request(app).get('/').query({ q: term });", false),
        ("ast.sql-built-by-hand", "javascript", "db.query('SELECT * FROM t WHERE id = ' + id);", true),
        ("ast.sql-built-by-hand", "javascript", "await this.pool.query(`DELETE FROM notes WHERE id = ${id}`);", true),
        ("ast.sql-built-by-hand", "typescript", "await request(app).post('/search').query({ term });", false),
        ("ast.sql-built-by-hand", "typescript", "await db!.query(`SELECT * FROM t WHERE name = '${name}'`);", true),
        // Encryption that keeps data secret and cannot show it was changed (V11.3.3). ECB and the
        // retired ciphers are ast.weak-cipher's; these are the modes left once those are gone.
        ("ast.unauthenticated-encryption", "python", "cipher = AES.new(key, AES.MODE_CBC, iv)", true),
        ("ast.unauthenticated-encryption", "python", "c = Cipher(algorithms.AES(key), modes.CTR(nonce))", true),
        ("ast.unauthenticated-encryption", "python", "cipher = AES.new(key, AES.MODE_GCM)", false),
        ("ast.unauthenticated-encryption", "python", "c = Cipher(algorithms.AES(key), modes.GCM(iv))", false),
        ("ast.unauthenticated-encryption", "javascript", "crypto.createCipheriv('aes-256-cbc', key, iv)", true),
        ("ast.unauthenticated-encryption", "javascript", "crypto.createCipheriv('aes-256-gcm', key, iv)", false),
        ("ast.unauthenticated-encryption", "typescript", "crypto.createDecipheriv(\"aes-128-ctr\", key, iv)", true),
        ("ast.unauthenticated-encryption", "typescript", "crypto.createCipheriv(\"chacha20-poly1305\", key, iv)", false),
        ("ast.unauthenticated-encryption", "go", "mode := cipher.NewCBCEncrypter(block, iv)", true),
        ("ast.unauthenticated-encryption", "go", "stream := cipher.NewCTR(block, iv)", true),
        ("ast.unauthenticated-encryption", "go", "aead, err := cipher.NewGCM(block)", false),
        ("ast.unauthenticated-encryption", "php", "<?php openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);", true),
        ("ast.unauthenticated-encryption", "php", "<?php openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);", false),
        ("ast.unauthenticated-encryption", "ruby", "c = OpenSSL::Cipher.new('aes-256-cbc')", true),
        ("ast.unauthenticated-encryption", "ruby", "c = OpenSSL::Cipher.new('aes-256-gcm')", false),
        ("ast.unauthenticated-encryption", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES/CBC/PKCS5Padding\"); } }", true),
        ("ast.unauthenticated-encryption", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES/GCM/NoPadding\"); } }", false),
        ("ast.unauthenticated-encryption", "csharp", "class A { void F(Aes a) { a.Mode = CipherMode.CBC; } }", true),
        ("ast.unauthenticated-encryption", "csharp", "class A { void F(byte[] k) { var g = new AesGcm(k); } }", false),
        ("ast.unauthenticated-encryption", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/CTR/NoPadding\") }", true),
        ("ast.unauthenticated-encryption", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/GCM/NoPadding\") }", false),
        ("ast.unauthenticated-encryption", "dart", "final e = Encrypter(AES(key, mode: AESMode.cbc));", true),
        ("ast.unauthenticated-encryption", "dart", "final c = CBCBlockCipher(AESEngine());", true),
        ("ast.unauthenticated-encryption", "dart", "final e = Encrypter(AES(key, mode: AESMode.gcm));", false),
        ("ast.unauthenticated-encryption", "swift", "func f() throws { let a = try AES(key: k, blockMode: CBC(iv: iv)) }", true),
        ("ast.unauthenticated-encryption", "swift", "func f() throws { let b = try AES.GCM.seal(d, using: key) }", false),
        ("ast.unauthenticated-encryption", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, k, iv); }", true),
        ("ast.unauthenticated-encryption", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, iv); }", false),
        ("ast.unauthenticated-encryption", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), nullptr, k, iv); }", true),
        ("ast.unauthenticated-encryption", "cpp", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, k, iv); }", false),
        ("ast.unauthenticated-encryption", "rust", "fn f() { let c = Cipher::aes_256_cbc(); }", true),
        ("ast.unauthenticated-encryption", "rust", "fn f(k: &Key) { let e = cbc::Encryptor::<Aes128>::new(k, iv); }", true),
        ("ast.unauthenticated-encryption", "rust", "fn f() { let c = Cipher::aes_256_gcm(); }", false),
        ("ast.unauthenticated-encryption", "rust", "fn f(k: &Key) { let c = Aes256Gcm::new(k); }", false),
        ("ast.unauthenticated-encryption", "shell", "openssl enc -aes-256-cbc -pbkdf2 -in a -out b", true),
        ("ast.unauthenticated-encryption", "shell", "openssl enc -aes-256-ctr -in a -out b", true),
        ("ast.unauthenticated-encryption", "shell", "openssl dgst -sha256 report.txt", false),
        // Four forms the path and redirect rules missed.
        ("ast.open-redirect", "javascript", "res.redirect(301, req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.redirect(301, '/home')", false),
        ("ast.open-redirect", "typescript", "res.redirect(302, req.body.returnTo)", true),
        ("ast.open-redirect", "typescript", "res.redirect(302, \"/login\")", false),
        ("ast.file-path-from-value", "ruby", "send_file params[:path]", true),
        ("ast.file-path-from-value", "ruby", "send_file(params[:name], disposition: 'attachment')", true),
        ("ast.file-path-from-value", "ruby", "send_file 'public/terms.pdf'", false),
        ("ast.file-path-from-value", "ruby", "send_file Rails.root.join('public', 'report.pdf')", false),
        ("ast.file-path-from-value", "ruby", "send_message params[:text]", false),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { Path p = Paths.get(n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { Path p = Path.of(\"uploads\", n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f() { Path p = Path.of(\"uploads\", \"a.txt\"); } }", false),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { Path p = Path.of(n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f() { Path p = Paths.get(\"app.properties\"); } }", false),
        ("ast.file-path-from-value", "java", "class A { void f(java.util.Map<String, String> m, String n) { m.get(n); } }", false),
        ("ast.file-path-from-value", "php", "<?php include $_GET['page'];", true),
        ("ast.file-path-from-value", "php", "<?php require_once($page);", true),
        ("ast.file-path-from-value", "php", "<?php include 'header.php';", false),
        ("ast.file-path-from-value", "php", "<?php require_once __DIR__ . '/config.php';", false),
        ("ast.file-path-from-value", "php", "<?php require_once(dirname(__FILE__) . '/lib.php');", false),
        // The H5 follow-up: five differences from a second build of H5, ported onto its rules.
        // (a) `new URL("/path", base)` stays on the site only when the base is the request's own address.
        ("ast.open-redirect", "javascript", "return NextResponse.redirect(new URL('/login', req.query.next))", true),
        ("ast.open-redirect", "javascript", "return NextResponse.redirect(new URL('/login', request.url))", false),
        ("ast.open-redirect", "typescript", "return NextResponse.redirect(new URL('/account', searchParams.get('base')!))", true),
        ("ast.open-redirect", "typescript", "return NextResponse.redirect(new URL(\"/\", req.nextUrl))", false),
        ("ast.open-redirect", "typescript", "return NextResponse.redirect(new URL('/login', next))", true),
        // (b) The other frameworks' and the browser's redirects.
        ("ast.open-redirect", "javascript", "permanentRedirect(params.to)", true),
        ("ast.open-redirect", "javascript", "permanentRedirect('/new-home')", false),
        ("ast.open-redirect", "typescript", "permanentRedirect(params.to as string)", true),
        ("ast.open-redirect", "typescript", "permanentRedirect(`/posts/${post.id}`)", false),
        ("ast.open-redirect", "javascript", "return Response.redirect(url.searchParams.get('to'), 302)", true),
        ("ast.open-redirect", "javascript", "return Response.redirect('https://example.com/', 301)", false),
        ("ast.open-redirect", "typescript", "return Response.redirect(url.searchParams.get('to')!, 302)", true),
        ("ast.open-redirect", "typescript", "return Response.redirect('https://example.com/', 301)", false),
        ("ast.open-redirect", "javascript", "res.location(req.query.next)", true),
        ("ast.open-redirect", "javascript", "res.location('/ok')", false),
        ("ast.open-redirect", "typescript", "res.location(req.query.next as string)", true),
        ("ast.open-redirect", "typescript", "res.location('/ok')", false),
        ("ast.open-redirect", "javascript", "document.location = params.get('next')", true),
        ("ast.open-redirect", "javascript", "document.location = '/home'", false),
        ("ast.open-redirect", "typescript", "top.location.href = next", true),
        ("ast.open-redirect", "typescript", "self.location.href = '/home'", false),
        ("ast.open-redirect", "javascript", "throw redirect(303, url.searchParams.get('redirectTo'))", true),
        ("ast.open-redirect", "javascript", "throw redirect(303, '/login')", false),
        ("ast.open-redirect", "typescript", "throw redirect(303, url.searchParams.get('redirectTo') ?? '/')", true),
        ("ast.open-redirect", "typescript", "throw redirect(303, '/login')", false),
        // (c) A string called `location` has a `replace` of its own; the browser's `location` on `window` is the redirect.
        ("ast.open-redirect", "javascript", "const slug = location.replace(/\\s+/g, '-')", false),
        ("ast.open-redirect", "javascript", "window.location.replace(next)", true),
        ("ast.open-redirect", "typescript", "const city = location.replace(old, fresh)", false),
        ("ast.open-redirect", "typescript", "document.location.replace(next)", true),
        ("ast.open-redirect", "javascript", "location.assign(next)", true),
        ("ast.open-redirect", "typescript", "location.assign('/')", false),
        // (d) The folder the app was started from, and the ES module's own folder, are the app's own.
        ("ast.file-path-from-value", "typescript", "const md = await readFile(path.join(process.cwd(), 'posts', params.slug + '.md'), 'utf8')", true),
        ("ast.file-path-from-value", "typescript", "const md = await readFile(path.join(process.cwd(), 'posts', 'about.md'), 'utf8')", false),
        ("ast.file-path-from-value", "javascript", "const t = await readFile(path.join(process.cwd(), req.query.name))", true),
        ("ast.file-path-from-value", "javascript", "const t = await readFile(path.join(process.cwd(), 'content', 'index.md'))", false),
        ("ast.file-path-from-value", "javascript", "createReadStream(path.join(import.meta.dirname, req.params.file)).pipe(res)", true),
        ("ast.file-path-from-value", "javascript", "createReadStream(path.join(import.meta.dirname, 'public', 'app.js')).pipe(res)", false),
        ("ast.file-path-from-value", "typescript", "const s = readFileSync(new URL(name, import.meta.url), 'utf8')", true),
        ("ast.file-path-from-value", "typescript", "const s = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8')", false),
        ("ast.file-path-from-value", "javascript", "const s = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8')", false),
        // WebSocket addresses written into the code.
        // Tokens and passwords written into the browser's storage (6 October 2026).
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('token', data.token);", true),
        ("ast.token-in-browser-storage", "javascript", "window.localStorage.setItem(\"accessToken\", res.access_token);", true),
        ("ast.token-in-browser-storage", "javascript", "sessionStorage.setItem(`refresh_token`, r);", true),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('auth', JSON.stringify(session));", true),
        ("ast.token-in-browser-storage", "javascript", "localStorage['jwt'] = jwt;", true),
        ("ast.token-in-browser-storage", "javascript", "localStorage.idToken = t;", true),
        ("ast.token-in-browser-storage", "javascript", "document.cookie = `token=${t}; path=/`;", true),
        ("ast.token-in-browser-storage", "javascript", "document.cookie = 'access=' + t;", true),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('theme', 'dark');", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('csrfToken', c);", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('fcmToken', pushToken);", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('tokenExpiresAt', String(exp));", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.setItem('author', name);", false),
        ("ast.token-in-browser-storage", "javascript", "const t = localStorage.getItem('token');", false),
        ("ast.token-in-browser-storage", "javascript", "cache.setItem('token', t);", false),
        ("ast.token-in-browser-storage", "javascript", "localStorage.removeItem('token');", false),
        ("ast.password-in-browser-storage", "javascript", "localStorage.setItem('password', form.password);", true),
        ("ast.password-in-browser-storage", "javascript", "sessionStorage.setItem(\"userPassword\", pw);", true),
        ("ast.password-in-browser-storage", "javascript", "localStorage.pwd = pw;", true),
        ("ast.password-in-browser-storage", "javascript", "sessionStorage['password'] = pw;", true),
        ("ast.password-in-browser-storage", "javascript", "document.cookie = 'password=' + pw;", true),
        ("ast.password-in-browser-storage", "javascript", "localStorage.setItem('showPassword', 'true');", false),
        ("ast.password-in-browser-storage", "javascript", "localStorage.setItem('passwordStrength', score);", false),
        ("ast.password-in-browser-storage", "javascript", "localStorage.setItem('rememberPassword', '1');", false),
        ("ast.password-in-browser-storage", "javascript", "const p = localStorage.getItem('password');", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('token', data.token);", true),
        ("ast.token-in-browser-storage", "typescript", "window.localStorage.setItem(\"accessToken\", res.access_token);", true),
        ("ast.token-in-browser-storage", "typescript", "sessionStorage.setItem(`refresh_token`, r);", true),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('auth', JSON.stringify(session));", true),
        ("ast.token-in-browser-storage", "typescript", "localStorage['jwt'] = jwt;", true),
        ("ast.token-in-browser-storage", "typescript", "localStorage.idToken = t;", true),
        ("ast.token-in-browser-storage", "typescript", "document.cookie = `token=${t}; path=/`;", true),
        ("ast.token-in-browser-storage", "typescript", "document.cookie = 'access=' + t;", true),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('theme', 'dark');", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('csrfToken', c);", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('fcmToken', pushToken);", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('tokenExpiresAt', String(exp));", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.setItem('author', name);", false),
        ("ast.token-in-browser-storage", "typescript", "const t = localStorage.getItem('token');", false),
        ("ast.token-in-browser-storage", "typescript", "cache.setItem('token', t);", false),
        ("ast.token-in-browser-storage", "typescript", "localStorage.removeItem('token');", false),
        ("ast.password-in-browser-storage", "typescript", "localStorage.setItem('password', form.password);", true),
        ("ast.password-in-browser-storage", "typescript", "sessionStorage.setItem(\"userPassword\", pw);", true),
        ("ast.password-in-browser-storage", "typescript", "localStorage.pwd = pw;", true),
        ("ast.password-in-browser-storage", "typescript", "sessionStorage['password'] = pw;", true),
        ("ast.password-in-browser-storage", "typescript", "document.cookie = 'password=' + pw;", true),
        ("ast.password-in-browser-storage", "typescript", "localStorage.setItem('showPassword', 'true');", false),
        ("ast.password-in-browser-storage", "typescript", "localStorage.setItem('passwordStrength', score);", false),
        ("ast.password-in-browser-storage", "typescript", "localStorage.setItem('rememberPassword', '1');", false),
        ("ast.password-in-browser-storage", "typescript", "const p = localStorage.getItem('password');", false),
        ("ast.plaintext-websocket-url", "python", "ws = create_connection(\"ws://chat.example.com/live\")", true),
        ("ast.plaintext-websocket-url", "python", "ws = create_connection(\"wss://chat.example.com/live\")", false),
        ("ast.plaintext-websocket-url", "python", "ws = create_connection('ws://localhost:8765')", false),
        ("ast.plaintext-websocket-url", "javascript", "const s = new WebSocket('ws://chat.example.com/socket')", true),
        ("ast.plaintext-websocket-url", "javascript", "const s = new WebSocket(`wss://${location.host}/socket`)", false),
        ("ast.plaintext-websocket-url", "javascript", "const s = new WebSocket(`ws://${host}/socket`)", false),
        ("ast.plaintext-websocket-url", "javascript", "const u = url.replace('ws://', 'wss://')", false),
        ("ast.plaintext-websocket-url", "javascript", "const s = new WebSocket('ws://127.0.0.1:3000')", false),
        ("ast.plaintext-websocket-url", "typescript", "const s: WebSocket = new WebSocket(\"ws://feed.example.org\")", true),
        ("ast.plaintext-websocket-url", "typescript", "const s: WebSocket = new WebSocket(\"wss://feed.example.org\")", false),
        ("ast.plaintext-websocket-url", "go", "c, _, err := websocket.DefaultDialer.Dial(\"ws://chat.example.com/ws\", nil)", true),
        ("ast.plaintext-websocket-url", "go", "c, _, err := websocket.DefaultDialer.Dial(\"wss://chat.example.com/ws\", nil)", false),
        ("ast.plaintext-websocket-url", "php", "<?php $c = new Client('ws://chat.example.com/socket');", true),
        ("ast.plaintext-websocket-url", "php", "<?php $c = new Client('wss://chat.example.com/socket');", false),
        ("ast.plaintext-websocket-url", "ruby", "ws = WebSocket::Client::Simple.connect 'ws://chat.example.com'", true),
        ("ast.plaintext-websocket-url", "ruby", "ws = WebSocket::Client::Simple.connect 'wss://chat.example.com'", false),
        ("ast.plaintext-websocket-url", "java", "class A { void f() throws Exception { new URI(\"ws://chat.example.com/ws\"); } }", true),
        ("ast.plaintext-websocket-url", "java", "class A { void f() throws Exception { new URI(\"wss://chat.example.com/ws\"); } }", false),
        ("ast.plaintext-websocket-url", "csharp", "class A { void F() { var u = new Uri(\"ws://chat.example.com/ws\"); } }", true),
        ("ast.plaintext-websocket-url", "csharp", "class A { void F() { var u = new Uri(\"wss://chat.example.com/ws\"); } }", false),
        ("ast.plaintext-websocket-url", "kotlin", "val request = Request.Builder().url(\"ws://chat.example.com/ws\").build()", true),
        ("ast.plaintext-websocket-url", "kotlin", "val request = Request.Builder().url(\"wss://chat.example.com/ws\").build()", false),
        ("ast.plaintext-websocket-url", "dart", "void f() { final c = WebSocketChannel.connect(Uri.parse('ws://chat.example.com/ws')); }", true),
        ("ast.plaintext-websocket-url", "dart", "void f() { final c = WebSocketChannel.connect(Uri.parse('wss://chat.example.com/ws')); }", false),
        ("ast.plaintext-websocket-url", "swift", "let url = URL(string: \"ws://chat.example.com/ws\")!", true),
        ("ast.plaintext-websocket-url", "swift", "let url = URL(string: \"wss://chat.example.com/ws\")!", false),
        ("ast.plaintext-websocket-url", "rust", "fn f() { let r = connect_async(\"ws://chat.example.com/ws\"); }", true),
        ("ast.plaintext-websocket-url", "rust", "fn f() { let r = connect_async(\"wss://chat.example.com/ws\"); }", false),
        ("ast.plaintext-websocket-url", "c", "void f(void) { lws_client_connect(\"ws://chat.example.com/ws\"); }", true),
        ("ast.plaintext-websocket-url", "c", "void f(void) { lws_client_connect(\"wss://chat.example.com/ws\"); }", false),
        ("ast.plaintext-websocket-url", "cpp", "void f() { lws_client_connect(\"ws://chat.example.com/ws\"); }", true),
        ("ast.plaintext-websocket-url", "cpp", "void f() { lws_client_connect(\"wss://chat.example.com/ws\"); }", false),
        ("ast.plaintext-websocket-url", "shell", "websocat ws://chat.example.com/ws", true),
        ("ast.plaintext-websocket-url", "shell", "websocat wss://chat.example.com/ws", false),
        ("ast.plaintext-websocket-url", "shell", "websocat ws://localhost:8080/ws", false),
        // Signatures compared with an ordinary equals.
        ("ast.digest-compared-with-equals", "python", "ok = hmac.new(k, body, hashlib.sha256).hexdigest() == sig", true),
        ("ast.digest-compared-with-equals", "python", "ok = sig != hmac.digest(k, body, 'sha256')", true),
        ("ast.digest-compared-with-equals", "python", "ok = hmac.compare_digest(hmac.new(k, body, hashlib.sha256).hexdigest(), sig)", false),
        ("ast.digest-compared-with-equals", "python", "ok = hashlib.sha256(body).hexdigest() == checksum", false),
        ("ast.digest-compared-with-equals", "javascript", "if (crypto.createHmac('sha256', k).update(b).digest('hex') === sig) { go(); }", true),
        ("ast.digest-compared-with-equals", "javascript", "if (sig !== createHmac('sha256', k).update(b).digest('hex')) { stop(); }", true),
        ("ast.digest-compared-with-equals", "javascript", "const ok = crypto.timingSafeEqual(crypto.createHmac('sha256', k).update(b).digest(), sig);", false),
        ("ast.digest-compared-with-equals", "javascript", "if (crypto.createHash('sha256').update(b).digest('hex') === sum) { go(); }", false),
        ("ast.digest-compared-with-equals", "typescript", "const ok: boolean = createHmac('sha256', k).update(b).digest('hex') == sig;", true),
        ("ast.digest-compared-with-equals", "typescript", "const ok: boolean = timingSafeEqual(createHmac('sha256', k).update(b).digest(), sig);", false),
        ("ast.digest-compared-with-equals", "php", "<?php if (hash_hmac('sha256', $body, $key) == $sig) { go(); }", true),
        ("ast.digest-compared-with-equals", "php", "<?php if (hash_equals(hash_hmac('sha256', $body, $key), $sig)) { go(); }", false),
        ("ast.digest-compared-with-equals", "ruby", "ok = OpenSSL::HMAC.hexdigest('SHA256', key, body) == sig", true),
        ("ast.digest-compared-with-equals", "ruby", "ok = Rack::Utils.secure_compare(OpenSSL::HMAC.hexdigest('SHA256', key, body), sig)", false),
        ("ast.digest-compared-with-equals", "go", "package m\nfunc f() bool { return bytes.Equal(mac.Sum(nil), sig) }", true),
        ("ast.digest-compared-with-equals", "go", "package m\nfunc f() bool { return hex.EncodeToString(mac.Sum(nil)) == sig }", true),
        ("ast.digest-compared-with-equals", "go", "package m\nfunc f() bool { return hmac.Equal(mac.Sum(nil), sig) }", false),
        ("ast.digest-compared-with-equals", "go", "package m\nfunc f() bool { return bytes.Equal(h.Sum(nil), want) }", false),
        ("ast.digest-compared-with-equals", "java", "class A { boolean f() { return Arrays.equals(mac.doFinal(body), sig); } }", true),
        ("ast.digest-compared-with-equals", "java", "class A { boolean f() { return Hex.encodeHexString(mac.doFinal(body)).equals(sig); } }", true),
        ("ast.digest-compared-with-equals", "java", "class A { boolean f() { return MessageDigest.isEqual(mac.doFinal(body), sig); } }", false),
        ("ast.digest-compared-with-equals", "kotlin", "fun f() = mac.doFinal(body).contentEquals(sig)", true),
        ("ast.digest-compared-with-equals", "kotlin", "fun f() = hex(mac.doFinal(body)) == sig", true),
        ("ast.digest-compared-with-equals", "kotlin", "fun f() = MessageDigest.isEqual(mac.doFinal(body), sig)", false),
        ("ast.digest-compared-with-equals", "csharp", "class A { bool F() { return hmac.ComputeHash(body).SequenceEqual(sig); } }", true),
        ("ast.digest-compared-with-equals", "csharp", "class A { bool F() { return Convert.ToHexString(HMACSHA256.HashData(key, body)) == sig; } }", true),
        ("ast.digest-compared-with-equals", "csharp", "class A { bool F() { return CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(body), sig); } }", false),
        ("ast.digest-compared-with-equals", "rust", "fn f() -> bool { mac.finalize().into_bytes().as_slice() == sig }", true),
        ("ast.digest-compared-with-equals", "rust", "fn f() -> bool { mac.verify_slice(sig).is_ok() }", false),
        ("ast.digest-compared-with-equals", "rust", "fn f() -> bool { hasher.finalize().as_slice() == want }", false),
        ("ast.digest-compared-with-equals", "c", "int f(void) { return memcmp(mac, sig, 32) == 0; }", true),
        ("ast.digest-compared-with-equals", "c", "int f(void) { return CRYPTO_memcmp(mac, sig, 32) == 0; }", false),
        ("ast.digest-compared-with-equals", "c", "int f(void) { return memcmp(buf, header, 4) == 0; }", false),
        ("ast.digest-compared-with-equals", "cpp", "bool f() { return memcmp(expected_mac, sig, 32) == 0; }", true),
        ("ast.digest-compared-with-equals", "cpp", "bool f() { return sodium_memcmp(expected_mac, sig, 32) == 0; }", false),
        ("ast.digest-compared-with-equals", "dart", "bool f() => Hmac(sha256, key).convert(body).toString() == sig;", true),
        ("ast.digest-compared-with-equals", "dart", "bool f() => sha256.convert(body).toString() == checksum;", false),
        ("ast.digest-compared-with-equals", "swift", "let ok = Data(HMAC<SHA256>.authenticationCode(for: body, using: key)) == sig", true),
        ("ast.digest-compared-with-equals", "swift", "let ok = HMAC<SHA256>.isValidAuthenticationCode(sig, authenticating: body, using: key)", false),
        // Model files loaded by a reader that can run code.
        ("ast.model-loaded-with-pickle", "python", "model = joblib.load('model.joblib')", true),
        ("ast.model-loaded-with-pickle", "python", "state = torch.load(path, weights_only=False)", true),
        ("ast.model-loaded-with-pickle", "python", "m = AutoModel.from_pretrained(name, trust_remote_code=True)", true),
        ("ast.model-loaded-with-pickle", "python", "state = torch.load(path, weights_only=True)", false),
        ("ast.model-loaded-with-pickle", "python", "settings = json.load(f)", false),
        // Models downloaded by name without a commit.
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained('bert-org/bert-base')", true),
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained('bert-org/bert-base', revision='main')", true),
        ("ast.model-download-not-pinned", "python", "p = hf_hub_download(repo_id='org/model', filename='w.safetensors')", true),
        ("ast.model-download-not-pinned", "python", "p = pipeline('text-generation', model='org/model')", true),
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained('bert-org/bert-base', revision='0123456789abcdef0123456789abcdef01234567')", false),
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained('./models/bert')", false),
        ("ast.model-download-not-pinned", "python", "m = AutoModel.from_pretrained(settings.model_dir)", false),
        ("ast.model-download-not-pinned", "javascript", "const p = await pipeline('sentiment-analysis', 'Xenova/distilbert');", true),
        ("ast.model-download-not-pinned", "javascript", "const p = await pipeline('sentiment-analysis', 'Xenova/distilbert', { revision: '0123456789abcdef0123456789abcdef01234567' });", false),
        ("ast.model-download-not-pinned", "typescript", "const p = await pipeline('sentiment-analysis', 'Xenova/distilbert');", true),
        ("ast.model-download-not-pinned", "typescript", "const p = await pipeline('sentiment-analysis', 'Xenova/distilbert', { revision: '0123456789abcdef0123456789abcdef01234567' });", false),
        // Hosted models asked for by a name that moves.
        ("ast.floating-model-name", "python", "r = client.messages.create(model='claude-3-5-sonnet-latest', messages=m)", true),
        ("ast.floating-model-name", "python", "r = client.messages.create(model='claude-sonnet-4-5-20250929', messages=m)", false),
        ("ast.floating-model-name", "python", "runner = 'ubuntu-latest'", false),
        ("ast.floating-model-name", "javascript", "const r = await openai.chat.completions.create({ model: 'chatgpt-4o-latest', messages });", true),
        ("ast.floating-model-name", "javascript", "const r = await openai.chat.completions.create({ model: 'gpt-4o-2024-08-06', messages });", false),
        ("ast.floating-model-name", "typescript", "const model: string = `gemini-flash-latest`;", true),
        ("ast.floating-model-name", "typescript", "const model: string = `gemini-2.5-flash`;", false),
        ("ast.floating-model-name", "go", "package m\nvar model = \"mistral-large-latest\"", true),
        ("ast.floating-model-name", "go", "package m\nvar model = \"mistral-large-2411\"", false),
        ("ast.floating-model-name", "ruby", "resp = client.chat(parameters: { model: \"llama3:latest\" })", true),
        ("ast.floating-model-name", "ruby", "resp = client.chat(parameters: { model: \"llama3:8b\" })", false),
        ("ast.floating-model-name", "php", "<?php $model = 'claude-3-opus-latest';", true),
        ("ast.floating-model-name", "php", "<?php $model = 'claude-3-opus-20240229';", false),
        ("ast.floating-model-name", "java", "class A { String model = \"gpt-4o-latest\"; }", true),
        ("ast.floating-model-name", "java", "class A { String model = \"gpt-4o\"; }", false),
        ("ast.floating-model-name", "csharp", "class A { string model = \"codestral-latest\"; }", true),
        ("ast.floating-model-name", "csharp", "class A { string model = \"codestral-2501\"; }", false),
        ("ast.floating-model-name", "kotlin", "val model = \"gpt-4o-latest\"", true),
        ("ast.floating-model-name", "kotlin", "val model = \"gpt-4o-2024-08-06\"", false),
        ("ast.floating-model-name", "dart", "const model = 'gemini-pro-latest';", true),
        ("ast.floating-model-name", "dart", "const model = 'gemini-2.5-pro';", false),
        ("ast.floating-model-name", "swift", "let model = \"claude-3-7-sonnet-latest\"", true),
        ("ast.floating-model-name", "swift", "let model = \"claude-3-7-sonnet-20250219\"", false),
        ("ast.floating-model-name", "rust", "fn f() { let model = \"mistral-small-latest\"; }", true),
        ("ast.floating-model-name", "rust", "fn f() { let model = \"mistral-small-2503\"; }", false),
        ("ast.floating-model-name", "c", "const char *model = \"llama3:latest\";", true),
        ("ast.floating-model-name", "c", "const char *model = \"llama3:8b\";", false),
        ("ast.floating-model-name", "cpp", "const char *model = \"qwen2.5:latest\";", true),
        ("ast.floating-model-name", "cpp", "const char *model = \"qwen2.5:7b\";", false),
        ("ast.floating-model-name", "shell", "ollama run llama3:latest", true),
        ("ast.floating-model-name", "shell", "docker pull node:latest", false),
        // A key made from a password with too few rounds: only a count written into the code, below
        // 210,000, and never a key length that sits in the same call.
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 1000)", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=100_000)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, settings.ROUNDS)", false),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=600000)", false),
        ("ast.weak-password-key-derivation", "python", "x = resize(img, w, h, 1000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha512', pw, salt, 209_999)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha512', pw, salt, 210_000)", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 10000, 32, 'sha256');", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.pbkdf2(pw, salt, 1000, 64, 'sha512', done);", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);", true),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 600000, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, ROUNDS, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);", false),
        // `deriveBits` takes the key's length third: 256 bits, not 256 rounds.
        ("ast.weak-password-key-derivation", "javascript", "const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, 256);", false),
        // Only the `iterations` key is the count, whatever other number sits beside it.
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', saltLength: 16, iterations: 600000, hash: 'SHA-256' }, base, aes, false, use);", false),
        ("ast.weak-password-key-derivation", "typescript", "const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' }, base, 256);", true),
        ("ast.weak-password-key-derivation", "typescript", "const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, 256);", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 1000, 32, 'sha256');", true),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 600_000, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "java", "class A { void f() { KeySpec s = new PBEKeySpec(pw, salt, 1000, 256); } }", true),
        ("ast.weak-password-key-derivation", "java", "class A { void f() { KeySpec s = new PBEKeySpec(pw, salt, 600000, 256); } }", false),
        ("ast.weak-password-key-derivation", "java", "class A { void f() { KeySpec s = new PBEKeySpec(pw, salt, rounds, 256); } }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 4096, 32, sha256.New) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 600_000, 32, sha256.New) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, n, 32, sha256.New) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := cache.Key(a, b, 100, 2) }", false),
        // The standard library's crypto/pbkdf2 (Go 1.24) takes the hash first and the count fourth.
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha256.New, pw, salt, 4096, 32) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha512.New, pw, salt, 100_000, keyLen) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha512.New, pw, salt, 210_000, 64) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha256.New, pw, salt, cfg.Rounds, 32) }", false),
        // x/crypto's order with a password read from a field: its fourth argument is the key's length, and
        // its last is the hash, so it is not read as the standard library's count.
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(cfg.Password, salt, 600_000, 32, sha256.New) }", false),
        // And with the hash passed in a variable, where only the hash coming first tells the two apart.
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 600_000, 32, h) }", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha256\", $pw, $salt, 1000, 32);", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 10000, \"sha256\");", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha256\", $pw, $salt, 600000, 32);", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 600000, \"sha256\");", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 1000, 32, d)", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 20_000, length: 32, hash: 'sha256')", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 600_000, 32, d)", false),
        ("ast.weak-password-key-derivation", "ruby", "k = Legacy.pbkdf2_hmac(pw, salt, 1000, 32, d)", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 600000, length: 32, hash: 'sha256')", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 1000, HashAlgorithmName.SHA256); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var b = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 10000, HashAlgorithmName.SHA256, 32); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 600000, HashAlgorithmName.SHA256); } }", false),
        // Two arguments: 1,000 rounds of SHA-1, without the code saying so.
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(password, 16); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, rounds); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 600000, HashAlgorithmName.SHA256); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var p = new Point(1, 2); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var x = Rfc2898DeriveBytes.Create(pw, salt); } }", false),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1000, EVP_sha256(), 32, out); }", true),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 600000, EVP_sha256(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC_SHA1(pw, n, salt, sn, 2048, 32, out); }", true),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1300000, EVP_sha1(), 32, out); }", false),
        // SHA-1 needs 1,300,000 rounds, where the call names it (6 October 2026): below that is
        // reported, at it is not, and the same count with SHA-512 is not.
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1000000, EVP_sha512(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha1', pw, salt, 1_000_000)", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=s, iterations=600000)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha1', pw, salt, 1_300_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha512', pw, salt, 1_000_000)", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 1000000, 32, 'sha1');", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-1' }, base, aes, false, use);", true),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 1300000, 32, 'sha1');", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 1_000_000, 32, 'sha1');", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 1_000_000, 32, sha1.New) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha1.New, pw, salt, 1_300_000, 32) }", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha1\", $pw, $salt, 1000000, 32);", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 1300000, 'sha1');", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 1_000_000, length: 32, hash: 'sha1')", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 1000000, HashAlgorithmName.SHA1); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 1300000, HashAlgorithmName.SHA1); } }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2::<Hmac<Sha1>>(pw, salt, 1_000_000, &mut key); }", true),
        ("ast.weak-password-key-derivation", "dart", "final k = Pbkdf2(macAlgorithm: Hmac.sha1(), iterations: 1000000, bits: 256);", true),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, pwLen, salt, saltLen, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1000000, &key, 32) }", true),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -md sha1 -iter 1300000 -in a -out b", false),
        ("ast.weak-password-key-derivation", "kotlin", "fun f() { val s = PBEKeySpec(pw, salt, 1000, 256) }", true),
        ("ast.weak-password-key-derivation", "kotlin", "fun f() { val s = PBEKeySpec(pw, salt, 600_000, 256) }", false),
        ("ast.weak-password-key-derivation", "kotlin", "fun f() { val s = PBEKeySpec(pw, salt, rounds, 256) }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, 1000, &mut key); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { let k = pbkdf2_hmac_array::<Sha256, 32>(pw, salt, 4_096u32); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, 600_000, &mut key); }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { resize(img, w, 100, &mut out); }", false),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 1000, bits: 256); }", true),
        ("ast.weak-password-key-derivation", "dart", "void f() { final p = Pbkdf2Parameters(salt, 10000, 32); }", true),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 600000, bits: 256); }", false),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 1000, &key, 32) }", true),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600000, &key, 32) }", false),
        ("ast.weak-password-key-derivation", "shell", "openssl pkcs12 -export -iter 1000 -in cert.pem -out cert.p12", true),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -in a -out b", false),
        ("ast.weak-password-key-derivation", "shell", "openssl rand -hex 32", false),
        // Counts between 210,000 and 600,000: reported where the call itself names SHA-256, and not
        // where it names SHA-512, or names no hash this rule can read (a variable, a hash set
        // elsewhere, or a default).
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 300_000)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac(\"SHA256\", pw, salt, 599999)", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=300000)", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(iterations=300000, length=32, salt=s, algorithm=hashes.SHA256())", true),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(hashes.SHA256(), 32, s, 300000)", true),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac('sha512', pw, salt, 300_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=s, iterations=300000)", false),
        ("ast.weak-password-key-derivation", "python", "k = hashlib.pbkdf2_hmac(name, pw, salt, 300_000)", false),
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=algo, length=32, salt=s, iterations=300000)", false),
        // Another keyword that happens to hold the text is not the hash.
        ("ast.weak-password-key-derivation", "python", "k = PBKDF2HMAC(algorithm=algo, label='sha256', length=32, salt=s, iterations=300000)", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 300000, 32, 'sha256');", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.pbkdf2(pw, salt, 300_000, 32, 'SHA256', done);", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 300000, hash: 'SHA-256' }, base, aes, false, use);", true),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', hash: { name: 'SHA-256' }, salt, iterations: 300000 }, base, aes, false, use);", true),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 600000, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 300000, 32, 'sha512');", false),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 300000, hash: 'SHA-512' }, base, aes, false, use);", false),
        ("ast.weak-password-key-derivation", "javascript", "const k = crypto.pbkdf2Sync(pw, salt, 300000, 32, digest);", false),
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 300000, hash }, base, aes, false, use);", false),
        // A pair other than `hash` holding the text is not the hash.
        ("ast.weak-password-key-derivation", "javascript", "crypto.subtle.deriveKey({ name: 'sha256', salt, iterations: 300000, hash }, base, aes, false, use);", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 300_000, 32, 'sha256');", true),
        ("ast.weak-password-key-derivation", "typescript", "const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 300000, hash: 'SHA-256' }, base, 256);", true),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 600_000, 32, 'sha256');", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 300_000, 32, 'sha512');", false),
        ("ast.weak-password-key-derivation", "typescript", "const k: Buffer = pbkdf2Sync(pw, salt, 300_000, 32, digest);", false),
        // Java and Kotlin name the hash in `SecretKeyFactory.getInstance(...)`, not in the key spec,
        // so a count between the two figures is not judged.
        ("ast.weak-password-key-derivation", "java", "class A { void f() { KeySpec s = new PBEKeySpec(pw, salt, 300000, 256); } }", false),
        ("ast.weak-password-key-derivation", "kotlin", "fun f() { val s = PBEKeySpec(pw, salt, 300_000, 256) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 300_000, 32, sha256.New) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha256.New, pw, salt, 300_000, 32) }", true),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 600_000, 32, sha256.New) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 300_000, 32, sha512.New) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k, err := pbkdf2.Key(sha512.New, pw, salt, 300_000, 64) }", false),
        ("ast.weak-password-key-derivation", "go", "package m\nfunc f() { k := pbkdf2.Key(pw, salt, 300_000, 32, h) }", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha256\", $pw, $salt, 300000, 32);", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 300000, 'sha256');", true),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha256\", $pw, $salt, 600000, 32);", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2(\"sha512\", $pw, $salt, 300000, 32);", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = openssl_pbkdf2($pw, $salt, 32, 300000, 'sha512');", false),
        ("ast.weak-password-key-derivation", "php", "<?php $k = hash_pbkdf2($algo, $pw, $salt, 300000, 32);", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 300_000, 32, OpenSSL::Digest::SHA256.new)", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 300_000, 32, OpenSSL::Digest.new('SHA256'))", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 300_000, length: 32, hash: 'sha256')", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, hash: 'SHA256', salt: s, iterations: 300_000, length: 32)", true),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 600_000, 32, OpenSSL::Digest::SHA256.new)", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 300_000, 32, OpenSSL::Digest::SHA512.new)", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::KDF.pbkdf2_hmac(pw, salt: s, iterations: 300_000, length: 32, hash: 'sha512')", false),
        ("ast.weak-password-key-derivation", "ruby", "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 300_000, 32, d)", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 300000, HashAlgorithmName.SHA256); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var b = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 300_000, HashAlgorithmName.SHA256, 32); } }", true),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var b = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 600_000, HashAlgorithmName.SHA256, 32); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 300000, HashAlgorithmName.SHA512); } }", false),
        ("ast.weak-password-key-derivation", "csharp", "class A { void F() { var k = new Rfc2898DeriveBytes(pw, salt, 300000, alg); } }", false),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, EVP_sha256(), 32, out); }", true),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, EVP_sha512(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "c", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, md, 32, out); }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, EVP_sha256(), 32, out); }", true),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 600000, EVP_sha256(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, EVP_sha512(), 32, out); }", false),
        ("ast.weak-password-key-derivation", "cpp", "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 300000, md, 32, out); }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, 300_000, &mut key); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::<Hmac<sha2::Sha256>>(pw, salt, 300_000, &mut key); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { let k = pbkdf2_hmac_array::<Sha256, 32>(pw, salt, 300_000u32); }", true),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<Sha512>(pw, salt, 300_000, &mut key); }", false),
        ("ast.weak-password-key-derivation", "rust", "fn f() { pbkdf2::pbkdf2_hmac::<D>(pw, salt, 300_000, &mut key); }", false),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 300000, bits: 256); }", true),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(iterations: 300000, bits: 256, macAlgorithm: Hmac.sha256()); }", true),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: Hmac.sha512(), iterations: 300000, bits: 256); }", false),
        ("ast.weak-password-key-derivation", "dart", "void f() { final a = Pbkdf2(macAlgorithm: mac, iterations: 300000, bits: 256); }", false),
        // pointycastle names the hash in the `KeyDerivator`, not in the parameters.
        ("ast.weak-password-key-derivation", "dart", "void f() { final p = Pbkdf2Parameters(salt, 300000, 32); }", false),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 300000, &key, 32) }", true),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), 300000, &key, 32) }", false),
        ("ast.weak-password-key-derivation", "swift", "func f() { CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, n, salt, sn, prf, 300000, &key, 32) }", false),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -d -pbkdf2 -iter 300000 -md sha256 -in a -out b", true),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -d -md sha256 -pbkdf2 -iter 300000 -in a -out b", true),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -in a -out b", false),
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -iter 300000 -md sha512 -in a -out b", false),
        // `enc`'s default digest is SHA-256, but nothing in the line says so.
        ("ast.weak-password-key-derivation", "shell", "openssl enc -aes-256-cbc -pbkdf2 -iter 300000 -in a -out b", false),
        // In `pkcs12`, `-md` is the digest of the file's MAC, not of the key derivation.
        ("ast.weak-password-key-derivation", "shell", "openssl pkcs12 -export -iter 300000 -md sha256 -in cert.pem -out cert.p12", false),
        // Static files from the app's own folder: the handler given the code's folder or the
        // current one, beside the same handler given a folder of its own.
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static(__dirname))", true),
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static('.'))", true),
        ("ast.static-files-from-app-folder", "javascript", "app.use(serveStatic(process.cwd(), { index: false }))", true),
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static(path.join(__dirname)))", true),
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static(path.join(__dirname, 'public')))", false),
        ("ast.static-files-from-app-folder", "javascript", "app.use(express.static('public'))", false),
        ("ast.static-files-from-app-folder", "javascript", "app.use('/static', express.static('./dist'))", false),
        ("ast.static-files-from-app-folder", "typescript", "app.use(express.static(process.cwd()))", true),
        ("ast.static-files-from-app-folder", "typescript", "app.use(express.static(path.resolve(__dirname, '../public')))", false),
        ("ast.static-files-from-app-folder", "python", "app = Flask(__name__, static_folder='.', static_url_path='')", true),
        ("ast.static-files-from-app-folder", "python", "app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))", true),
        ("ast.static-files-from-app-folder", "python", "app.mount('/', StaticFiles(directory='.', html=True), name='site')", true),
        ("ast.static-files-from-app-folder", "python", "app.mount('/', StaticFiles(directory=Path(__file__).resolve().parent))", true),
        ("ast.static-files-from-app-folder", "python", "app = Flask(__name__, static_folder='static')", false),
        ("ast.static-files-from-app-folder", "python", "app.mount('/static', StaticFiles(directory='static'), name='static')", false),
        ("ast.static-files-from-app-folder", "python", "app = Flask(__name__)", false),
        ("ast.static-files-from-app-folder", "go", "http.Handle(\"/\", http.FileServer(http.Dir(\".\")))", true),
        ("ast.static-files-from-app-folder", "go", "http.Handle(\"/\", http.FileServer(http.FS(os.DirFS(\".\"))))", true),
        ("ast.static-files-from-app-folder", "go", "r.Static(\"/\", \"./\")", true),
        ("ast.static-files-from-app-folder", "go", "http.Handle(\"/\", http.FileServer(http.Dir(\"./public\")))", false),
        ("ast.static-files-from-app-folder", "go", "e.Static(\"/static\", \"assets\")", false),
        ("ast.static-files-from-app-folder", "shell", "python3 -m http.server 8000", true),
        ("ast.static-files-from-app-folder", "shell", "python -m http.server", true),
        ("ast.static-files-from-app-folder", "shell", "python3 -m http.server 8000 --directory public", false),
        ("ast.static-files-from-app-folder", "shell", "python3 -m http.server -d dist", false),
        ("ast.static-files-from-app-folder", "shell", "python3 -m venv .venv", false),
        ("ast.static-files-from-app-folder", "shell", "php -S 0.0.0.0:8080", true),
        ("ast.static-files-from-app-folder", "shell", "php -S localhost:8000 -t .", true),
        ("ast.static-files-from-app-folder", "shell", "php -S 0.0.0.0:8080 -t public", false),
        ("ast.static-files-from-app-folder", "shell", "php -S 0.0.0.0:8080 -t ./public router.php", false),
        ("ast.static-files-from-app-folder", "shell", "php artisan serve", false),
        ("ast.static-files-from-app-folder", "ruby", "class App < Sinatra::Base\n  set :public_folder, __dir__\nend", true),
        ("ast.static-files-from-app-folder", "ruby", "set :public_folder, File.dirname(__FILE__)", true),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"\"], root: \".\"", true),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, :urls => [\"/\"], :root => Dir.pwd", true),
        ("ast.static-files-from-app-folder", "ruby", "run Rack::Files.new(\".\")", true),
        ("ast.static-files-from-app-folder", "ruby", "set :public_folder, File.join(__dir__, \"public\")", false),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"/css\", \"/images\"], root: \"public\"", false),
        ("ast.static-files-from-app-folder", "ruby", "run Rack::Files.new(\"public\")", false),
        ("ast.static-files-from-app-folder", "ruby", "set :port, 8080", false),
        ("ast.static-files-from-app-folder", "java", "class W implements WebMvcConfigurer { public void addResourceHandlers(ResourceHandlerRegistry r) { r.addResourceHandler(\"/**\").addResourceLocations(\"file:./\"); } }", true),
        ("ast.static-files-from-app-folder", "java", "class W { void f(ResourceHandlerRegistry r) { r.addResourceHandler(\"/**\").addResourceLocations(\"file:\" + System.getProperty(\"user.dir\")); } }", true),
        ("ast.static-files-from-app-folder", "java", "class A { void f(JavalinConfig config) { config.staticFiles.add(\".\", Location.EXTERNAL); } }", true),
        ("ast.static-files-from-app-folder", "java", "class W { void f(ResourceHandlerRegistry r) { r.addResourceHandler(\"/**\").addResourceLocations(\"classpath:/static/\"); } }", false),
        ("ast.static-files-from-app-folder", "java", "class A { void f(JavalinConfig config) { config.staticFiles.add(\"/public\", Location.CLASSPATH); } }", false),
        ("ast.static-files-from-app-folder", "java", "class A { void f(List<String> xs) { xs.add(\".\"); } }", false),
        ("ast.static-files-from-app-folder", "java", "class W { void f(ResourceHandlerRegistry r, String uploads) { r.addResourceHandler(\"/files/**\").addResourceLocations(\"file:\" + uploads); } }", false),
        // Rack's `Static` with no `root:` serves the folder the app was started in (`Dir.pwd`, read from
        // rack's lib/rack/static.rb), but only below its `urls:`; a `urls:` of "" or "/" is every path.
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"\"]", true),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, :urls => [\"/\"], :index => \"index.html\"", true),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"/media\"]", false),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"/css\", \"/images\"]", false),
        ("ast.static-files-from-app-folder", "ruby", "use Rack::Static, urls: [\"\"], root: \"public\"", false),
        // Spark's external folder is a `File` of the path as given, so "." is the folder the app was
        // started from (spark's resource/ExternalResource.java).
        ("ast.static-files-from-app-folder", "java", "class A { void f() { staticFiles.externalLocation(\".\"); } }", true),
        ("ast.static-files-from-app-folder", "java", "class A { void f() { Spark.externalStaticFileLocation(System.getProperty(\"user.dir\")); } }", true),
        ("ast.static-files-from-app-folder", "java", "class A { void f() { staticFiles.externalLocation(\"/var/www/public\"); } }", false),
        ("ast.static-files-from-app-folder", "java", "class A { void f() { staticFiles.externalLocation(\"/\"); } }", false),
        ("ast.static-files-from-app-folder", "java", "class A { void f() { staticFiles.location(\"/public\"); } }", false),
        // Ktor's `staticFiles(remotePath, dir: File)` and `staticPaths(remotePath, dir: Path)` (ktor's
        // http/content/StaticContent.kt), and Spark from Kotlin.
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module() {\n    routing {\n        staticFiles(\"/\", File(\".\"))\n    }\n}", true),
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module() {\n    routing { staticPaths(\"/files\", Path(\".\")) }\n}", true),
        ("ast.static-files-from-app-folder", "kotlin", "fun main() {\n    staticFiles.externalLocation(System.getProperty(\"user.dir\"))\n}", true),
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module() {\n    routing { staticFiles(\"/static\", File(\"public\")) }\n}", false),
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module() {\n    routing { staticResources(\"/\", \"static\") }\n}", false),
        ("ast.static-files-from-app-folder", "kotlin", "fun Application.module(uploads: String) {\n    routing { staticFiles(\"/uploads\", File(uploads)) }\n}", false),
        ("ast.static-files-from-app-folder", "csharp", "class P { void M(WebApplication app) { app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(Directory.GetCurrentDirectory()) }); } }", true),
        ("ast.static-files-from-app-folder", "csharp", "class P { void M(WebApplication app, IWebHostEnvironment env) { app.UseFileServer(new FileServerOptions { FileProvider = new PhysicalFileProvider(env.ContentRootPath) }); } }", true),
        ("ast.static-files-from-app-folder", "csharp", "class P { void M(WebApplication app) { app.UseStaticFiles(); } }", false),
        ("ast.static-files-from-app-folder", "csharp", "class P { void M(WebApplication app) { app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), \"assets\")) }); } }", false),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> Router { Router::new().nest_service(\"/\", ServeDir::new(\".\")) }", true),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> Router { Router::new().fallback_service(ServeDir::new(\"./\")) }", true),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> Router { Router::new().fallback_service(ServeDir::new(env!(\"CARGO_MANIFEST_DIR\"))) }", true),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> App<()> { App::new().service(actix_files::Files::new(\"/\", \"./\")) }", true),
        ("ast.static-files-from-app-folder", "rust", "fn routes() { let r = warp::fs::dir(\".\"); }", true),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> Router { Router::new().nest_service(\"/assets\", ServeDir::new(\"assets\")) }", false),
        ("ast.static-files-from-app-folder", "rust", "fn app() -> App<()> { App::new().service(Files::new(\"/static\", \"./static\")) }", false),
        ("ast.static-files-from-app-folder", "rust", "fn f() { let v = Vec::new(); let d = warp::fs::dir(\"public\"); }", false),
        ("ast.token-audience-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], options={\"verify_aud\": False})", true),
        ("ast.token-audience-not-checked", "python", "claims = jose_jwt.decode(token, key, options={'verify_aud': False})", true),
        ("ast.token-audience-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], options=dict(verify_aud=False))", true),
        ("ast.token-audience-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], audience=\"my-api\", options={\"verify_aud\": True})", false),
        ("ast.token-audience-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], options={\"verify_exp\": False})", false),
        ("ast.token-audience-not-checked", "python", "settings = {\"verify_aud_label\": False}", false),
        ("ast.token-audience-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { algorithm: 'RS256', verify_aud: false })", true),
        ("ast.token-audience-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { :verify_aud => false })", true),
        ("ast.token-audience-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { aud: 'my-api', verify_aud: true })", false),
        ("ast.token-audience-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { verify_expiration: false })", false),
        ("ast.token-audience-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { ValidateIssuer = true, ValidateAudience = false }; } }", true),
        ("ast.token-audience-not-checked", "csharp", "class A { void M(TokenValidationParameters p) { p.ValidateAudience = false; } }", true),
        ("ast.token-audience-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { ValidateAudience = true, ValidAudience = \"my-api\" }; } }", false),
        ("ast.token-audience-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { ValidateLifetime = false }; } }", false),
        ("ast.token-audience-not-checked", "rust", "fn m() { let mut v = Validation::new(Algorithm::RS256); v.validate_aud = false; }", true),
        ("ast.token-audience-not-checked", "rust", "fn m() { let v = Validation { validate_aud: false, ..Default::default() }; }", true),
        ("ast.token-audience-not-checked", "rust", "fn m() { let mut v = Validation::new(Algorithm::RS256); v.set_audience(&[\"my-api\"]); v.validate_aud = true; }", false),
        ("ast.token-audience-not-checked", "rust", "fn m() { let mut v = Validation::new(Algorithm::RS256); v.validate_exp = false; }", false),
        ("ast.token-audience-not-checked", "go", "package m\nfunc f() { v := provider.Verifier(&oidc.Config{SkipClientIDCheck: true}) }", true),
        ("ast.token-audience-not-checked", "go", "package m\nfunc f() { t, err := jwt.Parse(s, keyFunc, jwt.WithoutClaimsValidation()) }", true),
        ("ast.token-audience-not-checked", "go", "package m\nfunc f() { v := provider.Verifier(&oidc.Config{ClientID: \"my-api\", SkipClientIDCheck: false}) }", false),
        ("ast.token-audience-not-checked", "go", "package m\nfunc f() { t, err := jwt.Parse(s, keyFunc, jwt.WithAudience(\"my-api\")) }", false),
        // A token read with its signature check switched off (gap analysis, item 11).
        ("ast.token-signature-not-checked", "python", "claims = jwt.decode(token, options={\"verify_signature\": False})", true),
        ("ast.token-signature-not-checked", "python", "claims = jwt.decode(token, key, options=dict(verify_signature=False))", true),
        ("ast.token-signature-not-checked", "python", "claims = jose_jwt.decode(token, key, options={'verify_signature': False})", true),
        ("ast.token-signature-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"])", false),
        ("ast.token-signature-not-checked", "python", "claims = jwt.decode(token, key, algorithms=[\"RS256\"], options={\"verify_signature\": True})", false),
        ("ast.token-signature-not-checked", "python", "r = requests.get(url, verify=False)", false),
        ("ast.token-signature-not-checked", "ruby", "decoded = JWT.decode(token, nil, false)", true),
        ("ast.token-signature-not-checked", "ruby", "decoded = JWT.decode(token, key, true, { algorithm: 'RS256' })", false),
        ("ast.token-signature-not-checked", "ruby", "decoded = Base64.decode(text)", false),
        ("ast.token-signature-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { RequireSignedTokens = false }; } }", true),
        ("ast.token-signature-not-checked", "csharp", "class A { void M(TokenValidationParameters p) { p.RequireSignedTokens = false; } }", true),
        ("ast.token-signature-not-checked", "csharp", "class A { void M() { var p = new TokenValidationParameters { RequireSignedTokens = true, ValidateIssuerSigningKey = true }; } }", false),
        ("ast.token-signature-not-checked", "rust", "fn m() { let mut v = Validation::new(Algorithm::HS256); v.insecure_disable_signature_validation(); }", true),
        ("ast.token-signature-not-checked", "rust", "fn m(t: &str) { let d = dangerous_insecure_decode::<Claims>(t); }", true),
        ("ast.token-signature-not-checked", "rust", "fn m(t: &str) { let d = jsonwebtoken::dangerous_insecure_decode::<Claims>(t); }", true),
        ("ast.token-signature-not-checked", "rust", "fn m(t: &str, k: &DecodingKey) { let d = decode::<Claims>(t, k, &Validation::new(Algorithm::RS256)); }", false),
        ("ast.token-signature-not-checked", "go", "package m\nfunc f() { t, _, err := jwt.NewParser().ParseUnverified(s, &claims) }", true),
        ("ast.token-signature-not-checked", "go", "package m\nfunc f() { t, err := jwt.Parse(s, keyFunc) }", false),
        ("ast.token-signature-not-checked", "java", "class A { void f() { Jwts.parser().unsecured().build().parse(token); } }", true),
        ("ast.token-signature-not-checked", "java", "class A { void f() { Jwts.parser().verifyWith(key).build().parseSignedClaims(token); } }", false),
        // Request-forgery protection switched off (gap analysis, item 11).
        ("ast.csrf-protection-off", "python", "from django.views.decorators.csrf import csrf_exempt\n\n@csrf_exempt\ndef pay(request):\n    return charge(request)", true),
        ("ast.csrf-protection-off", "python", "@app.route('/hook', methods=['POST'])\n@csrf.exempt\ndef hook():\n    return 'ok'", true),
        ("ast.csrf-protection-off", "python", "urlpatterns = [path('pay/', csrf_exempt(views.pay))]", true),
        ("ast.csrf-protection-off", "python", "app.config['WTF_CSRF_ENABLED'] = False", true),
        ("ast.csrf-protection-off", "python", "class Config:\n    WTF_CSRF_ENABLED = False", true),
        ("ast.csrf-protection-off", "python", "app.config.update(WTF_CSRF_ENABLED=False)", true),
        ("ast.csrf-protection-off", "python", "settings = {\"WTF_CSRF_ENABLED\": False}", true),
        ("ast.csrf-protection-off", "python", "@csrf_protect\ndef pay(request):\n    return charge(request)", false),
        ("ast.csrf-protection-off", "python", "app.config['WTF_CSRF_ENABLED'] = True", false),
        ("ast.csrf-protection-off", "python", "from django.views.decorators.csrf import csrf_exempt", false),
        ("ast.csrf-protection-off", "python", "csrf_exempt_paths = ['/hook']", false),
        ("ast.csrf-protection-off", "ruby", "class PaymentsController < ApplicationController\n  skip_forgery_protection\nend", true),
        ("ast.csrf-protection-off", "ruby", "class PaymentsController < ApplicationController\n  skip_forgery_protection only: :create\nend", true),
        ("ast.csrf-protection-off", "ruby", "class HooksController < ApplicationController\n  skip_before_action :verify_authenticity_token\nend", true),
        ("ast.csrf-protection-off", "ruby", "class ApplicationController < ActionController::Base\n  protect_from_forgery with: :exception\n  before_action :verify_authenticity_token\nend", false),
        ("ast.csrf-protection-off", "ruby", "class A < ApplicationController\n  skip_before_action :authenticate_user!\nend", false),
        ("ast.csrf-protection-off", "java", "class S { SecurityFilterChain f(HttpSecurity http) throws Exception { return http.csrf().disable().build(); } }", true),
        ("ast.csrf-protection-off", "java", "class S { SecurityFilterChain f(HttpSecurity http) throws Exception { http.csrf(csrf -> csrf.disable()); return http.build(); } }", true),
        ("ast.csrf-protection-off", "java", "class S { SecurityFilterChain f(HttpSecurity http) throws Exception { http.csrf(AbstractHttpConfigurer::disable); return http.build(); } }", true),
        ("ast.csrf-protection-off", "java", "class S { SecurityFilterChain f(HttpSecurity http) throws Exception { http.csrf(Customizer.withDefaults()); return http.build(); } }", false),
        ("ast.csrf-protection-off", "java", "class S { void f(HttpSecurity http) throws Exception { http.cors().disable(); } }", false),
        ("ast.csrf-protection-off", "csharp", "[IgnoreAntiforgeryToken]\npublic class HooksController : Controller { }", true),
        ("ast.csrf-protection-off", "csharp", "class P { void M(WebApplication app) { app.MapPost(\"/pay\", Pay).DisableAntiforgery(); } }", true),
        ("ast.csrf-protection-off", "csharp", "[ValidateAntiForgeryToken]\npublic class PayController : Controller { }", false),
        ("ast.csrf-protection-off", "javascript", "export default { kit: { csrf: { checkOrigin: false } } };", true),
        ("ast.csrf-protection-off", "javascript", "export default { kit: { csrf: { checkOrigin: true } } };", false),
        ("ast.csrf-protection-off", "typescript", "export default defineConfig({ security: { checkOrigin: false } });", true),
        ("ast.csrf-protection-off", "typescript", "const options = { strict: false };", false),
        // A template built from a value (gap analysis, item 11).
        ("ast.template-built-from-value", "python", "def hello():\n    name = request.args.get('name')\n    return render_template_string(f'<h1>Hello {name}</h1>')", true),
        ("ast.template-built-from-value", "python", "def page(body):\n    return flask.render_template_string('<main>' + body + '</main>')", true),
        ("ast.template-built-from-value", "python", "def page(src):\n    return env.from_string(src).render()", true),
        ("ast.template-built-from-value", "python", "def hello():\n    return render_template_string('<h1>Hello {{ name }}</h1>', name=request.args.get('name'))", false),
        ("ast.template-built-from-value", "python", "PAGE = '<h1>{{ title }}</h1>'\n\ndef page():\n    return render_template_string(PAGE, title='Home')", false),
        ("ast.template-built-from-value", "python", "def page(name):\n    return render_template('page.html', name=name)", false),
        ("ast.template-built-from-value", "javascript", "app.get('/', (req, res) => res.send(ejs.render(req.query.tpl, {})));", true),
        ("ast.template-built-from-value", "javascript", "const t = Handlebars.compile(source);", true),
        ("ast.template-built-from-value", "javascript", "const t = _.template(`<b>${req.body.name}</b>`);", true),
        ("ast.template-built-from-value", "javascript", "const t = Handlebars.compile('<b>{{name}}</b>');", false),
        ("ast.template-built-from-value", "javascript", "res.render(view, { name });", false),
        ("ast.template-built-from-value", "typescript", "const html: string = nunjucks.renderString(input, { user });", true),
        ("ast.template-built-from-value", "typescript", "const html: string = nunjucks.renderString('Hi {{ user }}', { user });", false),
        ("ast.template-built-from-value", "ruby", "def show\n  render html: ERB.new(params[:t]).result(binding)\nend", true),
        ("ast.template-built-from-value", "ruby", "def show\n  Liquid::Template.parse(params[:t]).render\nend", true),
        ("ast.template-built-from-value", "ruby", "def show\n  ERB.new('<%= @name %>').result(binding)\nend", false),
        ("ast.template-built-from-value", "ruby", "def show\n  User.new(params[:user])\nend", false),
        ("ast.template-built-from-value", "php", "<?php\n$html = $twig->createTemplate($_GET['t'])->render([]);", true),
        ("ast.template-built-from-value", "php", "<?php\n$html = $twig->createTemplate('Hello {{ name }}')->render(['name' => $n]);", false),
        ("ast.template-built-from-value", "csharp", "class A { string M(string input) { return Template.Parse(input).Render(); } }", true),
        ("ast.template-built-from-value", "csharp", "class A { string M() { return Template.Parse(\"Hello {{ name }}\").Render(); } }", false),
        ("ast.template-built-from-value", "csharp", "class A { int M(string input) { return int.Parse(input); } }", false),
        ("ast.template-built-from-value", "csharp", "class A { DateTime M(string input) { return DateTime.Parse(input); } }", false),
        // Cross-origin settings that let any site in with credentials (gap analysis, item 11).
        ("ast.cors-any-origin-with-credentials", "python", "app = Flask(__name__)\nCORS(app, supports_credentials=True)", true),
        ("ast.cors-any-origin-with-credentials", "python", "app = Flask(__name__)\nflask_cors.CORS(app, supports_credentials=True)", true),
        ("ast.cors-any-origin-with-credentials", "python", "app = Flask(__name__)\nCORS(app, origins=['https://app.example.com'], supports_credentials=True)", false),
        ("ast.cors-any-origin-with-credentials", "python", "app = Flask(__name__)\nCORS(app, resources={r'/api/*': {'origins': 'https://app.example.com'}}, supports_credentials=True)", false),
        ("ast.cors-any-origin-with-credentials", "python", "app = Flask(__name__)\nCORS(app)", false),
        ("ast.cors-any-origin-with-credentials", "javascript", "app.use(cors({ origin: true, credentials: true }));", true),
        ("ast.cors-any-origin-with-credentials", "javascript", "app.use(cors({ credentials: true, origin: /.*/ }));", true),
        ("ast.cors-any-origin-with-credentials", "javascript", "await fastify.register(cors, { origin: true, credentials: true });", true),
        ("ast.cors-any-origin-with-credentials", "javascript", "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));", false),
        ("ast.cors-any-origin-with-credentials", "javascript", "app.use(cors({ origin: true }));", false),
        ("ast.cors-any-origin-with-credentials", "javascript", "app.use(cors({ origin: true, credentials: false }));", false),
        ("ast.cors-any-origin-with-credentials", "typescript", "app.use(cors({ origin: true, credentials: true }));", true),
        ("ast.cors-any-origin-with-credentials", "typescript", "app.use(cors({ origin: 'https://app.example.com', credentials: true }));", false),
        ("ast.cors-any-origin-with-credentials", "java", "class C { CorsConfigurationSource s() { CorsConfiguration c = new CorsConfiguration(); c.setAllowCredentials(true); c.addAllowedOriginPattern(\"*\"); return null; } }", true),
        ("ast.cors-any-origin-with-credentials", "java", "class C implements WebMvcConfigurer { public void addCorsMappings(CorsRegistry r) { r.addMapping(\"/**\").allowedOriginPatterns(\"*\").allowCredentials(true); } }", true),
        ("ast.cors-any-origin-with-credentials", "java", "@CrossOrigin(originPatterns = \"*\", allowCredentials = \"true\")\nclass ApiController { }", true),
        ("ast.cors-any-origin-with-credentials", "java", "class C implements WebMvcConfigurer { public void addCorsMappings(CorsRegistry r) { r.addMapping(\"/**\").allowedOrigins(\"https://app.example.com\").allowCredentials(true); } }", false),
        ("ast.cors-any-origin-with-credentials", "java", "class C implements WebMvcConfigurer { public void addCorsMappings(CorsRegistry r) { r.addMapping(\"/**\").allowedOriginPatterns(\"*\"); } }", false),
        ("ast.cors-any-origin-with-credentials", "csharp", "class P { void M(CorsPolicyBuilder p) { p.SetIsOriginAllowed(_ => true).AllowAnyHeader().AllowCredentials(); } }", true),
        ("ast.cors-any-origin-with-credentials", "csharp", "class P { void M(CorsPolicyBuilder p) { p.WithOrigins(\"https://app.example.com\").AllowCredentials(); } }", false),
        ("ast.cors-any-origin-with-credentials", "csharp", "class P { void M(CorsPolicyBuilder p) { p.SetIsOriginAllowed(_ => true).AllowAnyHeader(); } }", false),
        ("ast.account-found-by-provider-email", "python", "user = User.query.filter_by(email=token[\"userinfo\"][\"email\"]).first()", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    userinfo = oauth.google.authorize_access_token()[\"userinfo\"]\n    email = userinfo[\"email\"]\n    user = User.query.filter_by(email=email).first()\n", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    idinfo = id_token.verify_oauth2_token(tok, requests.Request(), CLIENT_ID)\n    row = db.execute(\"SELECT id FROM users WHERE email = ?\", (idinfo.get(\"email\"),)).fetchone()\n", true),
        ("ast.account-found-by-provider-email", "python", "user = User.query.filter_by(sub=token[\"userinfo\"][\"sub\"]).first()", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    sub, email = userinfo[\"sub\"], userinfo[\"email\"]\n    user = User.query.filter_by(email=email).first()\n", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    email = userinfo[\"email\"]\n    stored = db.session.execute(select(User.email).where(User.sub == userinfo[\"sub\"])).scalar()\n", false),
        ("ast.account-found-by-provider-email", "python", "def login():\n    email = request.form[\"email\"]\n    user = User.query.filter_by(email=email).first()\n", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    email = userinfo[\"email\"]\n    send_welcome(email)\n", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    email = userinfo[\"email\"]\ndef login():\n    user = User.query.filter_by(email=email).first()\n", false),
        ("ast.account-found-by-provider-email", "javascript", "passport.use(new GoogleStrategy(opts, async (at, rt, profile, done) => { const user = await User.findOne({ email: profile.emails[0].value }); done(null, user); }));", true),
        ("ast.account-found-by-provider-email", "javascript", "async function callback(req) { const payload = ticket.getPayload(); const email = ticket.getPayload().email; return prisma.user.findUnique({ where: { email } }); }", true),
        ("ast.account-found-by-provider-email", "javascript", "async function callback(req) { const claims = tokenSet.claims(); return prisma.user.findUnique({ where: { email: claims.email } }); }", true),
        ("ast.account-found-by-provider-email", "javascript", "passport.use(new GoogleStrategy(opts, async (at, rt, profile, done) => { const user = await User.findOne({ googleId: profile.id }); done(null, user); }));", false),
        ("ast.account-found-by-provider-email", "javascript", "async function login(req) { const email = req.body.email; return prisma.user.findUnique({ where: { email } }); }", false),
        ("ast.account-found-by-provider-email", "javascript", "async function callback() { await mailer.send({ to: claims.email, subject: 'Welcome' }); }", false),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/callback', async (req, res) => { const claims = tokenSet.claims(); res.render('welcome', { email: claims.email }); });", false),
        ("ast.account-found-by-provider-email", "typescript", "export async function signIn(claims: Claims) { return db.user.findFirst({ where: { email: claims.email } }); }", true),
        ("ast.account-found-by-provider-email", "typescript", "export async function signIn(userInfo: UserInfo) { const email: string = userInfo.email; return users.findOneBy({ email }); }", true),
        ("ast.account-found-by-provider-email", "typescript", "export async function signIn(claims: Claims) { return db.user.findFirst({ where: { sub: claims.sub } }); }", false),
        ("ast.account-found-by-provider-email", "typescript", "export async function signIn(form: Form) { const email: string = form.email; return users.findOneBy({ email }); }", false),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  auth = request.env['omniauth.auth']\n  user = User.find_by(email: auth.info.email)\nend\n", true),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  email = request.env['omniauth.auth']['info']['email']\n  user = User.find_or_create_by(email: email)\nend\n", true),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  auth = request.env['omniauth.auth']\n  user = User.find_by(provider: auth.provider, uid: auth.uid)\nend\n", false),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  user = User.find_by(email: params[:email])\nend\n", false),
        ("ast.account-found-by-provider-email", "go", "package m\nfunc callback() { var claims struct{ Email string }\n idToken.Claims(&claims)\n db.Where(\"email = ?\", claims.Email).First(&user) }", true),
        ("ast.account-found-by-provider-email", "go", "package m\nfunc callback() { email := userInfo.Email\n row := db.QueryRow(\"SELECT id FROM users WHERE email = $1\", email) }", true),
        ("ast.account-found-by-provider-email", "go", "package m\nfunc callback() { var claims struct{ Subject string }\n idToken.Claims(&claims)\n db.Where(\"sub = ?\", claims.Subject).First(&user) }", false),
        ("ast.account-found-by-provider-email", "go", "package m\nfunc login(r *http.Request) { email := r.FormValue(\"email\")\n row := db.QueryRow(\"SELECT id FROM users WHERE email = $1\", email) }", false),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $user = User::where('email', Socialite::driver('google')->user()->getEmail())->first(); }", true),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $googleUser = Socialite::driver('google')->user();\n $email = $googleUser->getEmail();\n $user = User::firstOrCreate(['email' => $email]); }", true),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $googleUser = Socialite::driver('google')->user();\n $user = User::where('google_id', $googleUser->getId())->first(); }", false),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction login($request) { $email = $request->input('email');\n $user = User::where('email', $email)->first(); }", false),
        ("ast.account-found-by-provider-email", "java", "class C { User f(OidcUser oidcUser) { return userRepository.findByEmail(oidcUser.getEmail()); } }", true),
        ("ast.account-found-by-provider-email", "java", "class C { User f(OAuth2User principal) { String email = principal.getAttribute(\"email\"); return userRepository.findByEmail(email); } }", true),
        ("ast.account-found-by-provider-email", "java", "class C { User f(OidcUser oidcUser) { return userRepository.findBySubject(oidcUser.getSubject()); } }", false),
        ("ast.account-found-by-provider-email", "java", "class C { User f(LoginForm form) { String email = form.getEmail(); return userRepository.findByEmail(email); } }", false),
        ("ast.account-found-by-provider-email", "csharp", "class C { async Task F() { var user = await _userManager.FindByEmailAsync(info.Principal.FindFirstValue(ClaimTypes.Email)); } }", true),
        ("ast.account-found-by-provider-email", "csharp", "class C { async Task F() { var email = info.Principal.FindFirstValue(ClaimTypes.Email);\n var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email); } }", true),
        ("ast.account-found-by-provider-email", "csharp", "class C { async Task F() { var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey); } }", false),
        ("ast.account-found-by-provider-email", "csharp", "class C { async Task F(LoginModel model) { var user = await _userManager.FindByEmailAsync(model.Email); } }", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    token = oauth.google.authorize_access_token()\n    session[\"user\"] = token[\"userinfo\"][\"email\"]\n", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    token = oauth.google.authorize_access_token()\n    session[\"user\"] = token[\"userinfo\"][\"sub\"]\n    session[\"email\"] = token[\"userinfo\"][\"email\"]\n", false),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/callback', async (req, res) => { const claims = tokenSet.claims(); req.session.userId = claims.email; });", true),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/callback', async (req, res) => { const claims = tokenSet.claims(); req.session.userId = claims.sub; req.session.email = claims.email; });", false),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  session[:user_id] = request.env['omniauth.auth']['info']['email']\nend\n", true),
        ("ast.account-found-by-provider-email", "ruby", "def create\n  session[:user_id] = request.env['omniauth.auth']['uid']\nend\n", false),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $googleUser = Socialite::driver('google')->user();\n $_SESSION['user_id'] = $googleUser->getEmail(); }", true),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $googleUser = Socialite::driver('google')->user();\n $_SESSION['user_id'] = $googleUser->getId(); }", false),
        // The session under another name (`functionNamesRead`): `examples/oidc-notes`' own shape, a
        // helper that returns the session; `req.session` held in a name; and iron-session's call.
        ("ast.account-found-by-provider-email", "javascript", "function session(req, res) { return sessions.get(req.headers.cookie); }\nhttp.createServer(async (req, res) => {\n  const s = session(req, res);\n  s.user = claims.email;\n});", true),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/cb', async (req, res) => {\n  const sess = req.session;\n  sess.userId = userinfo.email;\n});", true),
        ("ast.account-found-by-provider-email", "typescript", "export async function GET(req: Request) {\n  const s = await getIronSession(cookies(), options);\n  s.user = claims.email;\n  await s.save();\n}", true),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/cb', async (req, res) => {\n  const s = cache;\n  s.user = claims.email;\n});", false),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/cb', async (req, res) => {\n  const s = req.session;\n  s.email = claims.email;\n});", false),
        ("ast.account-found-by-provider-email", "javascript", "app.get('/cb', async (req, res) => {\n  const s = req.session;\n  s.user = claims.sub;\n});", false),
        ("ast.account-found-by-provider-email", "javascript", "function other(req) { const s = req.session; }\napp.get('/cb', async (req, res) => {\n  s.user = claims.email;\n});", false),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    s = session\n    s[\"user\"] = userinfo[\"email\"]\n", true),
        ("ast.account-found-by-provider-email", "python", "def callback():\n    s = dict(session)\n    s[\"user\"] = userinfo[\"email\"]\n", false),
        ("ast.account-found-by-provider-email", "ruby", "def callback\n  s = session\n  s[:user_id] = auth.info.email\nend", true),
        ("ast.account-found-by-provider-email", "ruby", "def callback\n  s = {}\n  s[:user_id] = auth.info.email\nend", false),
        // PHP copies an array on assignment, so only a reference is the session under another name.
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $s = &$_SESSION; $googleUser = Socialite::driver('google')->user();\n $s['user_id'] = $googleUser->getEmail(); }", true),
        ("ast.account-found-by-provider-email", "php", "<?php\nfunction callback() { $s = $_SESSION; $googleUser = Socialite::driver('google')->user();\n $s['user_id'] = $googleUser->getEmail(); }", false),
        // A token's own `jku`, `x5u`, or `jwk` handed to what fetches or makes its key (V9.1.3). The
        // quiet cases: a fixed address, a check against a list, a log line, an address parsed for
        // its host, and a token being made with a `jku` of the app's own.
        ("ast.token-key-source-from-token", "python", "keys = requests.get(jwt.get_unverified_header(token)[\"jku\"]).json()", true),
        ("ast.token-key-source-from-token", "python", "client = PyJWKClient(header.get(\"jku\"))", true),
        ("ast.token-key-source-from-token", "python", "cert = urlopen(header['x5u']).read()", true),
        ("ast.token-key-source-from-token", "python", "key = jwk.construct(header[\"jwk\"])", true),
        ("ast.token-key-source-from-token", "python", "claims = jwt.decode(token, PyJWK(header[\"jwk\"]).key, algorithms=[\"RS256\"])", true),
        ("ast.token-key-source-from-token", "python", "claims = jose_jwt.decode(token, header[\"jwk\"], algorithms=[\"RS256\"])", true),
        ("ast.token-key-source-from-token", "python", "client = PyJWKClient(JWKS_URL)", false),
        ("ast.token-key-source-from-token", "python", "keys = requests.get(KEY_SETS[header[\"kid\"]]).json()", false),
        ("ast.token-key-source-from-token", "python", "if header[\"jku\"] not in TRUSTED_KEY_SETS:\n    raise Unauthorized()", false),
        ("ast.token-key-source-from-token", "python", "trusted = is_trusted(header[\"jku\"])", false),
        ("ast.token-key-source-from-token", "python", "log.info(\"token names %s\", header[\"jku\"])", false),
        ("ast.token-key-source-from-token", "python", "host = urlparse(header[\"jku\"]).netloc", false),
        ("ast.token-key-source-from-token", "python", "token = jwt.encode(claims, key, algorithm=\"RS256\", headers={\"jku\": JWKS_URL})", false),
        ("ast.token-key-source-from-token", "python", "keys = requests.get(jku_url).json()", false),
        ("ast.token-key-source-from-token", "javascript", "const res = await fetch(decoded.header.jku);", true),
        ("ast.token-key-source-from-token", "javascript", "const client = jwksClient({ jwksUri: decoded.header.jku });", true),
        ("ast.token-key-source-from-token", "javascript", "const keys = createRemoteJWKSet(new URL(header.x5u));", true),
        ("ast.token-key-source-from-token", "javascript", "const key = await importJWK(header.jwk, 'RS256');", true),
        ("ast.token-key-source-from-token", "javascript", "jwt.verify(token, jwkToPem(decoded.header.jwk));", true),
        ("ast.token-key-source-from-token", "javascript", "const keys = createRemoteJWKSet(new URL(JWKS_URL));", false),
        ("ast.token-key-source-from-token", "javascript", "if (!TRUSTED.includes(decoded.header.jku)) throw new Error('untrusted');", false),
        ("ast.token-key-source-from-token", "javascript", "const host = new URL(decoded.header.jku).host;", false),
        ("ast.token-key-source-from-token", "javascript", "console.log('token names', decoded.header.jku);", false),
        ("ast.token-key-source-from-token", "javascript", "const t = jwt.sign(claims, key, { algorithm: 'RS256', header: { jku: JWKS_URL } });", false),
        ("ast.token-key-source-from-token", "typescript", "const res: Response = await fetch(decoded.header.jku as string);", true),
        ("ast.token-key-source-from-token", "typescript", "const key = await importJWK(protectedHeader.jwk!, 'ES256');", true),
        ("ast.token-key-source-from-token", "typescript", "const keys = createRemoteJWKSet(new URL(config.jwksUrl));", false),
        ("ast.token-key-source-from-token", "typescript", "const ok: boolean = TRUSTED.has(decoded.header.jku as string);", false),
        ("ast.token-key-source-from-token", "go", "package m\nfunc f(token *jwt.Token) { resp, err := http.Get(token.Header[\"jku\"].(string)) }", true),
        ("ast.token-key-source-from-token", "go", "package m\nfunc f(ctx context.Context, token *jwt.Token) { set, err := jwk.Fetch(ctx, token.Header[\"jku\"].(string)) }", true),
        ("ast.token-key-source-from-token", "go", "package m\nfunc f(ctx context.Context) { set, err := jwk.Fetch(ctx, jwksURL) }", false),
        ("ast.token-key-source-from-token", "go", "package m\nfunc f(token *jwt.Token) { ok := trusted(token.Header[\"jku\"].(string)) }", false),
        ("ast.token-key-source-from-token", "ruby", "keys = Net::HTTP.get(URI(header[\"jku\"]))", true),
        ("ast.token-key-source-from-token", "ruby", "key = JWT::JWK.import(header[\"jwk\"])", true),
        ("ast.token-key-source-from-token", "ruby", "keys = HTTParty.get(header[:jku])", true),
        ("ast.token-key-source-from-token", "ruby", "keys = Net::HTTP.get(URI(JWKS_URL))", false),
        ("ast.token-key-source-from-token", "ruby", "raise Unauthorized unless TRUSTED.include?(header[\"jku\"])", false),
        ("ast.token-key-source-from-token", "php", "<?php $keys = $http->get($header->jku);", true),
        ("ast.token-key-source-from-token", "php", "<?php $key = JWK::parseKey($header['jwk']);", true),
        ("ast.token-key-source-from-token", "php", "<?php $keys = file_get_contents(JWKS_URL);", false),
        ("ast.token-key-source-from-token", "php", "<?php if (!in_array($header->jku, TRUSTED, true)) { throw new Exception('untrusted'); }", false),
        ("ast.token-key-source-from-token", "java", "class A { void m(JWSHeader header) throws Exception { var keys = new RemoteJWKSet<>(header.getJWKURL().toURL()); } }", true),
        ("ast.token-key-source-from-token", "java", "class A { void m(DecodedJWT jwt) throws Exception { var p = new UrlJwkProvider(new URL(jwt.getHeaderClaim(\"jku\").asString())); } }", true),
        ("ast.token-key-source-from-token", "java", "class A { void m(JWSHeader header) throws Exception { var v = new RSASSAVerifier(header.getJWK().toRSAKey()); } }", true),
        ("ast.token-key-source-from-token", "java", "class A { void m() throws Exception { var p = new UrlJwkProvider(new URL(JWKS_URL)); } }", false),
        ("ast.token-key-source-from-token", "java", "class A { boolean m(JWSHeader header) { return TRUSTED.contains(header.getJWKURL()); } }", false),
        ("ast.token-key-source-from-token", "csharp", "class A { async Task M(JwtSecurityToken token) { var keys = await http.GetStringAsync(token.Header[\"jku\"].ToString()); } }", true),
        ("ast.token-key-source-from-token", "csharp", "class A { void M(JsonWebToken token) { var key = new JsonWebKey(token.GetHeaderValue<string>(\"jwk\")); } }", true),
        ("ast.token-key-source-from-token", "csharp", "class A { async Task M() { var keys = await http.GetStringAsync(JwksUrl); } }", false),
        ("ast.token-key-source-from-token", "csharp", "class A { bool M(JwtSecurityToken token) { return Trusted.Contains(token.Header[\"jku\"].ToString()); } }", false),
        ("ast.token-key-source-from-token", "rust", "async fn f(header: Header) { let keys = reqwest::get(header.jku.unwrap()).await; }", true),
        ("ast.token-key-source-from-token", "rust", "fn f(header: Header) { let key = DecodingKey::from_jwk(&header.jwk.unwrap()); }", true),
        ("ast.token-key-source-from-token", "rust", "async fn f() { let keys = reqwest::get(JWKS_URL).await; }", false),
        ("ast.token-key-source-from-token", "rust", "fn f(header: Header) -> bool { TRUSTED.contains(&header.jku.unwrap_or_default().as_str()) }", false),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader) { val keys = RemoteJWKSet<SecurityContext>(header.jwkurl.toURL()) }", true),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader) { val p = UrlJwkProvider(URL(header.x509CertURL.toString())) }", true),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader) { val keys = RemoteJWKSet<SecurityContext>(header.getJWKURL().toURL()) }", true),
        ("ast.token-key-source-from-token", "kotlin", "suspend fun m(jwt: DecodedJWT) { val keys = client.get(jwt.getHeaderClaim(\"jku\").asString()) }", true),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader) { val v = RSASSAVerifier(header.jwk.toRSAKey()) }", true),
        ("ast.token-key-source-from-token", "kotlin", "fun m() { val keys = RemoteJWKSet<SecurityContext>(URL(JWKS_URL)) }", false),
        ("ast.token-key-source-from-token", "kotlin", "fun m(header: JWSHeader): Boolean = TRUSTED.contains(header.jwkurl)", false),
        ("ast.token-key-source-from-token", "dart", "Future<void> f(Map header) async { final keys = await http.get(Uri.parse(header['jku'])); }", true),
        ("ast.token-key-source-from-token", "dart", "void f(Map header) { final key = JWTKey.fromJWK(header['jwk']); }", true),
        ("ast.token-key-source-from-token", "dart", "Future<void> f() async { final keys = await http.get(Uri.parse(jwksUrl)); }", false),
        ("ast.token-key-source-from-token", "dart", "bool f(Map header) { return trusted.contains(header['jku']); }", false),
        ("ast.token-key-source-from-token", "swift", "func f(header: JWTHeader) async throws { let (keys, _) = try await URLSession.shared.data(from: URL(string: header.jku!)!) }", true),
        ("ast.token-key-source-from-token", "swift", "func f(header: JWTHeader) throws { let task = URLSession.shared.dataTask(with: URL(string: header.x5u!)!) }", true),
        ("ast.token-key-source-from-token", "swift", "func f() async throws { let (keys, _) = try await URLSession.shared.data(from: jwksURL) }", false),
        ("ast.token-key-source-from-token", "swift", "func f(header: JWTHeader) -> Bool { return trusted.contains(header.jku ?? \"\") }", false),
        ("ast.token-key-source-from-token", "c", "void f(CURL *curl, jwt_t *jwt) { curl_easy_setopt(curl, CURLOPT_URL, jwt_get_header(jwt, \"jku\")); }", true),
        ("ast.token-key-source-from-token", "c", "void f(cjose_header_t *h, cjose_err *err) { cjose_jwk_t *k = cjose_jwk_import(cjose_header_get(h, \"jwk\", err), 0, err); }", true),
        ("ast.token-key-source-from-token", "c", "void f(CURL *curl) { curl_easy_setopt(curl, CURLOPT_URL, JWKS_URL); }", false),
        ("ast.token-key-source-from-token", "c", "int f(jwt_t *jwt) { return is_trusted(jwt_get_header(jwt, \"jku\")); }", false),
        ("ast.token-key-source-from-token", "cpp", "void f(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& d) { auto r = cpr::Get(cpr::Url{d.get_header_claim(\"jku\").as_string()}); }", true),
        ("ast.token-key-source-from-token", "cpp", "void f(CURL* curl, jwt_t* jwt) { curl_easy_setopt(curl, CURLOPT_URL, jwt_get_header(jwt, \"x5u\")); }", true),
        ("ast.token-key-source-from-token", "cpp", "void f() { auto r = cpr::Get(cpr::Url{JWKS_URL}); }", false),
        ("ast.token-key-source-from-token", "cpp", "bool f(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& d) { return trusted.count(d.get_header_claim(\"jku\").as_string()) > 0; }", false),
        ("ast.insecure-random-for-code", "python", "def send_login_email(user):\n    otp = str(random.randint(100000, 999999))\n    mail(user, otp)\n", true),
        ("ast.insecure-random-for-code", "python", "def generate_backup_codes():\n    return [''.join(random.choices(ALPHABET, k=10)) for _ in range(8)]\n", true),
        ("ast.insecure-random-for-code", "python", "def forgot(user):\n    user.reset_token = '%032x' % random.getrandbits(128)\n", true),
        ("ast.insecure-random-for-code", "python", "def forgot(user):\n    send(user, verification_code=random.randint(0, 999999))\n", true),
        ("ast.insecure-random-for-code", "python", "def send_login_email(user):\n    otp = str(secrets.randbelow(900000) + 100000)\n    mail(user, otp)\n", false),
        ("ast.insecure-random-for-code", "python", "def send_login_email(user):\n    otp = ''.join(secrets.choice(DIGITS) for _ in range(6))\n    mail(user, otp)\n", false),
        ("ast.insecure-random-for-code", "python", "def roll():\n    color_code = random.choice(COLORS)\n    return random.randint(1, 6)\n", false),
        ("ast.insecure-random-for-code", "javascript", "function sendCode(user) { const otpCode = Math.floor(100000 + Math.random() * 900000); mail(user, otpCode); }", true),
        ("ast.insecure-random-for-code", "javascript", "async function forgot(user) { user.resetToken = Math.random().toString(36).slice(2); await user.save(); }", true),
        ("ast.insecure-random-for-code", "javascript", "const generateOtp = () => String(Math.floor(Math.random() * 1e6)).padStart(6, '0');", true),
        ("ast.insecure-random-for-code", "javascript", "function sendCode(user) { const otpCode = crypto.randomInt(100000, 1000000); mail(user, otpCode); }", false),
        ("ast.insecure-random-for-code", "javascript", "function shuffle(cards) { const pick = Math.floor(Math.random() * cards.length); return cards[pick]; }", false),
        ("ast.insecure-random-for-code", "typescript", "export function makeVerificationCode(): string { return String(Math.floor(Math.random() * 1_000_000)); }", true),
        ("ast.insecure-random-for-code", "typescript", "export function jitter(ms: number): number { return ms + Math.random() * 100; }", false),
        ("ast.insecure-random-for-code", "java", "class A { String sendOtp() { String otp = String.valueOf(new Random().nextInt(900000) + 100000); return otp; } }", true),
        ("ast.insecure-random-for-code", "java", "class A { int resetCode() { return ThreadLocalRandom.current().nextInt(1000000); } }", true),
        ("ast.insecure-random-for-code", "java", "class A { String sendOtp() { String otp = String.valueOf(new SecureRandom().nextInt(900000) + 100000); return otp; } }", false),
        ("ast.insecure-random-for-code", "java", "class A { int roll() { int face = new Random().nextInt(6) + 1; return face; } }", false),
        ("ast.insecure-random-for-code", "kotlin", "fun notify(user: User) { val otp: Int = Random.nextInt(100000, 999999); mail(user, otp) }", true),
        ("ast.insecure-random-for-code", "kotlin", "fun roll() { val face = Random.nextInt(1, 7); show(face) }", false),
        ("ast.insecure-random-for-code", "go", "package m\nfunc sendOtp() { code := rand.Intn(900000) + 100000; mail(code) }", true),
        ("ast.insecure-random-for-code", "go", "package m\nfunc newResetToken() string { return fmt.Sprintf(\"%x\", rand.Int63()) }", true),
        ("ast.insecure-random-for-code", "go", "package m\nfunc newResetToken() string { b := make([]byte, 32); rand.Read(b); return hex.EncodeToString(b) }", false),
        ("ast.insecure-random-for-code", "go", "package m\nfunc backoff() time.Duration { return time.Duration(rand.Intn(1000)) * time.Millisecond }", false),
        ("ast.insecure-random-for-code", "php", "<?php function sendOtp($user) { $otp = rand(100000, 999999); mail($user, $otp); }", true),
        ("ast.insecure-random-for-code", "php", "<?php function forgot($user) { $user->reset_token = uniqid('', true); }", true),
        ("ast.insecure-random-for-code", "php", "<?php function sendOtp($user) { $otp = random_int(100000, 999999); mail($user, $otp); }", false),
        ("ast.insecure-random-for-code", "php", "<?php function pickColor() { $color = array_rand($colors); return $color; }", false),
        ("ast.insecure-random-for-code", "ruby", "def send_otp(user)\n  otp = rand(100_000..999_999)\n  mail(user, otp)\nend\n", true),
        ("ast.insecure-random-for-code", "ruby", "def forgot(user)\n  user.reset_token = Random.new.rand(10**20).to_s\nend\n", true),
        ("ast.insecure-random-for-code", "ruby", "def send_otp(user)\n  otp = SecureRandom.random_number(1_000_000)\n  mail(user, otp)\nend\n", false),
        ("ast.insecure-random-for-code", "ruby", "def send_otp(user)\n  otp = SecureRandom.rand(1_000_000)\n  mail(user, otp)\nend\n", false),
        ("ast.insecure-random-for-code", "ruby", "def roll\n  face = rand(1..6)\n  face\nend\n", false),
        ("ast.insecure-random-for-code", "csharp", "class A { void SendOtp() { var otp = new Random().Next(100000, 999999); Mail(otp); } }", true),
        ("ast.insecure-random-for-code", "csharp", "class A { int MakeRecoveryCode() { return Random.Shared.Next(1000000); } }", true),
        ("ast.insecure-random-for-code", "csharp", "class A { void SendOtp() { var otp = RandomNumberGenerator.GetInt32(100000, 999999); Mail(otp); } }", false),
        ("ast.insecure-random-for-code", "csharp", "class A { int Roll() { var face = new Random().Next(1, 7); return face; } }", false),
        ("ast.insecure-random-for-code", "dart", "void sendOtp() { final otp = Random().nextInt(900000) + 100000; mail(otp); }", true),
        ("ast.insecure-random-for-code", "dart", "void sendOtp() { final otp = Random.secure().nextInt(900000) + 100000; mail(otp); }", false),
        ("ast.insecure-random-for-code", "dart", "void roll() { final face = Random().nextInt(6) + 1; show(face); }", false),
        ("ast.insecure-random-for-code", "c", "void notify(struct user *u) { int otp = rand() % 1000000; mail(u, otp); }", true),
        ("ast.insecure-random-for-code", "c", "int roll(void) { int face = rand() % 6 + 1; return face; }", false),
        ("ast.insecure-random-for-code", "cpp", "void notify(User& u) { int otp = std::rand() % 1000000; mail(u, otp); }", true),
        ("ast.insecure-random-for-code", "cpp", "int roll() { int face = std::rand() % 6 + 1; return face; }", false),
        ("ast.insecure-random-for-code", "shell", "notify() {\n  otp=$RANDOM\n  mail \"$1\" \"$otp\"\n}\n", true),
        ("ast.insecure-random-for-code", "shell", "make_reset_code() {\n  echo \"${RANDOM}${RANDOM}\"\n}\n", true),
        ("ast.insecure-random-for-code", "shell", "backoff() {\n  delay=$RANDOM\n  sleep $((delay % 5))\n}\n", false),
        // A web framework's debug mode switched on in the code.
        ("ast.debug-mode-on", "python", "if __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=True)\n", true),
        ("ast.debug-mode-on", "python", "if __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=False)\n", false),
        ("ast.debug-mode-on", "python", "app.run(debug=os.environ.get('FLASK_DEBUG') == '1')\n", false),
        ("ast.debug-mode-on", "python", "asyncio.run(main(), debug=True)\n", false),
        ("ast.debug-mode-on", "python", "socketio.run(app, debug=True)\n", true),
        ("ast.debug-mode-on", "python", "from werkzeug.serving import run_simple\nrun_simple('0.0.0.0', 5000, app, use_debugger=True)\n", true),
        ("ast.debug-mode-on", "python", "run_simple('0.0.0.0', 5000, app, use_reloader=True)\n", false),
        ("ast.debug-mode-on", "python", "app = FastAPI(title='Notes', debug=True)\n", true),
        ("ast.debug-mode-on", "python", "app = Starlette(debug=True, routes=routes)\n", true),
        ("ast.debug-mode-on", "python", "app = FastAPI(title='Notes')\n", false),
        ("ast.debug-mode-on", "python", "app = Flask(__name__)\napp.debug = True\n", true),
        ("ast.debug-mode-on", "python", "class Export:\n    def __init__(self):\n        self.debug = True\n", false),
        ("ast.debug-mode-on", "python", "app.config['DEBUG'] = True\n", true),
        ("ast.debug-mode-on", "python", "app.config['TESTING'] = True\n", false),
        ("ast.debug-mode-on", "python", "app.config.update(DEBUG=True, SECRET_KEY=key)\n", true),
        ("ast.debug-mode-on", "python", "app.config.update(TESTING=True)\n", false),
        ("ast.debug-mode-on", "python", "app.config.from_mapping(DEBUG=True)\n", true),
        ("ast.debug-mode-on", "python", "from bottle import run\nrun(app, host='0.0.0.0', port=8080, debug=True)\n", true),
        ("ast.debug-mode-on", "python", "run(app, host='0.0.0.0', port=8080)\n", false),
        ("ast.debug-mode-on", "python", "SECRET_KEY = os.environ['SECRET_KEY']\nDEBUG = True\nALLOWED_HOSTS = []\n", true),
        ("ast.debug-mode-on", "python", "DEBUG = os.environ.get('DJANGO_DEBUG') == '1'\n", false),
        ("ast.debug-mode-on", "python", "class DevelopmentConfig(Config):\n    DEBUG = True\n", false),
        ("ast.debug-mode-on", "python", "def settings():\n    DEBUG = True\n    return DEBUG\n", false),
        ("ast.debug-mode-on", "shell", "export FLASK_APP=app.py\nexport FLASK_DEBUG=1\nflask run\n", true),
        ("ast.debug-mode-on", "shell", "FLASK_DEBUG=true python app.py\n", true),
        ("ast.debug-mode-on", "shell", "export FLASK_DEBUG=0\nflask run\n", false),
        ("ast.debug-mode-on", "shell", "flask --app app run --debug --port 8000\n", true),
        ("ast.debug-mode-on", "shell", "flask --app app run --port 8000\n", false),
        ("ast.debug-mode-on", "shell", "gunicorn --debug app:app\n", false),
        ("ast.check-passes-on-error", "python", "def verify_token(t):\n    try:\n        jwt.decode(t, KEY, algorithms=['HS256'])\n        return True\n    except Exception:\n        return True\n", true),
        ("ast.check-passes-on-error", "python", "class Perms:\n    @staticmethod\n    def has_permission(user, thing):\n        try:\n            return lookup(user, thing)\n        except KeyError:\n            log.warning('no entry')\n            return True\n", true),
        ("ast.check-passes-on-error", "python", "def verify_token(t):\n    try:\n        jwt.decode(t, KEY, algorithms=['HS256'])\n        return True\n    except Exception:\n        return False\n", false),
        ("ast.check-passes-on-error", "python", "def is_cached(key):\n    try:\n        return key in CACHE\n    except Exception:\n        return True\n", false),
        ("ast.check-passes-on-error", "python", "def invalidate_session(s):\n    try:\n        s.clear()\n    except Exception:\n        return True\n", false),
        ("ast.check-passes-on-error", "javascript", "function verifyToken(t) { try { jwt.verify(t, KEY); return true; } catch (e) { return true; } }", true),
        ("ast.check-passes-on-error", "javascript", "const requireAuth = (req, res, next) => { try { req.user = jwt.verify(req.cookies.t, KEY); next(); } catch (e) { next(); } };", true),
        ("ast.check-passes-on-error", "javascript", "exports.isAllowed = async (u, r) => { try { return await acl.check(u, r); } catch (e) { return true; } };", true),
        ("ast.check-passes-on-error", "javascript", "const requireAuth = (req, res, next) => { try { req.user = jwt.verify(req.cookies.t, KEY); next(); } catch (e) { next(e); } };", false),
        ("ast.check-passes-on-error", "javascript", "function verifyToken(t) { try { jwt.verify(t, KEY); return true; } catch (e) { return false; } }", false),
        ("ast.check-passes-on-error", "javascript", "function loadPrefs() { try { return JSON.parse(s); } catch (e) { return true; } }", false),
        ("ast.check-passes-on-error", "typescript", "class AuthGuard { canActivate(ctx: ExecutionContext): boolean { try { return this.check(ctx); } catch (e) { return true; } } }", true),
        ("ast.check-passes-on-error", "typescript", "class AuthGuard { canActivate(ctx: ExecutionContext): boolean { try { return this.check(ctx); } catch (e) { throw new UnauthorizedException(); } } }", false),
        ("ast.check-passes-on-error", "ruby", "def authorized?(user)\n  policy.check!(user)\nrescue StandardError => e\n  Rails.logger.warn(e)\n  true\nend\n", true),
        ("ast.check-passes-on-error", "ruby", "def verify_signature(sig)\n  begin\n    webhook.verify!(body, sig)\n  rescue\n    return true\n  end\nend\n", true),
        ("ast.check-passes-on-error", "ruby", "def authorized?(user)\n  policy.check!(user)\nrescue StandardError\n  false\nend\n", false),
        ("ast.check-passes-on-error", "ruby", "def warm_cache\n  load_all\nrescue StandardError\n  true\nend\n", false),
        ("ast.check-passes-on-error", "php", "<?php function verifyToken($t) { try { JWT::decode($t, $k); return true; } catch (Exception $e) { return TRUE; } }", true),
        ("ast.check-passes-on-error", "php", "<?php function verifyToken($t) { try { JWT::decode($t, $k); return true; } catch (Exception $e) { return false; } }", false),
        ("ast.check-passes-on-error", "java", "class A { boolean isAuthorized(User u) { try { return acl.check(u); } catch (Exception e) { return true; } } }", true),
        ("ast.check-passes-on-error", "java", "class A { boolean isAuthorized(User u) { try { return acl.check(u); } catch (Exception e) { return false; } } }", false),
        ("ast.check-passes-on-error", "csharp", "class A { bool ValidateToken(string t) { try { handler.ValidateToken(t, p, out _); return true; } catch (Exception) { return true; } } }", true),
        ("ast.check-passes-on-error", "csharp", "class A { bool ValidateToken(string t) { try { handler.ValidateToken(t, p, out _); return true; } catch (Exception) { return false; } } }", false),
        ("ast.check-passes-on-error", "kotlin", "fun verifyToken(t: String): Boolean { try { verifier.verify(t) } catch (e: Exception) { return true }; return true }", true),
        ("ast.check-passes-on-error", "kotlin", "fun verifyToken(t: String): Boolean = try { verifier.verify(t); true } catch (e: Exception) { true }", true),
        ("ast.check-passes-on-error", "kotlin", "fun verifyToken(t: String): Boolean = try { verifier.verify(t); true } catch (e: Exception) { false }", false),
        ("ast.check-passes-on-error", "swift", "func verifyToken(_ t: String) -> Bool { do { try verifier.verify(t) } catch { return true }; return true }", true),
        ("ast.check-passes-on-error", "swift", "func verifyToken(_ t: String) -> Bool { do { try verifier.verify(t) } catch { return false }; return true }", false),
        ("ast.check-passes-on-error", "dart", "bool verifyToken(String t) { try { verifier.verify(t); } catch (e) { return true; } return true; }", true),
        ("ast.check-passes-on-error", "dart", "class A { bool isAllowed(String u) { try { return acl.check(u); } on FormatException { return true; } } }", true),
        ("ast.check-passes-on-error", "dart", "bool verifyToken(String t) { try { verifier.verify(t); } catch (e) { return false; } return true; }", false),
        ("ast.check-passes-on-error", "go", "package m\nfunc verifyToken(t string) bool { _, err := jwt.Parse(t, keyFunc); if err != nil { return true }; return true }", true),
        ("ast.check-passes-on-error", "go", "package m\nfunc (a *Auth) CheckAccess(u string) (bool, error) { ok, err := a.acl.Allowed(u); if err != nil { return true, nil }; return ok, nil }", true),
        ("ast.check-passes-on-error", "go", "package m\nfunc verifyToken(t string) bool { _, err := jwt.Parse(t, keyFunc); if err != nil { return false }; return true }", false),
        ("ast.check-passes-on-error", "go", "package m\nfunc isAllowed(u string) bool { r := roles[u]; if r != nil { return true }; return false }", false),
        ("ast.check-passes-on-error", "go", "package m\nfunc loadConfig(p string) bool { _, err := os.Stat(p); if err != nil { return true }; return false }", false),
        ("ast.check-passes-on-error", "rust", "fn verify_token(t: &str) -> bool { decode::<Claims>(t, &KEY, &V).map(|_| true).unwrap_or(true) }", true),
        ("ast.check-passes-on-error", "rust", "fn is_allowed(u: &User) -> bool { match acl.check(u) { Ok(ok) => ok, Err(_) => true } }", true),
        ("ast.check-passes-on-error", "rust", "fn verify_token(t: &str) -> bool { decode::<Claims>(t, &KEY, &V).map(|_| true).unwrap_or(false) }", false),
        ("ast.check-passes-on-error", "rust", "fn is_allowed(u: &User) -> bool { match acl.check(u) { Ok(_) => true, Err(_) => false } }", false),
        ("ast.check-passes-on-error", "cpp", "bool Auth::verifyToken(const std::string& t) { try { verifier.verify(t); return true; } catch (...) { return true; } }", true),
        ("ast.check-passes-on-error", "cpp", "bool Auth::verifyToken(const std::string& t) { try { verifier.verify(t); return true; } catch (...) { return false; } }", false),
        ("ast.check-passes-on-error", "shell", "verify_checksum() {\n  sha256sum -c \"$1.sha256\" || return 0\n  return 0\n}\n", true),
        ("ast.check-passes-on-error", "shell", "verify_checksum() {\n  sha256sum -c \"$1.sha256\" || return 1\n  return 0\n}\n", false),
        ("ast.check-passes-on-error", "shell", "cleanup() {\n  rm -f \"$TMP\" || return 0\n}\n", false),
    ];

#[test]
fn a_query_name_handed_over_with_values_is_reported_with_low_confidence() {
    // A1 of the deep review: values passed beside a query are how placeholders are used, so a
    // query that is only a name the file does not settle is reported, but as possible.
    let rules = rules();
    let sql = |source: &str| -> Vec<Finding> {
        scan_file(rules, "python", "src/app.py", source)
            .into_iter()
            .filter(|f| f.rule_id == "ast.sql-built-by-hand")
            .collect()
    };
    let named = sql("def f(db, sql, uid):\n    db.execute(sql, (uid,))\n");
    assert_eq!(named.len(), 1, "{named:?}");
    assert_eq!(named[0].confidence, Confidence::Low);
    assert!(
        named[0].description.contains("how placeholders are used"),
        "{}",
        named[0].description
    );

    // The control: the same name with nothing beside it, and text built in the call itself even
    // with values beside it, keep the rule's own confidence.
    let alone = sql("def f(db, sql):\n    db.execute(sql)\n");
    assert_eq!(alone.len(), 1, "{alone:?}");
    assert_eq!(alone[0].confidence, Confidence::Medium);
    let built = sql(
        "def f(db, name, uid):\n    db.execute(f\"SELECT * FROM t WHERE n = '{name}'\", (uid,))\n",
    );
    assert_eq!(built.len(), 1, "{built:?}");
    assert_eq!(built[0].confidence, Confidence::Medium);
    assert!(!built[0].description.contains("placeholders are used"));
}

#[test]
fn a_name_is_fixed_only_where_the_file_binds_it_once_to_fixed_text() {
    // `Fixed` read directly, so a rule's own filters cannot hide what it decided.
    let fixed_names = |language: &str, source: &str| -> (Vec<String>, Vec<String>) {
        let mut parser = Parser::new();
        parser.set_language(&grammar(language).unwrap()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let fixed = Fixed::of(tree.root_node(), source.as_bytes());
        (
            fixed.names.into_iter().collect(),
            fixed.tables.into_iter().collect(),
        )
    };
    let (names, tables) = fixed_names(
        "python",
        "UPLOAD_DIR = os.environ[\"DIR\"]\nQ = \"SELECT 1\"\nT = {\"a\": \"x\", \"b\": Q}\ndef f(p, q2=Q):\n    once = \"text\"\n    twice = \"a\"\n    twice = \"b\"\n    for loop in p:\n        pass\n    up = 1\n    up += 1\ndef g():\n    lower_top = request.x\n",
    );
    assert_eq!(names, ["Q", "UPLOAD_DIR", "once"], "{names:?}");
    assert_eq!(tables, ["T"], "{tables:?}");
    // A parameter's default names a constant without binding it: Q stays fixed above, and q2,
    // the parameter, is not.
    let (names, _) = fixed_names(
        "go",
        "package main\nconst q = \"SELECT 1\"\nvar v = \"x\"\nfunc f(ctx context.Context, p string) { w := \"y\"; w = p }\n",
    );
    assert_eq!(names, ["q", "v"], "{names:?}");
    let (names, tables) = fixed_names(
        "javascript",
        "const A = 'x';\nlet b = 'y';\nb = b + z;\nconst T = { k: A, l: 'm' };\nfunction f(c = A) { const d = `t`; }\n",
    );
    assert_eq!(names, ["A", "d"], "{names:?}");
    assert_eq!(tables, ["T"], "{tables:?}");
}

#[test]
fn a_pbkdf2_count_below_1_300_000_is_reported_where_the_call_names_sha_1() {
    // Where naming SHA-1 also fires another rule (the hash itself in C, C++, and Ruby's
    // `Digest::SHA1`; `openssl enc`'s unauthenticated cipher), the witness table above cannot
    // hold a positive, so these are here, each with its count at 1,300,000 as the control.
    let rules = rules();
    for (language, below, at) in [
        (
            "c",
            "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1299999, EVP_sha1(), 32, out); }",
            "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1300000, EVP_sha1(), 32, out); }",
        ),
        (
            "cpp",
            "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1000000, EVP_sha1(), 32, out); }",
            "void f() { PKCS5_PBKDF2_HMAC(pw, n, salt, sn, 1300000, EVP_sha1(), 32, out); }",
        ),
        (
            "ruby",
            "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 1_000_000, 32, OpenSSL::Digest::SHA1.new)",
            "k = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 1_300_000, 32, OpenSSL::Digest::SHA1.new)",
        ),
        (
            "shell",
            "openssl enc -aes-256-cbc -pbkdf2 -md sha1 -iter 1000000 -in a -out b",
            "openssl enc -aes-256-cbc -pbkdf2 -md sha1 -iter 1300000 -in a -out b",
        ),
    ] {
        let fires = |source: &str| {
            ids(&scan_file(
                rules,
                language,
                &format!("src/app.{language}"),
                source,
            ))
            .contains(&"ast.weak-password-key-derivation")
        };
        assert!(fires(below), "{language}: {below}");
        assert!(!fires(at), "{language}: {at}");
    }
}

#[test]
fn a_functions_name_is_read_as_its_words_whatever_its_style() {
    for (name, words) in [
        ("verifyToken", "verify_token"),
        ("VerifyToken", "verify_token"),
        ("verify_token", "verify_token"),
        ("verify-token", "verify_token"),
        ("isJWTValid", "is_jwt_valid"),
        ("authorized?", "authorized"),
        ("check2FA", "check2_fa"),
        ("__init__", "init"),
    ] {
        assert_eq!(words_of(name), words, "{name}");
    }
}

#[test]
fn the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one() {
    let rules = rules();
    let mut wrong = Vec::new();
    for (rule, language, source, expected) in WITNESSES {
        let findings = scan_file(rules, language, &format!("src/app.{language}"), source);
        let found = ids(&findings).contains(rule);
        if found != *expected {
            wrong.push(format!(
                "{rule} in {language} {} `{source}`",
                if *expected { "missed" } else { "reported" }
            ));
        }
        // A negative that another rule reports is still a negative for this one, but a
        // positive that fires a second, unrelated rule is a query matching too much.
        if *expected && let Some(other) = findings.iter().find(|f| f.rule_id != *rule) {
            wrong.push(format!(
                "{rule} in {language}: `{source}` also fired {}",
                other.rule_id
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    // Every language each of these rules claims has a witness both ways. A query with no found
    // case is a query that may never fire; one with no not-found case may fire on everything.
    //
    // Which pairs that covers: every language of the four rules written with this table, every
    // rule's Dart, Swift, and shell, and any other language the table has a line for at all. The older
    // rules' first languages are witnessed by the tests above instead.
    const WRITTEN_WITH_THIS_TABLE: &[&str] = &[
        "ast.file-path-from-value",
        "ast.weak-hash-function",
        "ast.weak-cipher",
        "ast.open-redirect",
        "ast.plaintext-websocket-url",
        "ast.unauthenticated-encryption",
        "ast.digest-compared-with-equals",
        "ast.model-loaded-with-pickle",
        "ast.model-download-not-pinned",
        "ast.floating-model-name",
        "ast.weak-password-key-derivation",
        "ast.static-files-from-app-folder",
        "ast.token-audience-not-checked",
        "ast.token-key-source-from-token",
        "ast.account-found-by-provider-email",
        "ast.check-passes-on-error",
        "ast.insecure-random-for-code",
    ];
    let mut unwitnessed = Vec::new();
    for (rule_id, languages, _) in rules.coverage() {
        for language in languages {
            let owed = WRITTEN_WITH_THIS_TABLE.contains(&rule_id)
                || matches!(language, "dart" | "swift" | "shell")
                || WITNESSES
                    .iter()
                    .any(|(r, l, ..)| *r == rule_id && *l == language);
            if !owed {
                continue;
            }
            for want in [true, false] {
                if !WITNESSES
                    .iter()
                    .any(|(r, l, _, e)| *r == rule_id && *l == language && *e == want)
                {
                    unwitnessed.push(format!("{rule_id} {language} has no {want} case"));
                }
            }
        }
    }
    assert!(unwitnessed.is_empty(), "{}", unwitnessed.join("\n"));
}

/// Prints the parse tree of a snippet, for writing a query against what the grammar really
/// produces rather than what it plausibly does. Not a test; run by hand:
///
/// `SV_DUMP_LANG=dart SV_DUMP_SRC='…' cargo test -p sv-check --lib dump_trees -- --ignored --nocapture`
#[test]
#[ignore]
fn dump_trees() {
    let lang = std::env::var("SV_DUMP_LANG").unwrap();
    let src = std::env::var("SV_DUMP_SRC").unwrap();
    let mut parser = Parser::new();
    parser.set_language(&grammar(&lang).unwrap()).unwrap();
    let tree = parser.parse(&src, None).unwrap();
    println!("{}", tree.root_node().to_sexp());
}
