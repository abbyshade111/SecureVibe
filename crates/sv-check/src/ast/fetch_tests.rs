//! `ast.fetch-address-from-request` (the gap analysis of 7 October 2026, finding 11): an outgoing
//! request whose address is taken straight from the incoming one, so whoever sends the request
//! chooses where the server goes. Its own file, so its cases do not land at the end of `tests.rs`.

use super::*;
use std::path::PathBuf;

const RULE: &str = "ast.fetch-address-from-request";

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

const PYTHON: &[(&str, bool)] = &[
    (
        "import requests\ndef f(request):\n    return requests.get(request.args[\"url\"])\n",
        true,
    ),
    (
        "import httpx\ndef f(request):\n    return httpx.post(request.json[\"callback\"], json={})\n",
        true,
    ),
    (
        "from urllib.request import urlopen\ndef f(request):\n    return urlopen(request.GET[\"u\"])\n",
        true,
    ),
    (
        "import requests\ndef f(request):\n    url = request.args.get(\"url\")\n    return requests.get(url)\n",
        true,
    ),
    // A written-out address, one from the app's settings, and a fixed host with a path from the
    // request: the request cannot choose the server.
    (
        "import requests\ndef f():\n    return requests.get(\"https://api.example.com/users\")\n",
        false,
    ),
    (
        "import requests\ndef f(settings):\n    return requests.get(settings.API_BASE + \"/users\")\n",
        false,
    ),
    (
        "import requests\ndef f(request):\n    return requests.get(f\"https://api.example.com/users/{request.args['id']}\")\n",
        false,
    ),
    // Not an outgoing request: a cache's `get`.
    (
        "def f(cache, request):\n    return cache.get(request.args[\"key\"])\n",
        false,
    ),
];

const JAVASCRIPT: &[(&str, bool)] = &[
    (
        "app.get('/p', async (req, res) => res.send(await fetch(req.query.url)));",
        true,
    ),
    (
        "app.post('/p', async (req, res) => res.json(await axios.get(req.body.callback)));",
        true,
    ),
    (
        "app.get('/p', async (req, res) => { const target = req.query.u; res.send(await fetch(target)); });",
        true,
    ),
    (
        "router.get('/p', async (ctx) => { ctx.body = await got(ctx.query.url); });",
        true,
    ),
    (
        "app.get('/p', async (req, res) => res.send(await fetch(process.env.API_BASE + '/users')));",
        false,
    ),
    (
        "app.get('/p', async (req, res) => res.send(await fetch(`https://api.example.com/users/${req.params.id}`)));",
        false,
    ),
    (
        "app.get('/p', async (req, res) => res.send(await fetch('https://api.example.com/users')));",
        false,
    ),
    // Not an outgoing request: the app's own route, and a cache.
    ("app.get(req.query.path, handler);", false),
    ("cache.get(req.query.key);", false),
];

const GO: &[(&str, bool)] = &[
    (
        "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { http.Get(r.URL.Query().Get(\"url\")) }\n",
        true,
    ),
    (
        "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { u := r.FormValue(\"u\"); http.Get(u) }\n",
        true,
    ),
    (
        "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { http.NewRequest(\"GET\", r.URL.Query().Get(\"url\"), nil) }\n",
        true,
    ),
    (
        "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { http.Get(apiBase + \"/users\") }\n",
        false,
    ),
    (
        "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { http.Get(\"https://api.example.com/users/\" + r.URL.Query().Get(\"id\")) }\n",
        false,
    ),
    // The method is the first argument of `NewRequest`, and it is not the address.
    (
        "package main\nimport \"net/http\"\nfunc h(w http.ResponseWriter, r *http.Request) { http.NewRequest(r.FormValue(\"m\"), \"https://api.example.com/x\", nil) }\n",
        false,
    ),
];

#[test]
fn an_address_from_the_request_is_reported_and_one_the_app_chose_is_not() {
    let mut wrong = Vec::new();
    for (language, file, cases) in [
        ("python", "app.py", PYTHON),
        ("javascript", "app.js", JAVASCRIPT),
        ("typescript", "app.ts", JAVASCRIPT),
        ("go", "main.go", GO),
    ] {
        for (source, expected) in cases {
            if reported(language, file, source) != *expected {
                wrong.push(format!("{language}, expected {expected}: {source}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_rule_is_only_ever_a_finding() {
    let rule = rules()
        .rules()
        .find(|r| r.id == RULE)
        .expect("the rule is loaded");
    assert!(rule.findings_only, "finding none credits nothing");
    assert_eq!(rule.requirement_ids, ["V1.3.6", "V13.2.4"]);
}
