//! Each suite says its name as it begins, so a person watching a long run at a terminal sees it
//! move (backlog 226, part 2, item 15), and a suite the manifest does not ask for says nothing.

use super::*;
use std::cell::RefCell;

/// A harness over nothing that writes down each suite's name as it begins, and each request as a
/// mark between them, so the order of the two can be read.
struct Watched {
    said: RefCell<Vec<String>>,
}

struct Quiet;
impl Http for Quiet {
    fn send(&mut self, _request: &ProbeRequest) -> Option<ProbeResponse> {
        None
    }
}

impl Services for Watched {
    fn http<'s>(&'s self, _target: Target, _with: With) -> Box<dyn Http + 's> {
        self.said.borrow_mut().push("(asks)".to_owned());
        Box::new(Quiet)
    }
    fn model_canary(&self) -> Option<String> {
        None
    }
    fn app_log(&self) -> String {
        String::new()
    }
    fn seed(&self, _target: Target, _seed: &str, _accounts: &Accounts) -> Result<(), String> {
        Ok(())
    }
    fn start_switched_off(&self, _setting: &str) -> bool {
        false
    }
    fn remove_switched_off(&self) {}
    fn liveness(&self, after: &str) -> Liveness {
        Liveness {
            after: after.to_owned(),
            status: "running".to_owned(),
            restarts: 0,
            exit_code: 0,
            out_of_memory: false,
            answered: true,
        }
    }
    fn starting(&self, suite: &str) {
        self.said.borrow_mut().push(suite.to_owned());
    }
}

fn accounts() -> Accounts {
    let account = |role: &str| crate::signed_in::Account {
        user: format!("sv-{role}@example.test"),
        password: format!("Sv-{role}-aZ9!"),
    };
    Accounts {
        a: account("a"),
        b: account("b"),
        admin: None,
        spare: "0123456789abcdef0123456789abcdef".to_owned(),
        totp: None,
        admin_totp_secret: None,
    }
}

/// The names said, with the marks between them folded: a name followed by its suite's requests.
fn names_before_requests(said: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in said {
        if line == "(asks)" {
            if out.last().map(String::as_str) != Some("(asks)") {
                out.push(line.clone());
            }
        } else {
            out.push(line.clone());
        }
    }
    out
}

#[test]
fn each_suite_says_its_name_before_it_asks_anything() {
    let watched = Watched {
        said: RefCell::new(Vec::new()),
    };
    let (users, policy) = (UsersSection::default(), PolicySection::default());
    let (oidc, ai) = (OidcSection::default(), AiSection::default());
    let (mcp, fetch) = (McpServerSection::default(), FetchSection::default());
    let accounts = accounts();
    let plan = Plan {
        users: Some(&users),
        policy: &policy,
        oidc: Some(&oidc),
        ai: Some(&ai),
        mcp_server: Some(&mcp),
        fetch: Some(&fetch),
        health_path: "/health",
        slow: false,
        accounts: Some(&accounts),
        mcp_token: Some("t"),
    };
    run(&watched, &plan, &[]);
    assert_eq!(
        names_before_requests(&watched.said.borrow()),
        [
            "the questions asked as somebody not signed in",
            "(asks)",
            "the questions asked as the test users",
            "(asks)",
            "signing in through the test provider",
            "(asks)",
            "the app as an MCP server",
            "(asks)",
            "the feature that fetches an address",
            "(asks)",
            "the AI feature",
            "(asks)",
        ]
    );
}

#[test]
fn a_suite_the_manifest_does_not_ask_for_says_nothing() {
    let watched = Watched {
        said: RefCell::new(Vec::new()),
    };
    let policy = PolicySection::default();
    let plan = Plan {
        users: None,
        policy: &policy,
        oidc: None,
        ai: None,
        mcp_server: None,
        fetch: None,
        health_path: "/",
        slow: false,
        accounts: None,
        mcp_token: None,
    };
    run(&watched, &plan, &[]);
    assert_eq!(
        watched.said.borrow().as_slice(),
        ["the questions asked as somebody not signed in", "(asks)"]
    );
}
