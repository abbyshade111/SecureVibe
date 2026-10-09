//! The anonymous questions asked in one go (`Http::send_in_turn`), and what happens when a rate
//! limiter answers one of them: the same answers as asking one at a time, the same waiting, and the
//! one-at-a-time way whenever the way to the app cannot ask in one go (BACKLOG, "From the
//! architecture assessment of 8 October 2026", item 12).

use super::*;
use std::collections::HashMap;

/// An app that answers each request by its id, and a limiter that says no to some of them a set
/// number of times, counting every time it is asked; it can be asked in one go or not.
struct Recorded {
    in_one_go: bool,
    /// How many more times each id is answered by the limiter before the app answers it.
    limited: HashMap<String, u32>,
    /// What reached the app, in order, and how: `true` in one go, `false` alone.
    asked: Vec<(String, bool)>,
    calls_in_one_go: usize,
    waited: u64,
}

impl Recorded {
    fn new(in_one_go: bool) -> Self {
        Recorded {
            in_one_go,
            limited: HashMap::new(),
            asked: Vec::new(),
            calls_in_one_go: 0,
            waited: 0,
        }
    }

    fn answer(&mut self, request: &ProbeRequest, in_one_go: bool) -> Option<ProbeResponse> {
        self.asked.push((request.id.clone(), in_one_go));
        if request.id == "silent" {
            return None;
        }
        if let Some(left) = self.limited.get_mut(&request.id).filter(|n| **n > 0) {
            *left -= 1;
            return Some(ProbeResponse {
                id: request.id.clone(),
                status: 429,
                headers: vec![("retry-after".to_owned(), "3".to_owned())],
                body: "slow down".to_owned(),
            });
        }
        Some(ProbeResponse {
            id: request.id.clone(),
            status: 200,
            headers: Vec::new(),
            body: format!("the app's answer to {}", request.id),
        })
    }
}

impl Http for Recorded {
    fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        self.answer(request, false)
    }

    fn send_in_turn(&mut self, requests: &[ProbeRequest]) -> Option<Vec<Option<ProbeResponse>>> {
        if !self.in_one_go {
            return None;
        }
        self.calls_in_one_go += 1;
        Some(requests.iter().map(|r| self.answer(r, true)).collect())
    }

    fn wait(&mut self, seconds: u64) {
        self.waited += seconds;
    }
}

fn get(id: &str) -> ProbeRequest {
    ProbeRequest {
        id: id.to_owned(),
        method: "GET".to_owned(),
        path: format!("/{id}"),
        headers: Vec::new(),
        body: None,
    }
}

fn requests(ids: &[&str]) -> Vec<ProbeRequest> {
    ids.iter().map(|id| get(id)).collect()
}

fn ids(answers: &[ProbeResponse]) -> Vec<&str> {
    answers.iter().map(|a| a.id.as_str()).collect()
}

#[test]
fn every_question_is_asked_in_one_go_and_none_alone() {
    let asked = requests(&["home", "headers", "cors", "git"]);
    let mut app = Recorded::new(true);
    let (answers, left_out) = ask_anonymously(&mut app, &asked);
    assert_eq!(app.calls_in_one_go, 1);
    assert!(
        app.asked.iter().all(|(_, in_one_go)| *in_one_go),
        "{:?}",
        app.asked
    );
    assert_eq!(app.asked.len(), 4, "each asked once");
    assert_eq!(ids(&answers), ["home", "headers", "cors", "git"]);
    assert!(left_out.is_empty(), "{left_out:?}");
}

#[test]
fn the_answers_are_those_asking_one_at_a_time_gets() {
    let asked = requests(&["home", "silent", "cors", "git"]);
    let mut in_one_go = Recorded::new(true);
    let mut alone = Recorded::new(false);
    let (together, _) = ask_anonymously(&mut in_one_go, &asked);
    let (one_by_one, _) = ask_anonymously(&mut alone, &asked);
    // The control: the second really was asked one at a time.
    assert_eq!(alone.calls_in_one_go, 0);
    assert!(alone.asked.iter().all(|(_, in_one_go)| !*in_one_go));
    // A question with no answer is left out either way, and the rest are the same answers.
    assert_eq!(ids(&together), ["home", "cors", "git"]);
    assert_eq!(together, one_by_one);
}

#[test]
fn from_the_first_limited_answer_on_each_is_asked_alone_and_waited_for_as_before() {
    let asked = requests(&["home", "headers", "cors", "git"]);
    let mut app = Recorded::new(true);
    // The limiter says no to `headers` twice: once in the one go, once more when it is asked alone
    // straight after, and then lets it through after the wait.
    app.limited.insert("headers".to_owned(), 2);
    let (answers, left_out) = ask_anonymously(&mut app, &asked);
    assert_eq!(ids(&answers), ["home", "headers", "cors", "git"]);
    assert!(answers.iter().all(|a| a.status == 200), "{answers:?}");
    assert!(left_out.is_empty(), "{left_out:?}");
    // `home` was answered in the one go and not asked again; from `headers` on, each was asked
    // alone after it, as one at a time would have; the one go asked all four.
    let alone: Vec<&str> = app
        .asked
        .iter()
        .filter(|(_, in_one_go)| !*in_one_go)
        .map(|(id, _)| id.as_str())
        .collect();
    assert_eq!(alone, ["headers", "headers", "cors", "git"]);
    // One wait, of the limiter's own three seconds: the same as asking one at a time.
    assert_eq!(app.waited, 3);
    let mut one_by_one = Recorded::new(false);
    one_by_one.limited.insert("headers".to_owned(), 1);
    ask_anonymously(&mut one_by_one, &asked);
    assert_eq!(one_by_one.waited, app.waited);
}

#[test]
fn an_answer_still_limited_after_the_wait_is_left_out_as_before() {
    let asked = requests(&["home", "headers", "cors"]);
    let mut app = Recorded::new(true);
    app.limited.insert("headers".to_owned(), 99);
    let (answers, left_out) = ask_anonymously(&mut app, &asked);
    assert_eq!(ids(&answers), ["home", "cors"]);
    assert_eq!(left_out, ["headers (429)"]);
}
