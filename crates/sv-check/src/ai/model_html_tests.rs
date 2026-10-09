//! The model's reply written into the page as HTML (the gap analysis of 7 October 2026, finding
//! 13(b), the test model's half): found when the app's answer is a page holding the reply's tag as it
//! was written, and never judged from an answer in JSON.

use super::tests::{Flaws, ask, credited, found, markup_tag};
use super::*;

fn page(unescaped: bool) -> Flaws {
    let mut flaws = Flaws::default();
    flaws.html_page = true;
    flaws.html_unescaped = unescaped;
    flaws
}

fn markup_step(o: &Outcome) -> &String {
    o.steps
        .iter()
        .find(|s| s.starts_with("had the test model write an HTML tag"))
        .unwrap_or_else(|| panic!("{:?}", o.steps))
}

#[test]
fn a_reply_written_into_the_page_as_html_is_found() {
    let o = ask(page(true));
    let f = o
        .findings
        .iter()
        .find(|f| f.rule_id == REPLY_HTML.rule_id)
        .unwrap_or_else(|| panic!("{:?}", o.steps));
    assert_eq!(f.requirement_ids, ["V1.2.1"]);
    assert!(
        markup_step(&o).ends_with("the page held the tag as it was written"),
        "{}",
        markup_step(&o)
    );
}

#[test]
fn a_page_that_escapes_the_reply_is_said_and_not_credited() {
    let o = ask(page(false));
    assert!(!found(&o).contains(&REPLY_HTML.rule_id), "{:?}", o.findings);
    assert!(!credited(&o).contains(&REPLY_HTML.rule_id));
    // The setup: the reply was in the page, so the page was looked at.
    assert!(
        markup_step(&o).ends_with("the page held it escaped, as text"),
        "{}",
        markup_step(&o)
    );
}

#[test]
fn an_answer_in_json_is_not_judged() {
    // JSON carries the tag as it is, rightly: the page that draws it decides.
    let o = ask(Flaws::default());
    assert!(!found(&o).contains(&REPLY_HTML.rule_id), "{:?}", o.findings);
    assert!(
        markup_step(&o).ends_with("the answer is not a page of HTML, so it was not judged"),
        "{}",
        markup_step(&o)
    );
}

#[test]
fn only_a_raw_image_tag_carrying_the_marker_counts() {
    let tag = "1a2b";
    let raw = format!("<p>{}</p>", markup_tag(tag));
    assert!(holds_raw_markup(&raw, tag));
    // Quotes escaped and the `<` left: still a tag in the page.
    assert!(holds_raw_markup(&raw.replace('"', "&quot;"), tag));
    // The `<` escaped: text.
    assert!(!holds_raw_markup(&raw.replace('<', "&lt;"), tag));
    // An image of the page's own, and the marker outside any tag, say nothing.
    assert!(!holds_raw_markup(
        "<img src=logo.png> SVMARKUP1a2b in a sentence",
        tag
    ));
    // Another message's tag is not this one's.
    assert!(!holds_raw_markup(&markup_tag("9f9f"), tag));
}
