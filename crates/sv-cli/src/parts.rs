//! An answer in parts: `stackvet_plan` and `stackvet_check`, in pieces an AI coding tool takes in whole.
//!
//! Found in the loop pilot (5 October 2026, BACKLOG "`sv`'s plan is too big for an AI tool to take in as one
//! answer"): the plan for the trials' club app was 115,618 characters, and Claude Code refused to pass it to the
//! model, saving it to a file instead; a check of one build, 50.2 KB, was saved to a file the same way. The builder
//! then read both back in pieces with a script it wrote. What a builder is given should be what it reads.
//!
//! # The budget, and where it comes from
//!
//! Claude Code is the tool the pilot used, and its limits are the ones on record:
//!
//! - **It refuses an MCP result over 25,000 tokens** (`MAX_MCP_OUTPUT_TOKENS`, its documented default), saving it
//!   to a file and telling the model only where. The plan hit this one.
//! - **It saves any tool result over 50,000 characters to a file** and shows the model a 2 KB preview. The check hit
//!   this one, at 50.2 KB; a check of 38 KB in the same trials was passed whole. The 50,000 is not in Claude Code's
//!   documentation: it was read from the program the pilot ran (2.1.286), where it is the default for every MCP tool,
//!   and it agrees with what the transcripts show.
//! - **It hands the model the structured result, not the text**, when a tool sends one: the pilot's saved files
//!   are the structured result as compact JSON. So the structured result has to fit as well as the text does;
//!   other clients read the text.
//!
//! [`ANSWER_BUDGET`] keeps each answer, its text and its structured result each measured on its own, to 40,000
//! bytes: a fifth under the 50,000 characters (a byte is never fewer characters than one), and about 10,000 to
//! 13,000 tokens, half Claude Code's token limit. Other clients' limits were not found on record; one that passes
//! less than this would still need the parts, which is why they are small rather than just under Claude Code's line.
//!
//! # What an answer holds
//!
//! An answer is made of sections, in the order of the whole answer, each in pages of at most [`PAGE`]. Asked
//! with no `section`, the tool gives the whole answer exactly as before when it fits the budget, so a small app sees
//! no change. When it does not, it gives as many pages as fit, in the order a builder needs them (for a plan: the
//! decisions and the run settings before the requirements), and then a list of every section with its pages and the
//! argument that asks for each. `section` and `page` ask for a page, and the answer holds the pages after it in
//! that section while they fit; `"section": "all"` gives the whole answer at once, as before, for a client that
//! takes it.
//!
//! **Nothing is dropped.** Every page is cut from the same sections the whole answer is joined from, at the end of a
//! line, and the structured result is cut at the same places: the items on a page are the items of its lines. A
//! field a page holds none of is left out of that page's structured result, never sent empty, so an absent list
//! cannot be read as "none"; `part` in it says which pages it holds. A test joins every page of the club app's plan
//! and check and holds them to the whole answer.
//!
//! **The app's text stays fenced in every part** (deep review R9): each answer is made with `fence::fenced`, so its
//! tags are named for that answer and appear nowhere in it, and it says first what they mean.

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use sv_report::fence::Fence;

/// The most one answer holds, in bytes: its text, and separately its structured result as compact JSON. See the
/// module's documentation for why 40,000.
pub const ANSWER_BUDGET: usize = 40_000;

/// The most the pages in one answer hold together, leaving the rest of [`ANSWER_BUDGET`] for what frames them: the
/// list of sections, the line naming each page, what the fence's tags mean, and the fields every part carries.
pub const PAGE_BUDGET: usize = 30_000;

/// The most one page holds, in its text and in its structured items alike: half of [`PAGE_BUDGET`], so that a
/// first answer can hold the start of a long section after the short ones before it, and an answer asked for one
/// page can hold the next too. An item larger than this has a page of its own.
pub const PAGE: usize = 15_000;

/// One line or a few of an answer, and the item of the structured result it shows, if any.
pub struct Item {
    pub text: String,
    /// The structured result's list this item belongs in, and the item.
    pub data: Option<(&'static str, Value)>,
}

impl Item {
    pub fn text(text: String) -> Item {
        Item { text, data: None }
    }
    pub fn with(text: String, field: &'static str, data: Value) -> Item {
        Item {
            text,
            data: Some((field, data)),
        }
    }
}

/// One section of an answer.
pub struct Section {
    /// The name `section` asks for it by.
    pub name: &'static str,
    /// What it is, in `sv`'s own words: never the app's text, since the list of sections is not fenced.
    pub title: String,
    /// What opens it, on its first page.
    pub lead: String,
    pub items: Vec<Item>,
    /// The structured result's lists its items fill.
    pub fields: &'static [&'static str],
}

impl Section {
    pub fn new(name: &'static str, title: String, fields: &'static [&'static str]) -> Section {
        Section {
            name,
            title,
            lead: String::new(),
            items: Vec::new(),
            fields,
        }
    }

    /// Its whole text, as the whole answer has it.
    pub fn text(&self) -> String {
        let mut out = self.lead.clone();
        for item in &self.items {
            out.push_str(&item.text);
        }
        out
    }

    /// The items on each page. The first page also holds the lead; a section with no items has one page.
    fn pages(&self) -> Vec<std::ops::Range<usize>> {
        let mut pages = Vec::new();
        let (mut start, mut text, mut data) = (0, self.lead.len(), 0);
        for (n, item) in self.items.iter().enumerate() {
            let (t, d) = (item.text.len(), item_bytes(item));
            if n > start && (text + t > PAGE || data + d > PAGE) {
                pages.push(start..n);
                (start, text, data) = (n, 0, 0);
            }
            text += t;
            data += d;
        }
        pages.push(start..self.items.len());
        pages
    }
}

/// Pages in the order given, while they fit [`PAGE_BUDGET`] together; always the first.
fn fill(
    order: impl Iterator<Item = (usize, usize)>,
    sections: &[Section],
    pages: &[Vec<std::ops::Range<usize>>],
) -> Vec<(usize, usize)> {
    let (mut units, mut text, mut data) = (Vec::new(), 0, 0);
    for (s, p) in order {
        let section = &sections[s];
        let items = &section.items[pages[s][p].clone()];
        let lead = if p == 0 { section.lead.len() } else { 0 };
        let t = lead + items.iter().map(|i| i.text.len()).sum::<usize>();
        let d: usize = items.iter().map(item_bytes).sum();
        if !units.is_empty() && (text + t > PAGE_BUDGET || data + d > PAGE_BUDGET) {
            break;
        }
        units.push((s, p));
        (text, data) = (text + t, data + d);
    }
    units
}

/// What an item adds to the structured result, as compact JSON with the comma between it and the next.
fn item_bytes(item: &Item) -> usize {
    item.data
        .as_ref()
        .map_or(0, |(_, v)| v.to_string().len() + 1)
}

/// What the tool was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// No `section`: the whole answer if it fits, and otherwise its first pages and the list of the rest.
    First,
    /// `"section": "all"`: the whole answer, whatever its size.
    All,
    /// One page of one section.
    Part { section: String, page: usize },
}

/// Reads `section` and `page` from a tool's arguments, refusing a section the tool does not have.
pub fn ask(args: &Value, tool: &str, names: &[&str]) -> Result<Ask> {
    let section = args.get("section").filter(|v| !v.is_null());
    let page = args.get("page").filter(|v| !v.is_null());
    let page = match page {
        None => None,
        Some(p) => match p.as_u64() {
            Some(p) if p >= 1 => Some(p as usize),
            _ => bail!("`page` for {tool} is a whole number from 1"),
        },
    };
    let Some(section) = section else {
        if page.is_some() {
            bail!(
                "`page` for {tool} needs a `section` too; the sections are {}",
                names.join(", ")
            );
        }
        return Ok(Ask::First);
    };
    let Some(section) = section.as_str() else {
        bail!(
            "`section` for {tool} is one of {}, or all",
            names.join(", ")
        );
    };
    if section == "all" {
        return Ok(Ask::All);
    }
    if !names.contains(&section) {
        bail!(
            "{tool} has no section {section:?}; its sections are {}, or all for the whole answer",
            names.join(", ")
        );
    }
    Ok(Ask::Part {
        section: section.to_owned(),
        page: page.unwrap_or(1),
    })
}

/// One answer of a tool whose answer comes in parts.
pub struct Answer<'a> {
    pub tool: &'static str,
    /// What the answer is, for the list of parts: "plan" or "check".
    pub what: &'static str,
    /// Its sections, in the order of the whole answer, made with the fence given.
    pub sections: &'a dyn Fn(&Fence) -> Vec<Section>,
    /// The sections the first answer starts with, in that order; the rest follow in the whole answer's order.
    pub first: &'a [&'static str],
    /// The structured result's fields every part carries.
    pub always: Map<String, Value>,
    /// The whole answer, as it was before it came in parts.
    pub whole_text: &'a dyn Fn(&Fence) -> String,
    pub whole_structured: Value,
}

/// The tool's result for what was asked.
pub fn respond(answer: &Answer, ask: &Ask) -> Result<Value> {
    let whole = || {
        json!({
            "content": [{ "type": "text", "text": sv_report::fence::fenced(answer.whole_text) }],
            "structuredContent": answer.whole_structured.clone(),
            "isError": false,
        })
    };
    // The pages are worked out with a fence whose tags are as long as any answer's, so they come out the same
    // size in every answer: a tag's name is always the same length.
    let measured = (answer.sections)(&Fence::for_draft(""));
    let pages: Vec<Vec<std::ops::Range<usize>>> = measured.iter().map(Section::pages).collect();
    let index = |name: &str| measured.iter().position(|s| s.name == name);
    let units: Vec<(usize, usize)> = match ask {
        Ask::All => return Ok(whole()),
        Ask::First => {
            let text = sv_report::fence::fenced(answer.whole_text);
            if text.len() <= ANSWER_BUDGET
                && answer.whole_structured.to_string().len() <= ANSWER_BUDGET
            {
                return Ok(whole());
            }
            let mut order: Vec<usize> = answer.first.iter().filter_map(|n| index(n)).collect();
            let rest: Vec<usize> = (0..measured.len()).filter(|n| !order.contains(n)).collect();
            order.extend(rest);
            let all = order
                .iter()
                .flat_map(|&s| (0..pages[s].len()).map(move |p| (s, p)));
            fill(all, &measured, &pages)
        }
        Ask::Part { section, page } => {
            let s = index(section).expect("the section was checked against the tool's names");
            if *page > pages[s].len() {
                bail!(
                    "{}'s section {section} has {} page{}, so there is no page {page}",
                    answer.tool,
                    pages[s].len(),
                    if pages[s].len() == 1 { "" } else { "s" }
                );
            }
            // The page asked for, and the ones after it in the same section while they fit.
            fill(
                (page - 1..pages[s].len()).map(|p| (s, p)),
                &measured,
                &pages,
            )
        }
    };

    let text = sv_report::fence::fenced(|fence| {
        let sections = (answer.sections)(fence);
        let mut out = String::new();
        for &(s, p) in &units {
            let section = &sections[s];
            let mut body = if p == 0 {
                section.lead.clone()
            } else {
                String::new()
            };
            for item in &section.items[pages[s][p].clone()] {
                body.push_str(&item.text);
            }
            // A page with no text (an empty section, or one in the structured result only) is named in
            // the list of parts, not given a line of its own here.
            if !body.is_empty() {
                out.push_str(&format!(
                    "{}{}, page {} of {}]\n{body}",
                    MARK,
                    section.name,
                    p + 1,
                    pages[s].len()
                ));
            }
        }
        out.push_str(&list_of_parts(answer, &sections, &pages, &units));
        out
    });

    let mut structured = answer.always.clone();
    for &(s, p) in &units {
        let section = &measured[s];
        for field in section.fields {
            let items: Vec<Value> = section.items[pages[s][p].clone()]
                .iter()
                .filter_map(|i| i.data.as_ref())
                .filter(|(f, _)| f == field)
                .map(|(_, v)| v.clone())
                .collect();
            let none_at_all = !section
                .items
                .iter()
                .any(|i| i.data.as_ref().is_some_and(|(f, _)| f == field));
            // A list is sent when this part holds some of it, or when it is empty and this is where it would be.
            if !items.is_empty() || (none_at_all && p == 0) {
                let list = structured
                    .entry(field.to_string())
                    .or_insert_with(|| json!([]));
                list.as_array_mut()
                    .expect("a field filled by items is a list")
                    .extend(items);
            }
        }
    }
    structured.insert(
        "part".to_owned(),
        json!({
            "shown": units.iter().map(|&(s, p)| json!({
                "section": measured[s].name, "page": p + 1, "pages": pages[s].len(),
            })).collect::<Vec<_>>(),
            "sections": measured.iter().zip(&pages).map(|(s, p)| json!({
                "section": s.name, "title": s.title, "pages": p.len(),
                "fields": s.fields,
            })).collect::<Vec<_>>(),
            "howToAsk": how_to_ask(answer),
        }),
    );
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": Value::Object(structured),
        "isError": false,
    }))
}

/// What opens each page in an answer's text, before the section's name and the page.
pub const MARK: &str = "[part: ";

/// What opens the list of parts at the end of an answer's text.
pub const PARTS: &str = "[the parts of this answer]";

fn how_to_ask(answer: &Answer) -> String {
    format!(
        "Call {} again for the same app with `section` set to a section's name, and `page` when it has more \
         than one page (pages start at 1). `\"section\": \"all\"` gives the whole {} at once, which may be more \
         than you can take in whole.",
        answer.tool, answer.what
    )
}

fn list_of_parts(
    answer: &Answer,
    sections: &[Section],
    pages: &[Vec<std::ops::Range<usize>>],
    units: &[(usize, usize)],
) -> String {
    let mut out = format!(
        "\n{PARTS}\nThis {} is in parts so that each answer fits what an AI coding tool takes in whole, about \
         {},{:03} characters. Nothing is left out: every part below is a piece of the whole {}. {}\n",
        answer.what,
        ANSWER_BUDGET / 1000,
        ANSWER_BUDGET % 1000,
        answer.what,
        how_to_ask(answer)
    );
    for (s, section) in sections.iter().enumerate() {
        let n = pages[s].len();
        let shown: Vec<usize> = units
            .iter()
            .filter(|(u, _)| *u == s)
            .map(|(_, p)| p + 1)
            .collect();
        let no_text = section.lead.is_empty() && section.items.iter().all(|i| i.text.is_empty());
        let mut line = format!("- `{}`: {}", section.name, section.title);
        if section.items.is_empty() && no_text {
            line.push_str(", empty");
        } else if no_text {
            line.push_str(", in the structured result only");
        }
        line.push_str(&if n == 1 {
            String::from(", 1 page")
        } else {
            format!(", {n} pages")
        });
        if shown.len() == n {
            line.push_str(", shown here");
        } else if !shown.is_empty() {
            let (first, last) = (shown[0], shown[shown.len() - 1]);
            let these = if first == last {
                format!("page {first}")
            } else {
                format!("pages {first} to {last}")
            };
            line.push_str(&format!(", {these} shown here"));
            if first > 1 {
                line.push_str(&format!(
                    "; earlier pages with {{\"section\": \"{}\", \"page\": 1}}",
                    section.name
                ));
            }
            if last < n {
                line.push_str(&format!(
                    "; ask for the next with {{\"section\": \"{}\", \"page\": {}}}",
                    section.name,
                    last + 1
                ));
            }
        } else if n == 1 {
            line.push_str(&format!(": {{\"section\": \"{}\"}}", section.name));
        } else {
            line.push_str(&format!(
                ": {{\"section\": \"{}\", \"page\": 1}} to {}",
                section.name, n
            ));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A section `name` with `n` items of `size` bytes of text each, every one an item of `field`.
    fn items(field: &'static str, n: usize, size: usize) -> Vec<Item> {
        (0..n)
            .map(|i| {
                Item::with(
                    format!("{:>width$}\n", i, width = size - 1),
                    field,
                    json!(i),
                )
            })
            .collect()
    }

    fn sections(_: &Fence) -> Vec<Section> {
        // Two lists in one section, the first filling more than a page, then a list nobody has items of.
        let mut both = Section::new("both", "Two lists".to_owned(), &["first", "second"]);
        both.lead = "## Both\n".to_owned();
        both.items = items("first", 14, 2_000);
        both.items.extend(items("second", 3, 2_000));
        let mut empty = Section::new("empty", "Nothing".to_owned(), &["none"]);
        empty.lead = "## Empty\n".to_owned();
        vec![both, empty]
    }

    fn whole_text(fence: &Fence) -> String {
        sections(fence).iter().map(Section::text).collect()
    }

    fn answer() -> Answer<'static> {
        let mut always = Map::new();
        always.insert("app".to_owned(), json!("t"));
        Answer {
            tool: "t",
            what: "test",
            sections: &sections,
            first: &["both", "empty"],
            always,
            whole_text: &whole_text,
            whole_structured: json!({ "app": "t", "first": [], "second": [], "none": [], "padding": "x".repeat(ANSWER_BUDGET) }),
        }
    }

    fn part(section: &str, page: usize) -> Value {
        respond(
            &answer(),
            &Ask::Part {
                section: section.to_owned(),
                page,
            },
        )
        .unwrap()["structuredContent"]
            .clone()
    }

    #[test]
    fn a_list_a_page_holds_none_of_is_left_out_and_an_empty_one_is_sent_empty() {
        // The setup: the section is on three pages, the first list on the first two and the second list only on
        // the last, and the first two pages fit one answer together.
        let pages = sections(&Fence::none())[0].pages();
        assert_eq!(pages, [0..7, 7..14, 14..17]);
        let first = part("both", 1);
        assert_eq!(
            first["part"]["shown"].as_array().unwrap().len(),
            2,
            "{first:#}"
        );
        assert_eq!(first["first"].as_array().unwrap().len(), 14, "{first:#}");
        assert!(first.get("second").is_none(), "{first:#}");
        let last = part("both", 3);
        assert!(last.get("first").is_none(), "{last:#}");
        assert_eq!(last["second"], json!([0, 1, 2]));
        // A list with no items at all is sent empty where it would be, so "none" is said.
        assert_eq!(part("empty", 1)["none"], json!([]));
        assert_eq!(part("empty", 1)["app"], "t");
    }

    #[test]
    fn an_item_larger_than_a_page_has_a_page_of_its_own() {
        let mut s = Section::new("big", String::new(), &["x"]);
        s.items = items("x", 1, 10);
        s.items.extend(items("x", 1, PAGE + 1));
        s.items.extend(items("x", 1, 10));
        assert_eq!(s.pages(), [0..1, 1..2, 2..3]);
    }

    #[test]
    fn what_is_asked_for_is_read_and_a_section_that_is_not_there_refused() {
        let names = &["a", "b"];
        assert_eq!(ask(&json!({}), "t", names).unwrap(), Ask::First);
        assert_eq!(
            ask(&json!({ "section": "all" }), "t", names).unwrap(),
            Ask::All
        );
        assert_eq!(
            ask(&json!({ "section": "b", "page": 3 }), "t", names).unwrap(),
            Ask::Part {
                section: "b".to_owned(),
                page: 3
            }
        );
        assert_eq!(
            ask(&json!({ "section": "a" }), "t", names).unwrap(),
            Ask::Part {
                section: "a".to_owned(),
                page: 1
            }
        );
        for bad in [
            json!({ "section": "c" }),
            json!({ "page": 2 }),
            json!({ "section": "a", "page": 0 }),
            json!({ "section": "a", "page": "2" }),
            json!({ "section": 1 }),
        ] {
            assert!(ask(&bad, "t", names).is_err(), "{bad}");
        }
    }
}
