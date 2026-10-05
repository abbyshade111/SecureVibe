//! Where in securevibe.toml a field went wrong, and where it belongs.
//!
//! serde's `deny_unknown_fields` says "unknown field `enabled`, expected one of `chat`, …" and
//! nothing else: not which section the line was read in. In the loop pilot an AI coding tool wrote
//! `enabled = true` under `[stack.run.ai]`, was told the field and the fields allowed, and sent the
//! same file back five times before it put the field under `[capabilities.ai]`, where it belongs
//! (DESIGN, "A misplaced field names its section"). This module finds the section from the error's
//! position in the file, and finds every other section that takes a field of that name from the
//! manifest's own types, so the list cannot fall behind the code the way a list written by hand
//! would.
//!
//! The sections come from walking the `Deserialize` implementations themselves: a deserializer that
//! holds no data, and that answers each struct by noting the fields serde says it has and then
//! visiting every one of them, each option as present, each list as one entry, each keyed table as
//! one key. serde passes a struct's field names, as written in the file, to `deserialize_struct`;
//! that is the whole trick.

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor};
use std::cell::RefCell;
use std::fmt;

/// One step of a section's place in the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A field with this name.
    Key(&'static str),
    /// Any key of a keyed table, such as the requirement id in `[design.V1.2.3]`.
    AnyKey,
    /// One entry of an array of tables, such as `[[finding-review]]`.
    Entry,
}

/// A table the manifest reads, and the fields it takes.
#[derive(Debug, Clone)]
pub struct Section {
    pub path: Vec<Step>,
    pub fields: &'static [&'static str],
}

impl Section {
    /// The section as it is written in securevibe.toml: `[capabilities.ai]`, `[[finding-review]]`,
    /// `[design.<key>]`, or "the top level" for the fields before any `[section]`.
    pub fn name(&self) -> String {
        if self.path.is_empty() {
            return "the top level (before any [section])".to_owned();
        }
        let mut parts: Vec<String> = Vec::new();
        for step in &self.path {
            match step {
                Step::Key(k) => parts.push(quoted(k)),
                Step::AnyKey => parts.push("<key>".to_owned()),
                Step::Entry => {}
            }
        }
        if self.path.last() == Some(&Step::Entry) {
            format!("[[{}]]", parts.join("."))
        } else {
            format!("[{}]", parts.join("."))
        }
    }

    /// Whether a place in a real file is this section.
    fn matches(&self, at: &[Place]) -> bool {
        self.path.len() == at.len()
            && self
                .path
                .iter()
                .zip(at)
                .all(|(step, place)| match (step, place) {
                    (Step::Key(k), Place::Key(name)) => k == name,
                    (Step::AnyKey, Place::Key(_)) => true,
                    (Step::Entry, Place::Entry(_)) => true,
                    _ => false,
                })
    }
}

/// Every table `Manifest` reads, from its own `Deserialize` implementation.
pub fn sections() -> Vec<Section> {
    let found = RefCell::new(Vec::new());
    let probe = Probe {
        path: Vec::new(),
        found: &found,
    };
    // A walk that stops early would leave sections out, and a suggestion missing. The walk gives
    // every type a value it accepts, so it does not stop; a test holds it to finishing.
    let walked = crate::Manifest::deserialize(probe);
    debug_assert!(walked.is_ok(), "the schema walk stopped: {walked:?}");
    found.into_inner()
}

/// A place in a real file: a key, or the entry of an array of tables, counted from 0.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Place {
    Key(String),
    Entry(usize),
}

/// What to say about a TOML error in securevibe.toml. The line, the pointer to it, and the fields
/// allowed are kept; an unknown field is named with the section it was read in, and with the
/// sections where a field of that name belongs, if any. Any other error that points into a section
/// says which section.
pub fn explain(text: &str, error: &toml::de::Error) -> String {
    let shown = error.to_string();
    let Some(span) = error.span() else {
        return shown;
    };
    let Ok(document) = toml::de::DeTable::parse(text) else {
        return shown;
    };
    let Some(at) = locate(document.get_ref(), &span, &mut Vec::new()) else {
        return shown;
    };
    let message = error.message();
    // The snippet toml draws above its message, kept as it is.
    let snippet = shown
        .strip_suffix(&format!("{message}\n"))
        .unwrap_or(&shown)
        .to_owned();
    let all = sections();
    let here = describe(&at.table);
    let said = match unknown_field(message) {
        Some(field) => {
            let mut said = format!("`{field}` is not a field of {here}.");
            let elsewhere: Vec<String> = all
                .iter()
                .filter(|s| s.fields.contains(&field))
                .map(Section::name)
                .collect();
            if !elsewhere.is_empty() {
                said.push_str(&format!(
                    " Did you mean {}? `{field}` is a field there.",
                    or_list(&elsewhere)
                ));
            }
            match all.iter().find(|s| s.matches(&at.table)) {
                Some(s) if s.fields.is_empty() => {
                    said.push_str(&format!("\n{} takes no fields.", describe(&at.table)));
                }
                Some(s) => said.push_str(&format!(
                    "\nThe fields {} takes are {}.",
                    describe(&at.table),
                    s.fields
                        .iter()
                        .map(|f| format!("`{f}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                // Not a section the walk knows, which should not happen: serde's own list, then.
                None => said.push_str(&format!("\n({message})")),
            }
            said
        }
        None => format!("{message} (in {here})"),
    };
    format!("{snippet}{said}\n")
}

/// The field serde's `deny_unknown_fields` names, from its message.
fn unknown_field(message: &str) -> Option<&str> {
    let rest = message.strip_prefix("unknown field `")?;
    Some(&rest[..rest.find('`')?])
}

/// The section a real place is, as written in the file: `[stack.run.ai]`, `[design."V1.2.3"]`, or
/// `[[finding-review]] number 2`.
fn describe(table: &[Place]) -> String {
    if table.is_empty() {
        return "the top level (before any [section])".to_owned();
    }
    let mut keys: Vec<String> = Vec::new();
    let mut entry: Option<(String, usize)> = None;
    for place in table {
        match place {
            Place::Key(k) => keys.push(quoted(k)),
            Place::Entry(i) => entry = Some((keys.join("."), *i)),
        }
    }
    match (entry, table.last()) {
        (Some((array, i)), Some(Place::Entry(_))) => format!("[[{array}]] number {}", i + 1),
        (Some((array, i)), _) => format!("[{}] in [[{array}]] number {}", keys.join("."), i + 1),
        (None, _) => format!("[{}]", keys.join(".")),
    }
}

/// A key as TOML needs it written: bare when it can be, quoted otherwise.
fn quoted(key: &str) -> String {
    if !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        key.to_owned()
    } else {
        format!("{key:?}")
    }
}

fn or_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} or {b}"),
        [rest @ .., last] => format!("{}, or {last}", rest.join(", ")),
    }
}

/// Where an error's position is: the table it is in.
struct Located {
    table: Vec<Place>,
}

/// The table holding the key or value the span points into. A span on a key is that key's error,
/// in the table holding the key; a span inside a table's value is looked for further in.
fn locate(
    table: &toml::de::DeTable<'_>,
    span: &std::ops::Range<usize>,
    path: &mut Vec<Place>,
) -> Option<Located> {
    for (key, value) in table.iter() {
        let name = key.get_ref().to_string();
        if within(span, &key.span()) {
            return Some(Located {
                table: path.clone(),
            });
        }
        path.push(Place::Key(name));
        let found = locate_value(value, span, path);
        path.pop();
        if found.is_some() {
            return found;
        }
    }
    None
}

fn locate_value(
    value: &toml::Spanned<toml::de::DeValue<'_>>,
    span: &std::ops::Range<usize>,
    path: &mut Vec<Place>,
) -> Option<Located> {
    match value.get_ref() {
        toml::de::DeValue::Table(inner) => locate(inner, span, path).or_else(|| {
            within(span, &value.span()).then(|| Located {
                table: path.clone(),
            })
        }),
        toml::de::DeValue::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(Place::Entry(i));
                let found = locate_value(item, span, path);
                path.pop();
                if found.is_some() {
                    return found;
                }
            }
            None
        }
        // An error on a plain value is in the table that holds its key.
        _ => within(span, &value.span()).then(|| {
            let mut table = path.clone();
            table.pop();
            Located { table }
        }),
    }
}

fn within(inner: &std::ops::Range<usize>, outer: &std::ops::Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end && outer.start < outer.end
}

// The walk over the manifest's types.

#[derive(Debug)]
struct ProbeError(String);

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProbeError {}

impl de::Error for ProbeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        ProbeError(msg.to_string())
    }
}

/// Deep enough for any manifest; a type that refers to itself would otherwise walk forever.
const DEEPEST: usize = 24;

struct Probe<'a> {
    path: Vec<Step>,
    found: &'a RefCell<Vec<Section>>,
}

impl<'a> Probe<'a> {
    fn deeper(&self, step: Step) -> Result<Probe<'a>, ProbeError> {
        if self.path.len() >= DEEPEST {
            return Err(ProbeError("the manifest's types nest too deep".into()));
        }
        let mut path = self.path.clone();
        path.push(step);
        Ok(Probe {
            path,
            found: self.found,
        })
    }
}

macro_rules! answer {
    ($($method:ident => $visit:ident($($value:expr)?)),* $(,)?) => {
        $(fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, ProbeError> {
            visitor.$visit($($value)?)
        })*
    };
}

impl<'de> de::Deserializer<'de> for Probe<'_> {
    type Error = ProbeError;

    answer! {
        deserialize_any => visit_unit(),
        deserialize_bool => visit_bool(false),
        deserialize_i8 => visit_i64(0),
        deserialize_i16 => visit_i64(0),
        deserialize_i32 => visit_i64(0),
        deserialize_i64 => visit_i64(0),
        deserialize_u8 => visit_u64(0),
        deserialize_u16 => visit_u64(0),
        deserialize_u32 => visit_u64(0),
        deserialize_u64 => visit_u64(0),
        deserialize_f32 => visit_f64(0.0),
        deserialize_f64 => visit_f64(0.0),
        deserialize_char => visit_char('x'),
        deserialize_str => visit_str(""),
        deserialize_string => visit_str(""),
        deserialize_bytes => visit_bytes(&[]),
        deserialize_byte_buf => visit_bytes(&[]),
        deserialize_unit => visit_unit(),
        deserialize_identifier => visit_str(""),
        deserialize_ignored_any => visit_unit(),
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, ProbeError> {
        visitor.visit_some(self)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, ProbeError> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, ProbeError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, ProbeError> {
        visitor.visit_seq(OneEntry {
            probe: Some(self.deeper(Step::Entry)?),
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, ProbeError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, ProbeError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, ProbeError> {
        visitor.visit_map(OneKey {
            probe: Some(self.deeper(Step::AnyKey)?),
            value: None,
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, ProbeError> {
        self.found.borrow_mut().push(Section {
            path: self.path.clone(),
            fields,
        });
        visitor.visit_map(EveryField {
            probe: self,
            fields,
            next: 0,
        })
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, ProbeError> {
        let first: &'static str = variants
            .first()
            .ok_or_else(|| ProbeError("an enum with no variants".into()))?;
        visitor.visit_enum(first.into_deserializer())
    }
}

/// A struct's fields, each given once.
struct EveryField<'a> {
    probe: Probe<'a>,
    fields: &'static [&'static str],
    next: usize,
}

impl<'de> MapAccess<'de> for EveryField<'_> {
    type Error = ProbeError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, ProbeError> {
        match self.fields.get(self.next) {
            Some(field) => seed.deserialize(field.into_deserializer()).map(Some),
            None => Ok(None),
        }
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<T::Value, ProbeError> {
        let field = self.fields[self.next];
        self.next += 1;
        seed.deserialize(self.probe.deeper(Step::Key(field))?)
    }
}

/// A list of one entry.
struct OneEntry<'a> {
    probe: Option<Probe<'a>>,
}

impl<'de> SeqAccess<'de> for OneEntry<'_> {
    type Error = ProbeError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, ProbeError> {
        match self.probe.take() {
            Some(probe) => seed.deserialize(probe).map(Some),
            None => Ok(None),
        }
    }
}

/// A keyed table of one key.
struct OneKey<'a> {
    probe: Option<Probe<'a>>,
    value: Option<Probe<'a>>,
}

impl<'de> MapAccess<'de> for OneKey<'_> {
    type Error = ProbeError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, ProbeError> {
        match self.probe.take() {
            Some(probe) => {
                self.value = Some(probe);
                seed.deserialize("key".into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<T::Value, ProbeError> {
        let probe = self
            .value
            .take()
            .ok_or_else(|| ProbeError("a value with no key".into()))?;
        seed.deserialize(probe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `sv` says about `text`, through the same `Manifest::parse` every command and MCP tool
    /// reads securevibe.toml with. The text must be refused: a test whose file was read would
    /// assert nothing.
    fn said(text: &str) -> String {
        match crate::Manifest::parse(text, std::path::Path::new("securevibe.toml")) {
            Ok(_) => panic!("the manifest was read, so there is no message to look at:\n{text}"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn the_walk_over_the_types_finishes_and_finds_every_kind_of_section() {
        let found = RefCell::new(Vec::new());
        let walked = crate::Manifest::deserialize(Probe {
            path: Vec::new(),
            found: &found,
        });
        assert!(walked.is_ok(), "{walked:?}");
        let names: Vec<String> = found.into_inner().iter().map(Section::name).collect();
        for expected in [
            "the top level (before any [section])",
            "[app]",
            "[capabilities.ai]",
            "[stack.run.ai]",
            "[stack.run.users.upload]",
            "[[finding-review]]",
            "[[stack.run.users.admin-actions]]",
            "[[stack.run.users.flow.steps]]",
            "[design.<key>]",
            "[design.<key>.confirmed]",
            "[policy.fix-within-days]",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "{expected} in {names:?}"
            );
        }
    }

    #[test]
    fn the_pilots_field_under_the_run_section_names_both_sections() {
        // Haiku 4.5's file in the loop pilot, the line that came back five times.
        let text =
            "manifest-version = 1\n[app]\nname = \"club\"\n\n[stack.run.ai]\nenabled = true\n";
        let message = said(text);
        assert!(
            message.contains("`enabled` is not a field of [stack.run.ai]."),
            "{message}"
        );
        assert!(
            message.contains("Did you mean [capabilities.ai]? `enabled` is a field there."),
            "{message}"
        );
        // The line, the pointer to it, and the fields allowed are kept.
        assert!(message.contains("line 6, column 1"), "{message}");
        assert!(message.contains("6 | enabled = true"), "{message}");
        assert!(
            message.contains("The fields [stack.run.ai] takes are `chat`, `signed-in`"),
            "{message}"
        );
        assert!(message.contains("parsing securevibe.toml"), "{message}");
    }

    #[test]
    fn a_field_that_belongs_in_two_other_sections_names_both() {
        // `mcp-server` is a yes-or-no in [capabilities] and a section of its own in [stack.run].
        let message = said("[app]\nmcp-server = true\n");
        assert!(
            message.contains("`mcp-server` is not a field of [app]."),
            "{message}"
        );
        assert!(
            message.contains("Did you mean [stack.run] or [capabilities]?"),
            "{message}"
        );
    }

    #[test]
    fn a_field_no_section_takes_suggests_nothing() {
        let message = said("[capabilities.ai]\nenabledd = true\n");
        assert!(
            message.contains("`enabledd` is not a field of [capabilities.ai]."),
            "{message}"
        );
        assert!(!message.contains("Did you mean"), "{message}");
        assert!(
            message.contains("The fields [capabilities.ai] takes are `enabled`"),
            "{message}"
        );
    }

    #[test]
    fn a_field_deep_in_the_run_section_is_named_with_its_whole_path() {
        let text = "[stack.run.users]\nlogin = { path = \"/login\" }\n\n\
                    [stack.run.users.upload]\npath = \"/up\"\nfield = \"file\"\nkill-switch = \"AI=off\"\n";
        let message = said(text);
        assert!(
            message.contains("`kill-switch` is not a field of [stack.run.users.upload]."),
            "{message}"
        );
        assert!(
            message.contains("Did you mean [stack.run.ai]?"),
            "{message}"
        );
        assert!(message.contains("line 7"), "{message}");
    }

    #[test]
    fn a_field_in_an_inline_table_names_the_table_it_is_in() {
        let message = said("[policy]\nfix-within-days = { urgent = 1 }\n");
        assert!(
            message.contains("`urgent` is not a field of [policy.fix-within-days]."),
            "{message}"
        );
        assert!(
            message.contains("`critical`, `high`, `medium`, `low`"),
            "{message}"
        );
    }

    #[test]
    fn an_entry_of_an_array_of_tables_is_named_by_its_number() {
        let entry = |extra: &str| {
            format!(
                "[[finding-review]]\nrule = \"r\"\nfile = \"a.js\"\nfingerprint = \"f\"\nverdict = \"false-alarm\"\n{extra}\n"
            )
        };
        let text = format!("{}{}", entry(""), entry("answer = \"yes\""));
        let message = said(&text);
        assert!(
            message.contains("`answer` is not a field of [[finding-review]] number 2."),
            "{message}"
        );
        assert!(message.contains("Did you mean [design.<key>]"), "{message}");
        assert!(message.contains("line 12"), "{message}");
        assert!(
            message.contains("The fields [[finding-review]] number 2 takes are `rule`, `file`"),
            "{message}"
        );

        // An array of tables inside another section.
        let message = said(
            "[stack.run.users]\n[[stack.run.users.admin-actions]]\npath = \"/a\"\ncheck = \"/b\"\nchat = 1\n",
        );
        assert!(
            message
                .contains("`chat` is not a field of [[stack.run.users.admin-actions]] number 1."),
            "{message}"
        );
        assert!(
            message.contains("Did you mean [stack.run.ai]?"),
            "{message}"
        );
    }

    #[test]
    fn a_keyed_section_is_named_with_its_key() {
        let message = said("[design.\"V6.2.1\"]\nanswer = \"yes\"\nresult = \"done\"\n");
        assert!(
            message.contains("`result` is not a field of [design.\"V6.2.1\"]."),
            "{message}"
        );
        assert!(message.contains("[checked-by-hand.<key>]"), "{message}");
        // A field that belongs in an array of tables is pointed there.
        let message = said("[design.\"V6.2.1\"]\nanswer = \"yes\"\nverdict = \"false-alarm\"\n");
        assert!(
            message.contains("Did you mean [[finding-review]]?"),
            "{message}"
        );
    }

    #[test]
    fn a_field_before_any_section_says_so_and_where_it_belongs() {
        let message = said("manifest-version = 1\nname = \"club\"\n[app]\n");
        assert!(
            message.contains("`name` is not a field of the top level (before any [section])."),
            "{message}"
        );
        assert!(message.contains("Did you mean [app]"), "{message}");
        assert!(message.contains("`manifest-version`, `app`"), "{message}");
    }

    #[test]
    fn a_value_of_the_wrong_kind_says_which_section_it_is_in() {
        let message = said("[capabilities.ai]\nenabled = \"yes\"\n");
        assert!(message.contains("(in [capabilities.ai])"), "{message}");
        assert!(message.contains("line 2"), "{message}");
    }
}
