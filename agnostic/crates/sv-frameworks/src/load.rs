//! Loads the OWASP data files. These are the same files v1 reads, from the same `data/frameworks`
//! folder: one source of truth for ASVS across both products, so a correction fixes both.
//!
//! ASVS and AISVS share a shape (chapters → sections → requirements). Appendix C is families →
//! requirements, with no section level; its ids carry two segments of family ("AC.4.1" → "AC.4"),
//! which is why `chapter_id_of` special-cases them.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Requirement {
    pub id: String,
    pub description: String,
    pub level: u8,
}

#[derive(Debug, Deserialize)]
pub struct Section {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Chapter {
    pub id: String,
    pub name: String,
    /// ASVS and AISVS nest a section level; Appendix C families do not.
    #[serde(default)]
    pub sections: Vec<Section>,
    /// Appendix C families hold requirements directly.
    #[serde(default)]
    pub requirements: Vec<Requirement>,
}

/// Namespace for the Secure by Design checklist's control ids. See `load_checklist`.
pub const SBD_PREFIX: &str = "SBD-";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChecklistFile {
    checklist_domains: Vec<ChecklistDomain>,
}

#[derive(Debug, Deserialize)]
struct ChecklistDomain {
    id: String,
    name: String,
    controls: Vec<ChecklistControl>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChecklistControl {
    id: String,
    statement: String,
    #[serde(default)]
    critical: bool,
    #[serde(default)]
    severity_if_no: String,
}

/// The checklist has no levels, so one is derived from how much its absence costs.
///
/// This is SecureVibe's mapping and not OWASP's, which is why it is one function with a name rather
/// than three comparisons spread around.
fn level_of(control: &ChecklistControl) -> u8 {
    if control.critical || control.severity_if_no == "high" {
        1
    } else if control.severity_if_no == "medium" {
        2
    } else {
        3
    }
}

#[derive(Debug, Deserialize)]
pub struct FrameworkFile {
    #[serde(default)]
    pub standard: String,
    #[serde(default)]
    pub version: String,
    /// ASVS and AISVS call the top level `chapters`; Appendix C calls it `families`.
    #[serde(default, alias = "families")]
    pub chapters: Vec<Chapter>,
}

/// One requirement with the context needed to reason about it, flattened out of the nesting.
#[derive(Debug, Clone)]
pub struct RequirementInfo {
    pub id: String,
    pub description: String,
    pub level: u8,
    pub chapter_id: String,
    pub chapter_name: String,
    /// Absent for Appendix C, which has no section level.
    pub section_id: Option<String>,
    /// Where the level came from, when it is not the framework's own: the Secure by Design checklist
    /// has no levels, so each of its controls says how it got one. `None` for ASVS and AISVS.
    pub level_basis: Option<String>,
    /// Requirements in another framework that ask the same thing, from the crosswalk. Evidence about
    /// one of these is shown beside this requirement as supporting, never as checking it.
    pub counterparts: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Frameworks {
    /// Every requirement from every loaded file, keyed by id.
    pub requirements: BTreeMap<String, RequirementInfo>,
}

impl Frameworks {
    /// Loads ASVS, AISVS and Appendix C from a `data/frameworks` directory.
    pub fn load(frameworks_dir: &Path) -> Result<Self> {
        let mut out = Self::default();
        for file in [
            "asvs-5.0.0.json",
            "aisvs-1.0.json",
            "aisvs-1.0-appendix-c.json",
        ] {
            out.load_file(&frameworks_dir.join(file))?;
        }
        out.load_checklist(&frameworks_dir.join("sbd-checklist-0.5.0.json"))?;
        Ok(out)
    }

    fn load_file(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading framework file {}", path.display()))?;
        let parsed: FrameworkFile = serde_json::from_str(&text)
            .with_context(|| format!("parsing framework file {}", path.display()))?;
        for chapter in &parsed.chapters {
            for req in &chapter.requirements {
                self.insert(req, chapter, None);
            }
            for section in &chapter.sections {
                for req in &section.requirements {
                    self.insert(req, chapter, Some(&section.id));
                }
            }
        }
        Ok(())
    }

    /// The Secure by Design checklist, which is a third schema and not a set of requirements.
    ///
    /// `sv --help` and the README claimed this was checked for as long as it was not loaded at all,
    /// which is the plainest kind of untruth this tool can tell. Two things had to be decided before
    /// it could be loaded, and both are choices rather than readings:
    ///
    /// **Ids are prefixed `SBD-`.** The checklist names its own controls `AC-01` … `AC-07`, and
    /// AISVS Appendix C already owns `AC.1.1` … `AC.13.4`. Those are different strings and would not
    /// collide in the map, but they collide in a reader's head — and this codebase has already
    /// shipped five checkers citing `AC-05` for a family written `AC.5`. A citation that resolves to
    /// the wrong framework is worse than one that resolves to nothing, because nothing looks wrong.
    /// So the checklist's ids are namespaced here and the prefix is printed everywhere they appear.
    ///
    /// **Levels are derived, because the checklist has none.** It has `critical` and `severityIfNo`
    /// instead. A control that is critical, or whose absence is high severity, is level 1; medium is
    /// level 2; low is level 3. That mapping is this tool's, not OWASP's, and is stated wherever the
    /// level is shown.
    fn load_checklist(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading checklist file {}", path.display()))?;
        let parsed: ChecklistFile = serde_json::from_str(&text)
            .with_context(|| format!("parsing checklist file {}", path.display()))?;
        for domain in &parsed.checklist_domains {
            let chapter = Chapter {
                id: format!("{SBD_PREFIX}{}", domain.id),
                name: domain.name.clone(),
                sections: Vec::new(),
                requirements: Vec::new(),
            };
            for control in &domain.controls {
                let requirement = Requirement {
                    id: format!("{SBD_PREFIX}{}", control.id),
                    description: control.statement.clone(),
                    level: level_of(control),
                };
                self.insert(&requirement, &chapter, None);
                if let Some(info) = self.requirements.get_mut(&requirement.id) {
                    info.level_basis = Some(format!(
                        "level {}, set by sv from the checklist's severity; the checklist has no levels",
                        requirement.level
                    ));
                }
            }
        }
        Ok(())
    }

    /// Grounds the checklist's levels in ASVS through the crosswalk in `path`.
    ///
    /// A control's level becomes the lower of the one derived from its severity and the lowest level
    /// among the ASVS requirements that ask the same thing. Lower only: the crosswalk can bring a
    /// control into an app's scope sooner and can never take one out. A control nothing in ASVS
    /// matches is level 1 — shown at every target — because excluding it would rest on `sv`'s own
    /// derived level and nothing else. Every control has to be listed, and every id cited has to
    /// exist; either failing is a load error rather than a control quietly keeping its old level.
    pub fn apply_crosswalk(&mut self, path: &Path) -> Result<()> {
        #[derive(Deserialize)]
        struct Crosswalk {
            /// Control → ASVS requirement → the few words naming what the two ask in common.
            controls: BTreeMap<String, BTreeMap<String, String>>,
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading crosswalk {}", path.display()))?;
        let crosswalk: Crosswalk = serde_json::from_str(&text)
            .with_context(|| format!("parsing crosswalk {}", path.display()))?;

        let controls: Vec<String> = self
            .requirements
            .keys()
            .filter(|id| id.starts_with(SBD_PREFIX))
            .cloned()
            .collect();
        for id in &controls {
            anyhow::ensure!(
                crosswalk.controls.contains_key(id),
                "the crosswalk does not list {id}; every control has to be listed, with an empty list \
                 when nothing in ASVS asks the same thing"
            );
        }
        for (id, counterparts) in &crosswalk.controls {
            anyhow::ensure!(
                self.requirements.contains_key(id),
                "the crosswalk lists {id}, which is not a loaded control"
            );
            let mut lowest: Option<(u8, &str)> = None;
            for asvs in counterparts.keys() {
                let level = self
                    .requirements
                    .get(asvs)
                    .with_context(|| {
                        format!("the crosswalk cites {asvs} for {id}, which does not exist")
                    })?
                    .level;
                if lowest.is_none_or(|(l, _)| level < l) {
                    lowest = Some((level, asvs));
                }
            }
            let info = self.requirements.get_mut(id).expect("checked above");
            let derived = info.level;
            info.counterparts = counterparts.keys().cloned().collect();
            let (level, basis) = match lowest {
                None => (
                    1,
                    "shown at every level: nothing in ASVS asks the same thing, and the checklist has \
                     no levels"
                        .to_owned(),
                ),
                Some((asvs_level, asvs)) if asvs_level <= derived => {
                    (asvs_level, format!("level {asvs_level}, as {asvs}"))
                }
                Some((asvs_level, asvs)) => (
                    derived,
                    format!(
                        "level {derived}, from the checklist's severity; its ASVS counterpart {asvs} \
                         is level {asvs_level}"
                    ),
                ),
            };
            info.level = level;
            info.level_basis = Some(basis);
        }
        Ok(())
    }

    fn insert(&mut self, req: &Requirement, chapter: &Chapter, section_id: Option<&str>) {
        self.requirements.insert(
            req.id.clone(),
            RequirementInfo {
                id: req.id.clone(),
                description: req.description.clone(),
                level: req.level,
                chapter_id: chapter.id.clone(),
                chapter_name: chapter.name.clone(),
                section_id: section_id.map(str::to_owned),
                level_basis: None,
                counterparts: Vec::new(),
            },
        );
    }

    pub fn get(&self, id: &str) -> Option<&RequirementInfo> {
        self.requirements.get(id)
    }

    pub fn len(&self) -> usize {
        self.requirements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }
}

/// The section id of a requirement id ("V6.2.1" → "V6.2").
pub fn section_id_of(requirement_id: &str) -> &str {
    // The checklist has no section level, so a control's section is its family. Without this the
    // whole id comes back and a rule scoped to a family would never match one.
    if requirement_id.starts_with(SBD_PREFIX) {
        return chapter_id_of(requirement_id);
    }
    match requirement_id.rfind('.') {
        Some(i) => &requirement_id[..i],
        None => requirement_id,
    }
}

/// The chapter id of a requirement or section id ("V6.2.1" → "V6", "AC.4.1" → "AC.4").
pub fn chapter_id_of(id: &str) -> &str {
    // "SBD-AC-01" -> "SBD-AC": the family, so one rule can scope every access-control control.
    if let Some(after_prefix) = id.strip_prefix(SBD_PREFIX) {
        let end = after_prefix
            .find('-')
            .map_or(id.len(), |i| SBD_PREFIX.len() + i);
        return &id[..end];
    }
    if let Some(rest) = id.strip_prefix("AC.") {
        // Appendix C ids carry two segments of family, so keep "AC." plus the next one.
        let end = rest.find('.').map_or(id.len(), |i| "AC.".len() + i);
        return &id[..end];
    }
    match id.find('.') {
        Some(i) => &id[..i],
        None => id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_section_and_chapter_ids() {
        assert_eq!(section_id_of("V6.2.1"), "V6.2");
        assert_eq!(chapter_id_of("V6.2.1"), "V6");
        assert_eq!(chapter_id_of("V6.2"), "V6");
        assert_eq!(chapter_id_of("AC.4.1"), "AC.4");
        assert_eq!(chapter_id_of("AC.4"), "AC.4");
        assert_eq!(chapter_id_of("C9.2.1"), "C9");
        // The checklist. "SBD-AC-01" must not be read as Appendix C's "AC." family, and its
        // section has to be its family or no family-scoped rule would ever match.
        assert_eq!(chapter_id_of("SBD-AC-01"), "SBD-AC");
        assert_eq!(chapter_id_of("SBD-MT-07"), "SBD-MT");
        assert_eq!(section_id_of("SBD-AC-01"), "SBD-AC");
    }

    #[test]
    fn the_checklist_level_is_derived_from_what_its_absence_costs() {
        let critical = ChecklistControl {
            id: "AS-01".into(),
            statement: String::new(),
            critical: true,
            severity_if_no: "high".into(),
        };
        assert_eq!(level_of(&critical), 1);
        let high_but_not_critical = ChecklistControl {
            severity_if_no: "high".into(),
            critical: false,
            ..ChecklistControl {
                id: "AC-03".into(),
                statement: String::new(),
                critical: false,
                severity_if_no: "high".into(),
            }
        };
        assert_eq!(level_of(&high_but_not_critical), 1, "high alone is enough");
        let medium = ChecklistControl {
            id: "DM-01".into(),
            statement: String::new(),
            critical: false,
            severity_if_no: "medium".into(),
        };
        assert_eq!(level_of(&medium), 2);
        let low = ChecklistControl {
            id: "AS-02".into(),
            statement: String::new(),
            critical: false,
            severity_if_no: "low".into(),
        };
        assert_eq!(level_of(&low), 3);
    }
}
