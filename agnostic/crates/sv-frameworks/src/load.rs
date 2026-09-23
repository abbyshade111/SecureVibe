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
    match requirement_id.rfind('.') {
        Some(i) => &requirement_id[..i],
        None => requirement_id,
    }
}

/// The chapter id of a requirement or section id ("V6.2.1" → "V6", "AC.4.1" → "AC.4").
pub fn chapter_id_of(id: &str) -> &str {
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
    }
}
