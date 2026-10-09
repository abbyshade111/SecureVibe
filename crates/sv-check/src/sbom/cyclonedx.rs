//! The bill of materials written as CycloneDX. Moved out of `sbom.rs` unchanged on 9 October 2026
//! (architecture assessment, item 11).

use super::*;

#[derive(Serialize)]
pub(super) struct CycloneComponent {
    #[serde(rename = "type")]
    pub(super) kind: &'static str,
    #[serde(rename = "bom-ref")]
    pub(super) bom_ref: String,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) purl: String,
    pub(super) properties: Vec<Property>,
}

#[derive(Serialize)]
pub(super) struct Property {
    pub(super) name: String,
    pub(super) value: String,
}

#[derive(Serialize)]
pub(super) struct Metadata {
    pub(super) tools: Vec<Tool>,
    pub(super) properties: Vec<Property>,
}

#[derive(Serialize)]
pub(super) struct Tool {
    pub(super) vendor: &'static str,
    pub(super) name: &'static str,
}

#[derive(Serialize)]
pub struct CycloneDx {
    #[serde(rename = "bomFormat")]
    pub(super) bom_format: &'static str,
    #[serde(rename = "specVersion")]
    pub(super) spec_version: &'static str,
    pub(super) version: u32,
    pub(super) metadata: Metadata,
    pub(super) components: Vec<CycloneComponent>,
}

/// Renders the bill of materials as CycloneDX 1.5 JSON.
///
/// The completeness caveats go in `metadata.properties` rather than only in the terminal, because the
/// document is the thing that gets sent to somebody else, and a caveat that stays behind is not a caveat.
pub fn to_cyclonedx(sbom: &Sbom) -> CycloneDx {
    let mut properties = vec![Property {
        name: "securevibe:complete".into(),
        value: sbom.is_complete().to_string(),
    }];
    if sbom.declared_count() > 0 {
        properties.push(Property {
            name: "securevibe:declared-versions".into(),
            value: format!(
                "{} component(s) carry the version that was asked for, not the version installed",
                sbom.declared_count()
            ),
        });
    }
    for (eco, why) in &sbom.unread {
        properties.push(Property {
            name: format!("securevibe:unread:{eco}"),
            value: why.clone(),
        });
    }
    for passed in &sbom.passed_over {
        properties.push(Property {
            name: format!("securevibe:lockfile-passed-over:{}", passed.project),
            value: passed.explain(),
        });
    }
    for disagreement in &sbom.disagreements {
        if disagreement.differs() {
            properties.push(Property {
                name: format!("securevibe:manifest-disagrees:{}", disagreement.project),
                value: disagreement.explain(),
            });
        }
        if disagreement.comparison.not_all_compared() {
            properties.push(Property {
                name: format!("securevibe:manifest-not-compared:{}", disagreement.project),
                value: disagreement.explain_not_compared(),
            });
        }
    }

    CycloneDx {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        version: 1,
        metadata: Metadata {
            tools: vec![Tool {
                vendor: "StackVet",
                name: "sv",
            }],
            properties,
        },
        components: sbom
            .components
            .iter()
            .map(|c| CycloneComponent {
                kind: "library",
                bom_ref: c.purl(),
                name: c.name.clone(),
                version: c.version.clone(),
                purl: c.purl(),
                properties: vec![Property {
                    name: "securevibe:version-source".into(),
                    value: match c.source {
                        VersionSource::Locked => "locked: this is what is installed".into(),
                        VersionSource::Declared => {
                            "declared: this is what was asked for, and may be a range".to_string()
                        }
                    },
                }],
            })
            .collect(),
    }
}

/// A finding when the bill of materials cannot be trusted as a complete list.
/// The requirement a complete bill of materials is evidence about: an inventory catalog of every
/// third-party library in use. Named once so the check and `sv coverage` cannot disagree.
pub const INVENTORY_REQUIREMENT: &str = "V15.1.2";

/// What the bill of materials may claim to be, when it is complete enough to claim anything.
///
/// The mirror of `incompleteness_finding`: exactly one of the two speaks, and which one is decided
/// by `is_complete`, so a document cannot be reported as both incomplete and a good inventory. An
/// empty list is not a complete inventory either — an app with no dependencies `sv` could find is
/// far more often an app whose manifests were not read than an app with no dependencies.
/// "1 package", "2 packages".
pub(crate) fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}
