//! The five files a report is written as: each name, what kind of file it is, and how it is rendered.
//!
//! The one table in this crate that every reader of a report folder's names derives from (BACKLOG,
//! "From the architecture assessment of 8 October 2026", item 5): `write_report` writes these in this
//! order, the seal covers them (`report_seal::SEALED`), and the MCP server offers them as resources.
//! `sv-scan`'s walk leaves a folder out that holds nothing but these names and the marker and lock,
//! and that crate cannot see this one, so the names are its (`sv_scan::ecosystems::REPORT_FILES`)
//! and this table's are held to them by the compiler: the build fails when a name here is not the
//! name there, in the same place. Before 8 October 2026 the five names were written out four times,
//! held together by a test.

/// One file of a report.
pub(crate) struct ReportFile {
    /// Its name in the report folder.
    pub name: &'static str,
    /// What kind of file it is, as the MCP server tells a client.
    pub mime: &'static str,
    /// The report rendered as this file.
    pub render: fn(&sv_report::Report) -> String,
}

/// The five files, in the order they are written and sealed.
pub(crate) const REPORT_FILES: [ReportFile; 5] = [
    ReportFile {
        name: "report.html",
        mime: "text/html",
        render: sv_report::html::page,
    },
    ReportFile {
        name: "compliance.md",
        mime: "text/markdown",
        render: sv_report::markdown::compliance,
    },
    ReportFile {
        name: "security.md",
        mime: "text/markdown",
        render: sv_report::markdown::security,
    },
    ReportFile {
        name: "findings.sarif",
        mime: "application/sarif+json",
        render: sv_report::sarif::render,
    },
    ReportFile {
        name: "report.json",
        mime: "application/json",
        render: sv_report::json::to_string,
    },
];

/// The names alone, in the same order.
pub(crate) const NAMES: [&str; REPORT_FILES.len()] = {
    let mut names = [""; REPORT_FILES.len()];
    let mut i = 0;
    while i < REPORT_FILES.len() {
        names[i] = REPORT_FILES[i].name;
        i += 1;
    }
    names
};

/// The table and `sv-scan`'s list are the same names in the same order, or nothing compiles.
const _: () = {
    let theirs = sv_scan::ecosystems::REPORT_FILES;
    assert!(NAMES.len() == theirs.len());
    let mut i = 0;
    while i < NAMES.len() {
        assert!(
            same(NAMES[i], theirs[i]),
            "a report file's name differs between sv-cli's report_files and sv-scan's REPORT_FILES"
        );
        i += 1;
    }
};

/// `a == b`, in a form the compiler can run while it builds.
const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_file_is_rendered_from_the_report_and_named_for_its_kind() {
        let app =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
        let report = crate::assemble_report(
            &app,
            &crate::ReportOptions::reading_only("a test"),
            &crate::Loaded::load().unwrap(),
        )
        .unwrap();
        for file in &REPORT_FILES {
            let text = (file.render)(&report);
            assert!(!text.is_empty(), "{} renders to nothing", file.name);
            let kind = match file.name.rsplit('.').next().unwrap() {
                "md" => "markdown",
                extension => extension,
            };
            assert!(
                file.mime.contains(kind),
                "{} is offered as {}",
                file.name,
                file.mime
            );
        }
    }
}
