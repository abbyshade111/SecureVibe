//! ADR-054: a template that holds code is named in what `sv` says, and so are `.sql` files, which no
//! rule reads and which hold nothing back.

use std::process::Command;

fn app(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-templates-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("views")).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    std::fs::write(dir.join("views/index.erb"), "<p><%= name %></p>\n").unwrap();
    std::fs::write(dir.join("schema.sql"), "create table notes (id int);\n").unwrap();
    dir
}

#[test]
fn the_terminal_names_the_template_and_the_sql() {
    let dir = app("check");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("check")
        .arg(&dir)
        .output()
        .expect("sv runs");
    std::fs::remove_dir_all(&dir).ok();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nothing here reads erb"), "{stdout}");
    assert!(
        stdout.contains(
            "Templates with code in them, which `sv` does not read yet: `views/index.erb`."
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("Not read by the rules that read code: `schema.sql` (1 SQL file)."),
        "{stdout}"
    );
}

#[test]
fn the_report_names_them_as_gaps() {
    let dir = app("report");
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tested-notes/stackvet.toml");
    std::fs::copy(manifest, dir.join("stackvet.toml")).unwrap();
    let out_dir = dir.join("report");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap_or_default();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !compliance.is_empty(),
        "the report was not written: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        compliance.contains("the templates are `views/index.erb`"),
        "{compliance}"
    );
    assert!(
        compliance.contains("the SQL in `schema.sql`"),
        "{compliance}"
    );
}
