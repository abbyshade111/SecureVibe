//! A workflow that hands every secret to a job, end to end: a real `sv report` on a small app with
//! one, and V13.3.2 needing attention in the report it writes. Without the workflow, V13.3.2 is not
//! credited, since finding none says nothing about who else can read the secrets.

use std::process::Command;

fn report_for(name: &str, workflow: Option<&str>) -> serde_json::Value {
    let app =
        std::env::temp_dir().join(format!("sv-workflow-secrets-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&app).ok();
    std::fs::create_dir_all(app.join(".github/workflows")).unwrap();
    std::fs::write(app.join("app.py"), "def hello():\n    return 'hello'\n").unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Secrets\"\naudience = \"customers\"\n\
         deployment = \"internet\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();
    if let Some(workflow) = workflow {
        std::fs::write(app.join(".github/workflows/release.yml"), workflow).unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .output()
        .expect("sv runs");
    assert!(
        out.status.code().is_some_and(|c| c == 0 || c == 2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = serde_json::from_str(
        &std::fs::read_to_string(
            app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)
                .join("report.json"),
        )
        .unwrap(),
    )
    .unwrap();
    std::fs::remove_dir_all(&app).ok();
    json
}

fn requirement<'a>(report: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    report["requirements"]
        .as_array()
        .and_then(|all| all.iter().find(|r| r["id"] == id))
        .unwrap_or_else(|| panic!("{id} is not in the report"))
}

#[test]
fn a_workflow_passing_every_secret_on_leaves_v13_3_2_needing_attention() {
    let inherits = report_for(
        "inherit",
        Some(
            "on: push\npermissions:\n  contents: read\njobs:\n  release:\n    \
             uses: ./.github/workflows/publish.yml\n    secrets: inherit\n",
        ),
    );
    let v13_3_2 = requirement(&inherits, "V13.3.2");
    assert_eq!(v13_3_2["status"], "needs-attention", "{v13_3_2}");
    assert!(
        v13_3_2
            .to_string()
            .contains("config.workflow-hands-out-all-secrets"),
        "{v13_3_2}"
    );

    let none = report_for("none", None);
    let v13_3_2 = requirement(&none, "V13.3.2");
    assert_ne!(v13_3_2["status"], "checked", "{v13_3_2}");
    assert_ne!(v13_3_2["status"], "needs-attention", "{v13_3_2}");
}
