//! A manifest that says "no training" beside code that fine-tunes through a vendor, end to end
//! through the binary: the report says the code contradicts the claim.
//!
//! The scan tests hold each vendor's call as a signature. This holds what the owner sees: before
//! 28 September 2026 the `training` corroborator knew only the frameworks, so an app that
//! fine-tunes with one call to OpenAI and says it trains nothing read as consistent.

use serde_json::Value;
use std::process::Command;

fn training_claim(name: &str, code: &str) -> Value {
    let dir = std::env::temp_dir().join(format!("sv-fine-tune-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Tuner\"\n[stack]\nlanguages = [\"python\"]\n\
         [capabilities.ai]\nenabled = true\ntraining = false\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), code).unwrap();
    let out = dir.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    let claims = report["claims"].as_array().expect("claims").clone();
    claims
        .into_iter()
        .find(|c| c["name"] == "training")
        .unwrap_or_else(|| panic!("no training claim in {}", report["claims"]))
}

#[test]
fn a_fine_tuning_call_contradicts_a_manifest_that_denies_training() {
    let tunes = training_claim(
        "tunes",
        "from openai import OpenAI\nclient = OpenAI()\n\
         job = client.fine_tuning.jobs.create(training_file=file_id, model=\"gpt-4o-mini\")\n",
    );
    assert_eq!(
        tunes["claimed"], false,
        "the setup: the manifest denies training"
    );
    assert_eq!(tunes["found_in_code"], true, "{tunes}");

    // The control: the same client asking a model something is not fine-tuning, and the claim
    // stands uncontradicted.
    let asks = training_claim(
        "asks",
        "from openai import OpenAI\nclient = OpenAI()\n\
         reply = client.chat.completions.create(model=\"gpt-4o-mini\", messages=m)\n",
    );
    assert_eq!(asks["claimed"], false);
    assert_ne!(asks["found_in_code"], true, "{asks}");
}
