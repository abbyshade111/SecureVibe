//! Why the app is held to its level, in the owner's words (the gap analysis of 7 October 2026,
//! finding 17): each answer that decides it is named, and level 1 says what it rests on.

use std::path::Path;
use sv_manifest::Manifest;

fn manifest(audience: &str, data: &str) -> Manifest {
    let text =
        format!("manifest-version = 1\n[app]\nname = \"t\"\naudience = \"{audience}\"\n{data}");
    Manifest::parse(&text, Path::new("stackvet.toml")).expect("the manifest parses")
}

#[test]
fn each_answer_that_decides_the_level_is_named() {
    for (audience, data, level, said) in [
        (
            "just-me",
            "[data]\ncategories = []\n",
            1,
            "stackvet.toml says only you use it, and that the app holds nothing sensitive about people",
        ),
        (
            "my-team",
            "[data]\ncategories = [\"contact\"]\n",
            1,
            "only your own team uses it, and that the app holds nothing sensitive",
        ),
        (
            "customers",
            "[data]\ncategories = []\n",
            2,
            "stackvet.toml says customers use it",
        ),
        (
            "public",
            "[data]\ncategories = []\n",
            2,
            "anyone on the internet can use it",
        ),
        (
            "just-me",
            "",
            2,
            "it does not say what information the app holds about people",
        ),
        (
            "just-me",
            "[data]\ncategories = [\"health\"]\n",
            2,
            "it lists health information among what the app holds",
        ),
        (
            "just-me",
            "[data]\ncategories = [\"helth\"]\n",
            2,
            "it lists information under names `sv` does not know",
        ),
        (
            "public",
            "[data]\ncategories = [\"health\"]\n",
            2,
            "stackvet.toml says anyone on the internet can use it, and it lists health information",
        ),
    ] {
        let m = manifest(audience, data);
        assert_eq!(m.target_level(), level, "{audience} {data}");
        let because = m.level_because();
        assert!(because.contains(said), "{audience} {data}: {because}");
    }
}
