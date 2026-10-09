//! A build step that downloads packages is said before any run (the gap analysis of 7 October
//! 2026, finding 9).

use super::*;

fn build_said(build: &str) -> Option<String> {
    let text = format!(
        "manifest-version = 1\n[app]\nname = \"t\"\n[stack.run]\nimage = \"python:3.12-slim\"\n\
         build = {build:?}\nstart = \"python app.py\"\nhealth = \"/\"\n"
    );
    let manifest = Manifest::parse(&text, Path::new("stackvet.toml")).expect("the manifest parses");
    // The build line has to reach the manifest, or every "nothing said" below passes for nothing.
    assert_eq!(manifest.stack.run.build.as_deref(), Some(build));
    let item = build_installs(&manifest)?;
    assert_eq!(item.topic, "build-install");
    assert_eq!(item.answer, Answer::Look);
    Some(item.text(&Fence::none()))
}

#[test]
fn each_installer_is_named() {
    for (build, named) in [
        ("pip install -r requirements.txt", "pip install"),
        ("pip3 install flask", "pip3 install"),
        (
            "python -m pip install -r requirements.txt",
            "python -m pip install",
        ),
        ("cd api && pip install -r requirements.txt", "pip install"),
        ("PIP_NO_CACHE_DIR=1 pip install .", "pip install"),
        ("uv pip install -r requirements.txt", "uv pip install"),
        ("uv sync", "uv sync"),
        ("poetry install", "poetry install"),
        ("npm ci", "npm ci"),
        ("npm install && npm run build", "npm install"),
        ("npm run build;npm i", "npm i"),
        ("yarn", "yarn install"),
        ("yarn --frozen-lockfile", "yarn install"),
        ("pnpm install", "pnpm install"),
        ("/usr/local/bin/pip install flask", "pip install"),
        ("bundle install", "bundle install"),
        ("sh -c \"pip install -r requirements.txt\"", "pip install"),
        ("bash -c 'cd web && npm ci'", "npm ci"),
    ] {
        let words = build_said(build).unwrap_or_else(|| panic!("`{build}` was not said"));
        assert!(
            words.contains(&format!("runs `{named}`")),
            "`{build}` should name `{named}`: {words}"
        );
        assert!(
            words.contains("`install = true`") && words.contains("`image`"),
            "the two ways that work are named: {words}"
        );
    }
}

#[test]
fn a_build_that_downloads_nothing_is_not_said() {
    // The control: without it, saying something for every build step would pass the test above.
    for build in [
        "npm run build",
        "python manage.py collectstatic --noinput",
        "go build -o app .",
        "echo \"no packages to install\"",
        "yarn build",
        "pip --version",
    ] {
        assert_eq!(build_said(build), None, "`{build}` downloads nothing");
    }
}

#[test]
fn the_preflight_of_an_app_folder_says_it() {
    // Through `of`, as `sv preflight` reads an app, so the item cannot be built and never shown.
    let dir =
        std::env::temp_dir().join(format!("sv-preflight-build-install-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = |build: &str| {
        format!(
            "manifest-version = 1\n[app]\nname = \"t\"\n[stack.run]\nimage = \"python:3.12-slim\"\n\
             build = \"{build}\"\nstart = \"python app.py\"\nhealth = \"/\"\n"
        )
    };
    std::fs::write(dir.join("app.py"), "print(1)\n").unwrap();
    std::fs::write(dir.join("stackvet.toml"), manifest("pip install flask")).unwrap();
    let (items, _, _) = of(&dir).expect("the preflight runs");
    let said = items.iter().filter(|i| i.topic == "build-install").count();
    std::fs::write(dir.join("stackvet.toml"), manifest("python make.py")).unwrap();
    let (control, _, _) = of(&dir).expect("the preflight runs");
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        said, 1,
        "the preflight said nothing of `pip install` in the build step"
    );
    assert!(
        control.iter().all(|i| i.topic != "build-install"),
        "a build step that downloads nothing was said"
    );
}
