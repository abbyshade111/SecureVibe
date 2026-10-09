use super::*;

fn docker(user: Option<&str>) -> Runner {
    Runner::Docker {
        docker: "/usr/local/bin/docker".to_owned(),
        user: user.map(str::to_owned),
    }
}

fn args_of(block: &Value, servers: &str) -> Vec<String> {
    block[servers]["stackvet"]["args"]
        .as_array()
        .expect("args")
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_container_block_names_the_folder_in_all_three_places_and_gives_no_network() {
    let folder = Path::new("/Users/someone/code/my app");
    let block = block(Tool::Claude, &docker(None), folder);
    assert_eq!(
        block["mcpServers"]["stackvet"]["command"],
        "/usr/local/bin/docker"
    );
    let args = args_of(&block, "mcpServers");
    assert_eq!(
        args,
        [
            "run",
            "-i",
            "--rm",
            "--network",
            "none",
            "-v",
            "/Users/someone/code/my app:/Users/someone/code/my app",
            sv_frameworks::names::IMAGE,
            "mcp",
            "--root",
            "/Users/someone/code/my app",
        ]
    );
}

#[test]
fn the_user_goes_before_the_image_so_docker_reads_it_as_its_own() {
    let block = block(
        Tool::Cursor,
        &docker(Some("1000:1000")),
        Path::new("/home/a/app"),
    );
    let args = args_of(&block, "mcpServers");
    let user = args.iter().position(|a| a == "--user").expect("--user");
    let image = args
        .iter()
        .position(|a| a == sv_frameworks::names::IMAGE)
        .expect("image");
    assert_eq!(args[user + 1], "1000:1000");
    assert!(user < image, "{args:?}");
}

#[test]
fn vs_code_has_its_own_shape_and_the_others_share_one() {
    let folder = Path::new("/w/app");
    let vscode = block(Tool::VsCode, &docker(None), folder);
    assert_eq!(vscode["servers"]["stackvet"]["type"], "stdio");
    assert!(vscode.get("mcpServers").is_none());
    for tool in [Tool::Claude, Tool::Cursor] {
        let other = block(tool, &docker(None), folder);
        assert!(other.get("servers").is_none(), "{tool:?}");
        assert_eq!(args_of(&other, "mcpServers"), args_of(&vscode, "servers"));
    }
}

#[test]
fn an_installed_copy_is_started_by_its_own_path_with_only_the_folder() {
    let block = block(
        Tool::Claude,
        &Runner::Installed(PathBuf::from("/opt/homebrew/bin/sv")),
        Path::new("/w/app"),
    );
    assert_eq!(
        block["mcpServers"]["stackvet"]["command"],
        "/opt/homebrew/bin/sv"
    );
    assert_eq!(args_of(&block, "mcpServers"), ["mcp", "--root", "/w/app"]);
}

#[test]
fn each_tool_names_its_own_settings_file() {
    assert_eq!(Tool::Claude.settings_file(), ".mcp.json");
    assert_eq!(Tool::VsCode.settings_file(), ".vscode/mcp.json");
    assert_eq!(Tool::Cursor.settings_file(), ".cursor/mcp.json");
    for name in ["claude", "vscode", "cursor"] {
        assert!(Tool::NAMES.contains(name), "{name}");
        assert!(Tool::named(name).is_some(), "{name}");
    }
    assert_eq!(Tool::named("Claude"), None);
    assert_eq!(Tool::named("copilot"), None);
}

#[test]
fn a_user_is_two_numbers() {
    assert!(check_user("1000:1000").is_ok());
    assert!(check_user("501:20").is_ok());
    for wrong in [
        "1000",
        "a:b",
        ":1000",
        "1000:",
        "1000:1000:1",
        "$(id -u):$(id -g)",
    ] {
        assert!(check_user(wrong).is_err(), "{wrong}");
    }
}

#[test]
fn docker_named_without_its_full_path_is_refused_before_anything_is_printed() {
    let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let err = command(&words(&["claude", "--docker", "docker"])).unwrap_err();
    assert!(err.to_string().contains("full path"), "{err}");
    assert!(command(&words(&["claude", "--docker", "/usr/bin/docker"])).is_ok());
}
