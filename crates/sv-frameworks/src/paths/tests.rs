use super::*;

#[test]
fn a_drive_path_loses_the_prefix() {
    assert_eq!(
        short_form(r"\\?\C:\Users\me\app").as_deref(),
        Some(r"C:\Users\me\app")
    );
    assert_eq!(short_form(r"\\?\D:\").as_deref(), Some(r"D:\"));
}

#[test]
fn a_network_share_becomes_its_usual_form() {
    assert_eq!(
        short_form(r"\\?\UNC\server\share\app").as_deref(),
        Some(r"\\server\share\app")
    );
}

#[test]
fn a_path_the_short_form_would_name_differently_keeps_the_prefix() {
    let long_name = format!(r"\\?\C:\{}", "a".repeat(300));
    for kept in [
        long_name.as_str(),
        r"\\?\C:\app\name.",
        r"\\?\C:\app\name ",
        r"\\?\C:\app\CON",
        r"\\?\C:\app\nul.txt",
        r"\\?\C:\app\com1",
        r"\\?\C:\app\Lpt9.log",
        r"\\?\C:\app/also",
        r"\\?\Volume{0b1f}\app",
        r"\\?\GLOBALROOT\Device\X",
    ] {
        assert_eq!(short_form(kept), None, "{kept}");
    }
}

#[test]
fn names_that_only_look_like_devices_are_files() {
    for file in [
        r"\\?\C:\app\console",
        r"\\?\C:\app\com10",
        r"\\?\C:\app\com0",
        r"\\?\C:\app\nullable.txt",
        r"\\?\C:\app\.env",
    ] {
        assert!(short_form(file).is_some(), "{file}");
    }
}

#[test]
fn a_path_without_the_prefix_is_not_changed() {
    for plain in ["/home/me/app", r"C:\Users\me\app", r"\\server\share", ""] {
        assert_eq!(short_form(plain), None, "{plain}");
    }
}

#[test]
fn the_real_place_is_the_standard_librarys_without_the_prefix() {
    let dir = std::env::temp_dir().join(format!("sv-paths-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    let real = canonical(dir.join("a/..")).unwrap();
    let standard = std::fs::canonicalize(&dir).unwrap();
    assert!(
        !real.display().to_string().starts_with(r"\\?\"),
        "{}",
        real.display()
    );
    if cfg!(windows) {
        assert_eq!(
            Some(real.display().to_string()),
            short_form(&standard.display().to_string())
        );
    } else {
        assert_eq!(real, standard);
    }
    assert_eq!(dir.join("a/..").as_path().canonical().unwrap(), real);
    assert!(canonical(dir.join("not here")).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn what_a_person_or_docker_reads_never_starts_with_the_prefix() {
    // The places a Windows run hands to Docker and writes in a report: a home folder, a name with
    // spaces, letters beyond English, and a folder of the CI runner's.
    for long in [
        r"\\?\C:\Users\runneradmin\AppData\Local\Temp\sv-history-4580\apps\tested-notes",
        r"\\?\D:\a\StackVet\StackVet\crates\sv-run\tests\fixtures\install-app",
        r"\\?\c:\My Apps\notes app",
        r"\\?\E:\Usuários\josé\aplicação",
    ] {
        let short = short_form(long).unwrap_or_else(|| panic!("{long} kept its prefix"));
        assert!(!short.starts_with(r"\\?\"), "{short}");
        assert_eq!(
            format!(r"\\?\{short}"),
            long,
            "the same place, without the prefix"
        );
    }
}
