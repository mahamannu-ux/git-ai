#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    fn make_executable(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn macos_package_has_receipt_metadata_matching_cargo_version() {
        let temp_dir = tempfile::tempdir().unwrap();
        let binary = temp_dir.path().join("git-ai");
        let output = temp_dir.path().join("git-ai.pkg");
        let mock_bin = temp_dir.path().join("bin");
        let pkgbuild = mock_bin.join("pkgbuild");
        let pkgbuild_args = temp_dir.path().join("pkgbuild-args");

        fs::create_dir(&mock_bin).unwrap();
        fs::write(&binary, "#!/bin/sh\n").unwrap();
        make_executable(&binary);
        fs::write(
            &pkgbuild,
            "#!/bin/sh\n\
             set -eu\n\
             printf '%s\\n' \"$@\" > \"$PKGBUILD_ARGS\"\n\
             for output_path do :; done\n\
             : > \"$output_path\"\n",
        )
        .unwrap();
        make_executable(&pkgbuild);

        let path = format!("{}:{}", mock_bin.display(), std::env::var("PATH").unwrap());
        let status = Command::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packaging/macos/build-pkg.sh"
        ))
        .args([
            "--binary",
            binary.to_str().unwrap(),
            "--arch",
            "arm64",
            "--version",
            env!("CARGO_PKG_VERSION"),
            "--output",
            output.to_str().unwrap(),
        ])
        .env("PATH", path)
        .env("PKGBUILD_ARGS", &pkgbuild_args)
        .status()
        .unwrap();

        assert!(status.success());
        let args: Vec<_> = fs::read_to_string(pkgbuild_args)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert!(
            !args.iter().any(|arg| arg == "--nopayload"),
            "--nopayload packages do not leave an installer receipt"
        );

        let root = args
            .windows(2)
            .find_map(|args| (args[0] == "--root").then_some(Path::new(&args[1])))
            .expect("pkgbuild should receive an empty payload root");
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);

        let version = args
            .windows(2)
            .find_map(|args| (args[0] == "--version").then_some(args[1].as_str()));
        assert_eq!(version, Some(env!("CARGO_PKG_VERSION")));
        assert!(output.is_file());
    }
}
