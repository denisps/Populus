use super::{
    CoverageCounts, RUST_COMPONENTS, TOOLS, component_setup_command,
    duplicate_version_count_from_tree, format_coverage_percent, missing_components, missing_tools,
    package_label, parse_lcov_coverage, setup_command, tool_version_matches, validate_tools,
};
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn package_labels_ignore_version_and_source() {
    assert_eq!(
        package_label("populus-types v0.1.0 (/workspace/crates/populus-types)"),
        Some("populus-types")
    );
}

#[test]
fn pinned_tool_versions_must_match_exactly() {
    assert!(tool_version_matches("cargo-nextest 0.9.148", "0.9.148"));
    assert!(tool_version_matches("0.9.2", "0.9.2"));
    assert!(!tool_version_matches("cargo-nextest 0.9.149", "0.9.148"));
    assert!(!tool_version_matches("cargo-nextest 0.9.148", "0.9.14"));
    assert!(!tool_version_matches(
        "cargo-nextest unavailable",
        "0.9.148"
    ));
}

#[test]
fn setup_installs_all_pinned_tools_in_one_unoptimized_command() -> Result<(), String> {
    let command =
        setup_command(Path::new("/workspace"), &TOOLS).ok_or("tools need installation")?;
    assert_eq!(command.get_program(), "cargo");
    let arguments: Vec<_> = command.get_args().collect();
    assert_eq!(
        &arguments[..5],
        ["install", "--locked", "--profile", "dev", "--target-dir"]
    );
    assert_eq!(
        arguments[5],
        Path::new("/workspace")
            .join(".cache/populus-tools")
            .as_os_str()
    );
    assert_eq!(
        &arguments[6..],
        [
            "cargo-nextest@0.9.148",
            "cargo-llvm-cov@0.9.1",
            "cargo-machete@0.9.2",
            "cargo-deny@0.20.2",
        ]
    );
    let environment: BTreeMap<_, _> = command.get_envs().collect();
    assert_eq!(
        environment[std::ffi::OsStr::new("CARGO_PROFILE_DEV_DEBUG")],
        Some(std::ffi::OsStr::new("0"))
    );
    assert_eq!(
        environment[std::ffi::OsStr::new("CARGO_PROFILE_DEV_INCREMENTAL")],
        Some(std::ffi::OsStr::new("false"))
    );
    assert_eq!(environment[std::ffi::OsStr::new("CARGO_PKG_NAME")], None);
    assert_eq!(command.get_current_dir(), Some(Path::new("/workspace")));
    Ok(())
}

#[test]
fn setup_only_installs_missing_or_incorrect_cargo_tools() -> Result<(), String> {
    let missing = missing_tools(&TOOLS, |tool, version| {
        let installed = match tool {
            "nextest" => "cargo-nextest 0.9.148",
            "llvm-cov" => "cargo-llvm-cov 0.9.0",
            "deny" => "cargo-deny 0.20.2",
            _ => "",
        };
        tool_version_matches(installed, version)
    });
    assert_eq!(missing, [("llvm-cov", "0.9.1"), ("machete", "0.9.2")]);
    let command = setup_command(Path::new("/workspace"), &missing).ok_or("missing tools")?;
    assert_eq!(
        command.get_args().skip(6).collect::<Vec<_>>(),
        ["cargo-llvm-cov@0.9.1", "cargo-machete@0.9.2"]
    );
    let ready = missing_tools(&TOOLS, |_, _| true);
    assert_eq!(ready, Vec::<(&str, &str)>::new());
    assert!(setup_command(Path::new("/workspace"), &ready).is_none());
    Ok(())
}

#[test]
fn setup_checks_toolchain_components_and_installs_only_missing_ones() -> Result<(), String> {
    let installed =
        "cargo-aarch64-apple-darwin\nclippy-aarch64-apple-darwin\nrustfmt-aarch64-apple-darwin\n";
    let host = "x86_64-unknown-linux-gnu";
    let missing = missing_components(installed, &RUST_COMPONENTS, host);
    assert_eq!(missing, ["llvm-tools-preview"]);
    let command =
        component_setup_command(Path::new("/workspace"), &missing).ok_or("missing component")?;
    assert_eq!(command.get_program(), "rustup");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        ["component", "add", "llvm-tools-preview"]
    );
    assert_eq!(command.get_current_dir(), Some(Path::new("/workspace")));

    let all_installed = format!("{installed}llvm-tools-{host}\n");
    let ready = missing_components(&all_installed, &RUST_COMPONENTS, host);
    assert_eq!(ready, Vec::<&str>::new());
    assert!(component_setup_command(Path::new("/workspace"), &ready).is_none());
    assert_eq!(
        missing_components("", &RUST_COMPONENTS, host),
        RUST_COMPONENTS
    );
    assert_eq!(
        missing_components(
            "rustfmtish\nclippyish\nllvm-toolset\n",
            &RUST_COMPONENTS,
            host
        ),
        RUST_COMPONENTS
    );
    assert_eq!(
        missing_components(
            "rustfmt-x86_64-unknown-linux-gnu\nclippy-x86_64-unknown-linux-gnu\nllvm-tools-x86_64-unknown-linux-gnu\n",
            &RUST_COMPONENTS,
            host
        ),
        Vec::<&str>::new()
    );
    assert_eq!(
        missing_components(
            "rustfmt-x86_64-unknown-linux-gnu\nclippy-x86_64-unknown-linux-gnu\nllvm-tools-aarch64-apple-darwin\n",
            &RUST_COMPONENTS,
            host
        ),
        ["llvm-tools-preview"]
    );
    Ok(())
}

#[test]
fn setup_components_match_repository_toolchain_requirements() -> Result<(), String> {
    let toolchain = include_str!("../../rust-toolchain.toml");
    let components = toolchain
        .lines()
        .find_map(|line| line.strip_prefix("components = "))
        .ok_or("repository toolchain components")?;
    let expected: Vec<_> = components
        .trim_matches(['[', ']'])
        .split(',')
        .map(|component| component.trim().trim_matches('"'))
        .collect();
    assert_eq!(RUST_COMPONENTS.as_slice(), expected);
    Ok(())
}

#[test]
fn tool_preflight_reports_all_unavailable_versions_with_setup_instruction() {
    let mut checked = Vec::new();
    let result = validate_tools(&TOOLS, |tool, version| {
        checked.push(tool);
        tool_version_matches("cargo-nextest 0.9.148", version)
    });
    assert_eq!(checked, ["nextest", "llvm-cov", "machete", "deny"]);
    assert_eq!(result, Err(
        "Missing or incorrect development tools: cargo-llvm-cov@0.9.1, cargo-machete@0.9.2, cargo-deny@0.20.2. Install all required tools with `cargo xtask setup`.".to_owned()
    ));
    assert_eq!(validate_tools(&TOOLS, |_, _| true), Ok(()));
}

#[test]
fn duplicate_versions_count_only_additional_versions() {
    let tree = "serde v1.0.0\nserde v2.0.0\nother v1.0.0\nother v1.0.0\n";

    assert_eq!(duplicate_version_count_from_tree(tree), 1);
}

#[test]
fn coverage_summary_groups_lcov_records_by_workspace_package() {
    let report = concat!(
        "SF:/workspace/crates/populus-cluster/src/lib.rs\n",
        "FNF:10\nFNH:9\nLF:100\nLH:98\nend_of_record\n",
        "SF:/workspace/crates/populus-cluster/src/tests.rs\n",
        "FNF:2\nFNH:2\nLF:20\nLH:20\nend_of_record\n",
        "SF:/workspace/sim/populus-sim/src/authority.rs\n",
        "FNF:3\nFNH:3\nLF:30\nLH:30\nend_of_record\n",
    );
    assert_eq!(
        parse_lcov_coverage(report, Path::new("/workspace")),
        Ok(BTreeMap::from([
            (
                "populus-cluster".to_owned(),
                CoverageCounts {
                    files: 2,
                    functions_found: 12,
                    functions_hit: 11,
                    lines_found: 120,
                    lines_hit: 118,
                },
            ),
            (
                "populus-sim".to_owned(),
                CoverageCounts {
                    files: 1,
                    functions_found: 3,
                    functions_hit: 3,
                    lines_found: 30,
                    lines_hit: 30,
                },
            ),
        ]))
    );
}

#[test]
fn coverage_summary_rejects_malformed_or_empty_lcov_reports() {
    assert!(parse_lcov_coverage("", Path::new("/workspace")).is_err());
    assert!(
        parse_lcov_coverage(
            "SF:/workspace/crates/example/src/lib.rs\nLF:not-a-number\nend_of_record\n",
            Path::new("/workspace")
        )
        .is_err()
    );
    assert!(
        parse_lcov_coverage(
            "SF:/outside/lib.rs\nLF:1\nLH:1\nend_of_record\n",
            Path::new("/workspace")
        )
        .is_err()
    );
    assert_eq!(format_coverage_percent(0, 0), Ok("100.0".to_owned()));
    assert_eq!(format_coverage_percent(3, 4), Ok("75.0".to_owned()));
}
