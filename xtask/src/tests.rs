use super::{
    CoverageCounts, duplicate_version_count_from_tree, format_coverage_percent, package_label,
    parse_lcov_coverage, tool_version_matches,
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
