use super::{duplicate_version_count_from_tree, package_label};

#[test]
fn package_labels_ignore_version_and_source() {
    assert_eq!(
        package_label("populus-types v0.1.0 (/workspace/crates/populus-types)"),
        Some("populus-types")
    );
}

#[test]
fn duplicate_versions_count_only_additional_versions() {
    let tree = "serde v1.0.0\nserde v2.0.0\nother v1.0.0\nother v1.0.0\n";

    assert_eq!(duplicate_version_count_from_tree(tree), 1);
}
