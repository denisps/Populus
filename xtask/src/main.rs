//! Developer commands and repository quality gates for Populus.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};
use std::time::Instant;

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf);

    let Some(root) = root else {
        eprintln!("could not locate the workspace root");
        return ExitCode::FAILURE;
    };

    match run(&root, &arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    match arguments.first().map(String::as_str) {
        Some("fmt") => run_cargo(root, &["fmt"]),
        Some("lint") => lint(root),
        Some("test") => nextest(root),
        Some("test-all") => {
            nextest(root)?;
            run_cargo(root, &["test", "--workspace", "--doc"])
        }
        Some("coverage") => run_cargo(root, &["llvm-cov", "nextest", "--workspace"]),
        Some("deps") => dependencies(root),
        Some("metrics") => {
            let quick = arguments.iter().any(|argument| argument == "--quick");
            metrics(root, quick)
        }
        Some("gate") => match arguments.get(1).map(String::as_str) {
            Some("commit") => gate_commit(root),
            Some("pr") => gate_pr(root),
            _ => Err("usage: cargo xtask gate <commit|pr>".to_owned()),
        },
        Some(command) => Err(format!("unknown xtask command: {command}")),
        None => {
            Err("usage: cargo xtask <fmt|lint|test|test-all|coverage|deps|metrics|gate>".to_owned())
        }
    }
}

fn lint(root: &Path) -> Result<(), String> {
    run_cargo(
        root,
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )
}

fn nextest(root: &Path) -> Result<(), String> {
    run_cargo(root, &["nextest", "run", "--workspace"])
}

fn dependencies(root: &Path) -> Result<(), String> {
    run_cargo(root, &["tree", "-e", "features"])?;
    run_cargo(root, &["tree", "-d"])?;
    run_cargo(root, &["machete"])?;
    run_cargo(root, &["deny", "check"])
}

fn gate_commit(root: &Path) -> Result<(), String> {
    run_cargo(root, &["fmt", "--check"])?;
    lint(root)?;
    nextest(root)?;
    run_cargo(root, &["machete"])?;
    run_cargo(root, &["deny", "check"])?;
    run_cargo(root, &["xtask", "metrics", "--quick"])
}

fn gate_pr(root: &Path) -> Result<(), String> {
    gate_commit(root)?;
    run_cargo(root, &["test", "--workspace", "--doc"])?;

    if cargo_tool_available(root, "llvm-cov") {
        run_cargo(root, &["llvm-cov", "nextest", "--workspace"])?;
    } else {
        println!("SKIP: cargo-llvm-cov is not installed; coverage is unavailable.");
    }

    println!("SKIP: selected cargo-mutants checks are deferred until protocol targets exist.");
    println!("SKIP: deterministic simulator scenarios are deferred until scenarios exist.");
    println!("SKIP: iai-callgrind checks are deferred until benchmark harnesses exist.");
    println!("INFO: release binary-size measurements are included in the metrics artifact.");
    run_cargo(root, &["tree", "-d"])
}

fn cargo_tool_available(root: &Path, tool: &str) -> bool {
    Command::new("cargo")
        .arg(tool)
        .arg("--version")
        .env_remove("CARGO_PKG_NAME")
        .current_dir(root)
        .status()
        .is_ok_and(|status| status.success())
}

fn run_cargo(root: &Path, arguments: &[&str]) -> Result<(), String> {
    println!("$ cargo {}", arguments.join(" "));
    let status = Command::new("cargo")
        .args(arguments)
        .env_remove("CARGO_PKG_NAME")
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not run cargo {}: {error}", arguments.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "cargo {} exited with {status}",
            arguments.join(" ")
        ))
    }
}

fn command_output(root: &Path, arguments: &[&str]) -> Result<Output, String> {
    Command::new("cargo")
        .args(arguments)
        .env_remove("CARGO_PKG_NAME")
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not run cargo {}: {error}", arguments.join(" ")))
}

fn metrics(root: &Path, quick: bool) -> Result<(), String> {
    run_cargo(root, &["clean"])?;
    let clean_started = Instant::now();
    run_cargo(root, &["build", "--workspace", "--release"])?;
    let clean_build_ms = clean_started.elapsed().as_millis();

    let incremental_started = Instant::now();
    run_cargo(root, &["build", "--workspace", "--release"])?;
    let incremental_build_ms = incremental_started.elapsed().as_millis();

    let tree = command_output(
        root,
        &[
            "tree",
            "--workspace",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
    )?;
    require_success(&tree, "cargo tree runtime dependencies")?;

    let duplicates = command_output(
        root,
        &[
            "tree",
            "--workspace",
            "--edges",
            "normal",
            "--duplicates",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
    )?;
    require_success(&duplicates, "cargo tree duplicate versions")?;

    let member_names = workspace_member_names(root)?;
    let direct_dependencies = direct_external_dependency_count(root, &member_names)?;
    let transitive_dependencies = external_tree_package_count(&tree, &member_names);
    let duplicate_versions = duplicate_version_count(&duplicates);
    let release_binary_bytes = release_binary_size(root);
    let revision = git_revision(root);
    let output_path = root.join("metrics").join(format!("{revision}.json"));
    fs::create_dir_all(root.join("metrics"))
        .map_err(|error| format!("could not create metrics directory: {error}"))?;

    let report = format!(
        concat!(
            "{{\n",
            "  \"git_sha\": \"{revision}\",\n",
            "  \"quick\": {quick},\n",
            "  \"release_binary_bytes\": {release_binary},\n",
            "  \"text_section_bytes\": null,\n",
            "  \"runtime_direct_dependency_count\": {direct_dependencies},\n",
            "  \"runtime_transitive_dependency_count\": {transitive_dependencies},\n",
            "  \"duplicate_dependency_versions\": {duplicate_versions},\n",
            "  \"clean_build_duration_ms\": {clean_build_ms},\n",
            "  \"incremental_build_duration_ms\": {incremental_build_ms},\n",
            "  \"hll_insert_cost\": null,\n",
            "  \"hll_merge_cost\": null,\n",
            "  \"hll_memory_bytes\": null,\n",
            "  \"routing_lookup_cost\": null,\n",
            "  \"client_assignment_cost\": null,\n",
            "  \"canonical_encode_decode_cost\": null,\n",
            "  \"simulated_ingest_messages_per_second\": null,\n",
            "  \"simulated_authority_messages_per_second\": null,\n",
            "  \"peak_simulator_memory_bytes\": null\n",
            "}}\n"
        ),
        revision = revision,
        quick = quick,
        release_binary = json_number(release_binary_bytes),
        direct_dependencies = direct_dependencies,
        transitive_dependencies = transitive_dependencies,
        duplicate_versions = duplicate_versions,
        clean_build_ms = clean_build_ms,
        incremental_build_ms = incremental_build_ms,
    );
    fs::write(&output_path, report)
        .map_err(|error| format!("could not write metrics report: {error}"))?;
    println!("Wrote {}", output_path.display());
    Ok(())
}

fn require_success(output: &Output, description: &str) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{description} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn workspace_member_names(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for manifest in workspace_manifest_paths(root)? {
        if let Some(name) = package_name(&manifest)? {
            names.insert(name);
        }
    }
    Ok(names)
}

fn workspace_manifest_paths(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut manifests = vec![root.join("xtask/Cargo.toml")];
    for directory in [root.join("crates"), root.join("sim")] {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("could not inspect {}: {error}", directory.display()))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("could not read workspace entry: {error}"))?;
            if entry.path().is_dir() {
                let manifest = entry.path().join("Cargo.toml");
                if manifest.is_file() {
                    manifests.push(manifest);
                }
            }
        }
    }
    Ok(manifests)
}

fn package_name(manifest: &Path) -> Result<Option<String>, String> {
    let contents = fs::read_to_string(manifest)
        .map_err(|error| format!("could not read {}: {error}", manifest.display()))?;
    let mut in_package = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_package = line == "[package]";
        } else if in_package
            && line.starts_with("name")
            && let Some((_, value)) = line.split_once('=')
        {
            return Ok(Some(value.trim().trim_matches('"').to_owned()));
        }
    }
    Ok(None)
}

fn direct_external_dependency_count(
    root: &Path,
    member_names: &BTreeSet<String>,
) -> Result<usize, String> {
    let mut count = 0;
    for manifest in workspace_manifest_paths(root)? {
        count += direct_dependencies_in_manifest(&manifest, member_names)?;
    }
    Ok(count)
}

fn direct_dependencies_in_manifest(
    manifest: &Path,
    member_names: &BTreeSet<String>,
) -> Result<usize, String> {
    let contents = fs::read_to_string(manifest)
        .map_err(|error| format!("could not read {}: {error}", manifest.display()))?;
    let mut runtime_dependencies = false;
    let mut count = 0;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = line.trim_matches(['[', ']']);
            runtime_dependencies = section == "dependencies" || section.ends_with(".dependencies");
            if let Some(dependency_name) = section.strip_prefix("dependencies.")
                && !member_names.contains(dependency_name)
            {
                count += 1;
            }
        } else if runtime_dependencies
            && !line.is_empty()
            && !line.starts_with('#')
            && let Some((name, _)) = line.split_once('=')
            && !member_names.contains(name.trim())
        {
            count += 1;
        }
    }
    Ok(count)
}

fn external_tree_package_count(output: &Output, member_names: &BTreeSet<String>) -> usize {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(package_label)
        .filter(|name| !member_names.contains(*name))
        .collect::<BTreeSet<_>>()
        .len()
}

fn duplicate_version_count(output: &Output) -> usize {
    duplicate_version_count_from_tree(&String::from_utf8_lossy(&output.stdout))
}

fn duplicate_version_count_from_tree(output: &str) -> usize {
    let mut package_versions = std::collections::BTreeMap::<&str, BTreeSet<&str>>::new();
    for line in output.lines() {
        if let Some((name, version)) = package_identity(line) {
            package_versions.entry(name).or_default().insert(version);
        }
    }
    package_versions
        .values()
        .map(|versions| versions.len().saturating_sub(1))
        .sum()
}

fn package_label(line: &str) -> Option<&str> {
    package_identity(line).map(|(name, _)| name)
}

fn package_identity(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let separator = line.find(" v")?;
    let version = line[separator + 2..].split_whitespace().next()?;
    Some((&line[..separator], version))
}

fn release_binary_size(root: &Path) -> Option<u64> {
    let binary = root.join("target").join("release").join("populus-node");
    fs::metadata(binary).ok().map(|metadata| metadata.len())
}

fn json_number(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |number| number.to_string())
}

fn git_revision(root: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(root)
        .output();
    let revision = output
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|revision| !revision.is_empty());
    match revision {
        Some(revision) => revision,
        None => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
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
}
