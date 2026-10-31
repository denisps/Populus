//! Developer commands and repository quality gates for Populus.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};
use std::time::Instant;

const NEXTTEST_VERSION: &str = "0.9.148";
const LLVM_COV_VERSION: &str = "0.9.1";
const MACHETE_VERSION: &str = "0.9.2";
const DENY_VERSION: &str = "0.20.2";

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
        Some("setup") => setup(root),
        Some("fmt") => run_cargo(root, &["fmt"]),
        Some("lint") => lint(root),
        Some("test") => nextest(root),
        Some("test-all") => {
            nextest(root)?;
            run_cargo(root, &["test", "--workspace", "--doc"])
        }
        Some("coverage") => coverage(root),
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
        None => Err(
            "usage: cargo xtask <setup|fmt|lint|test|test-all|coverage|deps|metrics|gate>"
                .to_owned(),
        ),
    }
}

fn setup(root: &Path) -> Result<(), String> {
    ensure_nextest(root)?;
    ensure_cargo_tool(root, "llvm-cov", "cargo-llvm-cov", LLVM_COV_VERSION)?;
    ensure_cargo_tool(root, "machete", "cargo-machete", MACHETE_VERSION)?;
    ensure_cargo_tool(root, "deny", "cargo-deny", DENY_VERSION)?;
    println!("Populus development tools are ready.");
    Ok(())
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
    ensure_nextest(root)?;
    run_cargo(root, &["nextest", "run", "--workspace"])
}

fn ensure_nextest(root: &Path) -> Result<(), String> {
    ensure_cargo_tool(root, "nextest", "cargo-nextest", NEXTTEST_VERSION)
}

fn coverage(root: &Path) -> Result<(), String> {
    ensure_nextest(root)?;
    ensure_cargo_tool(root, "llvm-cov", "cargo-llvm-cov", LLVM_COV_VERSION)?;

    let arguments = [
        "llvm-cov",
        "nextest",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--lcov",
        "--summary-only",
    ];
    println!("$ cargo {}", arguments.join(" "));
    let output = command_output(root, &arguments)?;
    if !output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return Err(format!(
            "cargo {} exited with {}",
            arguments.join(" "),
            output.status
        ));
    }

    let summaries = parse_lcov_coverage(&String::from_utf8_lossy(&output.stdout), root)?;
    println!("Coverage tests passed.");
    for (package, counts) in summaries {
        println!(
            "{package}: {} files, lines {}/{} ({}%), functions {}/{} ({}%)",
            counts.files,
            counts.lines_hit,
            counts.lines_found,
            format_coverage_percent(counts.lines_hit, counts.lines_found)?,
            counts.functions_hit,
            counts.functions_found,
            format_coverage_percent(counts.functions_hit, counts.functions_found)?,
        );
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CoverageCounts {
    files: usize,
    functions_found: usize,
    functions_hit: usize,
    lines_found: usize,
    lines_hit: usize,
}

impl CoverageCounts {
    fn add_assign(&mut self, other: &Self) {
        self.files += other.files;
        self.functions_found += other.functions_found;
        self.functions_hit += other.functions_hit;
        self.lines_found += other.lines_found;
        self.lines_hit += other.lines_hit;
    }
}

fn parse_lcov_coverage(
    report: &str,
    root: &Path,
) -> Result<BTreeMap<String, CoverageCounts>, String> {
    let mut summaries = BTreeMap::new();
    let mut current: Option<(String, CoverageCounts)> = None;

    for line in report.lines() {
        if let Some(source) = line.strip_prefix("SF:") {
            if current.is_some() {
                return Err(
                    "LCOV report started a file before ending the previous record".to_owned(),
                );
            }
            current = Some((
                coverage_package_name(source, root)?,
                CoverageCounts::default(),
            ));
        } else if line == "end_of_record" {
            let Some((package, counts)) = current.take() else {
                return Err("LCOV report ended a record without a source file".to_owned());
            };
            summaries
                .entry(package)
                .or_insert_with(CoverageCounts::default)
                .add_assign(&CoverageCounts { files: 1, ..counts });
        } else if let Some((prefix, field)) = [
            ("FNF:", "functions_found"),
            ("FNH:", "functions_hit"),
            ("LF:", "lines_found"),
            ("LH:", "lines_hit"),
        ]
        .into_iter()
        .find(|(prefix, _)| line.starts_with(prefix))
        {
            let Some((_, counts)) = current.as_mut() else {
                return Err(format!(
                    "LCOV counter appeared outside a file record: {line}"
                ));
            };
            let value = line
                .strip_prefix(prefix)
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| format!("invalid LCOV counter: {line}"))?;
            match field {
                "functions_found" => counts.functions_found = value,
                "functions_hit" => counts.functions_hit = value,
                "lines_found" => counts.lines_found = value,
                "lines_hit" => counts.lines_hit = value,
                _ => return Err(format!("unsupported LCOV counter: {field}")),
            }
        }
    }

    if current.is_some() {
        return Err("LCOV report ended before closing the current file record".to_owned());
    }
    if summaries.is_empty() {
        return Err("LCOV report contained no file coverage records".to_owned());
    }
    Ok(summaries)
}

fn coverage_package_name(source: &str, root: &Path) -> Result<String, String> {
    let path = Path::new(source);
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "coverage source is outside the workspace: {}",
            path.display()
        )
    })?;
    let mut components = relative.components();
    let first = components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .ok_or_else(|| format!("invalid workspace coverage path: {}", path.display()))?;
    let package = if matches!(first, "crates" | "sim") {
        components
            .next()
            .and_then(|component| component.as_os_str().to_str())
            .ok_or_else(|| format!("missing package in coverage path: {}", path.display()))?
    } else {
        first
    };
    Ok(package.to_owned())
}

fn format_coverage_percent(hit: usize, total: usize) -> Result<String, String> {
    let tenths = if total == 0 {
        1_000
    } else {
        let hit = u128::try_from(hit)
            .map_err(|error| format!("coverage count does not fit u128: {error}"))?;
        let total = u128::try_from(total)
            .map_err(|error| format!("coverage total does not fit u128: {error}"))?;
        hit.saturating_mul(1_000)
            .saturating_add(total / 2)
            .checked_div(total)
            .ok_or_else(|| "coverage total unexpectedly became zero".to_owned())?
    };
    Ok(format!("{}.{:01}", tenths / 10, tenths % 10))
}

fn ensure_cargo_tool(
    root: &Path,
    command: &str,
    package: &str,
    version: &str,
) -> Result<(), String> {
    if cargo_tool_version_matches(root, command, version) {
        return Ok(());
    }

    println!("{package} {version} is missing; installing the pinned version.");
    run_cargo(
        root,
        &[
            "install",
            "--force",
            "--locked",
            package,
            "--version",
            version,
        ],
    )?;
    if cargo_tool_version_matches(root, command, version) {
        Ok(())
    } else {
        Err(format!(
            "{package} {version} installation completed but `cargo {command} --version` did not report the pinned version"
        ))
    }
}

fn dependencies(root: &Path) -> Result<(), String> {
    run_cargo(root, &["tree", "-e", "features"])?;
    run_cargo(root, &["tree", "-d"])?;
    ensure_cargo_tool(root, "machete", "cargo-machete", MACHETE_VERSION)?;
    ensure_cargo_tool(root, "deny", "cargo-deny", DENY_VERSION)?;
    run_cargo(root, &["machete"])?;
    run_cargo(root, &["deny", "check"])
}

fn gate_commit(root: &Path) -> Result<(), String> {
    run_cargo(root, &["fmt", "--check"])?;
    lint(root)?;
    nextest(root)?;
    ensure_cargo_tool(root, "machete", "cargo-machete", MACHETE_VERSION)?;
    run_cargo(root, &["machete"])?;
    ensure_cargo_tool(root, "deny", "cargo-deny", DENY_VERSION)?;
    run_cargo(root, &["deny", "check"])?;
    run_cargo(root, &["xtask", "metrics", "--quick"])
}

fn gate_pr(root: &Path) -> Result<(), String> {
    gate_commit(root)?;
    run_cargo(root, &["test", "--workspace", "--doc"])?;

    coverage(root)?;

    println!("SKIP: selected cargo-mutants checks are deferred until protocol targets exist.");
    println!("SKIP: deterministic simulator scenarios are deferred until scenarios exist.");
    println!("SKIP: iai-callgrind checks are deferred until benchmark harnesses exist.");
    println!("INFO: release binary-size measurements are included in the metrics artifact.");
    run_cargo(root, &["tree", "-d"])
}

fn cargo_tool_version_matches(root: &Path, tool: &str, version: &str) -> bool {
    let output = Command::new("cargo")
        .args([tool, "--version"])
        .env_remove("CARGO_PKG_NAME")
        .current_dir(root)
        .output();
    output.is_ok_and(|output| {
        output.status.success()
            && tool_version_matches(&String::from_utf8_lossy(&output.stdout), version)
    })
}

fn tool_version_matches(output: &str, expected: &str) -> bool {
    let Some(first_line) = output.lines().next() else {
        return false;
    };
    first_line == expected || first_line.split_whitespace().nth(1) == Some(expected)
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
    let (clean_build_ms, incremental_build_ms, quick_build_ms) = if quick {
        let started = Instant::now();
        run_cargo(root, &["build", "--workspace", "--release"])?;
        (None, None, Some(started.elapsed().as_millis()))
    } else {
        run_cargo(root, &["clean"])?;
        let clean_started = Instant::now();
        run_cargo(root, &["build", "--workspace", "--release"])?;
        let clean_build_ms = clean_started.elapsed().as_millis();

        let incremental_started = Instant::now();
        run_cargo(root, &["build", "--workspace", "--release"])?;
        let incremental_build_ms = incremental_started.elapsed().as_millis();
        (Some(clean_build_ms), Some(incremental_build_ms), None)
    };

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
            "  \"quick_build_duration_ms\": {quick_build_ms},\n",
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
        clean_build_ms = json_number(clean_build_ms),
        incremental_build_ms = json_number(incremental_build_ms),
        quick_build_ms = json_number(quick_build_ms),
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
    let mut package_versions = BTreeMap::<&str, BTreeSet<&str>>::new();
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

fn json_number(value: Option<impl std::fmt::Display>) -> String {
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
mod tests;
