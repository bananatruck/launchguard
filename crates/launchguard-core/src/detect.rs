//! Deterministic framework detection over a bounded file index.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component as PathComponent, Path},
};

use regex::Regex;
use serde_json::Value as JsonValue;
use tracing::{debug, info};
use walkdir::{DirEntry, WalkDir};

use crate::{
    CandidateClassification, Component, DeploymentKind, DetectionStatus, EnvironmentVariable,
    Evidence, Framework, LaunchGuardError, PROJECT_PROFILE_SCHEMA_VERSION, PackageManager,
    ProjectProfile, Result, Runtime,
};

/// Bounds applied before repository content is parsed.
#[derive(Debug, Clone, Copy)]
pub struct DetectionLimits {
    /// Maximum directory depth below the selected root.
    pub max_depth: usize,
    /// Maximum number of files considered.
    pub max_files: usize,
    /// Maximum size of any text file read by a detector.
    pub max_file_bytes: u64,
}

impl Default for DetectionLimits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_files: 20_000,
            max_file_bytes: 1024 * 1024,
        }
    }
}

/// Read-only framework detection engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct DetectionEngine {
    limits: DetectionLimits,
}

impl DetectionEngine {
    /// Construct an engine with explicit inspection limits.
    #[must_use]
    pub fn new(limits: DetectionLimits) -> Self {
        Self { limits }
    }

    /// Inspect an acquired repository and produce a versioned profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository cannot be walked or an inspection
    /// size, depth, or file-count limit is exceeded.
    pub fn inspect(&self, repository: &crate::AcquiredRepository) -> Result<ProjectProfile> {
        info!(source = repository.source(), "starting read-only detection");
        let index = RepositoryIndex::build(repository.root(), self.limits)?;
        let mut candidates = Vec::new();
        candidates.extend(detect_node_projects(&index));
        candidates.extend(detect_fastapi_projects(&index));
        candidates.extend(detect_axum_projects(&index));
        candidates.sort_by(|left, right| {
            left.component_root
                .cmp(&right.component_root)
                .then(left.framework.cmp(&right.framework))
        });
        candidates.dedup_by(|left, right| {
            left.component_root == right.component_root && left.framework == right.framework
        });

        let public_candidates = candidates
            .iter()
            .map(DetectedCandidate::public)
            .collect::<Vec<_>>();
        let components = candidates
            .iter()
            .map(|candidate| Component {
                path: candidate.component_root.clone(),
                framework: candidate.framework,
                deployment_kind: candidate.deployment_kind,
            })
            .collect::<Vec<_>>();
        let evidence = public_candidates
            .iter()
            .flat_map(|candidate| candidate.evidence.iter().cloned())
            .collect::<Vec<_>>();

        let status = match candidates.len() {
            0 => DetectionStatus::Unsupported,
            1 => DetectionStatus::Detected,
            _ => DetectionStatus::NeedsConfirmation,
        };
        let selected = (candidates.len() == 1).then(|| &candidates[0]);
        let confidence = candidates
            .iter()
            .map(|candidate| candidate.confidence)
            .fold(0.0_f32, f32::max);

        let environment_variables = detect_environment_variables(&index);
        let detected_ports = detect_ports(&index);
        let profile = ProjectProfile {
            schema_version: PROJECT_PROFILE_SCHEMA_VERSION.to_owned(),
            source: repository.source().to_owned(),
            revision: repository.revision().to_owned(),
            status,
            components,
            framework: selected.map(|candidate| candidate.framework),
            runtime: selected.map(|candidate| candidate.runtime),
            package_manager: selected.and_then(|candidate| candidate.package_manager),
            deployment_kind: selected.map(|candidate| candidate.deployment_kind),
            build_command: selected.and_then(|candidate| candidate.build_command.clone()),
            test_commands: selected
                .map_or_else(Vec::new, |candidate| candidate.test_commands.clone()),
            start_command: selected.and_then(|candidate| candidate.start_command.clone()),
            output_directory: selected.and_then(|candidate| candidate.output_directory.clone()),
            detected_ports,
            required_services: Vec::new(),
            environment_variables,
            confidence,
            candidates: public_candidates,
            evidence,
        };
        debug!(
            status = ?profile.status,
            candidates = profile.candidates.len(),
            "detection completed"
        );
        Ok(profile)
    }
}

#[derive(Debug)]
struct RepositoryIndex {
    files: BTreeMap<String, String>,
}

impl RepositoryIndex {
    fn build(root: &Path, limits: DetectionLimits) -> Result<Self> {
        let mut files = BTreeMap::new();
        let mut files_seen = 0_usize;
        let walker = WalkDir::new(root)
            .follow_links(false)
            .max_depth(limits.max_depth)
            .into_iter()
            .filter_entry(should_visit);

        for entry_result in walker {
            let entry = entry_result.map_err(|error| {
                LaunchGuardError::Io(
                    error
                        .into_io_error()
                        .unwrap_or_else(|| std::io::Error::other("repository walk failed")),
                )
            })?;
            if !entry.file_type().is_file() {
                continue;
            }
            files_seen += 1;
            if files_seen > limits.max_files {
                return Err(LaunchGuardError::InspectionLimit(format!(
                    "repository contains more than {} files",
                    limits.max_files
                )));
            }
            if !is_detector_input(entry.path()) {
                continue;
            }

            let metadata = entry
                .metadata()
                .map_err(|error| LaunchGuardError::Io(std::io::Error::other(error.to_string())))?;
            if metadata.len() > limits.max_file_bytes {
                debug!(path = %entry.path().display(), "skipping oversized detector input");
                continue;
            }
            let Ok(content) = fs::read_to_string(entry.path()) else {
                debug!(path = %entry.path().display(), "skipping non-UTF-8 detector input");
                continue;
            };
            let relative = normalize_relative(
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("walker entries remain under root"),
            );
            files.insert(relative, content);
        }
        Ok(Self { files })
    }

    fn get(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(String::as_str)
    }

    fn direct_file(&self, root: &str, name: &str) -> Option<(&str, &str)> {
        let path = join_repo_path(root, name);
        self.files
            .get_key_value(&path)
            .map(|(stored_path, content)| (stored_path.as_str(), content.as_str()))
    }

    fn files_below<'a>(&'a self, root: &str) -> Vec<(&'a str, &'a str)> {
        self.files
            .iter()
            .filter_map(|(path, content)| {
                is_below(path, root).then_some((path.as_str(), content.as_str()))
            })
            .collect()
    }
}

fn should_visit(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(
            ".git"
                | ".hg"
                | ".svn"
                | ".next"
                | ".venv"
                | "build"
                | "dist"
                | "node_modules"
                | "target"
                | "venv"
        )
    )
}

fn is_detector_input(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if matches!(
        name,
        "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lock"
            | "bun.lockb"
            | "Cargo.toml"
            | "Cargo.lock"
            | "pyproject.toml"
            | "poetry.lock"
            | "uv.lock"
            | ".env.example"
            | ".env.sample"
            | "example.env"
    ) || name.starts_with("requirements") && name.ends_with(".txt")
        || name.starts_with("vite.config.")
        || name.starts_with("next.config.")
    {
        return true;
    }

    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "py" | "rs")
    )
}

fn normalize_relative(path: &Path) -> String {
    let parts = path
        .components()
        .filter_map(|component| match component {
            PathComponent::Normal(part) => Some(part.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>();
    parts.join("/")
}

fn join_repo_path(root: &str, name: &str) -> String {
    if root == "." {
        name.to_owned()
    } else {
        format!("{root}/{name}")
    }
}

fn parent_repo_path(path: &str) -> String {
    path.rsplit_once('/')
        .map_or_else(|| ".".to_owned(), |(parent, _)| parent.to_owned())
}

fn is_below(path: &str, root: &str) -> bool {
    root == "." || path == root || path.starts_with(&format!("{root}/"))
}

#[derive(Debug, Clone)]
struct DetectedCandidate {
    framework: Framework,
    component_root: String,
    runtime: Runtime,
    package_manager: Option<PackageManager>,
    deployment_kind: DeploymentKind,
    confidence: f32,
    evidence: Vec<Evidence>,
    build_command: Option<String>,
    test_commands: Vec<String>,
    start_command: Option<String>,
    output_directory: Option<String>,
}

impl DetectedCandidate {
    fn public(&self) -> CandidateClassification {
        CandidateClassification {
            framework: self.framework,
            component_root: self.component_root.clone(),
            confidence: self.confidence,
            evidence: self.evidence.clone(),
        }
    }
}

fn evidence(kind: &str, path: &str, description: &str, weight: f32) -> Evidence {
    Evidence {
        kind: kind.to_owned(),
        path: path.to_owned(),
        description: description.to_owned(),
        weight,
    }
}

fn detect_node_projects(index: &RepositoryIndex) -> Vec<DetectedCandidate> {
    let package_files = index
        .files
        .iter()
        .filter(|(path, _)| path.ends_with("package.json"))
        .map(|(path, content)| (path.clone(), content.clone()))
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();

    for (path, content) in package_files {
        let Ok(package) = serde_json::from_str::<JsonValue>(&content) else {
            debug!(path, "ignoring invalid package.json");
            continue;
        };
        let root = parent_repo_path(&path);
        let package_manager = detect_node_package_manager(index, &root, &package);
        let scripts = package.get("scripts").and_then(JsonValue::as_object);

        let vite_config = find_direct_config(index, &root, "vite.config.");
        let vite_dependency = node_dependency(&package, "vite");
        if vite_dependency || vite_config.is_some() {
            let mut facts = vec![evidence(
                "node_manifest",
                &path,
                "package.json is present",
                0.25,
            )];
            if vite_dependency {
                facts.push(evidence(
                    "vite_dependency",
                    &path,
                    "Vite is declared as a dependency",
                    0.55,
                ));
            } else if let Some(config_path) = vite_config {
                facts.push(evidence(
                    "vite_config",
                    config_path,
                    "A Vite configuration file is present",
                    0.55,
                ));
            }
            if node_dependency(&package, "react") {
                facts.push(evidence(
                    "react_dependency",
                    &path,
                    "React is declared as a dependency",
                    0.20,
                ));
            }
            let command = package_script_command(package_manager, "build");
            let test_command = scripts
                .is_some_and(|value| value.contains_key("test"))
                .then(|| package_script_command(package_manager, "test"))
                .flatten();
            let start_command = scripts
                .is_some_and(|value| value.contains_key("preview"))
                .then(|| package_script_command(package_manager, "preview"))
                .flatten();
            candidates.push(DetectedCandidate {
                framework: Framework::ReactVite,
                component_root: root.clone(),
                runtime: Runtime::NodeJs,
                package_manager,
                deployment_kind: DeploymentKind::Static,
                confidence: facts.iter().map(|fact| fact.weight).sum::<f32>().min(1.0),
                evidence: facts,
                build_command: scripts
                    .is_some_and(|value| value.contains_key("build"))
                    .then_some(command)
                    .flatten(),
                test_commands: test_command.into_iter().collect(),
                start_command,
                output_directory: Some(join_repo_path(&root, "dist")),
            });
        }

        if node_dependency(&package, "next") {
            let facts = vec![
                evidence("node_manifest", &path, "package.json is present", 0.25),
                evidence(
                    "next_dependency",
                    &path,
                    "Next.js is declared as a dependency",
                    0.75,
                ),
            ];
            let is_static = find_direct_config(index, &root, "next.config.")
                .and_then(|config_path| index.get(config_path))
                .is_some_and(next_config_exports_static);
            let deployment_kind = if is_static {
                DeploymentKind::Static
            } else {
                DeploymentKind::Server
            };
            let build_command = scripts
                .is_some_and(|value| value.contains_key("build"))
                .then(|| package_script_command(package_manager, "build"))
                .flatten();
            let test_command = scripts
                .is_some_and(|value| value.contains_key("test"))
                .then(|| package_script_command(package_manager, "test"))
                .flatten();
            let start_command = scripts
                .is_some_and(|value| value.contains_key("start"))
                .then(|| package_script_command(package_manager, "start"))
                .flatten();
            candidates.push(DetectedCandidate {
                framework: Framework::NextJs,
                component_root: root.clone(),
                runtime: Runtime::NodeJs,
                package_manager,
                deployment_kind,
                confidence: 1.0,
                evidence: facts,
                build_command,
                test_commands: test_command.into_iter().collect(),
                start_command,
                output_directory: Some(join_repo_path(
                    &root,
                    if is_static { "out" } else { ".next" },
                )),
            });
        }
    }
    candidates
}

fn find_direct_config<'a>(index: &'a RepositoryIndex, root: &str, prefix: &str) -> Option<&'a str> {
    index.files.keys().find_map(|path| {
        let parent = parent_repo_path(path);
        let name = path.rsplit('/').next().unwrap_or(path);
        (parent == root && name.starts_with(prefix)).then_some(path.as_str())
    })
}

fn node_dependency(package: &JsonValue, name: &str) -> bool {
    ["dependencies", "devDependencies", "peerDependencies"]
        .iter()
        .filter_map(|section| package.get(section).and_then(JsonValue::as_object))
        .any(|dependencies| dependencies.contains_key(name))
}

fn detect_node_package_manager(
    index: &RepositoryIndex,
    root: &str,
    package: &JsonValue,
) -> Option<PackageManager> {
    if index.direct_file(root, "pnpm-lock.yaml").is_some() {
        return Some(PackageManager::Pnpm);
    }
    if index.direct_file(root, "yarn.lock").is_some() {
        return Some(PackageManager::Yarn);
    }
    if index.direct_file(root, "bun.lock").is_some()
        || index.direct_file(root, "bun.lockb").is_some()
    {
        return Some(PackageManager::Bun);
    }
    if index.direct_file(root, "package-lock.json").is_some() {
        return Some(PackageManager::Npm);
    }

    package
        .get("packageManager")
        .and_then(JsonValue::as_str)
        .and_then(|manager| {
            let name = manager.split('@').next().unwrap_or(manager);
            match name {
                "npm" => Some(PackageManager::Npm),
                "pnpm" => Some(PackageManager::Pnpm),
                "yarn" => Some(PackageManager::Yarn),
                "bun" => Some(PackageManager::Bun),
                _ => None,
            }
        })
}

fn package_script_command(manager: Option<PackageManager>, script: &str) -> Option<String> {
    match manager? {
        PackageManager::Npm => Some(format!("npm run {script}")),
        PackageManager::Pnpm => Some(format!("pnpm run {script}")),
        PackageManager::Yarn => Some(format!("yarn {script}")),
        PackageManager::Bun => Some(format!("bun run {script}")),
        _ => None,
    }
}

fn next_config_exports_static(content: &str) -> bool {
    let compact = content
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    ["output:'export'", "output:\"export\"", "output=`export`"]
        .iter()
        .any(|marker| compact.contains(marker))
}

fn detect_fastapi_projects(index: &RepositoryIndex) -> Vec<DetectedCandidate> {
    let mut roots = BTreeSet::new();
    for path in index.files.keys() {
        let name = path.rsplit('/').next().unwrap_or(path);
        if name == "pyproject.toml" || name.starts_with("requirements") && name.ends_with(".txt") {
            roots.insert(parent_repo_path(path));
        }
    }

    let import_pattern =
        Regex::new(r"(?m)^\s*(?:from\s+fastapi\s+import|import\s+fastapi(?:\s|$))")
            .expect("static regular expression");
    let application_pattern = Regex::new(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*FastAPI\s*\(")
        .expect("static regular expression");
    let mut candidates = Vec::new();

    for root in roots {
        let dependency_path = python_fastapi_dependency(index, &root);
        let import_file = index
            .files_below(&root)
            .into_iter()
            .find(|(path, content)| path.ends_with(".py") && import_pattern.is_match(content));
        let (Some(dependency_path), Some((source_path, source))) = (dependency_path, import_file)
        else {
            continue;
        };

        let facts = vec![
            evidence(
                "python_manifest",
                dependency_path,
                "FastAPI is declared in a Python dependency manifest",
                0.5,
            ),
            evidence(
                "fastapi_import",
                source_path,
                "FastAPI is imported by Python source",
                0.5,
            ),
        ];
        let module = source_path
            .strip_suffix(".py")
            .unwrap_or(source_path)
            .replace('/', ".");
        let application = application_pattern
            .captures(source)
            .and_then(|captures| captures.get(1))
            .map_or("app", |matched| matched.as_str());
        let package_manager = detect_python_package_manager(index, &root);
        candidates.push(DetectedCandidate {
            framework: Framework::FastApi,
            component_root: root,
            runtime: Runtime::Python,
            package_manager,
            deployment_kind: DeploymentKind::Server,
            confidence: 1.0,
            evidence: facts,
            build_command: None,
            test_commands: has_python_tests(index)
                .then(|| "python -m pytest".to_owned())
                .into_iter()
                .collect(),
            start_command: Some(format!("python -m uvicorn {module}:{application}")),
            output_directory: None,
        });
    }
    candidates
}

fn python_fastapi_dependency<'a>(index: &'a RepositoryIndex, root: &str) -> Option<&'a str> {
    index.files.iter().find_map(|(path, content)| {
        if parent_repo_path(path) != root {
            return None;
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        let is_manifest =
            name == "pyproject.toml" || name.starts_with("requirements") && name.ends_with(".txt");
        (is_manifest && contains_dependency_token(content, "fastapi")).then_some(path.as_str())
    })
}

fn contains_dependency_token(content: &str, dependency: &str) -> bool {
    let pattern = Regex::new(&format!(
        r"(?i)(?:^|[^A-Za-z0-9_-]){}(?:$|[^A-Za-z0-9_-])",
        regex::escape(dependency)
    ))
    .expect("escaped dependency creates a valid expression");
    pattern.is_match(content)
}

fn detect_python_package_manager(index: &RepositoryIndex, root: &str) -> Option<PackageManager> {
    if index.direct_file(root, "uv.lock").is_some() {
        Some(PackageManager::Uv)
    } else if index.direct_file(root, "poetry.lock").is_some() {
        Some(PackageManager::Poetry)
    } else if index.files.keys().any(|path| {
        parent_repo_path(path) == root
            && path
                .rsplit('/')
                .next()
                .is_some_and(|name| name.starts_with("requirements") && name.ends_with(".txt"))
    }) {
        Some(PackageManager::Pip)
    } else {
        None
    }
}

fn has_python_tests(index: &RepositoryIndex) -> bool {
    index
        .files
        .keys()
        .any(|path| path.ends_with("_test.py") || path.contains("/test_"))
}

fn detect_axum_projects(index: &RepositoryIndex) -> Vec<DetectedCandidate> {
    let cargo_files = index
        .files
        .iter()
        .filter(|(path, _)| path.ends_with("Cargo.toml"))
        .map(|(path, content)| (path.clone(), content.clone()))
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();

    for (path, content) in cargo_files {
        let Ok(manifest) = toml::from_str::<toml::Value>(&content) else {
            debug!(path, "ignoring invalid Cargo.toml");
            continue;
        };
        if !toml_has_dependency(&manifest, "axum") {
            continue;
        }
        let root = parent_repo_path(&path);
        let facts = vec![
            evidence("cargo_manifest", &path, "Cargo.toml is present", 0.25),
            evidence(
                "axum_dependency",
                &path,
                "Axum is declared as a Cargo dependency",
                0.75,
            ),
        ];
        let locked = index.direct_file(&root, "Cargo.lock").is_some();
        let locked_flag = if locked { " --locked" } else { "" };
        candidates.push(DetectedCandidate {
            framework: Framework::RustAxum,
            component_root: root.clone(),
            runtime: Runtime::Rust,
            package_manager: Some(PackageManager::Cargo),
            deployment_kind: DeploymentKind::Server,
            confidence: 1.0,
            evidence: facts,
            build_command: Some(format!("cargo build{locked_flag}")),
            test_commands: vec![format!("cargo test{locked_flag}")],
            start_command: Some(format!("cargo run{locked_flag} --release")),
            output_directory: Some(join_repo_path(&root, "target/release")),
        });
    }
    candidates
}

fn toml_has_dependency(value: &toml::Value, dependency: &str) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    table.iter().any(|(key, nested)| {
        let dependency_section = matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        );
        (dependency_section
            && nested
                .as_table()
                .is_some_and(|dependencies| dependencies.contains_key(dependency)))
            || toml_has_dependency(nested, dependency)
    })
}

fn detect_environment_variables(index: &RepositoryIndex) -> Vec<EnvironmentVariable> {
    let template_pattern =
        Regex::new(r"(?m)^\s*([A-Z][A-Z0-9_]*)\s*=").expect("static regular expression");
    let source_patterns = [
        Regex::new(r"(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]*)")
            .expect("static regular expression"),
        Regex::new(r#"(?:std::)?env::var\(\s*"([A-Z][A-Z0-9_]*)""#)
            .expect("static regular expression"),
        Regex::new(r#"(?:os\.getenv|os\.environ\.get)\(\s*["']([A-Z][A-Z0-9_]*)["']"#)
            .expect("static regular expression"),
        Regex::new(r#"os\.environ\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]"#)
            .expect("static regular expression"),
    ];
    let mut variables = BTreeMap::<String, EnvironmentVariable>::new();

    for (path, content) in &index.files {
        let name = path.rsplit('/').next().unwrap_or(path);
        if matches!(name, ".env.example" | ".env.sample" | "example.env") {
            for captures in template_pattern.captures_iter(content) {
                let variable_name = captures[1].to_owned();
                variables
                    .entry(variable_name.clone())
                    .or_insert(EnvironmentVariable {
                        name: variable_name,
                        required: true,
                        evidence_path: path.clone(),
                    });
            }
        }
        for pattern in &source_patterns {
            for captures in pattern.captures_iter(content) {
                let variable_name = captures[1].to_owned();
                variables
                    .entry(variable_name.clone())
                    .or_insert(EnvironmentVariable {
                        name: variable_name,
                        required: true,
                        evidence_path: path.clone(),
                    });
            }
        }
    }
    variables.into_values().collect()
}

fn detect_ports(index: &RepositoryIndex) -> Vec<u16> {
    let patterns = [
        Regex::new(r"(?im)^\s*PORT\s*=\s*([0-9]{2,5})\s*$").expect("static regular expression"),
        Regex::new(r#"(?i)(?:port|listen)\s*[:=]\s*["']?([0-9]{2,5})"#)
            .expect("static regular expression"),
        Regex::new(r"(?:localhost|127\.0\.0\.1):([0-9]{2,5})").expect("static regular expression"),
    ];
    let mut ports = BTreeSet::new();
    for content in index.files.values() {
        for pattern in &patterns {
            for captures in pattern.captures_iter(content) {
                if let Ok(port) = captures[1].parse::<u16>()
                    && port != 0
                {
                    ports.insert(port);
                }
            }
        }
    }
    ports.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{next_config_exports_static, normalize_relative, toml_has_dependency};
    use std::path::Path;

    #[test]
    fn static_next_configuration_is_recognized() {
        assert!(next_config_exports_static(
            "export default { output: 'export' };"
        ));
        assert!(!next_config_exports_static("export default {};"));
    }

    #[test]
    fn repository_paths_use_forward_slashes() {
        assert_eq!(normalize_relative(Path::new("src/main.rs")), "src/main.rs");
    }

    #[test]
    fn axum_dependency_is_recognized() {
        let manifest = toml::from_str::<toml::Value>(
            r#"
            [package]
            name = "api"
            version = "0.1.0"

            [dependencies]
            axum = "0.8"
        "#,
        )
        .expect("valid Cargo manifest");
        assert!(toml_has_dependency(&manifest, "axum"));
    }
}
