//! Versioned public records emitted by project detection.

use serde::{Deserialize, Serialize};

/// The only `ProjectProfile` schema accepted by this release.
pub const PROJECT_PROFILE_SCHEMA_VERSION: &str = "1.0";

/// Outcome of deterministic framework classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    /// Exactly one supported classification is backed by the required evidence.
    Detected,
    /// Multiple supported classifications are plausible and require a person to choose.
    NeedsConfirmation,
    /// No supported classification has its required evidence.
    Unsupported,
}

/// Frameworks supported by the Phase 1 detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    /// A React application built with Vite.
    ReactVite,
    /// A Next.js application.
    NextJs,
    /// A Python `FastAPI` service.
    FastApi,
    /// A Rust service using Axum.
    RustAxum,
}

impl std::fmt::Display for Framework {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::ReactVite => "React/Vite",
            Self::NextJs => "Next.js",
            Self::FastApi => "FastAPI",
            Self::RustAxum => "Rust/Axum",
        };
        formatter.write_str(value)
    }
}

/// Runtime required by a detected framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    /// Node.js.
    NodeJs,
    /// Python.
    Python,
    /// Native Rust binary.
    Rust,
}

/// Package manager selected from lockfile evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    /// npm.
    Npm,
    /// pnpm.
    Pnpm,
    /// Yarn.
    Yarn,
    /// Bun.
    Bun,
    /// pip or a requirements file.
    Pip,
    /// Poetry.
    Poetry,
    /// uv.
    Uv,
    /// Cargo.
    Cargo,
}

/// Deployment behavior inferred without running the project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentKind {
    /// Output consists of static files.
    Static,
    /// Output requires a running application server.
    Server,
}

/// A concrete, source-addressable fact used during classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Stable evidence category.
    pub kind: String,
    /// Repository-relative path where the fact was found.
    pub path: String,
    /// Human-readable description that does not include source contents.
    pub description: String,
    /// Contribution to the candidate confidence score.
    pub weight: f32,
}

/// A supported classification and the evidence supporting it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateClassification {
    /// Candidate framework.
    pub framework: Framework,
    /// Repository-relative component root.
    pub component_root: String,
    /// Deterministic confidence in the range `0.0..=1.0`.
    pub confidence: f32,
    /// Facts contributing to this candidate.
    pub evidence: Vec<Evidence>,
}

/// A supported component found in a repository.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Component {
    /// Repository-relative component root.
    pub path: String,
    /// Detected framework.
    pub framework: Framework,
    /// Static or server deployment behavior.
    pub deployment_kind: DeploymentKind,
}

/// An environment variable name observed in a template or source expression.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EnvironmentVariable {
    /// Variable name. Values are never collected.
    pub name: String,
    /// Whether the available syntax provides no default value.
    pub required: bool,
    /// Repository-relative source of the observation.
    pub evidence_path: String,
}

/// Evidence-backed description of a repository revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectProfile {
    /// Public record schema.
    pub schema_version: String,
    /// User-provided path or normalized GitHub repository URL.
    pub source: String,
    /// Git commit SHA when available, otherwise `unversioned`.
    pub revision: String,
    /// Classification outcome.
    pub status: DetectionStatus,
    /// Supported components. Ambiguous multi-component repositories retain every candidate.
    pub components: Vec<Component>,
    /// Selected framework when classification is unambiguous.
    pub framework: Option<Framework>,
    /// Selected runtime when classification is unambiguous.
    pub runtime: Option<Runtime>,
    /// Package manager inferred from lockfiles or manifests.
    pub package_manager: Option<PackageManager>,
    /// Static or server behavior.
    pub deployment_kind: Option<DeploymentKind>,
    /// Reviewed-template build command proposed for later planning.
    pub build_command: Option<String>,
    /// Reviewed-template test commands proposed for later planning.
    pub test_commands: Vec<String>,
    /// Reviewed-template start command proposed for later planning.
    pub start_command: Option<String>,
    /// Expected repository-relative build output.
    pub output_directory: Option<String>,
    /// Explicitly observed application ports.
    pub detected_ports: Vec<u16>,
    /// Required external services. Phase 1 leaves this empty unless deterministically observed.
    pub required_services: Vec<String>,
    /// Names of environment variables; values are never read or stored.
    pub environment_variables: Vec<EnvironmentVariable>,
    /// Confidence of the selected classification, or the strongest candidate.
    pub confidence: f32,
    /// Every supported candidate meeting its minimum evidence contract.
    pub candidates: Vec<CandidateClassification>,
    /// Evidence for the selected classification, or all competing evidence.
    pub evidence: Vec<Evidence>,
}

impl ProjectProfile {
    /// Reject profiles written by a schema unknown to this release.
    ///
    /// # Errors
    ///
    /// Returns [`crate::LaunchGuardError::UnknownSchemaVersion`] when the
    /// profile does not use the schema supported by this release.
    pub fn validate_schema(&self) -> crate::Result<()> {
        if self.schema_version == PROJECT_PROFILE_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(crate::LaunchGuardError::UnknownSchemaVersion(
                self.schema_version.clone(),
            ))
        }
    }
}
