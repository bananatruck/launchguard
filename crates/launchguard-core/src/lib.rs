//! Deterministic, read-only repository inspection for `LaunchGuard`.

mod acquire;
mod artifact;
mod detect;
mod error;
mod finding;
mod history;
mod model;
mod scanner;

pub use acquire::{AcquiredRepository, RepositoryAcquirer};
pub use artifact::{ArtifactStore, RAW_ARTIFACT_SCHEMA_VERSION, RawArtifact};
pub use detect::{DetectionEngine, DetectionLimits};
pub use error::{LaunchGuardError, Result};
pub use finding::{
    Confidence, FINDING_SCHEMA_VERSION, Finding, FindingCategory, FindingLocation,
    PackageReference, ScannerKind, Severity,
};
pub use history::{HistoryEntry, HistoryStore};
pub use model::{
    CandidateClassification, Component, DeploymentKind, DetectionStatus, EnvironmentVariable,
    Evidence, Framework, PROJECT_PROFILE_SCHEMA_JSON, PROJECT_PROFILE_SCHEMA_VERSION,
    PackageManager, ProjectProfile, Runtime,
};
pub use scanner::{
    ScannerConfig, ScannerLimits, ScannerReport, ScannerRunner, merge_findings, normalize_osv,
    normalize_trivy,
};
