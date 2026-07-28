//! Deterministic, read-only repository inspection for `LaunchGuard`.

mod acquire;
mod artifact;
mod degradation;
mod detect;
mod error;
mod finding;
mod history;
mod model;
mod plan;
mod readiness;
mod scanner;

pub use acquire::{AcquiredRepository, RepositoryAcquirer};
pub use artifact::{ArtifactStore, RAW_ARTIFACT_SCHEMA_VERSION, RawArtifact};
pub use degradation::{
    DEGRADATION_SCHEMA_JSON, DEGRADATION_SCHEMA_VERSION, Degradation, DegradationKind,
};
pub use detect::{DetectionEngine, DetectionLimits};
pub use error::{LaunchGuardError, Result};
pub use finding::{
    Confidence, FINDING_SCHEMA_JSON, FINDING_SCHEMA_VERSION, Finding, FindingCategory,
    FindingLocation, PackageReference, ScannerKind, Severity,
};
pub use history::{HistoryEntry, HistoryStore, RunRecord};
pub use model::{
    CandidateClassification, Component, DeploymentKind, DetectionStatus, EnvironmentVariable,
    Evidence, Framework, PROJECT_PROFILE_SCHEMA_JSON, PROJECT_PROFILE_SCHEMA_VERSION,
    PackageManager, ProjectProfile, Runtime,
};
pub use plan::{
    ApprovalState, CommandStage, EXECUTION_PLAN_SCHEMA_JSON, EXECUTION_PLAN_SCHEMA_VERSION,
    ExecutionPlan, ExpectedOutput, HealthCheck, HealthCheckKind, NetworkPolicy, OutputKind,
    PlanCommand, PlanGenerator, REVIEWED_TEMPLATE_VERSION, ResourceLimits,
};
pub use readiness::{
    DimensionScore, READINESS_POLICY_VERSION, READINESS_SCHEMA_JSON, READINESS_SCHEMA_VERSION,
    ReadinessAssessment, ReadinessCheck, ReadinessDimension, ReadinessEngine, ReadinessScores,
};
pub use scanner::{
    SCANNER_PROVENANCE_SCHEMA_VERSION, ScannerConfig, ScannerLimits, ScannerProvenance,
    ScannerReport, ScannerRunner, merge_findings, normalize_osv, normalize_trivy,
};
