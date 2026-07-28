//! Deterministic, read-only repository inspection for `LaunchGuard`.

mod acquire;
mod artifact;
mod capability;
mod degradation;
mod deploy;
mod detect;
mod error;
mod finding;
mod github;
mod history;
mod model;
mod plan;
mod provider;
mod provision;
mod publication;
mod publish;
mod readiness;
mod scanner;

pub use acquire::{AcquiredRepository, RepositoryAcquirer};
pub use artifact::{ArtifactStore, RAW_ARTIFACT_SCHEMA_VERSION, RawArtifact};
pub use capability::{
    CAPABILITY_REPORT_SCHEMA_JSON, CAPABILITY_REPORT_SCHEMA_VERSION, Capability, CapabilityKind,
    CapabilityProbe, CapabilityReport, CapabilityStatus, DeliveryTrack, Platform, ProbeConfig,
};
pub use degradation::{
    DEGRADATION_SCHEMA_JSON, DEGRADATION_SCHEMA_VERSION, Degradation, DegradationKind,
};
pub use deploy::{
    DEPLOYMENT_INTENT_SCHEMA_JSON, DEPLOYMENT_INTENT_SCHEMA_VERSION, DeploymentIntent,
    IntentGenerator, Provider, ProviderCandidate, ProviderLimit,
};
pub use detect::{DetectionEngine, DetectionLimits};
pub use error::{LaunchGuardError, Result};
pub use finding::{
    Confidence, FINDING_SCHEMA_JSON, FINDING_SCHEMA_VERSION, Finding, FindingCategory,
    FindingLocation, PackageReference, ScannerKind, Severity,
};
pub use github::{
    DeviceAuthorization, DeviceFlow, GitHubClient, PublishedPullRequest, RepositoryFacts,
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
pub use provider::{
    GENERATED_FILE_SCHEMA_JSON, GENERATED_FILE_SCHEMA_VERSION, GeneratedFile, GeneratedFileKind,
    ProviderAdapter, adapter_for, generate_configuration, validate_generated,
};
pub use provision::{
    OSV_SCANNER_VERSION, PROVISIONED_TOOL_SCHEMA_JSON, PROVISIONED_TOOL_SCHEMA_VERSION,
    ProvisionedTool, Provisioner, TRIVY_VERSION,
};
pub use publication::{
    GateLevel, GateReason, PUBLICATION_DECISION_SCHEMA_JSON, PUBLICATION_DECISION_SCHEMA_VERSION,
    PreviewOutcome, PublicationDecision, PublicationGate,
};
pub use publish::{
    PULL_REQUEST_PLAN_SCHEMA_JSON, PULL_REQUEST_PLAN_SCHEMA_VERSION, PublicationContext,
    PullRequestPlan, PullRequestPlanner, RequestedScope,
};
pub use readiness::{
    DimensionScore, READINESS_POLICY_VERSION, READINESS_SCHEMA_JSON, READINESS_SCHEMA_VERSION,
    ReadinessAssessment, ReadinessCheck, ReadinessDimension, ReadinessEngine, ReadinessScores,
};
pub use scanner::{
    SCANNER_PROVENANCE_SCHEMA_VERSION, ScannerConfig, ScannerLimits, ScannerProvenance,
    ScannerReport, ScannerRunner, merge_findings, normalize_osv, normalize_trivy,
};
