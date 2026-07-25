//! Deterministic, read-only repository inspection for `LaunchGuard`.

mod acquire;
mod detect;
mod error;
mod history;
mod model;

pub use acquire::{AcquiredRepository, RepositoryAcquirer};
pub use detect::{DetectionEngine, DetectionLimits};
pub use error::{LaunchGuardError, Result};
pub use history::{HistoryEntry, HistoryStore};
pub use model::{
    CandidateClassification, Component, DeploymentKind, DetectionStatus, EnvironmentVariable,
    Evidence, Framework, PROJECT_PROFILE_SCHEMA_JSON, PROJECT_PROFILE_SCHEMA_VERSION,
    PackageManager, ProjectProfile, Runtime,
};
