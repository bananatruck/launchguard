//! Error types exposed by the `LaunchGuard` engine.

use std::path::PathBuf;

/// Errors produced while acquiring, inspecting, or recording a repository.
#[derive(Debug, thiserror::Error)]
pub enum LaunchGuardError {
    /// The requested source is neither a local directory nor a supported URL.
    #[error("unsupported repository source: {0}")]
    UnsupportedSource(String),

    /// The selected local path is invalid.
    #[error("repository path is not a readable directory: {0}")]
    InvalidRepositoryPath(PathBuf),

    /// A remote repository URL is malformed or outside the allowed GitHub shape.
    #[error("invalid GitHub repository URL: {0}")]
    InvalidGitHubUrl(String),

    /// GitHub returned a revision that was not a complete commit identifier.
    #[error("GitHub returned an invalid commit revision: {0}")]
    InvalidRemoteRevision(String),

    /// Remote acquisition exceeded a safety limit.
    #[error("repository archive exceeds the {limit_bytes}-byte download limit")]
    ArchiveTooLarge {
        /// Configured maximum archive size.
        limit_bytes: usize,
    },

    /// Extraction found an unsafe archive path or entry type.
    #[error("unsafe repository archive entry: {0}")]
    UnsafeArchiveEntry(String),

    /// Repository inspection exceeded a configured bound.
    #[error("repository inspection limit exceeded: {0}")]
    InspectionLimit(String),

    /// An HTTP request failed.
    #[error("GitHub request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// A filesystem operation failed.
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON document could not be parsed.
    #[error("JSON parsing failed: {0}")]
    Json(#[from] serde_json::Error),

    /// A scanner executable could not be started.
    #[error("{scanner} is unavailable at {executable}: {source}")]
    ScannerUnavailable {
        /// Stable scanner name.
        scanner: &'static str,
        /// Configured executable.
        executable: PathBuf,
        /// Process launch failure.
        source: std::io::Error,
    },

    /// A scanner exceeded its execution deadline.
    #[error("{scanner} exceeded its {timeout_seconds}-second timeout")]
    ScannerTimeout {
        /// Stable scanner name.
        scanner: &'static str,
        /// Configured deadline.
        timeout_seconds: u64,
    },

    /// A scanner produced more output than `LaunchGuard` accepts.
    #[error("{scanner} {stream} exceeded the {limit_bytes}-byte limit")]
    ScannerOutputTooLarge {
        /// Stable scanner name.
        scanner: &'static str,
        /// Standard stream being collected.
        stream: &'static str,
        /// Configured maximum.
        limit_bytes: usize,
    },

    /// A scanner returned a failure exit status.
    #[error("{scanner} failed with status {status}: {message}")]
    ScannerFailed {
        /// Stable scanner name.
        scanner: &'static str,
        /// Numeric status, or `terminated` when unavailable.
        status: String,
        /// Bounded, lossy diagnostic output.
        message: String,
    },

    /// A scanner JSON contract is unsupported or malformed.
    #[error("unsupported or malformed {scanner} report: {message}")]
    ScannerReport {
        /// Stable scanner name.
        scanner: &'static str,
        /// Contract failure without report contents.
        message: String,
    },

    /// A background scanner-output task could not be joined.
    #[error("scanner output task failed: {0}")]
    ScannerTask(#[from] tokio::task::JoinError),

    /// A `SQLite` operation failed.
    #[error("history database operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A stored record uses an unsupported schema.
    #[error("unsupported ProjectProfile schema version: {0}")]
    UnknownSchemaVersion(String),

    /// A requested run does not exist.
    #[error("run not found: {0}")]
    RunNotFound(String),

    /// A reviewed execution plan cannot be generated from this profile.
    #[error("execution plan unavailable: {0}")]
    PlanUnavailable(String),

    /// A content-addressed record does not match its embedded digest.
    #[error("content digest mismatch for {record}")]
    DigestMismatch {
        /// Record type that failed validation.
        record: &'static str,
    },

    /// This build pins no release of a tool for the running platform.
    #[error("{tool} cannot be provisioned for {os}/{architecture} by this release")]
    ProvisioningUnsupported {
        /// Tool that cannot be provisioned.
        tool: &'static str,
        /// Host operating system.
        os: &'static str,
        /// Host architecture.
        architecture: &'static str,
    },

    /// A downloaded artifact did not match its pinned digest.
    ///
    /// This fails closed with nothing retained. There is no unverified fallback.
    #[error("{tool} download failed verification: expected {expected}, got {actual}")]
    ProvisioningDigestMismatch {
        /// Tool being provisioned.
        tool: &'static str,
        /// Digest compiled into this release.
        expected: String,
        /// Digest actually computed over the download.
        actual: String,
    },

    /// A verified artifact did not contain the expected executable.
    #[error("unusable {tool} release artifact: {message}")]
    ProvisioningArtifact {
        /// Tool being provisioned.
        tool: &'static str,
        /// Contract failure without artifact contents.
        message: String,
    },

    /// Deployment intent cannot be captured for this profile or provider.
    #[error("deployment intent unavailable: {0}")]
    DeploymentIntentUnavailable(String),

    /// A generated deployment artifact failed local validation.
    #[error("invalid generated artifact {path}: {message}")]
    GeneratedArtifact {
        /// Repository-relative artifact path, when known.
        path: String,
        /// Validation failure without artifact contents.
        message: String,
    },
}

/// Result type used by the `LaunchGuard` engine.
pub type Result<T> = std::result::Result<T, LaunchGuardError>;
