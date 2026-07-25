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

    /// A `SQLite` operation failed.
    #[error("history database operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A stored record uses an unsupported schema.
    #[error("unsupported ProjectProfile schema version: {0}")]
    UnknownSchemaVersion(String),

    /// A requested run does not exist.
    #[error("run not found: {0}")]
    RunNotFound(String),
}

/// Result type used by the `LaunchGuard` engine.
pub type Result<T> = std::result::Result<T, LaunchGuardError>;
