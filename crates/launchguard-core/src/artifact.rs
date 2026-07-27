//! Content-addressed storage for sensitive raw scanner reports.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{Result, ScannerKind};

/// Raw artifact metadata contract emitted by this release.
pub const RAW_ARTIFACT_SCHEMA_VERSION: &str = "1.0";

/// Metadata for a raw report stored outside history records and normalized findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawArtifact {
    /// Public record schema.
    pub schema_version: String,
    /// Lowercase SHA-256 of the exact report bytes.
    pub digest: String,
    /// Scanner that emitted the report.
    pub scanner: ScannerKind,
    /// Report media type.
    pub media_type: String,
    /// Exact report size.
    pub size_bytes: u64,
    /// Path relative to the artifact-store root.
    pub relative_path: String,
}

/// Local, content-addressed report store.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    /// Configure storage rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Persist exact raw report bytes with an atomic rename.
    ///
    /// Raw scanner output can contain matched secret text. The resulting file and
    /// store directories are restricted to the current user on Unix.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when secure local persistence fails.
    pub fn put_report(&self, scanner: ScannerKind, bytes: &[u8]) -> Result<RawArtifact> {
        let digest = format!("{:x}", Sha256::digest(bytes));
        let relative_path = PathBuf::from("sha256").join(format!("{digest}.json"));
        let directory = self.root.join("sha256");
        let destination = self.root.join(&relative_path);
        create_private_directory(&directory)?;

        if !destination.exists() {
            let mut temporary = NamedTempFile::new_in(&directory)?;
            set_private_file_permissions(temporary.path())?;
            temporary.write_all(bytes)?;
            temporary.as_file_mut().sync_all()?;
            match temporary.persist_noclobber(&destination) {
                Ok(_) => {}
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.error.into()),
            }
        }

        Ok(RawArtifact {
            schema_version: RAW_ARTIFACT_SCHEMA_VERSION.to_owned(),
            digest,
            scanner,
            media_type: "application/json".to_owned(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            relative_path: path_for_record(&relative_path),
        })
    }

    /// Resolve artifact metadata to a local path.
    #[must_use]
    pub fn resolve(&self, artifact: &RawArtifact) -> PathBuf {
        self.root.join(&artifact.relative_path)
    }
}

fn path_for_record(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    set_private_directory_permissions(path)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
