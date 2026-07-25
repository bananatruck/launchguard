//! Safe local and public GitHub repository acquisition.

use std::{
    fs::{self, File},
    io::{Cursor, Read},
    path::{Component, Path, PathBuf},
};

use flate2::read::GzDecoder;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::Deserialize;
use tempfile::TempDir;
use tracing::{debug, info};
use url::Url;

use crate::{LaunchGuardError, Result};

const MAX_ARCHIVE_BYTES: usize = 100 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 250 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 20_000;
const GITHUB_USER_AGENT: &str = "launchguard/0.1";

/// A repository made available for read-only inspection.
pub struct AcquiredRepository {
    root: PathBuf,
    source: String,
    revision: String,
    _temporary_directory: Option<TempDir>,
}

impl AcquiredRepository {
    /// Filesystem root to inspect.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Normalized path or URL identifying the source.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Git revision, or `unversioned` when local metadata is unavailable.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

/// Acquires local directories or public GitHub repository snapshots.
#[derive(Clone)]
pub struct RepositoryAcquirer {
    client: reqwest::Client,
}

impl RepositoryAcquirer {
    /// Construct an acquirer with bounded HTTP behavior.
    ///
    /// # Errors
    ///
    /// Returns an HTTP client configuration error when the platform TLS or
    /// resolver configuration cannot initialize.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(std::time::Duration::from_mins(1))
            .build()?;
        Ok(Self { client })
    }

    /// Acquire a source without invoking Git hooks, package managers, or project code.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid local paths, unsupported URLs, failed
    /// GitHub requests, unsafe archives, or exceeded acquisition limits.
    pub async fn acquire(&self, source: &str) -> Result<AcquiredRepository> {
        let local_path = Path::new(source);
        if local_path.exists() {
            return acquire_local(local_path);
        }

        let github = GitHubRepository::parse(source)?;
        self.acquire_github(&github).await
    }

    async fn acquire_github(&self, repository: &GitHubRepository) -> Result<AcquiredRepository> {
        info!(repository = %repository.slug(), "acquiring public GitHub snapshot");

        let metadata_url = format!("https://api.github.com/repos/{}", repository.slug());
        let metadata: RepositoryMetadata = self
            .client
            .get(metadata_url)
            .header(USER_AGENT, GITHUB_USER_AGENT)
            .header(ACCEPT, "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let commit_url = format!(
            "https://api.github.com/repos/{}/commits/{}",
            repository.slug(),
            metadata.default_branch
        );
        let commit: CommitMetadata = self
            .client
            .get(commit_url)
            .header(USER_AGENT, GITHUB_USER_AGENT)
            .header(ACCEPT, "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let archive_url = format!(
            "https://api.github.com/repos/{}/tarball/{}",
            repository.slug(),
            commit.sha
        );
        let response = self
            .client
            .get(archive_url)
            .header(USER_AGENT, GITHUB_USER_AGENT)
            .header(ACCEPT, "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?;

        if response
            .content_length()
            .is_some_and(|length| length > MAX_ARCHIVE_BYTES as u64)
        {
            return Err(LaunchGuardError::ArchiveTooLarge {
                limit_bytes: MAX_ARCHIVE_BYTES,
            });
        }

        let bytes = response.bytes().await?;
        if bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(LaunchGuardError::ArchiveTooLarge {
                limit_bytes: MAX_ARCHIVE_BYTES,
            });
        }

        let temporary_directory = tempfile::Builder::new()
            .prefix("launchguard-source-")
            .tempdir()?;
        extract_snapshot(&bytes, temporary_directory.path())?;

        Ok(AcquiredRepository {
            root: temporary_directory.path().to_path_buf(),
            source: repository.normalized_url(),
            revision: commit.sha,
            _temporary_directory: Some(temporary_directory),
        })
    }
}

impl Default for RepositoryAcquirer {
    fn default() -> Self {
        Self::new().expect("the built-in HTTP client configuration must be valid")
    }
}

fn acquire_local(path: &Path) -> Result<AcquiredRepository> {
    let root = path
        .canonicalize()
        .map_err(|_| LaunchGuardError::InvalidRepositoryPath(path.to_path_buf()))?;
    if !root.is_dir() {
        return Err(LaunchGuardError::InvalidRepositoryPath(root));
    }

    debug!(path = %root.display(), "using local repository without staging");
    let revision = read_local_revision(&root).unwrap_or_else(|| "unversioned".to_owned());
    Ok(AcquiredRepository {
        source: root.display().to_string(),
        root,
        revision,
        _temporary_directory: None,
    })
}

fn read_local_revision(root: &Path) -> Option<String> {
    let git_directory = root.join(".git");
    if !git_directory.is_dir() {
        return None;
    }

    let head = read_small_text(&git_directory.join("HEAD"))?;
    let head = head.trim();
    if is_commit_id(head) {
        return Some(head.to_owned());
    }

    let reference = head.strip_prefix("ref: ")?.trim();
    if reference.contains("..") || reference.starts_with('/') {
        return None;
    }

    let loose = read_small_text(&git_directory.join(reference));
    if let Some(commit) = loose
        .as_deref()
        .map(str::trim)
        .filter(|id| is_commit_id(id))
    {
        return Some(commit.to_owned());
    }

    let packed = read_small_text(&git_directory.join("packed-refs"))?;
    packed.lines().find_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        let commit = fields.next()?;
        let packed_reference = fields.next()?;
        (packed_reference == reference && is_commit_id(commit)).then(|| commit.to_owned())
    })
}

fn read_small_text(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    if file.metadata().ok()?.len() > 1024 * 1024 {
        return None;
    }
    let mut value = String::new();
    file.read_to_string(&mut value).ok()?;
    Some(value)
}

fn is_commit_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn extract_snapshot(archive_bytes: &[u8], destination: &Path) -> Result<()> {
    let decoder = GzDecoder::new(Cursor::new(archive_bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut entries_seen = 0_usize;
    let mut bytes_seen = 0_u64;

    for entry_result in archive.entries()? {
        entries_seen += 1;
        if entries_seen > MAX_ARCHIVE_ENTRIES {
            return Err(LaunchGuardError::InspectionLimit(format!(
                "archive contains more than {MAX_ARCHIVE_ENTRIES} entries"
            )));
        }

        let mut entry = entry_result?;
        let entry_path = entry.path()?.into_owned();
        let relative_path = strip_archive_root(&entry_path)?;
        if relative_path.as_os_str().is_empty() {
            continue;
        }

        let entry_type = entry.header().entry_type();
        let output_path = destination.join(&relative_path);
        if entry_type.is_dir() {
            fs::create_dir_all(&output_path)?;
            continue;
        }
        if !entry_type.is_file() {
            debug!(path = %relative_path.display(), "skipping non-file archive entry");
            continue;
        }

        let entry_size = entry.size();
        bytes_seen = bytes_seen.saturating_add(entry_size);
        if bytes_seen > MAX_EXTRACTED_BYTES {
            return Err(LaunchGuardError::InspectionLimit(format!(
                "extracted repository exceeds {MAX_EXTRACTED_BYTES} bytes"
            )));
        }

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = File::create(output_path)?;
        std::io::copy(&mut entry, &mut output)?;
    }

    Ok(())
}

fn strip_archive_root(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let Some(Component::Normal(_root)) = components.next() else {
        return Err(LaunchGuardError::UnsafeArchiveEntry(
            path.display().to_string(),
        ));
    };

    let mut relative = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(part) => relative.push(part),
            _ => {
                return Err(LaunchGuardError::UnsafeArchiveEntry(
                    path.display().to_string(),
                ));
            }
        }
    }
    Ok(relative)
}

#[derive(Debug)]
struct GitHubRepository {
    owner: String,
    name: String,
}

impl GitHubRepository {
    fn parse(value: &str) -> Result<Self> {
        let url =
            Url::parse(value).map_err(|_| LaunchGuardError::UnsupportedSource(value.to_owned()))?;
        if url.scheme() != "https" || url.host_str() != Some("github.com") {
            return Err(LaunchGuardError::UnsupportedSource(value.to_owned()));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(LaunchGuardError::InvalidGitHubUrl(value.to_owned()));
        }

        let segments = url
            .path_segments()
            .ok_or_else(|| LaunchGuardError::InvalidGitHubUrl(value.to_owned()))?
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        if segments.len() != 2 {
            return Err(LaunchGuardError::InvalidGitHubUrl(value.to_owned()));
        }

        let owner = segments[0];
        let name = segments[1].strip_suffix(".git").unwrap_or(segments[1]);
        if !valid_github_segment(owner) || !valid_github_segment(name) {
            return Err(LaunchGuardError::InvalidGitHubUrl(value.to_owned()));
        }

        Ok(Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }

    fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    fn normalized_url(&self) -> String {
        format!("https://github.com/{}/{}", self.owner, self.name)
    }
}

fn valid_github_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug, Deserialize)]
struct RepositoryMetadata {
    default_branch: String,
}

#[derive(Debug, Deserialize)]
struct CommitMetadata {
    sha: String,
}

#[cfg(test)]
mod tests {
    use super::{GitHubRepository, is_commit_id, strip_archive_root};
    use std::path::{Path, PathBuf};

    #[test]
    fn github_url_is_normalized() {
        let repository =
            GitHubRepository::parse("https://github.com/example/project.git").expect("valid URL");
        assert_eq!(
            repository.normalized_url(),
            "https://github.com/example/project"
        );
    }

    #[test]
    fn github_subpaths_are_rejected() {
        assert!(GitHubRepository::parse("https://github.com/example/project/tree/main").is_err());
    }

    #[test]
    fn archive_paths_cannot_escape() {
        assert!(strip_archive_root(Path::new("root/../../secret")).is_err());
        assert_eq!(
            strip_archive_root(Path::new("root/src/main.rs")).expect("safe path"),
            PathBuf::from("src/main.rs")
        );
    }

    #[test]
    fn commit_ids_are_strict_hex() {
        assert!(is_commit_id(&"a".repeat(40)));
        assert!(!is_commit_id(&"z".repeat(40)));
        assert!(!is_commit_id("deadbeef"));
    }
}
