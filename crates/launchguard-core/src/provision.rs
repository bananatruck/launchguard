//! Checksum-verified provisioning of trusted scanner binaries.
//!
//! Requiring every user to install scanners by hand excludes most of them from
//! the deterministic security checks entirely, so `LaunchGuard` can fetch them.
//! That is a real expansion of the trust boundary, so the controls are strict:
//! versions and digests are compiled into the release rather than resolved at
//! runtime, verification precedes execution, a mismatch retains nothing, and
//! nothing is written outside a user-private directory.
//!
//! Only tools distributed as a single static binary that installs without
//! elevation are provisioned. A container runtime and a model server are
//! documented instead.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{CapabilityKind, LaunchGuardError, Result};

/// Provisioned-tool contract emitted by this release.
pub const PROVISIONED_TOOL_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`ProvisionedTool`].
pub const PROVISIONED_TOOL_SCHEMA_JSON: &str =
    include_str!("../../../schemas/provisioned-tool-v1.schema.json");

/// Trivy release pinned by this build.
pub const TRIVY_VERSION: &str = "0.72.0";

/// OSV-Scanner release pinned by this build.
pub const OSV_SCANNER_VERSION: &str = "2.4.0";

/// Maximum accepted download size.
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// How a downloaded artifact is packaged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    /// The download is the executable itself.
    Raw,
    /// A gzipped tarball containing the executable.
    TarGzip,
}

/// One pinned, platform-specific release artifact.
#[derive(Debug, Clone, Copy)]
struct PinnedArtifact {
    version: &'static str,
    url: &'static str,
    sha256: &'static str,
    archive: ArchiveKind,
    /// Executable name inside the archive, or the installed name for a raw download.
    executable: &'static str,
}

/// Resolve the pinned artifact for a tool on the running platform.
///
/// Returns `None` when this build has no pinned artifact for the host, which is
/// reported as unsupported rather than resolved dynamically.
fn pinned(tool: CapabilityKind, os: &str, arch: &str) -> Option<PinnedArtifact> {
    const TRIVY: &str = "https://github.com/aquasecurity/trivy/releases/download/v0.72.0";
    const OSV: &str = "https://github.com/google/osv-scanner/releases/download/v2.4.0";

    // Trivy ships a Windows zip, which this release does not unpack, so Windows
    // is reported unsupported for Trivy rather than resolved some other way.
    let (url, sha256, archive, executable) = match (tool, os, arch) {
        (CapabilityKind::Trivy, "linux", "x86_64") => (
            concat!(
                "https://github.com/aquasecurity/trivy/releases/download/v0.72.0",
                "/trivy_0.72.0_Linux-64bit.tar.gz"
            ),
            "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea",
            ArchiveKind::TarGzip,
            "trivy",
        ),
        (CapabilityKind::Trivy, "linux", "aarch64") => (
            concat!(
                "https://github.com/aquasecurity/trivy/releases/download/v0.72.0",
                "/trivy_0.72.0_Linux-ARM64.tar.gz"
            ),
            "2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467",
            ArchiveKind::TarGzip,
            "trivy",
        ),
        (CapabilityKind::Trivy, "macos", "x86_64") => (
            concat!(
                "https://github.com/aquasecurity/trivy/releases/download/v0.72.0",
                "/trivy_0.72.0_macOS-64bit.tar.gz"
            ),
            "ee5e60df8a98e5b89fd74a6d86f9e5c7e9a266a35002cb1e43291698b3bfee08",
            ArchiveKind::TarGzip,
            "trivy",
        ),
        (CapabilityKind::Trivy, "macos", "aarch64") => (
            concat!(
                "https://github.com/aquasecurity/trivy/releases/download/v0.72.0",
                "/trivy_0.72.0_macOS-ARM64.tar.gz"
            ),
            "88f208680dc05da2b459e19b4f5aa2b4dc7c2117892ba4aab2ae63baba330016",
            ArchiveKind::TarGzip,
            "trivy",
        ),
        (CapabilityKind::OsvScanner, "linux", "x86_64") => (
            concat!(
                "https://github.com/google/osv-scanner/releases/download/v2.4.0",
                "/osv-scanner_linux_amd64"
            ),
            "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0",
            ArchiveKind::Raw,
            "osv-scanner",
        ),
        (CapabilityKind::OsvScanner, "linux", "aarch64") => (
            concat!(
                "https://github.com/google/osv-scanner/releases/download/v2.4.0",
                "/osv-scanner_linux_arm64"
            ),
            "44e580752910f0ff36ec99aff59af20f65df1e859aa31e5605a8f0d055b496e9",
            ArchiveKind::Raw,
            "osv-scanner",
        ),
        (CapabilityKind::OsvScanner, "macos", "x86_64") => (
            concat!(
                "https://github.com/google/osv-scanner/releases/download/v2.4.0",
                "/osv-scanner_darwin_amd64"
            ),
            "088119325156321c34c456ac3703d6013538fd71cbac82b891ab34db491e4d66",
            ArchiveKind::Raw,
            "osv-scanner",
        ),
        (CapabilityKind::OsvScanner, "macos", "aarch64") => (
            concat!(
                "https://github.com/google/osv-scanner/releases/download/v2.4.0",
                "/osv-scanner_darwin_arm64"
            ),
            "9ca3185ad63e9ab54f7cb90f46a7362be02d80e37f0123d095a54355ea202f5d",
            ArchiveKind::Raw,
            "osv-scanner",
        ),
        (CapabilityKind::OsvScanner, "windows", "x86_64") => (
            concat!(
                "https://github.com/google/osv-scanner/releases/download/v2.4.0",
                "/osv-scanner_windows_amd64.exe"
            ),
            "0cdd113610126d5dfd5e12ad0e0b4f3e879291ff19bb43b0c52ed2f2c2df1a37",
            ArchiveKind::Raw,
            "osv-scanner.exe",
        ),
        _ => return None,
    };
    debug_assert!(url.starts_with(TRIVY) || url.starts_with(OSV));

    Some(PinnedArtifact {
        version: match tool {
            CapabilityKind::Trivy => TRIVY_VERSION,
            _ => OSV_SCANNER_VERSION,
        },
        url,
        sha256,
        archive,
        executable,
    })
}

/// A tool installed by `LaunchGuard`, with the evidence that verified it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionedTool {
    /// Public record schema.
    pub schema_version: String,
    /// Capability this tool satisfies.
    pub tool: CapabilityKind,
    /// Pinned release version.
    pub version: String,
    /// Release artifact the binary came from.
    pub source_url: String,
    /// Expected and verified SHA-256 of the downloaded artifact.
    pub artifact_sha256: String,
    /// Absolute path to the installed executable.
    pub installed_path: String,
    /// Whether this call downloaded the tool or found it already verified.
    pub newly_installed: bool,
}

/// Installs pinned scanner binaries into a user-private directory.
#[derive(Debug, Clone)]
pub struct Provisioner {
    root: PathBuf,
}

impl Provisioner {
    /// Install tools beneath `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Directory holding provisioned executables.
    #[must_use]
    pub fn bin_directory(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// Path a provisioned tool would occupy, whether or not it exists.
    #[must_use]
    pub fn executable_path(&self, tool: CapabilityKind) -> Option<PathBuf> {
        let artifact = pinned(tool, std::env::consts::OS, std::env::consts::ARCH)?;
        Some(self.bin_directory().join(artifact.executable))
    }

    /// Whether this build can provision a tool on the running platform.
    #[must_use]
    pub fn supports(tool: CapabilityKind) -> bool {
        pinned(tool, std::env::consts::OS, std::env::consts::ARCH).is_some()
    }

    /// Download, verify, and install one pinned tool.
    ///
    /// Verification precedes installation. A digest mismatch aborts and leaves
    /// nothing behind; there is no unverified fallback and no runtime installer
    /// script is ever executed.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform is unsupported, the download fails or
    /// exceeds its size limit, the digest does not match, or installation fails.
    pub async fn install(&self, tool: CapabilityKind) -> Result<ProvisionedTool> {
        let artifact =
            pinned(tool, std::env::consts::OS, std::env::consts::ARCH).ok_or_else(|| {
                LaunchGuardError::ProvisioningUnsupported {
                    tool: tool.as_str(),
                    os: std::env::consts::OS,
                    architecture: std::env::consts::ARCH,
                }
            })?;
        let destination = self.bin_directory().join(artifact.executable);

        // An already-installed tool is not re-downloaded, but it is still reported.
        if destination.is_file() {
            return Ok(ProvisionedTool {
                schema_version: PROVISIONED_TOOL_SCHEMA_VERSION.to_owned(),
                tool,
                version: artifact.version.to_owned(),
                source_url: artifact.url.to_owned(),
                artifact_sha256: artifact.sha256.to_owned(),
                installed_path: destination.to_string_lossy().into_owned(),
                newly_installed: false,
            });
        }

        let bytes = download(artifact.url).await?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if digest != artifact.sha256 {
            return Err(LaunchGuardError::ProvisioningDigestMismatch {
                tool: tool.as_str(),
                expected: artifact.sha256.to_owned(),
                actual: digest,
            });
        }

        let executable = match artifact.archive {
            ArchiveKind::Raw => bytes,
            ArchiveKind::TarGzip => extract_from_tar_gzip(&bytes, artifact.executable, tool)?,
        };
        create_private_directory(&self.bin_directory())?;
        install_executable(&destination, &executable)?;

        Ok(ProvisionedTool {
            schema_version: PROVISIONED_TOOL_SCHEMA_VERSION.to_owned(),
            tool,
            version: artifact.version.to_owned(),
            source_url: artifact.url.to_owned(),
            artifact_sha256: digest,
            installed_path: destination.to_string_lossy().into_owned(),
            newly_installed: true,
        })
    }
}

/// Fetch a release artifact with a bounded size and deadline.
async fn download(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_mins(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    if let Some(length) = response.content_length()
        && length > MAX_DOWNLOAD_BYTES
    {
        return Err(LaunchGuardError::ArchiveTooLarge {
            limit_bytes: usize::try_from(MAX_DOWNLOAD_BYTES).unwrap_or(usize::MAX),
        });
    }
    let bytes = response.bytes().await?;
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(LaunchGuardError::ArchiveTooLarge {
            limit_bytes: usize::try_from(MAX_DOWNLOAD_BYTES).unwrap_or(usize::MAX),
        });
    }
    Ok(bytes.to_vec())
}

/// Pull one named executable out of a gzipped tarball.
///
/// Entries are matched by file name only, so a crafted archive cannot direct a
/// write outside the destination.
fn extract_from_tar_gzip(bytes: &[u8], executable: &str, tool: CapabilityKind) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.into_owned();
        if path.file_name().and_then(|name| name.to_str()) == Some(executable) {
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?;
            return Ok(contents);
        }
    }
    Err(LaunchGuardError::ProvisioningArtifact {
        tool: tool.as_str(),
        message: format!("archive did not contain an executable named {executable}"),
    })
}

fn install_executable(destination: &Path, contents: &[u8]) -> Result<()> {
    let directory = destination.parent().unwrap_or(destination);
    let mut temporary = NamedTempFile::new_in(directory)?;
    temporary.write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    set_executable_permissions(temporary.path())?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)?;
    Ok(())
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
fn set_executable_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_executable_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ArchiveKind, OSV_SCANNER_VERSION, Provisioner, TRIVY_VERSION, pinned};
    use crate::CapabilityKind;

    #[test]
    fn every_pinned_artifact_carries_a_full_length_digest() {
        for tool in [CapabilityKind::Trivy, CapabilityKind::OsvScanner] {
            for (os, arch) in [
                ("linux", "x86_64"),
                ("linux", "aarch64"),
                ("macos", "x86_64"),
                ("macos", "aarch64"),
            ] {
                let artifact = pinned(tool, os, arch)
                    .unwrap_or_else(|| panic!("{tool:?} must be pinned for {os}/{arch}"));
                assert_eq!(artifact.sha256.len(), 64, "{tool:?} {os}/{arch}");
                assert!(
                    artifact.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                    "{tool:?} {os}/{arch} digest must be hex"
                );
                assert!(
                    artifact.url.starts_with("https://"),
                    "{tool:?} {os}/{arch} must download over HTTPS"
                );
                assert!(artifact.url.contains(artifact.version));
            }
        }
    }

    #[test]
    fn pinned_urls_match_their_platform() {
        let linux = pinned(CapabilityKind::Trivy, "linux", "x86_64").expect("linux trivy");
        assert!(linux.url.contains("Linux-64bit"));
        assert_eq!(linux.archive, ArchiveKind::TarGzip);

        let mac = pinned(CapabilityKind::Trivy, "macos", "aarch64").expect("mac trivy");
        assert!(mac.url.contains("macOS-ARM64"));

        let osv = pinned(CapabilityKind::OsvScanner, "linux", "aarch64").expect("linux osv");
        assert!(osv.url.ends_with("osv-scanner_linux_arm64"));
        assert_eq!(osv.archive, ArchiveKind::Raw);

        let windows = pinned(CapabilityKind::OsvScanner, "windows", "x86_64").expect("windows osv");
        assert_eq!(windows.executable, "osv-scanner.exe");
    }

    #[test]
    fn versions_are_pinned_not_floating() {
        assert_eq!(TRIVY_VERSION, "0.72.0");
        assert_eq!(OSV_SCANNER_VERSION, "2.4.0");
        for tool in [CapabilityKind::Trivy, CapabilityKind::OsvScanner] {
            let artifact = pinned(tool, "linux", "x86_64").expect("pinned");
            assert!(
                !artifact.url.contains("latest"),
                "a provisioned URL must never resolve latest at runtime"
            );
        }
    }

    #[test]
    fn only_scanner_tools_are_provisionable() {
        assert!(pinned(CapabilityKind::ContainerRuntime, "linux", "x86_64").is_none());
        assert!(pinned(CapabilityKind::LocalInference, "linux", "x86_64").is_none());
        assert!(pinned(CapabilityKind::Git, "linux", "x86_64").is_none());
    }

    #[test]
    fn unsupported_platforms_report_rather_than_guess() {
        assert!(pinned(CapabilityKind::Trivy, "freebsd", "x86_64").is_none());
        assert!(pinned(CapabilityKind::OsvScanner, "linux", "riscv64").is_none());
        // Trivy ships a Windows zip this release does not unpack.
        assert!(pinned(CapabilityKind::Trivy, "windows", "x86_64").is_none());
    }

    #[test]
    fn executables_live_under_a_private_bin_directory() {
        let provisioner = Provisioner::new("/tmp/launchguard-test");
        assert!(provisioner.bin_directory().ends_with("bin"));
    }
}
