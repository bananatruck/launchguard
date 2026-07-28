//! Host capability discovery.
//!
//! Capability is measured, never inferred from the operating system. Probing
//! never blocks, installs, elevates, or mutates the host, and it passes no
//! repository-controlled input to any tool. Each probe runs only that tool's
//! own version subcommand, the same restriction applied to scanner provenance.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::Result;

/// Capability-report contract emitted by this release.
pub const CAPABILITY_REPORT_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`CapabilityReport`].
pub const CAPABILITY_REPORT_SCHEMA_JSON: &str =
    include_str!("../../../schemas/capability-report-v1.schema.json");

/// Wall-clock ceiling for a single probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Output ceiling for a version banner.
const PROBE_MAX_BYTES: usize = 64 * 1024;

/// Maximum retained diagnostic text.
const MAX_DETAIL_BYTES: usize = 256;

/// A host capability `LaunchGuard` can measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// Git, used for revision pinning and temporary worktrees.
    Git,
    /// An OCI runtime, used for sandboxed preview.
    ContainerRuntime,
    /// Aqua Trivy.
    Trivy,
    /// Google OSV-Scanner.
    OsvScanner,
    /// A local inference endpoint.
    LocalInference,
}

impl CapabilityKind {
    /// Stable identifier used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::ContainerRuntime => "container_runtime",
            Self::Trivy => "trivy",
            Self::OsvScanner => "osv_scanner",
            Self::LocalInference => "local_inference",
        }
    }

    /// What the capability enables, for user-facing guidance.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::Git => "revision pinning and temporary worktrees",
            Self::ContainerRuntime => "sandboxed build, test, and health checks",
            Self::Trivy => "vulnerability, secret, and configuration findings",
            Self::OsvScanner => "ecosystem vulnerability findings",
            Self::LocalInference => "failure explanation and bounded repair",
        }
    }

    /// Whether `setup` can provision this capability without elevation.
    #[must_use]
    pub const fn is_auto_provisionable(self) -> bool {
        matches!(self, Self::Trivy | Self::OsvScanner)
    }
}

/// Whether a capability was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// The capability responded and reported a version.
    Present,
    /// The capability is not usable on this host.
    Absent,
}

/// One measured capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Capability measured.
    pub kind: CapabilityKind,
    /// Measurement outcome.
    pub status: CapabilityStatus,
    /// Concrete implementation satisfying the capability, such as `podman`.
    pub implementation: Option<String>,
    /// Version reported by the tool, when it reported one.
    pub version: Option<String>,
    /// Bounded explanation. Never presented as a security conclusion.
    pub detail: String,
}

/// A delivery track the host can currently run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryTrack {
    /// Detect, scan, plan, generate configuration, and publish.
    Deploy,
    /// Everything in `Deploy`, plus locally verified build, test, and health.
    Verify,
}

impl DeliveryTrack {
    /// Stable identifier used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Verify => "verify",
        }
    }
}

/// Host operating system and architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    /// Operating system identifier.
    pub os: String,
    /// CPU architecture identifier.
    pub architecture: String,
}

impl Platform {
    /// Describe the host this binary is running on.
    #[must_use]
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
        }
    }
}

/// Measured host capability and the tracks it permits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// Public record schema.
    pub schema_version: String,
    /// Host description.
    pub platform: Platform,
    /// Every probed capability, ordered deterministically.
    pub capabilities: Vec<Capability>,
    /// Tracks this host can currently run.
    pub available_tracks: Vec<DeliveryTrack>,
    /// Capability blocking the first unavailable track, when one is blocked.
    pub blocking_capability: Option<CapabilityKind>,
    /// Measurement time.
    pub detected_at: DateTime<Utc>,
}

impl CapabilityReport {
    /// Look up one measured capability.
    #[must_use]
    pub fn get(&self, kind: CapabilityKind) -> Option<&Capability> {
        self.capabilities
            .iter()
            .find(|capability| capability.kind == kind)
    }

    /// Whether a capability was found on this host.
    #[must_use]
    pub fn has(&self, kind: CapabilityKind) -> bool {
        self.get(kind)
            .is_some_and(|capability| capability.status == CapabilityStatus::Present)
    }

    /// Capabilities that `setup` could provision without elevation.
    #[must_use]
    pub fn provisionable_gaps(&self) -> Vec<CapabilityKind> {
        self.capabilities
            .iter()
            .filter(|capability| {
                capability.status == CapabilityStatus::Absent
                    && capability.kind.is_auto_provisionable()
            })
            .map(|capability| capability.kind)
            .collect()
    }

    /// Whether the host can run a track.
    #[must_use]
    pub fn supports(&self, track: DeliveryTrack) -> bool {
        self.available_tracks.contains(&track)
    }
}

/// Configured probe targets.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Git executable.
    pub git_executable: PathBuf,
    /// Preferred OCI runtime. Rootless operation is the default rather than an option.
    pub podman_executable: PathBuf,
    /// Fallback OCI runtime.
    pub docker_executable: PathBuf,
    /// Trivy executable.
    pub trivy_executable: PathBuf,
    /// OSV-Scanner executable.
    pub osv_executable: PathBuf,
    /// Loopback inference endpoint.
    pub inference_endpoint: String,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            git_executable: PathBuf::from("git"),
            podman_executable: PathBuf::from("podman"),
            docker_executable: PathBuf::from("docker"),
            trivy_executable: PathBuf::from("trivy"),
            osv_executable: PathBuf::from("osv-scanner"),
            inference_endpoint: "http://127.0.0.1:11434".to_owned(),
        }
    }
}

/// Measures host capability without mutating anything.
#[derive(Debug, Clone, Default)]
pub struct CapabilityProbe {
    config: ProbeConfig,
}

impl CapabilityProbe {
    /// Construct a probe with explicit targets.
    #[must_use]
    pub const fn new(config: ProbeConfig) -> Self {
        Self { config }
    }

    /// Measure every capability.
    ///
    /// A probe never fails: an unusable capability is reported as absent with
    /// the reason, because absence is an expected outcome rather than an error.
    ///
    /// # Errors
    ///
    /// Returns an error only if the system clock cannot be read.
    pub async fn detect(&self) -> Result<CapabilityReport> {
        let mut capabilities = vec![
            probe_tool(
                CapabilityKind::Git,
                &self.config.git_executable,
                &["--version"],
            )
            .await,
            self.probe_container_runtime().await,
            probe_tool(
                CapabilityKind::Trivy,
                &self.config.trivy_executable,
                &["--version"],
            )
            .await,
            probe_tool(
                CapabilityKind::OsvScanner,
                &self.config.osv_executable,
                &["--version"],
            )
            .await,
            self.probe_inference().await,
        ];
        capabilities.sort_by_key(|capability| capability.kind);

        let present = |kind: CapabilityKind| {
            capabilities.iter().any(|capability| {
                capability.kind == kind && capability.status == CapabilityStatus::Present
            })
        };

        // Track A needs nothing beyond this binary, so it is always available.
        let mut available_tracks = vec![DeliveryTrack::Deploy];
        let runtime = present(CapabilityKind::ContainerRuntime);
        if runtime {
            available_tracks.push(DeliveryTrack::Verify);
        }

        Ok(CapabilityReport {
            schema_version: CAPABILITY_REPORT_SCHEMA_VERSION.to_owned(),
            platform: Platform::current(),
            capabilities,
            available_tracks,
            blocking_capability: (!runtime).then_some(CapabilityKind::ContainerRuntime),
            detected_at: Utc::now(),
        })
    }

    /// Prefer Podman because rootless operation is its default, then Docker.
    async fn probe_container_runtime(&self) -> Capability {
        let podman = probe_tool(
            CapabilityKind::ContainerRuntime,
            &self.config.podman_executable,
            &["--version"],
        )
        .await;
        if podman.status == CapabilityStatus::Present {
            return podman;
        }
        let docker = probe_tool(
            CapabilityKind::ContainerRuntime,
            &self.config.docker_executable,
            &["--version"],
        )
        .await;
        if docker.status == CapabilityStatus::Present {
            return docker;
        }
        Capability {
            kind: CapabilityKind::ContainerRuntime,
            status: CapabilityStatus::Absent,
            implementation: None,
            version: None,
            detail: "neither podman nor docker responded".to_owned(),
        }
    }

    /// A local model needs a responding endpoint, not merely an installed binary.
    async fn probe_inference(&self) -> Capability {
        let endpoint = format!("{}/api/version", self.config.inference_endpoint);
        let absent = |detail: String| Capability {
            kind: CapabilityKind::LocalInference,
            status: CapabilityStatus::Absent,
            implementation: None,
            version: None,
            detail,
        };
        let Ok(client) = reqwest::Client::builder().timeout(PROBE_TIMEOUT).build() else {
            return absent("could not construct an HTTP client".to_owned());
        };
        match client.get(&endpoint).send().await {
            Ok(response) if response.status().is_success() => {
                let version = response
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|body| {
                        body.get("version")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    });
                Capability {
                    kind: CapabilityKind::LocalInference,
                    status: CapabilityStatus::Present,
                    implementation: Some("ollama".to_owned()),
                    version,
                    detail: "loopback inference endpoint responded".to_owned(),
                }
            }
            Ok(response) => absent(format!("endpoint returned status {}", response.status())),
            Err(_) => absent("no loopback inference endpoint responded".to_owned()),
        }
    }
}

/// Run one tool's own version subcommand with bounded output and time.
async fn probe_tool(kind: CapabilityKind, executable: &PathBuf, arguments: &[&str]) -> Capability {
    let absent = |detail: String| Capability {
        kind,
        status: CapabilityStatus::Absent,
        implementation: None,
        version: None,
        detail,
    };

    let mut command = Command::new(executable);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let Ok(mut child) = command.spawn() else {
        return absent(format!("{} is not on PATH", executable.display()));
    };
    let Some(mut stdout) = child.stdout.take() else {
        return absent("stdout pipe unavailable".to_owned());
    };

    let mut banner = Vec::new();
    let read = async {
        let mut chunk = [0_u8; 4096];
        loop {
            let count = stdout.read(&mut chunk).await?;
            if count == 0 || banner.len() >= PROBE_MAX_BYTES {
                return Ok::<(), std::io::Error>(());
            }
            banner.extend_from_slice(&chunk[..count]);
        }
    };
    if timeout(PROBE_TIMEOUT, read).await.is_err() {
        let _ = child.kill().await;
        return absent("probe exceeded its timeout".to_owned());
    }
    let Ok(Ok(status)) = timeout(PROBE_TIMEOUT, child.wait()).await else {
        let _ = child.kill().await;
        return absent("probe exceeded its timeout".to_owned());
    };
    if !status.success() {
        return absent(bounded(&format!(
            "{} exited with a failure status",
            executable.display()
        )));
    }

    let banner = String::from_utf8_lossy(&banner);
    Capability {
        kind,
        status: CapabilityStatus::Present,
        implementation: Some(executable.file_stem().map_or_else(
            || executable.display().to_string(),
            |stem| stem.to_string_lossy().into_owned(),
        )),
        version: parse_version(&banner),
        detail: bounded(banner.lines().next().unwrap_or_default()),
    }
}

/// Extract the first dotted numeric token from a version banner.
fn parse_version(banner: &str) -> Option<String> {
    banner.split_whitespace().find_map(|token| {
        let candidate = token.trim_start_matches('v').trim_end_matches(',');
        let mut parts = candidate.split('.');
        let looks_numeric = parts.clone().count() >= 2
            && parts.all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .next()
                        .is_some_and(|character| character.is_ascii_digit())
            });
        looks_numeric.then(|| candidate.to_owned())
    })
}

fn bounded(detail: &str) -> String {
    let collapsed = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() <= MAX_DETAIL_BYTES {
        return collapsed;
    }
    let mut end = MAX_DETAIL_BYTES;
    while end > 0 && !collapsed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &collapsed[..end])
}

#[cfg(test)]
mod tests {
    use super::{
        Capability, CapabilityKind, CapabilityProbe, CapabilityReport, CapabilityStatus,
        DeliveryTrack, Platform, ProbeConfig, parse_version,
    };
    use std::path::PathBuf;

    #[test]
    fn version_banners_are_parsed_across_tools() {
        assert_eq!(
            parse_version("git version 2.51.0").as_deref(),
            Some("2.51.0")
        );
        assert_eq!(
            parse_version("podman version 5.7.1").as_deref(),
            Some("5.7.1")
        );
        assert_eq!(
            parse_version("Docker version 27.5.1, build 9f9e405").as_deref(),
            Some("27.5.1")
        );
        assert_eq!(parse_version("Version: 0.72.0").as_deref(), Some("0.72.0"));
        assert_eq!(
            parse_version("osv-scanner version: 2.4.0").as_deref(),
            Some("2.4.0")
        );
    }

    #[test]
    fn a_banner_without_a_version_yields_none() {
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version(""), None);
    }

    #[tokio::test]
    async fn an_absent_tool_is_reported_not_raised_as_an_error() {
        let config = ProbeConfig {
            git_executable: PathBuf::from("/nonexistent/git"),
            podman_executable: PathBuf::from("/nonexistent/podman"),
            docker_executable: PathBuf::from("/nonexistent/docker"),
            trivy_executable: PathBuf::from("/nonexistent/trivy"),
            osv_executable: PathBuf::from("/nonexistent/osv-scanner"),
            inference_endpoint: "http://127.0.0.1:1".to_owned(),
        };
        let report = CapabilityProbe::new(config)
            .detect()
            .await
            .expect("probing must not fail");

        assert!(
            report
                .capabilities
                .iter()
                .all(|capability| capability.status == CapabilityStatus::Absent)
        );

        // Track A never depends on host capability.
        assert!(report.supports(DeliveryTrack::Deploy));
        assert!(!report.supports(DeliveryTrack::Verify));
        assert_eq!(
            report.blocking_capability,
            Some(CapabilityKind::ContainerRuntime)
        );
        assert_eq!(
            report.provisionable_gaps(),
            vec![CapabilityKind::Trivy, CapabilityKind::OsvScanner]
        );
    }

    #[test]
    fn only_scanners_are_auto_provisionable() {
        assert!(CapabilityKind::Trivy.is_auto_provisionable());
        assert!(CapabilityKind::OsvScanner.is_auto_provisionable());
        // These need elevation or large downloads, so they are documented instead.
        assert!(!CapabilityKind::ContainerRuntime.is_auto_provisionable());
        assert!(!CapabilityKind::LocalInference.is_auto_provisionable());
        assert!(!CapabilityKind::Git.is_auto_provisionable());
    }

    #[test]
    fn reports_expose_capability_lookup() {
        let report = CapabilityReport {
            schema_version: super::CAPABILITY_REPORT_SCHEMA_VERSION.to_owned(),
            platform: Platform::current(),
            capabilities: vec![Capability {
                kind: CapabilityKind::Git,
                status: CapabilityStatus::Present,
                implementation: Some("git".to_owned()),
                version: Some("2.51.0".to_owned()),
                detail: "git version 2.51.0".to_owned(),
            }],
            available_tracks: vec![DeliveryTrack::Deploy],
            blocking_capability: Some(CapabilityKind::ContainerRuntime),
            detected_at: chrono::Utc::now(),
        };
        assert!(report.has(CapabilityKind::Git));
        assert!(!report.has(CapabilityKind::Trivy));
        assert_eq!(
            report
                .get(CapabilityKind::Git)
                .and_then(|c| c.version.as_deref()),
            Some("2.51.0")
        );
    }
}
