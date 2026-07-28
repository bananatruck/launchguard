//! Bounded scanner execution and scanner-neutral report normalization.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;

use crate::{
    ArtifactStore, Confidence, FINDING_SCHEMA_VERSION, Finding, FindingCategory, FindingLocation,
    LaunchGuardError, PackageReference, RawArtifact, Result, ScannerKind, Severity,
};

/// Configured scanner executable paths.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Trivy executable or absolute path.
    pub trivy_executable: PathBuf,
    /// OSV-Scanner executable or absolute path.
    pub osv_executable: PathBuf,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            trivy_executable: PathBuf::from("trivy"),
            osv_executable: PathBuf::from("osv-scanner"),
        }
    }
}

/// Resource limits applied to external scanner processes.
#[derive(Debug, Clone, Copy)]
pub struct ScannerLimits {
    /// Wall-clock deadline.
    pub timeout: Duration,
    /// Maximum accepted JSON report size.
    pub max_stdout_bytes: usize,
    /// Maximum retained diagnostic output.
    pub max_stderr_bytes: usize,
}

impl Default for ScannerLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_mins(5),
            max_stdout_bytes: 100 * 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
        }
    }
}

/// Scanner provenance contract emitted by this release.
pub const SCANNER_PROVENANCE_SCHEMA_VERSION: &str = "1.0";

/// Identity of the exact scanner build and vulnerability data used by a run.
///
/// `LaunchGuard` may report that a named scanner completed against a named
/// database version. It may never present that as proof a project is secure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScannerProvenance {
    /// Public record schema.
    pub schema_version: String,
    /// Scanner the versions describe.
    pub scanner: ScannerKind,
    /// Reported executable version.
    pub version: String,
    /// Vulnerability database schema version, when the scanner reports one.
    pub vulnerability_database_version: Option<String>,
    /// Vulnerability database build time, when the scanner reports one.
    pub vulnerability_database_updated_at: Option<String>,
}

/// OSV-Scanner exit status meaning it found no package manifests to match.
const OSV_NO_PACKAGE_SOURCES: i32 = 128;

/// OSV-Scanner exit status meaning it matched at least one vulnerability.
const OSV_VULNERABILITIES_FOUND: i32 = 1;

/// Exact output of a completed scanner process.
#[derive(Debug)]
pub struct ScannerReport {
    scanner: ScannerKind,
    raw_json: Vec<u8>,
    repository_root: PathBuf,
    /// The scanner ran but found nothing in its ecosystem to inspect.
    ///
    /// This is a completed scan with zero findings, not a failure. The scanner
    /// writes no JSON in this case, so the raw report is empty.
    no_package_sources: bool,
}

impl ScannerReport {
    /// Scanner that produced the report.
    #[must_use]
    pub const fn scanner(&self) -> ScannerKind {
        self.scanner
    }

    /// Store the sensitive raw report and return safe metadata.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when persistence fails.
    pub fn persist(&self, store: &ArtifactStore) -> Result<RawArtifact> {
        store.put_report(self.scanner, &self.raw_json)
    }

    /// Normalize the report and attach its content digest as provenance.
    ///
    /// # Errors
    ///
    /// Returns an error when the scanner schema is malformed or unsupported.
    pub fn normalize(&self, artifact: &RawArtifact) -> Result<Vec<Finding>> {
        if self.no_package_sources {
            return Ok(Vec::new());
        }
        let mut findings = match self.scanner {
            ScannerKind::Trivy => normalize_trivy(&self.raw_json, &self.repository_root)?,
            ScannerKind::OsvScanner => normalize_osv(&self.raw_json, &self.repository_root)?,
        };
        for finding in &mut findings {
            finding.raw_artifact_digests = vec![artifact.digest.clone()];
        }
        Ok(findings)
    }
}

/// Runs trusted scanner binaries without a shell and with bounded output.
#[derive(Debug, Clone)]
pub struct ScannerRunner {
    config: ScannerConfig,
    limits: ScannerLimits,
}

impl ScannerRunner {
    /// Construct a runner with explicit executable paths and limits.
    #[must_use]
    pub const fn new(config: ScannerConfig, limits: ScannerLimits) -> Self {
        Self { config, limits }
    }

    /// Execute one scanner against a repository path.
    ///
    /// Trivy is configured for vulnerability, secret, and misconfiguration
    /// inspection. OSV-Scanner is configured for recursive source inspection.
    /// Neither command is interpreted by a shell.
    ///
    /// # Errors
    ///
    /// Returns an error for launch failures, timeouts, excessive output,
    /// scanner failures, or malformed JSON.
    pub async fn run(&self, scanner: ScannerKind, repository: &Path) -> Result<ScannerReport> {
        let executable = self.executable(scanner);
        let mut command = Command::new(executable);
        match scanner {
            ScannerKind::Trivy => {
                command.args([
                    "filesystem",
                    "--format",
                    "json",
                    "--quiet",
                    "--scanners",
                    "vuln,secret,misconfig",
                ]);
            }
            ScannerKind::OsvScanner => {
                command.args([
                    "scan",
                    "source",
                    "--format",
                    "json",
                    "--verbosity",
                    "error",
                    "--recursive",
                ]);
            }
        }
        command.arg(repository);

        let output = run_bounded(command, scanner, executable, &self.limits).await?;
        // OSV-Scanner signals findings and an empty workspace through its exit
        // status rather than its report, and writes no JSON for the latter.
        let osv_status = (scanner == ScannerKind::OsvScanner)
            .then(|| output.status.code())
            .flatten();
        let no_package_sources = osv_status == Some(OSV_NO_PACKAGE_SOURCES);
        let accepted = output.status.success()
            || no_package_sources
            || osv_status == Some(OSV_VULNERABILITIES_FOUND);
        if !accepted {
            return Err(output.into_failure(scanner));
        }

        let raw_json = output.stdout;
        if !no_package_sources {
            match scanner {
                ScannerKind::Trivy => {
                    normalize_trivy(&raw_json, repository)?;
                }
                ScannerKind::OsvScanner => {
                    normalize_osv(&raw_json, repository)?;
                }
            }
        }
        Ok(ScannerReport {
            scanner,
            raw_json,
            repository_root: repository.to_path_buf(),
            no_package_sources,
        })
    }

    /// Record the scanner build and vulnerability database backing a run.
    ///
    /// This executes only the scanner's own version subcommand. It never
    /// touches repository content.
    ///
    /// # Errors
    ///
    /// Returns an error for launch failures, timeouts, a failure status, or
    /// output the scanner contract does not describe.
    pub async fn provenance(&self, scanner: ScannerKind) -> Result<ScannerProvenance> {
        let executable = self.executable(scanner);
        let mut command = Command::new(executable);
        match scanner {
            ScannerKind::Trivy => command.args(["version", "--format", "json"]),
            ScannerKind::OsvScanner => command.arg("--version"),
        };
        let limits = ScannerLimits {
            timeout: self.limits.timeout.min(Duration::from_mins(1)),
            max_stdout_bytes: self.limits.max_stdout_bytes.min(1024 * 1024),
            max_stderr_bytes: self.limits.max_stderr_bytes,
        };
        let output = run_bounded(command, scanner, executable, &limits).await?;
        if !output.status.success() {
            return Err(output.into_failure(scanner));
        }
        match scanner {
            ScannerKind::Trivy => parse_trivy_version(&output.stdout),
            ScannerKind::OsvScanner => parse_osv_version(&output.stdout),
        }
    }

    const fn executable(&self, scanner: ScannerKind) -> &PathBuf {
        match scanner {
            ScannerKind::Trivy => &self.config.trivy_executable,
            ScannerKind::OsvScanner => &self.config.osv_executable,
        }
    }
}

/// Bounded output of a completed trusted process.
struct ProcessOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ProcessOutput {
    fn into_failure(self, scanner: ScannerKind) -> LaunchGuardError {
        LaunchGuardError::ScannerFailed {
            scanner: scanner.as_str(),
            status: self
                .status
                .code()
                .map_or_else(|| "terminated".to_owned(), |code| code.to_string()),
            message: String::from_utf8_lossy(&self.stderr).trim().to_owned(),
        }
    }
}

/// Run a trusted executable without a shell, bounding output and wall-clock time.
async fn run_bounded(
    mut command: Command,
    scanner: ScannerKind,
    executable: &Path,
    limits: &ScannerLimits,
) -> Result<ProcessOutput> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command
        .spawn()
        .map_err(|source| LaunchGuardError::ScannerUnavailable {
            scanner: scanner.as_str(),
            executable: executable.to_path_buf(),
            source,
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| report_error(scanner, "stdout pipe unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| report_error(scanner, "stderr pipe unavailable"))?;
    let stdout_task = tokio::spawn(read_bounded(
        stdout,
        scanner,
        "stdout",
        limits.max_stdout_bytes,
    ));
    let stderr_task = tokio::spawn(read_bounded(
        stderr,
        scanner,
        "stderr",
        limits.max_stderr_bytes,
    ));

    let status = if let Ok(status) = timeout(limits.timeout, child.wait()).await {
        status?
    } else {
        let _ = child.kill().await;
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        return Err(LaunchGuardError::ScannerTimeout {
            scanner: scanner.as_str(),
            timeout_seconds: limits.timeout.as_secs(),
        });
    };
    Ok(ProcessOutput {
        status,
        stdout: stdout_task.await??,
        stderr: stderr_task.await??,
    })
}

/// Parse `trivy version --format json`.
///
/// `VulnerabilityDB` is absent until Trivy has downloaded its database, so the
/// database fields stay optional rather than being invented.
fn parse_trivy_version(stdout: &[u8]) -> Result<ScannerProvenance> {
    let report: Value = serde_json::from_slice(stdout)?;
    let version = owned_string_at(&report, "Version")
        .ok_or_else(|| report_error(ScannerKind::Trivy, "version report has no Version"))?;
    let database = report.get("VulnerabilityDB");
    Ok(ScannerProvenance {
        schema_version: SCANNER_PROVENANCE_SCHEMA_VERSION.to_owned(),
        scanner: ScannerKind::Trivy,
        version,
        vulnerability_database_version: database.and_then(|value| value.get("Version")).and_then(
            |value| match value {
                Value::Number(number) => Some(number.to_string()),
                Value::String(text) if !text.is_empty() => Some(text.clone()),
                _ => None,
            },
        ),
        vulnerability_database_updated_at: database
            .and_then(|value| owned_string_at(value, "UpdatedAt")),
    })
}

/// Parse the `osv-scanner --version` text banner.
///
/// OSV-Scanner matches against the upstream OSV database rather than a local
/// database file, so it reports no database version to record.
fn parse_osv_version(stdout: &[u8]) -> Result<ScannerProvenance> {
    let text = String::from_utf8_lossy(stdout);
    let version = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("osv-scanner version:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            report_error(
                ScannerKind::OsvScanner,
                "version banner has no osv-scanner version line",
            )
        })?;
    Ok(ScannerProvenance {
        schema_version: SCANNER_PROVENANCE_SCHEMA_VERSION.to_owned(),
        scanner: ScannerKind::OsvScanner,
        version: version.to_owned(),
        vulnerability_database_version: None,
        vulnerability_database_updated_at: None,
    })
}

impl Default for ScannerRunner {
    fn default() -> Self {
        Self::new(ScannerConfig::default(), ScannerLimits::default())
    }
}

async fn read_bounded<R>(
    mut reader: R,
    scanner: ScannerKind,
    stream: &'static str,
    limit: usize,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(count) > limit {
            return Err(LaunchGuardError::ScannerOutputTooLarge {
                scanner: scanner.as_str(),
                stream,
                limit_bytes: limit,
            });
        }
        output.extend_from_slice(&chunk[..count]);
    }
}

/// Normalize a Trivy JSON schema version 2 report.
///
/// Secret match and source-code fields are deliberately ignored. Reported
/// paths are rewritten relative to `repository_root` so findings for the same
/// artifact carry the same location regardless of which scanner saw it.
///
/// # Errors
///
/// Returns an error for malformed JSON or an unsupported schema version.
pub fn normalize_trivy(bytes: &[u8], repository_root: &Path) -> Result<Vec<Finding>> {
    let report: Value = serde_json::from_slice(bytes)?;
    if report.get("SchemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(report_error(
            ScannerKind::Trivy,
            "expected JSON SchemaVersion 2",
        ));
    }
    // Trivy omits Results entirely when a scan produces no findings. That is a
    // clean scan, not a malformed report; only a present non-array is invalid.
    let results = match report.get("Results") {
        None | Some(Value::Null) => &[][..],
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| report_error(ScannerKind::Trivy, "Results is not an array"))?,
    };
    let mut findings = Vec::new();
    for result in results {
        let target = relative_path(
            string_at(result, "Target").unwrap_or_default(),
            repository_root,
        );
        let target = target.as_str();
        for vulnerability in array_at(result, "Vulnerabilities") {
            let identifier = string_at(vulnerability, "VulnerabilityID");
            let package_name = string_at(vulnerability, "PkgName").unwrap_or("unknown");
            let installed = owned_string_at(vulnerability, "InstalledVersion");
            let fixed = first_csv_value(string_at(vulnerability, "FixedVersion"));
            let package = PackageReference {
                ecosystem: None,
                name: package_name.to_owned(),
                installed_version: installed,
                fixed_version: fixed.clone(),
            };
            let summary = string_at(vulnerability, "Title")
                .or_else(|| string_at(vulnerability, "Description"))
                .unwrap_or("Vulnerable dependency")
                .to_owned();
            let remediation = fixed.map(|version| format!("Upgrade {package_name} to {version}"));
            findings.push(make_finding(
                ScannerKind::Trivy,
                FindingSeed {
                    category: FindingCategory::Vulnerability,
                    severity: parse_severity(string_at(vulnerability, "Severity")),
                    vulnerability_id: identifier.map(str::to_owned),
                    package: Some(package),
                    location: location(target, None, None),
                    summary,
                    recommended_fix: remediation,
                },
            ));
        }
        for misconfiguration in array_at(result, "Misconfigurations") {
            let metadata = misconfiguration.get("CauseMetadata");
            findings.push(make_finding(
                ScannerKind::Trivy,
                FindingSeed {
                    category: FindingCategory::Misconfiguration,
                    severity: parse_severity(string_at(misconfiguration, "Severity")),
                    vulnerability_id: string_at(misconfiguration, "ID")
                        .or_else(|| string_at(misconfiguration, "AVDID"))
                        .map(str::to_owned),
                    package: None,
                    location: location(
                        target,
                        metadata.and_then(|value| integer_at(value, "StartLine")),
                        metadata.and_then(|value| integer_at(value, "EndLine")),
                    ),
                    summary: string_at(misconfiguration, "Title")
                        .or_else(|| string_at(misconfiguration, "Message"))
                        .unwrap_or("Configuration issue")
                        .to_owned(),
                    recommended_fix: owned_string_at(misconfiguration, "Resolution"),
                },
            ));
        }
        for secret in array_at(result, "Secrets") {
            findings.push(make_finding(
                ScannerKind::Trivy,
                FindingSeed {
                    category: FindingCategory::Secret,
                    severity: parse_severity(string_at(secret, "Severity")),
                    vulnerability_id: string_at(secret, "RuleID").map(str::to_owned),
                    package: None,
                    location: location(
                        target,
                        integer_at(secret, "StartLine"),
                        integer_at(secret, "EndLine"),
                    ),
                    summary: string_at(secret, "Title")
                        .or_else(|| string_at(secret, "Category"))
                        .unwrap_or("Potential secret")
                        .to_owned(),
                    recommended_fix: Some(
                        "Revoke the credential and replace it with a secret reference".to_owned(),
                    ),
                },
            ));
        }
        for license in array_at(result, "Licenses") {
            let name = string_at(license, "Name").unwrap_or("unknown");
            findings.push(make_finding(
                ScannerKind::Trivy,
                FindingSeed {
                    category: FindingCategory::License,
                    severity: parse_severity(string_at(license, "Severity")),
                    vulnerability_id: Some(name.to_owned()),
                    package: None,
                    location: location(target, None, None),
                    summary: format!("License policy observation: {name}"),
                    recommended_fix: None,
                },
            ));
        }
    }
    Ok(merge_findings(findings))
}

/// Normalize an OSV-Scanner v2 source-scan JSON report.
///
/// OSV-Scanner reports the absolute path it was given. Paths are rewritten
/// relative to `repository_root` so a dependency vulnerability seen by both
/// scanners produces one fingerprint instead of two.
///
/// # Errors
///
/// Returns an error for malformed JSON or a missing `results` contract.
pub fn normalize_osv(bytes: &[u8], repository_root: &Path) -> Result<Vec<Finding>> {
    let report: Value = serde_json::from_slice(bytes)?;
    let results = report
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| report_error(ScannerKind::OsvScanner, "missing results array"))?;
    let mut findings = Vec::new();
    for result in results {
        let source_path = relative_path(
            result
                .get("source")
                .and_then(|source| string_at(source, "path"))
                .unwrap_or_default(),
            repository_root,
        );
        let source_path = source_path.as_str();
        let alias_groups = alias_groups(result);
        for package_entry in array_at(result, "packages") {
            let package_value = package_entry.get("package").unwrap_or(&Value::Null);
            let package_name = string_at(package_value, "name").unwrap_or("unknown");
            let installed_version = owned_string_at(package_value, "version");
            let ecosystem = owned_string_at(package_value, "ecosystem");
            for vulnerability in array_at(package_entry, "vulnerabilities") {
                let reported_id = string_at(vulnerability, "id");
                let canonical_id = canonical_vulnerability_id(
                    reported_id,
                    array_strings(vulnerability, "aliases"),
                    &alias_groups,
                );
                let fixed_version = first_fixed_version(vulnerability);
                let package = PackageReference {
                    ecosystem: ecosystem.clone(),
                    name: package_name.to_owned(),
                    installed_version: installed_version.clone(),
                    fixed_version: fixed_version.clone(),
                };
                let remediation =
                    fixed_version.map(|version| format!("Upgrade {package_name} to {version}"));
                findings.push(make_finding(
                    ScannerKind::OsvScanner,
                    FindingSeed {
                        category: FindingCategory::Vulnerability,
                        severity: osv_severity(vulnerability),
                        vulnerability_id: canonical_id,
                        package: Some(package),
                        location: location(source_path, None, None),
                        summary: string_at(vulnerability, "summary")
                            .or_else(|| string_at(vulnerability, "details"))
                            .unwrap_or("Vulnerable dependency")
                            .to_owned(),
                        recommended_fix: remediation,
                    },
                ));
            }
        }
    }
    Ok(merge_findings(findings))
}

/// Merge duplicate findings without depending on scanner execution order.
#[must_use]
pub fn merge_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: BTreeMap<String, Finding> = BTreeMap::new();
    for mut finding in findings {
        finding.scanners.sort_unstable();
        finding.scanners.dedup();
        finding.raw_artifact_digests.sort();
        finding.raw_artifact_digests.dedup();
        if let Some(existing) = merged.get_mut(&finding.fingerprint) {
            existing.scanners.extend(finding.scanners);
            existing.scanners.sort_unstable();
            existing.scanners.dedup();
            existing.severity = existing.severity.max(finding.severity);
            existing.confidence = existing.confidence.max(finding.confidence);
            existing.blocks_preview |= finding.blocks_preview;
            existing.blocks_publication |= finding.blocks_publication;
            existing.vulnerability_id =
                smaller_option(existing.vulnerability_id.take(), finding.vulnerability_id);
            existing.package = merge_package(existing.package.take(), finding.package);
            existing.location = merge_location(existing.location.take(), finding.location);
            existing.summary = smaller_nonempty(&existing.summary, &finding.summary);
            existing.recommended_fix =
                smaller_option(existing.recommended_fix.take(), finding.recommended_fix);
            existing
                .raw_artifact_digests
                .extend(finding.raw_artifact_digests);
            existing.raw_artifact_digests.sort();
            existing.raw_artifact_digests.dedup();
        } else {
            merged.insert(finding.fingerprint.clone(), finding);
        }
    }
    merged.into_values().collect()
}

struct FindingSeed {
    category: FindingCategory,
    severity: Severity,
    vulnerability_id: Option<String>,
    package: Option<PackageReference>,
    location: Option<FindingLocation>,
    summary: String,
    recommended_fix: Option<String>,
}

fn make_finding(scanner: ScannerKind, seed: FindingSeed) -> Finding {
    let FindingSeed {
        category,
        severity,
        vulnerability_id,
        package,
        location,
        summary,
        recommended_fix,
    } = seed;
    let identity = format!(
        "{category:?}|{}|{}|{}|{}|{}",
        vulnerability_id
            .as_deref()
            .unwrap_or_default()
            .to_uppercase(),
        package
            .as_ref()
            .map_or("", |reference| reference.name.as_str())
            .to_lowercase(),
        package
            .as_ref()
            .and_then(|reference| reference.installed_version.as_deref())
            .unwrap_or_default(),
        location
            .as_ref()
            .map_or("", |value| value.path.as_str())
            .replace('\\', "/")
            .to_lowercase(),
        location
            .as_ref()
            .and_then(|value| value.start_line)
            .map_or_else(String::new, |line| line.to_string()),
    );
    let fingerprint = format!("{:x}", Sha256::digest(identity.as_bytes()));
    let (blocks_preview, blocks_publication) = blocking_policy(category, severity);
    Finding {
        schema_version: FINDING_SCHEMA_VERSION.to_owned(),
        fingerprint,
        scanners: vec![scanner],
        category,
        severity,
        confidence: Confidence::High,
        vulnerability_id,
        package,
        location,
        summary,
        recommended_fix,
        blocks_preview,
        blocks_publication,
        raw_artifact_digests: Vec::new(),
    }
}

const fn blocking_policy(category: FindingCategory, severity: Severity) -> (bool, bool) {
    match (category, severity) {
        (FindingCategory::Secret, Severity::High | Severity::Critical)
        | (FindingCategory::Vulnerability, Severity::Critical) => (true, true),
        (FindingCategory::Vulnerability | FindingCategory::Misconfiguration, Severity::High) => {
            (false, true)
        }
        _ => (false, false),
    }
}

fn report_error(scanner: ScannerKind, message: &str) -> LaunchGuardError {
    LaunchGuardError::ScannerReport {
        scanner: scanner.as_str(),
        message: message.to_owned(),
    }
}

fn parse_severity(value: Option<&str>) -> Severity {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "moderate" => Severity::Medium,
        "low" | "negligible" => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn osv_severity(vulnerability: &Value) -> Severity {
    if let Some(value) = vulnerability
        .get("database_specific")
        .and_then(|specific| string_at(specific, "severity"))
    {
        return parse_severity(Some(value));
    }
    if let Some(score) = array_at(vulnerability, "severity")
        .iter()
        .find_map(|item| string_at(item, "score"))
        .and_then(|score| score.parse::<f64>().ok())
    {
        return if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else {
            Severity::Low
        };
    }
    Severity::Unknown
}

fn alias_groups(result: &Value) -> Vec<Vec<String>> {
    array_at(result, "groups")
        .iter()
        .map(|group| array_strings(group, "ids"))
        .filter(|ids| !ids.is_empty())
        .collect()
}

fn canonical_vulnerability_id(
    reported: Option<&str>,
    mut aliases: Vec<String>,
    groups: &[Vec<String>],
) -> Option<String> {
    if let Some(identifier) = reported {
        aliases.push(identifier.to_owned());
        for group in groups {
            if group.iter().any(|candidate| candidate == identifier) {
                aliases.extend(group.iter().cloned());
            }
        }
    }
    aliases.sort();
    aliases.dedup();
    aliases
        .iter()
        .find(|identifier| identifier.starts_with("CVE-"))
        .or_else(|| {
            aliases
                .iter()
                .find(|identifier| identifier.starts_with("GHSA-"))
        })
        .or_else(|| aliases.first())
        .cloned()
}

fn first_fixed_version(vulnerability: &Value) -> Option<String> {
    array_at(vulnerability, "affected")
        .iter()
        .flat_map(|affected| array_at(affected, "ranges"))
        .flat_map(|range| array_at(range, "events"))
        .filter_map(|event| owned_string_at(event, "fixed"))
        .min()
}

fn array_at<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn array_strings(value: &Value, key: &str) -> Vec<String> {
    array_at(value, key)
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn string_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn owned_string_at(value: &Value, key: &str) -> Option<String> {
    string_at(value, key)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn integer_at(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn first_csv_value(value: Option<&str>) -> Option<String> {
    value
        .and_then(|value| {
            value
                .split(',')
                .map(str::trim)
                .find(|part| !part.is_empty())
        })
        .map(str::to_owned)
}

/// Rewrite a scanner-reported path as a repository-relative path.
///
/// Trivy reports paths relative to the scan root while OSV-Scanner echoes the
/// absolute path it was given. Public records use repository-relative paths,
/// and fingerprints hash the location, so both must agree.
fn relative_path(path: &str, repository_root: &Path) -> String {
    let path = path.replace('\\', "/");
    let root = repository_root.to_string_lossy().replace('\\', "/");
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return path;
    }
    let Some(remainder) = path.strip_prefix(root) else {
        return path;
    };
    // Only strip a whole path segment, never a partial directory name.
    if remainder.is_empty() {
        return ".".to_owned();
    }
    match remainder.strip_prefix('/') {
        Some(relative) if !relative.is_empty() => relative.to_owned(),
        Some(_) => ".".to_owned(),
        None => path,
    }
}

fn location(path: &str, start_line: Option<u64>, end_line: Option<u64>) -> Option<FindingLocation> {
    if path.is_empty() && start_line.is_none() && end_line.is_none() {
        None
    } else {
        Some(FindingLocation {
            path: path.replace('\\', "/"),
            start_line,
            end_line,
        })
    }
}

fn smaller_nonempty(left: &str, right: &str) -> String {
    match (left.is_empty(), right.is_empty()) {
        (true, _) => right.to_owned(),
        (_, true) => left.to_owned(),
        (false, false) => left.min(right).to_owned(),
    }
}

fn smaller_option(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn merge_package(
    left: Option<PackageReference>,
    right: Option<PackageReference>,
) -> Option<PackageReference> {
    match (left, right) {
        (Some(left), Some(right)) => Some(PackageReference {
            ecosystem: smaller_option(left.ecosystem, right.ecosystem),
            name: smaller_nonempty(&left.name, &right.name),
            installed_version: smaller_option(left.installed_version, right.installed_version),
            fixed_version: smaller_option(left.fixed_version, right.fixed_version),
        }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn merge_location(
    left: Option<FindingLocation>,
    right: Option<FindingLocation>,
) -> Option<FindingLocation> {
    match (left, right) {
        (Some(left), Some(right)) => Some(FindingLocation {
            path: smaller_nonempty(&left.path, &right.path),
            start_line: smaller_number(left.start_line, right.start_line),
            end_line: smaller_number(left.end_line, right.end_line),
        }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn smaller_number(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{parse_osv_version, parse_trivy_version, relative_path};
    use crate::ScannerKind;

    #[test]
    fn absolute_scanner_paths_become_repository_relative() {
        let root = Path::new("/tmp/checkout");
        assert_eq!(
            relative_path("/tmp/checkout/package-lock.json", root),
            "package-lock.json"
        );
        assert_eq!(
            relative_path("/tmp/checkout/api/pyproject.toml", root),
            "api/pyproject.toml"
        );
        assert_eq!(relative_path("/tmp/checkout", root), ".");
        assert_eq!(relative_path("/tmp/checkout/", root), ".");
    }

    #[test]
    fn already_relative_paths_are_unchanged() {
        let root = Path::new("/tmp/checkout");
        assert_eq!(
            relative_path("package-lock.json", root),
            "package-lock.json"
        );
        assert_eq!(relative_path("src/config.ts", root), "src/config.ts");
    }

    #[test]
    fn a_sibling_directory_sharing_a_prefix_is_not_stripped() {
        let root = Path::new("/tmp/checkout");
        assert_eq!(
            relative_path("/tmp/checkout-backup/package-lock.json", root),
            "/tmp/checkout-backup/package-lock.json"
        );
    }

    #[test]
    fn trivy_version_without_a_downloaded_database_reports_no_database() {
        let provenance = parse_trivy_version(br#"{"Version":"0.72.0"}"#).expect("parse version");
        assert_eq!(provenance.scanner, ScannerKind::Trivy);
        assert_eq!(provenance.version, "0.72.0");
        assert_eq!(provenance.vulnerability_database_version, None);
        assert_eq!(provenance.vulnerability_database_updated_at, None);
    }

    #[test]
    fn trivy_version_records_the_vulnerability_database() {
        let provenance = parse_trivy_version(
            br#"{"Version":"0.72.0","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-07-27T06:11:32Z"}}"#,
        )
        .expect("parse version");
        assert_eq!(
            provenance.vulnerability_database_version.as_deref(),
            Some("2")
        );
        assert_eq!(
            provenance.vulnerability_database_updated_at.as_deref(),
            Some("2026-07-27T06:11:32Z")
        );
    }

    #[test]
    fn osv_version_banner_is_parsed() {
        let provenance = parse_osv_version(
            b"osv-scanner version: 2.4.0\nosv-scalibr version: 0.4.5\ncommit: abc\n",
        )
        .expect("parse banner");
        assert_eq!(provenance.scanner, ScannerKind::OsvScanner);
        assert_eq!(provenance.version, "2.4.0");
        assert_eq!(provenance.vulnerability_database_version, None);
    }

    #[test]
    fn unrecognized_version_output_fails_closed() {
        assert!(parse_trivy_version(b"not json").is_err());
        assert!(parse_osv_version(b"some other tool v1\n").is_err());
    }
}
