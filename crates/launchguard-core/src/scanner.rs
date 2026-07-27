//! Bounded scanner execution and scanner-neutral report normalization.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

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

/// Exact output of a completed scanner process.
#[derive(Debug)]
pub struct ScannerReport {
    scanner: ScannerKind,
    raw_json: Vec<u8>,
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
        let mut findings = match self.scanner {
            ScannerKind::Trivy => normalize_trivy(&self.raw_json)?,
            ScannerKind::OsvScanner => normalize_osv(&self.raw_json)?,
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
        let executable = match scanner {
            ScannerKind::Trivy => &self.config.trivy_executable,
            ScannerKind::OsvScanner => &self.config.osv_executable,
        };
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
        command
            .arg(repository)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command
            .spawn()
            .map_err(|source| LaunchGuardError::ScannerUnavailable {
                scanner: scanner.as_str(),
                executable: executable.clone(),
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
            self.limits.max_stdout_bytes,
        ));
        let stderr_task = tokio::spawn(read_bounded(
            stderr,
            scanner,
            "stderr",
            self.limits.max_stderr_bytes,
        ));

        let status = if let Ok(status) = timeout(self.limits.timeout, child.wait()).await {
            status?
        } else {
            let _ = child.kill().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(LaunchGuardError::ScannerTimeout {
                scanner: scanner.as_str(),
                timeout_seconds: self.limits.timeout.as_secs(),
            });
        };
        let raw_json = stdout_task.await??;
        let stderr = stderr_task.await??;
        let accepted =
            status.success() || (scanner == ScannerKind::OsvScanner && status.code() == Some(1));
        if !accepted {
            return Err(LaunchGuardError::ScannerFailed {
                scanner: scanner.as_str(),
                status: status
                    .code()
                    .map_or_else(|| "terminated".to_owned(), |code| code.to_string()),
                message: String::from_utf8_lossy(&stderr).trim().to_owned(),
            });
        }

        match scanner {
            ScannerKind::Trivy => {
                normalize_trivy(&raw_json)?;
            }
            ScannerKind::OsvScanner => {
                normalize_osv(&raw_json)?;
            }
        }
        Ok(ScannerReport { scanner, raw_json })
    }
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
/// Secret match and source-code fields are deliberately ignored.
///
/// # Errors
///
/// Returns an error for malformed JSON or an unsupported schema version.
pub fn normalize_trivy(bytes: &[u8]) -> Result<Vec<Finding>> {
    let report: Value = serde_json::from_slice(bytes)?;
    if report.get("SchemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(report_error(
            ScannerKind::Trivy,
            "expected JSON SchemaVersion 2",
        ));
    }
    let results = report
        .get("Results")
        .and_then(Value::as_array)
        .ok_or_else(|| report_error(ScannerKind::Trivy, "missing Results array"))?;
    let mut findings = Vec::new();
    for result in results {
        let target = string_at(result, "Target").unwrap_or_default();
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
/// # Errors
///
/// Returns an error for malformed JSON or a missing `results` contract.
pub fn normalize_osv(bytes: &[u8]) -> Result<Vec<Finding>> {
    let report: Value = serde_json::from_slice(bytes)?;
    let results = report
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| report_error(ScannerKind::OsvScanner, "missing results array"))?;
    let mut findings = Vec::new();
    for result in results {
        let source_path = result
            .get("source")
            .and_then(|source| string_at(source, "path"))
            .unwrap_or_default();
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
