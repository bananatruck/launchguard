//! Stable, scanner-neutral security findings.

use serde::{Deserialize, Serialize};

/// Finding contract emitted by this release.
pub const FINDING_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`Finding`].
pub const FINDING_SCHEMA_JSON: &str = include_str!("../../../schemas/finding-v1.schema.json");

/// Supported external security scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerKind {
    /// Aqua Trivy.
    Trivy,
    /// Google OSV-Scanner.
    OsvScanner,
}

impl ScannerKind {
    /// Stable command/report name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trivy => "trivy",
            Self::OsvScanner => "osv-scanner",
        }
    }
}

/// Normalized class of security issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Vulnerable software dependency.
    Vulnerability,
    /// Credential or secret-like content. Secret values are never retained here.
    Secret,
    /// Infrastructure or application configuration problem.
    Misconfiguration,
    /// License policy observation.
    License,
}

/// Scanner-neutral severity ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Scanner did not provide a severity `LaunchGuard` understands.
    Unknown,
    /// Informational or low impact.
    Low,
    /// Moderate impact.
    Medium,
    /// High impact.
    High,
    /// Critical impact.
    Critical,
}

/// Confidence in a normalized observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Weak or heuristic evidence.
    Low,
    /// Reasonable scanner evidence.
    Medium,
    /// Direct scanner evidence with a stable identifier or location.
    High,
}

/// Repository-relative source location, if supplied by the scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingLocation {
    /// Normalized repository-relative path.
    pub path: String,
    /// One-indexed first line.
    pub start_line: Option<u64>,
    /// One-indexed last line.
    pub end_line: Option<u64>,
}

/// A vulnerable package observed by a dependency scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageReference {
    /// Ecosystem such as `npm`, `PyPI`, or `crates.io`.
    pub ecosystem: Option<String>,
    /// Package name.
    pub name: String,
    /// Installed version, when reported.
    pub installed_version: Option<String>,
    /// First fixed version selected by the scanner.
    pub fixed_version: Option<String>,
}

/// Deduplicated security finding that is safe to display or pass to an AI explainer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Public record schema.
    pub schema_version: String,
    /// SHA-256 over scanner-neutral identity fields.
    pub fingerprint: String,
    /// Every scanner contributing to this finding.
    pub scanners: Vec<ScannerKind>,
    /// Finding class.
    pub category: FindingCategory,
    /// Maximum severity reported by contributing scanners.
    pub severity: Severity,
    /// Maximum confidence reported by contributing scanners.
    pub confidence: Confidence,
    /// Stable vulnerability or rule identifier.
    pub vulnerability_id: Option<String>,
    /// Optional package coordinates.
    pub package: Option<PackageReference>,
    /// Optional source location.
    pub location: Option<FindingLocation>,
    /// Short explanation with secret-bearing fields excluded.
    pub summary: String,
    /// Deterministic remediation guidance, if known.
    pub recommended_fix: Option<String>,
    /// Whether the finding prevents a sandboxed local preview.
    pub blocks_preview: bool,
    /// Whether the finding prevents publication.
    pub blocks_publication: bool,
    /// Content digests of raw local reports supporting the finding.
    pub raw_artifact_digests: Vec<String>,
}
