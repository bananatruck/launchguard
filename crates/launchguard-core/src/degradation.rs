//! Typed records describing capabilities that did not complete.
//!
//! A degraded run still produces a report. The specification requires that a
//! missing optional scanner continue with a degraded-coverage warning rather
//! than aborting the audit, and that reduced coverage stay visible instead of
//! being inferred from an empty finding list.

use serde::{Deserialize, Serialize};

use crate::{LaunchGuardError, ScannerKind};

/// Degradation contract emitted by this release.
pub const DEGRADATION_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`Degradation`].
pub const DEGRADATION_SCHEMA_JSON: &str =
    include_str!("../../../schemas/degradation-v1.schema.json");

/// Maximum retained diagnostic text. Scanner diagnostics are untrusted input.
const MAX_DETAIL_BYTES: usize = 512;

/// Capability that could not complete during an otherwise successful run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationKind {
    /// The scanner executable could not be started.
    ScannerUnavailable,
    /// The scanner exceeded its wall-clock deadline.
    ScannerTimeout,
    /// The scanner returned a failure status or oversized output.
    ScannerFailed,
    /// The scanner report used an unsupported or malformed contract.
    ScannerReportRejected,
    /// The raw report could not be stored locally.
    ArtifactNotStored,
    /// A reviewed execution plan could not be generated for a detected project.
    PlanUnavailable,
}

impl DegradationKind {
    /// Stable identifier used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScannerUnavailable => "scanner_unavailable",
            Self::ScannerTimeout => "scanner_timeout",
            Self::ScannerFailed => "scanner_failed",
            Self::ScannerReportRejected => "scanner_report_rejected",
            Self::ArtifactNotStored => "artifact_not_stored",
            Self::PlanUnavailable => "plan_unavailable",
        }
    }
}

/// One machine-readable reason a run has reduced coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Degradation {
    /// Public record schema.
    pub schema_version: String,
    /// Why the capability is unavailable.
    pub kind: DegradationKind,
    /// Affected capability, such as a scanner name or `execution-plan`.
    pub subject: String,
    /// Bounded diagnostic text. Never presented as a security conclusion.
    pub detail: String,
}

impl Degradation {
    /// Classify a scanner failure without aborting the run.
    #[must_use]
    pub fn from_scanner_error(scanner: ScannerKind, error: &LaunchGuardError) -> Self {
        let kind = match error {
            LaunchGuardError::ScannerUnavailable { .. } => DegradationKind::ScannerUnavailable,
            LaunchGuardError::ScannerTimeout { .. } => DegradationKind::ScannerTimeout,
            LaunchGuardError::ScannerReport { .. } | LaunchGuardError::Json(_) => {
                DegradationKind::ScannerReportRejected
            }
            _ => DegradationKind::ScannerFailed,
        };
        Self::new(kind, scanner.as_str(), &error.to_string())
    }

    /// Record a raw report that could not be persisted.
    #[must_use]
    pub fn artifact_not_stored(scanner: ScannerKind, error: &LaunchGuardError) -> Self {
        Self::new(
            DegradationKind::ArtifactNotStored,
            scanner.as_str(),
            &error.to_string(),
        )
    }

    /// Record a detected project that no reviewed template can plan.
    #[must_use]
    pub fn plan_unavailable(error: &LaunchGuardError) -> Self {
        Self::new(
            DegradationKind::PlanUnavailable,
            "execution-plan",
            &error.to_string(),
        )
    }

    fn new(kind: DegradationKind, subject: &str, detail: &str) -> Self {
        Self {
            schema_version: DEGRADATION_SCHEMA_VERSION.to_owned(),
            kind,
            subject: subject.to_owned(),
            detail: bounded(detail),
        }
    }
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
    use std::path::PathBuf;

    use super::{Degradation, DegradationKind, MAX_DETAIL_BYTES};
    use crate::{LaunchGuardError, ScannerKind};

    #[test]
    fn missing_executable_is_classified_as_unavailable() {
        let error = LaunchGuardError::ScannerUnavailable {
            scanner: "trivy",
            executable: PathBuf::from("trivy"),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        let degradation = Degradation::from_scanner_error(ScannerKind::Trivy, &error);
        assert_eq!(degradation.kind, DegradationKind::ScannerUnavailable);
        assert_eq!(degradation.subject, "trivy");
    }

    #[test]
    fn diagnostic_text_is_bounded_and_single_line() {
        let error = LaunchGuardError::ScannerFailed {
            scanner: "osv-scanner",
            status: "2".to_owned(),
            message: format!("line one\nline two\n{}", "x".repeat(4096)),
        };
        let degradation = Degradation::from_scanner_error(ScannerKind::OsvScanner, &error);
        assert_eq!(degradation.kind, DegradationKind::ScannerFailed);
        assert!(!degradation.detail.contains('\n'));
        assert!(degradation.detail.len() <= MAX_DETAIL_BYTES + 3);
    }
}
