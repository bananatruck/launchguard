//! Publication gating.
//!
//! Incomplete evidence and confirmed danger are not the same thing, so they do
//! not produce the same outcome. A hard block cannot be overridden at all. A
//! soft block can, by an explicit human decision that is recorded in the
//! deployment record and the pull request, naming exactly what was not verified.
//!
//! A host with no container runtime is a soft block. Refusing to publish because
//! a user cannot install a container runtime would make the deterministic
//! security work unreachable for the people most likely to need it, without
//! making any project safer.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CapabilityKind, CapabilityReport, Finding, FindingCategory, ReadinessAssessment, Result,
    Severity,
};

/// Publication-decision contract emitted by this release.
pub const PUBLICATION_DECISION_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`PublicationDecision`].
pub const PUBLICATION_DECISION_SCHEMA_JSON: &str =
    include_str!("../../../schemas/publication-decision-v1.schema.json");

/// How strongly policy resists publishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateLevel {
    /// Nothing blocks publication.
    Clear,
    /// Evidence is incomplete. Publication is permitted only with a recorded override.
    SoftBlock,
    /// A confirmed danger. Publication is refused and no override exists.
    HardBlock,
}

impl GateLevel {
    /// Stable identifier used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::SoftBlock => "soft_block",
            Self::HardBlock => "hard_block",
        }
    }
}

/// One reason policy resists publishing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReason {
    /// Stable policy identifier, safe to match on.
    pub code: String,
    /// Severity of this specific reason.
    pub level: GateLevel,
    /// Human-readable explanation without model-generated text.
    pub summary: String,
}

#[derive(Serialize)]
struct DecisionPayload<'a> {
    schema_version: &'a str,
    level: GateLevel,
    reasons: &'a [GateReason],
    override_accepted: bool,
    overridden_codes: &'a [String],
}

/// Whether an approved run may open a pull request, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationDecision {
    /// Public record schema.
    pub schema_version: String,
    /// Strongest level across every reason.
    pub level: GateLevel,
    /// Every reason, strongest first.
    pub reasons: Vec<GateReason>,
    /// Whether a person accepted the soft-blocked risks.
    pub override_accepted: bool,
    /// Codes the override covers, recorded for the pull request.
    pub overridden_codes: Vec<String>,
    /// SHA-256 over every field except this digest.
    pub digest: String,
}

impl PublicationDecision {
    /// Whether a pull request may be opened as things stand.
    #[must_use]
    pub fn permits_publication(&self) -> bool {
        match self.level {
            GateLevel::Clear => true,
            GateLevel::SoftBlock => self.override_accepted,
            GateLevel::HardBlock => false,
        }
    }

    /// Reasons at a given level.
    #[must_use]
    pub fn reasons_at(&self, level: GateLevel) -> Vec<&GateReason> {
        self.reasons
            .iter()
            .filter(|reason| reason.level == level)
            .collect()
    }

    /// Accept the soft-blocked risks as an explicit human decision.
    ///
    /// A hard block is never cleared, so this can only ever unblock a run whose
    /// evidence is incomplete, never one with a confirmed danger.
    ///
    /// # Errors
    ///
    /// Returns an error when the decision is hard-blocked, or when rehashing
    /// fails.
    pub fn accept_override(mut self) -> Result<Self> {
        if self.level == GateLevel::HardBlock {
            return Err(crate::LaunchGuardError::PublicationRefused(
                "a hard block cannot be overridden".to_owned(),
            ));
        }
        self.overridden_codes = self
            .reasons_at(GateLevel::SoftBlock)
            .into_iter()
            .map(|reason| reason.code.clone())
            .collect();
        self.override_accepted = true;
        self.digest = decision_digest(&self)?;
        Ok(self)
    }

    /// Recompute and validate the embedded digest.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the digest does not match.
    pub fn validate_digest(&self) -> Result<()> {
        if self.digest == decision_digest(self)? {
            Ok(())
        } else {
            Err(crate::LaunchGuardError::DigestMismatch {
                record: "PublicationDecision",
            })
        }
    }
}

/// Outcome of a local verification attempt, when one was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewOutcome {
    /// Verification ran and succeeded.
    Passed,
    /// Verification ran and failed.
    Failed,
    /// Verification was not attempted.
    NotAttempted,
}

/// Evaluates publication policy without a model.
#[derive(Debug, Default, Clone, Copy)]
pub struct PublicationGate;

impl PublicationGate {
    /// Decide whether a run may publish.
    ///
    /// # Errors
    ///
    /// Returns an error only when stable hashing fails.
    pub fn evaluate(
        &self,
        assessment: &ReadinessAssessment,
        findings: &[Finding],
        capability: Option<&CapabilityReport>,
        preview: PreviewOutcome,
    ) -> Result<PublicationDecision> {
        let mut reasons = Vec::new();

        // Hard blocks: confirmed danger, never overridable.
        if findings.iter().any(|finding| {
            finding.category == FindingCategory::Secret && finding.blocks_publication
        }) {
            reasons.push(GateReason {
                code: "secret_finding".to_owned(),
                level: GateLevel::HardBlock,
                summary: "A scanner reported a credential in the repository. Rotate it before \
                          publishing."
                    .to_owned(),
            });
        }
        if findings.iter().any(|finding| {
            finding.category == FindingCategory::Vulnerability
                && finding.severity == Severity::Critical
        }) {
            reasons.push(GateReason {
                code: "critical_vulnerability".to_owned(),
                level: GateLevel::HardBlock,
                summary: "An unacknowledged critical dependency vulnerability is present."
                    .to_owned(),
            });
        }

        // Soft blocks: incomplete evidence, overridable and recorded.
        if !assessment
            .completed_scanners
            .contains(&crate::ScannerKind::Trivy)
            || !assessment
                .completed_scanners
                .contains(&crate::ScannerKind::OsvScanner)
        {
            reasons.push(GateReason {
                code: "incomplete_scanner_coverage".to_owned(),
                level: GateLevel::SoftBlock,
                summary: "Not every trusted scanner completed, so absence of findings is not \
                          evidence that none exist."
                    .to_owned(),
            });
        }
        match preview {
            PreviewOutcome::Failed => reasons.push(GateReason {
                code: "preview_failed".to_owned(),
                level: GateLevel::SoftBlock,
                summary: "Local verification ran and failed.".to_owned(),
            }),
            PreviewOutcome::NotAttempted => {
                // Only a soft block when the host could actually have verified.
                let runtime_available =
                    capability.is_some_and(|report| report.has(CapabilityKind::ContainerRuntime));
                let summary = if runtime_available {
                    "A container runtime is available but local verification was not run."
                } else {
                    "No container runtime is available, so this deployment was never built or \
                     health-checked locally."
                };
                reasons.push(GateReason {
                    code: "not_locally_verified".to_owned(),
                    level: GateLevel::SoftBlock,
                    summary: summary.to_owned(),
                });
            }
            PreviewOutcome::Passed => {}
        }
        if assessment.plan_digest.is_none() {
            reasons.push(GateReason {
                code: "no_execution_plan".to_owned(),
                level: GateLevel::SoftBlock,
                summary: "No reviewed execution plan was generated for this project.".to_owned(),
            });
        }

        reasons.sort_by(|left, right| {
            right
                .level
                .cmp(&left.level)
                .then_with(|| left.code.cmp(&right.code))
        });
        let level = reasons
            .iter()
            .map(|reason| reason.level)
            .max()
            .unwrap_or(GateLevel::Clear);

        let mut decision = PublicationDecision {
            schema_version: PUBLICATION_DECISION_SCHEMA_VERSION.to_owned(),
            level,
            reasons,
            override_accepted: false,
            overridden_codes: Vec::new(),
            digest: String::new(),
        };
        decision.digest = decision_digest(&decision)?;
        Ok(decision)
    }
}

fn decision_digest(decision: &PublicationDecision) -> Result<String> {
    let payload = DecisionPayload {
        schema_version: &decision.schema_version,
        level: decision.level,
        reasons: &decision.reasons,
        override_accepted: decision.override_accepted,
        overridden_codes: &decision.overridden_codes,
    };
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload)?)
    ))
}

#[cfg(test)]
mod tests {
    use super::{GateLevel, PreviewOutcome, PublicationGate};
    use crate::{
        Confidence, FINDING_SCHEMA_VERSION, Finding, FindingCategory, ReadinessAssessment,
        ScannerKind, Severity,
    };

    fn assessment(scanners: Vec<ScannerKind>, plan: bool) -> ReadinessAssessment {
        ReadinessAssessment {
            schema_version: "1.0".to_owned(),
            policy_version: "test".to_owned(),
            profile_revision: "abc".to_owned(),
            plan_digest: plan.then(|| format!("{:064x}", 1)),
            findings_digest: format!("{:064x}", 2),
            completed_scanners: scanners,
            checks: Vec::new(),
            scores: crate::ReadinessScores {
                build: dimension(),
                security: dimension(),
                deployment: dimension(),
                operational: dimension(),
                overall_percentage: 100,
            },
            blocks_preview: false,
            blocks_publication: false,
            reproduction_digest: String::new(),
        }
    }

    fn dimension() -> crate::DimensionScore {
        crate::DimensionScore {
            earned: 1,
            possible: 1,
            percentage: 100,
        }
    }

    fn finding(category: FindingCategory, severity: Severity, blocks_publication: bool) -> Finding {
        Finding {
            schema_version: FINDING_SCHEMA_VERSION.to_owned(),
            fingerprint: format!("{:064x}", 3),
            scanners: vec![ScannerKind::Trivy],
            category,
            severity,
            confidence: Confidence::High,
            vulnerability_id: None,
            package: None,
            location: None,
            summary: "test".to_owned(),
            recommended_fix: None,
            blocks_preview: false,
            blocks_publication,
            raw_artifact_digests: Vec::new(),
        }
    }

    fn both() -> Vec<ScannerKind> {
        vec![ScannerKind::Trivy, ScannerKind::OsvScanner]
    }

    #[test]
    fn a_complete_verified_run_is_clear() {
        let decision = PublicationGate
            .evaluate(&assessment(both(), true), &[], None, PreviewOutcome::Passed)
            .expect("evaluate");
        assert_eq!(decision.level, GateLevel::Clear);
        assert!(decision.permits_publication());
        decision.validate_digest().expect("digest reproduces");
    }

    #[test]
    fn a_secret_is_a_hard_block_that_no_override_clears() {
        let decision = PublicationGate
            .evaluate(
                &assessment(both(), true),
                &[finding(FindingCategory::Secret, Severity::High, true)],
                None,
                PreviewOutcome::Passed,
            )
            .expect("evaluate");
        assert_eq!(decision.level, GateLevel::HardBlock);
        assert!(!decision.permits_publication());
        assert!(
            decision.accept_override().is_err(),
            "a hard block must refuse an override"
        );
    }

    #[test]
    fn a_critical_vulnerability_is_a_hard_block() {
        let decision = PublicationGate
            .evaluate(
                &assessment(both(), true),
                &[finding(
                    FindingCategory::Vulnerability,
                    Severity::Critical,
                    true,
                )],
                None,
                PreviewOutcome::Passed,
            )
            .expect("evaluate");
        assert_eq!(decision.level, GateLevel::HardBlock);
        assert!(!decision.permits_publication());
    }

    #[test]
    fn missing_coverage_is_a_soft_block_an_override_can_clear() {
        let decision = PublicationGate
            .evaluate(
                &assessment(vec![ScannerKind::Trivy], true),
                &[],
                None,
                PreviewOutcome::Passed,
            )
            .expect("evaluate");
        assert_eq!(decision.level, GateLevel::SoftBlock);
        assert!(!decision.permits_publication());

        let accepted = decision.accept_override().expect("override permitted");
        assert!(accepted.permits_publication());
        assert!(accepted.override_accepted);
        assert_eq!(
            accepted.overridden_codes,
            vec!["incomplete_scanner_coverage".to_owned()],
            "the override must record exactly what was skipped"
        );
        accepted.validate_digest().expect("digest reproduces");
    }

    #[test]
    fn a_host_without_a_runtime_is_soft_blocked_not_refused() {
        // Refusing here would put deployment out of reach for anyone who cannot
        // install a container runtime, without making the project safer.
        let decision = PublicationGate
            .evaluate(
                &assessment(both(), true),
                &[],
                None,
                PreviewOutcome::NotAttempted,
            )
            .expect("evaluate");
        assert_eq!(decision.level, GateLevel::SoftBlock);
        assert!(
            decision
                .reasons_at(GateLevel::SoftBlock)
                .iter()
                .any(|reason| reason.code == "not_locally_verified")
        );
        assert!(decision.accept_override().is_ok());
    }

    #[test]
    fn a_failed_preview_is_a_soft_block() {
        let decision = PublicationGate
            .evaluate(&assessment(both(), true), &[], None, PreviewOutcome::Failed)
            .expect("evaluate");
        assert_eq!(decision.level, GateLevel::SoftBlock);
        assert!(
            decision
                .reasons_at(GateLevel::SoftBlock)
                .iter()
                .any(|reason| reason.code == "preview_failed")
        );
    }

    #[test]
    fn a_hard_block_outranks_any_number_of_soft_blocks() {
        let decision = PublicationGate
            .evaluate(
                &assessment(vec![], false),
                &[finding(FindingCategory::Secret, Severity::Critical, true)],
                None,
                PreviewOutcome::Failed,
            )
            .expect("evaluate");
        assert_eq!(decision.level, GateLevel::HardBlock);
        assert!(decision.reasons.len() > 1);
        // Strongest reason first, so a reader sees the refusal before the noise.
        assert_eq!(decision.reasons[0].level, GateLevel::HardBlock);
        assert!(!decision.permits_publication());
    }

    #[test]
    fn evaluation_is_deterministic() {
        let left = PublicationGate
            .evaluate(
                &assessment(vec![ScannerKind::Trivy], false),
                &[],
                None,
                PreviewOutcome::NotAttempted,
            )
            .expect("evaluate");
        let right = PublicationGate
            .evaluate(
                &assessment(vec![ScannerKind::Trivy], false),
                &[],
                None,
                PreviewOutcome::NotAttempted,
            )
            .expect("evaluate");
        assert_eq!(left, right);
        assert_eq!(left.digest, right.digest);
    }
}
