//! Deterministic readiness policy calculated without a language model.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ApprovalState, CommandStage, DetectionStatus, ExecutionPlan, Finding, FindingCategory,
    ProjectProfile, Result, ScannerKind, Severity, merge_findings,
};

/// Readiness-assessment contract emitted by this release.
pub const READINESS_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`ReadinessAssessment`].
pub const READINESS_SCHEMA_JSON: &str =
    include_str!("../../../schemas/readiness-assessment-v1.schema.json");

/// Deterministic scoring-policy release.
pub const READINESS_POLICY_VERSION: &str = "2026-07-26.1";

/// Readiness score dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessDimension {
    /// Ability to create and validate build output.
    Build,
    /// Security findings and evidence.
    Security,
    /// Deployment configuration and approval controls.
    Deployment,
    /// Runtime limits and reproducibility.
    Operational,
}

/// One explicit, weighted policy decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessCheck {
    /// Stable policy check identifier.
    pub id: String,
    /// Score dimension.
    pub dimension: ReadinessDimension,
    /// Deterministic result.
    pub passed: bool,
    /// Relative contribution within its dimension.
    pub weight: u16,
    /// Human-readable result without model-generated text.
    pub message: String,
}

/// Weighted score for one dimension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionScore {
    /// Earned weight.
    pub earned: u16,
    /// Available weight.
    pub possible: u16,
    /// Integer percentage rounded down.
    pub percentage: u8,
}

/// Four published readiness scores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessScores {
    /// Build score.
    pub build: DimensionScore,
    /// Security score.
    pub security: DimensionScore,
    /// Deployment score.
    pub deployment: DimensionScore,
    /// Operational score.
    pub operational: DimensionScore,
    /// Equal-weight average of the four dimensions.
    pub overall_percentage: u8,
}

#[derive(Serialize)]
struct AssessmentPayload<'a> {
    schema_version: &'a str,
    policy_version: &'a str,
    profile_revision: &'a str,
    plan_digest: Option<&'a str>,
    findings_digest: &'a str,
    completed_scanners: &'a [ScannerKind],
    checks: &'a [ReadinessCheck],
    scores: &'a ReadinessScores,
    blocks_preview: bool,
    blocks_publication: bool,
}

/// Reproducible output of the deterministic readiness policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessAssessment {
    /// Public record schema.
    pub schema_version: String,
    /// Scoring policy release.
    pub policy_version: String,
    /// Repository revision inspected.
    pub profile_revision: String,
    /// Execution-plan digest, when planning succeeded.
    pub plan_digest: Option<String>,
    /// SHA-256 of the sorted normalized findings.
    pub findings_digest: String,
    /// Trusted scanners that completed with schema-valid reports.
    pub completed_scanners: Vec<ScannerKind>,
    /// Every input-backed scoring decision.
    pub checks: Vec<ReadinessCheck>,
    /// Published scores.
    pub scores: ReadinessScores,
    /// Whether policy prevents sandboxed preview.
    pub blocks_preview: bool,
    /// Whether policy prevents publication.
    pub blocks_publication: bool,
    /// SHA-256 over every assessment field except this digest.
    pub reproduction_digest: String,
}

impl ReadinessAssessment {
    /// Recompute and validate the assessment digest.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the digest does not match.
    pub fn validate_digest(&self) -> Result<()> {
        let expected = assessment_digest(self)?;
        if self.reproduction_digest == expected {
            Ok(())
        } else {
            Err(crate::LaunchGuardError::DigestMismatch {
                record: "ReadinessAssessment",
            })
        }
    }
}

/// Stateless deterministic scoring engine.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReadinessEngine;

impl ReadinessEngine {
    /// Calculate scores from a profile, normalized findings, and optional plan.
    ///
    /// # Errors
    ///
    /// Returns an error only when stable JSON hashing fails.
    pub fn assess(
        &self,
        profile: &ProjectProfile,
        findings: &[Finding],
        completed_scanners: &[ScannerKind],
        plan: Option<&ExecutionPlan>,
    ) -> Result<ReadinessAssessment> {
        let findings = merge_findings(findings.to_vec());
        let mut completed_scanners = completed_scanners.to_vec();
        completed_scanners.sort_unstable();
        completed_scanners.dedup();
        let scan_coverage_complete =
            completed_scanners == [ScannerKind::Trivy, ScannerKind::OsvScanner];
        let findings_digest = findings_digest(&findings)?;
        let critical_vulnerability = findings.iter().any(|finding| {
            finding.category == FindingCategory::Vulnerability
                && finding.severity == Severity::Critical
        });
        let blocking_secret = findings.iter().any(|finding| {
            finding.category == FindingCategory::Secret && finding.blocks_publication
        });
        let high_publication_blocker = findings.iter().any(|finding| {
            finding.blocks_publication
                && matches!(finding.severity, Severity::High | Severity::Critical)
        });
        let plan_generated = plan.is_some();
        let has_stage = |stage| {
            plan.is_some_and(|value| value.commands.iter().any(|command| command.stage == stage))
        };
        let plan_has_start_or_output = plan.is_some_and(|value| {
            value
                .commands
                .iter()
                .any(|command| command.stage == CommandStage::Start)
                || !value.expected_outputs.is_empty()
        });
        let checks = vec![
            check(
                "build.classification",
                ReadinessDimension::Build,
                profile.status == DetectionStatus::Detected,
                25,
                "Project classification is unambiguous",
            ),
            check(
                "build.plan",
                ReadinessDimension::Build,
                plan_generated,
                30,
                "Reviewed execution plan is available",
            ),
            check(
                "build.install",
                ReadinessDimension::Build,
                has_stage(CommandStage::Install),
                15,
                "Dependency step is explicit",
            ),
            check(
                "build.validation",
                ReadinessDimension::Build,
                has_stage(CommandStage::Test) || has_stage(CommandStage::Build),
                15,
                "Test or build validation is explicit",
            ),
            check(
                "build.output_or_start",
                ReadinessDimension::Build,
                plan_has_start_or_output,
                15,
                "Expected output or start process is explicit",
            ),
            check(
                "security.no_critical_vulnerabilities",
                ReadinessDimension::Security,
                !critical_vulnerability,
                25,
                "No critical dependency vulnerability blocks preview",
            ),
            check(
                "security.no_blocking_secrets",
                ReadinessDimension::Security,
                !blocking_secret,
                25,
                "No high-confidence secret blocks execution",
            ),
            check(
                "security.no_high_publication_blockers",
                ReadinessDimension::Security,
                !high_publication_blocker,
                15,
                "No high-severity finding blocks publication",
            ),
            check(
                "security.stable_fingerprints",
                ReadinessDimension::Security,
                findings
                    .iter()
                    .all(|finding| finding.fingerprint.len() == 64),
                5,
                "All findings have stable fingerprints",
            ),
            check(
                "security.scanner_coverage",
                ReadinessDimension::Security,
                scan_coverage_complete,
                30,
                "Trivy and OSV-Scanner completed with valid reports",
            ),
            check(
                "deployment.kind",
                ReadinessDimension::Deployment,
                profile.deployment_kind.is_some(),
                20,
                "Deployment behavior is classified",
            ),
            check(
                "deployment.environment_names_only",
                ReadinessDimension::Deployment,
                profile
                    .environment_variables
                    .iter()
                    .all(|variable| !variable.name.is_empty()),
                15,
                "Environment requirements contain names only",
            ),
            check(
                "deployment.health",
                ReadinessDimension::Deployment,
                plan.is_some_and(|value| !value.health_checks.is_empty()),
                25,
                "A deterministic output or health check is present",
            ),
            check(
                "deployment.approval",
                ReadinessDimension::Deployment,
                plan.is_some_and(|value| value.approval_state == ApprovalState::RequiresApproval),
                20,
                "Execution requires approval of the plan digest",
            ),
            check(
                "deployment.default_deny_network",
                ReadinessDimension::Deployment,
                plan.is_some_and(|value| value.network_policy.default_deny),
                20,
                "Sandbox network policy defaults to deny",
            ),
            check(
                "operational.resources",
                ReadinessDimension::Operational,
                plan.is_some_and(|value| {
                    value.resource_limits.cpu_millis > 0
                        && value.resource_limits.memory_mib > 0
                        && value.resource_limits.pids > 0
                }),
                30,
                "CPU, memory, and process ceilings are explicit",
            ),
            check(
                "operational.timeouts",
                ReadinessDimension::Operational,
                plan.is_some_and(|value| {
                    value.resource_limits.timeout_seconds > 0
                        && value
                            .commands
                            .iter()
                            .all(|command| command.timeout_seconds > 0)
                }),
                20,
                "Plan and command deadlines are explicit",
            ),
            check(
                "operational.revision",
                ReadinessDimension::Operational,
                profile.revision != "unversioned",
                20,
                "Repository revision is immutable",
            ),
            check(
                "operational.lifecycle",
                ReadinessDimension::Operational,
                plan_has_start_or_output,
                15,
                "Runtime lifecycle or static artifact is explicit",
            ),
            check(
                "operational.plan_digest",
                ReadinessDimension::Operational,
                plan.is_some_and(|value| value.validate_digest().is_ok()),
                15,
                "Execution plan content digest reproduces",
            ),
        ];
        let scores = scores(&checks);
        let blocks_preview = findings.iter().any(|finding| finding.blocks_preview)
            || profile.status != DetectionStatus::Detected
            || plan.is_none()
            || !scan_coverage_complete;
        let blocks_publication =
            findings.iter().any(|finding| finding.blocks_publication) || blocks_preview;
        let mut assessment = ReadinessAssessment {
            schema_version: READINESS_SCHEMA_VERSION.to_owned(),
            policy_version: READINESS_POLICY_VERSION.to_owned(),
            profile_revision: profile.revision.clone(),
            plan_digest: plan.map(|value| value.digest.clone()),
            findings_digest,
            completed_scanners,
            checks,
            scores,
            blocks_preview,
            blocks_publication,
            reproduction_digest: String::new(),
        };
        assessment.reproduction_digest = assessment_digest(&assessment)?;
        Ok(assessment)
    }
}

/// Hash the deterministic security content of the merged findings.
///
/// `raw_artifact_digests` points at stored raw reports, and scanners embed a
/// per-run report identifier and timestamp, so those digests legitimately
/// differ between two runs over an unchanged project. Hashing them would make
/// an otherwise reproducible assessment fail to reproduce. Provenance stays on
/// each finding; it just does not participate in the digest.
fn findings_digest(findings: &[Finding]) -> Result<String> {
    let mut value = serde_json::to_value(findings)?;
    if let Some(items) = value.as_array_mut() {
        for item in items.iter_mut() {
            if let Some(object) = item.as_object_mut() {
                object.remove("raw_artifact_digests");
            }
        }
    }
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)))
}

fn check(
    id: &str,
    dimension: ReadinessDimension,
    passed: bool,
    weight: u16,
    message: &str,
) -> ReadinessCheck {
    ReadinessCheck {
        id: id.to_owned(),
        dimension,
        passed,
        weight,
        message: message.to_owned(),
    }
}

fn scores(checks: &[ReadinessCheck]) -> ReadinessScores {
    let build = dimension_score(checks, ReadinessDimension::Build);
    let security = dimension_score(checks, ReadinessDimension::Security);
    let deployment = dimension_score(checks, ReadinessDimension::Deployment);
    let operational = dimension_score(checks, ReadinessDimension::Operational);
    let sum = u16::from(build.percentage)
        + u16::from(security.percentage)
        + u16::from(deployment.percentage)
        + u16::from(operational.percentage);
    ReadinessScores {
        build,
        security,
        deployment,
        operational,
        overall_percentage: u8::try_from(sum / 4).unwrap_or(100),
    }
}

fn dimension_score(checks: &[ReadinessCheck], dimension: ReadinessDimension) -> DimensionScore {
    let relevant = checks.iter().filter(|check| check.dimension == dimension);
    let possible: u16 = relevant.clone().map(|check| check.weight).sum();
    let earned: u16 = relevant
        .filter(|check| check.passed)
        .map(|check| check.weight)
        .sum();
    let percentage = earned
        .saturating_mul(100)
        .checked_div(possible)
        .map_or(0, |value| u8::try_from(value).unwrap_or(100));
    DimensionScore {
        earned,
        possible,
        percentage,
    }
}

fn assessment_digest(assessment: &ReadinessAssessment) -> Result<String> {
    let payload = AssessmentPayload {
        schema_version: &assessment.schema_version,
        policy_version: &assessment.policy_version,
        profile_revision: &assessment.profile_revision,
        plan_digest: assessment.plan_digest.as_deref(),
        findings_digest: &assessment.findings_digest,
        completed_scanners: &assessment.completed_scanners,
        checks: &assessment.checks,
        scores: &assessment.scores,
        blocks_preview: assessment.blocks_preview,
        blocks_publication: assessment.blocks_publication,
    };
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload)?)
    ))
}
