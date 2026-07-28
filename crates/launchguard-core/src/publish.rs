//! Pull-request planning.
//!
//! Everything a person sees before approving publication is assembled here,
//! content-addressed so the approval binds to exactly what will be pushed.
//! Planning contacts no network and needs no credential; it only describes what
//! publication would do.
//!
//! The branch name derives from the deployment intent digest, so re-running for
//! an unchanged project targets the same branch instead of opening a second
//! pull request.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    DeploymentIntent, Finding, GateLevel, GeneratedFile, LaunchGuardError, ProjectProfile,
    PublicationDecision, ReadinessAssessment, Result, ScannerProvenance, Severity,
};

/// Pull-request plan contract emitted by this release.
pub const PULL_REQUEST_PLAN_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`PullRequestPlan`].
pub const PULL_REQUEST_PLAN_SCHEMA_JSON: &str =
    include_str!("../../../schemas/pull-request-plan-v1.schema.json");

/// A repository permission publication needs, and what it allows.
///
/// The security model requires showing the exact scopes, the repository they
/// apply to, and the operations they permit, before a user authorizes anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedScope {
    /// Provider scope identifier.
    pub scope: String,
    /// What this scope lets `LaunchGuard` do.
    pub permits: String,
}

impl RequestedScope {
    /// The narrowest scope set that can open a pull request on a public repository.
    #[must_use]
    pub fn for_public_repository() -> Vec<Self> {
        vec![Self {
            scope: "public_repo".to_owned(),
            permits: "Create a branch, commit generated files, and open a pull request on \
                      public repositories. It cannot read private repositories."
                .to_owned(),
        }]
    }

    /// The scope set required when the target repository is private.
    #[must_use]
    pub fn for_private_repository() -> Vec<Self> {
        vec![Self {
            scope: "repo".to_owned(),
            permits: "Create a branch, commit generated files, and open a pull request. GitHub \
                      does not offer a narrower scope for private repositories, so this also \
                      grants read access to your private repository contents."
                .to_owned(),
        }]
    }
}

#[derive(Serialize)]
struct PlanPayload<'a> {
    schema_version: &'a str,
    repository: &'a str,
    base_branch: &'a str,
    head_branch: &'a str,
    title: &'a str,
    body: &'a str,
    files: &'a [GeneratedFile],
    requested_scopes: &'a [RequestedScope],
    revision: &'a str,
    intent_digest: &'a str,
    decision_digest: &'a str,
}

/// Exactly what publication would push, and under what permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequestPlan {
    /// Public record schema.
    pub schema_version: String,
    /// Target repository as `owner/name`.
    pub repository: String,
    /// Branch the pull request merges into.
    pub base_branch: String,
    /// Branch `LaunchGuard` creates, derived from the intent digest.
    pub head_branch: String,
    /// Pull-request title.
    pub title: String,
    /// Pull-request body, containing the full audit summary.
    pub body: String,
    /// Files the commit would add, with their digests.
    pub files: Vec<GeneratedFile>,
    /// Permissions publication requires.
    pub requested_scopes: Vec<RequestedScope>,
    /// Repository revision the audit inspected.
    pub revision: String,
    /// Deployment intent this publishes.
    pub intent_digest: String,
    /// Publication decision authorizing this.
    pub decision_digest: String,
    /// SHA-256 over every field except this digest.
    pub digest: String,
}

impl PullRequestPlan {
    /// Recompute and validate the embedded digest.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the digest does not match.
    pub fn validate_digest(&self) -> Result<()> {
        if self.digest == plan_digest(self)? {
            Ok(())
        } else {
            Err(LaunchGuardError::DigestMismatch {
                record: "PullRequestPlan",
            })
        }
    }
}

/// Inputs a pull-request plan is assembled from.
pub struct PublicationContext<'a> {
    /// Target repository as `owner/name`.
    pub repository: &'a str,
    /// Branch to merge into.
    pub base_branch: &'a str,
    /// Whether the target repository is private, which widens the scope needed.
    pub private_repository: bool,
    /// Detector output for the revision.
    pub profile: &'a ProjectProfile,
    /// Confirmed deployment intent.
    pub intent: &'a DeploymentIntent,
    /// Artifacts to commit.
    pub files: &'a [GeneratedFile],
    /// Deterministic readiness assessment.
    pub readiness: &'a ReadinessAssessment,
    /// Normalized findings.
    pub findings: &'a [Finding],
    /// Scanner build and database identity.
    pub provenance: &'a [ScannerProvenance],
    /// Gate decision authorizing publication.
    pub decision: &'a PublicationDecision,
}

/// Builds pull-request plans without contacting a network.
#[derive(Debug, Default, Clone, Copy)]
pub struct PullRequestPlanner;

impl PullRequestPlanner {
    /// Describe the pull request publication would open.
    ///
    /// # Errors
    ///
    /// Refuses when the decision does not permit publication, when the intent
    /// digest does not reproduce, or when there is nothing to commit.
    pub fn plan(&self, context: &PublicationContext<'_>) -> Result<PullRequestPlan> {
        if !context.decision.permits_publication() {
            return Err(LaunchGuardError::PublicationRefused(format!(
                "policy level is {} and no accepted override applies",
                context.decision.level.as_str()
            )));
        }
        context.intent.validate_digest()?;
        context.decision.validate_digest()?;
        if context.files.is_empty() {
            return Err(LaunchGuardError::PublicationRefused(
                "there is nothing to publish".to_owned(),
            ));
        }
        for file in context.files {
            file.validate_digest()?;
        }
        if context.repository.split('/').count() != 2
            || context.repository.split('/').any(str::is_empty)
        {
            return Err(LaunchGuardError::PublicationRefused(format!(
                "repository must be owner/name, got {}",
                context.repository
            )));
        }

        // Deriving the branch from the intent digest makes a repeated run target
        // the same branch instead of opening a second pull request.
        let head_branch = format!(
            "launchguard/deploy-{}-{}",
            context.intent.provider.as_str().replace('_', "-"),
            &context.intent.digest[..12]
        );

        let title = format!(
            "Add {} deployment configuration",
            context.intent.provider.display_name()
        );
        let body = compose_body(context, &head_branch);

        let mut plan = PullRequestPlan {
            schema_version: PULL_REQUEST_PLAN_SCHEMA_VERSION.to_owned(),
            repository: context.repository.to_owned(),
            base_branch: context.base_branch.to_owned(),
            head_branch,
            title,
            body,
            files: context.files.to_vec(),
            requested_scopes: if context.private_repository {
                RequestedScope::for_private_repository()
            } else {
                RequestedScope::for_public_repository()
            },
            revision: context.profile.revision.clone(),
            intent_digest: context.intent.digest.clone(),
            decision_digest: context.decision.digest.clone(),
            digest: String::new(),
        };
        plan.digest = plan_digest(&plan)?;
        Ok(plan)
    }
}

/// Compose the pull-request body.
///
/// The security model requires the reviewer receive the generated-file
/// inventory, findings, verification results, unresolved blockers, requested
/// permissions, and a reproducibility record. Anything skipped is stated
/// plainly rather than omitted.
fn compose_body(context: &PublicationContext<'_>, head_branch: &str) -> String {
    let mut body = String::new();
    let intent = context.intent;

    writeln!(
        body,
        "LaunchGuard generated deployment configuration for **{}** from revision `{}`.\n",
        intent.provider.display_name(),
        context.profile.revision
    )
    .expect("writing to String cannot fail");

    // Unresolved blockers first, so a reviewer never has to scroll to find them.
    let soft = context.decision.reasons_at(GateLevel::SoftBlock);
    if context.decision.override_accepted && !soft.is_empty() {
        writeln!(body, "## Accepted without verification\n").expect("write");
        writeln!(
            body,
            "This pull request was opened with an explicit override. The following were **not** \
             verified:\n"
        )
        .expect("write");
        for reason in &soft {
            writeln!(body, "- **{}** — {}", reason.code, reason.summary).expect("write");
        }
        writeln!(body).expect("write");
    }

    writeln!(body, "## Generated files\n").expect("write");
    for file in context.files {
        writeln!(
            body,
            "- `{}` — {:?}, `sha256:{}`",
            file.path,
            file.kind,
            &file.digest[..12]
        )
        .expect("write");
    }

    writeln!(body, "\n## Readiness\n").expect("write");
    let scores = &context.readiness.scores;
    writeln!(
        body,
        "| Build | Security | Deployment | Operational |\n| ---: | ---: | ---: | ---: |\n\
         | {}% | {}% | {}% | {}% |",
        scores.build.percentage,
        scores.security.percentage,
        scores.deployment.percentage,
        scores.operational.percentage
    )
    .expect("write");

    writeln!(body, "\n## Security findings\n").expect("write");
    if context.readiness.completed_scanners.is_empty() {
        writeln!(
            body,
            "No scanner completed, so this pull request carries no vulnerability evidence."
        )
        .expect("write");
    } else {
        let critical = count(context.findings, Severity::Critical);
        let high = count(context.findings, Severity::High);
        writeln!(
            body,
            "{} finding(s) from {} scanner(s): {critical} critical, {high} high.",
            context.findings.len(),
            context.readiness.completed_scanners.len()
        )
        .expect("write");
        writeln!(
            body,
            "\nAbsence of findings is not evidence that none exist."
        )
        .expect("write");
    }

    if !intent.secret_variable_names.is_empty() {
        writeln!(body, "\n## Set these in the provider dashboard\n").expect("write");
        writeln!(
            body,
            "These names look like credentials. They are **not** committed and have no values in \
             this pull request:\n"
        )
        .expect("write");
        for name in &intent.secret_variable_names {
            writeln!(body, "- `{name}`").expect("write");
        }
    }

    writeln!(body, "\n## Provider limits\n").expect("write");
    for limit in &intent.provider_limits {
        writeln!(body, "- {} — {}", limit.summary, limit.documentation_url).expect("write");
    }

    writeln!(body, "\n## Reproducibility\n").expect("write");
    writeln!(body, "- Revision: `{}`", context.profile.revision).expect("write");
    writeln!(body, "- Intent digest: `{}`", intent.digest).expect("write");
    writeln!(
        body,
        "- Readiness digest: `{}`",
        context.readiness.reproduction_digest
    )
    .expect("write");
    if let Some(plan_digest) = &context.readiness.plan_digest {
        writeln!(body, "- Execution plan digest: `{plan_digest}`").expect("write");
    }
    for entry in context.provenance {
        let database = entry
            .vulnerability_database_updated_at
            .as_deref()
            .map_or_else(String::new, |value| format!(", database {value}"));
        writeln!(
            body,
            "- Scanner: {} {}{database}",
            entry.scanner.as_str(),
            entry.version
        )
        .expect("write");
    }

    writeln!(body, "\n## Rollback\n").expect("write");
    writeln!(
        body,
        "Close this pull request without merging, or delete the `{head_branch}` branch. Nothing \
         was deployed and no cloud resource was created; merging is what hands the configuration \
         to {}.",
        intent.provider.display_name()
    )
    .expect("write");

    writeln!(
        body,
        "\n---\nLaunchGuard has not executed this project's code. A passing readiness score is \
         not a security or production-readiness claim."
    )
    .expect("write");

    body
}

fn count(findings: &[Finding], severity: Severity) -> usize {
    findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .count()
}

fn plan_digest(plan: &PullRequestPlan) -> Result<String> {
    let payload = PlanPayload {
        schema_version: &plan.schema_version,
        repository: &plan.repository,
        base_branch: &plan.base_branch,
        head_branch: &plan.head_branch,
        title: &plan.title,
        body: &plan.body,
        files: &plan.files,
        requested_scopes: &plan.requested_scopes,
        revision: &plan.revision,
        intent_digest: &plan.intent_digest,
        decision_digest: &plan.decision_digest,
    };
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload)?)
    ))
}
