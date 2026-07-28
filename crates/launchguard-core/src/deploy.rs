//! Deployment intent: where a project should go and what it needs to run there.
//!
//! Intent is captured before any credential exists and before any provider is
//! contacted. Candidates are proposed from detector evidence and confirmed by a
//! person; `LaunchGuard` never selects a provider silently.
//!
//! Environment variable values are never captured. Phase 1 collects names only,
//! so there is no value in the engine to leak into a generated artifact.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ApprovalState, DeploymentKind, DetectionStatus, Framework, LaunchGuardError, ProjectProfile,
    Result,
};

/// Deployment-intent contract emitted by this release.
pub const DEPLOYMENT_INTENT_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`DeploymentIntent`].
pub const DEPLOYMENT_INTENT_SCHEMA_JSON: &str =
    include_str!("../../../schemas/deployment-intent-v1.schema.json");

/// A deployment provider supported by this release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Cloudflare Pages, static output.
    CloudflarePages,
    /// Netlify, static output.
    Netlify,
    /// Render, server output.
    Render,
}

impl Provider {
    /// Stable identifier used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudflarePages => "cloudflare_pages",
            Self::Netlify => "netlify",
            Self::Render => "render",
        }
    }

    /// Human-readable provider name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::CloudflarePages => "Cloudflare Pages",
            Self::Netlify => "Netlify",
            Self::Render => "Render",
        }
    }

    /// Deployment behavior this provider serves in v1.
    #[must_use]
    pub const fn deployment_kind(self) -> DeploymentKind {
        match self {
            Self::CloudflarePages | Self::Netlify => DeploymentKind::Static,
            Self::Render => DeploymentKind::Server,
        }
    }

    /// Every provider this release can generate configuration for.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::CloudflarePages, Self::Netlify, Self::Render]
    }
}

/// A provider constraint the user must see before publishing.
///
/// Provider terms change, so a limit carries the documentation link that proves
/// it rather than asserting a value this release cannot keep current. Unknown
/// cost is shown as unknown, never as zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderLimit {
    /// Short description of the constraint.
    pub summary: String,
    /// Official documentation to verify it against.
    pub documentation_url: String,
}

#[derive(Serialize)]
struct IntentPayload<'a> {
    schema_version: &'a str,
    provider: Provider,
    deployment_kind: DeploymentKind,
    framework: Framework,
    component_root: &'a str,
    build_command: Option<&'a str>,
    output_directory: Option<&'a str>,
    service_port: Option<u16>,
    environment_variable_names: &'a [String],
    secret_variable_names: &'a [String],
    custom_domain: Option<&'a str>,
    provider_limits: &'a [ProviderLimit],
    approval_state: ApprovalState,
}

/// Where a project should be published and what it needs there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentIntent {
    /// Public record schema.
    pub schema_version: String,
    /// SHA-256 over every field except this digest.
    pub digest: String,
    /// Selected provider.
    pub provider: Provider,
    /// Static or server behavior.
    pub deployment_kind: DeploymentKind,
    /// Detected framework.
    pub framework: Framework,
    /// Repository-relative component root.
    pub component_root: String,
    /// Build command the provider should run.
    pub build_command: Option<String>,
    /// Repository-relative directory the build writes.
    pub output_directory: Option<String>,
    /// Port a server deployment listens on.
    pub service_port: Option<u16>,
    /// Non-secret environment variable names. Values are never captured.
    pub environment_variable_names: Vec<String>,
    /// Names that must be set in the provider interface rather than committed.
    pub secret_variable_names: Vec<String>,
    /// Optional custom domain.
    pub custom_domain: Option<String>,
    /// Constraints shown to the user at confirmation.
    pub provider_limits: Vec<ProviderLimit>,
    /// Explicit human gate, matching the execution-plan contract.
    pub approval_state: ApprovalState,
}

impl DeploymentIntent {
    /// Recompute and validate the embedded content digest.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the digest does not match.
    pub fn validate_digest(&self) -> Result<()> {
        if self.digest == intent_digest(self)? {
            Ok(())
        } else {
            Err(LaunchGuardError::DigestMismatch {
                record: "DeploymentIntent",
            })
        }
    }
}

/// A provider candidate proposed from detector evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCandidate {
    /// Candidate provider.
    pub provider: Provider,
    /// Why this provider suits the detected project.
    pub rationale: String,
    /// Constraints the user should weigh before choosing.
    pub limits: Vec<ProviderLimit>,
}

/// Proposes providers and builds intent from a detected profile.
#[derive(Debug, Default, Clone, Copy)]
pub struct IntentGenerator;

impl IntentGenerator {
    /// Providers that can serve this profile, best fit first.
    ///
    /// # Errors
    ///
    /// Fails closed for an ambiguous profile or one with no deployment kind.
    pub fn candidates(&self, profile: &ProjectProfile) -> Result<Vec<ProviderCandidate>> {
        profile.validate_schema()?;
        if profile.status != DetectionStatus::Detected {
            return Err(LaunchGuardError::DeploymentIntentUnavailable(
                "project classification requires confirmation".to_owned(),
            ));
        }
        let kind = profile.deployment_kind.ok_or_else(|| {
            LaunchGuardError::DeploymentIntentUnavailable(
                "detected profile has no deployment kind".to_owned(),
            )
        })?;

        let candidates: Vec<ProviderCandidate> = Provider::all()
            .into_iter()
            .filter(|provider| provider.deployment_kind() == kind)
            .map(|provider| ProviderCandidate {
                provider,
                rationale: rationale(provider, kind),
                limits: limits(provider),
            })
            .collect();

        if candidates.is_empty() {
            return Err(LaunchGuardError::DeploymentIntentUnavailable(format!(
                "no reviewed provider serves {kind:?} deployments"
            )));
        }
        Ok(candidates)
    }

    /// Build a content-addressed intent for one confirmed provider.
    ///
    /// # Errors
    ///
    /// Fails closed when the provider cannot serve the detected deployment kind
    /// or the profile lacks facts the provider requires.
    pub fn generate(
        &self,
        profile: &ProjectProfile,
        provider: Provider,
        custom_domain: Option<String>,
    ) -> Result<DeploymentIntent> {
        profile.validate_schema()?;
        if profile.status != DetectionStatus::Detected {
            return Err(LaunchGuardError::DeploymentIntentUnavailable(
                "project classification requires confirmation".to_owned(),
            ));
        }
        let framework = profile.framework.ok_or_else(|| {
            LaunchGuardError::DeploymentIntentUnavailable(
                "detected profile has no framework".to_owned(),
            )
        })?;
        let deployment_kind = profile.deployment_kind.ok_or_else(|| {
            LaunchGuardError::DeploymentIntentUnavailable(
                "detected profile has no deployment kind".to_owned(),
            )
        })?;
        if provider.deployment_kind() != deployment_kind {
            return Err(LaunchGuardError::DeploymentIntentUnavailable(format!(
                "{} serves {:?} deployments, but this project is {deployment_kind:?}",
                provider.display_name(),
                provider.deployment_kind()
            )));
        }
        if deployment_kind == DeploymentKind::Static && profile.output_directory.is_none() {
            return Err(LaunchGuardError::DeploymentIntentUnavailable(
                "a static deployment needs a known build output directory".to_owned(),
            ));
        }

        let component_root = profile
            .components
            .first()
            .map_or_else(|| ".".to_owned(), |component| component.path.clone());

        // Split observed names so the user knows what to commit and what to set
        // in the provider interface. Values were never collected.
        let mut environment_variable_names = Vec::new();
        let mut secret_variable_names = Vec::new();
        for variable in &profile.environment_variables {
            if looks_secret(&variable.name) {
                secret_variable_names.push(variable.name.clone());
            } else {
                environment_variable_names.push(variable.name.clone());
            }
        }
        environment_variable_names.sort();
        environment_variable_names.dedup();
        secret_variable_names.sort();
        secret_variable_names.dedup();

        let service_port = if deployment_kind == DeploymentKind::Server {
            Some(profile.detected_ports.first().copied().unwrap_or(8080))
        } else {
            None
        };

        let mut intent = DeploymentIntent {
            schema_version: DEPLOYMENT_INTENT_SCHEMA_VERSION.to_owned(),
            digest: String::new(),
            provider,
            deployment_kind,
            framework,
            component_root,
            build_command: profile.build_command.clone(),
            output_directory: profile.output_directory.clone(),
            service_port,
            environment_variable_names,
            secret_variable_names,
            custom_domain,
            provider_limits: limits(provider),
            approval_state: ApprovalState::RequiresApproval,
        };
        intent.digest = intent_digest(&intent)?;
        Ok(intent)
    }
}

/// Names that conventionally hold credentials, so they are never committed.
fn looks_secret(name: &str) -> bool {
    const MARKERS: [&str; 8] = [
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "PRIVATE_KEY",
        "API_KEY",
        "ACCESS_KEY",
    ];
    let upper = name.to_ascii_uppercase();
    MARKERS.iter().any(|marker| upper.contains(marker))
}

fn rationale(provider: Provider, kind: DeploymentKind) -> String {
    match (provider, kind) {
        (Provider::CloudflarePages, _) => {
            "Static hosting with a free plan suited to portfolio and preview sites".to_owned()
        }
        (Provider::Netlify, _) => {
            "Static hosting with a free plan bounded by bandwidth and build minutes".to_owned()
        }
        (Provider::Render, _) => {
            "Container hosting for a long-running service, free instances sleep when idle"
                .to_owned()
        }
    }
}

/// Constraints a user must see before publishing.
///
/// Each carries its documentation link rather than a value this release cannot
/// keep current, because provider terms change independently of `LaunchGuard`.
fn limits(provider: Provider) -> Vec<ProviderLimit> {
    match provider {
        Provider::CloudflarePages => vec![
            ProviderLimit {
                summary: "Free plan caps builds per month and files per deployment".to_owned(),
                documentation_url: "https://developers.cloudflare.com/pages/platform/limits/"
                    .to_owned(),
            },
            ProviderLimit {
                summary: "Verify current pricing and free-tier terms before publishing".to_owned(),
                documentation_url: "https://developers.cloudflare.com/pages/".to_owned(),
            },
        ],
        Provider::Netlify => vec![
            ProviderLimit {
                summary: "Free plan caps bandwidth and build minutes per month".to_owned(),
                documentation_url:
                    "https://docs.netlify.com/accounts-and-billing/billing-and-usage/".to_owned(),
            },
            ProviderLimit {
                summary: "Verify current pricing and free-tier terms before publishing".to_owned(),
                documentation_url: "https://www.netlify.com/pricing/".to_owned(),
            },
        ],
        Provider::Render => vec![
            ProviderLimit {
                summary: "Free instances sleep when idle, so the first request after \
                          inactivity is slow"
                    .to_owned(),
                documentation_url: "https://render.com/docs/free".to_owned(),
            },
            ProviderLimit {
                summary: "Free instances use an ephemeral filesystem; written files do not \
                          survive a restart"
                    .to_owned(),
                documentation_url: "https://render.com/docs/free".to_owned(),
            },
            ProviderLimit {
                summary: "An always-on instance is a paid plan; verify current pricing".to_owned(),
                documentation_url: "https://render.com/pricing".to_owned(),
            },
        ],
    }
}

fn intent_digest(intent: &DeploymentIntent) -> Result<String> {
    let payload = IntentPayload {
        schema_version: &intent.schema_version,
        provider: intent.provider,
        deployment_kind: intent.deployment_kind,
        framework: intent.framework,
        component_root: &intent.component_root,
        build_command: intent.build_command.as_deref(),
        output_directory: intent.output_directory.as_deref(),
        service_port: intent.service_port,
        environment_variable_names: &intent.environment_variable_names,
        secret_variable_names: &intent.secret_variable_names,
        custom_domain: intent.custom_domain.as_deref(),
        provider_limits: &intent.provider_limits,
        approval_state: intent.approval_state,
    };
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload)?)
    ))
}

#[cfg(test)]
mod tests {
    use super::{Provider, looks_secret};
    use crate::DeploymentKind;

    #[test]
    fn providers_are_matched_to_deployment_behavior() {
        assert_eq!(
            Provider::CloudflarePages.deployment_kind(),
            DeploymentKind::Static
        );
        assert_eq!(Provider::Netlify.deployment_kind(), DeploymentKind::Static);
        assert_eq!(Provider::Render.deployment_kind(), DeploymentKind::Server);
    }

    #[test]
    fn credential_shaped_names_are_separated_from_plain_configuration() {
        for name in [
            "API_SECRET",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "STRIPE_API_KEY",
            "AWS_ACCESS_KEY_ID",
            "SERVICE_PRIVATE_KEY",
            "vite_api_key",
        ] {
            assert!(looks_secret(name), "{name} should be treated as a secret");
        }
        for name in ["PORT", "NODE_ENV", "VITE_API_URL", "LOG_LEVEL", "HOST"] {
            assert!(!looks_secret(name), "{name} is plain configuration");
        }
    }

    #[test]
    fn every_provider_publishes_a_verifiable_limit() {
        for provider in Provider::all() {
            let limits = super::limits(provider);
            assert!(!limits.is_empty(), "{provider:?} must publish limits");
            for limit in limits {
                assert!(
                    limit.documentation_url.starts_with("https://"),
                    "{provider:?} limits must link official documentation"
                );
                assert!(!limit.summary.is_empty());
            }
        }
    }
}
