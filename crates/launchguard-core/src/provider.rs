//! Provider adapters that generate deployment configuration from reviewed
//! templates.
//!
//! Generation contacts no provider, creates no cloud resource, and needs no
//! credential. Every artifact is validated locally before it is offered for
//! publication, and no artifact ever carries an environment variable value:
//! only names are known to the engine, and secret names become placeholders.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DeploymentIntent, DeploymentKind, Framework, LaunchGuardError, Provider, Result};

/// Generated-file contract emitted by this release.
pub const GENERATED_FILE_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`GeneratedFile`].
pub const GENERATED_FILE_SCHEMA_JSON: &str =
    include_str!("../../../schemas/generated-file-v1.schema.json");

/// Purpose of a generated artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedFileKind {
    /// Container build definition.
    Dockerfile,
    /// Container build exclusions.
    DockerIgnore,
    /// Environment variable template containing names only.
    EnvironmentTemplate,
    /// Provider-specific deployment manifest.
    ProviderManifest,
}

/// One file an adapter proposes adding to the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedFile {
    /// Public record schema.
    pub schema_version: String,
    /// Repository-relative destination path.
    pub path: String,
    /// Artifact purpose.
    pub kind: GeneratedFileKind,
    /// Exact file contents.
    pub contents: String,
    /// SHA-256 over the contents.
    pub digest: String,
}

impl GeneratedFile {
    fn new(path: impl Into<String>, kind: GeneratedFileKind, contents: impl Into<String>) -> Self {
        let contents = contents.into();
        Self {
            schema_version: GENERATED_FILE_SCHEMA_VERSION.to_owned(),
            path: path.into(),
            kind,
            digest: format!("{:x}", Sha256::digest(contents.as_bytes())),
            contents,
        }
    }

    /// Recompute and validate the content digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the digest does not reproduce.
    pub fn validate_digest(&self) -> Result<()> {
        if self.digest == format!("{:x}", Sha256::digest(self.contents.as_bytes())) {
            Ok(())
        } else {
            Err(LaunchGuardError::DigestMismatch {
                record: "GeneratedFile",
            })
        }
    }
}

/// Generates deployment configuration for one provider.
///
/// Implementations must be deterministic: the same intent produces byte-identical
/// files, so a digest can bind an approval.
pub trait ProviderAdapter {
    /// Provider this adapter serves.
    fn provider(&self) -> Provider;

    /// Generate every artifact this provider needs.
    ///
    /// # Errors
    ///
    /// Fails closed when the intent lacks a fact the provider requires.
    fn generate(&self, intent: &DeploymentIntent) -> Result<Vec<GeneratedFile>>;
}

/// Select the adapter for a provider.
#[must_use]
pub fn adapter_for(provider: Provider) -> Box<dyn ProviderAdapter> {
    match provider {
        Provider::CloudflarePages => Box::new(CloudflarePagesAdapter),
        Provider::Netlify => Box::new(NetlifyAdapter),
        Provider::Render => Box::new(RenderAdapter),
    }
}

/// Generate and locally validate configuration for an approved intent.
///
/// # Errors
///
/// Returns an error when generation fails or an artifact fails validation.
pub fn generate_configuration(intent: &DeploymentIntent) -> Result<Vec<GeneratedFile>> {
    intent.validate_digest()?;
    let files = adapter_for(intent.provider).generate(intent)?;
    validate_generated(&files, intent)?;
    Ok(files)
}

/// Validate artifacts without contacting a provider.
///
/// # Errors
///
/// Returns an error when an artifact is empty, escapes the repository, carries a
/// duplicate path, or fails its digest.
pub fn validate_generated(files: &[GeneratedFile], intent: &DeploymentIntent) -> Result<()> {
    if files.is_empty() {
        return Err(LaunchGuardError::GeneratedArtifact {
            path: String::new(),
            message: "adapter produced no files".to_owned(),
        });
    }
    let mut seen: Vec<&str> = Vec::new();
    for file in files {
        file.validate_digest()?;
        let path = file.path.as_str();
        if path.is_empty() || file.contents.is_empty() {
            return Err(LaunchGuardError::GeneratedArtifact {
                path: path.to_owned(),
                message: "an artifact must have a path and contents".to_owned(),
            });
        }
        // A generated path is always inside the repository.
        if path.starts_with('/') || path.contains("..") || path.contains('\\') {
            return Err(LaunchGuardError::GeneratedArtifact {
                path: path.to_owned(),
                message: "artifact paths must stay inside the repository".to_owned(),
            });
        }
        if seen.contains(&path) {
            return Err(LaunchGuardError::GeneratedArtifact {
                path: path.to_owned(),
                message: "two artifacts claim the same path".to_owned(),
            });
        }
        seen.push(path);

        // A manifest the provider cannot parse is a defect worth catching here
        // rather than at the provider's build step.
        if path.ends_with(".toml")
            && let Err(error) = file.contents.parse::<toml::Table>()
        {
            return Err(LaunchGuardError::GeneratedArtifact {
                path: path.to_owned(),
                message: format!("generated TOML does not parse: {error}"),
            });
        }

        // A secret name may appear as a placeholder; a value never can, and the
        // engine holds none, so an assignment to a secret is a template defect.
        for secret in &intent.secret_variable_names {
            let assigned = format!("{secret}=");
            if let Some(index) = file.contents.find(&assigned) {
                let remainder = &file.contents[index + assigned.len()..];
                let value = remainder.lines().next().unwrap_or_default().trim();
                if !value.is_empty() {
                    return Err(LaunchGuardError::GeneratedArtifact {
                        path: path.to_owned(),
                        message: format!("{secret} must not be assigned a value"),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Shared environment template listing names only.
fn environment_template(intent: &DeploymentIntent) -> GeneratedFile {
    let mut contents = String::from(
        "# Environment variables observed in this project.\n\
         # Values are never collected by LaunchGuard. Fill these in locally.\n",
    );
    for name in &intent.environment_variable_names {
        writeln!(contents, "{name}=").expect("writing to String cannot fail");
    }
    if !intent.secret_variable_names.is_empty() {
        contents.push_str("\n# Set these in the provider dashboard rather than committing them.\n");
        for name in &intent.secret_variable_names {
            writeln!(contents, "{name}=").expect("writing to String cannot fail");
        }
    }
    GeneratedFile::new(
        join(&intent.component_root, ".env.example"),
        GeneratedFileKind::EnvironmentTemplate,
        contents,
    )
}

fn join(root: &str, name: &str) -> String {
    if root.is_empty() || root == "." {
        name.to_owned()
    } else {
        format!("{}/{name}", root.trim_end_matches('/'))
    }
}

fn require_output_directory(intent: &DeploymentIntent) -> Result<&str> {
    intent
        .output_directory
        .as_deref()
        .ok_or_else(|| LaunchGuardError::GeneratedArtifact {
            path: String::new(),
            message: "a static deployment needs a build output directory".to_owned(),
        })
}

/// Cloudflare Pages.
struct CloudflarePagesAdapter;

impl ProviderAdapter for CloudflarePagesAdapter {
    fn provider(&self) -> Provider {
        Provider::CloudflarePages
    }

    fn generate(&self, intent: &DeploymentIntent) -> Result<Vec<GeneratedFile>> {
        let output = require_output_directory(intent)?;
        let build = intent.build_command.as_deref().unwrap_or("npm run build");
        let manifest = format!(
            "# Cloudflare Pages configuration generated by LaunchGuard.\n\
             # Review before publishing. Verify current limits at\n\
             # https://developers.cloudflare.com/pages/platform/limits/\n\
             name = \"launchguard-site\"\n\
             pages_build_output_dir = \"{output}\"\n\
             compatibility_date = \"2026-07-28\"\n\
             \n\
             # Build command configured in the Pages project settings:\n\
             #   {build}\n"
        );
        Ok(vec![
            GeneratedFile::new(
                join(&intent.component_root, "wrangler.toml"),
                GeneratedFileKind::ProviderManifest,
                manifest,
            ),
            environment_template(intent),
        ])
    }
}

/// Netlify.
struct NetlifyAdapter;

impl ProviderAdapter for NetlifyAdapter {
    fn provider(&self) -> Provider {
        Provider::Netlify
    }

    fn generate(&self, intent: &DeploymentIntent) -> Result<Vec<GeneratedFile>> {
        let output = require_output_directory(intent)?;
        let build = intent.build_command.as_deref().unwrap_or("npm run build");
        let manifest = format!(
            "# Netlify configuration generated by LaunchGuard.\n\
             # Review before publishing. Verify current limits at\n\
             # https://docs.netlify.com/accounts-and-billing/billing-and-usage/\n\
             [build]\n\
             \x20\x20command = \"{build}\"\n\
             \x20\x20publish = \"{output}\"\n\
             \n\
             [[redirects]]\n\
             \x20\x20from = \"/*\"\n\
             \x20\x20to = \"/index.html\"\n\
             \x20\x20status = 200\n"
        );
        Ok(vec![
            GeneratedFile::new(
                join(&intent.component_root, "netlify.toml"),
                GeneratedFileKind::ProviderManifest,
                manifest,
            ),
            environment_template(intent),
        ])
    }
}

/// Render.
struct RenderAdapter;

impl ProviderAdapter for RenderAdapter {
    fn provider(&self) -> Provider {
        Provider::Render
    }

    fn generate(&self, intent: &DeploymentIntent) -> Result<Vec<GeneratedFile>> {
        if intent.deployment_kind != DeploymentKind::Server {
            return Err(LaunchGuardError::GeneratedArtifact {
                path: String::new(),
                message: "Render adapters serve server deployments".to_owned(),
            });
        }
        let port = intent.service_port.unwrap_or(8080);
        let dockerfile = dockerfile_for(intent.framework, port)?;

        let mut env_block = String::new();
        for name in &intent.environment_variable_names {
            write!(
                env_block,
                "\x20\x20\x20\x20- key: {name}\n\x20\x20\x20\x20\x20\x20sync: false\n"
            )
            .expect("writing to String cannot fail");
        }
        for name in &intent.secret_variable_names {
            write!(
                env_block,
                "\x20\x20\x20\x20- key: {name}\n\x20\x20\x20\x20\x20\x20sync: false\n"
            )
            .expect("writing to String cannot fail");
        }
        let env_section = if env_block.is_empty() {
            String::new()
        } else {
            format!("\x20\x20\x20\x20envVars:\n{env_block}")
        };

        let manifest = format!(
            "# Render blueprint generated by LaunchGuard.\n\
             # Free instances sleep when idle and use an ephemeral filesystem.\n\
             # Verify current terms at https://render.com/docs/free\n\
             services:\n\
             \x20\x20- type: web\n\
             \x20\x20\x20\x20name: launchguard-service\n\
             \x20\x20\x20\x20runtime: docker\n\
             \x20\x20\x20\x20plan: free\n\
             \x20\x20\x20\x20dockerfilePath: ./Dockerfile\n\
             \x20\x20\x20\x20healthCheckPath: /\n\
             {env_section}"
        );

        Ok(vec![
            GeneratedFile::new(
                join(&intent.component_root, "render.yaml"),
                GeneratedFileKind::ProviderManifest,
                manifest,
            ),
            GeneratedFile::new(
                join(&intent.component_root, "Dockerfile"),
                GeneratedFileKind::Dockerfile,
                dockerfile,
            ),
            GeneratedFile::new(
                join(&intent.component_root, ".dockerignore"),
                GeneratedFileKind::DockerIgnore,
                "# Generated by LaunchGuard.\n\
                 .git\n\
                 .github\n\
                 node_modules\n\
                 target\n\
                 dist\n\
                 build\n\
                 .venv\n\
                 __pycache__\n\
                 .env\n\
                 .env.*\n\
                 *.log\n",
            ),
            environment_template(intent),
        ])
    }
}

/// Reviewed container templates.
///
/// Every template runs as a non-root user and binds the configured port
/// explicitly, matching the controls the security model requires of anything
/// that later executes.
fn dockerfile_for(framework: Framework, port: u16) -> Result<String> {
    let contents = match framework {
        Framework::FastApi => format!(
            "# Generated by LaunchGuard. Review before publishing.\n\
             FROM python:3.13-slim\n\
             \n\
             ENV PYTHONDONTWRITEBYTECODE=1 \\\n\
             \x20\x20\x20\x20PYTHONUNBUFFERED=1 \\\n\
             \x20\x20\x20\x20PORT={port}\n\
             \n\
             WORKDIR /app\n\
             \n\
             COPY requirements*.txt pyproject.toml* ./\n\
             RUN python -m pip install --no-cache-dir --upgrade pip \\\n\
             \x20\x20&& if [ -f requirements.txt ]; then \\\n\
             \x20\x20\x20\x20\x20\x20python -m pip install --no-cache-dir -r requirements.txt; \\\n\
             \x20\x20\x20\x20 else python -m pip install --no-cache-dir .; fi\n\
             \n\
             COPY . .\n\
             \n\
             # Run as a non-root user.\n\
             RUN useradd --create-home --uid 10001 launchguard \\\n\
             \x20\x20&& chown -R launchguard:launchguard /app\n\
             USER launchguard\n\
             \n\
             EXPOSE {port}\n\
             CMD [\"python\", \"-m\", \"uvicorn\", \"main:app\", \"--host\", \"0.0.0.0\", \"--port\", \"{port}\"]\n"
        ),
        Framework::RustAxum => format!(
            "# Generated by LaunchGuard. Review before publishing.\n\
             FROM rust:1.97.1-bookworm AS build\n\
             WORKDIR /src\n\
             COPY . .\n\
             RUN cargo build --locked --release\n\
             \n\
             FROM debian:bookworm-slim\n\
             ENV PORT={port}\n\
             WORKDIR /app\n\
             \n\
             RUN apt-get update \\\n\
             \x20\x20&& apt-get install -y --no-install-recommends ca-certificates \\\n\
             \x20\x20&& rm -rf /var/lib/apt/lists/*\n\
             \n\
             COPY --from=build /src/target/release/ /app/bin/\n\
             \n\
             # Run as a non-root user.\n\
             RUN useradd --create-home --uid 10001 launchguard \\\n\
             \x20\x20&& chown -R launchguard:launchguard /app\n\
             USER launchguard\n\
             \n\
             EXPOSE {port}\n\
             # Review this path: it must name the binary your crate produces.\n\
             CMD [\"/app/bin/server\"]\n"
        ),
        Framework::NextJs => format!(
            "# Generated by LaunchGuard. Review before publishing.\n\
             FROM node:22-slim AS build\n\
             WORKDIR /src\n\
             COPY . .\n\
             RUN npm ci && npm run build\n\
             \n\
             FROM node:22-slim\n\
             ENV NODE_ENV=production \\\n\
             \x20\x20\x20\x20PORT={port}\n\
             WORKDIR /app\n\
             COPY --from=build /src ./\n\
             \n\
             # Run as the image's existing non-root user.\n\
             USER node\n\
             \n\
             EXPOSE {port}\n\
             CMD [\"npm\", \"run\", \"start\"]\n"
        ),
        Framework::ReactVite => {
            return Err(LaunchGuardError::GeneratedArtifact {
                path: String::new(),
                message: "React/Vite builds static output and needs no container".to_owned(),
            });
        }
    };
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::{GeneratedFileKind, dockerfile_for, join};
    use crate::Framework;

    #[test]
    fn component_roots_are_joined_without_escaping() {
        assert_eq!(join(".", "netlify.toml"), "netlify.toml");
        assert_eq!(join("", "netlify.toml"), "netlify.toml");
        assert_eq!(join("frontend", "netlify.toml"), "frontend/netlify.toml");
        assert_eq!(join("frontend/", "netlify.toml"), "frontend/netlify.toml");
    }

    #[test]
    fn every_container_template_drops_root_and_binds_its_port() {
        for framework in [Framework::FastApi, Framework::RustAxum, Framework::NextJs] {
            let dockerfile = dockerfile_for(framework, 8080).expect("template");
            assert!(
                dockerfile.contains("USER "),
                "{framework:?} template must not run as root"
            );
            assert!(
                !dockerfile.contains("USER root"),
                "{framework:?} template must not select root"
            );
            assert!(
                dockerfile.contains("EXPOSE 8080"),
                "{framework:?} template must expose its port"
            );
        }
    }

    #[test]
    fn a_static_framework_is_refused_a_container_template() {
        // React/Vite produces files, not a service; generating a container for
        // it would invent a runtime the project does not have.
        assert!(dockerfile_for(Framework::ReactVite, 8080).is_err());
    }

    #[test]
    fn generated_kinds_are_distinct() {
        assert_ne!(
            GeneratedFileKind::Dockerfile,
            GeneratedFileKind::ProviderManifest
        );
    }

    #[test]
    fn a_manifest_that_does_not_parse_is_refused() {
        use super::{GeneratedFile, validate_generated};
        use crate::{ApprovalState, DeploymentIntent, DeploymentKind, Provider, ProviderLimit};

        let intent = DeploymentIntent {
            schema_version: "1.0".to_owned(),
            digest: String::new(),
            provider: Provider::Netlify,
            deployment_kind: DeploymentKind::Static,
            framework: Framework::ReactVite,
            component_root: ".".to_owned(),
            build_command: None,
            output_directory: Some("dist".to_owned()),
            service_port: None,
            environment_variable_names: Vec::new(),
            secret_variable_names: vec!["API_TOKEN".to_owned()],
            custom_domain: None,
            provider_limits: vec![ProviderLimit {
                summary: "example".to_owned(),
                documentation_url: "https://example.invalid".to_owned(),
            }],
            approval_state: ApprovalState::RequiresApproval,
        };

        let broken = GeneratedFile::new(
            "netlify.toml",
            GeneratedFileKind::ProviderManifest,
            "[build\ncommand = \"npm run build\"\n",
        );
        assert!(validate_generated(&[broken], &intent).is_err());

        // A secret may be named as an empty placeholder, never assigned a value.
        let placeholder = GeneratedFile::new(
            ".env.example",
            GeneratedFileKind::EnvironmentTemplate,
            "API_TOKEN=\n",
        );
        assert!(validate_generated(&[placeholder], &intent).is_ok());

        let leaked = GeneratedFile::new(
            ".env.example",
            GeneratedFileKind::EnvironmentTemplate,
            "API_TOKEN=sk-live-abc123\n",
        );
        assert!(validate_generated(&[leaked], &intent).is_err());
    }

    #[test]
    fn artifacts_may_not_escape_the_repository() {
        use super::{GeneratedFile, validate_generated};
        use crate::{ApprovalState, DeploymentIntent, DeploymentKind, Provider, ProviderLimit};

        let intent = DeploymentIntent {
            schema_version: "1.0".to_owned(),
            digest: String::new(),
            provider: Provider::Netlify,
            deployment_kind: DeploymentKind::Static,
            framework: Framework::ReactVite,
            component_root: ".".to_owned(),
            build_command: None,
            output_directory: Some("dist".to_owned()),
            service_port: None,
            environment_variable_names: Vec::new(),
            secret_variable_names: Vec::new(),
            custom_domain: None,
            provider_limits: vec![ProviderLimit {
                summary: "example".to_owned(),
                documentation_url: "https://example.invalid".to_owned(),
            }],
            approval_state: ApprovalState::RequiresApproval,
        };
        for path in ["/etc/passwd", "../outside.toml", "a\\b.toml"] {
            let file = GeneratedFile::new(path, GeneratedFileKind::ProviderManifest, "x = 1\n");
            assert!(
                validate_generated(&[file], &intent).is_err(),
                "{path} must be refused"
            );
        }
    }
}
