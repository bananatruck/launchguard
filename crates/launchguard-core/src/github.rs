//! GitHub publication.
//!
//! This is the only module that writes to a system outside the user's machine,
//! and the only one that touches a credential. Nothing here runs before the
//! publication stage.
//!
//! Authentication uses the device-authorization flow rather than asking a user
//! to hand-build a personal access token, so the scopes granted are exactly the
//! ones displayed. A token is held in memory for the process and never written
//! to the repository, history, or any record.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{LaunchGuardError, PullRequestPlan, Result};

/// GitHub REST API root.
const API: &str = "https://api.github.com";

/// Requests identify themselves, as the GitHub API requires.
const USER_AGENT: &str = concat!("launchguard/", env!("CARGO_PKG_VERSION"));

/// Deadline for a single API call.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A pending device authorization the user must approve in a browser.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceAuthorization {
    /// Opaque code this process polls with.
    pub device_code: String,
    /// Short code the user types into GitHub.
    pub user_code: String,
    /// Page the user opens to enter the code.
    pub verification_uri: String,
    /// Seconds until the code expires.
    pub expires_in: u64,
    /// Minimum seconds between polls.
    pub interval: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct RepositoryInfo {
    default_branch: String,
    private: bool,
    permissions: Option<RepositoryPermissions>,
}

#[derive(Deserialize)]
struct RepositoryPermissions {
    push: bool,
}

/// What publication learned about a target repository before writing anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryFacts {
    /// Branch a pull request should merge into.
    pub default_branch: String,
    /// Whether the repository is private, which widens the scope required.
    pub private: bool,
    /// Whether the authenticated user may push.
    pub can_push: bool,
}

/// Result of opening or updating a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedPullRequest {
    /// Pull-request number.
    pub number: u64,
    /// Web URL a person can open.
    pub url: String,
    /// Branch that was pushed.
    pub head_branch: String,
    /// Commit the branch now points at.
    pub commit_sha: String,
    /// Whether this call created the request or updated an existing one.
    pub newly_created: bool,
}

/// Starts a device-authorization flow.
///
/// GitHub issues device codes against a registered OAuth application, so the
/// client identifier is configuration rather than a constant.
#[derive(Debug, Clone)]
pub struct DeviceFlow {
    client_id: String,
}

impl DeviceFlow {
    /// Use a registered OAuth application.
    #[must_use]
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
        }
    }

    /// Request a device code for the given scopes.
    ///
    /// # Errors
    ///
    /// Returns an error when GitHub rejects the request or is unreachable.
    pub async fn start(&self, scopes: &[String]) -> Result<DeviceAuthorization> {
        let client = http_client()?;
        let response = client
            .post("https://github.com/login/device/code")
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("scope", &scopes.join(" ")),
            ])
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<DeviceAuthorization>().await?)
    }

    /// Poll until the user approves, declines, or the code expires.
    ///
    /// # Errors
    ///
    /// Returns an error when the user declines, the code expires, or GitHub is
    /// unreachable.
    pub async fn wait_for_token(&self, authorization: &DeviceAuthorization) -> Result<String> {
        let client = http_client()?;
        let mut interval = Duration::from_secs(authorization.interval.max(1));
        let deadline = std::time::Instant::now() + Duration::from_secs(authorization.expires_in);

        while std::time::Instant::now() < deadline {
            tokio::time::sleep(interval).await;
            let response: TokenResponse = client
                .post("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("device_code", authorization.device_code.as_str()),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ])
                .send()
                .await?
                .json()
                .await?;

            if let Some(token) = response.access_token {
                return Ok(token);
            }
            match response.error.as_deref() {
                // Still waiting for the user; keep polling.
                Some("authorization_pending") => {}
                // GitHub asks for a slower cadence.
                Some("slow_down") => {
                    interval = Duration::from_secs(
                        response.interval.unwrap_or(interval.as_secs() + 5).max(1),
                    );
                }
                Some(other) => {
                    return Err(LaunchGuardError::PublicationRefused(format!(
                        "device authorization failed: {other}"
                    )));
                }
                None => {
                    return Err(LaunchGuardError::PublicationRefused(
                        "device authorization returned neither a token nor an error".to_owned(),
                    ));
                }
            }
        }
        Err(LaunchGuardError::PublicationRefused(
            "device authorization expired before it was approved".to_owned(),
        ))
    }
}

/// Authenticated GitHub client used only at publication time.
#[derive(Clone)]
pub struct GitHubClient {
    token: String,
}

impl std::fmt::Debug for GitHubClient {
    /// Never render the token, so it cannot reach a log through a derived impl.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHubClient")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl GitHubClient {
    /// Authenticate with a token held only in memory.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }

    /// Learn the default branch and whether the caller may push.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository is missing or unreadable.
    pub async fn repository_facts(&self, repository: &str) -> Result<RepositoryFacts> {
        let info: RepositoryInfo = self
            .request(reqwest::Method::GET, &format!("/repos/{repository}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(RepositoryFacts {
            default_branch: info.default_branch,
            private: info.private,
            can_push: info.permissions.is_some_and(|permissions| permissions.push),
        })
    }

    /// Push the plan's files as one commit and open or update its pull request.
    ///
    /// Idempotent: the branch derives from the deployment intent digest, so a
    /// repeated run for an unchanged project updates that branch and its
    /// existing pull request rather than opening a second one.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan digest does not reproduce, the caller
    /// cannot push, or any API call fails.
    pub async fn publish(&self, plan: &PullRequestPlan) -> Result<PublishedPullRequest> {
        plan.validate_digest()?;
        let repository = plan.repository.as_str();

        let facts = self.repository_facts(repository).await?;
        if !facts.can_push {
            return Err(LaunchGuardError::PublicationRefused(format!(
                "the authenticated account cannot push to {repository}"
            )));
        }

        let base_sha = self.branch_head(repository, &plan.base_branch).await?;
        let base_tree = self.commit_tree(repository, &base_sha).await?;

        // Build one tree containing every generated file, then one commit.
        let mut entries = Vec::new();
        for file in &plan.files {
            entries.push(serde_json::json!({
                "path": file.path,
                "mode": "100644",
                "type": "blob",
                "content": file.contents,
            }));
        }
        let tree_sha = self
            .post_value(
                repository,
                "git/trees",
                &serde_json::json!({ "base_tree": base_tree, "tree": entries }),
            )
            .await?;

        let commit_sha = self
            .post_value(
                repository,
                "git/commits",
                &serde_json::json!({
                    "message": format!(
                        "{}\n\nGenerated by LaunchGuard from revision {}.\nIntent digest: {}",
                        plan.title, plan.revision, plan.intent_digest
                    ),
                    "tree": tree_sha,
                    "parents": [base_sha],
                }),
            )
            .await?;

        let existing = self.branch_head(repository, &plan.head_branch).await.ok();
        if existing.is_some() {
            self.request(
                reqwest::Method::PATCH,
                &format!("/repos/{repository}/git/refs/heads/{}", plan.head_branch),
            )
            .json(&serde_json::json!({ "sha": commit_sha, "force": true }))
            .send()
            .await?
            .error_for_status()?;
        } else {
            self.request(
                reqwest::Method::POST,
                &format!("/repos/{repository}/git/refs"),
            )
            .json(&serde_json::json!({
                "ref": format!("refs/heads/{}", plan.head_branch),
                "sha": commit_sha,
            }))
            .send()
            .await?
            .error_for_status()?;
        }

        // An open request for this head branch is updated, never duplicated.
        if let Some(open) = self
            .open_pull_request(repository, &plan.head_branch)
            .await?
        {
            return Ok(PublishedPullRequest {
                number: open.0,
                url: open.1,
                head_branch: plan.head_branch.clone(),
                commit_sha,
                newly_created: false,
            });
        }

        let created: serde_json::Value = self
            .request(reqwest::Method::POST, &format!("/repos/{repository}/pulls"))
            .json(&serde_json::json!({
                "title": plan.title,
                "body": plan.body,
                "head": plan.head_branch,
                "base": plan.base_branch,
                "maintainer_can_modify": true,
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(PublishedPullRequest {
            number: created["number"].as_u64().unwrap_or_default(),
            url: created["html_url"].as_str().unwrap_or_default().to_owned(),
            head_branch: plan.head_branch.clone(),
            commit_sha,
            newly_created: true,
        })
    }

    async fn open_pull_request(
        &self,
        repository: &str,
        head_branch: &str,
    ) -> Result<Option<(u64, String)>> {
        let owner = repository.split('/').next().unwrap_or_default();
        let requests: Vec<serde_json::Value> = self
            .request(reqwest::Method::GET, &format!("/repos/{repository}/pulls"))
            .query(&[
                ("state", "open"),
                ("head", &format!("{owner}:{head_branch}")),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(requests.first().map(|request| {
            (
                request["number"].as_u64().unwrap_or_default(),
                request["html_url"].as_str().unwrap_or_default().to_owned(),
            )
        }))
    }

    async fn branch_head(&self, repository: &str, branch: &str) -> Result<String> {
        let value: serde_json::Value = self
            .request(
                reqwest::Method::GET,
                &format!("/repos/{repository}/git/ref/heads/{branch}"),
            )
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        value["object"]["sha"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| {
                LaunchGuardError::PublicationRefused(format!("branch {branch} has no commit"))
            })
    }

    async fn commit_tree(&self, repository: &str, commit: &str) -> Result<String> {
        let value: serde_json::Value = self
            .request(
                reqwest::Method::GET,
                &format!("/repos/{repository}/git/commits/{commit}"),
            )
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        value["tree"]["sha"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| LaunchGuardError::PublicationRefused("commit has no tree".to_owned()))
    }

    async fn post_value(
        &self,
        repository: &str,
        path: &str,
        payload: &serde_json::Value,
    ) -> Result<String> {
        let value: serde_json::Value = self
            .request(
                reqwest::Method::POST,
                &format!("/repos/{repository}/{path}"),
            )
            .json(payload)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        value["sha"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| LaunchGuardError::PublicationRefused(format!("{path} returned no sha")))
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = if path.starts_with("http") {
            path.to_owned()
        } else {
            format!("{API}{path}")
        };
        http_client()
            .expect("HTTP client construction cannot fail")
            .request(method, url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }
}

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::{DeviceFlow, GitHubClient};

    #[test]
    fn a_client_never_renders_its_token() {
        let client = GitHubClient::new("ghp_supersecrettokenvalue");
        let rendered = format!("{client:?}");
        assert!(
            !rendered.contains("ghp_supersecrettokenvalue"),
            "a token must not reach a log through Debug"
        );
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn a_device_flow_is_bound_to_a_registered_application() {
        let flow = DeviceFlow::new("Iv1.example");
        assert!(format!("{flow:?}").contains("Iv1.example"));
    }
}
