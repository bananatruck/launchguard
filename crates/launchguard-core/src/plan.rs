//! Content-addressed execution plans produced only from reviewed templates.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    DeploymentKind, DetectionStatus, EnvironmentVariable, Framework, LaunchGuardError,
    PackageManager, ProjectProfile, Result,
};

/// Execution-plan contract emitted by this release.
pub const EXECUTION_PLAN_SCHEMA_VERSION: &str = "1.0";

/// Bundled JSON Schema for [`ExecutionPlan`].
pub const EXECUTION_PLAN_SCHEMA_JSON: &str =
    include_str!("../../../schemas/execution-plan-v1.schema.json");

/// Version of the human-reviewed command templates.
pub const REVIEWED_TEMPLATE_VERSION: &str = "2026-07-26.1";

/// Human approval state for a generated plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// The plan cannot execute until a person approves its exact digest.
    RequiresApproval,
}

/// Purpose of a typed process invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStage {
    /// Resolve or install dependencies.
    Install,
    /// Run project tests.
    Test,
    /// Produce deployable output.
    Build,
    /// Start a preview process.
    Start,
}

/// A process invocation represented without a shell command string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCommand {
    /// Stable command identifier.
    pub id: String,
    /// Command purpose.
    pub stage: CommandStage,
    /// Executable name selected by a reviewed template.
    pub executable: String,
    /// Individual process arguments.
    pub arguments: Vec<String>,
    /// Repository-relative working directory.
    pub working_directory: String,
    /// Accepted process exit codes.
    pub expected_exit_codes: Vec<i32>,
    /// Whether the command needs approved registry access.
    pub requires_network: bool,
    /// Command-specific wall-clock deadline.
    pub timeout_seconds: u64,
}

/// Network access policy for a future sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Network access begins denied.
    pub default_deny: bool,
    /// Reviewed dependency endpoints required by install commands.
    pub allowed_destinations: Vec<String>,
}

/// Resource ceilings a future sandbox must enforce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// CPU quota in milli-CPU units.
    pub cpu_millis: u32,
    /// Memory ceiling in MiB.
    pub memory_mib: u32,
    /// Maximum process count.
    pub pids: u32,
    /// Entire-plan wall-clock deadline.
    pub timeout_seconds: u64,
}

/// Type of expected build output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputKind {
    /// Directory containing static or binary output.
    Directory,
}

/// Output the plan expects to exist after successful commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedOutput {
    /// Repository-relative path.
    pub path: String,
    /// Expected filesystem type.
    pub kind: OutputKind,
}

/// Health-check mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckKind {
    /// Verify an output directory exists.
    DirectoryExists,
    /// Issue an HTTP GET inside the sandbox.
    HttpGet,
}

/// Deterministic post-build or runtime check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Check mechanism.
    pub kind: HealthCheckKind,
    /// Repository-relative path or loopback URL template.
    pub target: String,
    /// Health-check deadline.
    pub timeout_seconds: u64,
}

#[derive(Serialize)]
struct PlanPayload<'a> {
    schema_version: &'a str,
    template_version: &'a str,
    profile_revision: &'a str,
    component_root: &'a str,
    framework: Framework,
    deployment_kind: DeploymentKind,
    approval_state: ApprovalState,
    commands: &'a [PlanCommand],
    network_policy: &'a NetworkPolicy,
    resource_limits: &'a ResourceLimits,
    environment_variables: &'a [EnvironmentVariable],
    expected_outputs: &'a [ExpectedOutput],
    health_checks: &'a [HealthCheck],
}

/// Immutable, content-addressed proposal for later sandbox execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlan {
    /// Public record schema.
    pub schema_version: String,
    /// SHA-256 over every plan field except this digest.
    pub digest: String,
    /// Reviewed template release.
    pub template_version: String,
    /// Repository revision inspected.
    pub profile_revision: String,
    /// Repository-relative component root.
    pub component_root: String,
    /// Selected supported framework.
    pub framework: Framework,
    /// Static or server deployment behavior.
    pub deployment_kind: DeploymentKind,
    /// Explicit human gate.
    pub approval_state: ApprovalState,
    /// Typed process invocations in execution order.
    pub commands: Vec<PlanCommand>,
    /// Default-deny egress policy.
    pub network_policy: NetworkPolicy,
    /// Sandbox resource ceilings.
    pub resource_limits: ResourceLimits,
    /// Environment variable names only; values are not captured.
    pub environment_variables: Vec<EnvironmentVariable>,
    /// Expected build outputs.
    pub expected_outputs: Vec<ExpectedOutput>,
    /// Deterministic validation probes.
    pub health_checks: Vec<HealthCheck>,
}

impl ExecutionPlan {
    /// Recompute and validate the embedded content digest.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the digest does not match.
    pub fn validate_digest(&self) -> Result<()> {
        if self.digest == plan_digest(self)? {
            Ok(())
        } else {
            Err(LaunchGuardError::DigestMismatch {
                record: "ExecutionPlan",
            })
        }
    }
}

/// Deterministic generator for reviewed Phase 2 templates.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlanGenerator;

impl PlanGenerator {
    /// Generate a plan for one unambiguous supported profile.
    ///
    /// # Errors
    ///
    /// Fails closed for unknown profile schemas, ambiguous detection, missing
    /// deployment facts, or invalid template inputs.
    pub fn generate(&self, profile: &ProjectProfile) -> Result<ExecutionPlan> {
        profile.validate_schema()?;
        if profile.status != DetectionStatus::Detected {
            return Err(LaunchGuardError::PlanUnavailable(
                "project classification requires confirmation".to_owned(),
            ));
        }
        let framework = profile.framework.ok_or_else(|| {
            LaunchGuardError::PlanUnavailable("detected profile has no framework".to_owned())
        })?;
        let deployment_kind = profile.deployment_kind.ok_or_else(|| {
            LaunchGuardError::PlanUnavailable("detected profile has no deployment kind".to_owned())
        })?;
        let component_root = profile
            .components
            .first()
            .map_or_else(|| ".".to_owned(), |component| component.path.clone());
        let mut commands = Vec::new();
        let mut allowed_destinations = Vec::new();
        let mut expected_outputs = Vec::new();
        let mut health_checks = Vec::new();

        match framework {
            Framework::ReactVite | Framework::NextJs => {
                let manager = profile.package_manager.ok_or_else(|| {
                    LaunchGuardError::PlanUnavailable(
                        "Node profile has no reviewed package manager".to_owned(),
                    )
                })?;
                commands.push(node_install(manager, &component_root)?);
                allowed_destinations.extend(node_registries(manager));
                if !profile.test_commands.is_empty() {
                    commands.push(node_script(
                        manager,
                        "test",
                        CommandStage::Test,
                        &component_root,
                    )?);
                }
                commands.push(node_script(
                    manager,
                    "build",
                    CommandStage::Build,
                    &component_root,
                )?);
                if let Some(output) = &profile.output_directory {
                    expected_outputs.push(ExpectedOutput {
                        path: output.clone(),
                        kind: OutputKind::Directory,
                    });
                }
                if deployment_kind == DeploymentKind::Static {
                    if let Some(output) = &profile.output_directory {
                        health_checks.push(HealthCheck {
                            kind: HealthCheckKind::DirectoryExists,
                            target: output.clone(),
                            timeout_seconds: 10,
                        });
                    }
                } else {
                    commands.push(node_script(
                        manager,
                        "start",
                        CommandStage::Start,
                        &component_root,
                    )?);
                    health_checks.push(http_health_check());
                }
            }
            Framework::FastApi => {
                let manager = profile.package_manager;
                commands.push(python_install(manager, &component_root)?);
                allowed_destinations.extend(python_registries());
                if !profile.test_commands.is_empty() {
                    commands.push(python_test(manager, &component_root)?);
                }
                commands.push(python_start(profile, manager, &component_root)?);
                health_checks.push(http_health_check());
            }
            Framework::RustAxum => {
                let locked = profile
                    .build_command
                    .as_deref()
                    .is_some_and(|value| value.split_whitespace().any(|part| part == "--locked"));
                commands.push(command(
                    "install",
                    CommandStage::Install,
                    "cargo",
                    &rust_arguments("fetch", locked, false),
                    &component_root,
                    true,
                    300,
                ));
                commands.push(command(
                    "test",
                    CommandStage::Test,
                    "cargo",
                    &rust_arguments("test", locked, false),
                    &component_root,
                    false,
                    600,
                ));
                commands.push(command(
                    "build",
                    CommandStage::Build,
                    "cargo",
                    &rust_arguments("build", locked, true),
                    &component_root,
                    false,
                    900,
                ));
                commands.push(command(
                    "start",
                    CommandStage::Start,
                    "cargo",
                    &rust_arguments("run", locked, true),
                    &component_root,
                    false,
                    120,
                ));
                allowed_destinations.extend(rust_registries());
                if let Some(output) = &profile.output_directory {
                    expected_outputs.push(ExpectedOutput {
                        path: output.clone(),
                        kind: OutputKind::Directory,
                    });
                }
                health_checks.push(http_health_check());
            }
        }

        allowed_destinations.sort();
        allowed_destinations.dedup();
        let mut environment_variables = profile.environment_variables.clone();
        environment_variables.sort();
        let mut plan = ExecutionPlan {
            schema_version: EXECUTION_PLAN_SCHEMA_VERSION.to_owned(),
            digest: String::new(),
            template_version: REVIEWED_TEMPLATE_VERSION.to_owned(),
            profile_revision: profile.revision.clone(),
            component_root,
            framework,
            deployment_kind,
            approval_state: ApprovalState::RequiresApproval,
            commands,
            network_policy: NetworkPolicy {
                default_deny: true,
                allowed_destinations,
            },
            resource_limits: ResourceLimits {
                cpu_millis: 2_000,
                memory_mib: 4_096,
                pids: 256,
                timeout_seconds: 1_800,
            },
            environment_variables,
            expected_outputs,
            health_checks,
        };
        plan.digest = plan_digest(&plan)?;
        Ok(plan)
    }
}

fn plan_digest(plan: &ExecutionPlan) -> Result<String> {
    let payload = PlanPayload {
        schema_version: &plan.schema_version,
        template_version: &plan.template_version,
        profile_revision: &plan.profile_revision,
        component_root: &plan.component_root,
        framework: plan.framework,
        deployment_kind: plan.deployment_kind,
        approval_state: plan.approval_state,
        commands: &plan.commands,
        network_policy: &plan.network_policy,
        resource_limits: &plan.resource_limits,
        environment_variables: &plan.environment_variables,
        expected_outputs: &plan.expected_outputs,
        health_checks: &plan.health_checks,
    };
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload)?)
    ))
}

fn command(
    id: &str,
    stage: CommandStage,
    executable: &str,
    arguments: &[&str],
    working_directory: &str,
    requires_network: bool,
    timeout_seconds: u64,
) -> PlanCommand {
    PlanCommand {
        id: id.to_owned(),
        stage,
        executable: executable.to_owned(),
        arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
        working_directory: working_directory.to_owned(),
        expected_exit_codes: vec![0],
        requires_network,
        timeout_seconds,
    }
}

fn node_install(manager: PackageManager, root: &str) -> Result<PlanCommand> {
    let (executable, arguments): (&str, &[&str]) = match manager {
        PackageManager::Npm => ("npm", &["ci"]),
        PackageManager::Pnpm => ("pnpm", &["install", "--frozen-lockfile"]),
        PackageManager::Yarn => ("yarn", &["install", "--frozen-lockfile"]),
        PackageManager::Bun => ("bun", &["install", "--frozen-lockfile"]),
        _ => {
            return Err(LaunchGuardError::PlanUnavailable(
                "Node profile selected a non-Node package manager".to_owned(),
            ));
        }
    };
    Ok(command(
        "install",
        CommandStage::Install,
        executable,
        arguments,
        root,
        true,
        300,
    ))
}

fn node_script(
    manager: PackageManager,
    script: &str,
    stage: CommandStage,
    root: &str,
) -> Result<PlanCommand> {
    let executable = match manager {
        PackageManager::Npm => "npm",
        PackageManager::Pnpm => "pnpm",
        PackageManager::Yarn => "yarn",
        PackageManager::Bun => "bun",
        _ => {
            return Err(LaunchGuardError::PlanUnavailable(
                "Node profile selected a non-Node package manager".to_owned(),
            ));
        }
    };
    let arguments = if manager == PackageManager::Yarn {
        vec![script]
    } else {
        vec!["run", script]
    };
    Ok(command(
        script,
        stage,
        executable,
        &arguments,
        root,
        false,
        if stage == CommandStage::Build {
            600
        } else {
            300
        },
    ))
}

fn python_install(manager: Option<PackageManager>, root: &str) -> Result<PlanCommand> {
    match manager {
        Some(PackageManager::Uv) => Ok(command(
            "install",
            CommandStage::Install,
            "uv",
            &["sync", "--frozen"],
            root,
            true,
            300,
        )),
        Some(PackageManager::Poetry) => Ok(command(
            "install",
            CommandStage::Install,
            "poetry",
            &["install", "--no-interaction"],
            root,
            true,
            300,
        )),
        Some(PackageManager::Pip) => Ok(command(
            "install",
            CommandStage::Install,
            "python",
            &["-m", "pip", "install", "-r", "requirements.txt"],
            root,
            true,
            300,
        )),
        None => Ok(command(
            "install",
            CommandStage::Install,
            "python",
            &["-m", "pip", "install", "."],
            root,
            true,
            300,
        )),
        Some(_) => Err(LaunchGuardError::PlanUnavailable(
            "FastAPI profile selected a non-Python package manager".to_owned(),
        )),
    }
}

fn python_test(manager: Option<PackageManager>, root: &str) -> Result<PlanCommand> {
    match manager {
        Some(PackageManager::Uv) => Ok(command(
            "test",
            CommandStage::Test,
            "uv",
            &["run", "pytest"],
            root,
            false,
            300,
        )),
        Some(PackageManager::Poetry) => Ok(command(
            "test",
            CommandStage::Test,
            "poetry",
            &["run", "pytest"],
            root,
            false,
            300,
        )),
        Some(PackageManager::Pip) | None => Ok(command(
            "test",
            CommandStage::Test,
            "python",
            &["-m", "pytest"],
            root,
            false,
            300,
        )),
        Some(_) => Err(LaunchGuardError::PlanUnavailable(
            "FastAPI profile selected a non-Python package manager".to_owned(),
        )),
    }
}

fn python_start(
    profile: &ProjectProfile,
    manager: Option<PackageManager>,
    root: &str,
) -> Result<PlanCommand> {
    let application = profile
        .start_command
        .as_deref()
        .and_then(|value| value.split_whitespace().last())
        .filter(|value| {
            !value.is_empty()
                && value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "_.:".contains(character))
        })
        .ok_or_else(|| {
            LaunchGuardError::PlanUnavailable(
                "FastAPI application target is not a safe reviewed token".to_owned(),
            )
        })?;
    let mut arguments = vec![
        "-m",
        "uvicorn",
        application,
        "--host",
        "0.0.0.0",
        "--port",
        "${PORT}",
    ];
    let (executable, prefix): (&str, &[&str]) = match manager {
        Some(PackageManager::Uv) => ("uv", &["run", "python"]),
        Some(PackageManager::Poetry) => ("poetry", &["run", "python"]),
        Some(PackageManager::Pip) | None => ("python", &[]),
        Some(_) => {
            return Err(LaunchGuardError::PlanUnavailable(
                "FastAPI profile selected a non-Python package manager".to_owned(),
            ));
        }
    };
    let mut combined = prefix.to_vec();
    combined.append(&mut arguments);
    Ok(command(
        "start",
        CommandStage::Start,
        executable,
        &combined,
        root,
        false,
        120,
    ))
}

fn http_health_check() -> HealthCheck {
    HealthCheck {
        kind: HealthCheckKind::HttpGet,
        target: "http://127.0.0.1:${PORT}/".to_owned(),
        timeout_seconds: 30,
    }
}

fn node_registries(manager: PackageManager) -> Vec<String> {
    match manager {
        PackageManager::Yarn => vec![
            "registry.npmjs.org:443".to_owned(),
            "registry.yarnpkg.com:443".to_owned(),
        ],
        _ => vec!["registry.npmjs.org:443".to_owned()],
    }
}

fn python_registries() -> Vec<String> {
    vec![
        "files.pythonhosted.org:443".to_owned(),
        "pypi.org:443".to_owned(),
    ]
}

fn rust_registries() -> Vec<String> {
    vec![
        "index.crates.io:443".to_owned(),
        "static.crates.io:443".to_owned(),
    ]
}

fn rust_arguments(command_name: &str, locked: bool, release: bool) -> Vec<&str> {
    let mut arguments = vec![command_name];
    if release {
        arguments.push("--release");
    }
    if locked {
        arguments.push("--locked");
    }
    arguments
}
