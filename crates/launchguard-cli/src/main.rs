//! `LaunchGuard` command-line interface.

use std::{fmt::Write as _, path::PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use launchguard_core::{
    ArtifactStore, DetectionEngine, DetectionStatus, EXECUTION_PLAN_SCHEMA_JSON, ExecutionPlan,
    FINDING_SCHEMA_JSON, Finding, HistoryEntry, HistoryStore, PROJECT_PROFILE_SCHEMA_JSON,
    PlanGenerator, ProjectProfile, RAW_ARTIFACT_SCHEMA_VERSION, READINESS_SCHEMA_JSON, RawArtifact,
    ReadinessAssessment, ReadinessEngine, RepositoryAcquirer, ScannerKind, ScannerRunner,
    merge_findings,
};
use serde_json::json;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "launchguard",
    version,
    about = "Local-first deployment readiness inspection",
    long_about = "LaunchGuard detects supported stacks, normalizes optional trusted scanner reports, and generates approval-gated execution plans without running repository code."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// `SQLite` history path.
    #[arg(long, global = true, env = "LAUNCHGUARD_DATABASE")]
    database: Option<PathBuf>,

    /// Structured logging representation. Logs are always written to stderr.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Pretty)]
    log_format: LogFormat,

    /// Increase diagnostic logging.
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect manifests and source markers without executing project code.
    Audit {
        /// Local directory or public GitHub repository URL.
        source: String,

        /// Report representation.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,

        /// Do not save this inspection to local history.
        #[arg(long)]
        no_history: bool,

        /// Trusted scanner to execute. Repeat to run both Phase 2 scanners.
        #[arg(long, value_enum)]
        scanner: Vec<ScannerSelection>,

        /// Content-addressed directory for sensitive raw scanner reports.
        #[arg(long)]
        artifact_directory: Option<PathBuf>,
    },

    /// Generate a reviewed execution plan without running scanners or project code.
    Plan {
        /// Local directory or public GitHub repository URL.
        source: String,

        /// Report representation.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },

    /// Display a stored run.
    Status {
        /// Run identifier returned by `audit`.
        run_id: Uuid,

        /// Report representation.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },

    /// List recent stored runs.
    History {
        /// Maximum number of runs.
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,

        /// Report representation.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },

    /// Print a bundled public-record JSON Schema.
    Schema {
        /// Public record contract. Defaults to the Phase 1 profile contract.
        #[arg(value_enum, default_value_t = SchemaRecord::ProjectProfile)]
        record: SchemaRecord,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Markdown,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ScannerSelection {
    Trivy,
    OsvScanner,
}

impl From<ScannerSelection> for ScannerKind {
    fn from(value: ScannerSelection) -> Self {
        match value {
            ScannerSelection::Trivy => Self::Trivy,
            ScannerSelection::OsvScanner => Self::OsvScanner,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SchemaRecord {
    ProjectProfile,
    Finding,
    ExecutionPlan,
    ReadinessAssessment,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    initialize_tracing(cli.log_format, cli.verbose)?;
    let database_path = cli.database.map_or_else(default_database_path, Ok)?;

    match cli.command {
        Command::Audit {
            source,
            format,
            no_history,
            scanner,
            artifact_directory,
        } => {
            let artifact_directory = artifact_directory.map_or_else(default_artifact_path, Ok)?;
            audit(
                &source,
                format,
                no_history,
                &database_path,
                &artifact_directory,
                &scanner,
            )
            .await
        }
        Command::Plan { source, format } => plan(&source, format).await,
        Command::Status { run_id, format } => {
            let store = HistoryStore::open(&database_path)?;
            let entry = store.get(run_id)?;
            print_entry(&entry, format)
        }
        Command::History { limit, format } => {
            let store = HistoryStore::open(&database_path)?;
            let entries = store.list(usize::from(limit))?;
            print_history(&entries, format)
        }
        Command::Schema { record } => {
            let schema = match record {
                SchemaRecord::ProjectProfile => PROJECT_PROFILE_SCHEMA_JSON,
                SchemaRecord::Finding => FINDING_SCHEMA_JSON,
                SchemaRecord::ExecutionPlan => EXECUTION_PLAN_SCHEMA_JSON,
                SchemaRecord::ReadinessAssessment => READINESS_SCHEMA_JSON,
            };
            println!("{schema}");
            Ok(())
        }
    }
}

async fn audit(
    source: &str,
    format: OutputFormat,
    no_history: bool,
    database_path: &PathBuf,
    artifact_directory: &PathBuf,
    selected_scanners: &[ScannerSelection],
) -> Result<()> {
    let repository = RepositoryAcquirer::new()?
        .acquire(source)
        .await
        .with_context(|| format!("failed to acquire {source}"))?;
    let profile = DetectionEngine::default()
        .inspect(&repository)
        .with_context(|| format!("failed to inspect {source}"))?;
    let plan = if profile.status == DetectionStatus::Detected {
        Some(
            PlanGenerator
                .generate(&profile)
                .context("failed to generate reviewed execution plan")?,
        )
    } else {
        None
    };
    let mut scanners = selected_scanners.to_vec();
    scanners.sort_unstable();
    scanners.dedup();
    let runner = ScannerRunner::default();
    let store = ArtifactStore::new(artifact_directory);
    let mut artifacts = Vec::new();
    let mut findings = Vec::new();
    let mut completed_scanners = Vec::new();
    for selected in scanners {
        let scanner = ScannerKind::from(selected);
        let report = runner
            .run(scanner, repository.root())
            .await
            .with_context(|| format!("{} scan failed", scanner.as_str()))?;
        let artifact = report
            .persist(&store)
            .with_context(|| format!("failed to persist {} report", scanner.as_str()))?;
        findings.extend(report.normalize(&artifact)?);
        artifacts.push(artifact);
        completed_scanners.push(scanner);
    }
    let findings = merge_findings(findings);
    let readiness = ReadinessEngine
        .assess(&profile, &findings, &completed_scanners, plan.as_ref())
        .context("failed to calculate readiness")?;

    let run_id = if no_history {
        None
    } else {
        Some(HistoryStore::open(database_path)?.record(&profile)?.run_id)
    };
    print_audit(
        &profile,
        run_id,
        plan.as_ref(),
        &findings,
        &artifacts,
        &readiness,
        format,
    )
}

async fn plan(source: &str, format: OutputFormat) -> Result<()> {
    let repository = RepositoryAcquirer::new()?
        .acquire(source)
        .await
        .with_context(|| format!("failed to acquire {source}"))?;
    let profile = DetectionEngine::default()
        .inspect(&repository)
        .with_context(|| format!("failed to inspect {source}"))?;
    let plan = PlanGenerator
        .generate(&profile)
        .context("failed to generate reviewed execution plan")?;
    let readiness = ReadinessEngine
        .assess(&profile, &[], &[], Some(&plan))
        .context("failed to calculate readiness")?;
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "profile": profile,
                    "plan": plan,
                    "readiness": readiness,
                }))?
            );
        }
        OutputFormat::Markdown => {
            println!("{}", plan_markdown(&profile, &plan, &readiness));
        }
    }
    Ok(())
}

fn print_entry(entry: &HistoryEntry, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(entry)?);
        }
        OutputFormat::Markdown => {
            println!("{}", profile_markdown(&entry.profile, Some(entry.run_id)));
        }
    }
    Ok(())
}

fn print_audit(
    profile: &ProjectProfile,
    run_id: Option<Uuid>,
    plan: Option<&ExecutionPlan>,
    findings: &[Finding],
    artifacts: &[RawArtifact],
    readiness: &ReadinessAssessment,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let output = json!({
                "run_id": run_id,
                "profile": profile,
                "plan": plan,
                "findings": findings,
                "artifacts": artifacts,
                "readiness": readiness,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Markdown => println!(
            "{}",
            audit_markdown(profile, run_id, plan, findings, artifacts, readiness)
        ),
    }
    Ok(())
}

fn audit_markdown(
    profile: &ProjectProfile,
    run_id: Option<Uuid>,
    plan: Option<&ExecutionPlan>,
    findings: &[Finding],
    artifacts: &[RawArtifact],
    readiness: &ReadinessAssessment,
) -> String {
    let mut output = profile_markdown(profile, run_id);
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Security findings").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    if readiness.completed_scanners.is_empty() {
        writeln!(
            output,
            "No scanners were requested. Security readiness is incomplete."
        )
        .expect("writing to String cannot fail");
    } else if findings.is_empty() {
        writeln!(
            output,
            "No findings were reported by the completed scanners."
        )
        .expect("writing to String cannot fail");
    } else {
        for finding in findings {
            writeln!(
                output,
                "- `{:?}` / `{:?}` — {} (`{}`)",
                finding.category, finding.severity, finding.summary, finding.fingerprint
            )
            .expect("writing to String cannot fail");
        }
    }
    if !artifacts.is_empty() {
        writeln!(output).expect("writing to String cannot fail");
        writeln!(
            output,
            "Raw reports use artifact schema `{RAW_ARTIFACT_SCHEMA_VERSION}` and remain local:"
        )
        .expect("writing to String cannot fail");
        for artifact in artifacts {
            writeln!(
                output,
                "- {}: `{}`",
                artifact.scanner.as_str(),
                artifact.relative_path
            )
            .expect("writing to String cannot fail");
        }
    }
    append_plan_and_scores(&mut output, plan, readiness);
    output
}

fn plan_markdown(
    profile: &ProjectProfile,
    plan: &ExecutionPlan,
    readiness: &ReadinessAssessment,
) -> String {
    let mut output = profile_markdown(profile, None);
    append_plan_and_scores(&mut output, Some(plan), readiness);
    output
}

fn append_plan_and_scores(
    output: &mut String,
    plan: Option<&ExecutionPlan>,
    readiness: &ReadinessAssessment,
) {
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Reviewed execution plan").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    if let Some(plan) = plan {
        writeln!(output, "- Digest: `{}`", plan.digest).expect("writing to String cannot fail");
        writeln!(output, "- Approval: `requires_approval`").expect("writing to String cannot fail");
        writeln!(output, "- Default network policy: deny").expect("writing to String cannot fail");
        for command in &plan.commands {
            writeln!(
                output,
                "- `{:?}`: `{}` with {} typed argument(s)",
                command.stage,
                command.executable,
                command.arguments.len()
            )
            .expect("writing to String cannot fail");
        }
    } else {
        writeln!(
            output,
            "No plan was generated because project classification is not unambiguous."
        )
        .expect("writing to String cannot fail");
    }
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Deterministic readiness").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "- Build: {}%", readiness.scores.build.percentage)
        .expect("writing to String cannot fail");
    writeln!(
        output,
        "- Security: {}%",
        readiness.scores.security.percentage
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "- Deployment: {}%",
        readiness.scores.deployment.percentage
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "- Operational: {}%",
        readiness.scores.operational.percentage
    )
    .expect("writing to String cannot fail");
    writeln!(output, "- Preview blocked: `{}`", readiness.blocks_preview)
        .expect("writing to String cannot fail");
    writeln!(
        output,
        "- Publication blocked: `{}`",
        readiness.blocks_publication
    )
    .expect("writing to String cannot fail");
}

fn print_history(entries: &[HistoryEntry], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(entries)?),
        OutputFormat::Markdown => {
            if entries.is_empty() {
                println!("No inspection runs recorded.");
                return Ok(());
            }
            println!("| Run | Created (UTC) | Status | Framework | Source |");
            println!("| --- | --- | --- | --- | --- |");
            for entry in entries {
                let framework = entry
                    .profile
                    .framework
                    .map_or_else(|| "—".to_owned(), |value| value.to_string());
                println!(
                    "| `{}` | {} | `{:?}` | {} | `{}` |",
                    entry.run_id,
                    entry.created_at.format("%Y-%m-%d %H:%M:%S"),
                    entry.profile.status,
                    framework,
                    escape_table(&entry.profile.source)
                );
            }
        }
    }
    Ok(())
}

fn profile_markdown(profile: &ProjectProfile, run_id: Option<Uuid>) -> String {
    let mut output = String::new();
    writeln!(output, "# LaunchGuard read-only audit").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    if let Some(run_id) = run_id {
        writeln!(output, "- Run: `{run_id}`").expect("writing to String cannot fail");
    }
    writeln!(output, "- Source: `{}`", profile.source).expect("writing to String cannot fail");
    writeln!(output, "- Revision: `{}`", profile.revision).expect("writing to String cannot fail");
    writeln!(output, "- Status: `{}`", status_name(profile.status))
        .expect("writing to String cannot fail");
    writeln!(output, "- Confidence: {:.0}%", profile.confidence * 100.0)
        .expect("writing to String cannot fail");

    if let Some(framework) = profile.framework {
        writeln!(output, "- Framework: {framework}").expect("writing to String cannot fail");
    }
    if profile.status == DetectionStatus::NeedsConfirmation {
        writeln!(output).expect("writing to String cannot fail");
        writeln!(output, "## Competing classifications").expect("writing to String cannot fail");
        writeln!(output).expect("writing to String cannot fail");
        for candidate in &profile.candidates {
            writeln!(
                output,
                "- {} at `{}` ({:.0}% confidence)",
                candidate.framework,
                candidate.component_root,
                candidate.confidence * 100.0
            )
            .expect("writing to String cannot fail");
        }
    }

    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Evidence").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    if profile.evidence.is_empty() {
        writeln!(output, "No supported framework met its evidence contract.")
            .expect("writing to String cannot fail");
    } else {
        for item in &profile.evidence {
            writeln!(
                output,
                "- `{}` — {} (`{}`)",
                item.kind, item.description, item.path
            )
            .expect("writing to String cannot fail");
        }
    }

    if !profile.environment_variables.is_empty() {
        writeln!(output).expect("writing to String cannot fail");
        writeln!(output, "## Environment variable names").expect("writing to String cannot fail");
        writeln!(output).expect("writing to String cannot fail");
        for variable in &profile.environment_variables {
            writeln!(
                output,
                "- `{}` (observed in `{}`)",
                variable.name, variable.evidence_path
            )
            .expect("writing to String cannot fail");
        }
    }
    output
}

fn status_name(status: DetectionStatus) -> &'static str {
    match status {
        DetectionStatus::Detected => "detected",
        DetectionStatus::NeedsConfirmation => "needs_confirmation",
        DetectionStatus::Unsupported => "unsupported",
    }
}

fn escape_table(value: &str) -> String {
    value.replace('|', "\\|")
}

fn default_database_path() -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from("dev", "LaunchGuard", "LaunchGuard")
        .ok_or_else(|| anyhow!("could not determine the user data directory"))?;
    Ok(project_dirs.data_local_dir().join("history.sqlite3"))
}

fn default_artifact_path() -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from("dev", "LaunchGuard", "LaunchGuard")
        .ok_or_else(|| anyhow!("could not determine the user data directory"))?;
    Ok(project_dirs.data_local_dir().join("artifacts"))
}

fn initialize_tracing(format: LogFormat, verbose: bool) -> Result<()> {
    let default_filter = if verbose {
        "launchguard=debug"
    } else {
        "launchguard=info"
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_filter))
        .context("invalid tracing filter")?;

    match format {
        LogFormat::Pretty => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .try_init()
            .map_err(|error| anyhow!("failed to initialize tracing: {error}"))?,
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(true)
            .try_init()
            .map_err(|error| anyhow!("failed to initialize tracing: {error}"))?,
    }
    Ok(())
}
