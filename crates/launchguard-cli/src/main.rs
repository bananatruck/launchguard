//! `LaunchGuard` command-line interface.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use launchguard_core::{
    ArtifactStore, CAPABILITY_REPORT_SCHEMA_JSON, CapabilityProbe, CapabilityReport,
    CapabilityStatus, DEGRADATION_SCHEMA_JSON, Degradation, DeliveryTrack, DetectionEngine,
    DetectionStatus, EXECUTION_PLAN_SCHEMA_JSON, FINDING_SCHEMA_JSON, Finding, HistoryEntry,
    HistoryStore, PROJECT_PROFILE_SCHEMA_JSON, PlanGenerator, ProjectProfile,
    RAW_ARTIFACT_SCHEMA_VERSION, READINESS_SCHEMA_JSON, RawArtifact, ReadinessEngine,
    RepositoryAcquirer, RunRecord, ScannerConfig, ScannerKind, ScannerLimits, ScannerProvenance,
    ScannerRunner, merge_findings,
};
use tracing::warn;
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
    /// Probe this host and report which delivery tracks it can run.
    Doctor {
        /// Report representation.
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },

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

        /// Trivy executable. A missing scanner degrades coverage instead of failing.
        #[arg(long, env = "LAUNCHGUARD_TRIVY", default_value = "trivy")]
        trivy_executable: PathBuf,

        /// OSV-Scanner executable. A missing scanner degrades coverage instead of failing.
        #[arg(long, env = "LAUNCHGUARD_OSV_SCANNER", default_value = "osv-scanner")]
        osv_executable: PathBuf,
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
    Degradation,
    CapabilityReport,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    initialize_tracing(cli.log_format, cli.verbose)?;
    let database_path = cli.database.map_or_else(default_database_path, Ok)?;

    match cli.command {
        Command::Doctor { format } => doctor(format).await,
        Command::Audit {
            source,
            format,
            no_history,
            scanner,
            artifact_directory,
            trivy_executable,
            osv_executable,
        } => {
            let artifact_directory = artifact_directory.map_or_else(default_artifact_path, Ok)?;
            audit(
                &source,
                format,
                no_history,
                &database_path,
                &artifact_directory,
                &scanner,
                ScannerConfig {
                    trivy_executable,
                    osv_executable,
                },
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
                SchemaRecord::Degradation => DEGRADATION_SCHEMA_JSON,
                SchemaRecord::CapabilityReport => CAPABILITY_REPORT_SCHEMA_JSON,
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
    scanner_config: ScannerConfig,
) -> Result<()> {
    let repository = RepositoryAcquirer::new()?
        .acquire(source)
        .await
        .with_context(|| format!("failed to acquire {source}"))?;
    let profile = DetectionEngine::default()
        .inspect(&repository)
        .with_context(|| format!("failed to inspect {source}"))?;

    let mut degradations = Vec::new();
    let plan = if profile.status == DetectionStatus::Detected {
        match PlanGenerator.generate(&profile) {
            Ok(plan) => Some(plan),
            Err(error) => {
                warn!(reason = %error, "continuing without a reviewed execution plan");
                degradations.push(Degradation::plan_unavailable(&error));
                None
            }
        }
    } else {
        None
    };

    let mut scanners = selected_scanners.to_vec();
    scanners.sort_unstable();
    scanners.dedup();
    let runner = ScannerRunner::new(scanner_config, ScannerLimits::default());
    let store = ArtifactStore::new(artifact_directory);
    let mut artifacts = Vec::new();
    let mut findings = Vec::new();
    let mut completed_scanners = Vec::new();
    let mut scanner_provenance = Vec::new();
    for selected in scanners {
        let scanner = ScannerKind::from(selected);
        match scan(&runner, &store, scanner, repository.root()).await {
            Ok(completed) => {
                findings.extend(completed.findings);
                artifacts.push(completed.artifact);
                scanner_provenance.extend(completed.provenance);
                completed_scanners.push(scanner);
            }
            Err(degradation) => {
                warn!(
                    scanner = scanner.as_str(),
                    kind = degradation.kind.as_str(),
                    reason = degradation.detail.as_str(),
                    "continuing with degraded security coverage"
                );
                degradations.push(degradation);
            }
        }
    }

    let findings = merge_findings(findings);
    let readiness = ReadinessEngine
        .assess(&profile, &findings, &completed_scanners, plan.as_ref())
        .context("failed to calculate readiness")?;
    let record = RunRecord {
        profile,
        plan,
        findings,
        readiness: Some(readiness),
        degradations,
        scanner_provenance,
        artifacts,
    };

    let run_id = if no_history {
        None
    } else {
        Some(HistoryStore::open(database_path)?.record(&record)?.run_id)
    };
    print_report(&record, run_id, format)
}

/// Report which delivery tracks this host can run, and why.
///
/// Discovery never blocks, installs, or mutates the host. A missing capability
/// is an outcome to report, not a reason to refuse work.
async fn doctor(format: OutputFormat) -> Result<()> {
    let report = CapabilityProbe::default()
        .detect()
        .await
        .context("failed to probe host capability")?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => println!("{}", capability_markdown(&report)),
    }
    Ok(())
}

fn capability_markdown(report: &CapabilityReport) -> String {
    let mut output = String::new();
    writeln!(output, "# LaunchGuard host capability").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    writeln!(
        output,
        "- Platform: `{}` on `{}`",
        report.platform.os, report.platform.architecture
    )
    .expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Capabilities").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    for capability in &report.capabilities {
        let mark = match capability.status {
            CapabilityStatus::Present => "found",
            CapabilityStatus::Absent => "missing",
        };
        let version = capability
            .version
            .as_deref()
            .map_or_else(String::new, |value| format!(" {value}"));
        writeln!(
            output,
            "- `{}` — {mark}{version} ({})",
            capability.kind.as_str(),
            capability.kind.purpose()
        )
        .expect("writing to String cannot fail");
    }

    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Available tracks").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    for track in &report.available_tracks {
        let description = match track {
            DeliveryTrack::Deploy => "audit, plan, generate configuration, and publish",
            DeliveryTrack::Verify => "everything above, plus locally verified build and health",
        };
        writeln!(output, "- `{}` — {description}", track.as_str())
            .expect("writing to String cannot fail");
    }
    if let Some(blocking) = report.blocking_capability {
        writeln!(output).expect("writing to String cannot fail");
        writeln!(
            output,
            "Local verification is unavailable because `{}` is missing. Deployment does not require it.",
            blocking.as_str()
        )
        .expect("writing to String cannot fail");
    }

    let gaps = report.provisionable_gaps();
    if !gaps.is_empty() {
        writeln!(output).expect("writing to String cannot fail");
        writeln!(output, "## Next step").expect("writing to String cannot fail");
        writeln!(output).expect("writing to String cannot fail");
        let names = gaps
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            output,
            "Run `launchguard setup` to install {names} from pinned, checksum-verified releases."
        )
        .expect("writing to String cannot fail");
    }
    output
}

/// One scanner that completed, persisted, and normalized successfully.
struct CompletedScan {
    findings: Vec<Finding>,
    artifact: RawArtifact,
    provenance: Option<ScannerProvenance>,
}

/// Run one scanner, converting any failure into a typed degradation.
///
/// A scanner that cannot run reduces coverage; it does not end the audit.
async fn scan(
    runner: &ScannerRunner,
    store: &ArtifactStore,
    scanner: ScannerKind,
    repository: &Path,
) -> std::result::Result<CompletedScan, Degradation> {
    let report = runner
        .run(scanner, repository)
        .await
        .map_err(|error| Degradation::from_scanner_error(scanner, &error))?;
    let artifact = report
        .persist(store)
        .map_err(|error| Degradation::artifact_not_stored(scanner, &error))?;
    let findings = report
        .normalize(&artifact)
        .map_err(|error| Degradation::from_scanner_error(scanner, &error))?;
    let provenance = match runner.provenance(scanner).await {
        Ok(provenance) => Some(provenance),
        Err(error) => {
            warn!(
                scanner = scanner.as_str(),
                reason = %error,
                "scanner version is unavailable; the report cannot cite a scanner or database version"
            );
            None
        }
    };
    Ok(CompletedScan {
        findings,
        artifact,
        provenance,
    })
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
    let record = RunRecord {
        profile,
        plan: Some(plan),
        findings: Vec::new(),
        readiness: Some(readiness),
        degradations: Vec::new(),
        scanner_provenance: Vec::new(),
        artifacts: Vec::new(),
    };
    print_report(&record, None, format)
}

fn print_entry(entry: &HistoryEntry, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(entry)?);
        }
        OutputFormat::Markdown => {
            println!("{}", report_markdown(&entry.record, Some(entry.run_id)));
        }
    }
    Ok(())
}

fn print_report(record: &RunRecord, run_id: Option<Uuid>, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let mut output = serde_json::to_value(record)?;
            if let Some(object) = output.as_object_mut() {
                object.insert("run_id".to_owned(), serde_json::to_value(run_id)?);
            }
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Markdown => println!("{}", report_markdown(record, run_id)),
    }
    Ok(())
}

fn report_markdown(record: &RunRecord, run_id: Option<Uuid>) -> String {
    let mut output = profile_markdown(&record.profile, run_id);
    append_findings(&mut output, record);
    append_degradations(&mut output, &record.degradations);
    append_plan_and_scores(&mut output, record);
    output
}

fn append_findings(output: &mut String, record: &RunRecord) {
    let completed = record
        .readiness
        .as_ref()
        .map_or(0, |readiness| readiness.completed_scanners.len());
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Security findings").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    if completed == 0 {
        writeln!(
            output,
            "No scanner completed. Security readiness is incomplete."
        )
        .expect("writing to String cannot fail");
    } else if record.findings.is_empty() {
        writeln!(
            output,
            "No findings were reported by the completed scanners. This is not evidence that none exist."
        )
        .expect("writing to String cannot fail");
    } else {
        for finding in &record.findings {
            writeln!(
                output,
                "- `{:?}` / `{:?}` — {} (`{}`)",
                finding.category, finding.severity, finding.summary, finding.fingerprint
            )
            .expect("writing to String cannot fail");
        }
    }
    if !record.scanner_provenance.is_empty() {
        writeln!(output).expect("writing to String cannot fail");
        writeln!(output, "Completed scanners:").expect("writing to String cannot fail");
        for provenance in &record.scanner_provenance {
            let database = provenance
                .vulnerability_database_updated_at
                .as_deref()
                .or(provenance.vulnerability_database_version.as_deref())
                .map_or_else(
                    || "no local database reported".to_owned(),
                    |value| format!("database {value}"),
                );
            writeln!(
                output,
                "- {} {} ({database})",
                provenance.scanner.as_str(),
                provenance.version
            )
            .expect("writing to String cannot fail");
        }
    }
    if !record.artifacts.is_empty() {
        writeln!(output).expect("writing to String cannot fail");
        writeln!(
            output,
            "Raw reports use artifact schema `{RAW_ARTIFACT_SCHEMA_VERSION}` and remain local:"
        )
        .expect("writing to String cannot fail");
        for artifact in &record.artifacts {
            writeln!(
                output,
                "- {}: `{}`",
                artifact.scanner.as_str(),
                artifact.relative_path
            )
            .expect("writing to String cannot fail");
        }
    }
}

fn append_degradations(output: &mut String, degradations: &[Degradation]) {
    if degradations.is_empty() {
        return;
    }
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Coverage degradations").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    writeln!(
        output,
        "This run completed with reduced coverage. Treat the result as partial."
    )
    .expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    for degradation in degradations {
        writeln!(
            output,
            "- `{}` for `{}`: {}",
            degradation.kind.as_str(),
            degradation.subject,
            degradation.detail
        )
        .expect("writing to String cannot fail");
    }
}

fn append_plan_and_scores(output: &mut String, record: &RunRecord) {
    let plan = record.plan.as_ref();
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
        let reason = if record.profile.status == DetectionStatus::Detected {
            "no reviewed template covers this detected project"
        } else {
            "project classification is not unambiguous"
        };
        writeln!(output, "No plan was generated because {reason}.")
            .expect("writing to String cannot fail");
    }

    let Some(readiness) = record.readiness.as_ref() else {
        return;
    };
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "## Deterministic readiness").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "- Policy: `{}`", readiness.policy_version)
        .expect("writing to String cannot fail");
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
                let profile = entry.profile();
                let framework = profile
                    .framework
                    .map_or_else(|| "—".to_owned(), |value| value.to_string());
                println!(
                    "| `{}` | {} | `{:?}` | {} | `{}` |",
                    entry.run_id,
                    entry.created_at.format("%Y-%m-%d %H:%M:%S"),
                    profile.status,
                    framework,
                    escape_table(&profile.source)
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
