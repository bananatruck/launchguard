//! `LaunchGuard` command-line interface.

use std::{fmt::Write as _, path::PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use launchguard_core::{
    DetectionEngine, DetectionStatus, HistoryEntry, HistoryStore, PROJECT_PROFILE_SCHEMA_JSON,
    ProjectProfile, RepositoryAcquirer,
};
use serde_json::json;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "launchguard",
    version,
    about = "Read-only deployment readiness inspection",
    long_about = "LaunchGuard Phase 1 detects supported project stacks without executing repository code."
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

    /// Print the bundled `ProjectProfile` JSON Schema.
    Schema,
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
        } => audit(&source, format, no_history, &database_path).await,
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
        Command::Schema => {
            println!("{PROJECT_PROFILE_SCHEMA_JSON}");
            Ok(())
        }
    }
}

async fn audit(
    source: &str,
    format: OutputFormat,
    no_history: bool,
    database_path: &PathBuf,
) -> Result<()> {
    let repository = RepositoryAcquirer::new()?
        .acquire(source)
        .await
        .with_context(|| format!("failed to acquire {source}"))?;
    let profile = DetectionEngine::default()
        .inspect(&repository)
        .with_context(|| format!("failed to inspect {source}"))?;

    let run_id = if no_history {
        None
    } else {
        Some(HistoryStore::open(database_path)?.record(&profile)?.run_id)
    };
    print_profile(&profile, run_id, format)
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

fn print_profile(
    profile: &ProjectProfile,
    run_id: Option<Uuid>,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let output = json!({
                "run_id": run_id,
                "profile": profile,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Markdown => println!("{}", profile_markdown(profile, run_id)),
    }
    Ok(())
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
