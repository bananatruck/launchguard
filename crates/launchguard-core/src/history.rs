//! SQLite-backed history for immutable inspection records.
//!
//! Schema version 2 retains the complete audit record: the detector profile,
//! normalized findings, the reviewed execution plan, the deterministic
//! readiness assessment, scanner provenance, and any coverage degradations.
//! Version 1 rows remain readable and report empty Phase 2 sections.

use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Degradation, ExecutionPlan, Finding, LaunchGuardError, ProjectProfile, RawArtifact,
    ReadinessAssessment, Result, ScannerProvenance,
};

const DATABASE_SCHEMA_VERSION: i64 = 2;

/// Everything one audit produced, stored and replayed as a unit.
///
/// Findings carry only scanner-neutral metadata. Raw reports stay in the
/// content-addressed artifact store and are referenced by digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRecord {
    /// Full versioned detector output.
    pub profile: ProjectProfile,
    /// Reviewed execution plan, when one could be generated.
    #[serde(default)]
    pub plan: Option<ExecutionPlan>,
    /// Deduplicated normalized findings.
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Deterministic readiness assessment.
    #[serde(default)]
    pub readiness: Option<ReadinessAssessment>,
    /// Capabilities that did not complete.
    #[serde(default)]
    pub degradations: Vec<Degradation>,
    /// Scanner build and database identity.
    #[serde(default)]
    pub scanner_provenance: Vec<ScannerProvenance>,
    /// References to locally stored raw reports.
    #[serde(default)]
    pub artifacts: Vec<RawArtifact>,
}

impl RunRecord {
    /// Build a profile-only record, as produced before any scanner runs.
    #[must_use]
    pub const fn new(profile: ProjectProfile) -> Self {
        Self {
            profile,
            plan: None,
            findings: Vec::new(),
            readiness: None,
            degradations: Vec::new(),
            scanner_provenance: Vec::new(),
            artifacts: Vec::new(),
        }
    }
}

/// A persisted inspection run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Time-sortable run identifier.
    pub run_id: Uuid,
    /// UTC creation time.
    pub created_at: DateTime<Utc>,
    /// Complete audit record for the run.
    #[serde(flatten)]
    pub record: RunRecord,
}

impl HistoryEntry {
    /// Detector output for the run.
    #[must_use]
    pub const fn profile(&self) -> &ProjectProfile {
        &self.record.profile
    }
}

/// Local `SQLite` store for detector runs.
pub struct HistoryStore {
    connection: Connection,
    path: PathBuf,
}

impl HistoryStore {
    /// Open or create a history database and apply compatible migrations.
    ///
    /// # Errors
    ///
    /// Returns an error when the parent directory cannot be created or the
    /// database cannot be opened or migrated.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS inspection_runs (
                run_id TEXT PRIMARY KEY NOT NULL,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                revision TEXT NOT NULL,
                status TEXT NOT NULL,
                profile_schema_version TEXT NOT NULL,
                profile_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS inspection_runs_created_at
                ON inspection_runs(created_at DESC);
            ",
        )?;
        migrate_to_version_two(&connection)?;
        connection.pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    /// Path to the active database.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist a complete audit record as a new immutable run.
    ///
    /// Content-addressed records are re-validated before storage so a run can
    /// never persist a plan or assessment whose digest does not reproduce.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown profile schema, a digest mismatch,
    /// serialization failure, or a database write failure.
    pub fn record(&self, record: &RunRecord) -> Result<HistoryEntry> {
        let profile = &record.profile;
        profile.validate_schema()?;
        if let Some(plan) = &record.plan {
            plan.validate_digest()?;
        }
        if let Some(readiness) = &record.readiness {
            readiness.validate_digest()?;
        }
        let run_id = Uuid::now_v7();
        let created_at = Utc::now();
        let profile_json = serde_json::to_string(profile)?;
        let records_json = serde_json::to_string(&StoredRecords::from(record))?;
        let status = match profile.status {
            crate::DetectionStatus::Detected => "detected",
            crate::DetectionStatus::NeedsConfirmation => "needs_confirmation",
            crate::DetectionStatus::Unsupported => "unsupported",
        };
        self.connection.execute(
            "
            INSERT INTO inspection_runs (
                run_id,
                created_at,
                source,
                revision,
                status,
                profile_schema_version,
                profile_json,
                plan_digest,
                findings_digest,
                reproduction_digest,
                records_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ",
            params![
                run_id.to_string(),
                created_at.to_rfc3339(),
                profile.source,
                profile.revision,
                status,
                profile.schema_version,
                profile_json,
                record.plan.as_ref().map(|plan| plan.digest.as_str()),
                record
                    .readiness
                    .as_ref()
                    .map(|readiness| readiness.findings_digest.as_str()),
                record
                    .readiness
                    .as_ref()
                    .map(|readiness| readiness.reproduction_digest.as_str()),
                records_json,
            ],
        )?;
        Ok(HistoryEntry {
            run_id,
            created_at,
            record: record.clone(),
        })
    }

    /// Load one run by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the run does not exist, the stored profile is
    /// invalid, or the database cannot be read.
    pub fn get(&self, run_id: Uuid) -> Result<HistoryEntry> {
        let mut statement = self.connection.prepare(
            "
            SELECT run_id, created_at, profile_json, records_json
            FROM inspection_runs
            WHERE run_id = ?1
            ",
        )?;
        let row = statement
            .query_row([run_id.to_string()], |row| {
                Ok(StoredRow {
                    run_id: row.get(0)?,
                    created_at: row.get(1)?,
                    profile_json: row.get(2)?,
                    records_json: row.get(3)?,
                })
            })
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    LaunchGuardError::RunNotFound(run_id.to_string())
                }
                other => LaunchGuardError::Sqlite(other),
            })?;
        row.into_entry()
    }

    /// Return newest runs first, bounded by `limit`.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be read or a stored profile
    /// is invalid.
    pub fn list(&self, limit: usize) -> Result<Vec<HistoryEntry>> {
        let bounded_limit = limit.clamp(1, 1_000);
        let mut statement = self.connection.prepare(
            "
            SELECT run_id, created_at, profile_json, records_json
            FROM inspection_runs
            ORDER BY created_at DESC
            LIMIT ?1
            ",
        )?;
        let rows = statement
            .query_map([i64::try_from(bounded_limit).unwrap_or(1_000)], |row| {
                Ok(StoredRow {
                    run_id: row.get(0)?,
                    created_at: row.get(1)?,
                    profile_json: row.get(2)?,
                    records_json: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter().map(StoredRow::into_entry).collect()
    }
}

/// Phase 2 sections of a run, stored beside the profile.
///
/// Every field defaults so a schema version 1 row deserializes as an audit
/// that simply had no scanners, plan, or assessment.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredRecords {
    #[serde(default)]
    plan: Option<ExecutionPlan>,
    #[serde(default)]
    findings: Vec<Finding>,
    #[serde(default)]
    readiness: Option<ReadinessAssessment>,
    #[serde(default)]
    degradations: Vec<Degradation>,
    #[serde(default)]
    scanner_provenance: Vec<ScannerProvenance>,
    #[serde(default)]
    artifacts: Vec<RawArtifact>,
}

impl From<&RunRecord> for StoredRecords {
    fn from(record: &RunRecord) -> Self {
        Self {
            plan: record.plan.clone(),
            findings: record.findings.clone(),
            readiness: record.readiness.clone(),
            degradations: record.degradations.clone(),
            scanner_provenance: record.scanner_provenance.clone(),
            artifacts: record.artifacts.clone(),
        }
    }
}

struct StoredRow {
    run_id: String,
    created_at: String,
    profile_json: String,
    records_json: Option<String>,
}

impl StoredRow {
    fn into_entry(self) -> Result<HistoryEntry> {
        let profile = serde_json::from_str::<ProjectProfile>(&self.profile_json)?;
        profile.validate_schema()?;
        let stored = match self.records_json.as_deref() {
            Some(json) if !json.is_empty() => serde_json::from_str::<StoredRecords>(json)?,
            _ => StoredRecords::default(),
        };
        let run_id = Uuid::parse_str(&self.run_id)
            .map_err(|error| LaunchGuardError::RunNotFound(error.to_string()))?;
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map_err(|error| {
                LaunchGuardError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            })?
            .with_timezone(&Utc);
        Ok(HistoryEntry {
            run_id,
            created_at,
            record: RunRecord {
                profile,
                plan: stored.plan,
                findings: stored.findings,
                readiness: stored.readiness,
                degradations: stored.degradations,
                scanner_provenance: stored.scanner_provenance,
                artifacts: stored.artifacts,
            },
        })
    }
}

/// Add the schema version 2 columns to a database created by an earlier release.
fn migrate_to_version_two(connection: &Connection) -> Result<()> {
    for (column, definition) in [
        ("plan_digest", "TEXT"),
        ("findings_digest", "TEXT"),
        ("reproduction_digest", "TEXT"),
        ("records_json", "TEXT"),
    ] {
        if !column_exists(connection, column)? {
            connection.execute_batch(&format!(
                "ALTER TABLE inspection_runs ADD COLUMN {column} {definition};"
            ))?;
        }
    }
    Ok(())
}

fn column_exists(connection: &Connection, column: &str) -> Result<bool> {
    let mut statement =
        connection.prepare("SELECT name FROM pragma_table_info('inspection_runs')")?;
    let mut names = statement.query_map([], |row| row.get::<_, String>(0))?;
    Ok(names.any(|name| name.is_ok_and(|name| name == column)))
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, params};

    use super::{HistoryStore, RunRecord};
    use crate::{DetectionStatus, PROJECT_PROFILE_SCHEMA_VERSION, ProjectProfile};

    fn unsupported_profile() -> ProjectProfile {
        ProjectProfile {
            schema_version: PROJECT_PROFILE_SCHEMA_VERSION.to_owned(),
            source: "/tmp/example".to_owned(),
            revision: "unversioned".to_owned(),
            status: DetectionStatus::Unsupported,
            components: Vec::new(),
            framework: None,
            runtime: None,
            package_manager: None,
            deployment_kind: None,
            build_command: None,
            test_commands: Vec::new(),
            start_command: None,
            output_directory: None,
            detected_ports: Vec::new(),
            required_services: Vec::new(),
            environment_variables: Vec::new(),
            confidence: 0.0,
            candidates: Vec::new(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn profile_round_trips_through_sqlite() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let store =
            HistoryStore::open(directory.path().join("history.sqlite3")).expect("open history");
        let recorded = store
            .record(&RunRecord::new(unsupported_profile()))
            .expect("record run");
        let loaded = store.get(recorded.run_id).expect("load run");
        assert_eq!(loaded.profile(), recorded.profile());
        assert_eq!(loaded.record, recorded.record);
        assert_eq!(store.list(10).expect("list runs").len(), 1);
    }

    #[test]
    fn schema_version_one_databases_are_migrated_and_remain_readable() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("history.sqlite3");
        let profile = unsupported_profile();

        let legacy = Connection::open(&path).expect("create legacy database");
        legacy
            .execute_batch(
                "
                CREATE TABLE inspection_runs (
                    run_id TEXT PRIMARY KEY NOT NULL,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    status TEXT NOT NULL,
                    profile_schema_version TEXT NOT NULL,
                    profile_json TEXT NOT NULL
                );
                PRAGMA user_version = 1;
                ",
            )
            .expect("create legacy table");
        let legacy_run = uuid::Uuid::now_v7();
        legacy
            .execute(
                "INSERT INTO inspection_runs VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    legacy_run.to_string(),
                    chrono::Utc::now().to_rfc3339(),
                    profile.source,
                    profile.revision,
                    "unsupported",
                    profile.schema_version,
                    serde_json::to_string(&profile).expect("serialize profile"),
                ],
            )
            .expect("insert legacy run");
        drop(legacy);

        let store = HistoryStore::open(&path).expect("migrate and open history");
        let loaded = store.get(legacy_run).expect("read migrated run");
        assert_eq!(loaded.profile(), &profile);
        assert!(loaded.record.plan.is_none());
        assert!(loaded.record.findings.is_empty());
        assert!(loaded.record.readiness.is_none());

        store
            .record(&RunRecord::new(profile))
            .expect("write after migration");
        assert_eq!(store.list(10).expect("list runs").len(), 2);

        let version: i64 = Connection::open(&path)
            .expect("reopen database")
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read user_version");
        assert_eq!(version, 2);
    }
}
