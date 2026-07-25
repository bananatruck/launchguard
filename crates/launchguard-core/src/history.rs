//! SQLite-backed history for immutable Phase 1 inspection records.

use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{LaunchGuardError, ProjectProfile, Result};

const DATABASE_SCHEMA_VERSION: i64 = 1;

/// A persisted inspection run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Time-sortable run identifier.
    pub run_id: Uuid,
    /// UTC creation time.
    pub created_at: DateTime<Utc>,
    /// Full versioned detector output.
    pub profile: ProjectProfile,
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

    /// Persist a profile as a new immutable run.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown profile schema, serialization failure,
    /// or database write failure.
    pub fn record(&self, profile: &ProjectProfile) -> Result<HistoryEntry> {
        profile.validate_schema()?;
        let run_id = Uuid::now_v7();
        let created_at = Utc::now();
        let profile_json = serde_json::to_string(profile)?;
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
                profile_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ",
            params![
                run_id.to_string(),
                created_at.to_rfc3339(),
                profile.source,
                profile.revision,
                status,
                profile.schema_version,
                profile_json,
            ],
        )?;
        Ok(HistoryEntry {
            run_id,
            created_at,
            profile: profile.clone(),
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
            SELECT run_id, created_at, profile_json
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
            SELECT run_id, created_at, profile_json
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
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter().map(StoredRow::into_entry).collect()
    }
}

struct StoredRow {
    run_id: String,
    created_at: String,
    profile_json: String,
}

impl StoredRow {
    fn into_entry(self) -> Result<HistoryEntry> {
        let profile = serde_json::from_str::<ProjectProfile>(&self.profile_json)?;
        profile.validate_schema()?;
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
            profile,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::HistoryStore;
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
        let recorded = store.record(&unsupported_profile()).expect("record run");
        let loaded = store.get(recorded.run_id).expect("load run");
        assert_eq!(loaded.profile, recorded.profile);
        assert_eq!(store.list(10).expect("list runs").len(), 1);
    }
}
