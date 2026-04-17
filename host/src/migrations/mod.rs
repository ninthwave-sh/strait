//! SQLite schema migrations for the host rule store.
//!
//! Migrations are tracked in a `schema_migrations` table that records which
//! numbered migrations have been applied. The list is append-only: new
//! migrations take a fresh version number and live alongside the existing
//! ones. The apply function is idempotent, so a freshly-opened database and
//! an already-migrated one both return Ok(()).
//!
//! SQL sources live as sibling files embedded via `include_str!`. Keeping the
//! SQL out of `.rs` files makes the schema easy to grep for and easy to diff
//! when a migration lands.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

/// One numbered migration step.
struct Migration {
    version: u32,
    sql: &'static str,
}

/// All migrations in application order. Append new entries; never renumber
/// or rewrite an existing one. The apply function skips any version already
/// recorded in `schema_migrations`.
const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: include_str!("001_initial.sql"),
}];

/// Apply every migration that has not yet been recorded in the `schema_migrations`
/// table. Creates the table on first run. Each migration is applied inside a
/// transaction so a crash mid-migration does not leave the database in an
/// inconsistent state.
pub fn apply(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at_unix_ms INTEGER NOT NULL
        );",
    )
    .context("creating schema_migrations table")?;

    let applied = applied_versions(conn).context("reading applied migrations")?;

    for m in MIGRATIONS {
        if applied.contains(&m.version) {
            continue;
        }
        let tx = conn
            .transaction()
            .context("starting migration transaction")?;
        tx.execute_batch(m.sql)
            .with_context(|| format!("applying migration {}", m.version))?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at_unix_ms) VALUES (?1, ?2)",
            params![i64::from(m.version), now_unix_ms()],
        )
        .with_context(|| format!("recording migration {}", m.version))?;
        tx.commit()
            .with_context(|| format!("committing migration {}", m.version))?;
    }

    Ok(())
}

/// Return the set of already-applied migration versions. Exposed for tests
/// that want to assert the schema version after a fresh open.
pub fn applied_versions(conn: &Connection) -> Result<Vec<u32>> {
    let mut stmt = conn
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .context("preparing schema_migrations query")?;
    let rows: Result<Vec<u32>, _> = stmt
        .query_map([], |row| row.get::<_, i64>(0).map(|v| v as u32))?
        .collect();
    rows.context("reading applied migration rows")
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_is_idempotent_on_fresh_db() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn).unwrap();
        apply(&mut conn).unwrap();
        let versions = applied_versions(&conn).unwrap();
        assert_eq!(versions, vec![1]);
    }

    #[test]
    fn schema_creates_rules_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "rules table should exist");
    }

    #[test]
    fn schema_creates_scope_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_rules_scope'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "idx_rules_scope should exist");
    }
}
