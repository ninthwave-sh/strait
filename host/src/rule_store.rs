//! SQLite-backed persistent rule store for `strait-host`.
//!
//! The rule store owns every Cedar policy the host has collected for its
//! in-container agents. Rules are scoped: a rule at [`RuleStore::DEFAULT_SCOPE`]
//! applies to every registered container, while a rule scoped to a session
//! id applies only to that one container session. Sessions share a single
//! on-disk database because the desktop UI and the rule editor are one
//! process, and because default-scoped rules naturally need a common store.
//!
//! The store is purposefully minimal:
//!
//!   * [`RuleStore::open`] points at a filesystem path. Missing directories
//!     are created. Schema migrations run on open.
//!   * [`RuleStore::upsert`], [`RuleStore::remove`], [`RuleStore::get`],
//!     [`RuleStore::list_all`], and [`RuleStore::snapshot_for_session`]
//!     handle CRUD. Every mutating call assigns a fresh `version_token` so
//!     stream listeners can de-duplicate.
//!   * [`RuleStore::subscribe`] returns a `tokio::sync::broadcast::Receiver`
//!     that the gRPC `StreamRules` impl tails after sending the initial
//!     snapshot.
//!
//! The store is shareable behind `Arc`: it uses interior mutability so one
//! instance can be handed to both the Unix-socket and TCP listeners.
//!
//! The backing `rusqlite::Connection` is held behind a `std::sync::Mutex`
//! because every SQL call is short and synchronous. Callers must not hold
//! the guard across an `await` point; all code inside this module drops the
//! guard before yielding.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, types::Type as SqlType, Connection, OptionalExtension};
use tokio::sync::broadcast;

use crate::migrations;

/// Broadcast channel capacity for live rule updates. Large enough to absorb
/// burst inserts without lagging a slow subscriber; small enough that a
/// wedged subscriber cannot keep unbounded memory pinned.
const BROADCAST_CAPACITY: usize = 256;

/// What to do when a Cedar policy matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Permit the request and proceed with upstream call.
    Allow,
    /// Return a proxy-generated denial.
    Deny,
    /// Hold the request and ask the operator for a verdict.
    Prompt,
}

impl RuleAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Prompt => "prompt",
        }
    }

    fn parse(s: &str) -> Result<Self, UnknownEnum> {
        Ok(match s {
            "allow" => Self::Allow,
            "deny" => Self::Deny,
            "prompt" => Self::Prompt,
            other => return Err(UnknownEnum(other.to_string())),
        })
    }
}

/// How long a rule stays live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDuration {
    /// Applies to exactly one request; the caller deletes the rule after
    /// applying it. Used by hold-and-resume `ALLOW_ONCE` verdicts.
    Once,
    /// Applies for the life of the owning session; deleted when the agent
    /// unregisters or the host restarts without persistence.
    Session,
    /// Persisted across host restarts. The default duration for rules the
    /// operator writes directly in the desktop app.
    Persist,
}

impl RuleDuration {
    fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::Persist => "persist",
        }
    }

    fn parse(s: &str) -> Result<Self, UnknownEnum> {
        Ok(match s {
            "once" => Self::Once,
            "session" => Self::Session,
            "persist" => Self::Persist,
            other => return Err(UnknownEnum(other.to_string())),
        })
    }
}

#[derive(Debug)]
struct UnknownEnum(String);

impl std::fmt::Display for UnknownEnum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown enum discriminant {:?}", self.0)
    }
}

impl std::error::Error for UnknownEnum {}

/// One rule row.
///
/// `version_token` is assigned by the store at insert/update time; callers
/// may leave it empty on an inbound upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub rule_id: String,
    pub scope: String,
    pub cedar_source: String,
    pub action: RuleAction,
    pub duration: RuleDuration,
    pub ttl_unix_ms: Option<i64>,
    pub version_token: String,
}

/// Broadcast event emitted when a rule is added, updated, or removed.
#[derive(Debug, Clone)]
pub enum RuleChange {
    Add(Rule),
    Update(Rule),
    Remove {
        rule_id: String,
        scope: String,
        version_token: String,
    },
}

/// SQLite-backed rule store with a `tokio` broadcast channel for live updates.
pub struct RuleStore {
    conn: Mutex<Connection>,
    updates: broadcast::Sender<RuleChange>,
    version_counter: AtomicU64,
}

impl RuleStore {
    /// Scope label that matches every registered container session.
    pub const DEFAULT_SCOPE: &'static str = "default";

    /// Open (or create) a rule store backed by `path`. Creates any missing
    /// parent directories and applies every pending migration.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating parent dir {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening rule store {}", path.display()))?;
        Self::with_connection(conn)
    }

    /// Open a throwaway in-memory rule store. Useful for tests and for
    /// non-persistent fixtures.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory rule store")?;
        Self::with_connection(conn)
    }

    fn with_connection(mut conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .context("setting busy timeout")?;
        // WAL lets multiple reader threads see a consistent snapshot while a
        // single writer is committing. Failure to switch (for example on an
        // in-memory DB that already defaults to MEMORY journalling) is not
        // fatal; the store still functions with the default journal mode.
        let _: Result<String, _> =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0));
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign_keys")?;

        migrations::apply(&mut conn).context("applying migrations")?;

        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(Self {
            conn: Mutex::new(conn),
            updates: tx,
            version_counter: AtomicU64::new(0),
        })
    }

    /// Insert or update a rule by `rule_id`. Returns the stored row with the
    /// freshly-assigned `version_token`. Broadcasts an [`RuleChange::Add`]
    /// for inserts and [`RuleChange::Update`] for updates.
    pub fn upsert(&self, mut rule: Rule) -> Result<Rule> {
        if rule.rule_id.is_empty() {
            anyhow::bail!("rule_id must not be empty");
        }
        if rule.scope.is_empty() {
            anyhow::bail!("scope must not be empty");
        }
        let now = now_unix_ms();
        let new_version = self.next_version_token();
        rule.version_token = new_version;

        let is_update = {
            let conn = self.lock();
            let existing: Option<String> = conn
                .query_row(
                    "SELECT version_token FROM rules WHERE rule_id = ?1",
                    params![rule.rule_id],
                    |row| row.get(0),
                )
                .optional()
                .context("checking existing rule")?;
            if existing.is_some() {
                conn.execute(
                    "UPDATE rules
                        SET scope = ?1,
                            cedar_source = ?2,
                            action = ?3,
                            duration = ?4,
                            ttl_unix_ms = ?5,
                            version_token = ?6,
                            updated_at_unix_ms = ?7
                      WHERE rule_id = ?8",
                    params![
                        rule.scope,
                        rule.cedar_source,
                        rule.action.as_str(),
                        rule.duration.as_str(),
                        rule.ttl_unix_ms,
                        rule.version_token,
                        now,
                        rule.rule_id,
                    ],
                )
                .context("updating rule row")?;
                true
            } else {
                conn.execute(
                    "INSERT INTO rules (
                        rule_id, scope, cedar_source, action, duration,
                        ttl_unix_ms, version_token,
                        created_at_unix_ms, updated_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                    params![
                        rule.rule_id,
                        rule.scope,
                        rule.cedar_source,
                        rule.action.as_str(),
                        rule.duration.as_str(),
                        rule.ttl_unix_ms,
                        rule.version_token,
                        now,
                    ],
                )
                .context("inserting rule row")?;
                false
            }
        };

        let change = if is_update {
            RuleChange::Update(rule.clone())
        } else {
            RuleChange::Add(rule.clone())
        };
        // `send` only errors when there are no live receivers; that's not a
        // real failure, it just means nobody is listening yet.
        let _ = self.updates.send(change);
        Ok(rule)
    }

    /// Remove a rule by id. Returns the removed rule if one existed.
    /// Broadcasts a [`RuleChange::Remove`] with a fresh `version_token`.
    pub fn remove(&self, rule_id: &str) -> Result<Option<Rule>> {
        let existing = {
            let conn = self.lock();
            let existing: Option<Rule> = conn
                .query_row(SELECT_RULE, params![rule_id], row_to_rule)
                .optional()
                .context("reading rule before remove")?;
            if existing.is_some() {
                conn.execute("DELETE FROM rules WHERE rule_id = ?1", params![rule_id])
                    .context("deleting rule row")?;
            }
            existing
        };
        let Some(rule) = existing else {
            return Ok(None);
        };
        let version_token = self.next_version_token();
        let _ = self.updates.send(RuleChange::Remove {
            rule_id: rule.rule_id.clone(),
            scope: rule.scope.clone(),
            version_token,
        });
        Ok(Some(rule))
    }

    /// Fetch one rule by id.
    pub fn get(&self, rule_id: &str) -> Result<Option<Rule>> {
        let conn = self.lock();
        conn.query_row(SELECT_RULE, params![rule_id], row_to_rule)
            .optional()
            .context("reading rule by id")
    }

    /// Return the rules a given session should see: every default-scoped
    /// rule plus every rule scoped exactly to this session id.
    pub fn snapshot_for_session(&self, session_id: &str) -> Result<Vec<Rule>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT rule_id, scope, cedar_source, action, duration,
                        ttl_unix_ms, version_token
                   FROM rules
                  WHERE scope = ?1 OR scope = ?2
                  ORDER BY rule_id",
            )
            .context("preparing snapshot_for_session")?;
        let rows: Result<Vec<Rule>, _> = stmt
            .query_map(params![Self::DEFAULT_SCOPE, session_id], row_to_rule)?
            .collect();
        rows.context("reading snapshot rows")
    }

    /// Return every rule in the store. Intended for tests and admin tools.
    pub fn list_all(&self) -> Result<Vec<Rule>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT rule_id, scope, cedar_source, action, duration,
                        ttl_unix_ms, version_token
                   FROM rules
                  ORDER BY rule_id",
            )
            .context("preparing list_all")?;
        let rows: Result<Vec<Rule>, _> = stmt.query_map([], row_to_rule)?.collect();
        rows.context("reading all rules")
    }

    /// Subscribe to live rule changes. The receiver sees every event
    /// emitted after the call returns; the initial snapshot is delivered by
    /// the caller using [`RuleStore::snapshot_for_session`].
    pub fn subscribe(&self) -> broadcast::Receiver<RuleChange> {
        self.updates.subscribe()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // Poisoning would mean a previous caller panicked mid-operation;
        // clear the poison and keep going, since every SQL call is
        // self-contained and a poisoned connection has no dangling lock.
        match self.conn.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        }
    }

    fn next_version_token(&self) -> String {
        let seq = self.version_counter.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("v-{nanos:x}-{seq:x}")
    }
}

impl std::fmt::Debug for RuleStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleStore").finish_non_exhaustive()
    }
}

const SELECT_RULE: &str = "SELECT rule_id, scope, cedar_source, action, duration,
                                  ttl_unix_ms, version_token
                             FROM rules
                            WHERE rule_id = ?1";

fn row_to_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<Rule> {
    let action: String = row.get(3)?;
    let duration: String = row.get(4)?;
    let action = RuleAction::parse(&action)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(3, SqlType::Text, Box::new(e)))?;
    let duration = RuleDuration::parse(&duration)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, SqlType::Text, Box::new(e)))?;
    Ok(Rule {
        rule_id: row.get(0)?,
        scope: row.get(1)?,
        cedar_source: row.get(2)?,
        action,
        duration,
        ttl_unix_ms: row.get(5)?,
        version_token: row.get(6)?,
    })
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
    use tempfile::tempdir;

    fn rule(id: &str, scope: &str) -> Rule {
        Rule {
            rule_id: id.into(),
            scope: scope.into(),
            cedar_source: format!("permit(principal, action, resource == \"{id}\");"),
            action: RuleAction::Allow,
            duration: RuleDuration::Persist,
            ttl_unix_ms: None,
            version_token: String::new(),
        }
    }

    #[test]
    fn migrations_run_on_fresh_in_memory_db() {
        let store = RuleStore::in_memory().unwrap();
        // A successful open means migrations ran.
        assert!(store.list_all().unwrap().is_empty());
    }

    #[test]
    fn upsert_insert_then_update_returns_fresh_version_token() {
        let store = RuleStore::in_memory().unwrap();
        let inserted = store.upsert(rule("r1", "default")).unwrap();
        assert!(!inserted.version_token.is_empty());
        let updated = store
            .upsert(Rule {
                cedar_source: "permit(principal, action, resource);".into(),
                ..inserted.clone()
            })
            .unwrap();
        assert_ne!(inserted.version_token, updated.version_token);
        assert_eq!(updated.cedar_source, "permit(principal, action, resource);");
        // Only one row should be present; upsert must not clone.
        assert_eq!(store.list_all().unwrap().len(), 1);
    }

    #[test]
    fn remove_returns_none_for_missing_rule() {
        let store = RuleStore::in_memory().unwrap();
        assert!(store.remove("nope").unwrap().is_none());
    }

    #[test]
    fn remove_returns_the_deleted_row() {
        let store = RuleStore::in_memory().unwrap();
        store.upsert(rule("r1", "default")).unwrap();
        let removed = store.remove("r1").unwrap().expect("rule existed");
        assert_eq!(removed.rule_id, "r1");
        assert!(store.get("r1").unwrap().is_none());
    }

    #[test]
    fn snapshot_for_session_filters_by_scope() {
        let store = RuleStore::in_memory().unwrap();
        store.upsert(rule("default-1", "default")).unwrap();
        store.upsert(rule("sess-a-1", "sess-a")).unwrap();
        store.upsert(rule("sess-b-1", "sess-b")).unwrap();

        let view_a = store.snapshot_for_session("sess-a").unwrap();
        let ids_a: Vec<_> = view_a.iter().map(|r| r.rule_id.as_str()).collect();
        assert_eq!(ids_a, vec!["default-1", "sess-a-1"]);

        let view_b = store.snapshot_for_session("sess-b").unwrap();
        let ids_b: Vec<_> = view_b.iter().map(|r| r.rule_id.as_str()).collect();
        assert_eq!(ids_b, vec!["default-1", "sess-b-1"]);
    }

    #[test]
    fn upsert_rejects_empty_identifiers() {
        let store = RuleStore::in_memory().unwrap();
        let err = store
            .upsert(Rule {
                rule_id: String::new(),
                ..rule("placeholder", "default")
            })
            .unwrap_err();
        assert!(err.to_string().contains("rule_id"));

        let err = store
            .upsert(Rule {
                rule_id: "ok".into(),
                scope: String::new(),
                ..rule("placeholder", "default")
            })
            .unwrap_err();
        assert!(err.to_string().contains("scope"));
    }

    #[test]
    fn persistence_survives_restart() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("rules.db");
        {
            let store = RuleStore::open(&db).unwrap();
            store.upsert(rule("keepme", "default")).unwrap();
            store
                .upsert(Rule {
                    duration: RuleDuration::Session,
                    ttl_unix_ms: Some(9_999_999),
                    ..rule("ttl-rule", "sess-x")
                })
                .unwrap();
        }
        let reopened = RuleStore::open(&db).unwrap();
        let rules = reopened.list_all().unwrap();
        assert_eq!(rules.len(), 2);
        let ttl = reopened.get("ttl-rule").unwrap().unwrap();
        assert_eq!(ttl.duration, RuleDuration::Session);
        assert_eq!(ttl.ttl_unix_ms, Some(9_999_999));
    }

    #[tokio::test]
    async fn subscribe_delivers_add_then_update_then_remove() {
        let store = RuleStore::in_memory().unwrap();
        let mut rx = store.subscribe();

        store.upsert(rule("r1", "default")).unwrap();
        let first = rx.recv().await.unwrap();
        match first {
            RuleChange::Add(r) => assert_eq!(r.rule_id, "r1"),
            other => panic!("expected Add, got {other:?}"),
        }

        store
            .upsert(Rule {
                cedar_source: "permit(principal, action, resource);".into(),
                ..rule("r1", "default")
            })
            .unwrap();
        let second = rx.recv().await.unwrap();
        match second {
            RuleChange::Update(r) => assert_eq!(r.rule_id, "r1"),
            other => panic!("expected Update, got {other:?}"),
        }

        store.remove("r1").unwrap();
        let third = rx.recv().await.unwrap();
        match third {
            RuleChange::Remove {
                rule_id,
                scope,
                version_token,
            } => {
                assert_eq!(rule_id, "r1");
                assert_eq!(scope, "default");
                assert!(!version_token.is_empty());
            }
            other => panic!("expected Remove, got {other:?}"),
        }
    }
}
