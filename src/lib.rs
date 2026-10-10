//! Atomic opaque issuer records. Callers must verify changes before issuing them.
//! No proof verification, holder keys, balances, receipts or request logging.
pub mod certificate;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::runtime::Runtime;

/// Storage failures deliberately contain no SQL, credentials or record data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("issuer storage failure")
    }
}
impl std::error::Error for Error {}
/// Storage result.
pub type Result<T> = std::result::Result<T, Error>;
/// One current opaque key/value pair, never an account-history entry.
pub type CurrentRecord = (Vec<u8>, Vec<u8>);
/// An atomic community-scoped issuer transaction. Dropping discards all changes.
pub trait Transaction {
    /// Read one exact current key.
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    /// Read a bounded half-open range of CURRENT opaque records in this same
    /// transaction, ordered by the composite primary key. Used by cblc's common
    /// epoch freeze, never a member lookup endpoint or an account-history scan.
    /// Older custom stores fail closed until they implement the actual snapshot.
    fn current_range(
        &mut self,
        _start: &[u8],
        _end: &[u8],
        _limit: u32,
    ) -> Result<Vec<CurrentRecord>> {
        Err(Error)
    }
    /// Replace a current record. Never append account history.
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
    /// Remove one exact record.
    fn delete(&mut self, key: &[u8]) -> Result<()>;
    /// Commit all changes together.
    fn commit(self: Box<Self>) -> Result<()>;
    /// Explicit rollback, including after an error.
    fn rollback(self: Box<Self>) -> Result<()>;
}
/// The small synchronous storage contract used by the balance facade.
/// A transaction serializes reads and writes against competing issuer instances.
pub trait Storage: Send {
    /// Begin an exclusive transaction. Do not hold it while verifying a proof.
    fn transaction(&mut self) -> Result<Box<dyn Transaction + '_>>;
}
/// Memory storage for deterministic tests; clones share the same community.
#[derive(Clone, Default)]
pub struct MemoryStore(Arc<Mutex<Records>>);
type Records = BTreeMap<Vec<u8>, Vec<u8>>;
struct MemoryTransaction<'a> {
    guard: MutexGuard<'a, BTreeMap<Vec<u8>, Vec<u8>>>,
    pending: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl Storage for MemoryStore {
    fn transaction(&mut self) -> Result<Box<dyn Transaction + '_>> {
        let guard = self.0.lock().or(Err(Error))?;
        let pending = guard.clone();
        Ok(Box::new(MemoryTransaction { guard, pending }))
    }
}
impl Transaction for MemoryTransaction<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.pending.get(key).cloned())
    }
    fn current_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<CurrentRecord>> {
        range_bounds(start, end, limit)?;
        Ok(self
            .pending
            .range(start.to_vec()..end.to_vec())
            .take(limit as usize)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.pending.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.pending.remove(key);
        Ok(())
    }
    fn commit(mut self: Box<Self>) -> Result<()> {
        *self.guard = std::mem::take(&mut self.pending);
        Ok(())
    }
    fn rollback(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}
/// Include this DDL in the service's shared migration history when composing leaves.
pub const SCHEMA: &str = "CREATE TABLE cssr_records (
 community_id TEXT NOT NULL, key BLOB NOT NULL, value BLOB NOT NULL,
 PRIMARY KEY (community_id,key)) WITHOUT ROWID;";
fn range_bounds(start: &[u8], end: &[u8], limit: u32) -> Result<()> {
    // One sentinel beyond the depth-20 capacity detects an oversized snapshot.
    if start.is_empty() || start >= end || !(1..=((1 << 20) + 1)).contains(&limit) {
        return Err(Error);
    }
    Ok(())
}
/// A libSQL store using the shared crlt facade. All queries use the composite primary key.
/// Run synchronous methods on a blocking thread outside a Tokio runtime.
pub struct LibsqlStore {
    runtime: Arc<Runtime>,
    community: crlt::Community,
}
impl LibsqlStore {
    /// Open an isolated library database. Services sharing a schema use `from_community`.
    pub fn open(config: crlt::Config, community: &str) -> Result<Self> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .or(Err(Error))?,
        );
        let db = runtime.block_on(crlt::Db::open(config)).or(Err(Error))?;
        runtime
            .block_on(db.migrate(&[crlt::Migration::new(1, "issuer", SCHEMA)]))
            .or(Err(Error))?;
        let scoped = db.community(community).or(Err(Error))?;
        Ok(Self {
            runtime,
            community: scoped,
        })
    }
    /// Open a real local file through the official libSQL client.
    pub fn local(path: impl AsRef<Path>, community: &str) -> Result<Self> {
        let path = std::path::absolute(path).or(Err(Error))?;
        let url = url::Url::from_file_path(path).or(Err(Error))?;
        Self::open(crlt::Config::new(url.to_string(), ""), community)
    }
    /// Compose with a service-owned, already migrated community capability.
    pub fn from_community(runtime: Arc<Runtime>, community: crlt::Community) -> Self {
        Self { runtime, community }
    }
    /// Verify the exact production read/write/delete query plans use indexes.
    pub fn check_query_plans(&self) -> Result<()> {
        for (sql, params) in [
            (
                "SELECT value FROM cssr_records WHERE key=?1",
                vec![crlt::Value::Blob(vec![0])],
            ),
            (
                "UPDATE cssr_records SET value=?2 WHERE key=?1",
                vec![crlt::Value::Blob(vec![0]), crlt::Value::Blob(vec![1])],
            ),
            (
                "DELETE FROM cssr_records WHERE key=?1",
                vec![crlt::Value::Blob(vec![0])],
            ),
            (
                "SELECT key,value FROM cssr_records WHERE key>=?1 AND key<?2 ORDER BY key LIMIT ?3",
                vec![
                    crlt::Value::Blob(vec![1]),
                    crlt::Value::Blob(vec![2]),
                    crlt::Value::Integer(100),
                ],
            ),
        ] {
            self.runtime
                .block_on(self.community.explain(sql, params))
                .and_then(|p| p.assert_indexed())
                .or(Err(Error))?;
        }
        Ok(())
    }
}
struct SqlTransaction {
    runtime: Arc<Runtime>,
    tx: Option<crlt::Transaction>,
}
impl Storage for LibsqlStore {
    fn transaction(&mut self) -> Result<Box<dyn Transaction + '_>> {
        let tx = self.runtime.block_on(self.community.tx()).or(Err(Error))?;
        Ok(Box::new(SqlTransaction {
            runtime: self.runtime.clone(),
            tx: Some(tx),
        }))
    }
}
impl Transaction for SqlTransaction {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let rows = self
            .runtime
            .block_on(self.tx.as_mut().ok_or(Error)?.query(
                "SELECT value FROM cssr_records WHERE key=?1",
                crlt::params![key],
            ))
            .or(Err(Error))?;
        rows.first()
            .map(|row| match row.get_value(0).or(Err(Error))? {
                crlt::Value::Blob(value) => Ok(value.clone()),
                _ => Err(Error),
            })
            .transpose()
    }
    fn current_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        limit: u32,
    ) -> Result<Vec<CurrentRecord>> {
        range_bounds(start, end, limit)?;
        let rows = self
            .runtime
            .block_on(self.tx.as_mut().ok_or(Error)?.query(
                "SELECT key,value FROM cssr_records WHERE key>=?1 AND key<?2 ORDER BY key LIMIT ?3",
                crlt::params![start, end, i64::from(limit)],
            ))
            .or(Err(Error))?;
        rows.iter()
            .map(|row| {
                match (
                    row.get_value(0).or(Err(Error))?,
                    row.get_value(1).or(Err(Error))?,
                ) {
                    (crlt::Value::Blob(key), crlt::Value::Blob(value)) => {
                        Ok((key.clone(), value.clone()))
                    }
                    _ => Err(Error),
                }
            })
            .collect()
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        // Keep SQL portable and scope-aware; the immediate transaction protects the check.
        let exists = self.get(key)?.is_some();
        let sql = if exists {
            "UPDATE cssr_records SET value=?2 WHERE key=?1"
        } else {
            "INSERT INTO cssr_records(key,value) VALUES(?1,?2)"
        };
        self.runtime
            .block_on(
                self.tx
                    .as_mut()
                    .ok_or(Error)?
                    .execute(sql, crlt::params![key, value]),
            )
            .or(Err(Error))?;
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.runtime
            .block_on(
                self.tx
                    .as_mut()
                    .ok_or(Error)?
                    .execute("DELETE FROM cssr_records WHERE key=?1", crlt::params![key]),
            )
            .or(Err(Error))?;
        Ok(())
    }
    fn commit(mut self: Box<Self>) -> Result<()> {
        self.runtime
            .block_on(self.tx.take().ok_or(Error)?.commit())
            .or(Err(Error))
    }
    fn rollback(mut self: Box<Self>) -> Result<()> {
        self.runtime
            .block_on(self.tx.take().ok_or(Error)?.rollback())
            .or(Err(Error))
    }
}
impl Drop for SqlTransaction {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = self.runtime.block_on(tx.rollback());
        }
    }
}
