//! Integration tests for the public contract.
use cssr::{LibsqlStore, MemoryStore, Storage, Transaction};
fn round_trip(store: &mut dyn Storage) {
    {
        let mut tx = store.transaction().unwrap();
        tx.put(b"state", b"first").unwrap();
        tx.commit().unwrap();
    }
    {
        let mut tx = store.transaction().unwrap();
        assert_eq!(tx.get(b"state").unwrap(), Some(b"first".to_vec()));
        tx.put(b"state", b"aborted").unwrap();
        tx.rollback().unwrap();
    }
    {
        let mut tx = store.transaction().unwrap();
        tx.delete(b"state").unwrap();
        // Implicit rollback on drop must preserve the committed value too.
    }
    {
        let mut tx = store.transaction().unwrap();
        assert_eq!(tx.get(b"state").unwrap(), Some(b"first".to_vec()));
        tx.put(b"state", b"next").unwrap();
        tx.put(b"marker", b"spent").unwrap();
        tx.commit().unwrap();
    }
    {
        let mut tx = store.transaction().unwrap();
        assert_eq!(tx.get(b"state").unwrap(), Some(b"next".to_vec()));
        assert_eq!(tx.get(b"marker").unwrap(), Some(b"spent".to_vec()));
        tx.delete(b"state").unwrap();
        tx.commit().unwrap();
    }
    assert!(
        store
            .transaction()
            .unwrap()
            .get(b"state")
            .unwrap()
            .is_none()
    );
}

#[test]
fn invalid_storage_configuration_refuses_without_record_data() {
    let dir = tempfile::tempdir().unwrap();
    assert!(LibsqlStore::local(dir.path(), "a").is_err());
    assert!(LibsqlStore::local(dir.path().join("bad"), "").is_err());
    assert!(LibsqlStore::open(crlt::Config::new("garbage", ""), "a").is_err());
    assert_eq!(cssr::Error.to_string(), "issuer storage failure");
}

#[test]
fn interrupted_memory_transaction_is_never_recovered_as_accepted() {
    let mut store = MemoryStore::default();
    let mut other = store.clone();
    let worker = std::thread::spawn(move || {
        let mut tx = other.transaction().unwrap();
        tx.put(b"state", b"uncommitted").unwrap();
        panic!("synthetic interrupted transaction");
    });
    assert!(worker.join().is_err());
    assert!(store.transaction().is_err());
}

#[test]
fn service_composition_rejects_corrupt_values_and_absent_schema() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
    );
    let url = url::Url::from_file_path(dir.path().join("service.db")).unwrap();
    let db = runtime
        .block_on(crlt::Db::open(crlt::Config::new(url.to_string(), "")))
        .unwrap();
    let community = db.community("service").unwrap();
    let mut store = LibsqlStore::from_community(runtime.clone(), community.clone());
    assert!(store.check_query_plans().is_err());
    {
        let mut tx = store.transaction().unwrap();
        assert!(tx.get(b"state").is_err());
        tx.rollback().unwrap();
    }
    {
        let mut tx = store.transaction().unwrap();
        assert!(tx.delete(b"state").is_err());
    }
    runtime
        .block_on(db.migrate(&[crlt::Migration::new(1, "issuer", cssr::SCHEMA)]))
        .unwrap();
    runtime
        .block_on(community.execute(
            "INSERT INTO cssr_records(key,value) VALUES(?1,?2)",
            crlt::params![b"corrupt".as_slice(), "not a blob"],
        ))
        .unwrap();
    {
        let mut tx = store.transaction().unwrap();
        assert!(tx.get(b"corrupt").is_err());
        // A valid first row must not turn a malformed later row into a partial
        // epoch snapshot. Exercise SQLite's actual non-BLOB stored value.
        tx.put(b"ca", b"valid").unwrap();
        assert!(tx.current_range(b"c", b"d", 2).is_err());
        tx.rollback().unwrap();
    }
    store.check_query_plans().unwrap();
    round_trip(&mut store);
}

#[test]
fn migration_conflict_and_real_constraint_failure_are_redacted() {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("constrained.db");
    let runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
    );
    let url = url::Url::from_file_path(&path).unwrap();
    let db = runtime
        .block_on(crlt::Db::open(crlt::Config::new(url.to_string(), "")))
        .unwrap();
    let constrained = cssr::SCHEMA.replace(
        "value BLOB NOT NULL",
        "value BLOB NOT NULL CHECK(length(value) < 10)",
    );
    runtime
        .block_on(db.migrate(&[crlt::Migration::new(1, "constraint", &constrained)]))
        .unwrap();
    assert!(LibsqlStore::local(&path, "service").is_err());
    let community = db.community("service").unwrap();
    let mut store = LibsqlStore::from_community(runtime, community);
    let mut tx = store.transaction().unwrap();
    assert!(tx.put(b"state", b"too long for this schema").is_err());
    assert!(tx.commit().is_err());
    assert!(
        store
            .transaction()
            .unwrap()
            .get(b"state")
            .unwrap()
            .is_none()
    );
}
#[test]
fn memory_round_trip() {
    round_trip(&mut MemoryStore::default());
}

// A pre-snapshot custom store still implements only the original transaction
// contract. All its operations delegate to the real MemoryStore; deliberately
// leave current_range at the public trait's compatibility default.
struct LegacyStore(MemoryStore);
struct LegacyTransaction<'a>(Box<dyn Transaction + 'a>);
impl Storage for LegacyStore {
    fn transaction(&mut self) -> cssr::Result<Box<dyn Transaction + '_>> {
        Ok(Box::new(LegacyTransaction(self.0.transaction()?)))
    }
}
impl Transaction for LegacyTransaction<'_> {
    fn get(&mut self, key: &[u8]) -> cssr::Result<Option<Vec<u8>>> {
        self.0.get(key)
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> cssr::Result<()> {
        self.0.put(key, value)
    }
    fn delete(&mut self, key: &[u8]) -> cssr::Result<()> {
        self.0.delete(key)
    }
    fn commit(self: Box<Self>) -> cssr::Result<()> {
        self.0.commit()
    }
    fn rollback(self: Box<Self>) -> cssr::Result<()> {
        self.0.rollback()
    }
}

#[test]
fn legacy_custom_store_keeps_updates_but_refuses_epoch_snapshots() {
    let mut store = LegacyStore(MemoryStore::default());
    round_trip(&mut store);
    {
        let mut tx = store.transaction().unwrap();
        tx.put(b"state", b"pending").unwrap();
        // An unsupported snapshot must be an error, never an empty community.
        assert!(tx.current_range(b"s", b"t", 1).is_err());
        tx.rollback().unwrap();
    }
    assert_eq!(store.transaction().unwrap().get(b"state").unwrap(), None);
}

fn epoch_snapshot(store: &mut dyn Storage) {
    let mut tx = store.transaction().unwrap();
    for (key, value) in [(b"aa", b"v1"), (b"ab", b"v2"), (b"ba", b"v3")] {
        tx.put(key, value).unwrap();
    }
    assert_eq!(
        tx.current_range(b"a", b"b", 1).unwrap(),
        vec![(b"aa".to_vec(), b"v1".to_vec())]
    );
    assert_eq!(
        tx.current_range(b"a", b"b", 3).unwrap(),
        vec![
            (b"aa".to_vec(), b"v1".to_vec()),
            (b"ab".to_vec(), b"v2".to_vec())
        ]
    );
    tx.put(b"aa", b"v4").unwrap();
    tx.delete(b"ab").unwrap();
    assert_eq!(
        tx.current_range(b"a", b"b", 3).unwrap(),
        vec![(b"aa".to_vec(), b"v4".to_vec())]
    );
    for (start, end, limit) in [
        (b"".as_slice(), b"b".as_slice(), 1),
        (b"a", b"a", 1),
        (b"b", b"a", 1),
        (b"a", b"b", 0),
        (b"a", b"b", 100_002),
    ] {
        assert!(tx.current_range(start, end, limit).is_err());
    }
    tx.rollback().unwrap();
    assert!(
        store
            .transaction()
            .unwrap()
            .current_range(b"a", b"b", 3)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn real_memory_and_sql_epoch_snapshot_is_atomic_and_indexed() {
    epoch_snapshot(&mut MemoryStore::default());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("epoch.db");
    let mut sql = LibsqlStore::local(&path, "epoch-a").unwrap();
    let mut other = LibsqlStore::local(&path, "epoch-b").unwrap();
    let mut tx = other.transaction().unwrap();
    tx.put(b"ab", b"foreign").unwrap();
    tx.commit().unwrap();
    sql.check_query_plans().unwrap();
    epoch_snapshot(&mut sql);
    assert_eq!(
        other
            .transaction()
            .unwrap()
            .current_range(b"a", b"b", 3)
            .unwrap(),
        vec![(b"ab".to_vec(), b"foreign".to_vec())]
    );
}
#[test]
fn libsql_round_trip_restart_isolation_and_plans() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    {
        let mut store = LibsqlStore::local(&path, "a").unwrap();
        store.check_query_plans().unwrap();
        round_trip(&mut store);
    }
    let mut reopened = LibsqlStore::local(&path, "a").unwrap();
    assert_eq!(
        reopened.transaction().unwrap().get(b"marker").unwrap(),
        Some(b"spent".to_vec())
    );
    let mut other = LibsqlStore::local(&path, "b").unwrap();
    assert!(
        other
            .transaction()
            .unwrap()
            .get(b"marker")
            .unwrap()
            .is_none()
    );
}
#[test]
fn turso_when_configured() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        return;
    };
    if url.is_empty() || token.is_empty() {
        return;
    }
    let community = format!("cssr-test-{}", std::process::id());
    round_trip(&mut LibsqlStore::open(crlt::Config::new(url, token), &community).unwrap());
}

#[test]
fn remote_sqld_round_trip() {
    let Ok(url) = std::env::var("SQLD_URL") else {
        return;
    };
    assert!(!url.is_empty());
    let mut store = LibsqlStore::open(
        crlt::Config::new(url.clone(), "public-synthetic-test"),
        "remote-a",
    )
    .unwrap();
    store.check_query_plans().unwrap();
    round_trip(&mut store);
    let mut other =
        LibsqlStore::open(crlt::Config::new(url, "public-synthetic-test"), "remote-b").unwrap();
    assert!(
        other
            .transaction()
            .unwrap()
            .get(b"marker")
            .unwrap()
            .is_none()
    );
}
