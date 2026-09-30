//! Integration tests for the public contract.
use cssr::{LibsqlStore, MemoryStore, Storage};
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
fn memory_round_trip() {
    round_trip(&mut MemoryStore::default());
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
