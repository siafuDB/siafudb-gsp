//! Milestone 3 smoke test — two SiafuDB instances kept in sync via a
//! channel transport in the same process.

use siafudb_core::SiafuDB;
use siafudb_sync::InProcessReplicator;

#[test]
fn one_way_replication_carries_writes_across() {
    let db_a = SiafuDB::in_memory().unwrap();
    let db_b = SiafuDB::in_memory().unwrap();

    db_a.execute("CREATE (:Person {name: 'Amara'})").unwrap();
    db_a.execute("CREATE (:Person {name: 'Tatenda'})").unwrap();

    let mut replicator = InProcessReplicator::new();
    let applied = replicator.replicate(&db_a, &db_b).unwrap();
    assert_eq!(applied, 2);

    let result = db_b
        .query("MATCH (p:Person) RETURN p.name")
        .unwrap();
    assert_eq!(
        result.rows.len(),
        2,
        "destination should observe both creates"
    );
}

#[test]
fn cursor_advances_so_replays_only_carry_new_entries() {
    let db_a = SiafuDB::in_memory().unwrap();
    let db_b = SiafuDB::in_memory().unwrap();
    let mut replicator = InProcessReplicator::new();

    db_a.execute("CREATE (:Person {name: 'Amara'})").unwrap();
    let first = replicator.replicate(&db_a, &db_b).unwrap();
    assert_eq!(first, 1);
    assert_eq!(replicator.cursor(), 1);

    // No new writes — replicate is a no-op.
    let again = replicator.replicate(&db_a, &db_b).unwrap();
    assert_eq!(again, 0);

    db_a.execute("CREATE (:Person {name: 'Tatenda'})").unwrap();
    let second = replicator.replicate(&db_a, &db_b).unwrap();
    assert_eq!(second, 1, "only the new entry is applied");
    assert_eq!(replicator.cursor(), 2);

    let result = db_b
        .query("MATCH (p:Person) RETURN p.name")
        .unwrap();
    assert_eq!(result.rows.len(), 2);
}
