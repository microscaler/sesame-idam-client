//! `RedisStore` against a real Redis. Set `SESAME_BFF_TEST_REDIS`
//! (for example `redis://127.0.0.1:6379/15`) to run; skipped otherwise.
#![cfg(feature = "redis-store")]

use std::time::Duration;

use sesame_idam_client::bff::{PreAuth, RedisStore, SessionRecord, SessionStore};

fn store() -> Option<RedisStore> {
    let url = std::env::var("SESAME_BFF_TEST_REDIS").ok()?;
    let prefix = format!("bfftest:{}:", std::process::id());
    Some(RedisStore::new(&url, &prefix, Duration::from_secs(2)).expect("redis url"))
}

fn record(subject: &str) -> SessionRecord {
    SessionRecord {
        access_token: "at".into(),
        refresh_token: Some("rt".into()),
        id_token: None,
        access_expires_at: 10,
        subject: subject.into(),
        tenant_id: Some("acme".into()),
        organization_id: None,
        created_at: 1,
        last_seen: 1,
        absolute_expires_at: 100,
    }
}

#[test]
fn redis_store_round_trips_and_expires() {
    let Some(s) = store() else {
        eprintln!("SESAME_BFF_TEST_REDIS unset; skipping");
        return;
    };
    let pre = PreAuth {
        code_verifier: "v".into(),
        nonce: "n".into(),
        return_to: "/".into(),
        created_at: 1,
    };
    s.put_preauth("st", &pre, Duration::from_secs(5)).unwrap();
    assert_eq!(s.take_preauth("st").unwrap(), Some(pre));
    assert_eq!(s.take_preauth("st").unwrap(), None, "read once");

    s.put_session("k1", &record("u1"), Duration::from_millis(300))
        .unwrap();
    assert_eq!(s.get_session("k1").unwrap().unwrap().subject, "u1");
    std::thread::sleep(Duration::from_millis(400));
    assert!(s.get_session("k1").unwrap().is_none(), "TTL applied");

    s.index_session("acme:u1", "k2", Duration::from_secs(5))
        .unwrap();
    s.index_session("acme:u1", "k3", Duration::from_secs(5))
        .unwrap();
    let mut keys = s.indexed_sessions("acme:u1").unwrap();
    keys.sort();
    assert_eq!(keys, ["k2", "k3"]);
    s.unindex_session("acme:u1", "k2").unwrap();
    assert_eq!(s.indexed_sessions("acme:u1").unwrap(), ["k3"]);
    s.unindex_session("acme:u1", "k3").unwrap();

    assert!(s.try_lock("l", Duration::from_secs(5)).unwrap());
    assert!(!s.try_lock("l", Duration::from_secs(5)).unwrap());
    s.unlock("l").unwrap();
    assert!(s.try_lock("l", Duration::from_secs(5)).unwrap());
    s.unlock("l").unwrap();
    s.delete_session("k1").unwrap();
}
