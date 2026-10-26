//! A kept Redis connection the server closed while idle: the next command fails with
//! "unexpected end of file". `RedisStore` retries it once on a fresh connection instead of
//! failing the request (pp, Oct 2026: `session_unavailable` 503s on `/auth/start`).
#![cfg(feature = "redis-store")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sesame_idam_client::bff::{PreAuth, RedisStore, SessionStore};

/// Read one RESP command (an array of bulk strings); `None` at end of stream.
fn read_command(r: &mut impl BufRead) -> Option<Vec<String>> {
    let mut line = String::new();
    if r.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let n: usize = line.trim().strip_prefix('*')?.parse().ok()?;
    let mut parts = Vec::with_capacity(n);
    for _ in 0..n {
        line.clear();
        r.read_line(&mut line).ok()?; // $len
        line.clear();
        r.read_line(&mut line).ok()?;
        parts.push(line.trim_end().to_string());
    }
    Some(parts)
}

/// A fake Redis that closes each connection after answering `per_conn` commands.
fn fake_redis(per_conn: usize) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("redis://{}/", listener.local_addr().unwrap());
    let conns = Arc::new(AtomicUsize::new(0));
    let c = conns.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            c.fetch_add(1, Ordering::SeqCst);
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            // Connection setup (`CLIENT SETINFO`, `SELECT`, ...) is answered and not counted.
            let mut served = 0;
            while served < per_conn {
                let Some(cmd) = read_command(&mut r) else {
                    break;
                };
                let name = cmd
                    .first()
                    .map(|s| s.to_ascii_uppercase())
                    .unwrap_or_default();
                let reply: &[u8] = if name == "GETDEL" {
                    b"$-1\r\n"
                } else {
                    b"+OK\r\n"
                };
                let _ = w.write_all(reply);
                if !matches!(name.as_str(), "CLIENT" | "HELLO" | "SELECT") {
                    served += 1;
                }
            }
            // Dropping both halves closes the connection, as an idle timeout does.
        }
    });
    (url, conns)
}

#[test]
fn a_connection_closed_while_idle_is_replaced_and_the_command_retried() {
    let (url, conns) = fake_redis(1);
    let store = RedisStore::new(&url, "t:", Duration::from_secs(2)).unwrap();
    let pre = PreAuth {
        code_verifier: "v".into(),
        nonce: "n".into(),
        return_to: "/".into(),
        created_at: 1,
    };
    // Same key, so the same shard and connection.
    store
        .put_preauth("s1", &pre, Duration::from_secs(60))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50)); // the server has closed it by now
    assert_eq!(
        store.take_preauth("s1").unwrap(),
        None,
        "retried on a fresh connection"
    );
    assert_eq!(conns.load(Ordering::SeqCst), 2);
}

#[test]
fn a_fresh_connection_that_fails_is_not_retried() {
    // The server closes every connection before answering anything.
    let (url, conns) = fake_redis(0);
    let store = RedisStore::new(&url, "t:", Duration::from_secs(2)).unwrap();
    assert!(store.take_preauth("s2").is_err());
    assert_eq!(conns.load(Ordering::SeqCst), 1);
}
