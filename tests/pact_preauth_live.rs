//! Consumer-side Pact checks for Series A P0/P1.
//!
//! - Static: Pact file names the client as consumer and covers forgot/reset/social.
//! - Live HTTP: replays Pact interactions against the public API with the same
//!   request shapes the typed client emits (client_id, no X-Tenant-ID).
//!   Uses reqwest with lab TLS acceptance — same transport as login-service
//!   north_live BDD — because may_minihttp rejects the lab gateway cert.

use std::fs;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use sesame_idam_client::SesameIdamClientConfig;

const DEFAULT_NORTH_BASE: &str = "https://api.sesameidentity.dev.local/idam/v1";

fn provider_base() -> Option<String> {
    if let Ok(base) = std::env::var("SESAME_PACT_PROVIDER_BASE") {
        let base = base.trim_end_matches('/').to_string();
        if base_reachable(&base) {
            return Some(base);
        }
        return None;
    }
    let north = DEFAULT_NORTH_BASE.to_string();
    if base_reachable(&north) {
        Some(north)
    } else {
        None
    }
}

fn base_reachable(base: &str) -> bool {
    let stripped = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    let hostport = stripped.split('/').next().unwrap_or(stripped);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(443)),
        None => {
            if base.starts_with("https://") {
                (hostport, 443u16)
            } else {
                (hostport, 80u16)
            }
        }
    };
    if host == "127.0.0.1" || host == "localhost" {
        return TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(400),
        )
        .is_ok();
    }
    let Ok(mut addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    addrs.any(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_ok())
}

fn http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http client")
}

fn pact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../sesame-idam/microservices/pact-mock-server/pacts/Sesame-Identity-Login-PreAuth.json",
    )
}

fn load_pact() -> Value {
    let text = fs::read_to_string(pact_path()).expect("pact file readable via sibling sesame-idam");
    serde_json::from_str(&text).expect("valid pact json")
}

fn assert_body_subset(actual: &Value, expected: &Value, description: &str) {
    let exp_map = expected
        .as_object()
        .unwrap_or_else(|| panic!("{description}: expected object body"));
    let act_map = actual
        .as_object()
        .unwrap_or_else(|| panic!("{description}: got non-object {actual}"));
    for (key, exp_val) in exp_map {
        let act_val = act_map
            .get(key)
            .unwrap_or_else(|| panic!("{description}: missing `{key}` in {actual}"));
        assert_eq!(act_val, exp_val, "{description}: `{key}` mismatch");
    }
}

#[test]
fn consumer_pact_file_matches_client_operations() {
    let pact = load_pact();
    assert_eq!(pact["consumer"]["name"], "sesame-idam-client");
    assert_eq!(pact["provider"]["name"], "identity-login-service");

    let paths: Vec<&str> = pact["interactions"]
        .as_array()
        .expect("interactions")
        .iter()
        .filter_map(|i| i["request"]["path"].as_str())
        .collect();
    assert!(paths.iter().any(|p| p.contains("/auth/password/forgot")));
    assert!(paths.iter().any(|p| p.contains("/auth/password/reset")));
    assert!(paths.iter().any(|p| p.contains("/auth/social/")));
}

#[test]
fn typed_client_config_targets_login_base_for_password_ops() {
    let cfg = SesameIdamClientConfig::new(
        DEFAULT_NORTH_BASE,
        "https://org.example/idam/v1",
        "https://session.example/idam/v1",
        "acme",
        "acme-web",
    )
    .expect("config");
    assert_eq!(cfg.login_base(), DEFAULT_NORTH_BASE);
    assert_eq!(cfg.client_id, "acme-web");
}

#[test]
fn live_consumer_replays_preauth_pact_interactions() {
    let Some(base) = provider_base() else {
        eprintln!(
            "SKIP consumer live pact: set SESAME_PACT_PROVIDER_BASE \
             or expose the north API"
        );
        return;
    };
    eprintln!("consumer pact replay against {base}");

    let pact = load_pact();
    let client = http_client();
    for interaction in pact["interactions"].as_array().expect("interactions") {
        let description = interaction["description"].as_str().unwrap_or("interaction");
        let request = &interaction["request"];
        let expected = &interaction["response"];
        let method = request["method"].as_str().expect("method");
        let path = request["path"].as_str().expect("path");
        let query = request.get("query").and_then(Value::as_str).unwrap_or("");
        let url = if query.is_empty() {
            format!("{base}{path}")
        } else {
            format!("{base}{path}?{query}")
        };

        // Consumer contract: public pre-auth never sends X-Tenant-ID.
        if let Some(headers) = request.get("headers").and_then(Value::as_object) {
            assert!(
                !headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("X-Tenant-ID")),
                "{description}: consumer must omit X-Tenant-ID"
            );
        }

        let mut builder = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            other => panic!("{description}: unsupported {other}"),
        };
        if let Some(headers) = request.get("headers").and_then(Value::as_object) {
            for (name, value) in headers {
                if let Some(v) = value.as_str() {
                    builder = builder.header(name, v);
                }
            }
        }
        if let Some(body) = request.get("body") {
            builder = builder.json(body);
        }

        let response = builder.send().unwrap_or_else(|e| {
            panic!("{description}: request failed: {e}");
        });
        let expected_status = expected["status"].as_u64().expect("status") as u16;
        let status = response.status().as_u16();
        let text = response.text().unwrap_or_default();
        assert_eq!(
            status, expected_status,
            "{description}: status mismatch; body={text}"
        );
        if let Some(expected_body) = expected.get("body") {
            let actual: Value = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{description}: bad json ({e}): {text}"));
            assert_body_subset(&actual, expected_body, description);
        }
    }
}
