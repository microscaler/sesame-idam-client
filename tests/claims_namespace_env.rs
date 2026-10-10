//! The claim namespace is deployment configuration (`SESAME_CLAIMS_NAMESPACE`), matching the Sesame
//! deployment that issues the tokens. Its own test binary: the namespace is read once per process.

use serde_json::{json, Value};
use sesame_idam_client::{
    authorization_claims_namespace, parse_validated_claims, ClaimsError,
    AUTHORIZATION_CLAIMS_NAMESPACE, CLAIMS_NAMESPACE_KEY,
};

const NAMESPACE: &str = "https://sesame-idam.example.org/claims";

fn claims_under(namespace: &str) -> Value {
    let mut claims = json!({
        "sub": "a1000001-0001-4000-8000-000000000004",
        "user_id": "a1000001-0001-4000-8000-000000000004",
        "sid": "session-1",
        "client_id": "acme-web",
        "ver": 1,
        "tenant_id": "acme",
        "user_type": "customer"
    });
    claims[namespace] = json!({ "tenant": "acme", "roles": ["billing"], "permissions": [] });
    claims
}

#[test]
fn reads_authz_claims_under_the_configured_namespace_only() {
    std::env::set_var(CLAIMS_NAMESPACE_KEY, NAMESPACE);
    assert_eq!(authorization_claims_namespace(), NAMESPACE);

    let parsed =
        parse_validated_claims(Some(&claims_under(NAMESPACE))).expect("configured namespace");
    assert_eq!(parsed.roles, ["billing"]);

    // A token from a deployment with another namespace carries no authz claims for this consumer.
    assert_eq!(
        parse_validated_claims(Some(&claims_under(AUTHORIZATION_CLAIMS_NAMESPACE))).err(),
        Some(ClaimsError::MissingField(NAMESPACE))
    );
}
