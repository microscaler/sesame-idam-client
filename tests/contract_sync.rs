use std::fs;
use std::path::{Path, PathBuf};

use serde_yaml::Value;

fn sesame_repo() -> PathBuf {
    std::env::var_os("SESAME_IDAM_REPO")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../sesame-idam"))
}

fn read_spec(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_yaml::from_str(&text)
        .unwrap_or_else(|error| panic!("could not parse {}: {error}", path.display()))
}

fn mapping_at<'a>(root: &'a Value, keys: &[&str]) -> &'a serde_yaml::Mapping {
    let mut current = root;
    for key in keys {
        current = current
            .get(*key)
            .unwrap_or_else(|| panic!("missing OpenAPI field {}", keys.join(".")));
    }
    current
        .as_mapping()
        .unwrap_or_else(|| panic!("OpenAPI field {} is not an object", keys.join(".")))
}

fn assert_operation(spec: &Value, method: &str, path: &str, operation_id: &str) {
    let actual = spec
        .get("paths")
        .and_then(|paths| paths.get(path))
        .and_then(|path_item| path_item.get(method))
        .and_then(|operation| operation.get("operationId"))
        .and_then(Value::as_str);
    assert_eq!(
        actual,
        Some(operation_id),
        "expected {method} {path} to remain operationId {operation_id}"
    );
}

#[test]
fn client_operations_exist_in_provider_contracts() {
    let root = sesame_repo();
    let login = read_spec(&root.join("openapi/idam/identity-login-service/openapi.yaml"));
    for (method, path, operation) in [
        ("post", "/auth/login", "auth_login"),
        ("post", "/auth/register", "auth_register"),
        ("get", "/auth/signup/validate", "signup_validate"),
        ("get", "/auth/social/{provider}/login", "social_login"),
        (
            "post",
            "/auth/social/{provider}/callback",
            "social_callback",
        ),
        (
            "post",
            "/sessions/active-organization",
            "set_active_organization",
        ),
    ] {
        assert_operation(&login, method, path, operation);
    }

    let org = read_spec(&root.join("openapi/idam/org-mgmt/openapi.yaml"));
    for (method, path, operation) in [
        ("post", "/organizations", "create_organization"),
        ("post", "/invitations/accept", "accept_invitation"),
        (
            "post",
            "/organizations/{org_id}/invitations",
            "invite_user_to_org",
        ),
        ("get", "/organizations/{org_id}/users", "fetch_users_in_org"),
    ] {
        assert_operation(&org, method, path, operation);
    }
}

#[test]
fn signup_and_registration_shapes_match_typed_client() {
    let spec = read_spec(&sesame_repo().join("openapi/idam/identity-login-service/openapi.yaml"));
    let signup = mapping_at(
        &spec,
        &[
            "components",
            "schemas",
            "SignupValidationResponse",
            "properties",
        ],
    );
    for field in ["allowed", "reasons", "requires_mfa"] {
        assert!(signup.contains_key(field), "signup response lost {field}");
    }

    let registration = mapping_at(
        &spec,
        &["components", "schemas", "RegisterRequest", "properties"],
    );
    for field in [
        "email",
        "password",
        "first_name",
        "last_name",
        "username",
        "phone",
    ] {
        assert!(
            registration.contains_key(field),
            "register request lost {field}"
        );
    }
    assert!(
        !registration.contains_key("send_welcome_email"),
        "deprecated send_welcome_email returned to provider contract"
    );
}

#[test]
fn tenant_consumer_public_contract_lockstep() {
    use sesame_idam_client::{
        SUPPORTED_FIXTURE_VERSION, SUPPORTED_PROVIDER_PROFILE, SUPPORTED_TENANT_CONSUMER_API,
    };

    let root = sesame_repo();
    let tenant = read_spec(&root.join("openapi/idam/tenant-consumer/openapi.yaml"));
    assert_eq!(
        tenant
            .get("info")
            .and_then(|info| info.get("version"))
            .and_then(Value::as_str),
        Some(SUPPORTED_TENANT_CONSUMER_API),
        "client SUPPORTED_TENANT_CONSUMER_API out of sync"
    );
    assert_eq!(
        tenant
            .get("info")
            .and_then(|info| info.get("x-provider-profile"))
            .and_then(Value::as_str),
        Some(SUPPORTED_PROVIDER_PROFILE)
    );
    assert_eq!(
        tenant
            .get("info")
            .and_then(|info| info.get("x-fixture-version"))
            .and_then(Value::as_str),
        Some(SUPPORTED_FIXTURE_VERSION)
    );

    for (method, path, operation) in [
        ("post", "/auth/register", "register_user"),
        ("get", "/users/me/memberships", "list_my_memberships"),
        ("post", "/organizations", "create_organization"),
        (
            "post",
            "/organizations/{org_id}/invitations",
            "invite_user_to_organization",
        ),
        ("post", "/invitations/accept", "accept_invitation"),
        ("get", "/invitations/preview", "preview_invitation"),
        (
            "post",
            "/sessions/active-organization",
            "set_active_organization",
        ),
    ] {
        assert_operation(&tenant, method, path, operation);
    }

    let version = fs::read_to_string(root.join("conformance/oidc-v1/VERSION"))
        .expect("conformance VERSION");
    assert!(
        version.contains(&format!("provider_profile={SUPPORTED_PROVIDER_PROFILE}")),
        "fixture VERSION provider_profile mismatch"
    );
    assert!(
        version.contains(&format!("fixture_version={SUPPORTED_FIXTURE_VERSION}")),
        "fixture VERSION fixture_version mismatch"
    );
}
