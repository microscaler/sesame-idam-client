//! Parsing for claims that BRRTRouter has already authenticated.

use serde_json::Value;
use uuid::Uuid;

/// Namespace containing Sesame authorization claims.
pub const AUTHORIZATION_CLAIMS_NAMESPACE: &str = "https://sesame-idam.dev/claims";

/// Identity and authorization facts required by tenant-aware consumers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedClaims {
    pub tenant_id: String,
    pub subject_id: Uuid,
    pub organization_id: Uuid,
    pub session_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub user_type: Option<String>,
    pub org_type: Option<String>,
}

/// Failure to convert authenticated Sesame claims into a consumer context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimsError {
    MissingValidatedClaims,
    MissingField(&'static str),
    InvalidField(&'static str),
    ClaimMismatch {
        first: &'static str,
        second: &'static str,
    },
}

impl std::fmt::Display for ClaimsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingValidatedClaims => formatter.write_str("validated claims are missing"),
            Self::MissingField(field) => write!(formatter, "required claim is missing: {field}"),
            Self::InvalidField(field) => {
                write!(formatter, "claim has an invalid type or value: {field}")
            }
            Self::ClaimMismatch { first, second } => {
                write!(formatter, "validated claims disagree: {first} and {second}")
            }
        }
    }
}

impl std::error::Error for ClaimsError {}

/// Parse BRRTRouter-validated Sesame claims.
///
/// This function does **not** verify JWT, JWS, or JWE material. Callers must
/// pass only the claim value produced after BRRTRouter authentication. Keeping
/// cryptographic verification at the request boundary prevents consumers from
/// accidentally trusting decoded-but-unverified tokens.
///
/// # Errors
///
/// Returns [`ClaimsError`] when required identity claims are missing, malformed,
/// or disagree with the namespaced authorization claims.
pub fn parse_validated_claims(claims: Option<&Value>) -> Result<ValidatedClaims, ClaimsError> {
    let claims = claims.ok_or(ClaimsError::MissingValidatedClaims)?;
    let tenant = required_string(required(claims, "tenant_id")?, "tenant_id")?;
    let subject_id = required_uuid(required(claims, "sub")?, "sub")?;
    let user_id = required_uuid(required(claims, "user_id")?, "user_id")?;
    if subject_id != user_id {
        return Err(ClaimsError::ClaimMismatch {
            first: "sub",
            second: "user_id",
        });
    }

    let organization_id = required_uuid(required(claims, "org_id")?, "org_id")?;
    let session_id = required_string(required(claims, "sid")?, "sid")?;
    let authorization = claims
        .get(AUTHORIZATION_CLAIMS_NAMESPACE)
        .and_then(Value::as_object)
        .ok_or(ClaimsError::MissingField(AUTHORIZATION_CLAIMS_NAMESPACE))?;
    let authorization_tenant = required_string(
        authorization
            .get("tenant")
            .ok_or(ClaimsError::MissingField("sx.tenant"))?,
        "sx.tenant",
    )?;
    if tenant != authorization_tenant {
        return Err(ClaimsError::ClaimMismatch {
            first: "tenant_id",
            second: "sx.tenant",
        });
    }

    Ok(ValidatedClaims {
        tenant_id: tenant.to_string(),
        subject_id,
        organization_id,
        session_id: session_id.to_string(),
        roles: string_array(
            authorization
                .get("roles")
                .ok_or(ClaimsError::MissingField("sx.roles"))?,
            "sx.roles",
        )?,
        permissions: string_array(
            authorization
                .get("permissions")
                .ok_or(ClaimsError::MissingField("sx.permissions"))?,
            "sx.permissions",
        )?,
        user_type: optional_string(claims.get("user_type"), "user_type")?,
        org_type: optional_string(authorization.get("org_type"), "sx.org_type")?,
    })
}

fn required<'a>(value: &'a Value, field: &'static str) -> Result<&'a Value, ClaimsError> {
    value.get(field).ok_or(ClaimsError::MissingField(field))
}

fn required_string<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, ClaimsError> {
    let string = value
        .as_str()
        .ok_or(ClaimsError::InvalidField(field))?
        .trim();
    if string.is_empty() {
        return Err(ClaimsError::InvalidField(field));
    }
    Ok(string)
}

fn required_uuid(value: &Value, field: &'static str) -> Result<Uuid, ClaimsError> {
    Uuid::parse_str(required_string(value, field)?).map_err(|_| ClaimsError::InvalidField(field))
}

fn string_array(value: &Value, field: &'static str) -> Result<Vec<String>, ClaimsError> {
    value
        .as_array()
        .ok_or(ClaimsError::InvalidField(field))?
        .iter()
        .map(|entry| required_string(entry, field).map(str::to_string))
        .collect()
}

fn optional_string(
    value: Option<&Value>,
    field: &'static str,
) -> Result<Option<String>, ClaimsError> {
    value
        .map(|value| required_string(value, field).map(str::to_string))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Value {
        serde_json::json!({
            "sub": "a1000001-0001-4000-8000-000000000004",
            "user_id": "a1000001-0001-4000-8000-000000000004",
            "sid": "session-1",
            "tenant_id": "hauliage",
            "org_id": "b2000002-0002-4000-8000-000000000002",
            "user_type": "service",
            "https://sesame-idam.dev/claims": {
                "tenant": "hauliage",
                "roles": ["billing"],
                "permissions": ["accounting:invoice:write"]
            }
        })
    }

    #[test]
    fn parses_complete_context() {
        let parsed = parse_validated_claims(Some(&claims())).expect("valid claims");
        assert_eq!(parsed.tenant_id, "hauliage");
        assert_eq!(parsed.roles, ["billing"]);
    }

    #[test]
    fn rejects_subject_mismatch() {
        let mut value = claims();
        value["user_id"] = Value::String("a1000001-0001-4000-8000-000000000005".to_string());
        assert!(matches!(
            parse_validated_claims(Some(&value)),
            Err(ClaimsError::ClaimMismatch { .. })
        ));
    }
}
