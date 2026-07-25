# Changelog

All notable changes will be documented here.

## Unreleased

- Extract the Hauliage Sesame integration into a standalone shared crate.
- Use sibling BRRTRouter and Sesame-IDAM repositories during rapid development.
- Align registration and signup validation types with current provider specs.
- Add reusable parsing for BRRTRouter-validated Sesame claims.
- Add provider contract drift tests and continuous integration.
- **Breaking:** require an explicit base URL per Sesame service
  (`SESAME_LOGIN_BASE_URL`, `SESAME_ORG_MGMT_BASE_URL`,
  `SESAME_SESSION_BASE_URL`, `SESAME_TENANT_ID`). `SesameIdamClientConfig` is
  now built through `new`/`from_env`/`from_lookup`, which return
  `Result<_, ConfigError>`; the struct literal, `Default`, and the
  `login_url`/`org_mgmt_url`/`session_url` fields are gone.
- **Security:** stop deriving the org-mgmt and identity-session hosts by
  string-replacing `identity-login-service` (and `:8101`→`:8104`/`:8102`) in the
  login URL. The replacement was a silent no-op once the login host stopped
  containing the service name, which routed org and session calls to the login
  host. Missing configuration now fails closed at construction.
