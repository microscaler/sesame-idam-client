# Changelog

All notable changes will be documented here.

## Unreleased

- `RedisStore`: a command that fails because a reused connection was closed
  while idle ("unexpected end of file") is retried once on a fresh connection
  instead of failing the request (pp: `session_unavailable` 503s on sign-in).
- Add the `bff` module (Sesame ADR-014): relying-party BFFs sign users in
  through the hosted login as confidential OIDC clients (authorization code,
  PKCE S256, `state`, `nonce`, `client_secret_basic`), hold the tokens in a
  server-side store and give the browser an opaque `__Host-` cookie. Covers
  ID-token checks, single-flight refresh, the sliding idle and absolute
  timeouts, CSRF checks for non-safe methods, logout, "sign out everywhere"
  and session-id rotation on privilege change. `MemoryStore` for tests;
  `RedisStore` behind the `redis-store` feature (Redis 6.2 or later).
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
