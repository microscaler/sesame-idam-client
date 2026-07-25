# Sesame-IDAM Rust client

`sesame-idam-client` is the typed, may-native integration boundary for Rust
services consuming [Sesame-IDAM](https://github.com/microscaler/sesame-idam).
It uses `brrtrouter::http` and therefore the microscaler `may_minihttp` client;
it does not introduce Reqwest, Tokio, or another HTTP abstraction.

The crate currently covers:

- password login and registration;
- signup eligibility validation;
- social-login start and callback;
- active-organization selection;
- organization creation, invitations, and member listing; and
- strict conversion of BRRTRouter-validated claims into a reusable identity
  context.

## Configuration

Every Sesame service the client talks to has its own required base URL. Nothing
is derived from anything else, and there are no defaults: a missing value is a
`ConfigError::Missing` naming the key, raised when the config is built.

| Key (env / helm value)      | Service                    | Example                                            |
| --------------------------- | -------------------------- | -------------------------------------------------- |
| `SESAME_LOGIN_BASE_URL`     | identity-login-service     | `https://api.sesameidentity.dev.local/idam/v1`      |
| `SESAME_ORG_MGMT_BASE_URL`  | org-mgmt                   | `http://org-mgmt.sesame-idam.svc.cluster.local:8080/idam/v1` |
| `SESAME_SESSION_BASE_URL`   | identity-session-service   | `http://identity-session-service.sesame-idam.svc.cluster.local:8080/idam/v1` |
| `SESAME_TENANT_ID`          | `X-Tenant-ID` on every call | `hauliage`                                        |

Each value is the `…/idam/v1` prefix of that service and is used verbatim (only
a trailing `/` is trimmed). A full endpoint URL such as `…/idam/v1/auth/login`
in a base slot is rejected.

```rust,ignore
let config = SesameIdamClientConfig::from_env()?;             // process env
let config = SesameIdamClientConfig::from_lookup(|key| {      // helm over env
    helm_value(key).or_else(|| std::env::var(key).ok())
})?;
let config = SesameIdamClientConfig::new(login, org, session, tenant)?;
```

An earlier version accepted only `login_url` and synthesised the org-mgmt and
identity-session hosts from it by replacing `identity-login-service` in the
hostname (plus `:8101`→`:8104`/`:8102` dev-port variants). That is removed: the
replacement silently became a no-op once the deployment moved off cluster DNS
onto a real hostname, and org and session traffic was sent to the login host
instead of failing.

## Development layout

During rapid development the repositories are expected to be siblings:

```text
microscaler/
├── BRRTRouter/
├── microscaler-observability/
├── sesame-idam/
├── sesame-idam-client/
├── hauliage/
└── rerp/
```

The client depends on `../BRRTRouter`, whose observability adapter is the sibling
`../microscaler-observability`. Contract tests read the provider specs
from `../sesame-idam`, or from `SESAME_IDAM_REPO` when the provider checkout is
elsewhere. Hauliage and RERP likewise use a sibling path dependency so changes
can be developed together. Release branches should replace that development
path with an exact Git revision; the crate is intentionally not published to
crates.io.

Cargo Dependabot is deferred while the development manifest uses sibling path
dependencies, because its isolated checkout cannot resolve that topology.
GitHub Actions dependencies are still maintained automatically.

## Validation

Run the complete acceptance cycle with:

```shell
just check
```

or run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo doc` directly.

The contract test checks operations and response fields against the current
Sesame OpenAPI documents. It is a drift alarm, not a replacement for provider
integration tests.

## Trust boundary

`parse_validated_claims` does not decode or verify a token. It accepts only the
claim value that BRRTRouter exposes after successful JWT/JWS/JWE verification.
Passing claims parsed directly from an unverified token is a security defect.

## SAML status

The moved Hauliage integration already contains SAML login/callback methods.
They are retained to avoid breaking its consumer during extraction, but the
current Sesame login-service OpenAPI does not publish those operations. Treat
them as pre-contract and do not enable them in a production flow until Sesame
owns and implements the endpoints and the contract test is extended.
