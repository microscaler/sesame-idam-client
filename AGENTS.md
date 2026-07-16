# Sesame-IDAM client agent guide

## Scope

This repository owns the shared Rust consumer contract for Sesame-IDAM. It does
not own Sesame business rules, product-specific BFF behavior, token
cryptography, or generic HTTP transport behavior.

## Architecture rules

- Use `brrtrouter::http`; do not add Reqwest, Tokio, or a parallel executor.
- Keep the client synchronous and compatible with may coroutines.
- Change provider OpenAPI contracts before changing public wire types.
- Keep Hauliage- and RERP-specific policy in those repositories.
- Parse only BRRTRouter-validated claims; never trust decoded token JSON.
- During rapid development use sibling repositories. Pin exact Git revisions
  for a release rather than publishing microscaler forks to crates.io.
- BRRTRouter currently requires sibling `microscaler-observability`; preserve
  that layout in CI and isolated build environments.

## Validation and Git

Run commands and Git operations on `ms02` in
`~/Workspace/microscaler/sesame-idam-client`. Run `just check` before handoff.
Do not push without explicit authorization.
