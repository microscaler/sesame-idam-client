set shell := ["bash", "-cu"]

default: check

fmt:
    cargo fmt --all -- --check

lint:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo test --all-features

docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

check: fmt lint test docs
