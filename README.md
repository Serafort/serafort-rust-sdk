# Serafort Rust SDK (`serafort_sdk`)

High-performance, memory-safe Rust client library for the Serafort identity platform. Features zero-cost abstraction Machine Identity (M2M) token caching with proactive refresh and local B2B JWT validation.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
serafort_sdk = "0.1.0"
tokio = { version = "1.32", features = ["full"] }
```

## Quickstart

```rust
use serafort_sdk::{SerafortClient, SerafortConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SerafortConfig::new("https://auth.acme.com")
        .with_client_credentials("my-client-id", "my-client-secret");

    let client = SerafortClient::new(config);

    // 1. Retrieve M2M access token (cached, proactive 5-min refresh)
    let token = client.get_access_token(Some(vec!["read:users".into()])).await?;
    println!("Token: {}", token);

    // 2. Validate user token locally
    let user = client.validate_token(&token)?;
    println!("User {} authenticated in tenant {}", user.user_id, user.tenant_id);

    // 3. RBAC checks (wildcards supported)
    if client.has_permission(&user, "org:write") {
        println!("Permission granted!");
    }

    Ok(())
}
```

## Contributing

### Requirements

- Rust 1.74+ (stable toolchain)
- `rustfmt` and `clippy` components (`rustup component add rustfmt clippy`)

### Git hooks

This repo ships a portable pre-commit hook under `.githooks/pre-commit` that runs `cargo fmt --all -- --check` and `cargo clippy --all-targets -- -D warnings` before every commit. It is **not** installed automatically — enable it once per clone with:

```bash
git config core.hooksPath .githooks
```

There is no Husky setup here: Husky is an npm-ecosystem tool that hooks into `package.json`/`node_modules`, and this is a pure Cargo crate with no Node.js tooling involved. A plain POSIX shell script wired through `core.hooksPath` is the idiomatic equivalent for a Rust crate and keeps it dependency-free.

### CI

Every push and pull request against `main` runs `cargo build`, `cargo test`, `cargo fmt --check`, and `cargo clippy -- -D warnings` via GitHub Actions (`.github/workflows/ci.yml`).
