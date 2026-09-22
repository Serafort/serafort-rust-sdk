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
