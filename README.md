# ButtrBase Rust SDK

This is the official Rust SDK for the ButtrBase API.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
buttrbase-sdk = { git = "https://github.com/buttr-base/buttrbase-platform", branch = "master", package = "rust-sdk" }
```

## Usage

First, import and initialize the client:

```rust
use buttrbase_sdk::client::ButtrBaseClient;

#[tokio::main]
async fn main() {
    let mut client = ButtrBaseClient::new("https://api.buttrbase.com".to_string());

    let login_response = client
        .login("user@example.com", "yourpassword", "your-organization-name")
        .await;

    match login_response {
        Ok(resp) => println!("Logged in successfully: {:?}", resp),
        Err(e) => println!("Error logging in: {:?}", e),
    }
}
```
