# Rust SDK

## Overview

The official Rust SDK for ButtrBase. Two surfaces, one crate:

- **Client** — call the ButtrBase API from your Rust service (auth, organizations, billing, RBAC, teams, credentials, search, AI gateway, webhooks, and more).
- **Verifier** — verify ButtrBase-issued JWTs in your own Rust service for federated auth.

## Installation

```toml
[dependencies]
buttrbase-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Client Setup

```rust
use buttrbase_sdk::client::ButtrBaseClient;

let mut client = ButtrBaseClient::new("https://api.buttrbase.com".into());
```

## Authentication

### Registration

```rust
use buttrbase_sdk::models::RegisterRequest;

let response = client.register(&RegisterRequest {
    email: "alice@example.com",
    password: "secure-password",
    org_name: "my-org",
    first_name: Some("Alice"),
    last_name: Some("Smith"),
}).await?;
```

### Email/Password Login

```rust
let response = client.login("user@example.com", "password", "my-org").await?;
// Token is automatically stored on the client after login
```

### Login Options

```rust
let options = client.get_login_options("org-uuid").await?;
```

### OTP (Email)

```rust
client.send_otp("user@example.com", "my-app").await?;
client.verify_otp("user@example.com", "123456", "my-app").await?;
```

### OTP (Phone)

```rust
client.send_phone_otp("+15551234567", "my-app").await?;
client.verify_phone_otp("+15551234567", "123456", "my-app").await?;
```

### Passwordless OTP (v2)

```rust
client.otp_send("+15551234567").await?;
let login = client.otp_verify_code("+15551234567", "123456").await?;
```

### Magic Link

```rust
// Legacy
client.send_magic_link("user@example.com", "my-app", "my-org").await?;

// v2 — send and verify
client.magic_link_send("user@example.com", Some("https://app.example.com/callback")).await?;
let login = client.magic_link_verify("token-from-email").await?;
```

### SSO (OIDC / SAML)

```rust
// Get OIDC authorization URL
let auth = client.oidc_authorize_url("connection-uuid").await?;

// Handle OIDC callback
let mut params = std::collections::HashMap::new();
params.insert("code".into(), "auth-code".into());
params.insert("state".into(), "state-value".into());
let result = client.oidc_callback(&params).await?;

// SAML
let saml_auth = client.saml_authorize_url("connection-uuid").await?;
let saml_result = client.saml_callback(&serde_json::json!({ "SAMLResponse": "..." })).await?;
```

### Org by Domain

```rust
let org = client.get_org_by_domain("example.com").await?;
```

### Password Management

```rust
client.reset_password("reset-token", "new-password").await?;
client.change_password("old-password", "new-password").await?;
```

### Email Verification & Account Activation

```rust
client.verify_email("user@example.com").await?;
client.activate_account("activation-token").await?;
```

### Auth Status

```rust
let status = client.get_status().await?;
```

## MFA / TOTP

```rust
// Check MFA status
let status = client.mfa_status().await?;

// Enroll in TOTP — returns secret + QR code URL
let enrollment = client.mfa_totp_enroll().await?;
println!("Scan QR: {}", enrollment.qr_code_url);

// Activate with a code from the authenticator app
client.mfa_totp_activate("123456").await?;

// Verify a TOTP code during login
client.mfa_totp_verify("654321").await?;

// Challenge (trigger server-side TOTP check)
client.mfa_totp_challenge().await?;

// Disable TOTP
client.mfa_totp_disable().await?;

// Recovery codes
let codes = client.mfa_generate_recovery_codes().await?;
client.mfa_redeem_recovery_code("ABCD-1234-EFGH").await?;

// Step-up authentication
client.auth_step_up(&serde_json::json!({ "mfa_code": "123456" })).await?;
```

## Profile & User Management

```rust
let profile = client.get_profile().await?;

let mut updates = std::collections::HashMap::new();
updates.insert("first_name", "Alice");
client.update_profile(&updates).await?;

let users = client.get_users(None).await?;
client.get_user_level("user-uuid").await?;
client.set_user_level("user-uuid", "admin").await?;
client.upload_user_profile_picture("user-uuid", image_bytes).await?;
client.update_user_status("user-uuid", true).await?;
client.update_user_role("user-uuid", "editor").await?;
```

## Organization Security

```rust
// Security settings
let settings = client.get_security_settings("org-uuid").await?;
client.update_security_settings("org-uuid", &serde_json::json!({
    "mfa_required": true,
    "session_timeout_minutes": 60,
})).await?;

// SSO connections
let connections = client.list_sso_connections("org-uuid").await?;

use buttrbase_sdk::models::CreateSsoConnectionRequest;
let conn = client.create_sso_connection("org-uuid", &CreateSsoConnectionRequest {
    provider: "okta",
    name: "Okta SSO",
    config: serde_json::json!({ "domain": "myorg.okta.com" }),
}).await?;

client.update_sso_connection("org-uuid", "conn-uuid", &serde_json::json!({
    "name": "Updated Okta SSO"
})).await?;
client.delete_sso_connection("org-uuid", "conn-uuid").await?;

// Audit events
let events = client.list_audit_events("org-uuid").await?;
let export = client.export_audit_events("org-uuid").await?;
```

## Branding

```rust
let branding = client.get_branding("org-uuid").await?;
client.update_branding("org-uuid", &serde_json::json!({
    "primary_color": "#4F46E5",
    "company_name": "Acme Inc",
})).await?;
client.upload_org_logo("org-uuid", logo_bytes).await?;
```

## Sessions & Devices

```rust
// Org-level session management
let sessions = client.org_session_inventory("org-uuid").await?;
client.org_revoke_all_sessions("org-uuid").await?;

// Device account management
let accounts = client.list_device_accounts("device-uuid").await?;

use buttrbase_sdk::models::CreateDeviceAccountRequest;
client.add_device_account("device-uuid", &CreateDeviceAccountRequest {
    email: "user@example.com",
    org_name: "my-org",
    org_uuid: "org-uuid",
}).await?;

client.delete_device_accounts("device-uuid").await?;
client.delete_device_account("device-uuid", "account-uuid").await?;

// Bulk operations
client.add_device_accounts_bulk("device-uuid", &serde_json::json!([
    { "email": "a@example.com", "org_name": "org1", "org_uuid": "uuid1" },
    { "email": "b@example.com", "org_name": "org2", "org_uuid": "uuid2" },
])).await?;

// Switch active account
client.switch_device_active_account("device-uuid", "account-uuid").await?;

// Device sessions
let dev_sessions = client.device_session_inventory("device-uuid").await?;
client.revoke_all_device_sessions("device-uuid").await?;
```

## API Keys (v2)

```rust
let keys = client.list_api_keys_v2("org-uuid").await?;
let key = client.create_api_key_v2("org-uuid", "CI Deploy Key").await?;
client.delete_api_key_v2("org-uuid", &key.key_uuid).await?;
```

## Service Identities

```rust
let identities = client.list_service_identities("org-uuid").await?;
let identity = client.create_service_identity("org-uuid", &serde_json::json!({
    "name": "ci-bot",
    "scopes": ["deploy", "read"]
})).await?;
client.create_service_identity_automation_token("org-uuid", &serde_json::json!({
    "identity_id": "key-uuid",
})).await?;
client.delete_service_identity("org-uuid", "key-uuid").await?;
```

## Billing

```rust
let checkout = client.checkout("price_abc123", Some("DISCOUNT10"), None).await?;
let history = client.get_billing_history().await?;
let invoices = client.list_invoices().await?;
let config = client.get_provider_config("stripe").await?;
client.add_add_on("advanced-analytics").await?;
let balance = client.wallet().await?;
```

## Entitlements

```rust
use buttrbase_sdk::models::EntitlementCheckRequest;

let result = client.entitlements_check(&EntitlementCheckRequest {
    feature: "advanced-analytics",
    org_uuid: Some("org-uuid"),
}).await?;
println!("Allowed: {}", result.allowed);

// Batch check
client.entitlements_check_batch(&serde_json::json!({
    "checks": [
        { "feature": "sso" },
        { "feature": "audit-logs" },
    ]
})).await?;

// Effective entitlements for the current user
let effective = client.entitlements_effective().await?;

// Admin: explain entitlement resolution
client.admin_entitlements_explain(&serde_json::json!({
    "feature": "sso", "org_uuid": "org-uuid"
})).await?;
```

## Pricing

```rust
let preview = client.pricing_preview(&serde_json::json!({
    "plan": "pro", "seats": 10
})).await?;

let quote = client.pricing_quote(&serde_json::json!({
    "plan": "enterprise", "seats": 50, "add_ons": ["sso", "audit"]
})).await?;

let session = client.pricing_checkout_session(&serde_json::json!({
    "plan": "pro", "seats": 10
})).await?;

// Admin
client.admin_pricing_explain(&serde_json::json!({ "plan": "pro" })).await?;

// Catalog pricing preview
client.catalog_pricing_preview(&serde_json::json!({ "product_id": "prod-1" })).await?;
```

## Coupons & Gift Cards

```rust
// Validate a coupon code
client.validate_coupon("SAVE20").await?;

// Admin: manage product coupons
let coupons = client.admin_list_product_coupons("product-id").await?;
use buttrbase_sdk::models::Coupon;
let coupon = client.admin_create_product_coupon("product-id", &Coupon {
    id: None,
    code: "LAUNCH50".into(),
    product_id: Some(1),
    discount_type: "percent".into(),
    discount_value: 50.0,
    active: Some(true),
    labels: Some(vec!["launch".into()]),
}).await?;
client.admin_delete_product_coupon("product-id", "coupon-id").await?;

// Gift cards
let card = client.validate_gift_card("GIFT-ABC-123").await?;
client.redeem_gift_card("GIFT-ABC-123").await?;
```

## Labels & Tags

```rust
// Coupon labels
client.set_coupon_labels("coupon-id", &["vip", "early-access"]).await?;
client.add_coupon_label("coupon-id", "partner").await?;
client.remove_coupon_label("coupon-id", "partner").await?;

// Product tags
client.set_product_tags("product-id", &["featured", "new"]).await?;
client.add_product_tag("product-id", "sale").await?;
client.remove_product_tag("product-id", "sale").await?;
```

## RBAC (Role-Based Access Control)

```rust
use buttrbase_sdk::models::{CreateRoleRequest, PermissionId};

let permissions = client.get_product_permissions("product-id").await?;
let role = client.create_product_role("product-id", &CreateRoleRequest {
    name: "Editor".into(),
    permissions: vec![PermissionId { id: 1 }, PermissionId { id: 3 }],
}).await?;
let roles = client.get_assignable_roles("org-uuid", "product-id").await?;
client.assign_role_to_user("org-uuid", "user-uuid", role.id).await?;

// Global roles and permissions
let all_roles = client.list_roles().await?;
let all_perms = client.list_all_permissions().await?;
let role_perms = client.get_role_permissions(1).await?;
client.update_role_permissions(1, &serde_json::json!({
    "permissions": [{ "id": 1 }, { "id": 2 }]
})).await?;
```

## Teams

```rust
// Create, list, lifecycle
let team = client.create_team(&serde_json::json!({
    "name": "Engineering", "org_uuid": "org-uuid"
})).await?;
let teams = client.list_org_teams("org-uuid").await?;
let inactive = client.list_inactive_teams("org-uuid").await?;
client.archive_team("team-uuid").await?;
client.reactivate_team("team-uuid").await?;

// Members
let members = client.list_team_members("team-uuid").await?;
client.add_team_member("team-uuid", "user-uuid").await?;
client.remove_team_member("team-uuid", "user-uuid").await?;

// Observers
let observers = client.list_team_observers("team-uuid").await?;
client.add_team_observer("team-uuid", "user-uuid").await?;
client.remove_team_observer("team-uuid", "user-uuid").await?;

// User's teams
let my_teams = client.get_user_teams_list("user-uuid").await?;
let observed = client.get_user_observed_teams("user-uuid").await?;
```

## Org Features

```rust
let features = client.list_org_features("org-uuid").await?;
client.set_org_feature("org-uuid", &serde_json::json!({
    "feature_id": "advanced-analytics", "enabled": true
})).await?;
client.remove_org_feature("org-uuid", "advanced-analytics").await?;
```

## Credentials Management

```rust
use buttrbase_sdk::models::{CreateCredentialsRequest, UpdateCredentialsRequest};

let creds = client.create_credentials(&CreateCredentialsRequest {
    provider: "stripe",
    credentials: serde_json::json!({ "api_key": "sk_live_..." }),
    label: Some("Production Stripe"),
    environment: Some("production"),
    appid: None, appname: Some("my-app"), is_active: Some(true),
}).await?;
let all = client.list_credentials().await?;
let details = client.get_credentials_details(creds.id).await?;
client.delete_credentials(creds.id).await?;
```

## Analytics

```rust
// Ingest events
client.ingest_analytics_event(&serde_json::json!({
    "event": "page_view", "path": "/pricing", "user_uuid": "user-uuid"
})).await?;

// Dashboards
let app_stats = client.analytics_app_overview("app-uuid").await?;
let org_stats = client.analytics_org_overview("org-uuid").await?;
```

## Search & Discovery

```rust
client.search_index(&serde_json::json!({
    "id": "doc-1", "title": "Getting Started", "body": "Welcome..."
})).await?;
let results = client.search_query("authentication", None).await?;
let answer = client.search_chat("How do I set up SSO?", None).await?;
```

## AI Gateway

```rust
let response = client.ai_chat_completions(
    "org-uuid", "openai",
    &serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}]
    }),
).await?;
```

## Payments

```rust
use buttrbase_sdk::models::{CreatePaymentCheckoutRequest, SendInvoiceRequest};

// Dynamic payment routing (Stripe, Razorpay, Mollie, etc.)
let session = client.create_payment_checkout(&CreatePaymentCheckoutRequest {
    amount: 1000, // $10.00
    currency: "USD",
    country: "US",
    org_uuid: Some("org-uuid"),
}).await?;
println!("Provider: {}, Session: {}", session.provider, session.session_id);

// Send an invoice via SMS/email
let invoice = client.send_invoice(&SendInvoiceRequest {
    amount: 5000,
    currency: "USD",
    customer_phone: Some("+15551234567"),
    customer_email: Some("billing@example.com"),
    app_uuid: "app-uuid",
}).await?;
println!("Pay at: {}", invoice.payment_url);
```

## SMS

```rust
use buttrbase_sdk::models::SendSmsRequest;

client.send_sms(&SendSmsRequest {
    phone: "+15551234567",
    message: "Your verification code is 123456",
    scheme: Some("otp"),
    app_uuid: Some("app-uuid"),
}).await?;
```

## Email

```rust
use buttrbase_sdk::models::VerifyEmailIdentityRequest;

client.verify_email_identity(&VerifyEmailIdentityRequest {
    email: "noreply@example.com",
    aws_access_key_id: "AKIA...",
    aws_secret_access_key: "secret",
    aws_region: Some("us-east-1"),
}).await?;
```

## Environments

```rust
let envs = client.list_environments().await?;
```

## Plaid (Banking)

```rust
let token = client.plaid_create_link_token(&serde_json::json!({
    "user_id": "user-uuid"
})).await?;
let exchange = client.plaid_exchange_public_token("public-sandbox-xxx").await?;
let accounts = client.plaid_accounts().await?;
```

## Usage Reporting

```rust
client.usage_report(&serde_json::json!({
    "metric": "api_calls", "count": 1500, "period": "2025-05"
})).await?;
```

## Help Center

```rust
let help = client.help_root().await?;
let results = client.help_search("billing").await?;
let category = client.help_category("getting-started").await?;
let article = client.help_article("how-to-set-up-sso").await?;
```

## Webhooks

```rust
// Legacy webhook registration
client.register_webhook(
    "https://example.com/webhook",
    vec!["user.created", "billing.payment"],
    Some("org-uuid"),
).await?;

// Admin webhook endpoint management
let endpoints = client.list_webhook_endpoints("org-uuid").await?;
let ep = client.create_webhook_endpoint("org-uuid",
    "https://example.com/hooks",
    &["user.created", "team.updated"],
).await?;
let deliveries = client.list_webhook_deliveries("org-uuid").await?;
client.delete_webhook_endpoint("org-uuid", ep.id.unwrap()).await?;
```

## Custom Variables

```rust
client.set_custom_variable("theme", "dark", Some("user")).await?;
let val = client.get_custom_variable("theme").await?;
```

## Lifecycle Jobs & Notifications

```rust
client.enqueue_job("send-welcome-email", &serde_json::json!({
    "user_id": "user-uuid", "template": "welcome"
})).await?;
client.send_notification(&serde_json::json!({
    "user_uuid": "user-uuid", "title": "Welcome!", "body": "Your account is ready."
})).await?;
let notifications = client.list_notifications().await?;
```

## Admin: Signing Keys

```rust
let keys = client.list_signing_keys("org-uuid").await?;
client.rotate_signing_keys("org-uuid").await?;
let audit = client.list_signing_audit("org-uuid").await?;

// Sign arbitrary payloads
let sig = client.sign_payload("org-uuid", &serde_json::json!({
    "data": "payload-to-sign"
})).await?;

// Sign a document
let doc_sig = client.sign_document("org-uuid", &serde_json::json!({
    "document": "base64-encoded-doc",
    "content_type": "application/pdf"
})).await?;
```

## Admin: mTLS Certificate Authority

```rust
// Initialize a CA for mutual TLS
let ca = client.init_ca("org-uuid", &serde_json::json!({
    "common_name": "myorg.internal",
    "validity_days": 365
})).await?;
let ca_info = client.get_ca("org-uuid").await?;

// Issue and manage certificates
let certs = client.list_certificates("org-uuid").await?;
let cert = client.issue_certificate("org-uuid", &serde_json::json!({
    "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
})).await?;
client.revoke_certificate("org-uuid", &cert.serial).await?;
```

## Admin: Secrets Vault

```rust
// Encrypted-at-rest key-value store per org
let secrets = client.list_secrets("org-uuid").await?;
client.put_secret("org-uuid", "DATABASE_URL", "postgres://...").await?;
let secret = client.get_secret("org-uuid", "DATABASE_URL").await?;
client.delete_secret("org-uuid", "DATABASE_URL").await?;
```

## Admin: Domains

```rust
let domains = client.list_domains("org-uuid").await?;
let domain = client.create_domain("org-uuid", "example.com").await?;
// Verify after adding DNS TXT record
client.verify_domain("org-uuid", domain.id).await?;
client.delete_domain("org-uuid", domain.id).await?;
```

## Admin: Zero Trust & Security

```rust
// Revoke a JWT by its JTI
client.revoke_jti("jti-value").await?;

// Org metrics
let metrics = client.org_metrics("org-uuid").await?;

// Re-encrypt material after key rotation
client.re_encrypt_secrets("org-uuid").await?;
client.re_encrypt_signing_keys("org-uuid").await?;
client.re_encrypt_mtls_ca("org-uuid").await?;

// Auth event log
let events = client.list_auth_events("org-uuid").await?;
client.purge_auth_events("org-uuid").await?;

// KMS status
let kms = client.kms_status("org-uuid").await?;

// SAML certificate rollover
client.saml_cert_rollover("org-uuid", "conn-uuid", &serde_json::json!({
    "certificate": "-----BEGIN CERTIFICATE-----..."
})).await?;

// Payment settings
client.update_payment_settings("org-uuid", &serde_json::json!({
    "fee_strategy": "flat", "fee_config": { "cents": 100 }
})).await?;
```

## Admin: JIT Privilege Elevation

```rust
let grant = client.jit_request_grant("org-uuid", &serde_json::json!({
    "reason": "Production incident debugging",
    "scope": "admin",
    "duration_minutes": 30,
})).await?;

client.jit_approve_grant("org-uuid", &grant.grant_uuid).await?;
let grants = client.jit_list_grants("org-uuid").await?;
```

## Admin: SPIFFE

```rust
let svid = client.issue_svid("org-uuid", &serde_json::json!({
    "spiffe_id": "spiffe://myorg/service/api",
    "ttl_seconds": 3600,
})).await?;
```

## Admin: Portal & SCIM

```rust
// Issue a one-time admin portal token
let token = client.admin_portal_issue("org-uuid").await?;
let session = client.admin_portal_exchange(&token.token).await?;

// Issue a SCIM directory sync token
let scim = client.issue_scim_token("org-uuid").await?;
```

## JWT Verification

For services that federate auth through ButtrBase. Verify tokens without calling the ButtrBase API on every request.

```rust
use buttrbase_sdk::verify::{Verifier, VerifierConfig};

let verifier = Verifier::new(VerifierConfig {
    jwks_url: "https://api.buttrbase.com/.well-known/jwks.json".into(),
    issuer: "https://api.buttrbase.com".into(),
    audience: "my-app".into(),
});

// In an Axum handler:
async fn protected(
    headers: axum::http::HeaderMap,
) -> Result<String, StatusCode> {
    let auth = verifier.verify_bearer(&headers).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(format!("User: {}, Org: {}", auth.user_id, auth.org_id))
}
```

### Claims & AuthContext

- `Claims` — raw JWT payload: `sub` (user UUID), `org` (org UUID), `exp`, `iat`, `scope`
- `AuthContext` — simplified: `user_id`, `org_id`, `scopes`

### Error Handling

`VerifyError` variants map cleanly to HTTP status codes:

| Variant | HTTP | Meaning |
|---------|------|---------|
| `MissingBearer` | 401 | No Authorization header |
| `BadHeader` | 401 | Malformed token |
| `MissingKid` | 401 | Token has no key ID |
| `KidNotFound` | 401 | Key not in JWKS (revoked or rotated) |
| `InvalidToken` | 401 | Signature, audience, or expiry failed |
| `JwksFetch` | 502 | Could not reach ButtrBase JWKS endpoint |
| `JwksParse` | 502 | JWKS response was malformed |

## Format Negotiation

The SDK supports content negotiation between JSON and FlatBuffers for high-throughput scenarios.

```rust
use buttrbase_sdk::negotiator::{FormatNegotiator, DataFormat};
use reqwest::header::HeaderMap;

let mut headers = HeaderMap::new();
FormatNegotiator::add_headers(&mut headers, DataFormat::FlatBuffers);

if FormatNegotiator::is_binary(&response_headers) {
    // decode FlatBuffers
}
```

## Sister SDKs

- [buttrbase-sdk-python](https://github.com/Buttrbase/buttrbase-sdk-python)
- [buttrbase-sdk-node](https://github.com/Buttrbase/buttrbase-sdk-node)
- [buttrbase-sdk-go](https://github.com/Buttrbase/buttrbase-sdk-go)

## Docs

See https://buttrbase.com/docs for the full API reference.

## License

Apache-2.0
