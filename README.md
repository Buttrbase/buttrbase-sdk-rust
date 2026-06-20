# Rust SDK

> **0.3.0 — org-aware registration + invitations.** `register()` is now
> deprecated in favor of the new `finalize_registration()` flow. The old
> auto-create-by-domain behavior collided on the second sign-up from any
> domain and made invitations impossible. The new flow is:
>
> ```
> send_otp → verify_otp → finalize_registration(with OrgChoice)
> ```
>
> where `OrgChoice` is either `Create { name }` or `AcceptInvite {
> invitation_token }`. New methods cover org-invitation lifecycle:
> `create_invitation`, `preview_invitation`, `accept_invitation`,
> `list_invitations`, `revoke_invitation`. See CHANGELOG for the full
> migration recipe.

> **Breaking change (unreleased) — `app_uuid` migration.** `send_otp`,
> `verify_otp`, `magic_link_send`, and `register` now take `app_uuid: Uuid`
> in place of the old `app: &str` slug. Slug-based app identifiers are no
> longer accepted by the backend. See `CHANGELOG.md` for the full list of
> additions (OAuth start helper, OAuth config admin, audit log).

> **0.2.0 dependency bump — `jsonwebtoken` 9 → 10.** Transitive change; SDK
> public API unchanged. The SDK pins `jsonwebtoken = { version = "10",
> features = ["aws_lc_rs"] }` internally so this Just Works for you. **If you
> also depend on `jsonwebtoken` 10 directly elsewhere in your app**, make
> sure your own dependency line enables exactly one of `aws_lc_rs` or
> `rust_crypto`, otherwise your app will SIGABRT on the first JWT op:
>
> ```toml
> # In YOUR Cargo.toml — if you use jsonwebtoken 10 directly
> jsonwebtoken = { version = "10", features = ["aws_lc_rs"] }
> ```
>
> Don't enable both; the panic message asks for exactly one. See
> "Compatibility & gotchas" below for the full explanation.

## Overview

The official Rust SDK for ButtrBase. Two surfaces, one crate:

- **Client** — call the ButtrBase API from your Rust service (auth, organizations, billing, RBAC, teams, credentials, search, AI gateway, webhooks, and more).
- **Verifier** — verify ButtrBase-issued JWTs in your own Rust service for federated auth.

## Installation

```toml
[dependencies]
buttrbase-sdk = "0.3"
tokio = { version = "1", features = ["full"] }
```

## Compatibility & gotchas

### `jsonwebtoken 10` requires a crypto-provider feature flag

ButtrBase signs JWTs with RS256 and the SDK verifies them via `jsonwebtoken 10`.
That crate's default features (`["use_pem"]`) **do not enable a crypto provider** —
you must opt into exactly one of:

- `aws_lc_rs` — the default we pin in this SDK (FIPS-able, shared with rustls)
- `rust_crypto` — pure-Rust alternative

The SDK takes care of this internally. **You only need to act if you ALSO use
`jsonwebtoken` 10 directly in your own code** (or transitively from another
dep): add `features = ["aws_lc_rs"]` to your own `jsonwebtoken` dependency line,
or your app will panic on first JWT operation with:

```
thread 'tokio-rt-worker' panicked at jsonwebtoken-10.x/src/crypto/mod.rs:
Could not automatically determine the process-level CryptoProvider...
```

This is NOT the same as `rustls`'s `CryptoProvider::install_default()` —
`jsonwebtoken` has its own independent crypto-provider abstraction that's
selected at compile time. Installing the `rustls` provider at runtime does not
fix the `jsonwebtoken` panic.

If you need `rust_crypto` instead of `aws_lc_rs` (e.g., environments where you
can't link `aws-lc-sys` C bindings), open an issue — we'll expose a feature
flag in a future release.

## Client Setup

```rust
use buttrbase_sdk::client::ButtrBaseClient;

let mut client = ButtrBaseClient::new("https://api.buttrbase.com".into());
```

## Authentication

### Registration

```rust
use buttrbase_sdk::models::RegisterRequest;
use uuid::Uuid;

let app_uuid = Uuid::parse_str("018f1234-5678-7000-8000-000000000001").unwrap();

let response = client.register(&RegisterRequest {
    email: "alice@example.com",
    password: "secure-password",
    org_name: "my-org",
    app_uuid,
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
use uuid::Uuid;
let app_uuid = Uuid::parse_str("018f1234-5678-7000-8000-000000000001").unwrap();

client.send_otp("user@example.com", app_uuid).await?;
client.verify_otp("user@example.com", "123456", app_uuid).await?;
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
use uuid::Uuid;
let app_uuid = Uuid::parse_str("018f1234-5678-7000-8000-000000000001").unwrap();

client.magic_link_send(
    "user@example.com",
    Some("https://app.example.com/callback"),
    app_uuid,
).await?;
let login = client.magic_link_verify("token-from-email").await?;
println!("{}", login.access_token); // JWT with sub, org, aud claims
```

### Passkey support (WebAuthn)

Thin wrappers around the four passkey ceremony endpoints. The WebAuthn JSON
blobs are pass-through `serde_json::Value` — no `webauthn-rs` dep is pulled in
on the SDK side; consumers either hand the JSON to a browser (WASM /
JavaScript) or to a native authenticator helper.

```rust
use buttrbase_sdk::models::{PasskeyAuthComplete, PasskeyRegistrationComplete};

// Registration (requires an authenticated caller — passkey added to the
// user's existing account):
let begin = client.passkey_register_begin().await?;
// Hand `begin.challenge` (a WebAuthn `CreationChallengeResponse`) to a
// browser; the browser returns a `RegisterPublicKeyCredential`.
let result = client.passkey_register_complete(&PasskeyRegistrationComplete {
    registration_state: begin.registration_state,
    credential: browser_credential_json,
}).await?;
println!("registered passkey: {}", result.credential_id);

// Authentication (anonymous):
let challenge = client.passkey_authenticate_begin().await?;
// Browser produces a `PublicKeyCredential` assertion via
// `navigator.credentials.get({publicKey: challenge.publicKey})`.
let session = client.passkey_authenticate_complete(&PasskeyAuthComplete {
    auth_state: challenge.auth_state,
    credential: browser_assertion_json,
}).await?;

// List the signed-in user's enrolled passkeys (descending by created_at):
let passkeys = client.list_my_passkeys().await?;
for p in &passkeys {
    println!("{} ({})", p.nickname.as_deref().unwrap_or("—"), p.credential_id_prefix);
}

// Revoke one by its `credential_uuid` (owner check enforced server-side):
client.delete_my_passkey(passkeys[0].credential_uuid).await?;
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
    // Optional — buttrbase tokens carry no stable per-app `aud`. Leave None to
    // skip audience validation (identity comes from iss + signature + org claim).
    audience: None,
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

## Recipes

### Complete Onboarding

```rust
use buttrbase_sdk::client::ButtrBaseClient;
use buttrbase_sdk::models::RegisterRequest;
use uuid::Uuid;

let mut client = ButtrBaseClient::new("https://api.buttrbase.com".into());
let app_uuid = Uuid::parse_str("018f1234-5678-7000-8000-000000000001").unwrap();

// 1. Register and login
client.register(&RegisterRequest {
    email: "admin@acme.com", password: "s3cur3!", org_name: "Acme Corp",
    app_uuid,
    first_name: Some("Alice"), last_name: None,
}).await?;
client.login("admin@acme.com", "s3cur3!", "Acme Corp").await?;

// 2. Get profile
let profile = client.get_profile().await?;

// 3. Create a team and add a member
let team = client.create_team(&serde_json::json!({
    "name": "Engineering", "org_uuid": "org-uuid"
})).await?;
client.add_team_member("team-uuid", "colleague-uuid").await?;
```

### MFA Enrollment

```rust
// 1. Check MFA status
let status = client.mfa_status().await?;

// 2. Enroll in TOTP — returns secret + QR URL
let enrollment = client.mfa_totp_enroll().await?;
println!("Scan this QR: {}", enrollment.qr_code_url);

// 3. Activate with code from authenticator app
client.mfa_totp_activate("123456").await?;

// 4. Generate recovery codes
let codes = client.mfa_generate_recovery_codes().await?;
```

### Checkout Flow

```rust
// 1. Preview pricing
let preview = client.pricing_preview(&serde_json::json!({
    "plan": "pro", "seats": 10
})).await?;

// 2. Check entitlement
let check = client.entitlements_check(&EntitlementCheckRequest {
    feature: "advanced-analytics", org_uuid: Some("org-uuid"),
}).await?;

// 3. Create checkout session
let session = client.pricing_checkout_session(&serde_json::json!({
    "plan": "pro", "seats": 10
})).await?;
```

### SSO Setup

```rust
use buttrbase_sdk::models::CreateSsoConnectionRequest;

// 1. Create an OIDC connection
let conn = client.create_sso_connection("org-uuid", &CreateSsoConnectionRequest {
    provider: "okta", name: "Okta SSO",
    config: serde_json::json!({"domain": "myorg.okta.com"}),
}).await?;

// 2. Get the authorize URL
let auth = client.oidc_authorize_url("conn-uuid").await?;

// 3. Handle callback
let mut params = std::collections::HashMap::new();
params.insert("code".into(), "auth-code".into());
let result = client.oidc_callback(&params).await?;
```

### Secrets & Key Management

```rust
// 1. Store a secret
client.put_secret("org-uuid", "DATABASE_URL", "postgres://...").await?;

// 2. List and retrieve secrets
let secrets = client.list_secrets("org-uuid").await?;
let secret = client.get_secret("org-uuid", "DATABASE_URL").await?;

// 3. Rotate signing keys
client.rotate_signing_keys("org-uuid").await?;
let audit = client.list_signing_audit("org-uuid").await?;
```

### OAuth Start URL

`oauth_start_url` builds the URL the user-agent should be sent to; it does
not perform the redirect itself (the backend does, with a 302 once the user
hits it).

```rust
use buttrbase_sdk::models::OAuthProvider;
use uuid::Uuid;

let app_uuid = Uuid::parse_str("018f1234-5678-7000-8000-000000000001").unwrap();

let url = client.oauth_start_url(
    OAuthProvider::Google,
    app_uuid,
    "https://app.example.com/oauth/callback",
);
// e.g. https://api.buttrbase.com/api/v1/auth/oauth/google/start?app_uuid=…&return_to=…
// Redirect the browser to this URL.
```

### OAuth Provider Config

Per-app OAuth client credentials for Google / Microsoft / GitHub / Apple.
`client_secret` is encrypted at rest and never returned in responses.

```rust
use buttrbase_sdk::models::{CreateOAuthConfigRequest, UpdateOAuthConfigRequest};
use uuid::Uuid;

let app_uuid = Uuid::parse_str("018f1234-5678-7000-8000-000000000001").unwrap();

let cfg = client.create_oauth_config(
    app_uuid,
    &CreateOAuthConfigRequest {
        provider: "google".into(),
        client_id: "…apps.googleusercontent.com".into(),
        client_secret: "GOCSPX-…".into(),
        redirect_uris: vec!["https://app.example.com/oauth/callback".into()],
        scopes: vec!["openid".into(), "email".into(), "profile".into()],
        enabled: true,
    },
).await?;

// Rotate the secret without touching the rest of the config.
client.update_oauth_config(
    app_uuid,
    "google",
    &UpdateOAuthConfigRequest {
        client_secret: Some("GOCSPX-new-…".into()),
        ..Default::default()
    },
).await?;

let configs = client.list_oauth_configs(app_uuid).await?;

client.delete_oauth_config(app_uuid, "google").await?;
```

### Audit Log

Per-app, read-only stream of security events (`oauth_config.*`,
`credentials.*`, …), newest first.

```rust
use buttrbase_sdk::models::AuditLogQuery;
use uuid::Uuid;

let app_uuid = Uuid::parse_str("018f1234-5678-7000-8000-000000000001").unwrap();

let rows = client.read_audit_log(
    app_uuid,
    AuditLogQuery {
        limit: Some(50),
        action_prefix: Some("oauth_config.".into()),
    },
).await?;

for row in rows {
    println!("{}  {}  {:?}", row.created_at, row.action, row.target_id);
}
```

## Docs

See https://buttrbase.com/docs for the full API reference.

## License

Apache-2.0
