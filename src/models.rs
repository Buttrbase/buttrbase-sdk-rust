use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── App credentials ───────────────────────────────────────────────────────

/// Live/sandbox environment inferred from the credential prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Live,
    Sandbox,
}

impl Environment {
    pub(crate) fn from_client_id(client_id: &str) -> Self {
        if client_id.starts_with("bb_test_") {
            Self::Sandbox
        } else {
            Self::Live
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Sandbox => "sandbox",
        }
    }

    pub fn is_sandbox(&self) -> bool {
        matches!(self, Self::Sandbox)
    }
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Auth / tokens ─────────────────────────────────────────────────────────

/// Access + refresh token pair returned after OTP verification.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenPair {
    pub token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub user_uuid: Option<Uuid>,
}

/// Returned when sending/refreshing — always just the new access token.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub refresh_token: Option<String>,
}

// ── Entitlements ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct EntitlementResult {
    pub granted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EntitlementCheckResponse {
    pub data: EntitlementResult,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EntitlementBatchResponseData {
    pub data: std::collections::HashMap<String, EntitlementResult>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EffectiveEntitlement {
    pub feature_key: String,
    pub granted: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

// ── Wallet ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct WalletSummary {
    pub balance_cents: i64,
    pub budget_limit_cents: Option<i64>,
    pub budget_period: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WalletTransaction {
    pub id: i32,
    pub kind: String,
    pub amount_cents: i64,
    pub description: Option<String>,
    pub created_at: String,
}

// ── Subscriptions ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionItem {
    pub id: i32,
    pub user_uuid: Option<Uuid>,
    pub price_id: Option<i32>,
    pub provider: String,
    pub provider_subscription_id: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

// ── Pricing ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PricingPreviewRequest {
    pub price_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coupon_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seats: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PricingPreview {
    pub amount_cents: i64,
    pub currency: String,
    pub discount_cents: Option<i64>,
    pub tax_cents: Option<i64>,
    pub final_cents: i64,
    pub region_resolved: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckoutSessionRequest {
    pub price_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckoutSession {
    pub payment_url: String,
    pub session_id: Option<String>,
    pub provider: String,
}

// ── Usage reporting ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct UsageEvent {
    pub metric: String,
    pub quantity: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_uuid: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_uuid: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

// ── Analytics ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AnalyticsEvent {
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

// ── Teams ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct TeamItem {
    pub id: i32,
    pub team_uuid: Uuid,
    pub org_uuid: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

// ── App management ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AppEntry {
    pub app_uuid: Uuid,
    pub app_name: String,
    pub role: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppCredentialInfo {
    pub environment: String,
    pub client_id: String,
    pub client_secret_prefix: Option<String>,
    pub is_active: bool,
    pub created_at: Option<String>,
    pub rotated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppCredentialsResponse {
    pub app_name: String,
    pub sandbox_enabled: bool,
    pub live: Option<AppCredentialInfo>,
    pub sandbox: Option<AppCredentialInfo>,
}

// ── Orgs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct OrgEntry {
    pub org_uuid: Uuid,
    pub org_name: String,
    pub role: Option<String>,
}

// ── Billing ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Invoice {
    pub id: i32,
    #[serde(default)]
    pub user_id: i32,
    pub subscription_id: Option<i32>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub provider_invoice_id: String,
    pub amount: i32,
    #[serde(default)]
    pub status: String,
    pub invoice_pdf_url: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

// ── Error response shapes ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct ApiErrorBody {
    #[serde(default)]
    pub error: Option<ApiErrorDetail>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ApiErrorDetail {
    pub message: String,
    pub code: Option<String>,
}

// ── Generic data wrapper ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct DataWrapper<T> {
    pub data: T,
}

// ── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct RegisterRequest<'a> {
    pub email: &'a str,
    pub password: &'a str,
    pub org_name: &'a str,
    pub app_uuid: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<&'a str>,
}

// ── Auth: finalize-registration (0.3.0+) ─────────────────────────────────────
//
// Replaces the legacy `RegisterRequest`. Instead of unconditionally creating
// an org named after the email's domain, the caller provides an explicit
// `OrgChoice` — either creating a new org by name or accepting an
// invitation by token. See README "Compatibility & gotchas" for the
// migration recipe from 0.2.x.

/// Tagged enum: what to do about the org during finalize-registration.
#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OrgChoice<'a> {
    /// Create a brand-new organization with this name. The new user becomes
    /// the admin. Server validates uniqueness — a 409 with body
    /// `{"error": "...taken..."}` means the name was just claimed.
    Create { name: &'a str },
    /// Consume an existing org's invitation. The user is added with the
    /// role on the invitation.
    AcceptInvite { invitation_token: &'a str },
}

#[derive(Serialize, Debug)]
pub struct FinalizeRegistrationRequest<'a> {
    pub email: &'a str,
    pub password: &'a str,
    pub app_uuid: Uuid,
    pub signup_token: &'a str,
    pub org_choice: OrgChoice<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<&'a str>,
}

/// Returned by `finalize_registration` and the deprecated `register`.
///
/// # Full signup contract
///
/// **Step 1 — send OTP**
/// ```text
/// POST /api/v1/auth/otp/send   (app Basic auth)
/// { "email": "alice@example.com", "app_uuid": "018f…" }
/// → 204 No Content
/// ```
///
/// **Step 2 — verify OTP → get signup_token**
/// ```text
/// POST /api/v1/auth/otp/verify   (app Basic auth)
/// { "email": "alice@example.com", "otp": "123456", "app_uuid": "018f…" }
/// → TokenPair { token: "<signup_token>", refresh_token?, user_uuid? }
/// ```
///
/// **Step 3 — finalize registration**
/// ```text
/// POST /api/v1/auth/finalize-registration   (app Basic auth)
/// {
///   "email":        "alice@example.com",
///   "password":     "s3cur3!",
///   "app_uuid":     "018f…",
///   "signup_token": "<token from step 2>",
///   "org_choice": { "type": "create", "name": "Acme Inc" }
///   // OR:        { "type": "accept_invite", "invitation_token": "Bd9…" }
///   "first_name":   "Alice",   // optional
///   "last_name":    "Smith"    // optional
/// }
/// → RegistrationResult (see below)
/// ```
///
/// **Org name availability check (before step 3)**
/// ```text
/// POST /api/v1/auth/check-org-name   (app Basic auth)
/// { "name": "Acme Inc" }
/// → CheckOrgNameResponse { available, reason?, normalized }
/// ```
#[derive(Deserialize, Debug, Clone)]
pub struct RegistrationResult {
    /// Short-lived JWT — use as `Authorization: Bearer <access_token>`.
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub user_uuid: String,
    /// UUID of the org that was created or joined.
    pub org_uuid: String,
    /// Role the new user holds in that org (`"admin"` for new orgs,
    /// whatever is on the invitation for `AcceptInvite`).
    pub role: String,
    pub message: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct CheckOrgNameResponse {
    pub available: bool,
    pub reason: Option<String>,
    pub normalized: String,
}

// ── Org Invitations ──────────────────────────────────────────────────────────

#[derive(Serialize, Debug, Default)]
pub struct CreateInvitationRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<&'a str>,
    /// Lifetime of the invitation. Server-clamped to [1, 720].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_hours: Option<i64>,
}

#[derive(Deserialize, Debug)]
pub struct CreateInvitationResponse {
    pub id: i32,
    pub org_uuid: Uuid,
    pub email: Option<String>,
    pub role: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// PLAINTEXT token — server only stores `SHA-256(token)`. Capture or
    /// share via `signup_url` immediately; it can't be re-fetched.
    pub token: String,
    pub signup_url: String,
}

#[derive(Deserialize, Debug)]
pub struct InvitationPreview {
    pub org_uuid: Uuid,
    pub org_name: String,
    pub email: Option<String>,
    pub role: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub valid: bool,
    /// One of `expired | accepted | revoked | not_found`.
    pub invalid_reason: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct AcceptInvitationResponse {
    pub org_uuid: Uuid,
    pub org_name: String,
    pub role: String,
}

#[derive(Deserialize, Debug)]
pub struct InvitationListItem {
    pub id: i32,
    pub email: Option<String>,
    pub role: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ── MFA / TOTP ───────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct MfaStatusResponse {
    pub enabled: bool,
    pub method: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct MfaEnrollResponse {
    pub secret: String,
    pub qr_code_url: String,
}

#[derive(Deserialize, Debug)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
}

// ── Organization Security ────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SsoConnection {
    pub id: Option<i32>,
    pub connection_uuid: String,
    pub org_uuid: String,
    pub provider: String,
    pub name: String,
    pub config: Option<serde_json::Value>,
}

#[derive(Serialize, Debug)]
pub struct CreateSsoConnectionRequest<'a> {
    pub provider: &'a str,
    pub name: &'a str,
    pub config: serde_json::Value,
}

#[derive(Deserialize, Debug)]
pub struct AuditEvent {
    pub id: i64,
    pub org_uuid: String,
    pub actor: Option<String>,
    pub action: String,
    pub resource: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: String,
}

// ── Sessions / Devices ───────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct SessionInfo {
    pub session_id: String,
    pub user_uuid: String,
    pub device_uuid: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
}

#[derive(Serialize, Debug)]
pub struct CreateDeviceAccountRequest<'a> {
    pub email: &'a str,
    pub org_name: &'a str,
    pub org_uuid: &'a str,
}

// ── Entitlements ─────────────────────────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct EntitlementCheckRequest<'a> {
    pub feature: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_uuid: Option<&'a str>,
}

// ── Coupons / Gift Cards ─────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Coupon {
    pub id: Option<i32>,
    pub code: String,
    pub product_id: Option<i32>,
    pub discount_type: String,
    pub discount_value: f64,
    pub active: Option<bool>,
    pub labels: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
pub struct GiftCardValidation {
    pub valid: bool,
    pub balance: Option<f64>,
    pub currency: Option<String>,
}

// ── Admin: Signing Keys ─────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct SigningKey {
    pub key_id: String,
    pub algorithm: String,
    pub created_at: String,
    pub status: String,
}

#[derive(Deserialize, Debug)]
pub struct SigningAuditEntry {
    pub id: i64,
    pub key_id: String,
    pub action: String,
    pub timestamp: String,
}

// ── Admin: mTLS CA ───────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct CertificateAuthority {
    pub org_uuid: String,
    pub ca_pem: String,
    pub created_at: String,
}

#[derive(Deserialize, Debug)]
pub struct Certificate {
    pub serial: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub status: String,
}

// ── Admin: Secrets Vault ─────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct SecretEntry {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize, Debug)]
pub struct SecretValue {
    pub name: String,
    pub value: String,
}

// ── Admin: Domains ───────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct Domain {
    pub id: i32,
    pub domain: String,
    pub verified: bool,
    pub verification_token: Option<String>,
}

// ── Admin: Webhooks ──────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct WebhookEndpoint {
    pub id: Option<i32>,
    pub url: String,
    pub events: Vec<String>,
    pub created_at: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct WebhookDelivery {
    pub id: i64,
    pub endpoint_id: i32,
    pub event: String,
    pub status: String,
    pub attempted_at: String,
}

// ── Admin: JIT Elevation ─────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct JitGrant {
    pub grant_uuid: String,
    pub org_uuid: String,
    pub requester: String,
    pub status: String,
    pub created_at: String,
}

// ── Admin: Auth Events (Zero Trust) ──────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct AuthEvent {
    pub id: i64,
    pub org_uuid: String,
    pub user_uuid: Option<String>,
    pub event_type: String,
    pub ip: Option<String>,
    pub timestamp: String,
}

// ── Admin: Portal ────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct AdminPortalToken {
    pub token: String,
    pub expires_at: String,
}

// ── Payments ─────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct PaymentCheckoutSession {
    pub provider: String,
    pub provider_public_key: String,
    pub client_secret: String,
    pub session_id: String,
}

#[derive(Serialize, Debug)]
pub struct CreatePaymentCheckoutRequest<'a> {
    pub amount: u32,
    pub currency: &'a str,
    pub country: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_uuid: Option<&'a str>,
}

#[derive(Serialize, Debug)]
pub struct SendInvoiceRequest<'a> {
    pub amount: u32,
    pub currency: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_phone: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_email: Option<&'a str>,
    pub app_uuid: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct SendInvoiceResponse {
    pub invoice_uuid: String,
    pub payment_url: String,
}

// ── SMS ──────────────────────────────────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct SendSmsRequest<'a> {
    pub phone: &'a str,
    pub message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_uuid: Option<&'a str>,
}

// ── Email ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct VerifyEmailIdentityRequest<'a> {
    pub email: &'a str,
    pub aws_access_key_id: &'a str,
    pub aws_secret_access_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_region: Option<&'a str>,
}

// ── Org Features ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OrgFeature {
    pub feature_id: String,
    pub enabled: bool,
}

// ── Invite-based registration ─────────────────────────────────────────────────

#[derive(Serialize, Debug, Clone)]
pub struct InviteAcceptRequest<'a> {
    pub token:      &'a str,
    pub first_name: &'a str,
    pub last_name:  &'a str,
    pub username:   &'a str,
    pub password:   &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<&'a str>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct InviteAcceptResponse {
    pub user_uuid:     String,
    pub org_uuid:      String,
    pub role:          String,
    pub access_token:  String,
    pub refresh_token: String,
    pub token_type:    String,
    pub expires_in:    i64,
    pub message:       String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OrgCheckResponse {
    pub name:      String,
    pub available: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SuperuserResponse {
    pub email:        String,
    pub is_superuser: bool,
}

// ── Contact forms ─────────────────────────────────────────────────────────────

#[derive(Serialize, Debug, Clone)]
pub struct ContactRequest<'a> {
    pub name:    &'a str,
    pub email:   &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<&'a str>,
    pub message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id:  Option<&'a str>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ContactUsRequest<'a> {
    pub name:    &'a str,
    pub email:   &'a str,
    pub subject: &'a str,
    pub message: &'a str,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ContactSubmitResponse {
    pub message:      String,
    pub reference_id: String,
}

// ── Geo / IP ──────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
pub struct GeoResponse {
    pub ip:       String,
    pub country:  String,
    pub timezone: String,
}

// ── OAuth start URL helper ──────────────────────────────────────────────────

/// OAuth provider supported by `/api/v1/auth/oauth/{provider}/start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    Google,
    Microsoft,
    Github,
    Apple,
}

impl OAuthProvider {
    /// The URL-path segment for this provider.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Microsoft => "microsoft",
            Self::Github => "github",
            Self::Apple => "apple",
        }
    }
}

// ── App-level OAuth provider configs (admin) ────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
pub struct OAuthConfigSummary {
    pub provider: String,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CreateOAuthConfigRequest {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub enabled: bool,
    /// Provider-specific extras as raw JSON. Required for Apple sign-in
    /// (shape: `{"team_id": "...", "key_id": "...", "private_key": "<PEM>"}`);
    /// the `private_key` field is stripped from the JSON server-side and
    /// re-stored as `private_key_encrypted` under the app's DEK. Optional /
    /// `None` for providers that don't need extras (Google, Microsoft,
    /// GitHub).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_extras: Option<serde_json::Value>,
}

/// Patch body. Each `Option::Some` field overwrites the stored value; `None`
/// leaves it as-is. To rotate the secret, set `client_secret` to the new
/// plaintext value.
#[derive(Serialize, Debug, Clone, Default)]
pub struct UpdateOAuthConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Replace the provider_extras JSON entirely. For Apple, sending a
    /// fresh `private_key` triggers re-encryption under the app's DEK and
    /// rotates the stored ciphertext. Omit (or `None`) to leave the
    /// existing extras alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_extras: Option<serde_json::Value>,
}

// ── Audit log (admin) ───────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
pub struct AuditRow {
    pub id: i64,
    pub app_uuid: Uuid,
    pub actor_user_uuid: Option<Uuid>,
    pub action: String,
    pub target_id: Option<String>,
    pub details: Option<serde_json::Value>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for `GET /api/v1/apps/{app_uuid}/audit-log`.
#[derive(Debug, Clone, Default)]
pub struct AuditLogQuery {
    /// Page size. Backend default is 200, capped at 1000.
    pub limit: Option<u64>,
    /// Returns only events whose `action` starts with this string. Examples:
    /// `"oauth_config."`, `"credentials."`, `"oauth_config.updated"`.
    pub action_prefix: Option<String>,
}

// ── Passkeys (WebAuthn) ─────────────────────────────────────────────────────
//
// The backend wraps passkey responses in `{data: ...}` (the
// `DataEnvelope<T>` shape). The SDK methods unwrap this for ergonomics.
//
// The WebAuthn challenge / credential blobs are pass-through `serde_json::Value`
// — we deliberately don't pull in `webauthn-rs` as a dep; consumers either
// hand the JSON to a browser via WASM or to a native authenticator helper.

/// Internal envelope used to unwrap the backend's `{data: ...}` shape.
#[derive(Deserialize, Debug, Clone)]
pub(crate) struct DataEnvelope<T> {
    pub data: T,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PasskeyRegistrationChallenge {
    /// WebAuthn `CreationChallengeResponse`. Pass `challenge.publicKey` to
    /// `navigator.credentials.create({publicKey: ...})` in the browser.
    pub challenge: serde_json::Value,
    /// Opaque server-signed blob; pass back unchanged to
    /// [`super::client::ButtrBaseClient::passkey_register_complete`].
    pub registration_state: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct PasskeyRegistrationComplete {
    pub registration_state: String,
    /// WebAuthn `RegisterPublicKeyCredential` produced by the browser.
    pub credential: serde_json::Value,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PasskeyRegistrationResult {
    pub credential_id: String,
    pub message: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PasskeyAuthChallenge {
    /// WebAuthn `RequestChallengeResponse`. Pass `challenge.publicKey` to
    /// `navigator.credentials.get({publicKey: ...})` in the browser.
    pub challenge: serde_json::Value,
    pub auth_state: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct PasskeyAuthComplete {
    pub auth_state: String,
    /// WebAuthn `PublicKeyCredential` produced by the browser.
    pub credential: serde_json::Value,
}

/// A single row returned by `GET /api/v1/me/passkeys`.
///
/// `credential_id_prefix` is the first 12 characters of the WebAuthn
/// credential ID — enough to disambiguate in a dashboard table without
/// exposing the full identifier.
#[derive(Deserialize, Debug, Clone)]
pub struct PasskeyListItem {
    pub credential_uuid: Uuid,
    pub credential_id_prefix: String,
    pub app_uuid: Option<Uuid>,
    pub nickname: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Per-app WebAuthn relying-party configuration.
///
/// `rp_id` is the eTLD+1 the browser binds passkeys to (e.g. `app.example.com`).
/// `None` means the app falls back to the deployment-wide RP id from the
/// `BUTTRBASE_WEBAUTHN_RP_ID` env var. `rp_origins` lists every origin
/// permitted to ceremonies under this RP — a single app can serve
/// `https://app.example.com`, `https://staging.example.com`, and
/// `http://localhost:3001` without re-enrolling passkeys.
#[derive(Deserialize, Debug, Clone)]
pub struct AppRpConfig {
    pub app_uuid: Uuid,
    pub rp_id: Option<String>,
    pub rp_origins: Vec<String>,
}

/// Patch shape for `PATCH /api/v1/apps/{app_uuid}/rp-config`.
///
/// Fields default to `None` (omitted) — only the fields you set are updated.
/// To explicitly *clear* `rp_id` (revert to env fallback) the backend
/// accepts `{"rp_id": null}`; this SDK does not currently expose that —
/// drop to the raw [`Client::request`] for that one-off if needed.
#[derive(Serialize, Debug, Clone, Default)]
pub struct UpdateAppRpConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_origins: Option<Vec<String>>,
}

// ── Backwards compatibility / Legacy structures ──────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub id: i32,
    pub user_uuid: String,
    pub email: String,
    pub org_uuid: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginResponse {
    pub access_token: Option<String>,
    pub user: User,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EntitlementCheckResponseLegacy {
    #[serde(alias = "allowed", alias = "granted")]
    pub allowed: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use uuid::Uuid;

    // ── Environment ────────────────────────────────────────────────────────

    #[test]
    fn test_environment_as_str() {
        assert_eq!(Environment::Live.as_str(), "live");
        assert_eq!(Environment::Sandbox.as_str(), "sandbox");
    }

    #[test]
    fn test_environment_display() {
        assert_eq!(format!("{}", Environment::Live), "live");
        assert_eq!(format!("{}", Environment::Sandbox), "sandbox");
    }

    #[test]
    fn test_environment_is_sandbox() {
        assert!(Environment::Sandbox.is_sandbox());
        assert!(!Environment::Live.is_sandbox());
    }

    #[test]
    fn test_environment_from_client_id() {
        assert_eq!(Environment::from_client_id("bb_test_foo"), Environment::Sandbox);
        assert_eq!(Environment::from_client_id("bb_live_foo"), Environment::Live);
        assert_eq!(Environment::from_client_id("other"), Environment::Live);
    }

    #[test]
    fn test_environment_copy() {
        let e = Environment::Live;
        let e2 = e;
        assert_eq!(e, e2);
    }

    // ── TokenPair ──────────────────────────────────────────────────────────

    #[test]
    fn test_token_pair_full() {
        let uid = Uuid::nil();
        let json = format!(
            r#"{{"token":"acc","refresh_token":"ref","user_uuid":"{}"}}"#,
            uid
        );
        let pair: TokenPair = serde_json::from_str(&json).unwrap();
        assert_eq!(pair.token, "acc");
        assert_eq!(pair.refresh_token, Some("ref".to_string()));
        assert_eq!(pair.user_uuid, Some(uid));
    }

    #[test]
    fn test_token_pair_minimal() {
        let json = r#"{"token":"acc","user_uuid":null}"#;
        let pair: TokenPair = serde_json::from_str(json).unwrap();
        assert_eq!(pair.token, "acc");
        assert!(pair.refresh_token.is_none());
    }

    // ── AccessToken ────────────────────────────────────────────────────────

    #[test]
    fn test_access_token_deserialize() {
        let json = r#"{"token":"new_acc","refresh_token":"new_ref"}"#;
        let at: AccessToken = serde_json::from_str(json).unwrap();
        assert_eq!(at.token, "new_acc");
        assert_eq!(at.refresh_token, Some("new_ref".to_string()));
    }

    #[test]
    fn test_access_token_no_refresh() {
        let json = r#"{"token":"new_acc","refresh_token":null}"#;
        let at: AccessToken = serde_json::from_str(json).unwrap();
        assert!(at.refresh_token.is_none());
    }

    // ── EntitlementResult ──────────────────────────────────────────────────

    #[test]
    fn test_entitlement_result_granted() {
        let json = r#"{"granted":true,"reason":null}"#;
        let er: EntitlementResult = serde_json::from_str(json).unwrap();
        assert!(er.granted);
        assert!(er.reason.is_none());
    }

    #[test]
    fn test_entitlement_result_denied_with_reason() {
        let json = r#"{"granted":false,"reason":"plan_limit"}"#;
        let er: EntitlementResult = serde_json::from_str(json).unwrap();
        assert!(!er.granted);
        assert_eq!(er.reason, Some("plan_limit".to_string()));
    }

    // ── EffectiveEntitlement ───────────────────────────────────────────────

    #[test]
    fn test_effective_entitlement_deserialize() {
        let json = r#"{"feature_key":"feat_a","granted":true}"#;
        let ee: EffectiveEntitlement = serde_json::from_str(json).unwrap();
        assert_eq!(ee.feature_key, "feat_a");
        assert!(ee.granted);
        assert!(ee.reason.is_none());
    }

    // ── WalletSummary ──────────────────────────────────────────────────────

    #[test]
    fn test_wallet_summary_full() {
        let json = r#"{"balance_cents":5000,"budget_limit_cents":10000,"budget_period":"monthly"}"#;
        let ws: WalletSummary = serde_json::from_str(json).unwrap();
        assert_eq!(ws.balance_cents, 5000);
        assert_eq!(ws.budget_limit_cents, Some(10000));
        assert_eq!(ws.budget_period, Some("monthly".to_string()));
    }

    #[test]
    fn test_wallet_summary_no_budget() {
        let json = r#"{"balance_cents":100,"budget_limit_cents":null,"budget_period":null}"#;
        let ws: WalletSummary = serde_json::from_str(json).unwrap();
        assert!(ws.budget_limit_cents.is_none());
        assert!(ws.budget_period.is_none());
    }

    // ── WalletTransaction ──────────────────────────────────────────────────

    #[test]
    fn test_wallet_transaction_deserialize() {
        let json = r#"{"id":1,"kind":"deposit","amount_cents":1000,"description":"Top-up","created_at":"2024-01-01"}"#;
        let wt: WalletTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(wt.id, 1);
        assert_eq!(wt.kind, "deposit");
        assert_eq!(wt.amount_cents, 1000);
    }

    // ── SubscriptionItem ───────────────────────────────────────────────────

    #[test]
    fn test_subscription_item_deserialize() {
        let uid = Uuid::nil();
        let json = format!(
            r#"{{"id":1,"user_uuid":"{}","price_id":5,"provider":"stripe","provider_subscription_id":"sub_xxx","status":"active","created_at":"2024-01-01","updated_at":"2024-01-01"}}"#,
            uid
        );
        let sub: SubscriptionItem = serde_json::from_str(&json).unwrap();
        assert_eq!(sub.id, 1);
        assert_eq!(sub.provider, "stripe");
        assert_eq!(sub.status, "active");
    }

    // ── PricingPreviewRequest ──────────────────────────────────────────────

    #[test]
    fn test_pricing_preview_request_minimal_serialize() {
        let req = PricingPreviewRequest {
            price_id: 1,
            coupon_code: None,
            seats: None,
            country: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"price_id\":1"));
        assert!(!json.contains("coupon_code"));
        assert!(!json.contains("seats"));
    }

    #[test]
    fn test_pricing_preview_request_full_serialize() {
        let req = PricingPreviewRequest {
            price_id: 2,
            coupon_code: Some("SAVE10".to_string()),
            seats: Some(5),
            country: Some("US".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("SAVE10"));
        assert!(json.contains("\"seats\":5"));
        assert!(json.contains("US"));
    }

    // ── PricingPreview ─────────────────────────────────────────────────────

    #[test]
    fn test_pricing_preview_deserialize() {
        let json = r#"{"amount_cents":999,"currency":"USD","discount_cents":null,"tax_cents":100,"final_cents":1099,"region_resolved":"us-east"}"#;
        let pp: PricingPreview = serde_json::from_str(json).unwrap();
        assert_eq!(pp.amount_cents, 999);
        assert_eq!(pp.currency, "USD");
        assert_eq!(pp.final_cents, 1099);
        assert_eq!(pp.region_resolved, Some("us-east".to_string()));
    }

    // ── CheckoutSessionRequest ─────────────────────────────────────────────

    #[test]
    fn test_checkout_session_request_serialize() {
        let req = CheckoutSessionRequest {
            price_id: 1,
            quote_id: Some("q-123".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"price_id\":1"));
        assert!(json.contains("q-123"));
    }

    #[test]
    fn test_checkout_session_request_no_quote() {
        let req = CheckoutSessionRequest {
            price_id: 2,
            quote_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("quote_id"));
    }

    // ── CheckoutSession ────────────────────────────────────────────────────

    #[test]
    fn test_checkout_session_deserialize() {
        let json = r#"{"payment_url":"https://pay.example.com","session_id":"sess_1","provider":"stripe"}"#;
        let cs: CheckoutSession = serde_json::from_str(json).unwrap();
        assert_eq!(cs.provider, "stripe");
        assert_eq!(cs.session_id, Some("sess_1".to_string()));
    }

    // ── UsageEvent ─────────────────────────────────────────────────────────

    #[test]
    fn test_usage_event_minimal_serialize() {
        let event = UsageEvent {
            metric: "api_calls".to_string(),
            quantity: 1.0,
            org_uuid: None,
            app_uuid: None,
            timestamp: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("api_calls"));
        assert!(json.contains("1.0"));
        assert!(!json.contains("org_uuid"));
    }

    #[test]
    fn test_usage_event_full_serialize() {
        let uuid = Uuid::nil();
        let event = UsageEvent {
            metric: "storage_gb".to_string(),
            quantity: 2.5,
            org_uuid: Some(uuid),
            app_uuid: Some(uuid),
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("storage_gb"));
        assert!(json.contains("2.5"));
        assert!(json.contains("2024-01-01"));
    }

    // ── AnalyticsEvent ─────────────────────────────────────────────────────

    #[test]
    fn test_analytics_event_minimal() {
        let event = AnalyticsEvent {
            event_type: "click".to_string(),
            properties: None,
            timestamp: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("click"));
        assert!(!json.contains("properties"));
    }

    #[test]
    fn test_analytics_event_with_properties() {
        let event = AnalyticsEvent {
            event_type: "page_view".to_string(),
            properties: Some(serde_json::json!({"page": "/home"})),
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("/home"));
        assert!(json.contains("2024-01-01"));
    }

    // ── TeamItem ───────────────────────────────────────────────────────────

    #[test]
    fn test_team_item_deserialize() {
        let uid = Uuid::nil();
        let json = format!(
            r#"{{"id":1,"team_uuid":"{}","org_uuid":"org-1","name":"Engineering","description":null}}"#,
            uid
        );
        let team: TeamItem = serde_json::from_str(&json).unwrap();
        assert_eq!(team.id, 1);
        assert_eq!(team.name, "Engineering");
        assert!(team.description.is_none());
    }

    #[test]
    fn test_team_item_with_description() {
        let uid = Uuid::nil();
        let json = format!(
            r#"{{"id":2,"team_uuid":"{}","org_uuid":"org-2","name":"Design","description":"UX team"}}"#,
            uid
        );
        let team: TeamItem = serde_json::from_str(&json).unwrap();
        assert_eq!(team.description, Some("UX team".to_string()));
    }

    // ── AppEntry ───────────────────────────────────────────────────────────

    #[test]
    fn test_app_entry_deserialize() {
        let uid = Uuid::nil();
        let json = format!(
            r#"{{"app_uuid":"{}","app_name":"MySaaS","role":"admin"}}"#,
            uid
        );
        let app: AppEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(app.app_name, "MySaaS");
        assert_eq!(app.role, Some("admin".to_string()));
    }

    // ── AppCredentialInfo ──────────────────────────────────────────────────

    #[test]
    fn test_app_credential_info_deserialize() {
        let json = r#"{"environment":"live","client_id":"bb_live_cid","client_secret_prefix":"bb_live_sk","is_active":true,"created_at":"2024-01-01","rotated_at":null}"#;
        let info: AppCredentialInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.environment, "live");
        assert!(info.is_active);
        assert!(info.rotated_at.is_none());
    }

    // ── AppCredentialsResponse ─────────────────────────────────────────────

    #[test]
    fn test_app_credentials_response_deserialize() {
        let json = r#"{"app_name":"MySaaS","sandbox_enabled":true,"live":null,"sandbox":null}"#;
        let resp: AppCredentialsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.app_name, "MySaaS");
        assert!(resp.sandbox_enabled);
        assert!(resp.live.is_none());
    }

    // ── OrgEntry ───────────────────────────────────────────────────────────

    #[test]
    fn test_org_entry_deserialize() {
        let uid = Uuid::nil();
        let json = format!(
            r#"{{"org_uuid":"{}","org_name":"ACME","role":"owner"}}"#,
            uid
        );
        let org: OrgEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(org.org_name, "ACME");
        assert_eq!(org.role, Some("owner".to_string()));
    }

    // ── Invoice ────────────────────────────────────────────────────────────

    #[test]
    fn test_invoice_deserialize() {
        let json = r#"{"id":1,"user_id":2,"subscription_id":null,"provider":"stripe","provider_invoice_id":"inv_1","amount":999,"status":"paid","invoice_pdf_url":"https://pdf.example.com","created_at":"2024-01-01","updated_at":"2024-01-01"}"#;
        let inv: Invoice = serde_json::from_str(json).unwrap();
        assert_eq!(inv.provider, "stripe");
        assert_eq!(inv.amount, 999);
        assert_eq!(inv.status, "paid");
        assert!(inv.subscription_id.is_none());
    }
}
