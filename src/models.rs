use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Debug)]
pub struct User {
    pub id: i32,
    pub user_uuid: String,
    pub email: String,
    pub org_uuid: String,
}

#[derive(Deserialize, Debug)]
pub struct Profile {
    pub id: i32,
    pub user_uuid: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone: String,
    pub org_uuid: String,
}

#[derive(Deserialize, Debug)]
pub struct LoginResponse {
    pub access_token: Option<String>,
    pub user: User,
}

#[derive(Deserialize, Debug)]
pub struct CheckoutResponse {
    pub id: String,
    pub url: String,
}

#[derive(Deserialize, Debug)]
pub struct Invoice {
    pub id: i32,
    pub user_id: i32,
    pub subscription_id: i32,
    pub provider: String,
    pub provider_invoice_id: String,
    pub amount: i32,
    pub status: String,
    pub invoice_pdf_url: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize, Debug)]
pub struct ButtrBaseError {
    pub message: String,
    pub code: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ButtrBaseErrorResponse {
    pub error: ButtrBaseError,
}

#[derive(Deserialize, Debug)]
pub struct Permission {
    pub id: i32,
    pub name: String,
    pub description: String,
}

#[derive(Deserialize, Debug)]
pub struct Role {
    pub id: i32,
    pub name: String,
    pub product_id: i32,
}

#[derive(serde::Serialize, Debug)]
pub struct CreateRoleRequest {
    pub name: String,
    pub permissions: Vec<PermissionId>,
}

#[derive(Serialize, Debug)]
pub struct PermissionId {
    pub id: i32,
}

#[derive(Deserialize, Debug)]
pub struct Credentials {
    pub id: i32,
    pub clientid: String,
    pub appname: Option<String>,
    pub label: Option<String>,
    pub environment: Option<String>,
    pub is_active: bool,
    pub createdat: String,
    pub updatedat: String,
    pub appid: Option<i32>,
    pub org_uuid: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct CredentialsDetails {
    pub id: i32,
    pub clientid: String,
    pub appname: Option<String>,
    pub appid: Option<i32>,
    pub org_uuid: Option<String>,
    pub label: Option<String>,
    pub environment: Option<String>,
    pub is_active: bool,
    pub createdat: String,
    pub updatedat: String,
    pub credentials: serde_json::Value,
}

#[derive(Serialize, Debug)]
pub struct CreateCredentialsRequest<'a> {
    pub provider: &'a str,
    pub credentials: serde_json::Value,
    pub label: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub appid: Option<i32>,
    pub appname: Option<&'a str>,
    pub is_active: Option<bool>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCredentialsRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

#[derive(Deserialize, Debug)]
pub struct HelpCategory {
    pub id: i32,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub display_order: i32,
    pub visibility: String,
}

#[derive(Deserialize, Debug)]
pub struct HelpArticle {
    pub id: i32,
    pub category_id: Option<i32>,
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub body_markdown: String,
    pub body_html: Option<String>,
    pub status: String,
    pub tags: Option<Vec<String>>,
    pub author_id: Option<i32>,
    pub editor_id: Option<i32>,
    pub published_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub help_category: Option<HelpCategory>,
}

#[derive(Deserialize, Debug)]
pub struct Organization {
    pub id: i32,
    pub org_uuid: String,
    pub name: String,
    pub org_display_name: String,
    pub app_uuid: String,
    pub icon_url: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Team {
    pub id: i32,
    pub team_uuid: String,
    pub org_uuid: String,
    pub name: String,
}

#[derive(Deserialize, Debug)]
pub struct ApiKey {
    pub id: i32,
    pub key_uuid: String,
    pub org_uuid: String,
    pub name: String,
    pub access_key: String,
}

#[derive(Deserialize, Debug)]
pub struct OrgAddress {
    pub id: i32,
    pub org_uuid: String,
    pub street: String,
    pub city: String,
    pub state: String,
    pub zip: String,
    pub country: String,
}

#[derive(Deserialize, Debug)]
pub struct Subscription {
    pub id: i32,
    pub user_id: i32,
    pub user_uuid: Option<String>,
    pub price_id: Option<i32>,
    pub provider: String,
    pub provider_subscription_id: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize, Debug)]
pub struct UserAccount {
    pub id: i32,
    pub account_uuid: String,
    pub device_uuid: String,
    pub email: String,
    pub org_name: String,
    pub org_uuid: String,
    pub user_uuid: Option<String>,
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

#[derive(Deserialize, Debug)]
pub struct EntitlementCheckResponse {
    pub allowed: bool,
    pub reason: Option<String>,
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

// ── API key exchange (POST /api/v1/auth/api-key/exchange) ────────────────────

/// Response from `POST /api/v1/auth/api-key/exchange`.
///
/// `token_type` is always `"Bearer"`.
#[derive(Deserialize, Debug, Clone)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
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

// ── App-level API keys (admin) ──────────────────────────────────────────────

/// One entry from `GET /api/v1/apps/{app_uuid}/api-keys`.
#[derive(Deserialize, Debug, Clone)]
pub struct ApiKeySummary {
    pub key_uuid: Uuid,
    pub app_uuid: Uuid,
    pub key_prefix: String,
    pub name: String,
    /// One of `"short_lived"`, `"permanent"`, or `"expiring"`.
    pub key_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// "Shown once" response from create / rotate. `raw_key` is the only place the
/// plaintext key is ever returned — store it immediately or it cannot be
/// recovered.
#[derive(Deserialize, Debug, Clone)]
pub struct CreatedKeyResponse {
    pub key_uuid: Uuid,
    pub raw_key: String,
    pub key_prefix: String,
    pub key_type: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Key lifetime / rotation policy. Maps to backend `KeyType` discriminator
/// strings (`short_lived`, `permanent`, `expiring`).
#[derive(Debug, Clone)]
pub enum KeyType {
    ShortLived,
    Permanent,
    Expiring(ExpiryInput),
}

/// When an `Expiring` key should expire. Wire format:
/// `{"absolute": "<rfc3339>"}` or `{"in_days": 30}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryInput {
    Absolute(DateTime<Utc>),
    InDays(i64),
}

/// Body of `POST /api/v1/apps/{app_uuid}/api-keys`.
#[derive(Debug, Clone)]
pub struct CreateApiKeyRequest {
    pub name: String,
    /// `"live"` or `"test"` — selects the key prefix.
    pub env: String,
    pub key_type: KeyType,
}

impl Serialize for CreateApiKeyRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("env", &self.env)?;
        match &self.key_type {
            KeyType::ShortLived => {
                map.serialize_entry("key_type", "short_lived")?;
            }
            KeyType::Permanent => {
                map.serialize_entry("key_type", "permanent")?;
            }
            KeyType::Expiring(expiry) => {
                map.serialize_entry("key_type", "expiring")?;
                map.serialize_entry("expiry", expiry)?;
            }
        }
        map.end()
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
    /// `"api_key."`, `"oauth_config."`, `"api_key.revoked"`.
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
