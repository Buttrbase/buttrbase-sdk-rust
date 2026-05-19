use serde::{Deserialize, Serialize};

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
