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
    pub user_id: i32,
    pub subscription_id: Option<i32>,
    pub provider: String,
    pub provider_invoice_id: String,
    pub amount: i32,
    pub status: String,
    pub invoice_pdf_url: Option<String>,
    pub created_at: String,
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
