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
