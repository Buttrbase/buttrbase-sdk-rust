use reqwest::{Client, Method, Response};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::models::{
    AdminPortalToken, ApiKeySummary, AuditEvent, AuditLogQuery, AuditRow, AuthEvent,
    ButtrBaseErrorResponse, Certificate, CertificateAuthority, CheckoutResponse, Coupon,
    CreateApiKeyRequest, CreateCredentialsRequest, CreateDeviceAccountRequest,
    CreateOAuthConfigRequest, CreatePaymentCheckoutRequest, CreateSsoConnectionRequest,
    CreatedKeyResponse, Credentials, CredentialsDetails, DataEnvelope, Domain,
    EntitlementCheckRequest, EntitlementCheckResponse, ExchangeResponse, GiftCardValidation,
    Invoice, JitGrant, LoginResponse, MfaEnrollResponse, MfaStatusResponse, OAuthConfigSummary,
    OAuthProvider, OrgFeature, PasskeyAuthChallenge, PasskeyAuthComplete, PasskeyListItem,
    PasskeyRegistrationChallenge, PasskeyRegistrationComplete, PasskeyRegistrationResult,
    PaymentCheckoutSession, Profile, RecoveryCodesResponse, RegisterRequest, SecretEntry,
    SecretValue, SendInvoiceRequest, SendInvoiceResponse, SendSmsRequest, SessionInfo,
    SigningAuditEntry, SigningKey, SsoConnection, UpdateCredentialsRequest,
    UpdateOAuthConfigRequest, UserAccount, VerifyEmailIdentityRequest, WebhookDelivery,
    WebhookEndpoint,
};

#[derive(Error, Debug)]
pub enum ButtrBaseClientError {
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("API error: {message} (code: {code:?})")]
    Api {
        message: String,
        code: Option<String>,
    },
}

/// Whether the client is operating in the live or sandbox environment.
/// Auto-detected from the `client_id` prefix when using `new_with_credentials`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Environment {
    Live,
    Sandbox,
}

impl Environment {
    fn from_client_id(client_id: &str) -> Self {
        if client_id.starts_with("bb_test_") {
            Self::Sandbox
        } else {
            Self::Live
        }
    }

    fn default_base_url(&self) -> &'static str {
        match self {
            Self::Live => "https://api.buttrbase.com",
            Self::Sandbox => "https://api.buttrbase.com",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ButtrBaseClient {
    base_url: String,
    client: Client,
    token: Option<String>,
    /// App credentials for HTTP Basic auth (app-level calls).
    credentials: Option<(String, String)>,
    pub environment: Option<Environment>,
}

impl ButtrBaseClient {
    /// Create a client with a known base URL. Call `set_token` before making requests.
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: Client::new(),
            token: None,
            credentials: None,
            environment: None,
        }
    }

    /// Create a credential-based client. Environment is auto-detected from the
    /// `client_id` prefix (`bb_live_` → Live, `bb_test_` → Sandbox).
    /// Use this for app-level API calls that authenticate with HTTP Basic auth.
    pub fn new_with_credentials(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        let id = client_id.into();
        let env = Environment::from_client_id(&id);
        let base_url = env.default_base_url().to_string();
        Self {
            base_url,
            client: Client::new(),
            token: None,
            credentials: Some((id, client_secret.into())),
            environment: Some(env),
        }
    }

    /// Create a credential-based client with a custom base URL (for self-hosted deployments).
    pub fn with_base_url(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        let id = client_id.into();
        let env = Environment::from_client_id(&id);
        Self {
            base_url: base_url.into(),
            client: Client::new(),
            token: None,
            credentials: Some((id, client_secret.into())),
            environment: Some(env),
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<&impl serde::Serialize>,
    ) -> Result<T, ButtrBaseClientError> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut request_builder = self.client.request(method, &url);

        if let Some(token) = &self.token {
            request_builder = request_builder.bearer_auth(token);
        } else if let Some((id, secret)) = &self.credentials {
            request_builder = request_builder.basic_auth(id, Some(secret));
        }

        if let Some(body) = body {
            request_builder = request_builder.json(body);
        }

        let response = request_builder.send().await?;
        self.handle_response(response).await
    }

    /// Make a request using an explicit bearer token regardless of stored credentials.
    /// Use this for user-level calls when you have the user's token separately.
    pub async fn request_with_bearer<T: DeserializeOwned>(
        &self,
        method: Method,
        endpoint: &str,
        bearer: &str,
        body: Option<&impl serde::Serialize>,
    ) -> Result<T, ButtrBaseClientError> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut request_builder = self.client.request(method, &url).bearer_auth(bearer);

        if let Some(body) = body {
            request_builder = request_builder.json(body);
        }

        let response = request_builder.send().await?;
        self.handle_response(response).await
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: Response,
    ) -> Result<T, ButtrBaseClientError> {
        if response.status().is_success() {
            Ok(response.json::<T>().await?)
        } else {
            let error_response: ButtrBaseErrorResponse = response.json().await?;
            Err(ButtrBaseClientError::Api {
                message: error_response.error.message,
                code: error_response.error.code,
            })
        }
    }

    // Authentication
    pub async fn get_status(&self) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        self.request(Method::GET, "/api/auth/status", None::<&()>)
            .await
    }

    pub async fn send_otp(
        &self,
        email: &str,
        app_uuid: Uuid,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let body = serde_json::json!({
            "email": email,
            "app_uuid": app_uuid.to_string(),
        });
        self.request(Method::POST, "/api/auth/otp", Some(&body))
            .await
    }

    pub async fn verify_otp(
        &self,
        email: &str,
        otp: &str,
        app_uuid: Uuid,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let body = serde_json::json!({
            "email": email,
            "otp": otp,
            "app_uuid": app_uuid.to_string(),
        });
        self.request(Method::POST, "/api/auth/otp/verify", Some(&body))
            .await
    }

    pub async fn send_phone_otp(&self, phone: &str, app: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("phone", phone);
        body.insert("app", app);
        self.request(Method::POST, "/api/auth/phone/otp", Some(&body))
            .await
    }

    pub async fn verify_phone_otp(&self, phone: &str, otp: &str, app: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("phone", phone);
        body.insert("otp", otp);
        body.insert("app", app);
        self.request(Method::POST, "/api/auth/phone/otp/verify", Some(&body))
            .await
    }

    pub async fn verify_email(&self, email: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("email", email);
        self.request(Method::POST, "/api/auth/verify-email", Some(&body))
            .await
    }

    pub async fn activate_account(&self, token: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("token", token);
        self.request(Method::POST, "/api/auth/activate", Some(&body))
            .await
    }

    pub async fn send_magic_link(&self, email: &str, application: &str, org_name: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("email", email);
        body.insert("application", application);
        body.insert("org_name", org_name);
        self.request(Method::POST, "/api/auth/magic-link", Some(&body))
            .await
    }

    pub async fn reset_password(&self, token: &str, password: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("token", token);
        body.insert("password", password);
        self.request(Method::POST, "/api/auth/reset-password", Some(&body))
            .await
    }

    pub async fn change_password(&self, password: &str, new_password: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("password", password);
        body.insert("new_password", new_password);
        self.request(Method::PUT, "/api/auth/change-password", Some(&body))
            .await
    }

    pub async fn login(
        &mut self,
        email: &str,
        password: &str,
        org_name: &str,
    ) -> Result<LoginResponse, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("email", email);
        body.insert("password", password);
        body.insert("org_name", org_name);

        let response: LoginResponse = self
            .request(Method::POST, "/api/auth/login", Some(&body))
            .await?;

        if let Some(token) = &response.access_token {
            self.token = Some(token.clone());
        }

        Ok(response)
    }

    // Profile
    pub async fn get_profile(&self) -> Result<Profile, ButtrBaseClientError> {
        self.request(Method::GET, "/api/profile", None::<&()>)
            .await
    }

    pub async fn update_profile(
        &self,
        data: &HashMap<&str, &str>,
    ) -> Result<Profile, ButtrBaseClientError> {
        self.request(Method::PUT, "/api/profile", Some(data)).await
    }

    // Users
    pub async fn get_users(
        &self,
        filters: Option<&HashMap<&str, &str>>,
    ) -> Result<Vec<crate::models::User>, ButtrBaseClientError> {
        let mut endpoint = "/api/users".to_string();
        if let Some(filters) = filters {
            endpoint.push('?');
            let mut first = true;
            for (k, v) in filters.iter() {
                if !first {
                    endpoint.push('&');
                }
                endpoint.push_str(&format!("{}={}", k, v));
                first = false;
            }
        }
        self.request(Method::GET, &endpoint, None::<&()>)
            .await
    }

    pub async fn get_user_level(
        &self,
        user_uuid: &str,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/users/{}/level", user_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn set_user_level(
        &self,
        user_uuid: &str,
        user_type: &str,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("type", user_type);
        self.request(
            Method::POST,
            &format!("/api/users/{}/level", user_uuid),
            Some(&body),
        )
        .await
    }

    pub async fn get_user_profile_picture(
        &self,
        user_uuid: &str,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/users/{}/picture", user_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn upload_user_profile_picture(
        &self,
        user_uuid: &str,
        picture: Vec<u8>,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let part = reqwest::multipart::Part::bytes(picture);
        let form = reqwest::multipart::Form::new().part("picture", part);
        let url = format!("{}{}", self.base_url, &format!("/api/users/{}/picture", user_uuid));
        let mut request_builder = self.client.post(&url).multipart(form);

        if let Some(token) = &self.token {
            request_builder = request_builder.bearer_auth(token);
        }

        let response = request_builder.send().await?;
        self.handle_response(response).await
    }

    pub async fn update_user_status(
        &self,
        user_uuid: &str,
        active: bool,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("active", active);
        self.request(
            Method::PUT,
            &format!("/api/users/{}/status", user_uuid),
            Some(&body),
        )
        .await
    }

    pub async fn update_user_role(
        &self,
        user_uuid: &str,
        role: &str,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("role", role);
        self.request(
            Method::PUT,
            &format!("/api/users/{}/role", user_uuid),
            Some(&body),
        )
        .await
    }


    // Billing
    pub async fn checkout(
        &self,
        price_id: &str,
        coupon_code: Option<&str>,
        add_ons: Option<Vec<&str>>,
    ) -> Result<CheckoutResponse, ButtrBaseClientError> {
        let mut body: HashMap<&str, Value> = HashMap::new();
        body.insert("priceId", price_id.into());
        if let Some(code) = coupon_code {
            body.insert("couponCode", code.into());
        }
        if let Some(ons) = add_ons {
            body.insert("addOns", ons.into());
        }

        self.request(Method::POST, "/api/billing/checkout", Some(&body))
            .await
    }

    pub async fn get_billing_history(&self) -> Result<Vec<Invoice>, ButtrBaseClientError> {
        self.request(Method::GET, "/api/billing/history", None::<&()>)
            .await
    }

    pub async fn get_provider_config(
        &self,
        provider: &str,
    ) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/billing/config/{}", provider),
            None::<&()>,
        )
        .await
    }

    pub async fn add_add_on(&self, add_on: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("addOn", add_on);
        self.request(
            Method::POST,
            "/api/billing/subscriptions/add-on",
            Some(&body),
        )
        .await
    }

    pub async fn list_invoices(&self) -> Result<Vec<Invoice>, ButtrBaseClientError> {
        self.request(Method::GET, "/api/billing/invoices", None::<&()>)
            .await
    }

    // RBAC
    // App Administrator methods
    pub async fn get_product_permissions(
        &self,
        product_id: &str,
    ) -> Result<Vec<crate::models::Permission>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/v2/products/{}/permissions", product_id),
            None::<&()>,
        )
        .await
    }

    pub async fn create_product_role(
        &self,
        product_id: &str,
        role_data: &crate::models::CreateRoleRequest,
    ) -> Result<crate::models::Role, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/v2/products/{}/roles", product_id),
            Some(role_data),
        )
        .await
    }

    // Org Administrator methods
    pub async fn get_assignable_roles(
        &self,
        org_uuid: &str,
        product_id: &str,
    ) -> Result<Vec<crate::models::Role>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/v2/organizations/{}/products/{}/roles", org_uuid, product_id),
            None::<&()>,
        )
        .await
    }

    pub async fn assign_role_to_user(
        &self,
        org_uuid: &str,
        user_uuid: &str,
        role_id: i32,
    ) -> Result<(), ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("roleId", role_id);
        self.request(
            Method::PUT,
            &format!("/api/v2/organizations/{}/users/{}/role", org_uuid, user_uuid),
            Some(&body),
        )
        .await
    }

    // Teams
    pub async fn get_org_teams(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<crate::models::Team>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/v2/organizations/{}/teams", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn get_user_teams(
        &self,
        org_uuid: &str,
        user_uuid: &str,
    ) -> Result<Vec<crate::models::Team>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!(
                "/api/v2/organizations/{}/users/{}/teams",
                org_uuid, user_uuid
            ),
            None::<&()>,
        )
        .await
    }

    // Credentials
    pub async fn create_credentials(
        &self,
        data: &CreateCredentialsRequest<'_>,
    ) -> Result<Credentials, ButtrBaseClientError> {
        self.request(Method::POST, "/api/credentials", Some(data))
            .await
    }

    pub async fn list_credentials(&self) -> Result<Vec<Credentials>, ButtrBaseClientError> {
        self.request(Method::GET, "/api/credentials", None::<&()>)
            .await
    }

    pub async fn get_credentials_by_id(
        &self,
        id: i32,
    ) -> Result<Credentials, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/credentials/{}", id),
            None::<&()>,
        )
        .await
    }

    pub async fn get_credentials_details(
        &self,
        id: i32,
    ) -> Result<CredentialsDetails, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/credentials/{}/details", id),
            None::<&()>,
        )
        .await
    }

    pub async fn update_credentials(
        &self,
        id: i32,
        data: &UpdateCredentialsRequest<'_>,
    ) -> Result<Credentials, ButtrBaseClientError> {
        self.request(
            Method::PATCH,
            &format!("/api/credentials/{}", id),
            Some(data),
        )
        .await
    }

    pub async fn replace_credentials(
        &self,
        id: i32,
        data: &CreateCredentialsRequest<'_>,
    ) -> Result<Credentials, ButtrBaseClientError> {
        self.request(
            Method::PUT,
            &format!("/api/credentials/{}", id),
            Some(data),
        )
        .await
    }

    pub async fn delete_credentials(&self, id: i32) -> Result<(), ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/credentials/{}", id),
            None::<&()>,
        )
        .await
    }




    // Search & Discovery
    pub async fn search_index(&self, payload: &serde_json::Value) -> Result<serde_json::Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/v2/search/index", Some(payload)).await
    }

    pub async fn search_query(&self, q: &str, filters: Option<serde_json::Value>) -> Result<serde_json::Value, ButtrBaseClientError> {
        let mut payload = serde_json::json!({ "q": q });
        if let Some(f) = filters { payload["filters"] = f; }
        self.request(Method::POST, "/api/v2/search/query", Some(&payload)).await
    }


    pub async fn search_chat(&self, q: &str, options: Option<serde_json::Value>) -> Result<serde_json::Value, ButtrBaseClientError> {
        let mut payload = serde_json::json!({ "q": q });
        if let Some(o) = options {
            if let Some(obj) = o.as_object() {
                for (k, v) in obj {
                    payload[k] = v.clone();
                }
            }
        }
        self.request(Method::POST, "/api/v2/search/chat", Some(&payload)).await
    }

    // Lifecycle Jobs
    pub async fn enqueue_job(&self, name: &str, payload: &serde_json::Value) -> Result<serde_json::Value, ButtrBaseClientError> {
        let data = serde_json::json!({ "name": name, "payload": payload });
        self.request(Method::POST, "/api/v2/jobs/enqueue", Some(&data)).await
    }

    // Notifications
    pub async fn send_notification(&self, payload: &serde_json::Value) -> Result<serde_json::Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/v2/notifications/send", Some(payload)).await
    }

    pub async fn list_notifications(&self) -> Result<serde_json::Value, ButtrBaseClientError> {
        self.request(Method::GET, "/api/v2/notifications", None::<&()>).await
    }

    // ── Registration ─────────────────────────────────────────────────────────

    pub async fn register(
        &self,
        data: &RegisterRequest<'_>,
    ) -> Result<LoginResponse, ButtrBaseClientError> {
        self.request(Method::POST, "/api/auth/register", Some(data))
            .await
    }

    pub async fn get_login_options(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/auth/organizations/{}/login-options", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn get_org_by_domain(
        &self,
        domain: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/auth/orgs-by-domain/{}", domain),
            None::<&()>,
        )
        .await
    }

    // ── OIDC / SAML SSO ──────────────────────────────────────────────────────

    pub async fn oidc_authorize_url(
        &self,
        connection_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/auth/oidc/{}/authorize", connection_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn oidc_callback(
        &self,
        params: &HashMap<String, String>,
    ) -> Result<Value, ButtrBaseClientError> {
        let qs: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.request(
            Method::GET,
            &format!("/api/auth/oidc/callback?{}", qs),
            None::<&()>,
        )
        .await
    }

    pub async fn saml_authorize_url(
        &self,
        connection_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/auth/saml/{}/authorize", connection_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn saml_callback(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/auth/saml/callback", Some(payload))
            .await
    }

    // ── Magic Link v2 ────────────────────────────────────────────────────────

    pub async fn magic_link_send(
        &self,
        email: &str,
        redirect_to: Option<&str>,
        app_uuid: Uuid,
    ) -> Result<Value, ButtrBaseClientError> {
        let mut body = serde_json::json!({
            "email": email,
            "app_uuid": app_uuid.to_string(),
        });
        if let Some(url) = redirect_to {
            body["redirect_to"] = Value::String(url.to_string());
        }
        self.request(Method::POST, "/api/auth/magic-link/send", Some(&body))
            .await
    }

    pub async fn magic_link_verify(
        &self,
        token: &str,
    ) -> Result<LoginResponse, ButtrBaseClientError> {
        let body = serde_json::json!({ "token": token });
        self.request(Method::POST, "/api/auth/magic-link/verify", Some(&body))
            .await
    }

    // ── OTP v2 (passwordless phone) ──────────────────────────────────────────

    pub async fn otp_send(&self, phone: &str) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "phone": phone });
        self.request(Method::POST, "/api/auth/otp/send", Some(&body))
            .await
    }

    pub async fn otp_verify_code(
        &self,
        phone: &str,
        code: &str,
    ) -> Result<LoginResponse, ButtrBaseClientError> {
        let body = serde_json::json!({ "phone": phone, "code": code });
        self.request(Method::POST, "/api/auth/otp/verify", Some(&body))
            .await
    }

    // ── MFA / TOTP ───────────────────────────────────────────────────────────

    pub async fn mfa_status(&self) -> Result<MfaStatusResponse, ButtrBaseClientError> {
        self.request(Method::GET, "/api/auth/mfa/status", None::<&()>)
            .await
    }

    pub async fn mfa_totp_enroll(&self) -> Result<MfaEnrollResponse, ButtrBaseClientError> {
        self.request(Method::POST, "/api/auth/mfa/totp/enroll", None::<&()>)
            .await
    }

    pub async fn mfa_totp_activate(
        &self,
        code: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "code": code });
        self.request(Method::POST, "/api/auth/mfa/totp/activate", Some(&body))
            .await
    }

    pub async fn mfa_totp_verify(
        &self,
        code: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "code": code });
        self.request(Method::POST, "/api/auth/mfa/totp/verify", Some(&body))
            .await
    }

    pub async fn mfa_totp_challenge(&self) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/auth/mfa/totp/challenge", None::<&()>)
            .await
    }

    pub async fn mfa_totp_disable(&self) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::DELETE, "/api/auth/mfa/totp", None::<&()>)
            .await
    }

    pub async fn mfa_generate_recovery_codes(
        &self,
    ) -> Result<RecoveryCodesResponse, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/auth/mfa/recovery-codes",
            None::<&()>,
        )
        .await
    }

    pub async fn mfa_redeem_recovery_code(
        &self,
        code: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "code": code });
        self.request(
            Method::POST,
            "/api/auth/mfa/recovery-codes/redeem",
            Some(&body),
        )
        .await
    }

    pub async fn auth_step_up(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/auth/step-up", Some(payload))
            .await
    }

    // ── Organization Security ────────────────────────────────────────────────

    pub async fn get_security_settings(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/security-settings", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn update_security_settings(
        &self,
        org_uuid: &str,
        settings: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::PUT,
            &format!("/api/organizations/{}/security-settings", org_uuid),
            Some(settings),
        )
        .await
    }

    pub async fn list_sso_connections(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<SsoConnection>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/sso-connections", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn create_sso_connection(
        &self,
        org_uuid: &str,
        data: &CreateSsoConnectionRequest<'_>,
    ) -> Result<SsoConnection, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/organizations/{}/sso-connections", org_uuid),
            Some(data),
        )
        .await
    }

    pub async fn update_sso_connection(
        &self,
        org_uuid: &str,
        connection_uuid: &str,
        data: &Value,
    ) -> Result<SsoConnection, ButtrBaseClientError> {
        self.request(
            Method::PUT,
            &format!(
                "/api/organizations/{}/sso-connections/{}",
                org_uuid, connection_uuid
            ),
            Some(data),
        )
        .await
    }

    pub async fn delete_sso_connection(
        &self,
        org_uuid: &str,
        connection_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!(
                "/api/organizations/{}/sso-connections/{}",
                org_uuid, connection_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn list_audit_events(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<AuditEvent>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/audit-events", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn export_audit_events(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/audit-events/export", org_uuid),
            None::<&()>,
        )
        .await
    }

    // ── Branding ─────────────────────────────────────────────────────────────

    pub async fn get_branding(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/branding", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn update_branding(
        &self,
        org_uuid: &str,
        branding: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::PUT,
            &format!("/api/organizations/{}/branding", org_uuid),
            Some(branding),
        )
        .await
    }

    pub async fn upload_org_logo(
        &self,
        org_uuid: &str,
        logo: Vec<u8>,
    ) -> Result<Value, ButtrBaseClientError> {
        let part = reqwest::multipart::Part::bytes(logo);
        let form = reqwest::multipart::Form::new().part("logo", part);
        let url = format!(
            "{}/api/organizations/{}/branding/logo",
            self.base_url, org_uuid
        );
        let mut req = self.client.post(&url).multipart(form);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let response = req.send().await?;
        self.handle_response(response).await
    }

    // ── Sessions ─────────────────────────────────────────────────────────────

    pub async fn org_session_inventory(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<SessionInfo>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/session-inventory", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn org_revoke_all_sessions(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/organizations/{}/revoke-all-sessions", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn list_device_accounts(
        &self,
        device_uuid: &str,
    ) -> Result<Vec<UserAccount>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/devices/{}/accounts", device_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn add_device_account(
        &self,
        device_uuid: &str,
        data: &CreateDeviceAccountRequest<'_>,
    ) -> Result<UserAccount, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/devices/{}/accounts", device_uuid),
            Some(data),
        )
        .await
    }

    pub async fn delete_device_accounts(
        &self,
        device_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/devices/{}/accounts", device_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn add_device_accounts_bulk(
        &self,
        device_uuid: &str,
        accounts: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/devices/{}/accounts/bulk", device_uuid),
            Some(accounts),
        )
        .await
    }

    pub async fn create_device_accounts_bulk(
        &self,
        accounts: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/devices/accounts/bulk",
            Some(accounts),
        )
        .await
    }

    pub async fn delete_device_account(
        &self,
        device_uuid: &str,
        account_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/devices/{}/accounts/{}", device_uuid, account_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn switch_device_active_account(
        &self,
        device_uuid: &str,
        account_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "account_uuid": account_uuid });
        self.request(
            Method::POST,
            &format!("/api/devices/{}/active-account", device_uuid),
            Some(&body),
        )
        .await
    }

    pub async fn device_session_inventory(
        &self,
        device_uuid: &str,
    ) -> Result<Vec<SessionInfo>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/devices/{}/session-inventory", device_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn revoke_all_device_sessions(
        &self,
        device_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/devices/{}/revoke-all", device_uuid),
            None::<&()>,
        )
        .await
    }

    // ── API Keys v2 ──────────────────────────────────────────────────────────

    pub async fn list_api_keys_v2(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<crate::models::ApiKey>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/v2/organizations/{}/api-keys", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn create_api_key_v2(
        &self,
        org_uuid: &str,
        name: &str,
    ) -> Result<crate::models::ApiKey, ButtrBaseClientError> {
        let body = serde_json::json!({ "name": name });
        self.request(
            Method::POST,
            &format!("/api/v2/organizations/{}/api-keys", org_uuid),
            Some(&body),
        )
        .await
    }

    pub async fn delete_api_key_v2(
        &self,
        org_uuid: &str,
        key_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/v2/organizations/{}/api-keys/{}", org_uuid, key_uuid),
            None::<&()>,
        )
        .await
    }

    // ── Service Identities ───────────────────────────────────────────────────

    pub async fn list_service_identities(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<Value>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/service-identities", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn create_service_identity(
        &self,
        org_uuid: &str,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/organizations/{}/service-identities", org_uuid),
            Some(payload),
        )
        .await
    }

    pub async fn delete_service_identity(
        &self,
        org_uuid: &str,
        key_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!(
                "/api/organizations/{}/service-identities/{}",
                org_uuid, key_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn create_service_identity_automation_token(
        &self,
        org_uuid: &str,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/organizations/{}/service-identities/automation-token",
                org_uuid
            ),
            Some(payload),
        )
        .await
    }

    // ── Entitlements ─────────────────────────────────────────────────────────

    pub async fn entitlements_check(
        &self,
        data: &EntitlementCheckRequest<'_>,
    ) -> Result<EntitlementCheckResponse, ButtrBaseClientError> {
        self.request(Method::POST, "/api/entitlements/check", Some(data))
            .await
    }

    pub async fn entitlements_check_batch(
        &self,
        checks: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/entitlements/check/batch", Some(checks))
            .await
    }

    pub async fn entitlements_effective(&self) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::GET, "/api/entitlements/effective", None::<&()>)
            .await
    }

    pub async fn admin_entitlements_explain(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/admin/entitlements/explain",
            Some(payload),
        )
        .await
    }

    // ── Pricing ──────────────────────────────────────────────────────────────

    pub async fn pricing_preview(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/pricing/preview", Some(payload))
            .await
    }

    pub async fn pricing_quote(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/pricing/quote", Some(payload))
            .await
    }

    pub async fn pricing_checkout_session(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/pricing/checkout-session",
            Some(payload),
        )
        .await
    }

    pub async fn admin_pricing_explain(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/admin/pricing/explain",
            Some(payload),
        )
        .await
    }

    pub async fn catalog_pricing_preview(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/catalog/pricing/preview",
            Some(payload),
        )
        .await
    }

    // ── Coupons (Admin) ──────────────────────────────────────────────────────

    pub async fn admin_list_product_coupons(
        &self,
        product_id: &str,
    ) -> Result<Vec<Coupon>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/products/{}/coupons", product_id),
            None::<&()>,
        )
        .await
    }

    pub async fn admin_create_product_coupon(
        &self,
        product_id: &str,
        coupon: &Coupon,
    ) -> Result<Coupon, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/admin/products/{}/coupons", product_id),
            Some(coupon),
        )
        .await
    }

    pub async fn admin_update_product_coupon(
        &self,
        product_id: &str,
        coupon_id: &str,
        coupon: &Coupon,
    ) -> Result<Coupon, ButtrBaseClientError> {
        self.request(
            Method::PUT,
            &format!(
                "/api/admin/products/{}/coupons/{}",
                product_id, coupon_id
            ),
            Some(coupon),
        )
        .await
    }

    pub async fn admin_delete_product_coupon(
        &self,
        product_id: &str,
        coupon_id: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!(
                "/api/admin/products/{}/coupons/{}",
                product_id, coupon_id
            ),
            None::<&()>,
        )
        .await
    }

    // ── Coupons / Gift Cards (Public) ────────────────────────────────────────

    pub async fn validate_coupon(
        &self,
        code: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "code": code });
        self.request(Method::POST, "/api/coupons/validate", Some(&body))
            .await
    }

    pub async fn validate_gift_card(
        &self,
        code: &str,
    ) -> Result<GiftCardValidation, ButtrBaseClientError> {
        let body = serde_json::json!({ "code": code });
        self.request(Method::POST, "/api/gift-cards/validate", Some(&body))
            .await
    }

    pub async fn redeem_gift_card(
        &self,
        code: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "code": code });
        self.request(Method::POST, "/api/gift-cards/redeem", Some(&body))
            .await
    }

    // ── Labels ───────────────────────────────────────────────────────────────

    pub async fn set_coupon_labels(
        &self,
        coupon_id: &str,
        labels: &[&str],
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "labels": labels });
        self.request(
            Method::PUT,
            &format!("/api/admin/coupons/{}/labels", coupon_id),
            Some(&body),
        )
        .await
    }

    pub async fn add_coupon_label(
        &self,
        coupon_id: &str,
        label: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "label": label });
        self.request(
            Method::POST,
            &format!("/api/admin/coupons/{}/labels", coupon_id),
            Some(&body),
        )
        .await
    }

    pub async fn remove_coupon_label(
        &self,
        coupon_id: &str,
        label: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/admin/coupons/{}/labels/{}", coupon_id, label),
            None::<&()>,
        )
        .await
    }

    pub async fn set_product_tags(
        &self,
        product_id: &str,
        tags: &[&str],
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "tags": tags });
        self.request(
            Method::PUT,
            &format!("/api/admin/products/{}/tags", product_id),
            Some(&body),
        )
        .await
    }

    pub async fn add_product_tag(
        &self,
        product_id: &str,
        tag: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "tag": tag });
        self.request(
            Method::POST,
            &format!("/api/admin/products/{}/tags", product_id),
            Some(&body),
        )
        .await
    }

    pub async fn remove_product_tag(
        &self,
        product_id: &str,
        tag: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/admin/products/{}/tags/{}", product_id, tag),
            None::<&()>,
        )
        .await
    }

    // ── Analytics ────────────────────────────────────────────────────────────

    pub async fn ingest_analytics_event(
        &self,
        event: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/analytics/events", Some(event))
            .await
    }

    pub async fn analytics_app_overview(
        &self,
        app_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/analytics/apps/{}/overview", app_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn analytics_org_overview(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/analytics/organizations/{}/overview", org_uuid),
            None::<&()>,
        )
        .await
    }

    // ── Teams (expanded) ─────────────────────────────────────────────────────

    pub async fn create_team(
        &self,
        payload: &Value,
    ) -> Result<crate::models::Team, ButtrBaseClientError> {
        self.request(Method::POST, "/api/teams", Some(payload))
            .await
    }

    pub async fn list_org_teams(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<crate::models::Team>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/teams", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn list_inactive_teams(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<crate::models::Team>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/teams/org/{}/inactive", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn reactivate_team(
        &self,
        team_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/teams/lifecycle/{}/reactivate", team_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn archive_team(
        &self,
        team_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/teams/lifecycle/{}", team_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn list_team_members(
        &self,
        team_uuid: &str,
    ) -> Result<Vec<Value>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/teams/{}/members", team_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn add_team_member(
        &self,
        team_uuid: &str,
        user_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "user_uuid": user_uuid });
        self.request(
            Method::POST,
            &format!("/api/teams/{}/members", team_uuid),
            Some(&body),
        )
        .await
    }

    pub async fn remove_team_member(
        &self,
        team_uuid: &str,
        user_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/teams/{}/members/{}", team_uuid, user_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn list_team_observers(
        &self,
        team_uuid: &str,
    ) -> Result<Vec<Value>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/teams/{}/observers", team_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn add_team_observer(
        &self,
        team_uuid: &str,
        user_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "user_uuid": user_uuid });
        self.request(
            Method::POST,
            &format!("/api/teams/{}/observers", team_uuid),
            Some(&body),
        )
        .await
    }

    pub async fn remove_team_observer(
        &self,
        team_uuid: &str,
        user_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/teams/{}/observers/{}", team_uuid, user_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn get_user_teams_list(
        &self,
        user_uuid: &str,
    ) -> Result<Vec<crate::models::Team>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/users/{}/teams", user_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn get_user_observed_teams(
        &self,
        user_uuid: &str,
    ) -> Result<Vec<crate::models::Team>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/users/{}/observed-teams", user_uuid),
            None::<&()>,
        )
        .await
    }

    // ── Org Features ─────────────────────────────────────────────────────────

    pub async fn list_org_features(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<OrgFeature>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/organizations/{}/features", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn set_org_feature(
        &self,
        org_uuid: &str,
        feature: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/organizations/{}/features", org_uuid),
            Some(feature),
        )
        .await
    }

    pub async fn remove_org_feature(
        &self,
        org_uuid: &str,
        feature_id: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/organizations/{}/features/{}", org_uuid, feature_id),
            None::<&()>,
        )
        .await
    }

    // ── Roles ────────────────────────────────────────────────────────────────

    pub async fn list_roles(&self) -> Result<Vec<crate::models::Role>, ButtrBaseClientError> {
        self.request(Method::GET, "/api/roles", None::<&()>).await
    }

    pub async fn list_all_permissions(
        &self,
    ) -> Result<Vec<crate::models::Permission>, ButtrBaseClientError> {
        self.request(Method::GET, "/api/roles/permissions", None::<&()>)
            .await
    }

    pub async fn get_role_permissions(
        &self,
        role_id: i32,
    ) -> Result<Vec<crate::models::Permission>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/roles/{}/permissions", role_id),
            None::<&()>,
        )
        .await
    }

    pub async fn update_role_permissions(
        &self,
        role_id: i32,
        permissions: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::PUT,
            &format!("/api/roles/{}/permissions", role_id),
            Some(permissions),
        )
        .await
    }

    // ── Environments ─────────────────────────────────────────────────────────

    pub async fn list_environments(&self) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::GET, "/api/environments", None::<&()>)
            .await
    }

    // ── Plaid ────────────────────────────────────────────────────────────────

    pub async fn plaid_create_link_token(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/plaid/create-link-token",
            Some(payload),
        )
        .await
    }

    pub async fn plaid_exchange_public_token(
        &self,
        public_token: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "public_token": public_token });
        self.request(
            Method::POST,
            "/api/plaid/exchange-public-token",
            Some(&body),
        )
        .await
    }

    pub async fn plaid_accounts(&self) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::GET, "/api/plaid/accounts", None::<&()>)
            .await
    }

    // ── Usage ────────────────────────────────────────────────────────────────

    pub async fn usage_report(
        &self,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/usage/report", Some(payload))
            .await
    }

    // ── Help ─────────────────────────────────────────────────────────────────

    pub async fn help_root(&self) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::GET, "/api/help", None::<&()>).await
    }

    pub async fn help_search(
        &self,
        query: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/help/search?q={}", urlencoding::encode(query)),
            None::<&()>,
        )
        .await
    }

    pub async fn help_category(
        &self,
        slug: &str,
    ) -> Result<crate::models::HelpCategory, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/help/categories/{}", slug),
            None::<&()>,
        )
        .await
    }

    pub async fn help_article(
        &self,
        slug: &str,
    ) -> Result<crate::models::HelpArticle, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/help/articles/{}", slug),
            None::<&()>,
        )
        .await
    }

    // ── Wallet ───────────────────────────────────────────────────────────────

    pub async fn wallet(&self) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::GET, "/api/wallet", None::<&()>).await
    }

    // ── Admin: Signing Keys ──────────────────────────────────────────────────

    pub async fn list_signing_keys(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<SigningKey>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/signing-keys", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn rotate_signing_keys(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/signing-keys/rotate",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn list_signing_audit(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<SigningAuditEntry>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/signing-audit", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn sign_payload(
        &self,
        org_uuid: &str,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/orgs/{}/sign", org_uuid),
            Some(payload),
        )
        .await
    }

    pub async fn sign_document(
        &self,
        org_uuid: &str,
        document: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/orgs/{}/sign-document", org_uuid),
            Some(document),
        )
        .await
    }

    // ── Admin: mTLS Certificate Authority ────────────────────────────────────

    pub async fn get_ca(
        &self,
        org_uuid: &str,
    ) -> Result<CertificateAuthority, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!(
                "/api/admin/organizations/{}/certificate-authority",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn init_ca(
        &self,
        org_uuid: &str,
        config: &Value,
    ) -> Result<CertificateAuthority, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/certificate-authority/init",
                org_uuid
            ),
            Some(config),
        )
        .await
    }

    pub async fn list_certificates(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<Certificate>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/certificates", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn issue_certificate(
        &self,
        org_uuid: &str,
        csr: &Value,
    ) -> Result<Certificate, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/admin/organizations/{}/certificates", org_uuid),
            Some(csr),
        )
        .await
    }

    pub async fn revoke_certificate(
        &self,
        org_uuid: &str,
        serial: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/certificates/{}/revoke",
                org_uuid, serial
            ),
            None::<&()>,
        )
        .await
    }

    // ── Admin: Zero Trust ────────────────────────────────────────────────────

    pub async fn revoke_jti(
        &self,
        jti: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "jti": jti });
        self.request(
            Method::POST,
            "/api/admin/sessions/revoke",
            Some(&body),
        )
        .await
    }

    pub async fn org_metrics(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/metrics", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn re_encrypt_secrets(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/secrets/re-encrypt",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn re_encrypt_signing_keys(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/signing-keys/re-encrypt",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn re_encrypt_mtls_ca(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/mtls-ca/re-encrypt",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn list_auth_events(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<AuthEvent>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/auth-events", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn purge_auth_events(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/auth-events/purge",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn kms_status(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/kms-status", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn saml_cert_rollover(
        &self,
        org_uuid: &str,
        connection_uuid: &str,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::PATCH,
            &format!(
                "/api/admin/organizations/{}/sso/{}/saml-cert",
                org_uuid, connection_uuid
            ),
            Some(payload),
        )
        .await
    }

    pub async fn update_payment_settings(
        &self,
        org_uuid: &str,
        settings: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::PATCH,
            &format!(
                "/api/admin/organizations/{}/payment-settings",
                org_uuid
            ),
            Some(settings),
        )
        .await
    }

    // ── Admin: JIT Elevation ─────────────────────────────────────────────────

    pub async fn jit_request_grant(
        &self,
        org_uuid: &str,
        payload: &Value,
    ) -> Result<JitGrant, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/elevation/request",
                org_uuid
            ),
            Some(payload),
        )
        .await
    }

    pub async fn jit_approve_grant(
        &self,
        org_uuid: &str,
        grant_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/elevation/{}/approve",
                org_uuid, grant_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn jit_list_grants(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<JitGrant>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/elevation", org_uuid),
            None::<&()>,
        )
        .await
    }

    // ── Admin: SPIFFE ────────────────────────────────────────────────────────

    pub async fn issue_svid(
        &self,
        org_uuid: &str,
        payload: &Value,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/admin/organizations/{}/spiffe/svid", org_uuid),
            Some(payload),
        )
        .await
    }

    // ── Admin: Secrets Vault ─────────────────────────────────────────────────

    pub async fn list_secrets(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<SecretEntry>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/secrets", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn put_secret(
        &self,
        org_uuid: &str,
        name: &str,
        value: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "value": value });
        self.request(
            Method::PUT,
            &format!("/api/admin/organizations/{}/secrets/{}", org_uuid, name),
            Some(&body),
        )
        .await
    }

    pub async fn delete_secret(
        &self,
        org_uuid: &str,
        name: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/admin/organizations/{}/secrets/{}", org_uuid, name),
            None::<&()>,
        )
        .await
    }

    pub async fn get_secret(
        &self,
        org_uuid: &str,
        name: &str,
    ) -> Result<SecretValue, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/orgs/{}/secrets/{}", org_uuid, name),
            None::<&()>,
        )
        .await
    }

    // ── Admin: Portal ────────────────────────────────────────────────────────

    pub async fn admin_portal_issue(
        &self,
        org_uuid: &str,
    ) -> Result<AdminPortalToken, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/admin-portal/issue",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn admin_portal_exchange(
        &self,
        token: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        let body = serde_json::json!({ "token": token });
        self.request(
            Method::POST,
            "/api/admin-portal/exchange",
            Some(&body),
        )
        .await
    }

    // ── Admin: Domains ───────────────────────────────────────────────────────

    pub async fn list_domains(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<Domain>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/admin/organizations/{}/domains", org_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn create_domain(
        &self,
        org_uuid: &str,
        domain: &str,
    ) -> Result<Domain, ButtrBaseClientError> {
        let body = serde_json::json!({ "domain": domain });
        self.request(
            Method::POST,
            &format!("/api/admin/organizations/{}/domains", org_uuid),
            Some(&body),
        )
        .await
    }

    pub async fn verify_domain(
        &self,
        org_uuid: &str,
        domain_id: i32,
    ) -> Result<Domain, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/domains/{}/verify",
                org_uuid, domain_id
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn delete_domain(
        &self,
        org_uuid: &str,
        domain_id: i32,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!(
                "/api/admin/organizations/{}/domains/{}",
                org_uuid, domain_id
            ),
            None::<&()>,
        )
        .await
    }

    // ── Admin: Webhooks ──────────────────────────────────────────────────────

    pub async fn list_webhook_endpoints(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<WebhookEndpoint>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!(
                "/api/admin/organizations/{}/webhook-endpoints",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn create_webhook_endpoint(
        &self,
        org_uuid: &str,
        url: &str,
        events: &[&str],
    ) -> Result<WebhookEndpoint, ButtrBaseClientError> {
        let body = serde_json::json!({ "url": url, "events": events });
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/webhook-endpoints",
                org_uuid
            ),
            Some(&body),
        )
        .await
    }

    pub async fn delete_webhook_endpoint(
        &self,
        org_uuid: &str,
        endpoint_id: i32,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!(
                "/api/admin/organizations/{}/webhook-endpoints/{}",
                org_uuid, endpoint_id
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn list_webhook_deliveries(
        &self,
        org_uuid: &str,
    ) -> Result<Vec<WebhookDelivery>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!(
                "/api/admin/organizations/{}/webhook-deliveries",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    // ── Admin: SCIM Tokens ───────────────────────────────────────────────────

    pub async fn issue_scim_token(
        &self,
        org_uuid: &str,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!(
                "/api/admin/organizations/{}/scim-tokens",
                org_uuid
            ),
            None::<&()>,
        )
        .await
    }

    // ── Payments ─────────────────────────────────────────────────────────────

    pub async fn create_payment_checkout(
        &self,
        data: &CreatePaymentCheckoutRequest<'_>,
    ) -> Result<PaymentCheckoutSession, ButtrBaseClientError> {
        self.request(Method::POST, "/api/payments/checkout", Some(data))
            .await
    }

    pub async fn send_invoice(
        &self,
        data: &SendInvoiceRequest<'_>,
    ) -> Result<SendInvoiceResponse, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/payments/invoices/send",
            Some(data),
        )
        .await
    }

    // ── SMS ──────────────────────────────────────────────────────────────────

    pub async fn send_sms(
        &self,
        data: &SendSmsRequest<'_>,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(Method::POST, "/api/sms/send_sms", Some(data))
            .await
    }

    // ── Email ────────────────────────────────────────────────────────────────

    pub async fn verify_email_identity(
        &self,
        data: &VerifyEmailIdentityRequest<'_>,
    ) -> Result<Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/email/verify-identity",
            Some(data),
        )
        .await
    }

    // Custom Variables
    pub async fn get_custom_variable(&self, key: &str) -> Result<serde_json::Value, ButtrBaseClientError> {
        self.request(Method::GET, &format!("/api/v2/custom-variables/{}", key), None::<&()>)
            .await
    }

    pub async fn set_custom_variable(
        &self,
        key: &str,
        value: &str,
        scope: Option<&str>,
    ) -> Result<serde_json::Value, ButtrBaseClientError> {
        let mut payload = serde_json::json!({
            "key": key,
            "value": value
        });
        if let Some(s) = scope {
            payload["scope"] = serde_json::json!(s);
        }
        self.request(Method::POST, "/api/v2/custom-variables", Some(&payload))
            .await
    }

    // Webhooks
    pub async fn register_webhook(
        &self,
        url: &str,
        events: Vec<&str>,
        org_uuid: Option<&str>,
    ) -> Result<serde_json::Value, ButtrBaseClientError> {
        let mut payload = serde_json::json!({
            "url": url,
            "events": events
        });
        if let Some(uuid) = org_uuid {
            payload["org_uuid"] = serde_json::json!(uuid);
        }

        self.request(Method::POST, "/api/v2/webhooks", Some(&payload))
            .await
    }

    // AI Gateway
    pub async fn ai_chat_completions(
        &self,
        org_uuid: &str,
        provider: &str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, ButtrBaseClientError> {
        let url = "https://gateway.buttrbase.com/v1/chat/completions";
        let mut req = self.client.post(url)
            .header("Content-Type", "application/json")
            .header("x-buttrbase-target-org", org_uuid)
            .header("x-buttrbase-provider", provider)
            .json(payload);

        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let response = req.send().await?;
        
        if response.status().is_success() {
            let res = response.json::<serde_json::Value>().await?;
            Ok(res)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(ButtrBaseClientError::Api {
                message: format!("HTTP {}: {}", status, body),
                code: Some(status.as_str().to_string()),
            })
        }
    }

    // ── Invite-based registration ─────────────────────────────────────────────

    /// Accept an invitation and create a user account.
    /// No authentication required — the `token` in the payload acts as the credential.
    pub async fn invite_accept(
        &self,
        data: &crate::models::InviteAcceptRequest<'_>,
    ) -> Result<crate::models::InviteAcceptResponse, ButtrBaseClientError> {
        self.request(Method::POST, "/api/auth/invite/accept", Some(data))
            .await
    }

    /// Check whether an organisation name is available (case-sensitive).
    pub async fn check_org_name(
        &self,
        name: &str,
    ) -> Result<crate::models::OrgCheckResponse, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/auth/orgs/check?name={}", urlencoding::encode(name)),
            None::<&()>,
        )
        .await
    }

    /// Look up the superuser flag for a given email address.
    /// Requires platform-admin authentication.
    pub async fn get_superuser_flag(
        &self,
        email: &str,
    ) -> Result<crate::models::SuperuserResponse, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/auth/superuser?email={}", urlencoding::encode(email)),
            None::<&()>,
        )
        .await
    }

    // ── Contact forms ─────────────────────────────────────────────────────────

    /// Submit an account / sales enquiry form.
    pub async fn post_contact(
        &self,
        data: &crate::models::ContactRequest<'_>,
    ) -> Result<crate::models::ContactSubmitResponse, ButtrBaseClientError> {
        self.request(Method::POST, "/api/contact", Some(data))
            .await
    }

    /// Submit a general contact-us form.
    pub async fn post_contact_us(
        &self,
        data: &crate::models::ContactUsRequest<'_>,
    ) -> Result<crate::models::ContactSubmitResponse, ButtrBaseClientError> {
        self.request(Method::POST, "/api/contact-us", Some(data))
            .await
    }

    // ── Geo / IP ──────────────────────────────────────────────────────────────

    /// Return the caller's IP address and basic geo context.
    /// Useful during registration for timezone / country pre-fill.
    pub async fn get_client_ip(&self) -> Result<crate::models::GeoResponse, ButtrBaseClientError> {
        self.request(Method::GET, "/api/geo/ip", None::<&()>)
            .await
    }

    // ── API key exchange (anonymous) ─────────────────────────────────────────

    /// First-time exchange: convert a raw API key (`wb_live_…` / `wb_test_…`)
    /// for an access + refresh token pair. Does NOT send an `Authorization`
    /// header — the API key itself is the credential.
    pub async fn exchange_api_key(
        &self,
        api_key: &str,
    ) -> Result<ExchangeResponse, ButtrBaseClientError> {
        self.exchange_inner(serde_json::json!({ "api_key": api_key }))
            .await
    }

    /// Refresh-rotation exchange: trade a refresh token from a previous
    /// `exchange_api_key` call for a new access + refresh pair (the old
    /// refresh is revoked).
    pub async fn exchange_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<ExchangeResponse, ButtrBaseClientError> {
        self.exchange_inner(serde_json::json!({ "refresh_token": refresh_token }))
            .await
    }

    async fn exchange_inner(
        &self,
        body: Value,
    ) -> Result<ExchangeResponse, ButtrBaseClientError> {
        // Anonymous endpoint — do NOT attach the stored token / credentials.
        let url = format!("{}/api/v1/auth/api-key/exchange", self.base_url);
        let response = self.client.post(&url).json(&body).send().await?;
        self.handle_response(response).await
    }

    // ── OAuth start URL ──────────────────────────────────────────────────────

    /// Build the URL the user-agent should be redirected to in order to
    /// initiate an OAuth flow. The backend responds to this URL with a 302 to
    /// the upstream provider — this helper just constructs the URL, it does
    /// not perform the request.
    pub fn oauth_start_url(
        &self,
        provider: OAuthProvider,
        app_uuid: Uuid,
        return_to: &str,
    ) -> String {
        format!(
            "{}/api/v1/auth/oauth/{}/start?app_uuid={}&return_to={}",
            self.base_url,
            provider.as_str(),
            app_uuid,
            urlencoding::encode(return_to),
        )
    }

    // ── App-level API key admin ──────────────────────────────────────────────

    pub async fn list_app_api_keys(
        &self,
        app_uuid: Uuid,
    ) -> Result<Vec<ApiKeySummary>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/v1/apps/{}/api-keys", app_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn create_app_api_key(
        &self,
        app_uuid: Uuid,
        input: &CreateApiKeyRequest,
    ) -> Result<CreatedKeyResponse, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/v1/apps/{}/api-keys", app_uuid),
            Some(input),
        )
        .await
    }

    pub async fn revoke_app_api_key(
        &self,
        app_uuid: Uuid,
        key_uuid: Uuid,
    ) -> Result<(), ButtrBaseClientError> {
        let _: Value = self
            .request(
                Method::DELETE,
                &format!("/api/v1/apps/{}/api-keys/{}", app_uuid, key_uuid),
                None::<&()>,
            )
            .await?;
        Ok(())
    }

    pub async fn rotate_app_api_key(
        &self,
        app_uuid: Uuid,
        key_uuid: Uuid,
    ) -> Result<CreatedKeyResponse, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/v1/apps/{}/api-keys/{}/rotate", app_uuid, key_uuid),
            None::<&()>,
        )
        .await
    }

    // ── App-level OAuth provider config admin ────────────────────────────────

    pub async fn list_oauth_configs(
        &self,
        app_uuid: Uuid,
    ) -> Result<Vec<OAuthConfigSummary>, ButtrBaseClientError> {
        self.request(
            Method::GET,
            &format!("/api/v1/apps/{}/oauth-configs", app_uuid),
            None::<&()>,
        )
        .await
    }

    pub async fn create_oauth_config(
        &self,
        app_uuid: Uuid,
        input: &CreateOAuthConfigRequest,
    ) -> Result<OAuthConfigSummary, ButtrBaseClientError> {
        self.request(
            Method::POST,
            &format!("/api/v1/apps/{}/oauth-configs", app_uuid),
            Some(input),
        )
        .await
    }

    pub async fn update_oauth_config(
        &self,
        app_uuid: Uuid,
        provider: &str,
        patch: &UpdateOAuthConfigRequest,
    ) -> Result<OAuthConfigSummary, ButtrBaseClientError> {
        self.request(
            Method::PATCH,
            &format!("/api/v1/apps/{}/oauth-configs/{}", app_uuid, provider),
            Some(patch),
        )
        .await
    }

    pub async fn delete_oauth_config(
        &self,
        app_uuid: Uuid,
        provider: &str,
    ) -> Result<(), ButtrBaseClientError> {
        let _: Value = self
            .request(
                Method::DELETE,
                &format!("/api/v1/apps/{}/oauth-configs/{}", app_uuid, provider),
                None::<&()>,
            )
            .await?;
        Ok(())
    }

    // ── Audit log (read-only) ────────────────────────────────────────────────

    pub async fn read_audit_log(
        &self,
        app_uuid: Uuid,
        opts: AuditLogQuery,
    ) -> Result<Vec<AuditRow>, ButtrBaseClientError> {
        let mut endpoint = format!("/api/v1/apps/{}/audit-log", app_uuid);
        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(limit) = opts.limit {
            params.push(("limit".into(), limit.to_string()));
        }
        if let Some(prefix) = opts.action_prefix {
            if !prefix.is_empty() {
                params.push(("action_prefix".into(), prefix));
            }
        }
        if !params.is_empty() {
            let qs: String = params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            endpoint.push('?');
            endpoint.push_str(&qs);
        }
        self.request(Method::GET, &endpoint, None::<&()>).await
    }

    // ── Passkeys (WebAuthn) ─────────────────────────────────────────────────
    //
    // Thin HTTP wrappers around the four passkey ceremony endpoints. The
    // challenge / credential blobs are pass-through `serde_json::Value` —
    // the browser's `navigator.credentials.create/get` APIs do the heavy
    // lifting. Begin endpoints unwrap the backend's `{data: ...}` envelope.

    /// `POST /api/passkeys/register/begin` — start passkey registration.
    /// Requires an authenticated caller (passkey is added to the existing
    /// account). The returned `challenge` is a WebAuthn
    /// `CreationChallengeResponse`.
    pub async fn passkey_register_begin(
        &self,
    ) -> Result<PasskeyRegistrationChallenge, ButtrBaseClientError> {
        let env: DataEnvelope<PasskeyRegistrationChallenge> = self
            .request(Method::POST, "/api/passkeys/register/begin", None::<&()>)
            .await?;
        Ok(env.data)
    }

    /// `POST /api/passkeys/register/complete` — finish passkey registration.
    pub async fn passkey_register_complete(
        &self,
        body: &PasskeyRegistrationComplete,
    ) -> Result<PasskeyRegistrationResult, ButtrBaseClientError> {
        let env: DataEnvelope<PasskeyRegistrationResult> = self
            .request(Method::POST, "/api/passkeys/register/complete", Some(body))
            .await?;
        Ok(env.data)
    }

    /// `POST /api/passkeys/authenticate/begin` — start passkey authentication.
    /// Anonymous; no bearer required (the server-signed `auth_state` is the
    /// only state the client carries between begin and complete).
    pub async fn passkey_authenticate_begin(
        &self,
    ) -> Result<PasskeyAuthChallenge, ButtrBaseClientError> {
        let env: DataEnvelope<PasskeyAuthChallenge> = self
            .request(
                Method::POST,
                "/api/passkeys/authenticate/begin",
                None::<&()>,
            )
            .await?;
        Ok(env.data)
    }

    /// `POST /api/passkeys/authenticate/complete` — finish passkey
    /// authentication. The session payload shape is currently unstable on the
    /// backend, so we return raw JSON — callers should narrow at the call
    /// site.
    pub async fn passkey_authenticate_complete(
        &self,
        body: &PasskeyAuthComplete,
    ) -> Result<serde_json::Value, ButtrBaseClientError> {
        self.request(
            Method::POST,
            "/api/passkeys/authenticate/complete",
            Some(body),
        )
        .await
    }

    /// `GET /api/v1/me/passkeys` — list the authenticated user's enrolled
    /// passkeys. Returned in descending `created_at` order.
    ///
    /// Requires a bearer token. Each row carries `credential_uuid` (for
    /// revocation) and `credential_id_prefix` (a 12-char display fragment of
    /// the full WebAuthn credential ID).
    pub async fn list_my_passkeys(&self) -> Result<Vec<PasskeyListItem>, ButtrBaseClientError> {
        self.request(Method::GET, "/api/v1/me/passkeys", None::<&()>)
            .await
    }

    /// `DELETE /api/v1/me/passkeys/{credential_uuid}` — revoke one of the
    /// authenticated user's passkeys. Owner check is enforced on the
    /// backend; passing a UUID that belongs to another user returns 404.
    pub async fn delete_my_passkey(
        &self,
        credential_uuid: Uuid,
    ) -> Result<serde_json::Value, ButtrBaseClientError> {
        self.request(
            Method::DELETE,
            &format!("/api/v1/me/passkeys/{}", credential_uuid),
            None::<&()>,
        )
        .await
    }
}
