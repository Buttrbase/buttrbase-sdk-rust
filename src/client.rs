use reqwest::{Client, Method, Response};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;

use crate::models::{
    ButtrBaseErrorResponse, CheckoutResponse, Credentials, CredentialsDetails, CreateCredentialsRequest,
    Invoice, LoginResponse, Profile, UpdateCredentialsRequest,
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

#[derive(Debug, Clone)]
pub struct ButtrBaseClient {
    base_url: String,
    client: Client,
    token: Option<String>,
}

impl ButtrBaseClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: Client::new(),
            token: None,
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
        }

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

    pub async fn send_otp(&self, email: &str, app: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("email", email);
        body.insert("app", app);
        self.request(Method::POST, "/api/auth/otp", Some(&body))
            .await
    }

    pub async fn verify_otp(&self, email: &str, otp: &str, app: &str) -> Result<HashMap<String, Value>, ButtrBaseClientError> {
        let mut body = HashMap::new();
        body.insert("email", email);
        body.insert("otp", otp);
        body.insert("app", app);
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

    // Blog methods removed: CMS lives at metaphone.app — use the
    // `metaphone-sdk` crate (forthcoming) instead.

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
}
