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
