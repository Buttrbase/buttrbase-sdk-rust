import re

with open('src/client.rs', 'r') as f:
    content = f.read()

trait_def = """
use async_trait::async_trait;

#[async_trait]
pub trait ButtrbaseTransport: Send + Sync {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error>;
}

#[derive(Clone)]
pub struct DefaultTransport {
    client: reqwest::Client,
}

#[async_trait]
impl ButtrbaseTransport for DefaultTransport {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        self.client.execute(req).await
    }
}
"""

# Insert trait_def after "use std::time::Duration;"
content = content.replace("use std::time::Duration;", "use std::time::Duration;\n" + trait_def)

# Add transport field
content = content.replace(
    """    pub(crate) base_url: String,
    http: Client,
    verifier: Verifier,""",
    """    pub(crate) base_url: String,
    http: Client,
    transport: std::sync::Arc<dyn ButtrbaseTransport>,
    verifier: Verifier,"""
)

# update build
content = content.replace(
    """        Self {
            environment,
            client_id,
            client_secret,
            base_url,
            http,
            verifier,
        }""",
    """        let transport = std::sync::Arc::new(DefaultTransport { client: http.clone() });
        Self {
            environment,
            client_id,
            client_secret,
            base_url,
            http,
            transport,
            verifier,
        }"""
)

# Add with_transport
content = content.replace(
    """    pub fn base_url(&self) -> &str {
        &self.base_url
    }""",
    """    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    
    pub fn with_transport(mut self, transport: std::sync::Arc<dyn ButtrbaseTransport>) -> Self {
        self.transport = transport;
        self
    }"""
)

# update send and send_empty
content = content.replace(
    """    async fn send<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T, Error> {
        let resp = req.send().await?;
        parse_response(resp).await
    }

    async fn send_empty(&self, req: RequestBuilder) -> Result<(), Error> {
        let resp = req.send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(parse_error_body(status, &body))
    }""",
    """    async fn send<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T, Error> {
        let req = req.build().map_err(|e| Error::Unexpected { status: 0, body: e.to_string() })?;
        let resp = self.transport.execute(req).await.map_err(|e| Error::Unexpected { status: 0, body: e.to_string() })?;
        parse_response(resp).await
    }

    async fn send_empty(&self, req: RequestBuilder) -> Result<(), Error> {
        let req = req.build().map_err(|e| Error::Unexpected { status: 0, body: e.to_string() })?;
        let resp = self.transport.execute(req).await.map_err(|e| Error::Unexpected { status: 0, body: e.to_string() })?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(parse_error_body(status, &body))
    }"""
)

# wait! My previous public client change was lost because I did git checkout!
# Let me re-apply the public client changes too!
content = content.replace(
    'client_secret: String,',
    'client_secret: Option<String>,'
)

content = content.replace(
    'pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {',
    '''/// Create a public client for use in frontend/native apps without a client secret.
    pub fn new_public(client_id: impl Into<String>) -> Self {
        let client_id = client_id.into();
        let env = Environment::from_client_id(&client_id);
        let base_url = match env {
            Environment::Live => LIVE_BASE_URL,
            Environment::Sandbox => SANDBOX_BASE_URL,
        };
        Self::build(client_id, None, env, base_url.to_string())
    }

    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {'''
)

content = content.replace(
    'Self::build(client_id, client_secret.into(), env, base_url.to_string())',
    'Self::build(client_id, Some(client_secret.into()), env, base_url.to_string())'
)

content = content.replace(
    'Self::build(client_id, client_secret.into(), env, base_url.into())',
    'Self::build(client_id, Some(client_secret.into()), env, base_url.into())'
)

content = content.replace(
    '''fn build(
        client_id: String,
        client_secret: String,''',
    '''fn build(
        client_id: String,
        client_secret: Option<String>,'''
)

content = content.replace(
    '''fn app_request(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .basic_auth(&self.client_id, Some(&self.client_secret))
    }''',
    '''fn app_request(&self, method: Method, path: &str) -> RequestBuilder {
        let req = self.http.request(method, format!("{}{}", self.base_url, path));
        if let Some(secret) = &self.client_secret {
            req.basic_auth(&self.client_id, Some(secret))
        } else {
            req.basic_auth(&self.client_id, None::<&str>)
        }
    }'''
)

with open('src/client.rs', 'w') as f:
    f.write(content)
