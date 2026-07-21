import re

with open('src/client.rs', 'r') as f:
    content = f.read()

# Add trait
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

content = content.replace("use reqwest::{Client, Method, RequestBuilder, Response};", trait_def + "use reqwest::{Client, Method, RequestBuilder, Response};")

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

with open('src/client.rs', 'w') as f:
    f.write(content)
