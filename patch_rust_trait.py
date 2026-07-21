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
    pub client: reqwest::Client,
}

#[async_trait]
impl ButtrbaseTransport for DefaultTransport {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        self.client.execute(req).await
    }
}
"""

with open('src/client.rs', 'w') as f:
    f.write(trait_def + "\\n" + content)
