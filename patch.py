import re

with open('src/client.rs', 'r') as f:
    content = f.read()

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
