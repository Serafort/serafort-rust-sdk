use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: String,
    pub tenant_id: String,
    pub email: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub claims: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 500,
            max_delay_ms: 5000,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SerafortConfig {
    pub endpoint: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub timeout_seconds: u64,
    pub retry: RetryConfig,
}

impl SerafortConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client_id: None,
            client_secret: None,
            timeout_seconds: 10,
            retry: RetryConfig::default(),
        }
    }

    pub fn with_client_credentials(mut self, client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self.client_secret = Some(client_secret.into());
        self
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub(crate) struct OAuthResponse {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
}
