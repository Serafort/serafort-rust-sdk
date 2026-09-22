use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::errors::SerafortError;
use crate::types::{OAuthResponse, SerafortConfig};

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct CachedToken {
    access_token: String,
    expires_at: Instant,
    scope: Option<String>,
}

pub struct TokenCache {
    tokens: RwLock<HashMap<String, CachedToken>>,
    buffer: Duration,
}

impl TokenCache {
    pub fn new(buffer: Duration) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            buffer,
        }
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        let lock = self.tokens.read().await;
        if let Some(item) = lock.get(key) {
            if Instant::now() + self.buffer < item.expires_at {
                return Some(item.access_token.clone());
            }
        }
        None
    }

    pub async fn set(
        &self,
        key: String,
        token: String,
        expires_in_seconds: u64,
        scope: Option<String>,
    ) {
        let mut lock = self.tokens.write().await;
        let expires_at = Instant::now() + Duration::from_secs(expires_in_seconds);
        lock.insert(
            key,
            CachedToken {
                access_token: token,
                expires_at,
                scope,
            },
        );
    }

    pub async fn invalidate(&self, key: Option<&str>) {
        let mut lock = self.tokens.write().await;
        if let Some(k) = key {
            lock.remove(k);
        } else {
            lock.clear();
        }
    }
}

pub struct M2MModule {
    config: Arc<SerafortConfig>,
    cache: Arc<TokenCache>,
    client: reqwest::Client,
}

impl M2MModule {
    pub fn new(config: Arc<SerafortConfig>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .unwrap_or_default();

        Self {
            config,
            cache: Arc::new(TokenCache::new(Duration::from_secs(300))), // 5 min proactive buffer
            client,
        }
    }

    pub async fn get_access_token(
        &self,
        scopes: Option<Vec<String>>,
    ) -> Result<String, SerafortError> {
        self.get_token(scopes, false).await
    }

    pub async fn force_refresh_token(
        &self,
        scopes: Option<Vec<String>>,
    ) -> Result<String, SerafortError> {
        self.get_token(scopes, true).await
    }

    async fn get_token(
        &self,
        scopes: Option<Vec<String>>,
        force: bool,
    ) -> Result<String, SerafortError> {
        let mut sorted_scopes = scopes.clone().unwrap_or_default();
        sorted_scopes.sort();
        let scope_str = sorted_scopes.join(" ");
        let cache_key = format!(
            "{}:{}",
            self.config.client_id.as_deref().unwrap_or("default"),
            scope_str
        );

        if !force {
            if let Some(tok) = self.cache.get(&cache_key).await {
                return Ok(tok);
            }
        }

        self.fetch_token_with_retry(
            &cache_key,
            if scope_str.is_empty() {
                None
            } else {
                Some(&scope_str)
            },
        )
        .await
    }

    async fn fetch_token_with_retry(
        &self,
        cache_key: &str,
        scope: Option<&str>,
    ) -> Result<String, SerafortError> {
        let client_id = self.config.client_id.as_deref().ok_or_else(|| {
            SerafortError::Authentication(
                "client_id is required for M2M authentication".to_string(),
            )
        })?;
        let client_secret = self.config.client_secret.as_deref().ok_or_else(|| {
            SerafortError::Authentication(
                "client_secret is required for M2M authentication".to_string(),
            )
        })?;

        let token_url = format!("{}/oauth/token", self.config.endpoint.trim_end_matches('/'));

        let mut params = vec![
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];

        if let Some(s) = scope {
            params.push(("scope", s));
        }

        let retry_cfg = &self.config.retry;
        let mut last_err = None;

        for attempt in 0..=retry_cfg.max_retries {
            if attempt > 0 {
                let delay = retry_cfg.initial_delay_ms as f64 * 2.0_f64.powi(attempt as i32 - 1);
                let capped = (delay as u64).min(retry_cfg.max_delay_ms);
                tokio::time::sleep(Duration::from_millis(capped)).await;
            }

            let resp = self.client.post(&token_url).form(&params).send().await;

            match resp {
                Ok(response) => {
                    let status = response.status();
                    if status.as_u16() == 429 || status.is_server_error() {
                        last_err = Some(SerafortError::RateLimit(None));
                        continue;
                    }

                    if !status.is_success() {
                        let text = response.text().await.unwrap_or_default();
                        return Err(SerafortError::Authentication(format!(
                            "Token request failed with status {}: {}",
                            status, text
                        )));
                    }

                    let oauth: OAuthResponse = response.json().await.map_err(|e| {
                        SerafortError::Internal(format!("Failed to parse token response: {}", e))
                    })?;

                    let exp = oauth.expires_in.unwrap_or(3600);
                    self.cache
                        .set(
                            cache_key.to_string(),
                            oauth.access_token.clone(),
                            exp,
                            scope.map(String::from),
                        )
                        .await;

                    return Ok(oauth.access_token);
                }
                Err(err) => {
                    last_err = Some(SerafortError::Network(err));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| SerafortError::Internal("Max retries exceeded".to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_expiration_and_buffer() {
        let cache = TokenCache::new(Duration::from_secs(300)); // 5 min buffer

        // Token valid for 10 minutes -> Hit
        cache
            .set("key_1".to_string(), "tok_valid".to_string(), 600, None)
            .await;
        assert_eq!(cache.get("key_1").await, Some("tok_valid".to_string()));

        // Token valid for 2 minutes (< 5 min buffer) -> Proactively invalid / Miss
        cache
            .set("key_2".to_string(), "tok_expiring".to_string(), 120, None)
            .await;
        assert_eq!(cache.get("key_2").await, None);
    }
}
