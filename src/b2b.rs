use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::Value;

use crate::errors::SerafortError;
use crate::types::{SerafortConfig, UserContext};

pub struct B2BModule {
    config: Arc<SerafortConfig>,
}

impl B2BModule {
    pub fn new(config: Arc<SerafortConfig>) -> Self {
        Self { config }
    }

    pub fn validate_token(&self, token: &str) -> Result<UserContext, SerafortError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(SerafortError::Authentication("Invalid JWT: expected 3 parts".to_string()));
        }

        let payload_raw = decode_base64_url(parts[1])
            .map_err(|e| SerafortError::Authentication(format!("Failed to base64url decode payload: {}", e)))?;

        let claims: Value = serde_json::from_slice(&payload_raw)
            .map_err(|e| SerafortError::Authentication(format!("Failed to parse JWT claims: {}", e)))?;

        // Expiration check
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
            if now > exp + 60 {
                // 60s tolerance
                return Err(SerafortError::Authentication("Token has expired".to_string()));
            }
        }

        // Issuer check
        let expected_iss = self.config.endpoint.trim_end_matches('/');
        if let Some(iss) = claims.get("iss").and_then(|v| v.as_str()) {
            if iss.trim_end_matches('/') != expected_iss {
                return Err(SerafortError::Authentication(format!(
                    "Invalid issuer: expected '{}', got '{}'",
                    expected_iss, iss
                )));
            }
        }

        self.map_claims_to_user(&claims)
    }

    pub fn has_permission(&self, user: &UserContext, required_permission: &str) -> bool {
        if user.permissions.is_empty() {
            return false;
        }

        for perm in &user.permissions {
            if perm == "*" || perm == required_permission {
                return true;
            }
            if let Some(prefix) = perm.strip_suffix(":*") {
                if required_permission.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }

    pub fn has_role(&self, user: &UserContext, required_role: &str) -> bool {
        user.roles.iter().any(|r| r == required_role)
    }

    pub fn get_login_url(&self, tenant_id: &str, redirect_uri: &str) -> String {
        format!(
            "{}/api/auth/sso/login?tenant_id={}&redirect_uri={}",
            self.config.endpoint.trim_end_matches('/'),
            urlencoding(tenant_id),
            urlencoding(redirect_uri)
        )
    }

    fn map_claims_to_user(&self, claims: &Value) -> Result<UserContext, SerafortError> {
        let user_id = claims
            .get("sub")
            .or_else(|| claims.get("id"))
            .or_else(|| claims.get("user_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let tenant_id = claims
            .get("tenant_id")
            .or_else(|| claims.get("org_id"))
            .or_else(|| claims.get("tid"))
            .or_else(|| claims.get("app_metadata").and_then(|m| m.get("tenant_id")))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let email = claims.get("email").and_then(|v| v.as_str()).map(String::from);

        let mut roles = Vec::new();
        if let Some(r_arr) = claims.get("roles").and_then(|v| v.as_array()) {
            for r in r_arr {
                if let Some(s) = r.as_str() {
                    roles.push(s.to_string());
                }
            }
        } else if let Some(r_str) = claims.get("role").and_then(|v| v.as_str()) {
            roles.push(r_str.to_string());
        }

        let mut permissions = Vec::new();
        if let Some(p_arr) = claims.get("permissions").and_then(|v| v.as_array()) {
            for p in p_arr {
                if let Some(s) = p.as_str() {
                    permissions.push(s.to_string());
                }
            }
        } else if let Some(p_str) = claims.get("scope").and_then(|v| v.as_str()) {
            for s in p_str.split_whitespace() {
                permissions.push(s.to_string());
            }
        }

        Ok(UserContext {
            user_id,
            tenant_id,
            email,
            roles,
            permissions,
            claims: claims.clone(),
        })
    }
}

fn decode_base64_url(input: &str) -> Result<Vec<u8>, String> {
    let mut base64_str = input.replace('-', "+").replace('_', "/");
    while base64_str.len() % 4 != 0 {
        base64_str.push('=');
    }

    // Simple base64 decoder without extra external dependencies
    base64_decode_internal(&base64_str)
}

fn base64_decode_internal(input: &str) -> Result<Vec<u8>, String> {
    const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut char_map = [255u8; 256];
    for (i, &c) in B64_CHARS.iter().enumerate() {
        char_map[c as usize] = i as u8;
    }

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;

    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = char_map[b as usize];
        if val == 255 {
            continue; // Skip invalid or whitespace
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
        }
    }

    Ok(output)
}

fn urlencoding(input: &str) -> String {
    let mut encoded = String::new();
    for b in input.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => encoded.push(b as char),
            _ => encoded.push_str(&format!("%{:02X}", b)),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b2b_permissions_and_wildcards() {
        let config = Arc::new(SerafortConfig::new("https://auth.acme.com"));
        let b2b = B2BModule::new(config);

        let user = UserContext {
            user_id: "u1".to_string(),
            tenant_id: "t1".to_string(),
            email: None,
            roles: vec!["admin".to_string()],
            permissions: vec!["org:read".to_string(), "users:*".to_string()],
            claims: Value::Null,
        };

        assert!(b2b.has_permission(&user, "org:read"));
        assert!(b2b.has_permission(&user, "users:create"));
        assert!(b2b.has_permission(&user, "users:delete"));
        assert!(!b2b.has_permission(&user, "billing:write"));

        assert!(b2b.has_role(&user, "admin"));
        assert!(!b2b.has_role(&user, "viewer"));
    }

    #[test]
    fn test_get_login_url() {
        let config = Arc::new(SerafortConfig::new("https://auth.acme.com"));
        let b2b = B2BModule::new(config);

        let url = b2b.get_login_url("ten_123", "https://app.acme.com/cb");
        assert!(url.contains("tenant_id=ten_123"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapp.acme.com%2Fcb"));
    }
}
