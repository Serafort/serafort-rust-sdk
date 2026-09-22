use crate::b2b::B2BModule;
use crate::errors::SerafortError;
use crate::m2m::M2MModule;
use crate::types::{SerafortConfig, UserContext};
use std::sync::Arc;

#[derive(Clone)]
pub struct SerafortClient {
    pub config: Arc<SerafortConfig>,
    pub m2m: Arc<M2MModule>,
    pub b2b: Arc<B2BModule>,
}

impl SerafortClient {
    pub fn new(config: SerafortConfig) -> Self {
        let config_arc = Arc::new(config);
        let m2m = Arc::new(M2MModule::new(Arc::clone(&config_arc)));
        let b2b = Arc::new(B2BModule::new(Arc::clone(&config_arc)));

        Self {
            config: config_arc,
            m2m,
            b2b,
        }
    }

    pub async fn get_access_token(
        &self,
        scopes: Option<Vec<String>>,
    ) -> Result<String, SerafortError> {
        self.m2m.get_access_token(scopes).await
    }

    pub fn validate_token(&self, token: &str) -> Result<UserContext, SerafortError> {
        self.b2b.validate_token(token)
    }

    pub fn has_permission(&self, user: &UserContext, required_permission: &str) -> bool {
        self.b2b.has_permission(user, required_permission)
    }

    pub fn has_role(&self, user: &UserContext, required_role: &str) -> bool {
        self.b2b.has_role(user, required_role)
    }

    pub fn get_login_url(&self, tenant_id: &str, redirect_uri: &str) -> String {
        self.b2b.get_login_url(tenant_id, redirect_uri)
    }
}
