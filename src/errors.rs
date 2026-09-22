use thiserror::Error;

#[derive(Error, Debug)]
pub enum SerafortError {
    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Rate limit exceeded")]
    RateLimit(Option<u64>),

    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}
