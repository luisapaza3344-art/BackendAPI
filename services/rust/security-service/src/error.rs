use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

pub type SecurityResult<T> = Result<T, SecurityError>;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Redis error: {0}")]
    Redis(String),
    
    #[error("QLDB error: {0}")]
    QLDB(String),
    
    #[error("IPFS error: {0}")]
    IPFS(String),
    
    #[error("Bitcoin error: {0}")]
    Bitcoin(String),
    
    #[error("HSM error: {0}")]
    HSM(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("FIPS compliance error: {0}")]
    FIPSCompliance(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Configuration error: {0}")]
    Config(#[from] anyhow::Error),
    
    #[error("Audit trail error: {0}")]
    AuditTrail(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Rate limit exceeded")]
    RateLimit,
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for SecurityError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code) = match &self {
            SecurityError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database operation failed",
                "DATABASE_ERROR",
            ),
            SecurityError::Redis(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cache operation failed",
                "REDIS_ERROR",
            ),
            SecurityError::QLDB(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Ledger operation failed",
                "QLDB_ERROR",
            ),
            SecurityError::IPFS(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Distributed storage operation failed",
                "IPFS_ERROR",
            ),
            SecurityError::Bitcoin(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Blockchain operation failed",
                "BITCOIN_ERROR",
            ),
            SecurityError::HSM(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Hardware security module operation failed",
                "HSM_ERROR",
            ),
            SecurityError::Crypto(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Cryptographic operation failed",
                "CRYPTO_ERROR",
            ),
            SecurityError::Encryption(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Encryption operation failed",
                "ENCRYPTION_ERROR",
            ),
            SecurityError::FIPSCompliance(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "FIPS compliance violation",
                "FIPS_ERROR",
            ),
            SecurityError::Validation(_) => (
                StatusCode::BAD_REQUEST,
                "Validation failed",
                "VALIDATION_ERROR",
            ),
            SecurityError::Config(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Configuration error",
                "CONFIG_ERROR",
            ),
            SecurityError::AuditTrail(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Audit trail operation failed",
                "AUDIT_ERROR",
            ),
            SecurityError::Unauthorized(_) => (
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "UNAUTHORIZED",
            ),
            SecurityError::NotFound(_) => (
                StatusCode::NOT_FOUND,
                "Resource not found",
                "NOT_FOUND",
            ),
            SecurityError::RateLimit => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded",
                "RATE_LIMIT",
            ),
            SecurityError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "INTERNAL_ERROR",
            ),
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": error_message,
                "details": self.to_string(),
                "fips_compliant": true,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }
        }));

        (status, body).into_response()
    }
}

// Note: IntoResponse for SecurityResult removed due to orphan rules
// Handlers will use explicit error handling instead

// Helper function to convert SecurityResult to Response
pub fn handle_security_result<T>(result: SecurityResult<T>) -> axum::response::Response
where
    T: axum::response::IntoResponse,
{
    match result {
        Ok(value) => value.into_response(),
        Err(error) => error.into_response(),
    }
}