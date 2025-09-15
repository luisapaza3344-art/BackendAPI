use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub id: Uuid,
    pub provider: String, // "stripe", "paypal", "coinbase"
    pub amount: u64, // Amount in cents
    pub currency: String,
    pub customer_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentStatus {
    pub id: Uuid,
    pub status: String, // "pending", "processing", "completed", "failed", "cancelled"
    pub provider: String, // "stripe", "paypal", "coinbase"
    pub amount: u64, // Amount in cents
    pub currency: String,
    pub provider_transaction_id: Option<String>,
    pub attestation_hash: String, // HSM-signed attestation
    pub blockchain_anchor: Option<String>, // Bitcoin transaction hash for audit trail
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub payment_id: Uuid,
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub attestation_hash: String,
    pub created_at: DateTime<Utc>,
}