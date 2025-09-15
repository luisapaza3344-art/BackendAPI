use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use regex::Regex;

lazy_static::lazy_static! {
    static ref RISK_LEVEL_REGEX: Regex = Regex::new(r"^(LOW|MEDIUM|HIGH|CRITICAL)$").unwrap();
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditRecord {
    pub id: Uuid,
    pub event_type: String,
    pub service_name: String,
    pub operation: String,
    pub user_id: Option<String>,
    pub subject_id: String,
    pub resource: String,
    pub request_data: serde_json::Value,
    pub response_data: serde_json::Value,
    pub request_hash: String, // SHA-384
    pub response_hash: String, // SHA-384
    pub combined_hash: String, // SHA-384 of request + response
    pub merkle_root: String,
    pub client_ip: String,
    pub user_agent: String,
    pub request_id: String,
    pub session_id: Option<String>,
    pub risk_level: String,
    pub compliance_flags: serde_json::Value,
    pub fips_compliant: bool,
    pub hsm_signed: bool,
    pub hsm_signature: Option<String>,
    pub hsm_key_id: Option<String>,
    pub qldb_document_id: Option<String>,
    pub qldb_block_hash: Option<String>,
    pub ipfs_hash: Option<String>,
    pub ipfs_pin_status: Option<String>,
    pub bitcoin_anchor_txid: Option<String>,
    pub bitcoin_block_height: Option<i64>,
    pub blockchain_confirmations: Option<i32>,
    pub integrity_proof: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateAuditRequest {
    #[validate(length(min = 1, max = 100))]
    pub event_type: String,
    
    #[validate(length(min = 1, max = 100))]
    pub service_name: String,
    
    #[validate(length(min = 1, max = 100))]
    pub operation: String,
    
    pub user_id: Option<String>,
    
    #[validate(length(min = 1, max = 255))]
    pub subject_id: String,
    
    #[validate(length(min = 1, max = 255))]
    pub resource: String,
    
    pub request_data: serde_json::Value,
    pub response_data: serde_json::Value,
    
    #[validate(length(min = 1, max = 45))]
    pub client_ip: String,
    
    pub user_agent: String,
    
    #[validate(length(min = 1, max = 255))]
    pub request_id: String,
    
    pub session_id: Option<String>,
    
    #[validate(regex(path = "RISK_LEVEL_REGEX", message = "Risk level must be LOW, MEDIUM, HIGH, or CRITICAL"))]
    pub risk_level: String,
    
    pub compliance_flags: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResponse {
    pub id: Uuid,
    pub status: String,
    pub message: String,
    pub audit_record: Option<AuditRecord>,
    pub fips_compliant: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAnchor {
    pub id: Uuid,
    pub merkle_root: String,
    pub audit_record_ids: Vec<Uuid>,
    pub bitcoin_txid: Option<String>,
    pub bitcoin_block_height: Option<i64>,
    pub confirmations: Option<i32>,
    pub anchor_data: serde_json::Value,
    pub status: String, // PENDING, CONFIRMED, FAILED
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPFSRecord {
    pub id: Uuid,
    pub audit_record_id: Uuid,
    pub ipfs_hash: String,
    pub pin_status: String, // PINNED, UNPINNED, PINNING, ERROR
    pub gateway_url: String,
    pub data_size: i64,
    pub pin_service: Option<String>,
    pub created_at: DateTime<Utc>,
    pub pinned_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QLDBDocument {
    pub document_id: String,
    pub table_name: String,
    pub block_hash: String,
    pub audit_record_id: Uuid,
    pub data: serde_json::Value,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSMAttestation {
    pub id: Uuid,
    pub audit_record_id: Uuid,
    pub signature: String,
    pub key_id: String,
    pub algorithm: String,
    pub data_to_sign: String,
    pub signature_timestamp: DateTime<Utc>,
    pub fips_compliant: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub total_audit_records: i64,
    pub qldb_records: i64,
    pub ipfs_records: i64,
    pub bitcoin_anchors: i64,
    pub hsm_attestations: i64,
    pub fips_compliant_records: i64,
    pub high_risk_events: i64,
    pub blockchain_confirmations_avg: f64,
    pub last_bitcoin_anchor: Option<DateTime<Utc>>,
    pub system_health: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityVerification {
    pub audit_record_id: Uuid,
    pub local_hash: String,
    pub qldb_hash: Option<String>,
    pub ipfs_hash: Option<String>,
    pub bitcoin_merkle_proof: Option<String>,
    pub hsm_verification: bool,
    pub integrity_status: String, // VERIFIED, CORRUPTED, PARTIAL, UNKNOWN
    pub verification_timestamp: DateTime<Utc>,
    pub discrepancies: Vec<String>,
}