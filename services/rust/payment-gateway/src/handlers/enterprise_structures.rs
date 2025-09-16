// Enterprise data structures for the ultimate cryptocurrency payment processor
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EnterpriseCustomerInfo {
    pub customer_id: String,
    pub customer_name: String,
    pub email: String,
    pub country: String,
    pub jurisdiction: String,
    
    // Enhanced KYC/AML with Blockchain Analysis
    pub kyc_verified: bool,
    pub kyc_level: String, // "basic", "enhanced", "institutional"
    pub aml_risk_score: Option<f32>,
    pub sanctions_screening_status: String,
    pub pep_status: bool, // Politically Exposed Person
    pub fatf_travel_rule_applicable: bool,
    
    // Blockchain-Specific Compliance
    pub crypto_experience_level: String,
    pub wallet_addresses: Vec<VerifiedWalletAddress>,
    pub transaction_history_analysis: Option<TransactionHistoryAnalysis>,
    pub compliance_jurisdiction: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VerifiedWalletAddress {
    pub address: String,
    pub blockchain: String,
    pub verification_status: String,
    pub risk_score: f32,
    pub last_activity: Option<DateTime<Utc>>,
    pub compliance_flags: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TransactionHistoryAnalysis {
    pub total_volume: u64,
    pub transaction_count: u32,
    pub high_risk_transactions: u32,
    pub mixer_usage_detected: bool,
    pub exchange_interactions: Vec<String>,
    pub defi_protocol_usage: Vec<String>,
    pub nft_trading_activity: bool,
    pub analysis_timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlockchainRiskAssessment {
    pub overall_risk_score: f32,
    pub address_reputation_scores: HashMap<String, f32>,
    pub transaction_risk_factors: Vec<RiskFactor>,
    pub compliance_alerts: Vec<ComplianceAlert>,
    pub forensic_analysis: Option<ForensicAnalysis>,
    pub real_time_monitoring: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RiskFactor {
    pub factor_type: String,
    pub severity: String, // "low", "medium", "high", "critical"
    pub description: String,
    pub blockchain_evidence: Option<String>,
    pub mitigation_required: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ComplianceAlert {
    pub alert_type: String,
    pub alert_level: String,
    pub description: String,
    pub regulatory_framework: String,
    pub required_action: String,
    pub deadline: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ForensicAnalysis {
    pub analysis_type: String,
    pub blockchain_forensics: HashMap<String, serde_json::Value>,
    pub fund_flow_analysis: Vec<FundFlow>,
    pub entity_clustering: Vec<EntityCluster>,
    pub risk_propagation: RiskPropagation,
    pub investigation_notes: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FundFlow {
    pub source_address: String,
    pub destination_address: String,
    pub amount: u64,
    pub blockchain: String,
    pub transaction_hash: String,
    pub timestamp: DateTime<Utc>,
    pub risk_score: f32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EntityCluster {
    pub cluster_id: String,
    pub addresses: Vec<String>,
    pub entity_type: String, // "exchange", "mixer", "individual", "institution", "unknown"
    pub confidence_score: f32,
    pub risk_level: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RiskPropagation {
    pub propagation_score: f32,
    pub affected_addresses: Vec<String>,
    pub risk_transmission_paths: Vec<Vec<String>>,
    pub containment_recommendations: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DeFiIntegrationConfig {
    pub protocols: Vec<String>, // ["uniswap", "compound", "aave", "makerdao"]
    pub liquidity_provision: bool,
    pub yield_farming: bool,
    pub flash_loan_protection: bool,
    pub smart_contract_audit_required: bool,
    pub impermanent_loss_protection: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NFTPaymentConfig {
    pub nft_marketplaces: Vec<String>, // ["opensea", "rarible", "superrare"]
    pub supported_standards: Vec<String>, // ["ERC-721", "ERC-1155"]
    pub royalty_handling: bool,
    pub metadata_verification: bool,
    pub provenance_tracking: bool,
    pub fractional_ownership: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CrossChainConfig {
    pub bridge_protocols: Vec<String>,
    pub supported_networks: Vec<String>,
    pub atomic_swap_support: bool,
    pub cross_chain_validation: bool,
    pub bridge_security_validation: bool,
    pub slippage_protection: f32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EnterpriseMetadata {
    pub business_unit: String,
    pub cost_center: String,
    pub compliance_officer: String,
    pub risk_tolerance: String,
    pub reporting_requirements: Vec<String>,
    pub audit_trail_level: String, // "basic", "enhanced", "forensic"
    pub data_residency_requirements: Vec<String>,
}