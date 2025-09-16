// Enhanced response structures for ultimate enterprise cryptocurrency payment processing
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use super::CoinbaseLocalPrice;

#[derive(Debug, Serialize)]
pub struct EnhancedCryptoPricing {
    pub local: CoinbaseLocalPrice,
    
    // Extended Cryptocurrency Support
    #[serde(rename = "bitcoin")]
    pub btc: Option<EnhancedCryptoPrice>,
    #[serde(rename = "ethereum")]
    pub eth: Option<EnhancedCryptoPrice>,
    #[serde(rename = "litecoin")]
    pub ltc: Option<EnhancedCryptoPrice>,
    #[serde(rename = "bitcoincash")]
    pub bch: Option<EnhancedCryptoPrice>,
    
    // Additional Enterprise Cryptocurrencies
    #[serde(rename = "polygon")]
    pub matic: Option<EnhancedCryptoPrice>,
    #[serde(rename = "chainlink")]
    pub link: Option<EnhancedCryptoPrice>,
    #[serde(rename = "cardano")]
    pub ada: Option<EnhancedCryptoPrice>,
    #[serde(rename = "polkadot")]
    pub dot: Option<EnhancedCryptoPrice>,
    
    // Real-time Market Analytics
    pub volatility_data: VolatilityData,
    pub market_analysis: MarketAnalysis,
    pub fee_analysis: FeeAnalysis,
    
    // Pricing Optimization
    pub optimal_currency: String,
    pub slippage_protection: f32,
    pub price_validity_window: u32, // seconds
}

#[derive(Debug, Serialize)]
pub struct EnhancedCryptoPrice {
    pub amount: String,
    pub currency: String,
    pub network: String,
    pub current_price_usd: f64,
    pub volatility_24h: f32,
    pub network_fee_estimate: u64,
    pub confirmation_time_estimate: u32, // minutes
    pub liquidity_score: f32,
    pub price_impact: f32,
}

#[derive(Debug, Serialize)]
pub struct VolatilityData {
    pub volatility_1h: f32,
    pub volatility_24h: f32,
    pub volatility_7d: f32,
    pub price_stability_score: f32,
    pub risk_level: String, // "low", "medium", "high"
    pub volatility_alert: bool,
}

#[derive(Debug, Serialize)]
pub struct MarketAnalysis {
    pub market_sentiment: String, // "bullish", "bearish", "neutral"
    pub trading_volume_24h: u64,
    pub market_cap_rank: u32,
    pub liquidity_depth: f64,
    pub institutional_interest: String,
    pub regulatory_sentiment: String,
}

#[derive(Debug, Serialize)]
pub struct FeeAnalysis {
    pub network_congestion: String, // "low", "medium", "high"
    pub average_fee_usd: f64,
    pub fee_trend: String, // "increasing", "decreasing", "stable"
    pub optimal_time_to_transact: Option<DateTime<Utc>>,
    pub fee_optimization_savings: f64,
}

#[derive(Debug, Serialize)]
pub struct QuantumSecureCryptoAddresses {
    // Core Cryptocurrencies with Quantum Security
    #[serde(rename = "bitcoin")]
    pub btc: Option<QuantumSecureAddress>,
    #[serde(rename = "ethereum")]
    pub eth: Option<QuantumSecureAddress>,
    #[serde(rename = "litecoin")]
    pub ltc: Option<QuantumSecureAddress>,
    #[serde(rename = "bitcoincash")]
    pub bch: Option<QuantumSecureAddress>,
    
    // Extended Cryptocurrency Support
    #[serde(rename = "polygon")]
    pub matic: Option<QuantumSecureAddress>,
    #[serde(rename = "chainlink")]
    pub link: Option<QuantumSecureAddress>,
    #[serde(rename = "cardano")]
    pub ada: Option<QuantumSecureAddress>,
    #[serde(rename = "polkadot")]
    pub dot: Option<QuantumSecureAddress>,
    
    // Multi-signature and Advanced Addresses
    pub multi_sig_addresses: Option<Vec<MultiSigAddress>>,
    pub escrow_addresses: Option<Vec<EscrowAddress>>,
    pub quantum_secure_backup_addresses: Option<Vec<String>>,
    
    // Address Security Validation
    pub address_validation_proofs: HashMap<String, String>,
    pub quantum_attestations: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct QuantumSecureAddress {
    pub address: String,
    pub network: String,
    pub address_type: String, // "standard", "multi_sig", "smart_contract"
    pub quantum_secure: bool,
    pub address_reputation_score: f32,
    pub last_security_audit: DateTime<Utc>,
    pub compliance_verified: bool,
    pub sanction_screening_passed: bool,
    pub risk_level: String,
    pub monitoring_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct MultiSigAddress {
    pub address: String,
    pub required_signatures: u32,
    pub total_signers: u32,
    pub signer_addresses: Vec<String>,
    pub quantum_secure_keys: bool,
    pub timeout_configuration: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct EscrowAddress {
    pub address: String,
    pub escrow_type: String,
    pub release_conditions: Vec<String>,
    pub timeout_duration: Option<u32>,
    pub dispute_resolution: String,
    pub quantum_attestation: String,
}

#[derive(Debug, Serialize)]
pub struct EnterpriseComplianceFlags {
    // Enhanced AML/KYC Compliance
    pub aml_verified: bool,
    pub aml_level: String, // "basic", "enhanced", "institutional"
    pub kyc_required: bool,
    pub kyc_level: String,
    pub enhanced_due_diligence: bool,
    
    // Geographic and Sanctions Compliance
    pub country_restricted: bool,
    pub jurisdiction_compliance: HashMap<String, bool>,
    pub sanctions_check_passed: bool,
    pub ofac_screening_passed: bool,
    pub eu_sanctions_screening: bool,
    pub un_sanctions_screening: bool,
    
    // Blockchain-Specific Compliance
    pub blockchain_analysis_passed: bool,
    pub mixer_usage_detected: bool,
    pub high_risk_exchanges_detected: bool,
    pub fatf_travel_rule_compliant: bool,
    
    // Risk Assessment
    pub overall_risk_score: String, // "very_low", "low", "medium", "high", "critical"
    pub transaction_risk_score: f32,
    pub customer_risk_score: f32,
    pub blockchain_risk_score: f32,
    
    // Regulatory Reporting
    pub suspicious_activity_detected: bool,
    pub regulatory_reporting_required: Vec<String>,
    pub compliance_officer_notification: bool,
}

#[derive(Debug, Serialize)]
pub struct RegulatoryStatus {
    pub primary_jurisdiction: String,
    pub applicable_regulations: Vec<String>,
    pub compliance_certifications: Vec<String>,
    pub regulatory_notifications_sent: Vec<String>,
    pub next_compliance_review: Option<DateTime<Utc>>,
    pub regulatory_risk_level: String,
}

#[derive(Debug, Serialize)]
pub struct BlockchainRiskSummary {
    pub overall_risk_level: String,
    pub high_risk_addresses_detected: u32,
    pub suspicious_transactions_count: u32,
    pub compliance_alerts_count: u32,
    pub forensic_analysis_required: bool,
    pub real_time_monitoring_active: bool,
    pub last_risk_assessment: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct CryptoAnalytics {
    pub market_conditions: String, // "favorable", "neutral", "unfavorable"
    pub optimal_transaction_time: Option<DateTime<Utc>>,
    pub network_health_score: f32,
    pub transaction_success_probability: f32,
    pub estimated_confirmation_time: u32, // minutes
    pub gas_price_trend: String,
    pub liquidity_analysis: LiquidityAnalysis,
}

#[derive(Debug, Serialize)]
pub struct LiquidityAnalysis {
    pub liquidity_score: f32,
    pub bid_ask_spread: f32,
    pub market_depth: f64,
    pub impact_analysis: String,
    pub optimal_order_size: u64,
    pub total_liquidity_usd: f64,
    pub order_book_depth: f32,
    pub spread_percentage: f32,
    pub market_impact_score: f32,
}

#[derive(Debug, Serialize)]
pub struct NetworkStatus {
    pub network_congestion: HashMap<String, String>,
    pub block_times: HashMap<String, f32>,
    pub mempool_status: HashMap<String, u32>,
    pub validator_health: HashMap<String, String>,
    pub network_upgrades_pending: HashMap<String, bool>,
}

#[derive(Debug, Serialize)]
pub struct FeeOptimization {
    pub recommended_fees: HashMap<String, u64>,
    pub fee_savings_percentage: f32,
    pub optimal_confirmation_speed: String,
    pub dynamic_fee_adjustment: bool,
    pub batch_processing_available: bool,
    pub layer2_recommendations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EnterpriseMonitoringData {
    pub monitoring_level: String, // "basic", "enhanced", "forensic"
    pub real_time_alerts_enabled: bool,
    pub compliance_monitoring_active: bool,
    pub fraud_detection_score: f32,
    pub anomaly_detection_active: bool,
    pub behavioral_analysis_enabled: bool,
    pub audit_logging_level: String,
    pub monitoring_active: bool,
    pub real_time_alerts: bool,
    pub compliance_dashboard_url: String,
    pub last_monitoring_update: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct FraudAnalysisResults {
    pub fraud_risk_score: f32,
    pub risk_level: String,
    pub ai_confidence: f32,
    pub behavioral_anomalies_detected: u32,
    pub blockchain_forensics_flags: u32,
    pub recommended_actions: Vec<String>,
    pub manual_review_required: bool,
    pub risk_score: f32,
    pub fraud_indicators: Vec<String>,
    pub analysis_complete: bool,
    pub recommended_action: String,
}