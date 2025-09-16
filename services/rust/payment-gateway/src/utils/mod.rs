pub mod crypto;
pub mod pci_masking;
pub mod fraud_detection;

// Enhanced Enterprise Fraud Detection Modules
pub mod quantum_ml_fraud_core;
pub mod redis_fraud_scoring;
pub mod advanced_ml_algorithms;
pub mod enterprise_fraud_alerting;
pub mod enhanced_fraud_service;

// Re-export enhanced fraud service for easy access
pub use enhanced_fraud_service::{ENHANCED_FRAUD_SERVICE, initialize_enhanced_fraud_service, ComprehensiveFraudAnalysisResult, EnhancedFraudDetectionService};

// Re-export quantum ML core
pub use quantum_ml_fraud_core::{QUANTUM_ML_FRAUD_CORE, QuantumMLFraudResult};

// Re-export Redis fraud scoring
pub use redis_fraud_scoring::{REDIS_FRAUD_SCORING, RealTimeFraudScore};

// Re-export advanced ML algorithms
pub use advanced_ml_algorithms::{ADVANCED_ML_SERVICE, AdvancedMLFraudPrediction};

// Re-export enterprise alerting
pub use enterprise_fraud_alerting::{ENTERPRISE_FRAUD_ALERTING, FraudAlert};

// Enhanced fraud detection service - this is the main service for maximum enterprise fraud detection
pub struct FraudDetectionService {
    enhanced_service: std::sync::Arc<EnhancedFraudDetectionService>,
}

impl FraudDetectionService {
    /// Create new fraud detection service using the enhanced enterprise system
    pub async fn new() -> anyhow::Result<Self> {
        // Initialize the enhanced fraud detection service
        initialize_enhanced_fraud_service().await?;
        
        Ok(Self {
            enhanced_service: ENHANCED_FRAUD_SERVICE.clone(),
        })
    }
    
    /// Analyze payment using maximum enterprise fraud detection
    pub async fn analyze_payment(
        &self,
        payment_request: &crate::models::payment_request::PaymentRequest,
        request_metadata: Option<serde_json::Value>
    ) -> anyhow::Result<ComprehensiveFraudAnalysisResult> {
        self.enhanced_service.analyze_payment_comprehensive(payment_request, request_metadata).await
    }
    
    /// Get service status
    pub async fn get_service_status(&self) -> anyhow::Result<serde_json::Value> {
        self.enhanced_service.get_service_status().await
    }
    
    /// Legacy compatibility - convert comprehensive result to basic result
    pub fn to_legacy_result(comprehensive: &ComprehensiveFraudAnalysisResult) -> fraud_detection::FraudAnalysisResult {
        use fraud_detection::{FraudAnalysisResult, FraudRiskLevel, FraudAction};
        
        let risk_level = match comprehensive.enterprise_risk_level {
            enhanced_fraud_service::EnterpriseRiskLevel::VeryLow => FraudRiskLevel::VeryLow,
            enhanced_fraud_service::EnterpriseRiskLevel::Low => FraudRiskLevel::Low,
            enhanced_fraud_service::EnterpriseRiskLevel::Medium => FraudRiskLevel::Medium,
            enhanced_fraud_service::EnterpriseRiskLevel::High => FraudRiskLevel::High,
            enhanced_fraud_service::EnterpriseRiskLevel::Critical => FraudRiskLevel::Critical,
            enhanced_fraud_service::EnterpriseRiskLevel::SystemAlert => FraudRiskLevel::Critical,
        };
        
        let actions = comprehensive.recommended_actions.iter().map(|action| {
            match action {
                enhanced_fraud_service::EnterpriseAction::Allow => FraudAction::Allow,
                enhanced_fraud_service::EnterpriseAction::RequireStepUpAuth => FraudAction::EnableStepUpAuth,
                enhanced_fraud_service::EnterpriseAction::RequireManualReview => FraudAction::RequireManualReview,
                enhanced_fraud_service::EnterpriseAction::BlockTransaction => FraudAction::Block,
                enhanced_fraud_service::EnterpriseAction::RequireKYC => FraudAction::RequestKyc,
                _ => FraudAction::RequireAdditionalVerification,
            }
        }).collect();
        
        let blocked = matches!(comprehensive.enterprise_risk_level, 
                              enhanced_fraud_service::EnterpriseRiskLevel::Critical |
                              enhanced_fraud_service::EnterpriseRiskLevel::SystemAlert);
        
        let reasons = comprehensive.audit_trail.decision_justifications
            .iter()
            .map(|d| format!("{}: {}", d.decision_type, d.decision_outcome))
            .collect();
        
        FraudAnalysisResult {
            risk_score: comprehensive.final_risk_score,
            risk_level,
            blocked,
            reasons,
            recommended_actions: actions,
            analysis_metadata: serde_json::json!({
                "analysis_id": comprehensive.analysis_id,
                "quantum_verified": comprehensive.quantum_verification.verification_successful,
                "processing_time_ms": comprehensive.processing_metrics.total_processing_time_ms,
                "compliance_status": comprehensive.compliance_status,
                "enterprise_grade": true
            }),
        }
    }
}