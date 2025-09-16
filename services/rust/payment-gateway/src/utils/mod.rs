pub mod crypto;
pub mod pci_masking;
pub mod fraud_detection;

// Enhanced Enterprise Fraud Detection Modules
pub mod quantum_ml_fraud_core;
pub mod redis_fraud_scoring;
#[cfg(feature = "ml-full")]
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
#[cfg(feature = "ml-full")]
pub use advanced_ml_algorithms::{ADVANCED_ML_SERVICE, AdvancedMLFraudPrediction, AdvancedMLAlgorithmsService, TransactionHistoryPoint, initialize_advanced_ml_service};

// Minimal stubs for default ml-minimal build
#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdvancedMLFraudPrediction {
    pub prediction_id: uuid::Uuid,
    pub payment_id: uuid::Uuid,
    pub customer_id: String,
    pub final_fraud_probability: f64,
    pub confidence_score: f64,
    pub ensemble_results: EnsembleResults,
    pub neural_network_results: NeuralNetworkResults,
    pub time_series_analysis: TimeSeriesAnalysis,
    pub clustering_analysis: ClusteringAnalysis,
    pub model_consensus: f64,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnsembleResults {
    pub stacking_ensemble: StackingEnsemble,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StackingEnsemble {
    pub fraud_probability: f64,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NeuralNetworkResults {
    pub neural_ensemble_score: f64,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimeSeriesAnalysis {
    pub anomaly_detection: AnomalyDetection,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnomalyDetection {
    pub overall_anomaly_score: f64,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusteringAnalysis {
    pub kmeans_clustering: KMeansClustering,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KMeansClustering {
    pub cluster_risk_profile: ClusterRiskProfile,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterRiskProfile {
    pub average_fraud_rate: f64,
}

#[cfg(not(feature = "ml-full"))]
#[derive(Debug, Clone)]
pub struct TransactionHistoryPoint {
    pub payment_id: uuid::Uuid,
    pub amount: f64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[cfg(not(feature = "ml-full"))]
pub struct AdvancedMLAlgorithmsService;

#[cfg(not(feature = "ml-full"))]
impl AdvancedMLAlgorithmsService {
    pub fn new() -> Self { Self }
    
    pub async fn predict_fraud_advanced_ml(
        &self, 
        _request: &crate::models::payment_request::PaymentRequest,
        _profile: Option<&crate::utils::quantum_ml_fraud_core::EnterpriseCustomerProfile>,
        _history: Option<&[TransactionHistoryPoint]>
    ) -> anyhow::Result<AdvancedMLFraudPrediction> {
        Err(anyhow::anyhow!("Advanced ML requires ml-full feature"))
    }
}

#[cfg(not(feature = "ml-full"))]
pub async fn initialize_advanced_ml_service() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(feature = "ml-full"))]
pub static ADVANCED_ML_SERVICE: once_cell::sync::Lazy<std::sync::Arc<AdvancedMLAlgorithmsService>> = once_cell::sync::Lazy::new(|| {
    std::sync::Arc::new(AdvancedMLAlgorithmsService::new())
});

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