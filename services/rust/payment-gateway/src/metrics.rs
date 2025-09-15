use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec, 
    Registry, Opts, HistogramOpts
};
use std::sync::Arc;

#[derive(Clone)]
pub struct PaymentMetrics {
    pub registry: Arc<Registry>,
    
    // Request metrics
    pub http_requests_total: CounterVec,
    pub http_request_duration: HistogramVec,
    
    // Payment provider metrics
    pub payment_requests_total: CounterVec,
    pub payment_success_total: CounterVec,
    pub payment_errors_total: CounterVec,
    pub payment_amount_processed: CounterVec,
    
    // Security metrics
    pub fips_mode_enabled: Gauge,
    pub hsm_operations_total: CounterVec,
    pub attestation_operations_total: CounterVec,
    pub audit_logs_created: Counter,
    
    // Compliance metrics
    pub pci_dss_compliance: Gauge,
    pub encryption_operations_total: CounterVec,
    pub zero_knowledge_proofs_total: Counter,
    
    // System metrics
    pub database_connections_active: Gauge,
    pub webhook_processing_duration: HistogramVec,
}

impl PaymentMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Arc::new(Registry::new());
        
        // HTTP request metrics
        let http_requests_total = CounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests")
                .namespace("payment_gateway"),
            &["method", "endpoint", "status_code"]
        )?;
        
        let http_request_duration = HistogramVec::new(
            HistogramOpts::new("http_request_duration_seconds", "Duration of HTTP requests")
                .namespace("payment_gateway")
                .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["method", "endpoint"]
        )?;
        
        // Payment provider metrics
        let payment_requests_total = CounterVec::new(
            Opts::new("payment_requests_total", "Total number of payment requests by provider")
                .namespace("payment_gateway"),
            &["provider", "currency"]
        )?;
        
        let payment_success_total = CounterVec::new(
            Opts::new("payment_success_total", "Total number of successful payments")
                .namespace("payment_gateway"),
            &["provider", "currency"]
        )?;
        
        let payment_errors_total = CounterVec::new(
            Opts::new("payment_errors_total", "Total number of payment errors")
                .namespace("payment_gateway"),
            &["provider", "error_type"]
        )?;
        
        let payment_amount_processed = CounterVec::new(
            Opts::new("payment_amount_processed_total", "Total payment amount processed by currency")
                .namespace("payment_gateway"),
            &["provider", "currency"]
        )?;
        
        // Security metrics
        let fips_mode_enabled = Gauge::new(
            "fips_mode_enabled", "Whether FIPS 140-3 mode is enabled (1=enabled, 0=disabled)"
        )?;
        
        let hsm_operations_total = CounterVec::new(
            Opts::new("hsm_operations_total", "Total HSM operations performed")
                .namespace("payment_gateway"),
            &["operation_type", "status"]
        )?;
        
        let attestation_operations_total = CounterVec::new(
            Opts::new("attestation_operations_total", "Total cryptographic attestation operations")
                .namespace("payment_gateway"),
            &["operation_type", "status"]
        )?;
        
        let audit_logs_created = Counter::new(
            "audit_logs_created_total", "Total number of audit logs created"
        )?;
        
        // Compliance metrics
        let pci_dss_compliance = Gauge::new(
            "pci_dss_compliance_status", "PCI-DSS compliance status (1=compliant, 0=non-compliant)"
        )?;
        
        let encryption_operations_total = CounterVec::new(
            Opts::new("encryption_operations_total", "Total encryption/decryption operations")
                .namespace("payment_gateway"),
            &["operation", "algorithm"]
        )?;
        
        let zero_knowledge_proofs_total = Counter::new(
            "zero_knowledge_proofs_total", "Total zero-knowledge proofs generated"
        )?;
        
        // System metrics
        let database_connections_active = Gauge::new(
            "database_connections_active", "Number of active database connections"
        )?;
        
        let webhook_processing_duration = HistogramVec::new(
            HistogramOpts::new("webhook_processing_duration_seconds", "Duration of webhook processing")
                .namespace("payment_gateway")
                .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
            &["provider", "event_type"]
        )?;
        
        // Register all metrics
        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration.clone()))?;
        registry.register(Box::new(payment_requests_total.clone()))?;
        registry.register(Box::new(payment_success_total.clone()))?;
        registry.register(Box::new(payment_errors_total.clone()))?;
        registry.register(Box::new(payment_amount_processed.clone()))?;
        registry.register(Box::new(fips_mode_enabled.clone()))?;
        registry.register(Box::new(hsm_operations_total.clone()))?;
        registry.register(Box::new(attestation_operations_total.clone()))?;
        registry.register(Box::new(audit_logs_created.clone()))?;
        registry.register(Box::new(pci_dss_compliance.clone()))?;
        registry.register(Box::new(encryption_operations_total.clone()))?;
        registry.register(Box::new(zero_knowledge_proofs_total.clone()))?;
        registry.register(Box::new(database_connections_active.clone()))?;
        registry.register(Box::new(webhook_processing_duration.clone()))?;
        
        // Set initial compliance values
        fips_mode_enabled.set(1.0); // FIPS mode is enabled
        pci_dss_compliance.set(1.0); // PCI-DSS compliant
        
        Ok(PaymentMetrics {
            registry,
            http_requests_total,
            http_request_duration,
            payment_requests_total,
            payment_success_total,
            payment_errors_total,
            payment_amount_processed,
            fips_mode_enabled,
            hsm_operations_total,
            attestation_operations_total,
            audit_logs_created,
            pci_dss_compliance,
            encryption_operations_total,
            zero_knowledge_proofs_total,
            database_connections_active,
            webhook_processing_duration,
        })
    }
    
    pub fn render_metrics(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families).unwrap_or_else(|e| {
            format!("Error encoding metrics: {}", e)
        })
    }
}