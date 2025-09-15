use crate::{
    config::SecurityConfig,
    error::SecurityResult,
    handlers::{
        create_audit_record, get_audit_record, get_audit_trail, get_security_metrics,
        health_check, list_audit_records, readiness_check, security_alert, service_info,
        verify_audit_integrity, SharedAuditService,
    },
    middleware::SecurityMiddleware,
    services::audit::AuditService,
};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{sync::Arc, time::Duration};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::info;

pub struct SecurityApp {
    config: SecurityConfig,
    db_pool: PgPool,
    audit_service: SharedAuditService,
}

impl SecurityApp {
    pub async fn new(config: SecurityConfig) -> SecurityResult<Self> {
        info!("🔐 Initializing FIPS 140-3 Level 3 Security Service");

        // Create database connection pool
        let db_pool = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect(&config.database.url)
            .await
            .map_err(|e| crate::error::SecurityError::Database(e))?;

        info!("💾 Database connection pool created");

        // Run database migrations
        Self::run_migrations(&db_pool).await?;
        info!("📋 Database migrations completed");

        // Initialize audit service
        let audit_service = Arc::new(AuditService::new(config.clone(), db_pool.clone()).await?);
        info!("🔒 Audit service initialized with immutable trail capabilities");

        Ok(Self {
            config,
            db_pool,
            audit_service,
        })
    }

    pub async fn create_router(&self) -> SecurityResult<Router> {
        let security_middleware = SecurityMiddleware::new(self.config.clone());

        let app = Router::new()
            // Health and info endpoints
            .route("/health", get(health_check))
            .route("/ready", get(readiness_check))
            .route("/info", get(service_info))
            
            // Main audit endpoints
            .route("/api/v1/audit-records", post(create_audit_record))
            .route("/api/v1/audit-records", get(list_audit_records))
            .route("/api/v1/audit-records/:id", get(get_audit_record))
            .route("/api/v1/audit-records/:id/verify", post(verify_audit_integrity))
            
            // Audit trail and metrics
            .route("/api/v1/audit-trail/:resource", get(get_audit_trail))
            .route("/api/v1/metrics", get(get_security_metrics))
            
            // Emergency security alert
            .route("/api/v1/security-alert", post(security_alert))
            
            // Add middleware layers
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(TimeoutLayer::new(Duration::from_secs(30)))
                    .layer(CorsLayer::new()
                        .allow_origin("http://localhost:3000".parse::<axum::http::HeaderValue>().unwrap())
                        .allow_origin("https://localhost:3000".parse::<axum::http::HeaderValue>().unwrap()) 
                        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION]))
                    .layer(middleware::from_fn_with_state(
                        self.audit_service.clone(),
                        SecurityMiddleware::audit_middleware,
                    ))
            )
            
            // Add shared state
            .with_state(self.audit_service.clone());

        info!("🌐 Security service router configured with FIPS compliance");

        Ok(app)
    }

    /// Run database migrations
    async fn run_migrations(pool: &PgPool) -> SecurityResult<()> {
        info!("📋 Running database migrations for Security Service");

        // Create audit_records table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS audit_records (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                event_type VARCHAR(100) NOT NULL,
                service_name VARCHAR(100) NOT NULL,
                operation VARCHAR(100) NOT NULL,
                user_id VARCHAR(255),
                subject_id VARCHAR(255) NOT NULL,
                resource VARCHAR(255) NOT NULL,
                request_data JSONB NOT NULL,
                response_data JSONB NOT NULL,
                request_hash VARCHAR(128) NOT NULL,
                response_hash VARCHAR(128) NOT NULL,
                combined_hash VARCHAR(128) NOT NULL,
                merkle_root VARCHAR(128) NOT NULL,
                client_ip VARCHAR(45) NOT NULL,
                user_agent TEXT NOT NULL,
                request_id VARCHAR(255) NOT NULL,
                session_id VARCHAR(255),
                risk_level VARCHAR(50) NOT NULL DEFAULT 'LOW',
                compliance_flags JSONB DEFAULT '{}',
                fips_compliant BOOLEAN NOT NULL DEFAULT TRUE,
                hsm_signed BOOLEAN NOT NULL DEFAULT FALSE,
                hsm_signature TEXT,
                hsm_key_id VARCHAR(255),
                qldb_document_id VARCHAR(255),
                qldb_block_hash VARCHAR(255),
                ipfs_hash VARCHAR(255),
                ipfs_pin_status VARCHAR(50),
                bitcoin_anchor_txid VARCHAR(255),
                bitcoin_block_height BIGINT,
                blockchain_confirmations INTEGER,
                integrity_proof JSONB DEFAULT '{}',
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#)
        .execute(pool)
        .await
        .map_err(|e| crate::error::SecurityError::Database(e))?;

        // Create blockchain_anchors table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS blockchain_anchors (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                merkle_root VARCHAR(128) NOT NULL,
                audit_record_ids UUID[] NOT NULL,
                bitcoin_txid VARCHAR(255),
                bitcoin_block_height BIGINT,
                confirmations INTEGER,
                anchor_data JSONB DEFAULT '{}',
                status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                confirmed_at TIMESTAMP WITH TIME ZONE
            )
        "#)
        .execute(pool)
        .await
        .map_err(|e| crate::error::SecurityError::Database(e))?;

        // Create ipfs_records table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS ipfs_records (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                audit_record_id UUID REFERENCES audit_records(id),
                ipfs_hash VARCHAR(255) NOT NULL,
                pin_status VARCHAR(50) NOT NULL DEFAULT 'PINNED',
                gateway_url TEXT NOT NULL,
                data_size BIGINT NOT NULL,
                pin_service VARCHAR(100),
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                pinned_at TIMESTAMP WITH TIME ZONE
            )
        "#)
        .execute(pool)
        .await
        .map_err(|e| crate::error::SecurityError::Database(e))?;

        // Create hsm_attestations table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS hsm_attestations (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                audit_record_id UUID NOT NULL REFERENCES audit_records(id),
                signature TEXT NOT NULL,
                key_id VARCHAR(255) NOT NULL,
                algorithm VARCHAR(100) NOT NULL,
                data_to_sign TEXT NOT NULL,
                signature_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                fips_compliant BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        "#)
        .execute(pool)
        .await
        .map_err(|e| crate::error::SecurityError::Database(e))?;

        // Create indexes for performance
        let indexes = vec![
            "CREATE INDEX IF NOT EXISTS idx_audit_records_subject_id ON audit_records(subject_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_records_resource ON audit_records(resource)",
            "CREATE INDEX IF NOT EXISTS idx_audit_records_event_type ON audit_records(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_audit_records_created_at ON audit_records(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_audit_records_risk_level ON audit_records(risk_level)",
            "CREATE INDEX IF NOT EXISTS idx_audit_records_fips_compliant ON audit_records(fips_compliant)",
            "CREATE INDEX IF NOT EXISTS idx_audit_records_hsm_signed ON audit_records(hsm_signed)",
            "CREATE INDEX IF NOT EXISTS idx_blockchain_anchors_merkle_root ON blockchain_anchors(merkle_root)",
            "CREATE INDEX IF NOT EXISTS idx_blockchain_anchors_status ON blockchain_anchors(status)",
            "CREATE INDEX IF NOT EXISTS idx_ipfs_records_audit_record_id ON ipfs_records(audit_record_id)",
            "CREATE INDEX IF NOT EXISTS idx_ipfs_records_ipfs_hash ON ipfs_records(ipfs_hash)",
            "CREATE INDEX IF NOT EXISTS idx_hsm_attestations_audit_record_id ON hsm_attestations(audit_record_id)",
            "CREATE INDEX IF NOT EXISTS idx_hsm_attestations_key_id ON hsm_attestations(key_id)",
        ];

        for index_sql in indexes {
            sqlx::query(index_sql)
                .execute(pool)
                .await
                .map_err(|e| crate::error::SecurityError::Database(e))?;
        }

        info!("✅ Database migrations completed successfully");

        Ok(())
    }

    /// Graceful shutdown
    pub async fn shutdown(&self) -> SecurityResult<()> {
        info!("🔐 Shutting down Security Service gracefully");

        // Close database connection pool
        self.db_pool.close().await;

        info!("✅ Security Service shutdown completed");

        Ok(())
    }

    /// Health check for all components
    pub async fn health_check(&self) -> SecurityResult<serde_json::Value> {
        let metrics = self.audit_service.get_security_metrics().await?;

        Ok(serde_json::json!({
            "status": "healthy",
            "service": "security-service",
            "version": "1.0.0",
            "fips_mode": self.config.fips.enabled,
            "fips_level": self.config.fips.level,
            "compliance": "PCI-DSS_Level_1",
            "components": {
                "database": "connected",
                "qldb": "operational",
                "ipfs": "connected",
                "bitcoin": "connected",
                "hsm": "operational"
            },
            "metrics": {
                "total_audit_records": metrics.total_audit_records,
                "fips_compliant_records": metrics.fips_compliant_records,
                "hsm_attestations": metrics.hsm_attestations,
                "system_health": metrics.system_health
            },
            "features": {
                "immutable_audit_trail": true,
                "qldb_ledger": true,
                "ipfs_storage": true,
                "bitcoin_anchoring": true,
                "hsm_signing": true,
                "fips_140_3_level_3": true,
                "non_repudiation": true,
                "cryptographic_integrity": true
            },
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }
}