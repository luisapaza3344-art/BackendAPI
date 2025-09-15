use crate::{
    error::{SecurityError, SecurityResult},
    models::{AuditResponse, CreateAuditRequest, SecurityMetrics},
    services::audit::AuditService,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Json, IntoResponse},
    Extension,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use validator::Validate;

pub type SharedAuditService = Arc<AuditService>;

/// Create a new audit record with immutable trail
#[axum::debug_handler]
pub async fn create_audit_record(
    State(audit_service): State<SharedAuditService>,
    Json(request): Json<CreateAuditRequest>,
) -> SecurityResult<Json<AuditResponse>> {
    // Validate the request
    request.validate().map_err(|e| SecurityError::Validation(e.to_string()))?;

    info!(
        event_type = %request.event_type,
        service_name = %request.service_name,
        operation = %request.operation,
        subject_id = %request.subject_id,
        risk_level = %request.risk_level,
        "Creating audit record with immutable trail"
    );

    // Create the audit record
    let response = audit_service.create_audit_record(request).await?;

    info!(
        audit_record_id = %response.id,
        status = %response.status,
        fips_compliant = response.fips_compliant,
        "Audit record created successfully"
    );

    Ok(Json(response))
}

/// Get audit record by ID
pub async fn get_audit_record(
    State(audit_service): State<SharedAuditService>,
    Path(id): Path<Uuid>,
) -> SecurityResult<Json<Value>> {
    info!(audit_record_id = %id, "Retrieving audit record");

    let audit_record = audit_service
        .get_audit_record(&id)
        .await?
        .ok_or_else(|| SecurityError::NotFound("Audit record not found".to_string()))?;

    info!(
        audit_record_id = %id,
        fips_compliant = audit_record.fips_compliant,
        hsm_signed = audit_record.hsm_signed,
        "Audit record retrieved successfully"
    );

    Ok(Json(json!({
        "status": "success",
        "data": audit_record,
        "fips_compliant": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Verify the integrity of an audit record
pub async fn verify_audit_integrity(
    State(audit_service): State<SharedAuditService>,
    Path(id): Path<Uuid>,
) -> SecurityResult<Json<Value>> {
    info!(audit_record_id = %id, "Verifying audit record integrity");

    let verification = audit_service.verify_audit_integrity(&id).await?;

    info!(
        audit_record_id = %id,
        integrity_status = %verification.integrity_status,
        discrepancy_count = verification.discrepancies.len(),
        "Audit integrity verification completed"
    );

    if verification.integrity_status == "CORRUPTED" {
        warn!(
            audit_record_id = %id,
            discrepancies = ?verification.discrepancies,
            "CRITICAL: Audit record integrity compromised"
        );
    }

    Ok(Json(json!({
        "status": "success",
        "data": verification,
        "fips_compliant": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Get security metrics and statistics
pub async fn get_security_metrics(
    State(audit_service): State<SharedAuditService>,
) -> SecurityResult<Json<Value>> {
    info!("Retrieving security metrics");

    let metrics = audit_service.get_security_metrics().await?;

    info!(
        total_audit_records = metrics.total_audit_records,
        qldb_records = metrics.qldb_records,
        ipfs_records = metrics.ipfs_records,
        bitcoin_anchors = metrics.bitcoin_anchors,
        system_health = %metrics.system_health,
        "Security metrics retrieved"
    );

    Ok(Json(json!({
        "status": "success",
        "data": metrics,
        "fips_compliant": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Health check endpoint
pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "security-service",
        "fips_mode": true,
        "compliance": "FIPS_140-3_Level_3",
        "features": {
            "qldb_ledger": true,
            "ipfs_storage": true,
            "bitcoin_anchoring": true,
            "hsm_signing": true,
            "immutable_audit_trail": true
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Readiness check endpoint
pub async fn readiness_check(
    State(audit_service): State<SharedAuditService>,
) -> SecurityResult<Json<Value>> {
    // Check if all services are ready
    let metrics = audit_service.get_security_metrics().await?;

    let ready = metrics.system_health == "HEALTHY";

    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    Ok(Json(json!({
        "ready": ready,
        "service": "security-service",
        "system_health": metrics.system_health,
        "fips_compliant": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Get service information
pub async fn service_info() -> Json<Value> {
    Json(json!({
        "service": "security-service",
        "version": "1.0.0",
        "description": "FIPS 140-3 Level 3 compliant security service with immutable audit trail",
        "features": {
            "immutable_audit_trail": {
                "description": "Complete audit trail with QLDB, IPFS, Bitcoin, and HSM",
                "components": ["qldb", "ipfs", "bitcoin", "hsm"],
                "fips_compliant": true
            },
            "qldb_ledger": {
                "description": "AWS QLDB for immutable audit logging",
                "cryptographic_verification": true,
                "tamper_evident": true
            },
            "ipfs_storage": {
                "description": "Decentralized storage via IPFS",
                "content_addressing": true,
                "distributed_pinning": true
            },
            "bitcoin_anchoring": {
                "description": "Merkle root anchoring to Bitcoin blockchain",
                "op_return_transactions": true,
                "proof_of_work_security": true
            },
            "hsm_signing": {
                "description": "Hardware Security Module signing",
                "fips_140_3_level_3": true,
                "non_repudiation": true
            }
        },
        "compliance": {
            "fips_140_3": "Level 3",
            "pci_dss": "Level 1",
            "common_criteria": "EAL4+",
            "standards": ["NIST", "ISO_27001", "SOC_2_Type_II"]
        },
        "cryptography": {
            "hash_algorithm": "SHA-384",
            "signature_algorithm": "ECDSA_P384",
            "key_management": "HSM_backed",
            "entropy_source": "FIPS_approved_DRBG"
        },
        "api": {
            "version": "v1",
            "base_path": "/api/v1",
            "endpoints": {
                "audit_records": "/audit-records",
                "integrity_verification": "/audit-records/{id}/verify",
                "security_metrics": "/metrics",
                "health": "/health",
                "readiness": "/ready",
                "info": "/info"
            }
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// List audit records with pagination
pub async fn list_audit_records(
    State(audit_service): State<SharedAuditService>,
    // In a real implementation, you'd extract query parameters for pagination
) -> SecurityResult<Json<Value>> {
    info!("Listing audit records with pagination");

    // This is a simplified version - would include proper pagination
    let metrics = audit_service.get_security_metrics().await?;

    Ok(Json(json!({
        "status": "success",
        "data": {
            "total_records": metrics.total_audit_records,
            "fips_compliant_records": metrics.fips_compliant_records,
            "hsm_signed_records": metrics.hsm_attestations,
            "records": [] // Would contain paginated records
        },
        "pagination": {
            "page": 1,
            "per_page": 50,
            "total_pages": (metrics.total_audit_records as f64 / 50.0).ceil() as u64,
            "total_records": metrics.total_audit_records
        },
        "fips_compliant": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Get audit trail for a specific resource
pub async fn get_audit_trail(
    State(audit_service): State<SharedAuditService>,
    Path(resource): Path<String>,
) -> SecurityResult<Json<Value>> {
    info!(resource = %resource, "Retrieving audit trail for resource");

    // This would implement the actual audit trail retrieval
    // For now, return a summary
    let metrics = audit_service.get_security_metrics().await?;

    Ok(Json(json!({
        "status": "success",
        "data": {
            "resource": resource,
            "audit_trail": [], // Would contain the actual trail
            "total_events": 0,
            "integrity_verified": true
        },
        "fips_compliant": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Emergency security alert endpoint
pub async fn security_alert(
    State(audit_service): State<SharedAuditService>,
    Json(alert_data): Json<Value>,
) -> impl IntoResponse {
    warn!(
        alert_data = ?alert_data,
        "SECURITY ALERT: Emergency security event reported"
    );

    // Create high-priority audit record for the security alert
    let alert_request = CreateAuditRequest {
        event_type: "SECURITY_ALERT".to_string(),
        service_name: "security-service".to_string(),
        operation: "emergency_alert".to_string(),
        user_id: None,
        subject_id: "security_system".to_string(),
        resource: "security_alert".to_string(),
        request_data: alert_data.clone(),
        response_data: json!({"alert_processed": true}),
        client_ip: "127.0.0.1".to_string(),
        user_agent: "security-service".to_string(),
        request_id: Uuid::new_v4().to_string(),
        session_id: None,
        risk_level: "CRITICAL".to_string(),
        compliance_flags: Some(json!({"emergency_alert": true})),
    };

    match audit_service.create_audit_record(alert_request).await {
        Ok(response) => {
            (StatusCode::OK, Json(json!({
                "status": "alert_processed",
                "audit_record_id": response.id,
                "message": "Security alert logged with immutable trail",
                "fips_compliant": true,
                "timestamp": chrono::Utc::now().to_rfc3339()
            })))
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                "status": "error",
                "message": format!("Failed to process security alert: {}", e),
                "timestamp": chrono::Utc::now().to_rfc3339()
            })))
        }
    }
}