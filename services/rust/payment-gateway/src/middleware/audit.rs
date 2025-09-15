use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, HeaderMap, Method, Uri},
    middleware::Next,
    response::Response,
};
use tower::{Layer, Service};
use std::{
    task::{Context, Poll},
    time::Instant,
};
use tracing::{info, warn, error};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone)]
pub struct AuditMiddleware {
    security_service_url: String,
    http_client: reqwest::Client,
}

// Security Service audit request structure matching their API
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateAuditRequest {
    event_type: String,
    service_name: String,
    operation: String,
    user_id: Option<String>,
    subject_id: String,
    resource: String,
    request_data: Value,
    response_data: Value,
    client_ip: String,
    user_agent: String,
    request_id: String,
    session_id: Option<String>,
    risk_level: String,
    compliance_flags: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditResponse {
    status: String,
    message: String,
    fips_compliant: bool,
}

impl AuditMiddleware {
    pub fn new() -> Self {
        let security_service_url = std::env::var("SECURITY_SERVICE_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());
            
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client for audit middleware");
            
        info!("🔐 Audit middleware initialized with Security Service: {}", security_service_url);
        
        Self {
            security_service_url,
            http_client,
        }
    }
}

impl<S> Layer<S> for AuditMiddleware {
    type Service = AuditMiddlewareService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuditMiddlewareService {
            inner,
            security_service_url: self.security_service_url.clone(),
            http_client: self.http_client.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuditMiddlewareService<S> {
    inner: S,
    security_service_url: String,
    http_client: reqwest::Client,
}

impl<S> Service<Request> for AuditMiddlewareService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let mut inner = self.inner.clone();
        let security_service_url = self.security_service_url.clone();
        let http_client = self.http_client.clone();
        
        Box::pin(async move {
            let start_time = Instant::now();
            
            // Extract request details for audit
            let method = request.method().clone();
            let uri = request.uri().clone();
            let headers = request.headers().clone();
            
            // Extract key audit fields
            let client_ip = extract_client_ip(&headers);
            let user_agent = extract_user_agent(&headers);
            let request_id = extract_or_generate_request_id(&headers);
            let session_id = extract_session_id(&headers);
            let user_id = extract_user_id(&headers);
            
            // Capture request data (be careful with PCI data)
            let request_data = create_request_audit_data(&method, &uri, &headers);
            
            info!(
                request_id = %request_id,
                method = %method,
                uri = %uri,
                client_ip = %client_ip,
                "🔍 Processing request with audit logging"
            );
            
            // Process the actual request
            let response = inner.call(request).await?;
            
            let duration = start_time.elapsed();
            let status = response.status();
            
            // Capture response data
            let response_data = create_response_audit_data(&status, duration);
            
            // Determine risk level based on endpoint and operation
            let risk_level = determine_risk_level(&method, &uri, &status);
            
            info!(
                request_id = %request_id,
                status = %status,
                duration_ms = duration.as_millis(),
                risk_level = %risk_level,
                "✅ Request completed, sending to audit service"
            );
            
            // Send audit record to Security Service asynchronously (don't block response)
            let audit_future = send_audit_record(
                http_client,
                security_service_url,
                CreateAuditRequest {
                    event_type: "HTTP_REQUEST".to_string(),
                    service_name: "payment-gateway".to_string(),
                    operation: format!("{} {}", method, extract_operation_from_uri(&uri)),
                    user_id,
                    subject_id: format!("payment-gateway:{}", request_id),
                    resource: uri.to_string(),
                    request_data,
                    response_data,
                    client_ip,
                    user_agent,
                    request_id: request_id.clone(),
                    session_id,
                    risk_level,
                    compliance_flags: Some(serde_json::json!({
                        "pci_dss": true,
                        "duration_ms": duration.as_millis(),
                        "service": "payment-gateway"
                    })),
                },
            );
            
            // Spawn audit task to not block response
            tokio::spawn(audit_future);
            
            Ok(response)
        })
    }
}

// Helper functions for audit data extraction
fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

fn extract_or_generate_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .or_else(|| headers.get("request-id"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-session-id")
        .or_else(|| headers.get("session-id"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_user_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-user-id")
        .or_else(|| headers.get("user-id"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

fn create_request_audit_data(method: &Method, uri: &Uri, headers: &HeaderMap) -> Value {
    let mut data = serde_json::json!({
        "method": method.to_string(),
        "uri": uri.to_string(),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    // Add safe headers (exclude sensitive ones)
    let safe_headers: std::collections::HashMap<String, String> = headers
        .iter()
        .filter(|(name, _)| {
            let name_lower = name.as_str().to_lowercase();
            !name_lower.contains("authorization") 
                && !name_lower.contains("cookie")
                && !name_lower.contains("token")
                && !name_lower.contains("secret")
                && !name_lower.contains("key")
        })
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|v| (name.to_string(), v.to_string()))
        })
        .collect();
        
    data["headers"] = serde_json::to_value(safe_headers).unwrap_or_default();
    
    data
}

fn create_response_audit_data(status: &StatusCode, duration: std::time::Duration) -> Value {
    serde_json::json!({
        "status_code": status.as_u16(),
        "status_text": status.canonical_reason().unwrap_or("Unknown"),
        "duration_ms": duration.as_millis(),
        "timestamp": chrono::Utc::now().to_rfc3339()
    })
}

fn determine_risk_level(method: &Method, uri: &Uri, status: &StatusCode) -> String {
    let path = uri.path().to_lowercase();
    
    // High risk for payment operations
    if path.contains("/payments") || path.contains("/transaction") {
        if status.is_server_error() || status.is_client_error() {
            "CRITICAL".to_string()
        } else {
            "HIGH".to_string()
        }
    }
    // Medium risk for webhook operations
    else if path.contains("/webhook") {
        "MEDIUM".to_string()
    }
    // Low risk for health checks and info endpoints
    else if path.contains("/health") || path.contains("/info") || path.contains("/metrics") {
        "LOW".to_string()
    }
    // Medium risk for everything else
    else {
        "MEDIUM".to_string()
    }
}

fn extract_operation_from_uri(uri: &Uri) -> String {
    let path = uri.path();
    
    // Extract meaningful operation name from path
    if path.starts_with("/v1/payments/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 4 {
            format!("payment_{}", parts[3])
        } else {
            "payment_operation".to_string()
        }
    } else if path.starts_with("/v1/webhooks/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 4 {
            format!("webhook_{}", parts[3])
        } else {
            "webhook_operation".to_string()
        }
    } else {
        path.trim_start_matches('/').replace('/', "_")
    }
}

async fn send_audit_record(
    client: reqwest::Client,
    security_service_url: String,
    audit_request: CreateAuditRequest,
) {
    let url = format!("{}/api/v1/audit-records", security_service_url);
    
    match client
        .post(&url)
        .json(&audit_request)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<AuditResponse>().await {
                    Ok(audit_response) => {
                        info!(
                            request_id = %audit_request.request_id,
                            fips_compliant = audit_response.fips_compliant,
                            "✅ Audit record successfully sent to Security Service"
                        );
                    }
                    Err(e) => {
                        warn!(
                            request_id = %audit_request.request_id,
                            error = %e,
                            "⚠️ Failed to parse audit response from Security Service"
                        );
                    }
                }
            } else {
                warn!(
                    request_id = %audit_request.request_id,
                    status = %response.status(),
                    "⚠️ Security Service returned error for audit record"
                );
            }
        }
        Err(e) => {
            error!(
                request_id = %audit_request.request_id,
                error = %e,
                security_service_url = %security_service_url,
                "❌ Failed to send audit record to Security Service"
            );
        }
    }
}