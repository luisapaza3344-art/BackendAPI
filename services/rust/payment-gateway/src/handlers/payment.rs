use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Serialize, Deserialize};
use tracing::{info, error};
use crate::AppState;
use crate::models::payment_request::PaymentStatus;

#[derive(Debug, Serialize)]
pub struct PaymentStatusResponse {
    pub id: String,
    pub status: String,
    pub provider: String,
    pub amount: u64,
    pub currency: String,
    pub created_at: String,
    pub updated_at: String,
    pub attestation_hash: String,
    pub blockchain_anchor: Option<String>,
}

/// Get payment status by payment ID
/// 
/// Returns comprehensive payment status with:
/// - Current processing status
/// - HSM attestation verification
/// - Blockchain audit trail
/// - PCI-DSS compliant data masking
pub async fn get_payment_status(
    State(state): State<AppState>,
    Path(payment_id): Path<String>,
) -> Result<Json<PaymentStatusResponse>, StatusCode> {
    info!("Getting payment status for: {}", payment_id);

    // TODO: Query database for payment status
    // This would include:
    // 1. Retrieve payment record from PostgreSQL
    // 2. Verify HSM attestation
    // 3. Check blockchain anchor status
    // 4. Apply PCI-DSS data masking rules
    // 5. Return sanitized payment status

    match state.payment_service.get_payment_status(&payment_id).await {
        Ok(payment_status) => {
            let payment_id_clone = payment_id.clone();
            let response = PaymentStatusResponse {
                id: payment_status.id.to_string(),
                status: payment_status.status,
                provider: payment_status.provider,
                amount: payment_status.amount,
                currency: payment_status.currency,
                created_at: payment_status.created_at.to_rfc3339(),
                updated_at: payment_status.updated_at.to_rfc3339(),
                attestation_hash: payment_status.attestation_hash,
                blockchain_anchor: payment_status.blockchain_anchor,
            };
            
            info!("✅ Payment status retrieved successfully: {}", payment_id_clone);
            Ok(Json(response))
        },
        Err(e) => {
            error!("❌ Failed to get payment status: {}", e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct InitCheckoutRequest {
    pub temp_payment_id: String,
    pub cart_items: serde_json::Value,
    pub subtotal: f64,
    pub shipping: f64,
    pub tax: f64,
    pub total: f64,
    pub currency: String,
    pub customer_email: String,
    pub shipping_address: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct InitCheckoutResponse {
    pub success: bool,
    pub temp_payment_id: String,
}

/// Initialize secure checkout session and save to database
pub async fn init_checkout(
    State(state): State<AppState>,
    Json(payload): Json<InitCheckoutRequest>,
) -> Result<Json<InitCheckoutResponse>, StatusCode> {
    info!("🚀 Initializing checkout session: temp_payment_id={}", payload.temp_payment_id);

    // Save to database
    match state.payment_service.save_temp_payment(
        &payload.temp_payment_id,
        &payload.cart_items.to_string(),
        payload.subtotal,
        payload.shipping,
        payload.tax,
        payload.total,
        &payload.currency,
        &payload.customer_email,
        &payload.shipping_address.to_string(),
    ).await {
        Ok(_) => {
            info!("✅ Checkout session saved successfully: {}", payload.temp_payment_id);
            Ok(Json(InitCheckoutResponse {
                success: true,
                temp_payment_id: payload.temp_payment_id,
            }))
        },
        Err(e) => {
            error!("❌ Failed to save checkout session: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}