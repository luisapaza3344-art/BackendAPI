use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use rust_decimal::Decimal;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShipmentRecord {
    pub id: Uuid,
    pub tracking_number: String,
    pub provider: String,
    pub service_code: String,
    pub from_address: serde_json::Value,
    pub to_address: serde_json::Value,
    pub package_details: serde_json::Value,
    pub rate: Decimal,
    pub currency: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrackingUpdate {
    pub id: Uuid,
    pub shipment_id: Uuid,
    pub status: String,
    pub location: Option<String>,
    pub description: String,
    pub event_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShippingAnalytics {
    pub total_shipments: i64,
    pub total_revenue: Decimal,
    pub average_cost: Decimal,
    pub provider_performance: serde_json::Value,
    pub cost_savings: Decimal,
    pub carbon_footprint_reduction: Decimal,
    pub generated_at: DateTime<Utc>,
}