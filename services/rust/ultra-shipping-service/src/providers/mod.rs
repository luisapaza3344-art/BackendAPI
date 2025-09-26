use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use anyhow::Result;

pub mod dhl;
pub mod ups;
pub mod usps;
pub mod fedex;

use crate::{Address, PackageDetails};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShippingRequest {
    pub from_address: Address,
    pub to_address: Address,
    pub package: PackageDetails,
    pub service_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShippingQuote {
    pub service_name: String,
    pub service_code: String,
    pub rate: Decimal,
    pub currency: String,
    pub estimated_delivery: DateTime<Utc>,
    pub guaranteed_delivery: Option<DateTime<Utc>>,
    pub transit_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingInfo {
    pub tracking_number: String,
    pub status: String,
    pub location: Option<String>,
    pub estimated_delivery: Option<DateTime<Utc>>,
    pub events: Vec<TrackingEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingEvent {
    pub timestamp: DateTime<Utc>,
    pub status: String,
    pub location: String,
    pub description: String,
}

#[async_trait]
pub trait ShippingProvider: Send + Sync {
    async fn get_rates(&self, request: ShippingRequest) -> Result<ShippingQuote>;
    async fn create_shipment(&self, request: ShippingRequest) -> Result<String>;
    async fn track_package(&self, tracking_number: &str) -> Result<TrackingInfo>;
    async fn cancel_shipment(&self, tracking_number: &str) -> Result<bool>;
    fn provider_name(&self) -> &str;
}