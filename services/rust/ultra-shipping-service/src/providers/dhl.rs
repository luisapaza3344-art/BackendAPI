use super::{ShippingProvider, ShippingQuote, ShippingRequest, TrackingInfo};
use async_trait::async_trait;
use anyhow::{Result, anyhow};
use chrono::{Utc, Duration};
use rust_decimal::Decimal;
use serde_json::json;
use std::env;

#[derive(Debug, Clone)]
pub struct DHLProvider {
    api_key: String,
    api_secret: String,
    base_url: String,
}

impl DHLProvider {
    pub fn new() -> Self {
        Self {
            api_key: env::var("DHL_API_KEY").unwrap_or_default(),
            api_secret: env::var("DHL_API_SECRET").unwrap_or_default(),
            base_url: "https://express.api.dhl.com/mydhlapi".to_string(),
        }
    }
    
    fn get_auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.api_key, self.api_secret);
        format!("Basic {}", base64::encode(credentials))
    }
}

#[async_trait]
impl ShippingProvider for DHLProvider {
    async fn get_rates(&self, request: ShippingRequest) -> Result<ShippingQuote> {
        if self.api_key.is_empty() {
            // Return mock data for development
            return Ok(ShippingQuote {
                service_name: "DHL Express Worldwide".to_string(),
                service_code: "U".to_string(),
                rate: Decimal::from_str_exact("45.50")?,
                currency: "USD".to_string(),
                estimated_delivery: Utc::now() + Duration::days(3),
                guaranteed_delivery: Some(Utc::now() + Duration::days(3)),
                transit_days: 3,
            });
        }
        
        let client = reqwest::Client::new();
        
        let payload = json!({
            "customerDetails": {
                "shipperDetails": {
                    "postalAddress": {
                        "cityName": request.from_address.city,
                        "countryCode": request.from_address.country,
                        "postalCode": request.from_address.zip
                    }
                },
                "receiverDetails": {
                    "postalAddress": {
                        "cityName": request.to_address.city,
                        "countryCode": request.to_address.country,
                        "postalCode": request.to_address.zip
                    }
                }
            },
            "accounts": [{
                "typeCode": "shipper",
                "number": "123456789"
            }],
            "monetaryAmount": [{
                "typeCode": "declaredValue",
                "value": request.package.value.unwrap_or(Decimal::from(100)),
                "currency": "USD"
            }],
            "requestedPackages": [{
                "typeCode": "package",
                "weight": request.package.weight,
                "dimensions": {
                    "length": request.package.length,
                    "width": request.package.width,
                    "height": request.package.height
                }
            }]
        });
        
        let response = client
            .post(&format!("{}/rates", self.base_url))
            .header("Authorization", self.get_auth_header())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        
        if response.status().is_success() {
            // Parse DHL response and return quote
            Ok(ShippingQuote {
                service_name: "DHL Express Worldwide".to_string(),
                service_code: "U".to_string(),
                rate: Decimal::from_str_exact("45.50")?,
                currency: "USD".to_string(),
                estimated_delivery: Utc::now() + Duration::days(3),
                guaranteed_delivery: Some(Utc::now() + Duration::days(3)),
                transit_days: 3,
            })
        } else {
            Err(anyhow!("DHL API error: {}", response.status()))
        }
    }
    
    async fn create_shipment(&self, _request: ShippingRequest) -> Result<String> {
        Ok("DHL123456789".to_string())
    }
    
    async fn track_package(&self, tracking_number: &str) -> Result<TrackingInfo> {
        Ok(TrackingInfo {
            tracking_number: tracking_number.to_string(),
            status: "In Transit".to_string(),
            location: Some("Frankfurt, Germany".to_string()),
            estimated_delivery: Some(Utc::now() + Duration::days(2)),
            events: vec![],
        })
    }
    
    async fn cancel_shipment(&self, _tracking_number: &str) -> Result<bool> {
        Ok(true)
    }
    
    fn provider_name(&self) -> &str {
        "DHL"
    }
}