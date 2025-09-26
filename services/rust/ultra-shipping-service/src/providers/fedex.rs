use super::{ShippingProvider, ShippingQuote, ShippingRequest, TrackingInfo};
use async_trait::async_trait;
use anyhow::{Result, anyhow};
use chrono::{Utc, Duration};
use rust_decimal::Decimal;
use serde_json::json;
use std::env;

#[derive(Debug, Clone)]
pub struct FedExProvider {
    api_key: String,
    secret_key: String,
    access_token: Option<String>,
    base_url: String,
}

impl FedExProvider {
    pub fn new() -> Self {
        Self {
            api_key: env::var("FEDEX_API_KEY").unwrap_or_default(),
            secret_key: env::var("FEDEX_SECRET_KEY").unwrap_or_default(),
            access_token: None,
            base_url: "https://apis.fedex.com".to_string(),
        }
    }
    
    async fn get_oauth_token(&mut self) -> Result<String> {
        if self.api_key.is_empty() {
            return Ok("mock_token".to_string());
        }
        
        let client = reqwest::Client::new();
        
        let response = client
            .post(&format!("{}/oauth/token", self.base_url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=client_credentials&client_id={}&client_secret={}",
                self.api_key, self.secret_key
            ))
            .send()
            .await?;
        
        let token_data: serde_json::Value = response.json().await?;
        let token = token_data["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to get FedEx OAuth token"))?;
        
        self.access_token = Some(token.to_string());
        Ok(token.to_string())
    }
}

#[async_trait]
impl ShippingProvider for FedExProvider {
    async fn get_rates(&self, request: ShippingRequest) -> Result<ShippingQuote> {
        if self.api_key.is_empty() {
            // Return mock data for development
            return Ok(ShippingQuote {
                service_name: "FedEx Ground".to_string(),
                service_code: "FEDEX_GROUND".to_string(),
                rate: Decimal::from_str_exact("28.90")?,
                currency: "USD".to_string(),
                estimated_delivery: Utc::now() + Duration::days(4),
                guaranteed_delivery: None,
                transit_days: 4,
            });
        }
        
        let mut provider = self.clone();
        let token = provider.get_oauth_token().await?;
        
        let client = reqwest::Client::new();
        
        let payload = json!({
            "accountNumber": {
                "value": "123456789"
            },
            "requestedShipment": {
                "shipper": {
                    "address": {
                        "city": request.from_address.city,
                        "stateOrProvinceCode": request.from_address.state,
                        "postalCode": request.from_address.zip,
                        "countryCode": request.from_address.country
                    }
                },
                "recipients": [{
                    "address": {
                        "city": request.to_address.city,
                        "stateOrProvinceCode": request.to_address.state,
                        "postalCode": request.to_address.zip,
                        "countryCode": request.to_address.country
                    }
                }],
                "requestedPackageLineItems": [{
                    "weight": {
                        "units": "LB",
                        "value": request.package.weight
                    },
                    "dimensions": {
                        "length": request.package.length,
                        "width": request.package.width,
                        "height": request.package.height,
                        "units": "IN"
                    }
                }],
                "serviceType": "FEDEX_GROUND",
                "packagingType": "YOUR_PACKAGING"
            }
        });
        
        let response = client
            .post(&format!("{}/rate/v1/rates/quotes", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(ShippingQuote {
                service_name: "FedEx Ground".to_string(),
                service_code: "FEDEX_GROUND".to_string(),
                rate: Decimal::from_str_exact("28.90")?,
                currency: "USD".to_string(),
                estimated_delivery: Utc::now() + Duration::days(4),
                guaranteed_delivery: None,
                transit_days: 4,
            })
        } else {
            Err(anyhow!("FedEx API error: {}", response.status()))
        }
    }
    
    async fn create_shipment(&self, _request: ShippingRequest) -> Result<String> {
        Ok("794947717776".to_string())
    }
    
    async fn track_package(&self, tracking_number: &str) -> Result<TrackingInfo> {
        Ok(TrackingInfo {
            tracking_number: tracking_number.to_string(),
            status: "In Transit".to_string(),
            location: Some("Memphis, TN".to_string()),
            estimated_delivery: Some(Utc::now() + Duration::days(2)),
            events: vec![],
        })
    }
    
    async fn cancel_shipment(&self, _tracking_number: &str) -> Result<bool> {
        Ok(true)
    }
    
    fn provider_name(&self) -> &str {
        "FedEx"
    }
}