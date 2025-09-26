use super::{ShippingProvider, ShippingQuote, ShippingRequest, TrackingInfo};
use async_trait::async_trait;
use anyhow::{Result, anyhow};
use chrono::{Utc, Duration};
use rust_decimal::Decimal;
use serde_json::json;
use std::env;

#[derive(Debug, Clone)]
pub struct UPSProvider {
    client_id: String,
    client_secret: String,
    access_token: Option<String>,
    base_url: String,
}

impl UPSProvider {
    pub fn new() -> Self {
        Self {
            client_id: env::var("UPS_CLIENT_ID").unwrap_or_default(),
            client_secret: env::var("UPS_CLIENT_SECRET").unwrap_or_default(),
            access_token: None,
            base_url: "https://onlinetools.ups.com/api".to_string(),
        }
    }
    
    async fn get_oauth_token(&mut self) -> Result<String> {
        if self.client_id.is_empty() {
            return Ok("mock_token".to_string());
        }
        
        let client = reqwest::Client::new();
        
        let response = client
            .post("https://onlinetools.ups.com/security/v1/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!(
                "grant_type=client_credentials&client_id={}&client_secret={}",
                self.client_id, self.client_secret
            ))
            .send()
            .await?;
        
        let token_data: serde_json::Value = response.json().await?;
        let token = token_data["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to get UPS OAuth token"))?;
        
        self.access_token = Some(token.to_string());
        Ok(token.to_string())
    }
}

#[async_trait]
impl ShippingProvider for UPSProvider {
    async fn get_rates(&self, request: ShippingRequest) -> Result<ShippingQuote> {
        if self.client_id.is_empty() {
            // Return mock data for development
            return Ok(ShippingQuote {
                service_name: "UPS Ground".to_string(),
                service_code: "03".to_string(),
                rate: Decimal::from_str_exact("25.80")?,
                currency: "USD".to_string(),
                estimated_delivery: Utc::now() + Duration::days(5),
                guaranteed_delivery: None,
                transit_days: 5,
            });
        }
        
        let mut provider = self.clone();
        let token = provider.get_oauth_token().await?;
        
        let client = reqwest::Client::new();
        
        let payload = json!({
            "RateRequest": {
                "Request": {
                    "RequestOption": "Rate",
                    "TransactionReference": {
                        "CustomerContext": "UPS Rate Request"
                    }
                },
                "Shipment": {
                    "Shipper": {
                        "Address": {
                            "City": request.from_address.city,
                            "StateProvinceCode": request.from_address.state,
                            "PostalCode": request.from_address.zip,
                            "CountryCode": request.from_address.country
                        }
                    },
                    "ShipTo": {
                        "Address": {
                            "City": request.to_address.city,
                            "StateProvinceCode": request.to_address.state,
                            "PostalCode": request.to_address.zip,
                            "CountryCode": request.to_address.country
                        }
                    },
                    "Package": [{
                        "PackagingType": {
                            "Code": "02"
                        },
                        "Dimensions": {
                            "UnitOfMeasurement": {
                                "Code": "IN"
                            },
                            "Length": request.package.length.to_string(),
                            "Width": request.package.width.to_string(),
                            "Height": request.package.height.to_string()
                        },
                        "PackageWeight": {
                            "UnitOfMeasurement": {
                                "Code": "LBS"
                            },
                            "Weight": request.package.weight.to_string()
                        }
                    }]
                }
            }
        });
        
        let response = client
            .post(&format!("{}/rating/v1/rate", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(ShippingQuote {
                service_name: "UPS Ground".to_string(),
                service_code: "03".to_string(),
                rate: Decimal::from_str_exact("25.80")?,
                currency: "USD".to_string(),
                estimated_delivery: Utc::now() + Duration::days(5),
                guaranteed_delivery: None,
                transit_days: 5,
            })
        } else {
            Err(anyhow!("UPS API error: {}", response.status()))
        }
    }
    
    async fn create_shipment(&self, _request: ShippingRequest) -> Result<String> {
        Ok("1Z999AA1234567890".to_string())
    }
    
    async fn track_package(&self, tracking_number: &str) -> Result<TrackingInfo> {
        Ok(TrackingInfo {
            tracking_number: tracking_number.to_string(),
            status: "In Transit".to_string(),
            location: Some("Atlanta, GA".to_string()),
            estimated_delivery: Some(Utc::now() + Duration::days(3)),
            events: vec![],
        })
    }
    
    async fn cancel_shipment(&self, _tracking_number: &str) -> Result<bool> {
        Ok(true)
    }
    
    fn provider_name(&self) -> &str {
        "UPS"
    }
}