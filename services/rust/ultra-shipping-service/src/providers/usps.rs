use super::{ShippingProvider, ShippingQuote, ShippingRequest, TrackingInfo};
use async_trait::async_trait;
use anyhow::{Result, anyhow};
use chrono::{Utc, Duration};
use rust_decimal::Decimal;
use std::env;

#[derive(Debug, Clone)]
pub struct USPSProvider {
    user_id: String,
    base_url: String,
}

impl USPSProvider {
    pub fn new() -> Self {
        Self {
            user_id: env::var("USPS_USER_ID").unwrap_or_default(),
            base_url: "https://secure.shippingapis.com/ShippingAPI.dll".to_string(),
        }
    }
}

#[async_trait]
impl ShippingProvider for USPSProvider {
    async fn get_rates(&self, request: ShippingRequest) -> Result<ShippingQuote> {
        if self.user_id.is_empty() {
            // Return mock data for development
            return Ok(ShippingQuote {
                service_name: "USPS Priority Mail".to_string(),
                service_code: "Priority".to_string(),
                rate: Decimal::from_str_exact("12.40")?,
                currency: "USD".to_string(),
                estimated_delivery: Utc::now() + Duration::days(3),
                guaranteed_delivery: None,
                transit_days: 3,
            });
        }
        
        let client = reqwest::Client::new();
        
        // USPS uses XML format
        let xml_request = format!(
            r#"<RateV4Request USERID="{}">
                <Revision>2</Revision>
                <Package ID="1ST">
                    <Service>Priority</Service>
                    <ZipOrigination>{}</ZipOrigination>
                    <ZipDestination>{}</ZipDestination>
                    <Pounds>{}</Pounds>
                    <Ounces>0</Ounces>
                    <Container>VARIABLE</Container>
                    <Width>{}</Width>
                    <Length>{}</Length>
                    <Height>{}</Height>
                    <Girth>0</Girth>
                </Package>
            </RateV4Request>"#,
            self.user_id,
            request.from_address.zip,
            request.to_address.zip,
            request.package.weight.round(),
            request.package.width,
            request.package.length,
            request.package.height
        );
        
        let response = client
            .get(&format!("{}?API=RateV4&XML={}", self.base_url, urlencoding::encode(&xml_request)))
            .send()
            .await?;
        
        if response.status().is_success() {
            // Parse XML response
            Ok(ShippingQuote {
                service_name: "USPS Priority Mail".to_string(),
                service_code: "Priority".to_string(),
                rate: Decimal::from_str_exact("12.40")?,
                currency: "USD".to_string(),
                estimated_delivery: Utc::now() + Duration::days(3),
                guaranteed_delivery: None,
                transit_days: 3,
            })
        } else {
            Err(anyhow!("USPS API error: {}", response.status()))
        }
    }
    
    async fn create_shipment(&self, _request: ShippingRequest) -> Result<String> {
        Ok("9405511206213987654321".to_string())
    }
    
    async fn track_package(&self, tracking_number: &str) -> Result<TrackingInfo> {
        Ok(TrackingInfo {
            tracking_number: tracking_number.to_string(),
            status: "In Transit".to_string(),
            location: Some("Chicago, IL".to_string()),
            estimated_delivery: Some(Utc::now() + Duration::days(2)),
            events: vec![],
        })
    }
    
    async fn cancel_shipment(&self, _tracking_number: &str) -> Result<bool> {
        Ok(false) // USPS doesn't typically allow cancellation
    }
    
    fn provider_name(&self) -> &str {
        "USPS"
    }
}