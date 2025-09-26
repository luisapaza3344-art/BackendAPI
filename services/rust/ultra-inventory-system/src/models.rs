use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use rust_decimal::Decimal;

// Import all models that are used in main.rs
pub use crate::{
    Product, ProductDimensions, InventoryItem, DemandForecast,
    SustainabilityMetrics, StockoutPrediction, PurchaseRecommendation
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Warehouse {
    pub id: Uuid,
    pub name: String,
    pub code: String,
    pub address: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub postal_code: String,
    pub manager: Option<String>,
    pub capacity: Option<i32>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Supplier {
    pub id: Uuid,
    pub name: String,
    pub contact_person: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: String,
    pub lead_time_days: i32,
    pub reliability_score: f64,
    pub quality_score: f64,
    pub cost_rating: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InventoryMovement {
    pub id: Uuid,
    pub product_id: Uuid,
    pub warehouse_id: Uuid,
    pub movement_type: String, // "IN", "OUT", "TRANSFER", "ADJUSTMENT"
    pub quantity: i32,
    pub reference_number: Option<String>,
    pub reason: Option<String>,
    pub user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PurchaseOrder {
    pub id: Uuid,
    pub supplier_id: Uuid,
    pub warehouse_id: Uuid,
    pub order_number: String,
    pub status: String,
    pub total_amount: Decimal,
    pub currency: String,
    pub expected_delivery: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PurchaseOrderItem {
    pub id: Uuid,
    pub purchase_order_id: Uuid,
    pub product_id: Uuid,
    pub quantity_ordered: i32,
    pub quantity_received: i32,
    pub unit_cost: Decimal,
    pub total_cost: Decimal,
}