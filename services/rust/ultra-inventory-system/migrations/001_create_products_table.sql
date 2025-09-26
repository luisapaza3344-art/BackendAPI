-- 🏆 ULTRA PRODUCTION DATABASE SCHEMA
-- SUPERIOR A AMAZON + WALMART + SHOPIFY COMBINADOS

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Products table with ultra professional features
CREATE TABLE IF NOT EXISTS products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sku VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(500) NOT NULL,
    brand VARCHAR(200),
    category VARCHAR(100) NOT NULL,
    subcategory VARCHAR(100),
    
    -- DESCRIPCIONES ULTRA PROFESIONALES
    short_description TEXT NOT NULL,
    long_description TEXT,
    technical_specifications JSONB DEFAULT '{}',
    features TEXT[] DEFAULT '{}',
    materials VARCHAR(200),
    origin_country VARCHAR(100),
    
    -- DIMENSIONES PARA SHIPPING PERFECTO
    length_cm DECIMAL(10,3),
    width_cm DECIMAL(10,3),
    height_cm DECIMAL(10,3),
    volume_cm3 DECIMAL(12,3),
    dimensional_weight_kg DECIMAL(8,3),
    
    weight_kg DECIMAL(8,3) NOT NULL,
    shipping_weight_kg DECIMAL(8,3),
    packaging_type VARCHAR(100) DEFAULT 'Standard Box',
    fragile BOOLEAN DEFAULT FALSE,
    hazardous BOOLEAN DEFAULT FALSE,
    
    -- PRECIOS INTELIGENTES
    cost_price DECIMAL(12,2) NOT NULL,
    selling_price DECIMAL(12,2) NOT NULL,
    msrp DECIMAL(12,2),
    currency VARCHAR(3) DEFAULT 'USD',
    tax_category VARCHAR(50) DEFAULT 'Standard',
    
    -- STOCK CONFIGURATION
    reorder_point INTEGER DEFAULT 10,
    max_stock INTEGER DEFAULT 1000,
    
    -- AI Y ANALYTICS
    velocity_score DECIMAL(3,1) DEFAULT 0.0,
    profitability_score DECIMAL(3,1) DEFAULT 0.0,
    stockout_risk DECIMAL(4,3) DEFAULT 0.0,
    sustainability_score DECIMAL(3,1) DEFAULT 0.0,
    
    -- STATUS Y METADATA
    status VARCHAR(20) DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'Discontinued', 'OutOfStock', 'Backordered', 'PreOrder')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID,
    tags TEXT[] DEFAULT '{}'
);

-- Product images table
CREATE TABLE IF NOT EXISTS product_images (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    url VARCHAR(1000) NOT NULL,
    alt_text VARCHAR(500),
    image_type VARCHAR(50) DEFAULT 'gallery' CHECK (image_type IN ('primary', 'gallery', 'variant', 'detail')),
    order_index INTEGER DEFAULT 1,
    width_px INTEGER,
    height_px INTEGER,
    file_size_bytes BIGINT,
    format VARCHAR(10) DEFAULT 'jpg',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Product videos table  
CREATE TABLE IF NOT EXISTS product_videos (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    url VARCHAR(1000) NOT NULL,
    title VARCHAR(300),
    video_type VARCHAR(50) DEFAULT 'product_demo' CHECK (video_type IN ('product_demo', 'unboxing', 'tutorial')),
    duration_seconds INTEGER,
    thumbnail_url VARCHAR(1000),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Product documents table
CREATE TABLE IF NOT EXISTS product_documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    url VARCHAR(1000) NOT NULL,
    title VARCHAR(300) NOT NULL,
    document_type VARCHAR(50) DEFAULT 'manual' CHECK (document_type IN ('manual', 'warranty', 'certificate', 'datasheet')),
    file_size_bytes BIGINT NOT NULL,
    format VARCHAR(10) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Warehouses table
CREATE TABLE IF NOT EXISTS warehouses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    location VARCHAR(500) NOT NULL,
    efficiency_score DECIMAL(3,2) DEFAULT 0.95,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Inventory levels table - MULTI-WAREHOUSE SUPERIOR
CREATE TABLE IF NOT EXISTS inventory_levels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    warehouse_id UUID NOT NULL REFERENCES warehouses(id) ON DELETE CASCADE,
    quantity_available INTEGER NOT NULL DEFAULT 0,
    quantity_reserved INTEGER NOT NULL DEFAULT 0,
    quantity_incoming INTEGER NOT NULL DEFAULT 0,
    location VARCHAR(100),
    bin_location VARCHAR(100),
    last_counted TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(product_id, warehouse_id)
);

-- Stock movements table for audit trail
CREATE TABLE IF NOT EXISTS stock_movements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id),
    warehouse_id UUID NOT NULL REFERENCES warehouses(id),
    movement_type VARCHAR(20) NOT NULL CHECK (movement_type IN ('IN', 'OUT', 'TRANSFER', 'ADJUSTMENT')),
    quantity INTEGER NOT NULL,
    reference VARCHAR(200),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID
);

-- Demand forecasting table (AI PREDICTIONS)
CREATE TABLE IF NOT EXISTS demand_forecasts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    next_7_days INTEGER DEFAULT 0,
    next_30_days INTEGER DEFAULT 0,
    next_90_days INTEGER DEFAULT 0,
    seasonal_factor DECIMAL(5,3) DEFAULT 1.0,
    trend_direction VARCHAR(20) DEFAULT 'Stable',
    confidence_level DECIMAL(4,3) DEFAULT 0.85,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(product_id)
);

-- Performance indexes for ultra scalability
CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_products_brand ON products(brand);
CREATE INDEX IF NOT EXISTS idx_products_status ON products(status);
CREATE INDEX IF NOT EXISTS idx_products_created_at ON products(created_at);
CREATE INDEX IF NOT EXISTS idx_inventory_levels_product_warehouse ON inventory_levels(product_id, warehouse_id);
CREATE INDEX IF NOT EXISTS idx_stock_movements_product ON stock_movements(product_id);
CREATE INDEX IF NOT EXISTS idx_product_images_product ON product_images(product_id);

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON products
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();