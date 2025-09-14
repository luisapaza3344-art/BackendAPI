-- Migration: 001_initial_schema.sql
-- Description: Create initial payment gateway schema with FIPS 140-3 and PCI-DSS compliance
-- Date: 2025-09-14
-- Author: Financial Security Team

BEGIN;

-- This migration creates the foundational schema for the payment gateway
-- with enterprise-grade security and compliance features

\i '../schema.sql'

-- Verify critical extensions are enabled
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'uuid-ossp') THEN
        RAISE EXCEPTION 'uuid-ossp extension is required for payment gateway';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') THEN
        RAISE EXCEPTION 'pgcrypto extension is required for FIPS compliance';
    END IF;
END$$;

-- Insert initial system configuration
INSERT INTO hsm_attestations (
    key_id,
    operation_type,
    attestation_signature,
    attestation_timestamp,
    entity_type
) VALUES (
    'system-init-key',
    'system_initialization',
    'INIT_ATTESTATION_PLACEHOLDER',
    NOW(),
    'system'
);

COMMIT;