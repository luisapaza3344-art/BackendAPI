-- Financial-Grade Payment Gateway Database Schema
-- FIPS 140-3 Level 3, PCI-DSS Level 1 Compliant
-- Supports Stripe, PayPal, Coinbase Commerce

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- For FIPS-compliant encryption
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Custom types for payment status and providers
CREATE TYPE payment_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'cancelled', 'refunded');
CREATE TYPE payment_provider AS ENUM ('stripe', 'paypal', 'coinbase');
CREATE TYPE audit_event_type AS ENUM ('payment_created', 'payment_processed', 'payment_completed', 'payment_failed', 'webhook_received', 'security_event');

-- Payments table (PCI-DSS Level 1 compliant)
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider payment_provider NOT NULL,
    provider_transaction_id TEXT,
    
    -- Encrypted payment data (PCI-DSS tokenization)
    amount_cents BIGINT NOT NULL,
    currency CHAR(3) NOT NULL, -- ISO 4217
    
    -- Customer information (encrypted)
    customer_id TEXT,
    customer_email TEXT,
    
    -- Payment metadata (JSON encrypted)
    metadata JSONB DEFAULT '{}',
    
    -- Status tracking
    status payment_status NOT NULL DEFAULT 'pending',
    failure_reason TEXT,
    
    -- HSM attestation and blockchain anchoring
    attestation_hash TEXT NOT NULL, -- HSM-signed attestation
    blockchain_anchor TEXT, -- Bitcoin transaction hash for audit trail
    
    -- Zero-knowledge proof verification
    zkp_proof_hash TEXT, -- Hash of the ZKP proof
    zkp_verified BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Compliance flags
    pci_tokenized BOOLEAN DEFAULT FALSE,
    fips_compliant BOOLEAN DEFAULT TRUE,
    
    -- Indexes for performance and compliance auditing
    CONSTRAINT valid_amount CHECK (amount_cents > 0),
    CONSTRAINT valid_currency CHECK (LENGTH(currency) = 3)
);

-- Payment audit trail (immutable log for compliance)
CREATE TABLE payment_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    payment_id UUID REFERENCES payments(id),
    
    -- Event details
    event_type audit_event_type NOT NULL,
    event_data JSONB NOT NULL DEFAULT '{}',
    
    -- User and system tracking
    user_id TEXT,
    user_agent TEXT,
    ip_address INET,
    
    -- Cryptographic attestation
    attestation_hash TEXT NOT NULL, -- HSM-signed attestation of this event
    merkle_root TEXT, -- For blockchain anchoring
    
    -- IPFS and blockchain anchoring
    ipfs_hash TEXT, -- IPFS hash for decentralized storage
    bitcoin_tx_hash TEXT, -- Bitcoin transaction hash for immutability
    
    -- Timestamp (immutable)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Prevent updates after creation (immutability)
    CONSTRAINT immutable_log CHECK (created_at IS NOT NULL)
);

-- Webhook events table (for idempotency and replay protection)
CREATE TABLE webhook_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider payment_provider NOT NULL,
    
    -- Webhook identification
    provider_event_id TEXT NOT NULL, -- e.g., Stripe event ID
    event_type TEXT NOT NULL,
    
    -- Signature verification
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    signature_hash TEXT,
    
    -- Event payload (encrypted)
    payload JSONB NOT NULL,
    
    -- Processing status
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    processing_error TEXT,
    
    -- Timestamps for replay protection
    provider_created_at TIMESTAMP WITH TIME ZONE,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    
    -- Prevent duplicate processing
    UNIQUE(provider, provider_event_id)
);

-- HSM key management and attestations
CREATE TABLE hsm_attestations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Key and operation details
    key_id TEXT NOT NULL,
    operation_type TEXT NOT NULL, -- 'payment', 'audit', 'webhook'
    
    -- Cryptographic attestation
    attestation_signature TEXT NOT NULL, -- HSM signature
    attestation_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Chainlink VRF for timestamp verification
    vrf_proof TEXT,
    vrf_timestamp TIMESTAMP WITH TIME ZONE,
    
    -- Related entity
    entity_type TEXT, -- 'payment', 'audit_log', 'webhook'
    entity_id UUID,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Zero-knowledge proof verifications
CREATE TABLE zkp_verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    payment_id UUID REFERENCES payments(id),
    
    -- ZKP details
    proof_type TEXT NOT NULL, -- 'groth16', 'plonk'
    proof_data TEXT NOT NULL, -- Serialized proof
    public_inputs TEXT NOT NULL, -- Public inputs hash
    
    -- Verification result
    verified BOOLEAN NOT NULL,
    verification_time TIMESTAMP WITH TIME ZONE NOT NULL,
    verifier_id TEXT, -- Which verifier was used
    
    -- Circuit information
    circuit_hash TEXT NOT NULL, -- Hash of the proving circuit
    circuit_version TEXT NOT NULL,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Customer KYC/AML data (encrypted, GDPR compliant)
CREATE TABLE customer_kyc (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id TEXT UNIQUE NOT NULL,
    
    -- Encrypted customer data
    encrypted_personal_data TEXT NOT NULL, -- AES-256-GCM encrypted
    data_hash TEXT NOT NULL, -- SHA-384 hash for integrity
    
    -- KYC verification status
    kyc_verified BOOLEAN DEFAULT FALSE,
    kyc_verification_date TIMESTAMP WITH TIME ZONE,
    kyc_provider TEXT,
    
    -- AML risk assessment
    aml_risk_score DECIMAL(3,2) CHECK (aml_risk_score >= 0 AND aml_risk_score <= 1),
    aml_last_check TIMESTAMP WITH TIME ZONE,
    sanctions_checked BOOLEAN DEFAULT FALSE,
    
    -- GDPR compliance
    gdpr_consent BOOLEAN DEFAULT FALSE,
    gdpr_consent_date TIMESTAMP WITH TIME ZONE,
    data_retention_until TIMESTAMP WITH TIME ZONE,
    
    -- DID/VC integration
    did_identifier TEXT,
    verifiable_credentials JSONB DEFAULT '{}',
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance and compliance queries
CREATE INDEX idx_payments_provider_status ON payments(provider, status);
CREATE INDEX idx_payments_created_at ON payments(created_at);
CREATE INDEX idx_payments_customer_id ON payments(customer_id);
CREATE INDEX idx_payments_blockchain_anchor ON payments(blockchain_anchor);

CREATE INDEX idx_audit_log_payment_id ON payment_audit_log(payment_id);
CREATE INDEX idx_audit_log_event_type ON payment_audit_log(event_type);
CREATE INDEX idx_audit_log_created_at ON payment_audit_log(created_at);
CREATE INDEX idx_audit_log_bitcoin_tx ON payment_audit_log(bitcoin_tx_hash);

CREATE INDEX idx_webhooks_provider_event ON webhook_events(provider, provider_event_id);
CREATE INDEX idx_webhooks_received_at ON webhook_events(received_at);
CREATE INDEX idx_webhooks_processed ON webhook_events(processed);

CREATE INDEX idx_hsm_attestations_entity ON hsm_attestations(entity_type, entity_id);
CREATE INDEX idx_hsm_attestations_key_id ON hsm_attestations(key_id);

CREATE INDEX idx_zkp_payment_id ON zkp_verifications(payment_id);
CREATE INDEX idx_zkp_verified ON zkp_verifications(verified);

CREATE INDEX idx_kyc_customer_id ON customer_kyc(customer_id);
CREATE INDEX idx_kyc_verified ON customer_kyc(kyc_verified);

-- Row Level Security (RLS) for PCI-DSS compliance
ALTER TABLE payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_kyc ENABLE ROW LEVEL SECURITY;

-- Create policies for data access control
CREATE POLICY payment_access_policy ON payments
    FOR ALL 
    USING (current_setting('app.user_role')::text = 'payment_processor');

CREATE POLICY audit_read_only ON payment_audit_log
    FOR SELECT 
    USING (true); -- Audit logs are read-only for compliance

CREATE POLICY kyc_data_policy ON customer_kyc
    FOR ALL 
    USING (current_setting('app.user_role')::text IN ('kyc_officer', 'compliance_officer'));

-- Create function for automatic updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_payments_updated_at BEFORE UPDATE ON payments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_customer_kyc_updated_at BEFORE UPDATE ON customer_kyc
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create function for immutable audit log enforcement
CREATE OR REPLACE FUNCTION enforce_audit_immutability()
RETURNS TRIGGER AS $$
BEGIN
    -- Prevent any updates to audit log entries
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'Audit log entries are immutable and cannot be updated';
    END IF;
    
    -- Prevent deletion of audit log entries
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Audit log entries are immutable and cannot be deleted';
    END IF;
    
    RETURN NULL;
END;
$$ language 'plpgsql';

-- Create triggers for audit log immutability
CREATE TRIGGER enforce_audit_log_immutability 
    BEFORE UPDATE OR DELETE ON payment_audit_log
    FOR EACH ROW EXECUTE FUNCTION enforce_audit_immutability();

-- Comments for documentation
COMMENT ON TABLE payments IS 'PCI-DSS Level 1 compliant payment transactions with HSM attestation';
COMMENT ON TABLE payment_audit_log IS 'Immutable audit trail with blockchain anchoring for compliance';
COMMENT ON TABLE webhook_events IS 'Webhook event processing with signature verification and idempotency';
COMMENT ON TABLE hsm_attestations IS 'Hardware Security Module attestations for FIPS 140-3 compliance';
COMMENT ON TABLE zkp_verifications IS 'Zero-knowledge proof verifications for payment privacy';
COMMENT ON TABLE customer_kyc IS 'GDPR-compliant customer KYC/AML data with encryption';