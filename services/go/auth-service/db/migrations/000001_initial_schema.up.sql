-- Initial FIPS-compliant schema for Auth Service
-- Migration: 000001_initial_schema

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users table with FIPS compliance
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    fips_compliant BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- DID Documents table
CREATE TABLE IF NOT EXISTS did_documents (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    method VARCHAR(50) NOT NULL,
    document TEXT NOT NULL,
    private_key_jwk TEXT,
    public_key_jwk TEXT NOT NULL,
    key_type VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    fips_compliant BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_did_documents_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Verifiable Credentials table
CREATE TABLE IF NOT EXISTS verifiable_credentials (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    did_document_id VARCHAR(255) NOT NULL,
    issuer_did VARCHAR(255) NOT NULL,
    subject_did VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    credential TEXT NOT NULL,
    proof TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    expires_at TIMESTAMPTZ,
    fips_compliant BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_verifiable_credentials_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_verifiable_credentials_did_document_id FOREIGN KEY (did_document_id) REFERENCES did_documents(id) ON DELETE CASCADE
);

-- WebAuthn Credentials table
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    transport VARCHAR(50) NOT NULL,
    authenticator_data BYTEA NOT NULL,
    client_data_json BYTEA NOT NULL,
    sign_count INTEGER NOT NULL,
    clone_warning BOOLEAN DEFAULT FALSE,
    device_name VARCHAR(255),
    is_passkey BOOLEAN DEFAULT FALSE,
    fips_compliant BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    CONSTRAINT fk_webauthn_credentials_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- User Sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    device_info TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    auth_method VARCHAR(50) NOT NULL,
    fips_compliant BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_user_sessions_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Audit Logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36),
    event_type VARCHAR(100) NOT NULL,
    event_data TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    result VARCHAR(20) NOT NULL,
    error_message TEXT,
    fips_compliant BOOLEAN DEFAULT TRUE,
    integrity_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_audit_logs_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- DID Registry table
CREATE TABLE IF NOT EXISTS did_registry (
    id VARCHAR(255) PRIMARY KEY,
    method VARCHAR(50) NOT NULL,
    document TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    version INTEGER DEFAULT 1,
    update_key TEXT,
    fips_compliant BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- WebAuthn Sessions table
CREATE TABLE IF NOT EXISTS webauthn_sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36),
    challenge VARCHAR(255) NOT NULL,
    user_handle BYTEA,
    session_type VARCHAR(20) NOT NULL,
    session_data TEXT NOT NULL,
    fips_compliant BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_webauthn_sessions_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);