-- Create performance and security indexes
-- Migration: 000002_create_indexes

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email, email_verified) WHERE email_verified = true;

-- DID Documents table indexes
CREATE INDEX IF NOT EXISTS idx_did_documents_user_id ON did_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_did_documents_active ON did_documents(user_id, is_active) WHERE is_active = true;

-- Verifiable Credentials table indexes
CREATE INDEX IF NOT EXISTS idx_verifiable_credentials_user_id ON verifiable_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_verifiable_credentials_did_document_id ON verifiable_credentials(did_document_id);
CREATE INDEX IF NOT EXISTS idx_verifiable_credentials_status ON verifiable_credentials(user_id, status) WHERE status = 'active';

-- WebAuthn Credentials table indexes
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id, is_passkey);

-- User Sessions table indexes
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_session_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_token ON user_sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(user_id, is_active, expires_at) WHERE is_active = true;

-- Audit Logs table indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at, event_type);

-- DID Registry table indexes
CREATE INDEX IF NOT EXISTS idx_did_registry_method ON did_registry(method);
CREATE INDEX IF NOT EXISTS idx_did_registry_method_status ON did_registry(method, status) WHERE status = 'active';

-- WebAuthn Sessions table indexes
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id ON webauthn_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires ON webauthn_sessions(expires_at);