-- Drop indexes
-- Migration: 000002_create_indexes (down)

-- WebAuthn Sessions indexes
DROP INDEX IF EXISTS idx_webauthn_sessions_expires;
DROP INDEX IF EXISTS idx_webauthn_sessions_user_id;

-- DID Registry indexes
DROP INDEX IF EXISTS idx_did_registry_method_status;
DROP INDEX IF EXISTS idx_did_registry_method;

-- Audit Logs indexes
DROP INDEX IF EXISTS idx_audit_logs_time;
DROP INDEX IF EXISTS idx_audit_logs_event_type;
DROP INDEX IF EXISTS idx_audit_logs_user_id;

-- User Sessions indexes
DROP INDEX IF EXISTS idx_user_sessions_active;
DROP INDEX IF EXISTS idx_user_sessions_refresh_token;
DROP INDEX IF EXISTS idx_user_sessions_session_token;
DROP INDEX IF EXISTS idx_user_sessions_user_id;

-- WebAuthn Credentials indexes
DROP INDEX IF EXISTS idx_webauthn_credentials_user;
DROP INDEX IF EXISTS idx_webauthn_credentials_user_id;

-- Verifiable Credentials indexes
DROP INDEX IF EXISTS idx_verifiable_credentials_status;
DROP INDEX IF EXISTS idx_verifiable_credentials_did_document_id;
DROP INDEX IF EXISTS idx_verifiable_credentials_user_id;

-- DID Documents indexes
DROP INDEX IF EXISTS idx_did_documents_active;
DROP INDEX IF EXISTS idx_did_documents_user_id;

-- Users indexes
DROP INDEX IF EXISTS idx_users_email_verified;