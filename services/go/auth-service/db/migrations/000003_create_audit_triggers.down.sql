-- Drop audit triggers and function
-- Migration: 000003_create_audit_triggers (down)

-- Drop triggers
DROP TRIGGER IF EXISTS audit_trigger_user_sessions ON user_sessions;
DROP TRIGGER IF EXISTS audit_trigger_webauthn_credentials ON webauthn_credentials;
DROP TRIGGER IF EXISTS audit_trigger_verifiable_credentials ON verifiable_credentials;
DROP TRIGGER IF EXISTS audit_trigger_did_documents ON did_documents;
DROP TRIGGER IF EXISTS audit_trigger_users ON users;

-- Drop audit trigger function
DROP FUNCTION IF EXISTS audit_trigger_function();