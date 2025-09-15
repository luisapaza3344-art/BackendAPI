-- Rollback initial schema
-- Migration: 000001_initial_schema (down)

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS webauthn_sessions CASCADE;
DROP TABLE IF EXISTS did_registry CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS webauthn_credentials CASCADE;
DROP TABLE IF EXISTS verifiable_credentials CASCADE;
DROP TABLE IF EXISTS did_documents CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Note: We don't drop pgcrypto extension as it might be used by other services