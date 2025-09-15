-- Create FIPS-compliant audit triggers
-- Migration: 000003_create_audit_triggers

-- Create audit trigger function for FIPS compliance
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
DECLARE
    audit_data TEXT;
    integrity_hash TEXT;
BEGIN
    -- Create audit data
    IF TG_OP = 'DELETE' THEN
        audit_data := row_to_json(OLD);
    ELSE
        audit_data := row_to_json(NEW);
    END IF;
    
    -- Calculate FIPS-compliant integrity hash
    integrity_hash := encode(sha256(audit_data::bytea), 'hex');
    
    -- Insert audit record
    INSERT INTO audit_logs (
        id, user_id, event_type, event_data, result, 
        fips_compliant, integrity_hash, created_at
    ) VALUES (
        gen_random_uuid()::text,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END,
        TG_TABLE_NAME || '_' || TG_OP,
        audit_data,
        'success',
        true,
        integrity_hash,
        NOW()
    );
    
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for critical tables
CREATE TRIGGER audit_trigger_users
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_trigger_did_documents
    AFTER INSERT OR UPDATE OR DELETE ON did_documents
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_trigger_verifiable_credentials
    AFTER INSERT OR UPDATE OR DELETE ON verifiable_credentials
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_trigger_webauthn_credentials
    AFTER INSERT OR UPDATE OR DELETE ON webauthn_credentials
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER audit_trigger_user_sessions
    AFTER INSERT OR UPDATE OR DELETE ON user_sessions
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();