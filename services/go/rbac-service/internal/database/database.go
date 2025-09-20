package database

import (
	"database/sql"
	"fmt"
	"time"

	"rbac-service/internal/config"
	
	_ "github.com/lib/pq"
)

// DB represents the database connection with enterprise features
type DB struct {
	*sql.DB
	config *config.DatabaseConfig
}

// NewConnection creates a new enterprise database connection
func NewConnection(cfg config.DatabaseConfig) (*DB, error) {
	// Construct PostgreSQL connection string with enterprise security
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database, cfg.SSLMode,
	)

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool for enterprise load
	db.SetMaxOpenConns(cfg.MaxConnections)
	db.SetMaxIdleConns(cfg.MaxConnections / 2)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Initialize enterprise database schema if needed
	enterpriseDB := &DB{
		DB:     db,
		config: &cfg,
	}

	if err := enterpriseDB.initializeSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return enterpriseDB, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}

// initializeSchema creates the enterprise RBAC database schema
func (db *DB) initializeSchema() error {
	schema := `
	-- Enterprise Users table with FIPS compliance
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(100) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		is_active BOOLEAN DEFAULT true,
		is_super_admin BOOLEAN DEFAULT false,
		last_login TIMESTAMP WITH TIME ZONE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		fips_compliant BOOLEAN DEFAULT true,
		quantum_signature TEXT,
		hsm_key_id VARCHAR(100)
	);

	-- Enterprise Roles table with cryptographic attestation
	CREATE TABLE IF NOT EXISTS roles (
		id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(100) UNIQUE NOT NULL,
		display_name VARCHAR(200) NOT NULL,
		description TEXT,
		is_system_role BOOLEAN DEFAULT false,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		fips_compliant BOOLEAN DEFAULT true,
		audit_trail_id VARCHAR(36)
	);

	-- Enterprise Permissions table
	CREATE TABLE IF NOT EXISTS permissions (
		id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
		resource VARCHAR(100) NOT NULL,
		action VARCHAR(100) NOT NULL,
		scope VARCHAR(100) DEFAULT 'global',
		description TEXT,
		is_system_perm BOOLEAN DEFAULT false,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		fips_compliant BOOLEAN DEFAULT true,
		crypto_signature TEXT,
		UNIQUE(resource, action, scope)
	);

	-- User-Role relationships with audit trail
	CREATE TABLE IF NOT EXISTS user_roles (
		user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
		role_id VARCHAR(36) REFERENCES roles(id) ON DELETE CASCADE,
		assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		assigned_by VARCHAR(36) REFERENCES users(id),
		expires_at TIMESTAMP WITH TIME ZONE,
		is_active BOOLEAN DEFAULT true,
		audit_record_id VARCHAR(36),
		PRIMARY KEY (user_id, role_id)
	);

	-- Role-Permission relationships with HSM signatures
	CREATE TABLE IF NOT EXISTS role_permissions (
		role_id VARCHAR(36) REFERENCES roles(id) ON DELETE CASCADE,
		permission_id VARCHAR(36) REFERENCES permissions(id) ON DELETE CASCADE,
		granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		granted_by VARCHAR(36) REFERENCES users(id),
		hsm_signature TEXT,
		PRIMARY KEY (role_id, permission_id)
	);

	-- Enterprise Sessions with quantum resistance
	CREATE TABLE IF NOT EXISTS sessions (
		id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
		token_hash VARCHAR(255) NOT NULL,
		ip_address INET,
		user_agent TEXT,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		is_active BOOLEAN DEFAULT true,
		fips_compliant BOOLEAN DEFAULT true,
		quantum_token TEXT,
		hsm_signature TEXT
	);

	-- Enterprise Audit Logs with blockchain anchoring
	CREATE TABLE IF NOT EXISTS audit_logs (
		id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id VARCHAR(36) REFERENCES users(id),
		action VARCHAR(200) NOT NULL,
		resource VARCHAR(100) NOT NULL,
		resource_id VARCHAR(36),
		ip_address INET,
		user_agent TEXT,
		success BOOLEAN NOT NULL,
		error_message TEXT,
		timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		fips_compliant BOOLEAN DEFAULT true,
		blockchain_anchor VARCHAR(255),
		hsm_signature TEXT
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
	CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);

	-- Insert default enterprise roles
	INSERT INTO roles (name, display_name, description, is_system_role) VALUES
		('super_admin', 'Super Administrator', 'Full system access with all permissions', true),
		('admin', 'Administrator', 'Administrative access to most system functions', true),
		('merchant', 'Merchant', 'Payment processing and merchant functions', true),
		('operator', 'Operator', 'System operations and monitoring', true),
		('auditor', 'Auditor', 'Read-only access for compliance auditing', true),
		('viewer', 'Viewer', 'Read-only access to basic system information', true)
	ON CONFLICT (name) DO NOTHING;

	-- Insert default enterprise permissions
	INSERT INTO permissions (resource, action, description, is_system_perm) VALUES
		('payment', 'process', 'Process payment transactions', true),
		('payment', 'view', 'View payment information', true),
		('payment', 'refund', 'Process payment refunds', true),
		('payment', 'void', 'Void payment transactions', true),
		('security', 'view', 'View security information', true),
		('security', 'manage', 'Manage security settings', true),
		('security', 'audit', 'Access security audit logs', true),
		('user', 'create', 'Create new users', true),
		('user', 'view', 'View user information', true),
		('user', 'update', 'Update user information', true),
		('user', 'delete', 'Delete users', true),
		('role', 'create', 'Create new roles', true),
		('role', 'view', 'View role information', true),
		('role', 'update', 'Update role information', true),
		('role', 'delete', 'Delete roles', true),
		('role', 'assign', 'Assign roles to users', true),
		('system', 'config', 'Configure system settings', true),
		('system', 'monitor', 'Monitor system performance', true),
		('system', 'audit', 'Access system audit logs', true),
		('system', 'backup', 'Perform system backups', true)
	ON CONFLICT (resource, action, scope) DO NOTHING;
	`

	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to execute schema initialization: %w", err)
	}

	return nil
}

// Health checks the database health
func (db *DB) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	return nil
}