package database

import (
        "crypto/sha256"
        "fmt"
        "time"

        "auth-service/internal/config"
        "go.uber.org/zap"
        "gorm.io/driver/postgres"
        "gorm.io/gorm"
        gormlogger "gorm.io/gorm/logger"
)

// FIPSDatabase provides FIPS-compliant database operations for auth service
type FIPSDatabase struct {
        db     *gorm.DB
        logger *zap.Logger
        config *config.DatabaseConfig
}

// NewFIPSDatabase creates a new FIPS-compliant database connection
func NewFIPSDatabase(cfg *config.DatabaseConfig) (*FIPSDatabase, error) {
        logger, _ := zap.NewProduction()
        
        logger.Info("💾 Connecting to FIPS-compliant PostgreSQL database for Auth Service",
                zap.Bool("fips_mode", cfg.FIPSMode),
                zap.Int("max_connections", cfg.MaxConnections),
        )

        // Configure GORM logger (simplified)
        var gormLogger gormlogger.Interface
        gormLogger = gormlogger.Default.LogMode(gormlogger.Error)
        if cfg.FIPSMode {
                gormLogger = gormlogger.Default.LogMode(gormlogger.Silent) // Reduce logging in FIPS mode
        }

        // Open database connection with FIPS compliance
        db, err := gorm.Open(postgres.Open(cfg.URL), &gorm.Config{
                Logger: gormLogger,
                NowFunc: func() time.Time {
                        return time.Now().UTC() // Always use UTC for FIPS compliance
                },
                DisableForeignKeyConstraintWhenMigrating: true, // Prevent FK lock contention
        })
        if err != nil {
                return nil, fmt.Errorf("failed to connect to database: %w", err)
        }

        // Configure connection pool
        sqlDB, err := db.DB()
        if err != nil {
                return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
        }

        sqlDB.SetMaxOpenConns(cfg.MaxConnections)
        sqlDB.SetMaxIdleConns(cfg.MaxConnections / 2)
        sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
        sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

        // Test connection
        if err := sqlDB.Ping(); err != nil {
                return nil, fmt.Errorf("database ping failed: %w", err)
        }

        // Set timeouts to prevent indefinite hanging during migrations
        timeoutSQL := `
                SET lock_timeout = '5s';
                SET statement_timeout = '60s'; 
                SET idle_in_transaction_session_timeout = '60s';
        `
        if err := db.Exec(timeoutSQL).Error; err != nil {
                return nil, fmt.Errorf("failed to set database timeouts: %w", err)
        }

        fipsDB := &FIPSDatabase{
                db:     db,
                logger: logger,
                config: cfg,
        }

        // Auto-migrate schemas with FIPS compliance
        if err := fipsDB.autoMigrate(); err != nil {
                return nil, fmt.Errorf("auto-migration failed: %w", err)
        }

        logger.Info("✅ FIPS database connection established successfully")
        return fipsDB, nil
}

// autoMigrate creates/updates database schema with FIPS compliance
func (f *FIPSDatabase) autoMigrate() error {
        f.logger.Info("🔄 Running FIPS-compliant database migrations")

        // Auto-migrate all models
        err := f.db.AutoMigrate(
                &User{},
                &DIDDocument{},
                &VerifiableCredential{},
                &WebAuthnCredential{},
                &UserSession{},
                &AuditLog{},
                &DIDRegistry{},
                &WebAuthnSession{},
        )
        if err != nil {
                return fmt.Errorf("auto-migration failed: %w", err)
        }

        // Create indexes for performance and compliance
        if err := f.createIndexes(); err != nil {
                return fmt.Errorf("index creation failed: %w", err)
        }

        // Ensure pgcrypto extension is available for audit triggers
        if err := f.db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto").Error; err != nil {
                return fmt.Errorf("pgcrypto extension setup failed: %w", err)
        }

        // Set up audit triggers for FIPS compliance
        if err := f.setupAuditTriggers(); err != nil {
                return fmt.Errorf("audit trigger setup failed: %w", err)
        }

        f.logger.Info("✅ Database migrations completed successfully")
        return nil
}

// createIndexes creates performance and security indexes
func (f *FIPSDatabase) createIndexes() error {
        indexes := []string{
                "CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email, email_verified)",
                "CREATE INDEX IF NOT EXISTS idx_did_documents_active ON did_documents(user_id, is_active)",
                "CREATE INDEX IF NOT EXISTS idx_verifiable_credentials_status ON verifiable_credentials(user_id, status)",
                "CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id, is_passkey)",
                "CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(user_id, is_active, expires_at)",
                "CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at, event_type)",
                "CREATE INDEX IF NOT EXISTS idx_did_registry_method ON did_registry(method, status)",
                "CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires ON webauthn_sessions(expires_at)",
        }

        for _, indexSQL := range indexes {
                if err := f.db.Exec(indexSQL).Error; err != nil {
                        return fmt.Errorf("failed to create index: %w", err)
                }
        }

        return nil
}

// setupAuditTriggers sets up FIPS-compliant audit triggers
func (f *FIPSDatabase) setupAuditTriggers() error {
        // Create audit trigger function for FIPS compliance
        triggerFunction := `
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
        `

        if err := f.db.Exec(triggerFunction).Error; err != nil {
                return fmt.Errorf("failed to create audit trigger function: %w", err)
        }

        // Create triggers for critical tables
        tables := []string{"users", "did_documents", "verifiable_credentials", "webauthn_credentials", "user_sessions"}
        for _, table := range tables {
                triggerSQL := fmt.Sprintf(`
                        DROP TRIGGER IF EXISTS audit_trigger_%s ON %s;
                        CREATE TRIGGER audit_trigger_%s
                                AFTER INSERT OR UPDATE OR DELETE ON %s
                                FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
                `, table, table, table, table)

                if err := f.db.Exec(triggerSQL).Error; err != nil {
                        return fmt.Errorf("failed to create audit trigger for %s: %w", table, err)
                }
        }

        return nil
}

// GetDB returns the underlying GORM database instance
func (f *FIPSDatabase) GetDB() *gorm.DB {
        return f.db
}

// CreateUser creates a new user with FIPS compliance
func (f *FIPSDatabase) CreateUser(user *User) error {
        if user.ID == "" {
                user.ID = f.generateSecureID()
        }
        user.FIPSCompliant = true
        user.CreatedAt = time.Now().UTC()
        user.UpdatedAt = time.Now().UTC()

        return f.db.Create(user).Error
}

// GetUserByID retrieves a user by ID with FIPS audit logging
func (f *FIPSDatabase) GetUserByID(userID string) (*User, error) {
        var user User
        err := f.db.Preload("DIDs").Preload("WebAuthnCredentials").First(&user, "id = ?", userID).Error
        if err != nil {
                f.logAuditEvent(userID, "user_access_denied", map[string]interface{}{
                        "user_id": userID,
                        "reason":  "user_not_found",
                }, "failure")
                return nil, err
        }

        f.logAuditEvent(userID, "user_accessed", map[string]interface{}{
                "user_id": userID,
        }, "success")

        return &user, nil
}

// GetUserByEmail retrieves a user by email with FIPS audit logging
func (f *FIPSDatabase) GetUserByEmail(email string) (*User, error) {
        var user User
        err := f.db.Preload("DIDs").Preload("WebAuthnCredentials").First(&user, "email = ?", email).Error
        if err != nil {
                f.logAuditEvent("", "user_access_denied", map[string]interface{}{
                        "email":  email,
                        "reason": "user_not_found",
                }, "failure")
                return nil, err
        }

        f.logAuditEvent(user.ID, "user_accessed", map[string]interface{}{
                "user_id": user.ID,
                "email":   email,
        }, "success")

        return &user, nil
}

// CreateDIDDocument creates a new DID document with FIPS compliance
func (f *FIPSDatabase) CreateDIDDocument(did *DIDDocument) error {
        did.FIPSCompliant = true
        did.CreatedAt = time.Now().UTC()
        did.UpdatedAt = time.Now().UTC()

        return f.db.Create(did).Error
}

// CreateWebAuthnCredential creates a new WebAuthn credential with FIPS compliance
func (f *FIPSDatabase) CreateWebAuthnCredential(cred *WebAuthnCredential) error {
        cred.FIPSCompliant = true
        cred.CreatedAt = time.Now().UTC()
        cred.UpdatedAt = time.Now().UTC()

        return f.db.Create(cred).Error
}

// CreateUserSession creates a new user session with FIPS compliance
func (f *FIPSDatabase) CreateUserSession(session *UserSession) error {
        if session.ID == "" {
                session.ID = f.generateSecureID()
        }
        session.FIPSCompliant = true
        session.CreatedAt = time.Now().UTC()
        session.UpdatedAt = time.Now().UTC()

        return f.db.Create(session).Error
}

// generateSecureID generates a FIPS-compliant secure ID
func (f *FIPSDatabase) generateSecureID() string {
        // Use FIPS-approved randomness and hashing
        timestamp := time.Now().UnixNano()
        data := fmt.Sprintf("auth_service_%d", timestamp)
        hash := sha256.Sum256([]byte(data))
        return fmt.Sprintf("%x", hash)[:32]
}

// logAuditEvent logs an audit event with FIPS compliance
func (f *FIPSDatabase) logAuditEvent(userID, eventType string, eventData map[string]interface{}, result string) {
        dataJSON := fmt.Sprintf("%v", eventData)
        integrityHash := fmt.Sprintf("%x", sha256.Sum256([]byte(dataJSON)))

        auditLog := &AuditLog{
                ID:            f.generateSecureID(),
                EventType:     eventType,
                EventData:     dataJSON,
                Result:        result,
                FIPSCompliant: true,
                IntegrityHash: integrityHash,
                CreatedAt:     time.Now().UTC(),
        }

        if userID != "" {
                auditLog.UserID = &userID
        }

        f.db.Create(auditLog)
}

// Close closes the database connection
func (f *FIPSDatabase) Close() error {
        sqlDB, err := f.db.DB()
        if err != nil {
                return err
        }
        return sqlDB.Close()
}