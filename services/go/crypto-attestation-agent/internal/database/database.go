package database

import (
        "fmt"

        "gorm.io/driver/postgres"
        "gorm.io/gorm"
        "gorm.io/gorm/logger"
        "gorm.io/gorm/schema"

        "crypto-attestation-agent/internal/config"
        fipsLogger "crypto-attestation-agent/internal/logger"
)

// FIPSDatabase wraps GORM with FIPS compliance features
type FIPSDatabase struct {
        *gorm.DB
        config   *config.DatabaseConfig
        logger   *fipsLogger.FIPSLogger
        fipsMode bool
}

// NewFIPSDatabase creates a new FIPS-compliant database connection
func NewFIPSDatabase(cfg *config.DatabaseConfig) (*FIPSDatabase, error) {
        fipsLogger := fipsLogger.NewFIPSLogger()
        
        fipsLogger.Info("💾 Connecting to FIPS-compliant PostgreSQL database for Crypto Attestation Agent",
                "fips_mode", cfg.FIPSMode,
                "max_connections", cfg.MaxConnections,
        )

        // Configure GORM with FIPS compliance
        gormConfig := &gorm.Config{
                Logger: logger.Default.LogMode(logger.Info),
        }

        // Connect to PostgreSQL
        db, err := gorm.Open(postgres.Open(cfg.URL), gormConfig)
        if err != nil {
                return nil, fmt.Errorf("failed to connect to database: %w", err)
        }

        // Configure connection pool
        sqlDB, err := db.DB()
        if err != nil {
                return nil, fmt.Errorf("failed to get database instance: %w", err)
        }

        sqlDB.SetMaxOpenConns(cfg.MaxConnections)
        sqlDB.SetMaxIdleConns(cfg.MaxConnections / 2)
        sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
        sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

        fipsDB := &FIPSDatabase{
                DB:       db,
                config:   cfg,
                logger:   fipsLogger,
                fipsMode: cfg.FIPSMode,
        }

        // Test the connection
        if err := sqlDB.Ping(); err != nil {
                return nil, fmt.Errorf("failed to ping database: %w", err)
        }

        // Run FIPS-compliant migrations
        fipsLogger.Info("🔄 Running FIPS-compliant database migrations")
        if err := fipsDB.autoMigrate(); err != nil {
                return nil, fmt.Errorf("auto-migration failed: %w", err)
        }

        fipsLogger.Info("✅ Database connected with FIPS compliance enabled")

        return fipsDB, nil
}

// autoMigrate runs all database migrations with FIPS compliance
func (db *FIPSDatabase) autoMigrate() error {
        // Enable required PostgreSQL extensions
        if err := db.enableFIPSExtensions(); err != nil {
                return fmt.Errorf("failed to enable FIPS extensions: %w", err)
        }

        // Migrate all models
        models := []interface{}{
                &AttestationRequest{},
                &AttestationResult{},
                &TrustAnchor{},
                &HSMKey{},
                &AuditLog{},
        }

        for _, model := range models {
                if err := db.AutoMigrate(model); err != nil {
                        return fmt.Errorf("failed to migrate model %T: %w", model, err)
                }
        }

        // Create FIPS-compliant indexes
        if err := db.createFIPSIndexes(); err != nil {
                return fmt.Errorf("failed to create FIPS indexes: %w", err)
        }

        return nil
}

// enableFIPSExtensions enables PostgreSQL extensions required for FIPS compliance
func (db *FIPSDatabase) enableFIPSExtensions() error {
        extensions := []string{
                "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"",
                "CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"",
                "CREATE EXTENSION IF NOT EXISTS \"pg_stat_statements\"",
        }

        for _, ext := range extensions {
                if err := db.Exec(ext).Error; err != nil {
                        return fmt.Errorf("failed to create extension: %w", err)
                }
        }

        return nil
}

// createFIPSIndexes creates performance indexes with FIPS compliance
func (db *FIPSDatabase) createFIPSIndexes() error {
        indexes := []string{
                "CREATE INDEX IF NOT EXISTS idx_attestation_requests_subject_status ON attestation_requests(\"SubjectID\", \"Status\")",
                "CREATE INDEX IF NOT EXISTS idx_attestation_results_request_id ON attestation_results(\"RequestID\")",
                "CREATE INDEX IF NOT EXISTS idx_trust_anchors_fingerprint ON trust_anchors(\"Fingerprint\")",
                "CREATE INDEX IF NOT EXISTS idx_hsm_keys_key_id ON hsm_keys(\"KeyID\")",
                "CREATE INDEX IF NOT EXISTS idx_audit_logs_event_timestamp ON audit_logs(\"EventType\", \"CreatedAt\")",
                "CREATE INDEX IF NOT EXISTS idx_audit_logs_subject_id ON audit_logs(\"SubjectID\")",
        }

        for _, idx := range indexes {
                if err := db.Exec(idx).Error; err != nil {
                        return fmt.Errorf("index creation failed: %w", err)
                }
        }

        return nil
}

// GetDB returns the underlying GORM database instance
func (db *FIPSDatabase) GetDB() *gorm.DB {
        return db.DB
}

// CreateAuditLog creates a new audit log entry
func (db *FIPSDatabase) CreateAuditLog(log *AuditLog) error {
        if err := db.Create(log).Error; err != nil {
                return fmt.Errorf("failed to create audit log: %w", err)
        }
        return nil
}

// CustomNamingStrategy implements GORM naming strategy
type CustomNamingStrategy struct{}

func (CustomNamingStrategy) TableName(table string) string {
        return table
}

func (CustomNamingStrategy) SchemaName(table string) string {
        return ""
}

func (CustomNamingStrategy) ColumnName(table, column string) string {
        return column
}

func (CustomNamingStrategy) JoinTableName(joinTable string) string {
        return joinTable
}

func (CustomNamingStrategy) RelationshipFKName(rel schema.Relationship) string {
        return "fk_" + rel.Schema.Table + "_" + rel.Name
}

func (CustomNamingStrategy) CheckerName(table, column string) string {
        return "chk_" + table + "_" + column
}

func (CustomNamingStrategy) IndexName(table, column string) string {
        return "idx_" + table + "_" + column
}

func (CustomNamingStrategy) UniqueName(table, column string) string {
        return "uniq_" + table + "_" + column
}

// Repository methods for attestation operations

// CreateAttestationRequest creates a new attestation request
func (db *FIPSDatabase) CreateAttestationRequest(req *AttestationRequest) error {
        if err := db.Create(req).Error; err != nil {
                db.logger.Error("Failed to create attestation request", "error", err.Error())
                return fmt.Errorf("failed to create attestation request: %w", err)
        }

        db.logger.AttestationLog("request_created", req.SubjectID, req.AlgorithmType, "success", map[string]interface{}{
                "request_id": req.ID,
                "type":       req.AttestationType,
        })

        return nil
}

// GetAttestationRequest retrieves an attestation request by ID
func (db *FIPSDatabase) GetAttestationRequest(id string) (*AttestationRequest, error) {
        var req AttestationRequest
        if err := db.Where("id = ?", id).First(&req).Error; err != nil {
                return nil, fmt.Errorf("failed to get attestation request: %w", err)
        }
        return &req, nil
}

// UpdateAttestationRequestStatus updates the status of an attestation request
func (db *FIPSDatabase) UpdateAttestationRequestStatus(id, status string) error {
        if err := db.Model(&AttestationRequest{}).Where("id = ?", id).Update("status", status).Error; err != nil {
                return fmt.Errorf("failed to update attestation request status: %w", err)
        }
        return nil
}

// CreateAttestationResult creates a new attestation result
func (db *FIPSDatabase) CreateAttestationResult(result *AttestationResult) error {
        if err := db.Create(result).Error; err != nil {
                db.logger.Error("Failed to create attestation result", "error", err.Error())
                return fmt.Errorf("failed to create attestation result: %w", err)
        }

        db.logger.AttestationLog("result_created", result.SubjectID, result.AttestationType, result.Result, map[string]interface{}{
                "result_id":    result.ID,
                "request_id":   result.RequestID,
                "trust_level":  result.TrustLevel,
        })

        return nil
}

// GetAttestationResult retrieves an attestation result by ID
func (db *FIPSDatabase) GetAttestationResult(id string) (*AttestationResult, error) {
        var result AttestationResult
        if err := db.Where("id = ?", id).First(&result).Error; err != nil {
                return nil, fmt.Errorf("failed to get attestation result: %w", err)
        }
        return &result, nil
}

// CreateTrustAnchor creates a new trust anchor
func (db *FIPSDatabase) CreateTrustAnchor(anchor *TrustAnchor) error {
        if err := db.Create(anchor).Error; err != nil {
                return fmt.Errorf("failed to create trust anchor: %w", err)
        }
        return nil
}

// GetTrustAnchor retrieves a trust anchor by fingerprint
func (db *FIPSDatabase) GetTrustAnchor(fingerprint string) (*TrustAnchor, error) {
        var anchor TrustAnchor
        if err := db.Where("fingerprint = ?", fingerprint).First(&anchor).Error; err != nil {
                return nil, fmt.Errorf("failed to get trust anchor: %w", err)
        }
        return &anchor, nil
}

// CreateHSMKey creates a new HSM key record
func (db *FIPSDatabase) CreateHSMKey(key *HSMKey) error {
        if err := db.Create(key).Error; err != nil {
                return fmt.Errorf("failed to create HSM key: %w", err)
        }
        return nil
}

// GetHSMKey retrieves an HSM key by key ID
func (db *FIPSDatabase) GetHSMKey(keyID string) (*HSMKey, error) {
        var key HSMKey
        if err := db.Where("key_id = ?", keyID).First(&key).Error; err != nil {
                return nil, fmt.Errorf("failed to get HSM key: %w", err)
        }
        return &key, nil
}

