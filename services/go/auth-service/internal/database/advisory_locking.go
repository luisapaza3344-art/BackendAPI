package database

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// acquireAdvisoryLock attempts to acquire a PostgreSQL advisory lock for migrations
func (f *FIPSDatabase) acquireAdvisoryLock(key int64) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var locked bool
	query := "SELECT pg_try_advisory_lock($1)"
	
	// Get underlying sql.DB
	sqlDB, err := f.db.DB()
	if err != nil {
		return false, fmt.Errorf("failed to get sql.DB: %w", err)
	}
	
	err = sqlDB.QueryRowContext(ctx, query, key).Scan(&locked)
	if err != nil {
		return false, fmt.Errorf("advisory lock query failed: %w", err)
	}
	
	if locked {
		f.logger.Info("🔒 Advisory lock acquired successfully", zap.Int64("key", key))
	} else {
		f.logger.Warn("⚠️ Failed to acquire advisory lock - another process is running", zap.Int64("key", key))
	}
	
	return locked, nil
}

// releaseAdvisoryLock releases a PostgreSQL advisory lock
func (f *FIPSDatabase) releaseAdvisoryLock(key int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := "SELECT pg_advisory_unlock($1)"
	
	// Get underlying sql.DB
	sqlDB, err := f.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %w", err)
	}
	
	var unlocked bool
	err = sqlDB.QueryRowContext(ctx, query, key).Scan(&unlocked)
	if err != nil {
		return fmt.Errorf("advisory unlock query failed: %w", err)
	}
	
	if !unlocked {
		return fmt.Errorf("failed to unlock advisory lock %d", key)
	}
	
	f.logger.Info("🔓 Advisory lock released successfully", zap.Int64("key", key))
	return nil
}

// ensurePgcryptoExtension ensures pgcrypto extension is available with proper error handling
func (f *FIPSDatabase) ensurePgcryptoExtension() error {
	f.logger.Info("🔐 Ensuring pgcrypto extension for FIPS compliance")
	
	// First check if extension already exists
	var exists bool
	checkQuery := "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto')"
	
	err := f.db.Raw(checkQuery).Scan(&exists).Error
	if err != nil {
		return fmt.Errorf("failed to check pgcrypto extension: %w", err)
	}
	
	if exists {
		f.logger.Info("✅ pgcrypto extension already available")
		return nil
	}
	
	// Try to create extension
	if err := f.db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto").Error; err != nil {
		// Log warning but don't fail - extension might be available through other means
		f.logger.Warn("⚠️ Could not create pgcrypto extension, assuming available", zap.Error(err))
		
		// Test if pgcrypto functions are available
		var testResult string
		testQuery := "SELECT encode(sha256('test'::bytea), 'hex')"
		testErr := f.db.Raw(testQuery).Scan(&testResult).Error
		if testErr != nil {
			return fmt.Errorf("pgcrypto functions not available and cannot create extension: %w", testErr)
		}
		
		f.logger.Info("✅ pgcrypto functions available despite extension creation warning")
	} else {
		f.logger.Info("✅ pgcrypto extension created successfully")
	}
	
	return nil
}