// Package pqc provides FIPS compliance enforcement for service initialization
package pqc

import (
	"fmt"
	"log"
	"os"
)

// InitFIPSMode initializes and validates FIPS 140-3 Level 3 compliance
// This function MUST be called at service startup before any crypto operations
func InitFIPSMode() error {
	log.Println("🔐 Initializing FIPS 140-3 Level 3 compliance checks...")
	
	// Check FIPS compliance
	if err := FIPSCompliant(); err != nil {
		return fmt.Errorf("FIPS compliance check failed: %w", err)
	}
	
	log.Println("✅ FIPS 140-3 Level 3 compliance validated")
	log.Printf("   - FIPS_MODE: %s", os.Getenv("FIPS_MODE"))
	log.Printf("   - HSM_AVAILABLE: %s", os.Getenv("HSM_AVAILABLE"))
	log.Printf("   - PQ_CRYPTO_ENABLED: %s", os.Getenv("PQ_CRYPTO_ENABLED"))
	
	return nil
}

// MustInitFIPSMode is like InitFIPSMode but panics on error
// Use this for fail-fast behavior in production services
func MustInitFIPSMode() {
	if err := InitFIPSMode(); err != nil {
		log.Fatalf("FATAL: %v\n\nService cannot start without FIPS compliance.\nPlease set:\n  FIPS_MODE=true\n  HSM_AVAILABLE=true\n  PQ_CRYPTO_ENABLED=true", err)
	}
}
