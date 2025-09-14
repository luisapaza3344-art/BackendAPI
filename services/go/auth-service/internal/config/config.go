package config

import (
        "fmt"
        "os"
        "strconv"
        "time"
)

// Config holds all configuration for the Auth Service
type Config struct {
        Server   ServerConfig
        Database DatabaseConfig
        DID      DIDConfig
        WebAuthn WebAuthnConfig
        Security SecurityConfig
        Metrics  MetricsConfig
}

type ServerConfig struct {
        Host         string
        Port         int
        ReadTimeout  time.Duration
        WriteTimeout time.Duration
        IdleTimeout  time.Duration
        TLSEnabled   bool
        TLSCertPath  string
        TLSKeyPath   string
}

type DatabaseConfig struct {
        URL             string
        MaxConnections  int
        ConnMaxLifetime time.Duration
        ConnMaxIdleTime time.Duration
        FIPSMode        bool
}

type DIDConfig struct {
        Method          string // "did:web", "did:key", "did:ion"
        BaseURL         string
        KeyType         string // "Ed25519", "secp256k1", "P-256"
        FIPSMode        bool
        RegistryURL     string
        ResolverTimeout time.Duration
}

type WebAuthnConfig struct {
        RPDisplayName string
        RPID          string
        RPOrigins     []string
        FIPSMode      bool
        Timeout       time.Duration
}

type SecurityConfig struct {
        JWTSecret         string
        JWTExpiration     time.Duration
        DIDResolution     bool
        PasswordPolicy    PasswordPolicy
        SessionTimeout    time.Duration
        FIPSCompliant     bool
}

type PasswordPolicy struct {
        MinLength        int
        RequireUppercase bool
        RequireLowercase bool
        RequireNumbers   bool
        RequireSymbols   bool
}

type MetricsConfig struct {
        Port        int
        Path        string
        Enabled     bool
        FIPSMetrics bool
}

// LoadConfig loads configuration from environment variables with FIPS defaults
func LoadConfig() (*Config, error) {
        cfg := &Config{
                Server: ServerConfig{
                        Host:         getEnvOrDefault("SERVER_HOST", "0.0.0.0"),
                        Port:         getEnvAsIntOrDefault("SERVER_PORT", 8000),
                        ReadTimeout:  getEnvAsDurationOrDefault("SERVER_READ_TIMEOUT", 30*time.Second),
                        WriteTimeout: getEnvAsDurationOrDefault("SERVER_WRITE_TIMEOUT", 30*time.Second),
                        IdleTimeout:  getEnvAsDurationOrDefault("SERVER_IDLE_TIMEOUT", 120*time.Second),
                        TLSEnabled:   getEnvAsBoolOrDefault("TLS_ENABLED", true),
                        TLSCertPath:  getEnvOrDefault("TLS_CERT_PATH", "/etc/ssl/certs/auth-service.crt"),
                        TLSKeyPath:   getEnvOrDefault("TLS_KEY_PATH", "/etc/ssl/private/auth-service.key"),
                },
                Database: DatabaseConfig{
                        URL:             getEnvOrFail("DATABASE_URL"),
                        MaxConnections:  getEnvAsIntOrDefault("DB_MAX_CONNECTIONS", 25),
                        ConnMaxLifetime: getEnvAsDurationOrDefault("DB_CONN_MAX_LIFETIME", 5*time.Minute),
                        ConnMaxIdleTime: getEnvAsDurationOrDefault("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
                        FIPSMode:        getEnvAsBoolOrDefault("DB_FIPS_MODE", true),
                },
                DID: DIDConfig{
                        Method:          getEnvOrDefault("DID_METHOD", "did:web"),
                        BaseURL:         getEnvOrDefault("DID_BASE_URL", "https://auth-service.example.com/.well-known/did.json"),
                        KeyType:         getEnvOrDefault("DID_KEY_TYPE", "P-256"),
                        FIPSMode:        getEnvAsBoolOrDefault("DID_FIPS_MODE", true),
                        RegistryURL:     getEnvOrDefault("DID_REGISTRY_URL", ""),
                        ResolverTimeout: getEnvAsDurationOrDefault("DID_RESOLVER_TIMEOUT", 10*time.Second),
                },
                WebAuthn: WebAuthnConfig{
                        RPDisplayName: getEnvOrDefault("WEBAUTHN_RP_DISPLAY_NAME", "Auth Service"),
                        RPID:          getEnvOrDefault("WEBAUTHN_RP_ID", "auth-service.example.com"),
                        RPOrigins:     []string{getEnvOrDefault("WEBAUTHN_RP_ORIGIN", "https://auth-service.example.com")},
                        FIPSMode:      getEnvAsBoolOrDefault("WEBAUTHN_FIPS_MODE", true),
                        Timeout:       getEnvAsDurationOrDefault("WEBAUTHN_TIMEOUT", 60*time.Second),
                },
                Security: SecurityConfig{
                        JWTSecret:     getEnvOrDefault("JWT_SECRET", "fips-compliant-jwt-secret-key-development-use-only"),
                        JWTExpiration: getEnvAsDurationOrDefault("JWT_EXPIRATION", 24*time.Hour),
                        DIDResolution: getEnvAsBoolOrDefault("DID_RESOLUTION_ENABLED", true),
                        PasswordPolicy: PasswordPolicy{
                                MinLength:        getEnvAsIntOrDefault("PASSWORD_MIN_LENGTH", 12),
                                RequireUppercase: getEnvAsBoolOrDefault("PASSWORD_REQUIRE_UPPERCASE", true),
                                RequireLowercase: getEnvAsBoolOrDefault("PASSWORD_REQUIRE_LOWERCASE", true),
                                RequireNumbers:   getEnvAsBoolOrDefault("PASSWORD_REQUIRE_NUMBERS", true),
                                RequireSymbols:   getEnvAsBoolOrDefault("PASSWORD_REQUIRE_SYMBOLS", true),
                        },
                        SessionTimeout: getEnvAsDurationOrDefault("SESSION_TIMEOUT", 2*time.Hour),
                        FIPSCompliant:  getEnvAsBoolOrDefault("SECURITY_FIPS_COMPLIANT", true),
                },
                Metrics: MetricsConfig{
                        Port:        getEnvAsIntOrDefault("METRICS_PORT", 9092),
                        Path:        getEnvOrDefault("METRICS_PATH", "/metrics"),
                        Enabled:     getEnvAsBoolOrDefault("METRICS_ENABLED", true),
                        FIPSMetrics: getEnvAsBoolOrDefault("FIPS_METRICS", true),
                },
        }

        // Validate critical configuration
        if err := cfg.validate(); err != nil {
                return nil, fmt.Errorf("configuration validation failed: %w", err)
        }

        return cfg, nil
}

func (c *Config) validate() error {
        if c.Database.URL == "" {
                return fmt.Errorf("DATABASE_URL is required")
        }
        if c.Security.JWTSecret == "" {
                return fmt.Errorf("JWT_SECRET is required")
        }
        if c.Security.JWTSecret == "fips-compliant-jwt-secret-key-development-use-only" {
                fmt.Println("Warning: Using development JWT secret. Set JWT_SECRET environment variable for production.")
        }
        if c.WebAuthn.RPID == "" {
                return fmt.Errorf("WEBAUTHN_RP_ID is required")
        }
        if c.DID.BaseURL == "" && c.DID.Method == "did:web" {
                return fmt.Errorf("DID_BASE_URL is required for did:web method")
        }
        
        // FIPS 140-3 Level 3 compliance validation
        if c.DID.FIPSMode {
                if err := validateFIPSKeyType(c.DID.KeyType); err != nil {
                        return fmt.Errorf("FIPS DID key type validation failed: %w", err)
                }
        }
        
        return nil
}

// validateFIPSKeyType ensures only FIPS-approved key types are used
func validateFIPSKeyType(keyType string) error {
        approvedTypes := map[string]bool{
                "P-256":    true, // ECDSA with P-256 curve (FIPS 186-4 approved)
                "P-384":    true, // ECDSA with P-384 curve (FIPS 186-4 approved)
                "P-521":    true, // ECDSA with P-521 curve (FIPS 186-4 approved)
                "RSA-2048": true, // RSA with 2048-bit key (FIPS 186-4 approved)
                "RSA-3072": true, // RSA with 3072-bit key (FIPS 186-4 approved)
                "RSA-4096": true, // RSA with 4096-bit key (FIPS 186-4 approved)
        }
        
        if !approvedTypes[keyType] {
                return fmt.Errorf("key type '%s' is not FIPS 140-3 Level 3 approved. Allowed types: P-256, P-384, P-521, RSA-2048, RSA-3072, RSA-4096", keyType)
        }
        
        return nil
}

// Helper functions for environment variable parsing
func getEnvOrDefault(key, defaultValue string) string {
        if value := os.Getenv(key); value != "" {
                return value
        }
        return defaultValue
}

func getEnvOrFail(key string) string {
        if value := os.Getenv(key); value != "" {
                return value
        }
        panic(fmt.Sprintf("Environment variable %s is required", key))
}

// getEnvOrFailWithDefault provides a fallback for development
func getEnvOrFailWithDefault(key, defaultValue string) string {
        if value := os.Getenv(key); value != "" {
                return value
        }
        fmt.Printf("Warning: Using default value for %s in development\n", key)
        return defaultValue
}

func getEnvAsIntOrDefault(key string, defaultValue int) int {
        if value := os.Getenv(key); value != "" {
                if intValue, err := strconv.Atoi(value); err == nil {
                        return intValue
                }
        }
        return defaultValue
}

func getEnvAsBoolOrDefault(key string, defaultValue bool) bool {
        if value := os.Getenv(key); value != "" {
                if boolValue, err := strconv.ParseBool(value); err == nil {
                        return boolValue
                }
        }
        return defaultValue
}

func getEnvAsDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
        if value := os.Getenv(key); value != "" {
                if duration, err := time.ParseDuration(value); err == nil {
                        return duration
                }
        }
        return defaultValue
}