package config

import (
        "fmt"
        "os"
        "strconv"
        "time"
)

// Config holds the application configuration
type Config struct {
        Server      ServerConfig
        Database    DatabaseConfig
        HSM         HSMConfig
        Attestation AttestationConfig
        Security    SecurityConfig
        Metrics     MetricsConfig
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

type HSMConfig struct {
        Provider    string // "aws-cloudhsm", "softhsm", "mock"
        LibraryPath string
        SlotID      uint
        Pin         string
        KeyID       string
        FIPSMode    bool
}

type AttestationConfig struct {
        Enabled           bool
        TrustStoreURL     string
        CACertPath        string
        ValidityPeriod    time.Duration
        AllowedAlgorithms []string
        FIPSMode          bool
}

type SecurityConfig struct {
        JWTSecret         string
        JWTExpiration     time.Duration
        APIKeysEnabled    bool
        RateLimitEnabled  bool
        SessionTimeout    time.Duration
        FIPSCompliant     bool
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
                        Port:         getEnvAsIntOrDefault("SERVER_PORT", 9000),
                        ReadTimeout:  getEnvAsDurationOrDefault("SERVER_READ_TIMEOUT", 30*time.Second),
                        WriteTimeout: getEnvAsDurationOrDefault("SERVER_WRITE_TIMEOUT", 30*time.Second),
                        IdleTimeout:  getEnvAsDurationOrDefault("SERVER_IDLE_TIMEOUT", 120*time.Second),
                        TLSEnabled:   getEnvAsBoolOrDefault("TLS_ENABLED", true),
                        TLSCertPath:  getEnvOrDefault("TLS_CERT_PATH", "certs/crypto-attestation.crt"),
                        TLSKeyPath:   getEnvOrDefault("TLS_KEY_PATH", "certs/crypto-attestation.key"),
                },
                Database: DatabaseConfig{
                        URL:             getEnvOrFail("DATABASE_URL"),
                        MaxConnections:  getEnvAsIntOrDefault("DB_MAX_CONNECTIONS", 25),
                        ConnMaxLifetime: getEnvAsDurationOrDefault("DB_CONN_MAX_LIFETIME", 5*time.Minute),
                        ConnMaxIdleTime: getEnvAsDurationOrDefault("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
                        FIPSMode:        getEnvAsBoolOrDefault("DB_FIPS_MODE", true),
                },
                HSM: HSMConfig{
                        Provider:    getEnvOrDefault("HSM_PROVIDER", "aws-cloudhsm"),
                        LibraryPath: getEnvOrDefault("HSM_LIBRARY_PATH", "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"),
                        SlotID:      uint(getEnvAsIntOrDefault("HSM_SLOT_ID", 0)),
                        Pin:         getEnvOrFail("HSM_PIN"),
                        KeyID:       getEnvOrDefault("HSM_KEY_ID", "crypto-attestation-key"),
                        FIPSMode:    getEnvAsBoolOrDefault("HSM_FIPS_MODE", true),
                },
                Attestation: AttestationConfig{
                        Enabled:           getEnvAsBoolOrDefault("ATTESTATION_ENABLED", true),
                        TrustStoreURL:     getEnvOrDefault("TRUST_STORE_URL", "https://mds.fidoalliance.org/"),
                        CACertPath:        getEnvOrDefault("CA_CERT_PATH", "/etc/ssl/certs/ca-certificates.crt"),
                        ValidityPeriod:    getEnvAsDurationOrDefault("ATTESTATION_VALIDITY", 24*time.Hour),
                        AllowedAlgorithms: []string{"ES256", "RS256"}, // FIPS-approved only
                        FIPSMode:          getEnvAsBoolOrDefault("ATTESTATION_FIPS_MODE", true),
                },
                Security: SecurityConfig{
                        JWTSecret:         getEnvOrFail("JWT_SECRET"),
                        JWTExpiration:     getEnvAsDurationOrDefault("JWT_EXPIRATION", 24*time.Hour),
                        APIKeysEnabled:    getEnvAsBoolOrDefault("API_KEYS_ENABLED", true),
                        RateLimitEnabled:  getEnvAsBoolOrDefault("RATE_LIMIT_ENABLED", true),
                        SessionTimeout:    getEnvAsDurationOrDefault("SESSION_TIMEOUT", 30*time.Minute),
                        FIPSCompliant:     getEnvAsBoolOrDefault("SECURITY_FIPS_MODE", true),
                },
                Metrics: MetricsConfig{
                        Port:        getEnvAsIntOrDefault("METRICS_PORT", 9091),
                        Path:        getEnvOrDefault("METRICS_PATH", "/metrics"),
                        Enabled:     getEnvAsBoolOrDefault("METRICS_ENABLED", true),
                        FIPSMetrics: getEnvAsBoolOrDefault("METRICS_FIPS_MODE", true),
                },
        }

        return cfg, nil
}

func getEnvOrDefault(key, defaultValue string) string {
        if value := os.Getenv(key); value != "" {
                return value
        }
        return defaultValue
}

func getEnvOrFail(key string) string {
        value := os.Getenv(key)
        if value == "" {
                // Development fallback for critical secrets
                switch key {
                case "JWT_SECRET":
                        fmt.Printf("Warning: Using development JWT secret. Set %s environment variable for production.\n", key)
                        return "dev-crypto-attestation-secret-change-in-production"
                case "HSM_PIN":
                        fmt.Printf("Warning: Using development HSM PIN. Set %s environment variable for production.\n", key)
                        return "dev-hsm-pin-1234"
                default:
                        panic(fmt.Sprintf("Environment variable %s is required", key))
                }
        }
        return value
}

func getEnvAsIntOrDefault(key string, defaultValue int) int {
        if value := os.Getenv(key); value != "" {
                if parsed, err := strconv.Atoi(value); err == nil {
                        return parsed
                }
        }
        return defaultValue
}

func getEnvAsBoolOrDefault(key string, defaultValue bool) bool {
        if value := os.Getenv(key); value != "" {
                if parsed, err := strconv.ParseBool(value); err == nil {
                        return parsed
                }
        }
        return defaultValue
}

func getEnvAsDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
        if value := os.Getenv(key); value != "" {
                if parsed, err := time.ParseDuration(value); err == nil {
                        return parsed
                }
        }
        return defaultValue
}