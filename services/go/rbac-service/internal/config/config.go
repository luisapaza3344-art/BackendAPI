package config

import (
	"os"
	"strconv"
	"time"
)

// Config represents the enterprise RBAC service configuration
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`
	Security SecurityConfig `json:"security"`
	FIPS     FIPSConfig     `json:"fips"`
	Audit    AuditConfig    `json:"audit"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Address      string        `json:"address"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Database        string `json:"database"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	SSLMode         string `json:"ssl_mode"`
	MaxConnections  int    `json:"max_connections"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
}

// RedisConfig holds Redis connection configuration
type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Database int    `json:"database"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	JWTSecret        string        `json:"jwt_secret"`
	SessionTimeout   time.Duration `json:"session_timeout"`
	PasswordPolicy   PasswordPolicy `json:"password_policy"`
	RateLimitEnabled bool          `json:"rate_limit_enabled"`
	RateLimitRPS     int           `json:"rate_limit_rps"`
}

// PasswordPolicy defines enterprise password requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	MaxAge           int  `json:"max_age_days"`
}

// FIPSConfig holds FIPS 140-3 compliance configuration
type FIPSConfig struct {
	Enabled      bool   `json:"enabled"`
	Level        string `json:"level"`
	HSMProvider  string `json:"hsm_provider"`
	HSMKeyID     string `json:"hsm_key_id"`
}

// AuditConfig holds audit trail configuration
type AuditConfig struct {
	Enabled             bool   `json:"enabled"`
	RetentionDays       int    `json:"retention_days"`
	BlockchainAnchoring bool   `json:"blockchain_anchoring"`
	SecurityServiceURL  string `json:"security_service_url"`
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	config := &Config{
		Server: ServerConfig{
			Address:      getEnvString("RBAC_SERVER_ADDRESS", ":8080"),
			Port:         getEnvInt("RBAC_SERVER_PORT", 8080),
			ReadTimeout:  getEnvDuration("RBAC_READ_TIMEOUT", 15*time.Second),
			WriteTimeout: getEnvDuration("RBAC_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:  getEnvDuration("RBAC_IDLE_TIMEOUT", 60*time.Second),
		},
		Database: DatabaseConfig{
			Host:            getEnvString("RBAC_DB_HOST", "localhost"),
			Port:            getEnvInt("RBAC_DB_PORT", 5432),
			Database:        getEnvString("RBAC_DB_NAME", "enterprise_rbac"),
			Username:        getEnvString("RBAC_DB_USER", "postgres"),
			Password:        getEnvString("RBAC_DB_PASSWORD", ""),
			SSLMode:         getEnvString("RBAC_DB_SSL_MODE", "require"),
			MaxConnections:  getEnvInt("RBAC_DB_MAX_CONNECTIONS", 25),
			ConnMaxLifetime: getEnvDuration("RBAC_DB_CONN_MAX_LIFETIME", time.Hour),
		},
		Redis: RedisConfig{
			Host:     getEnvString("RBAC_REDIS_HOST", "localhost"),
			Port:     getEnvInt("RBAC_REDIS_PORT", 6379),
			Password: getEnvString("RBAC_REDIS_PASSWORD", ""),
			Database: getEnvInt("RBAC_REDIS_DB", 0),
		},
		Security: SecurityConfig{
			JWTSecret:        getEnvString("RBAC_JWT_SECRET", "enterprise-rbac-secret"),
			SessionTimeout:   getEnvDuration("RBAC_SESSION_TIMEOUT", 24*time.Hour),
			RateLimitEnabled: getEnvBool("RBAC_RATE_LIMIT_ENABLED", true),
			RateLimitRPS:     getEnvInt("RBAC_RATE_LIMIT_RPS", 100),
			PasswordPolicy: PasswordPolicy{
				MinLength:        getEnvInt("RBAC_PASSWORD_MIN_LENGTH", 12),
				RequireUppercase: getEnvBool("RBAC_PASSWORD_REQUIRE_UPPERCASE", true),
				RequireLowercase: getEnvBool("RBAC_PASSWORD_REQUIRE_LOWERCASE", true),
				RequireNumbers:   getEnvBool("RBAC_PASSWORD_REQUIRE_NUMBERS", true),
				RequireSymbols:   getEnvBool("RBAC_PASSWORD_REQUIRE_SYMBOLS", true),
				MaxAge:           getEnvInt("RBAC_PASSWORD_MAX_AGE_DAYS", 90),
			},
		},
		FIPS: FIPSConfig{
			Enabled:     getEnvBool("RBAC_FIPS_ENABLED", true),
			Level:       getEnvString("RBAC_FIPS_LEVEL", "140-3_Level_3"),
			HSMProvider: getEnvString("RBAC_HSM_PROVIDER", "aws_cloudhsm"),
			HSMKeyID:    getEnvString("RBAC_HSM_KEY_ID", "enterprise-rbac-signing-key"),
		},
		Audit: AuditConfig{
			Enabled:             getEnvBool("RBAC_AUDIT_ENABLED", true),
			RetentionDays:       getEnvInt("RBAC_AUDIT_RETENTION_DAYS", 2555),
			BlockchainAnchoring: getEnvBool("RBAC_AUDIT_BLOCKCHAIN_ANCHORING", true),
			SecurityServiceURL:  getEnvString("RBAC_SECURITY_SERVICE_URL", "http://localhost:8000"),
		},
	}

	return config, nil
}

// Helper functions for environment variable parsing
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}