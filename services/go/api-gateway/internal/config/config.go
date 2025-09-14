package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the API Gateway
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Redis     RedisConfig
	HSM       HSMConfig
	Security  SecurityConfig
	Metrics   MetricsConfig
	PaymentGW PaymentGatewayConfig
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
}

type RedisConfig struct {
	Addr         string
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
	MaxRetries   int
	TLSEnabled   bool
}

type HSMConfig struct {
	Provider    string // "AWS_CloudHSM", "Azure_KeyVault", "PKCS11"
	Endpoint    string
	Region      string
	KeyID       string
	TLSEnabled  bool
	FIPSMode    bool
}

type SecurityConfig struct {
	JWTSecret          string
	JWTExpiration      time.Duration
	COSEEnabled        bool
	WebAuthnEnabled    bool
	RateLimitEnabled   bool
	MaxRequestsPerMin  int
	CircuitBreakerEnabled bool
}

type MetricsConfig struct {
	Port        int
	Path        string
	Enabled     bool
	FIPSMetrics bool
}

type PaymentGatewayConfig struct {
	BaseURL        string
	Timeout        time.Duration
	RetryAttempts  int
	CircuitBreaker bool
}

// LoadConfig loads configuration from environment variables with FIPS-compliant defaults
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:         getEnvOrDefault("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvAsIntOrDefault("SERVER_PORT", 8000),
			ReadTimeout:  getEnvAsDurationOrDefault("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvAsDurationOrDefault("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvAsDurationOrDefault("SERVER_IDLE_TIMEOUT", 120*time.Second),
			TLSEnabled:   getEnvAsBoolOrDefault("TLS_ENABLED", true),
			TLSCertPath:  getEnvOrDefault("TLS_CERT_PATH", "/etc/ssl/certs/api-gateway.crt"),
			TLSKeyPath:   getEnvOrDefault("TLS_KEY_PATH", "/etc/ssl/private/api-gateway.key"),
		},
		Database: DatabaseConfig{
			URL:             getEnvOrFail("DATABASE_URL"),
			MaxConnections:  getEnvAsIntOrDefault("DB_MAX_CONNECTIONS", 25),
			ConnMaxLifetime: getEnvAsDurationOrDefault("DB_CONN_MAX_LIFETIME", 5*time.Minute),
			ConnMaxIdleTime: getEnvAsDurationOrDefault("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
		},
		Redis: RedisConfig{
			Addr:         getEnvOrDefault("REDIS_ADDR", "localhost:6379"),
			Password:     getEnvOrDefault("REDIS_PASSWORD", ""),
			DB:           getEnvAsIntOrDefault("REDIS_DB", 0),
			PoolSize:     getEnvAsIntOrDefault("REDIS_POOL_SIZE", 10),
			MinIdleConns: getEnvAsIntOrDefault("REDIS_MIN_IDLE_CONNS", 5),
			MaxRetries:   getEnvAsIntOrDefault("REDIS_MAX_RETRIES", 3),
			TLSEnabled:   getEnvAsBoolOrDefault("REDIS_TLS_ENABLED", true),
		},
		HSM: HSMConfig{
			Provider:   getEnvOrDefault("HSM_PROVIDER", "AWS_CloudHSM"),
			Endpoint:   getEnvOrDefault("HSM_ENDPOINT", ""),
			Region:     getEnvOrDefault("HSM_REGION", "us-east-1"),
			KeyID:      getEnvOrDefault("HSM_KEY_ID", ""),
			TLSEnabled: getEnvAsBoolOrDefault("HSM_TLS_ENABLED", true),
			FIPSMode:   getEnvAsBoolOrDefault("HSM_FIPS_MODE", true),
		},
		Security: SecurityConfig{
			JWTSecret:             getEnvOrFail("JWT_SECRET"),
			JWTExpiration:         getEnvAsDurationOrDefault("JWT_EXPIRATION", 24*time.Hour),
			COSEEnabled:           getEnvAsBoolOrDefault("COSE_ENABLED", true),
			WebAuthnEnabled:       getEnvAsBoolOrDefault("WEBAUTHN_ENABLED", true),
			RateLimitEnabled:      getEnvAsBoolOrDefault("RATE_LIMIT_ENABLED", true),
			MaxRequestsPerMin:     getEnvAsIntOrDefault("MAX_REQUESTS_PER_MIN", 1000),
			CircuitBreakerEnabled: getEnvAsBoolOrDefault("CIRCUIT_BREAKER_ENABLED", true),
		},
		Metrics: MetricsConfig{
			Port:        getEnvAsIntOrDefault("METRICS_PORT", 9091),
			Path:        getEnvOrDefault("METRICS_PATH", "/metrics"),
			Enabled:     getEnvAsBoolOrDefault("METRICS_ENABLED", true),
			FIPSMetrics: getEnvAsBoolOrDefault("FIPS_METRICS", true),
		},
		PaymentGW: PaymentGatewayConfig{
			BaseURL:        getEnvOrDefault("PAYMENT_GATEWAY_URL", "http://localhost:8080"),
			Timeout:        getEnvAsDurationOrDefault("PAYMENT_GATEWAY_TIMEOUT", 30*time.Second),
			RetryAttempts:  getEnvAsIntOrDefault("PAYMENT_GATEWAY_RETRIES", 3),
			CircuitBreaker: getEnvAsBoolOrDefault("PAYMENT_GATEWAY_CIRCUIT_BREAKER", true),
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
	if c.PaymentGW.BaseURL == "" {
		return fmt.Errorf("PAYMENT_GATEWAY_URL is required")
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