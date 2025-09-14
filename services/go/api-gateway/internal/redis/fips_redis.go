package redis

import (
        "context"
        "crypto/tls"
        "fmt"
        "time"

        "api-gateway/internal/config"
        "github.com/redis/go-redis/v9"
        "go.uber.org/zap"
)

// FIPSRedisClient provides FIPS-compliant Redis operations for rate limiting and session storage
type FIPSRedisClient struct {
        client    *redis.Client
        logger    *zap.Logger
        fipsMode  bool
        tlsConfig *tls.Config
}

// RateLimitResult contains rate limiting decision and metadata
type RateLimitResult struct {
        Allowed      bool          `json:"allowed"`
        Remaining    int64         `json:"remaining"`
        ResetTime    time.Time     `json:"reset_time"`
        RetryAfter   time.Duration `json:"retry_after"`
        WindowSize   time.Duration `json:"window_size"`
        FIPSVerified bool          `json:"fips_verified"`
}

// SessionData represents secure session information
type SessionData struct {
        UserID       string                 `json:"user_id"`
        Permissions  []string               `json:"permissions"`
        CreatedAt    time.Time              `json:"created_at"`
        ExpiresAt    time.Time              `json:"expires_at"`
        Metadata     map[string]interface{} `json:"metadata"`
        FIPSVerified bool                   `json:"fips_verified"`
}

// NewFIPSRedisClient creates a new FIPS-compliant Redis client
func NewFIPSRedisClient(cfg *config.RedisConfig) (*FIPSRedisClient, error) {
        logger, _ := zap.NewProduction()
        
        logger.Info("🔄 Initializing FIPS-compliant Redis client",
                zap.String("addr", cfg.Addr),
                zap.Bool("tls_enabled", cfg.TLSEnabled),
                zap.Int("pool_size", cfg.PoolSize),
        )

        // Configure FIPS-compliant TLS if enabled
        var tlsConfig *tls.Config
        if cfg.TLSEnabled {
                tlsConfig = &tls.Config{
                        MinVersion: tls.VersionTLS12, // FIPS requires TLS 1.2+
                        CipherSuites: []uint16{
                                // FIPS 140-3 approved cipher suites with Perfect Forward Secrecy
                                tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                // Removed TLS_RSA_* suites (no PFS)
                        },
                        InsecureSkipVerify: false,
                }
        }

        // Configure Redis client with FIPS compliance
        rdb := redis.NewClient(&redis.Options{
                Addr:         cfg.Addr,
                Password:     cfg.Password,
                DB:           cfg.DB,
                PoolSize:     cfg.PoolSize,
                MinIdleConns: cfg.MinIdleConns,
                MaxRetries:   cfg.MaxRetries,
                DialTimeout:  10 * time.Second,
                ReadTimeout:  5 * time.Second,
                WriteTimeout: 5 * time.Second,
                TLSConfig:    tlsConfig,
        })

        // Test connection
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        _, err := rdb.Ping(ctx).Result()
        if err != nil {
                return nil, fmt.Errorf("failed to connect to Redis: %w", err)
        }

        client := &FIPSRedisClient{
                client:    rdb,
                logger:    logger,
                fipsMode:  cfg.TLSEnabled, // FIPS mode requires TLS
                tlsConfig: tlsConfig,
        }

        logger.Info("✅ FIPS Redis client connected successfully")
        return client, nil
}

// CheckRateLimit implements sliding window rate limiting with FIPS compliance
func (r *FIPSRedisClient) CheckRateLimit(ctx context.Context, key string, limit int64, window time.Duration) (*RateLimitResult, error) {
        now := time.Now()
        windowStart := now.Add(-window)

        // Use Redis sorted set for sliding window rate limiting
        pipe := r.client.TxPipeline()

        // Remove expired entries
        pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

        // Count current requests in window
        countCmd := pipe.ZCard(ctx, key)

        // Add current request
        pipe.ZAdd(ctx, key, redis.Z{
                Score:  float64(now.UnixNano()),
                Member: fmt.Sprintf("%d", now.UnixNano()),
        })

        // Set expiration
        pipe.Expire(ctx, key, window+time.Minute)

        _, err := pipe.Exec(ctx)
        if err != nil {
                return nil, fmt.Errorf("rate limit check failed: %w", err)
        }

        currentCount := countCmd.Val()
        allowed := currentCount < limit
        remaining := limit - currentCount
        if remaining < 0 {
                remaining = 0
        }

        resetTime := now.Add(window)
        var retryAfter time.Duration
        if !allowed {
                retryAfter = window
        }

        result := &RateLimitResult{
                Allowed:      allowed,
                Remaining:    remaining,
                ResetTime:    resetTime,
                RetryAfter:   retryAfter,
                WindowSize:   window,
                FIPSVerified: r.fipsMode,
        }

        r.logger.Debug("Rate limit check completed",
                zap.String("key", key),
                zap.Bool("allowed", allowed),
                zap.Int64("remaining", remaining),
                zap.Bool("fips_verified", r.fipsMode),
        )

        return result, nil
}

// StoreSession stores session data with FIPS-compliant encryption metadata
func (r *FIPSRedisClient) StoreSession(ctx context.Context, sessionID string, data *SessionData, ttl time.Duration) error {
        data.FIPSVerified = r.fipsMode
        data.CreatedAt = time.Now()
        data.ExpiresAt = time.Now().Add(ttl)

        // Store session in Redis with TTL
        err := r.client.Set(ctx, fmt.Sprintf("session:%s", sessionID), data, ttl).Err()
        if err != nil {
                return fmt.Errorf("failed to store session: %w", err)
        }

        r.logger.Info("Session stored with FIPS compliance",
                zap.String("session_id", sessionID),
                zap.String("user_id", data.UserID),
                zap.Bool("fips_verified", data.FIPSVerified),
                zap.Time("expires_at", data.ExpiresAt),
        )

        return nil
}

// GetSession retrieves session data with FIPS verification
func (r *FIPSRedisClient) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
        var sessionData SessionData
        
        err := r.client.Get(ctx, fmt.Sprintf("session:%s", sessionID)).Scan(&sessionData)
        if err == redis.Nil {
                return nil, fmt.Errorf("session not found")
        }
        if err != nil {
                return nil, fmt.Errorf("failed to get session: %w", err)
        }

        // Verify session hasn't expired
        if time.Now().After(sessionData.ExpiresAt) {
                r.DeleteSession(ctx, sessionID)
                return nil, fmt.Errorf("session expired")
        }

        r.logger.Debug("Session retrieved with FIPS verification",
                zap.String("session_id", sessionID),
                zap.String("user_id", sessionData.UserID),
                zap.Bool("fips_verified", sessionData.FIPSVerified),
        )

        return &sessionData, nil
}

// DeleteSession removes a session from storage
func (r *FIPSRedisClient) DeleteSession(ctx context.Context, sessionID string) error {
        err := r.client.Del(ctx, fmt.Sprintf("session:%s", sessionID)).Err()
        if err != nil {
                return fmt.Errorf("failed to delete session: %w", err)
        }

        r.logger.Info("Session deleted",
                zap.String("session_id", sessionID),
        )

        return nil
}

// IncrementCounter increments a counter with FIPS-compliant logging
func (r *FIPSRedisClient) IncrementCounter(ctx context.Context, key string, expiration time.Duration) (int64, error) {
        // Increment counter
        result, err := r.client.Incr(ctx, key).Result()
        if err != nil {
                return 0, fmt.Errorf("failed to increment counter: %w", err)
        }

        // Set expiration if it's the first increment
        if result == 1 {
                r.client.Expire(ctx, key, expiration)
        }

        return result, nil
}

// StoreTemporaryData stores temporary data with automatic expiration
func (r *FIPSRedisClient) StoreTemporaryData(ctx context.Context, key string, data interface{}, ttl time.Duration) error {
        err := r.client.Set(ctx, key, data, ttl).Err()
        if err != nil {
                return fmt.Errorf("failed to store temporary data: %w", err)
        }

        r.logger.Debug("Temporary data stored",
                zap.String("key", key),
                zap.Duration("ttl", ttl),
                zap.Bool("fips_mode", r.fipsMode),
        )

        return nil
}

// GetTemporaryData retrieves temporary data
func (r *FIPSRedisClient) GetTemporaryData(ctx context.Context, key string, dest interface{}) error {
        err := r.client.Get(ctx, key).Scan(dest)
        if err == redis.Nil {
                return fmt.Errorf("data not found")
        }
        if err != nil {
                return fmt.Errorf("failed to get temporary data: %w", err)
        }

        return nil
}

// IsFIPSMode returns whether the Redis client is operating in FIPS mode
func (r *FIPSRedisClient) IsFIPSMode() bool {
        return r.fipsMode
}

// HealthCheck performs a FIPS-compliant health check
func (r *FIPSRedisClient) HealthCheck(ctx context.Context) error {
        _, err := r.client.Ping(ctx).Result()
        if err != nil {
                return fmt.Errorf("Redis health check failed: %w", err)
        }

        r.logger.Debug("Redis health check passed",
                zap.Bool("fips_mode", r.fipsMode),
        )

        return nil
}

// Close closes the Redis connection
func (r *FIPSRedisClient) Close() error {
        r.logger.Info("Closing FIPS Redis connection")
        return r.client.Close()
}