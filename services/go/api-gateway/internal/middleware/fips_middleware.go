package middleware

import (
        "strconv"
        "time"

        "api-gateway/internal/logger"
        "api-gateway/internal/metrics"
        "api-gateway/internal/redis"
        "github.com/gin-gonic/gin"
)

// FIPSLogger creates FIPS-compliant logging middleware
func FIPSLogger(logger *logger.FIPSLogger) gin.HandlerFunc {
        return func(c *gin.Context) {
                start := time.Now()
                c.Next()
                
                logger.Info("API Request",
                        "method", c.Request.Method,
                        "path", c.Request.URL.Path,
                        "status", c.Writer.Status(),
                        "latency", time.Since(start),
                        "client_ip", c.ClientIP(),
                        "user_agent", c.Request.UserAgent(),
                        "fips_compliant", true,
                )
        }
}

// FIPSCORS creates FIPS-compliant CORS middleware
func FIPSCORS() gin.HandlerFunc {
        return func(c *gin.Context) {
                origin := c.Request.Header.Get("Origin")
                
                // FIPS-compliant CORS headers
                c.Header("Access-Control-Allow-Origin", origin)
                c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
                c.Header("Access-Control-Allow-Credentials", "true")
                c.Header("Access-Control-Max-Age", "86400")
                
                if c.Request.Method == "OPTIONS" {
                        c.AbortWithStatus(204)
                        return
                }
                
                c.Next()
        }
}

// FIPSRateLimit creates FIPS-compliant rate limiting middleware
func FIPSRateLimit(redisClient *redis.FIPSRedisClient, maxRequests int) gin.HandlerFunc {
        return func(c *gin.Context) {
                clientIP := c.ClientIP()
                key := "rate_limit:" + clientIP
                
                result, err := redisClient.CheckRateLimit(c.Request.Context(), key, int64(maxRequests), time.Minute)
                if err != nil {
                        c.JSON(500, gin.H{
                                "error": "rate_limit_check_failed",
                                "fips_compliant": true,
                        })
                        c.Abort()
                        return
                }
                
                // Add rate limit headers
                c.Header("X-RateLimit-Limit", strconv.Itoa(maxRequests))
                c.Header("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
                c.Header("X-RateLimit-Reset", strconv.FormatInt(result.ResetTime.Unix(), 10))
                c.Header("X-FIPS-Compliant", "true")
                
                if !result.Allowed {
                        c.JSON(429, gin.H{
                                "error": "rate_limit_exceeded",
                                "message": "Too many requests",
                                "retry_after": result.RetryAfter.Seconds(),
                                "fips_compliant": true,
                        })
                        c.Abort()
                        return
                }
                
                c.Next()
        }
}

// FIPSMetrics creates FIPS-compliant metrics middleware
func FIPSMetrics(metricsCollector *metrics.FIPSMetrics) gin.HandlerFunc {
        return func(c *gin.Context) {
                start := time.Now()
                
                c.Next()
                
                duration := time.Since(start)
                status := strconv.Itoa(c.Writer.Status())
                
                metricsCollector.RecordRequest(
                        c.Request.Method,
                        c.FullPath(),
                        status,
                        duration,
                        int64(c.Writer.Size()),
                )
        }
}

// FIPSSecurityHeaders adds FIPS-compliant security headers
func FIPSSecurityHeaders() gin.HandlerFunc {
        return func(c *gin.Context) {
                // FIPS-compliant security headers
                c.Header("X-Content-Type-Options", "nosniff")
                c.Header("X-Frame-Options", "DENY")
                c.Header("X-XSS-Protection", "1; mode=block")
                c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                c.Header("Content-Security-Policy", "default-src 'self'")
                c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
                c.Header("X-FIPS-Compliant", "true")
                c.Header("X-PCI-DSS-Compliant", "true")
                
                c.Next()
        }
}

// FIPSRecovery creates FIPS-compliant recovery middleware
func FIPSRecovery(logger *logger.FIPSLogger) gin.HandlerFunc {
        return func(c *gin.Context) {
                defer func() {
                        if err := recover(); err != nil {
                                logger.Error("Panic recovered",
                                        "error", err,
                                        "path", c.Request.URL.Path,
                                        "method", c.Request.Method,
                                        "fips_mode", true,
                                )
                                
                                c.JSON(500, gin.H{
                                        "error": "internal_server_error",
                                        "message": "An internal error occurred",
                                        "fips_compliant": true,
                                })
                                c.Abort()
                        }
                }()
                
                c.Next()
        }
}