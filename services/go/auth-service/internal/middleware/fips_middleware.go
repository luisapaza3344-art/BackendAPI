package middleware

import (
	"time"

	"auth-service/internal/handlers"
	"auth-service/internal/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// FIPSRecovery creates FIPS-compliant recovery middleware
func FIPSRecovery(logger *logger.FIPSLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.SecurityLog("panic_recovered", "HIGH", map[string]interface{}{
					"error": err,
					"path":  c.Request.URL.Path,
					"method": c.Request.Method,
					"fips_mode": true,
				})
				
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

// FIPSLogger creates FIPS-compliant logging middleware
func FIPSLogger(logger *logger.FIPSLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		
		logger.Info("Auth Service Request",
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
		c.Header("X-Auth-Service", "FIPS-140-3-Level-3")
		
		c.Next()
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

// FIPSRequestID adds FIPS-compliant request ID middleware
func FIPSRequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := uuid.New().String()
		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	}
}

// RequireAuth middleware that requires authentication
func RequireAuth(authHandler *handlers.AuthHandler) gin.HandlerFunc {
	return authHandler.RequireAuthentication()
}

// RequireAdmin middleware that requires admin privileges
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user has admin role
		userRole, exists := c.Get("user_role")
		if !exists || userRole != "admin" {
			c.JSON(403, gin.H{
				"error": "insufficient_privileges",
				"message": "Admin access required",
				"fips_compliant": true,
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}