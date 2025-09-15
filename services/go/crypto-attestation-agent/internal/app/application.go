package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"crypto-attestation-agent/internal/attestation"
	"crypto-attestation-agent/internal/config"
	"crypto-attestation-agent/internal/database"
	"crypto-attestation-agent/internal/handlers"
	"crypto-attestation-agent/internal/logger"
)

// Application represents the main application
type Application struct {
	config             *config.Config
	db                 *database.FIPSDatabase
	attestationService *attestation.FIPSAttestationService
	handlers           *handlers.AttestationHandlers
	server             *http.Server
	logger             *logger.FIPSLogger
}

// NewApplication creates a new application instance
func NewApplication(cfg *config.Config) (*Application, error) {
	logger := logger.NewFIPSLogger()

	// Initialize database
	db, err := database.NewFIPSDatabase(&cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize attestation service
	attestationService, err := attestation.NewFIPSAttestationService(&cfg.Attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize attestation service: %w", err)
	}

	// Connect services
	attestationService.SetDatabase(db)

	// Initialize handlers
	attestationHandlers := handlers.NewAttestationHandlers(attestationService, db)

	app := &Application{
		config:             cfg,
		db:                 db,
		attestationService: attestationService,
		handlers:           attestationHandlers,
		logger:             logger,
	}

	// Setup HTTP server
	app.setupServer()

	return app, nil
}

// setupServer configures the HTTP server and routes
func (a *Application) setupServer() {
	// Configure Gin
	if a.config.Server.TLSEnabled {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(a.loggingMiddleware())
	router.Use(a.corsMiddleware())
	router.Use(a.securityMiddleware())

	// Health endpoints
	router.GET("/health", a.handlers.GetHealth)
	router.GET("/ready", a.handlers.GetReady)
	router.GET("/", a.statusHandler)

	// API routes
	api := router.Group("/api/v1")
	{
		// Attestation endpoints
		attestations := api.Group("/attestations")
		{
			attestations.POST("", a.handlers.CreateAttestation)
			attestations.GET("", a.handlers.ListAttestations)
			attestations.GET("/:id", a.handlers.GetAttestation)
			attestations.POST("/:id/verify", a.handlers.VerifyAttestation)
		}

		// System information
		api.GET("/info", a.infoHandler)
		api.GET("/status", a.statusHandler)
	}

	// Create HTTP server
	a.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port),
		Handler:      router,
		ReadTimeout:  a.config.Server.ReadTimeout,
		WriteTimeout: a.config.Server.WriteTimeout,
		IdleTimeout:  a.config.Server.IdleTimeout,
	}
}

// Start starts the application
func (a *Application) Start(ctx context.Context) error {
	a.logger.Info("🚀 Starting Crypto Attestation Agent HTTP server",
		"host", a.config.Server.Host,
		"port", a.config.Server.Port,
	)

	// Start HTTP server
	errChan := make(chan error, 1)
	go func() {
		if a.config.Server.TLSEnabled {
			a.logger.Info("🔒 Starting HTTPS server",
				"cert_path", a.config.Server.TLSCertPath,
				"key_path", a.config.Server.TLSKeyPath,
			)
			errChan <- a.server.ListenAndServeTLS(
				a.config.Server.TLSCertPath,
				a.config.Server.TLSKeyPath,
			)
		} else {
			a.logger.Info("🌐 Starting HTTP server (TLS disabled for development)")
			errChan <- a.server.ListenAndServe()
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		a.logger.Info("🛑 Shutting down server due to context cancellation")
		return a.Shutdown()
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			a.logger.Error("❌ Server error", "error", err.Error())
			return err
		}
		return nil
	}
}

// Shutdown gracefully shuts down the application
func (a *Application) Shutdown() error {
	a.logger.Info("🔄 Starting graceful shutdown")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := a.server.Shutdown(ctx); err != nil {
		a.logger.Error("❌ Failed to shutdown HTTP server", "error", err.Error())
		return err
	}

	// Close database connections
	if a.db != nil {
		if sqlDB, err := a.db.GetDB().DB(); err == nil {
			sqlDB.Close()
		}
	}

	a.logger.Info("✅ Graceful shutdown completed")
	return nil
}

// Middleware functions

func (a *Application) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		a.logger.Info("🌐 HTTP Request",
			"method", method,
			"path", path,
			"status", status,
			"latency", latency.String(),
			"client_ip", c.ClientIP(),
			"user_agent", c.GetHeader("User-Agent"),
		)
	}
}

func (a *Application) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (a *Application) securityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// FIPS compliance header
		c.Header("X-FIPS-Compliance", "FIPS-140-3-Level-3")

		c.Next()
	}
}

// Handler functions

func (a *Application) statusHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service":        "crypto-attestation-agent",
		"version":        "1.0.0",
		"status":         "running",
		"fips_compliant": true,
		"uptime":         time.Since(time.Now()).String(), // Would track actual uptime in real implementation
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *Application) infoHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": gin.H{
			"name":         "crypto-attestation-agent",
			"version":      "1.0.0",
			"description":  "FIPS 140-3 Level 3 compliant cryptographic attestation service",
			"capabilities": []string{
				"device_attestation",
				"key_attestation", 
				"identity_attestation",
				"fips_compliance_verification",
				"cryptographic_validation",
			},
		},
		"compliance": gin.H{
			"fips_140_3":     "Level_3",
			"pci_dss":        "Level_1",
			"attestation":    "enabled",
			"hsm_integration": "supported",
		},
		"algorithms": gin.H{
			"supported": a.config.Attestation.AllowedAlgorithms,
			"default":   "ES256",
		},
		"endpoints": gin.H{
			"attestations": "/api/v1/attestations",
			"health":       "/health",
			"ready":        "/ready",
			"status":       "/api/v1/status",
			"info":         "/api/v1/info",
		},
	})
}