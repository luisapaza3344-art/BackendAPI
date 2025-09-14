package app

import (
        "context"
        "fmt"
        "net/http"
        "time"

        "api-gateway/internal/auth"
        "api-gateway/internal/config"
        "api-gateway/internal/handlers"
        "api-gateway/internal/hsm"
        "api-gateway/internal/logger"
        "api-gateway/internal/metrics"
        "api-gateway/internal/middleware"
        "api-gateway/internal/redis"
        "github.com/gin-gonic/gin"
        "github.com/prometheus/client_golang/prometheus/promhttp"
        "go.uber.org/zap"
)

// Application represents the API Gateway application with FIPS 140-3 compliance
type Application struct {
        config      *config.Config
        logger      *logger.FIPSLogger
        server      *http.Server
        metricsServer *http.Server
        
        // Core services
        hsmService     *hsm.FIPSHSMService
        redisClient    *redis.FIPSRedisClient
        metricsCollector *metrics.FIPSMetrics
        authMiddleware *auth.COSEAuthMiddleware
        
        // Handlers
        healthHandler  *handlers.HealthHandler
        paymentHandler *handlers.PaymentHandler
        authHandler    *handlers.AuthHandler
        
        fipsMode bool
}

// NewApplication creates a new API Gateway application with FIPS compliance
func NewApplication(
        cfg *config.Config,
        logger *logger.FIPSLogger,
        hsmService *hsm.FIPSHSMService,
        redisClient *redis.FIPSRedisClient,
        metricsCollector *metrics.FIPSMetrics,
) (*Application, error) {
        
        logger.Info("⚙️ Initializing API Gateway application with FIPS 140-3 compliance")
        
        // Initialize authentication middleware
        authMiddleware := auth.NewCOSEAuthMiddleware(hsmService, redisClient, cfg.Security.JWTSecret)
        
        // Initialize handlers
        healthHandler := handlers.NewHealthHandler(logger, redisClient, hsmService)
        paymentHandler := handlers.NewPaymentHandler(cfg, logger, metricsCollector, redisClient)
        authHandler := handlers.NewAuthHandler(cfg, logger, hsmService, redisClient)
        
        app := &Application{
                config:           cfg,
                logger:           logger,
                hsmService:       hsmService,
                redisClient:      redisClient,
                metricsCollector: metricsCollector,
                authMiddleware:   authMiddleware,
                healthHandler:    healthHandler,
                paymentHandler:   paymentHandler,
                authHandler:      authHandler,
                fipsMode:         hsmService.IsFIPSMode(),
        }
        
        // Setup HTTP servers
        if err := app.setupServers(); err != nil {
                return nil, fmt.Errorf("failed to setup servers: %w", err)
        }
        
        logger.Info("✅ API Gateway application initialized successfully")
        return app, nil
}

// Start starts the API Gateway application
func (a *Application) Start(ctx context.Context) error {
        a.logger.Info("🚀 Starting API Gateway servers",
                zap.String("api_address", fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port)),
                zap.String("metrics_address", fmt.Sprintf(":%d", a.config.Metrics.Port)),
                zap.Bool("fips_mode", a.fipsMode),
        )
        
        // Start metrics server
        go func() {
                if err := a.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                        a.logger.Error("Metrics server failed", zap.Error(err))
                }
        }()
        
        // Start main API server
        go func() {
                var err error
                if a.config.Server.TLSEnabled {
                        err = a.server.ListenAndServeTLS(a.config.Server.TLSCertPath, a.config.Server.TLSKeyPath)
                } else {
                        err = a.server.ListenAndServe()
                }
                
                if err != nil && err != http.ErrServerClosed {
                        a.logger.Error("API server failed", zap.Error(err))
                }
        }()
        
        a.logger.Info("✅ API Gateway started successfully")
        
        // Wait for context cancellation
        <-ctx.Done()
        
        // Graceful shutdown
        return a.shutdown()
}

// setupServers configures the HTTP servers
func (a *Application) setupServers() error {
        // Configure Gin
        if a.fipsMode {
                gin.SetMode(gin.ReleaseMode)
        }
        
        router := gin.New()
        
        // Add global middleware with proper order for security
        router.Use(
                middleware.FIPSRecovery(a.logger), // First: catch panics
                middleware.FIPSLogger(a.logger),   // Second: log requests
                middleware.FIPSSecurityHeaders(),  // Third: security headers
                middleware.FIPSCORS(),             // Fourth: CORS handling
                middleware.FIPSRateLimit(a.redisClient, a.config.Security.MaxRequestsPerMin), // Fifth: rate limiting
                middleware.FIPSMetrics(a.metricsCollector), // Last: metrics collection
        )
        
        // Setup routes
        a.setupRoutes(router)
        
        // Main API server
        a.server = &http.Server{
                Addr:         fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port),
                Handler:      router,
                ReadTimeout:  a.config.Server.ReadTimeout,
                WriteTimeout: a.config.Server.WriteTimeout,
                IdleTimeout:  a.config.Server.IdleTimeout,
        }
        
        // Metrics server
        metricsRouter := gin.New()
        metricsRouter.GET("/metrics", gin.WrapH(promhttp.Handler()))
        metricsRouter.GET("/health", func(c *gin.Context) {
                c.JSON(200, gin.H{
                        "status": "healthy",
                        "fips_mode": a.fipsMode,
                        "timestamp": time.Now().Unix(),
                })
        })
        
        a.metricsServer = &http.Server{
                Addr:    fmt.Sprintf(":%d", a.config.Metrics.Port),
                Handler: metricsRouter,
        }
        
        return nil
}

// setupRoutes configures all API routes
func (a *Application) setupRoutes(router *gin.Engine) {
        // Health check endpoint (no authentication required)
        router.GET("/health", a.healthHandler.HealthCheck)
        router.GET("/health/detailed", a.healthHandler.DetailedHealthCheck)
        
        // FIPS compliance endpoints
        router.GET("/fips/status", a.healthHandler.FIPSStatus)
        router.GET("/fips/attestation/:key_id", a.authMiddleware.RequireAuthentication(), a.healthHandler.GetAttestation)
        
        // Authentication endpoints
        auth := router.Group("/auth")
        {
                auth.POST("/login", a.authHandler.Login)
                auth.POST("/logout", a.authMiddleware.RequireAuthentication(), a.authHandler.Logout)
                auth.POST("/refresh", a.authMiddleware.RequireAuthentication(), a.authHandler.RefreshToken)
                auth.GET("/profile", a.authMiddleware.RequireAuthentication(), a.authHandler.GetProfile)
                
                // COSE/WebAuthn endpoints
                auth.POST("/webauthn/register/begin", a.authMiddleware.RequireAuthentication(), a.authHandler.BeginWebAuthnRegistration)
                auth.POST("/webauthn/register/finish", a.authMiddleware.RequireAuthentication(), a.authHandler.FinishWebAuthnRegistration)
                auth.POST("/webauthn/login/begin", a.authHandler.BeginWebAuthnLogin)
                auth.POST("/webauthn/login/finish", a.authHandler.FinishWebAuthnLogin)
        }
        
        // Payment endpoints (require authentication and specific permissions)
        payments := router.Group("/payments")
        payments.Use(a.authMiddleware.RequireAuthentication())
        {
                // Stripe payments
                payments.POST("/stripe", a.authMiddleware.RequirePermission("payment:create"), a.paymentHandler.ProcessStripePayment)
                payments.POST("/stripe/webhook", a.paymentHandler.HandleStripeWebhook) // No auth for webhooks
                
                // PayPal payments
                payments.POST("/paypal", a.authMiddleware.RequirePermission("payment:create"), a.paymentHandler.ProcessPayPalPayment)
                payments.POST("/paypal/webhook", a.paymentHandler.HandlePayPalWebhook) // No auth for webhooks
                
                // Coinbase payments
                payments.POST("/coinbase", a.authMiddleware.RequirePermission("payment:create"), a.paymentHandler.ProcessCoinbasePayment)
                payments.POST("/coinbase/webhook", a.paymentHandler.HandleCoinbaseWebhook) // No auth for webhooks
                
                // Payment status and history
                payments.GET("/:payment_id", a.authMiddleware.RequirePermission("payment:read"), a.paymentHandler.GetPaymentStatus)
                payments.GET("/", a.authMiddleware.RequirePermission("payment:read"), a.paymentHandler.GetPaymentHistory)
        }
        
        // Admin endpoints (require admin permissions)
        admin := router.Group("/admin")
        admin.Use(a.authMiddleware.RequireAuthentication())
        admin.Use(a.authMiddleware.RequirePermission("admin"))
        {
                admin.GET("/metrics", a.healthHandler.GetMetrics)
                admin.GET("/audit-logs", a.healthHandler.GetAuditLogs)
                admin.POST("/hsm/rotate-keys", a.healthHandler.RotateHSMKeys)
                admin.GET("/compliance/report", a.healthHandler.GetComplianceReport)
        }
        
        // Public endpoints (optional authentication)
        public := router.Group("/public")
        public.Use(a.authMiddleware.OptionalAuthentication())
        {
                public.GET("/status", a.healthHandler.PublicStatus)
                public.GET("/cose/keys", a.healthHandler.GetPublicKeys)
        }
}

// shutdown gracefully shuts down the application
func (a *Application) shutdown() error {
        a.logger.Info("🛑 Shutting down API Gateway gracefully")
        
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        
        // Shutdown servers
        if err := a.server.Shutdown(ctx); err != nil {
                a.logger.Error("API server shutdown failed", zap.Error(err))
        }
        
        if err := a.metricsServer.Shutdown(ctx); err != nil {
                a.logger.Error("Metrics server shutdown failed", zap.Error(err))
        }
        
        // Close Redis connection
        if err := a.redisClient.Close(); err != nil {
                a.logger.Error("Redis connection close failed", zap.Error(err))
        }
        
        a.logger.Info("✅ API Gateway shutdown completed")
        return nil
}