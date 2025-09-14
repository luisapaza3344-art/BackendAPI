package app

import (
        "context"
        "fmt"
        "net/http"
        "time"

        "auth-service/internal/config"
        "auth-service/internal/database"
        "auth-service/internal/did"
        "auth-service/internal/handlers"
        "auth-service/internal/logger"
        "auth-service/internal/middleware"
        "auth-service/internal/webauthn"
        "github.com/gin-gonic/gin"
)

// Application represents the Auth Service application with FIPS 140-3 compliance
type Application struct {
        config    *config.Config
        logger    *logger.FIPSLogger
        server    *http.Server
        
        // Core services
        db             *database.FIPSDatabase
        didService     *did.FIPSDIDService
        webAuthnService *webauthn.FIPSWebAuthnService
        
        // Handlers
        authHandler    *handlers.AuthHandler
        didHandler     *handlers.DIDHandler
        webAuthnHandler *handlers.WebAuthnHandler
        healthHandler  *handlers.HealthHandler
        
        fipsMode bool
}

// NewApplication creates a new Auth Service application with FIPS compliance
func NewApplication(
        cfg *config.Config,
        logger *logger.FIPSLogger,
        db *database.FIPSDatabase,
        didService *did.FIPSDIDService,
        webAuthnService *webauthn.FIPSWebAuthnService,
) (*Application, error) {
        
        logger.Info("⚙️ Initializing Auth Service application with FIPS 140-3 compliance")
        
        // Set database connections
        didService.SetDatabase(db)
        webAuthnService.SetDatabase(db)
        
        // Initialize handlers
        authHandler := handlers.NewAuthHandler(cfg, logger, db, didService, webAuthnService)
        didHandler := handlers.NewDIDHandler(cfg, logger, didService)
        webAuthnHandler := handlers.NewWebAuthnHandler(cfg, logger, webAuthnService)
        healthHandler := handlers.NewHealthHandler(logger, db)
        
        app := &Application{
                config:          cfg,
                logger:          logger,
                db:              db,
                didService:      didService,
                webAuthnService: webAuthnService,
                authHandler:     authHandler,
                didHandler:      didHandler,
                webAuthnHandler: webAuthnHandler,
                healthHandler:   healthHandler,
                fipsMode:        cfg.Security.FIPSCompliant,
        }
        
        // Setup HTTP server
        if err := app.setupServer(); err != nil {
                return nil, fmt.Errorf("failed to setup server: %w", err)
        }
        
        logger.Info("✅ Auth Service application initialized successfully")
        return app, nil
}

// Start starts the Auth Service application
func (a *Application) Start(ctx context.Context) error {
        a.logger.Info("🚀 Starting Auth Service servers",
                "address", fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port),
                "fips_mode", a.fipsMode,
                "did_enabled", true,
                "webauthn_enabled", true,
        )
        
        // Start main API server
        go func() {
                var err error
                if a.config.Server.TLSEnabled {
                        err = a.server.ListenAndServeTLS(a.config.Server.TLSCertPath, a.config.Server.TLSKeyPath)
                } else {
                        err = a.server.ListenAndServe()
                }
                
                if err != nil && err != http.ErrServerClosed {
                        a.logger.Error("Auth Service server failed", "error", err)
                }
        }()
        
        a.logger.Info("✅ Auth Service started successfully")
        
        // Wait for context cancellation
        <-ctx.Done()
        
        // Graceful shutdown
        return a.shutdown()
}

// setupServer configures the HTTP server
func (a *Application) setupServer() error {
        // Configure Gin
        if a.fipsMode {
                gin.SetMode(gin.ReleaseMode)
        }
        
        router := gin.New()
        
        // Add global middleware with FIPS compliance
        router.Use(
                middleware.FIPSRecovery(a.logger),
                middleware.FIPSLogger(a.logger),
                middleware.FIPSSecurityHeaders(),
                middleware.FIPSCORS(),
                middleware.FIPSRequestID(),
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
        
        return nil
}

// setupRoutes configures all API routes
func (a *Application) setupRoutes(router *gin.Engine) {
        // Health check endpoint (no authentication required)
        router.GET("/health", a.healthHandler.HealthCheck)
        router.GET("/health/detailed", a.healthHandler.DetailedHealthCheck)
        
        // FIPS compliance endpoints
        router.GET("/fips/status", a.healthHandler.FIPSStatus)
        
        // Authentication endpoints
        auth := router.Group("/auth")
        {
                auth.POST("/register", a.authHandler.Register)
                auth.POST("/login", a.authHandler.Login)
                auth.POST("/logout", a.authHandler.Logout)
                auth.POST("/refresh", a.authHandler.RefreshToken)
                auth.GET("/profile", middleware.RequireAuth(a.authHandler), a.authHandler.GetProfile)
        }
        
        // DID endpoints
        did := router.Group("/did")
        {
                did.POST("/create", middleware.RequireAuth(a.authHandler), a.didHandler.CreateDID)
                did.GET("/:did_id", a.didHandler.ResolveDID)
                did.POST("/issue-credential", middleware.RequireAuth(a.authHandler), a.didHandler.IssueCredential)
                did.POST("/verify-credential", a.didHandler.VerifyCredential)
                did.GET("/user/:user_id/dids", middleware.RequireAuth(a.authHandler), a.didHandler.GetUserDIDs)
        }
        
        // WebAuthn/Passkey endpoints
        webauthn := router.Group("/webauthn")
        {
                webauthn.POST("/register/begin", middleware.RequireAuth(a.authHandler), a.webAuthnHandler.BeginRegistration)
                webauthn.POST("/register/finish", middleware.RequireAuth(a.authHandler), a.webAuthnHandler.FinishRegistration)
                webauthn.POST("/authenticate/begin", a.webAuthnHandler.BeginAuthentication)
                webauthn.POST("/authenticate/finish", a.webAuthnHandler.FinishAuthentication)
                webauthn.GET("/passkeys", middleware.RequireAuth(a.authHandler), a.webAuthnHandler.GetUserPasskeys)
                webauthn.DELETE("/passkeys/:credential_id", middleware.RequireAuth(a.authHandler), a.webAuthnHandler.DeletePasskey)
        }
        
        // Public endpoints for DID resolution and WebAuthn metadata
        public := router.Group("/public")
        {
                public.GET("/did/:did_id", a.didHandler.ResolveDID)
                public.GET("/webauthn/metadata", a.webAuthnHandler.GetMetadata)
        }
        
        // Admin endpoints
        admin := router.Group("/admin")
        admin.Use(middleware.RequireAuth(a.authHandler))
        admin.Use(middleware.RequireAdmin())
        {
                admin.GET("/users", a.authHandler.GetAllUsers)
                admin.GET("/audit-logs", a.healthHandler.GetAuditLogs)
                admin.GET("/metrics", a.healthHandler.GetMetrics)
                admin.POST("/users/:user_id/disable", a.authHandler.DisableUser)
                admin.POST("/credentials/:credential_id/revoke", a.didHandler.RevokeCredential)
        }
}

// shutdown gracefully shuts down the application
func (a *Application) shutdown() error {
        a.logger.Info("🛑 Shutting down Auth Service gracefully")
        
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        
        // Shutdown server
        if err := a.server.Shutdown(ctx); err != nil {
                a.logger.Error("Auth Service server shutdown failed", "error", err)
        }
        
        // Close database connection
        if err := a.db.Close(); err != nil {
                a.logger.Error("Database connection close failed", "error", err)
        }
        
        a.logger.Info("✅ Auth Service shutdown completed")
        return nil
}