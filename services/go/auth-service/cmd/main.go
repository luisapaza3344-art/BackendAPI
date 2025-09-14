package main

import (
        "context"
        "os"
        "os/signal"
        "syscall"

        "auth-service/internal/app"
        "auth-service/internal/config"
        "auth-service/internal/database"
        "auth-service/internal/did"
        "auth-service/internal/logger"
        "auth-service/internal/webauthn"
)

func main() {
        // Initialize FIPS-compliant logger
        logger := logger.NewFIPSLogger()
        logger.Info("🚀 Starting Auth Service with DID/VC + WebAuthn + Passkeys")
        logger.Info("🔐 FIPS 140-3 Level 3 compliance enabled")

        // Load configuration
        cfg, err := config.LoadConfig()
        if err != nil {
                logger.Fatal("Failed to load configuration", "error", err)
        }

        // Initialize database with FIPS compliance
        logger.Info("💾 Connecting to FIPS-compliant PostgreSQL database")
        db, err := database.NewFIPSDatabase(&cfg.Database)
        if err != nil {
                logger.Fatal("Failed to initialize database", "error", err)
        }

        // Initialize DID/VC service with FIPS cryptography
        logger.Info("🆔 Initializing DID/VC service with FIPS 140-3 cryptography")
        didService, err := did.NewFIPSDIDService(&cfg.DID)
        if err != nil {
                logger.Fatal("Failed to initialize DID service", "error", err)
        }

        // Initialize WebAuthn service with FIPS compliance
        logger.Info("🔑 Initializing WebAuthn/Passkeys service with FIPS compliance")
        webAuthnService, err := webauthn.NewFIPSWebAuthnService(&cfg.WebAuthn)
        if err != nil {
                logger.Fatal("Failed to initialize WebAuthn service", "error", err)
        }

        // Initialize and start the Auth Service application
        logger.Info("⚙️  Initializing Auth Service application")
        application, err := app.NewApplication(cfg, logger, db, didService, webAuthnService)
        if err != nil {
                logger.Fatal("Failed to initialize application", "error", err)
        }

        // Start the application with graceful shutdown
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        // Handle graceful shutdown
        go func() {
                sigChan := make(chan os.Signal, 1)
                signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
                <-sigChan
                
                logger.Info("🛑 Graceful shutdown initiated")
                cancel()
        }()

        // Start the application
        logger.Info("✅ Auth Service starting on port 8001")
        if err := application.Start(ctx); err != nil {
                logger.Fatal("Application failed to start", "error", err)
        }

        logger.Info("🏁 Auth Service has been shut down gracefully")
}