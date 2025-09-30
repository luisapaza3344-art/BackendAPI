package main

import (
        "context"
        "log"
        "os"
        "os/signal"
        "syscall"

        "crypto-attestation-agent/internal/app"
        "crypto-attestation-agent/internal/config"
        "crypto-attestation-agent/internal/logger"
        
        // Government-grade platform libraries
        pqc "platform/crypto/pqc-go"
)

func main() {
        // STEP 1: Initialize FIPS 140-3 Level 3 compliance (CRITICAL - must be first)
        log.Println("🔐 Initializing FIPS 140-3 Level 3 compliance...")
        pqc.MustInitFIPSMode()
        
        // Initialize FIPS-compliant logger
        logger := logger.NewFIPSLogger()
        logger.Info("🚀 Starting Government-Grade Crypto Attestation Agent")
        logger.Info("   - FIPS 140-3 Level 3 compliance enabled")

        // Load configuration
        cfg, err := config.LoadConfig()
        if err != nil {
                logger.Fatal("Failed to load configuration", "error", err)
        }

        // Create application
        app, err := app.NewApplication(cfg)
        if err != nil {
                logger.Fatal("Failed to initialize application", "error", err)
        }

        // Create context for graceful shutdown
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        // Handle shutdown signals
        go func() {
                quit := make(chan os.Signal, 1)
                signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
                <-quit
                logger.Info("🛑 Shutdown signal received")
                cancel()
        }()

        // Start application
        if err := app.Start(ctx); err != nil {
                logger.Fatal("Application failed", "error", err)
        }

        logger.Info("✅ Application shutdown complete")
}