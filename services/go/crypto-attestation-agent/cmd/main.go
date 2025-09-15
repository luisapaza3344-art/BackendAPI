package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"crypto-attestation-agent/internal/app"
	"crypto-attestation-agent/internal/config"
	"crypto-attestation-agent/internal/logger"
)

func main() {
	// Initialize FIPS-compliant logger
	logger := logger.NewFIPSLogger()
	logger.Info("🚀 Starting Crypto Attestation Agent with FIPS 140-3 Level 3 compliance")
	logger.Info("🔐 FIPS 140-3 Level 3 compliance enabled")

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