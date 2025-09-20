package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rbac-service/internal/app"
	"rbac-service/internal/config"
	"rbac-service/internal/database"
	"rbac-service/internal/logger"
)

func main() {
	// Initialize FIPS-compliant logger
	logger := logger.NewFIPSLogger()
	logger.Info("🚀 Starting Enterprise RBAC Service with FIPS 140-3 Level 3 compliance")

	// Load configuration with security validation
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("Failed to load configuration", "error", err)
	}

	// Initialize database with enterprise security
	logger.Info("📊 Connecting to enterprise database with cryptographic attestation")
	db, err := database.NewConnection(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database", "error", err)
	}
	defer db.Close()

	// Initialize RBAC application with enterprise features
	logger.Info("🔐 Initializing Enterprise RBAC System")
	application, err := app.NewApplication(cfg, logger, db)
	if err != nil {
		logger.Fatal("Failed to initialize RBAC application", "error", err)
	}

	// Start HTTP server with enterprise security
	server := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      application.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("🌐 Starting RBAC HTTP server", "address", cfg.Server.Address)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server failed to start", "error", err)
		}
	}()

	// Graceful shutdown handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("🛑 Graceful shutdown initiated")

	// Shutdown server with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown error", "error", err)
	}

	logger.Info("🏁 Enterprise RBAC Service has been shut down gracefully")
}