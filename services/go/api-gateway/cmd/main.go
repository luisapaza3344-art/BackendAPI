package main

import (
        "context"
        "os"
        "os/signal"
        "syscall"

        "api-gateway/internal/app"
        "api-gateway/internal/config"
        "api-gateway/internal/hsm"
        "api-gateway/internal/logger"
        "api-gateway/internal/metrics"
        "api-gateway/internal/redis"
)

func main() {
        // Initialize logger with FIPS 140-3 compliance
        logger := logger.NewFIPSLogger()
        logger.Info("🚀 Starting API Gateway with FIPS 140-3 Level 3 compliance")

        // Load configuration with security validation
        cfg, err := config.LoadConfig()
        if err != nil {
                logger.Fatal("Failed to load configuration", "error", err)
        }

        // Initialize FIPS-compliant HSM service
        logger.Info("🔐 Initializing HSM with FIPS 140-3 Level 3 compliance")
        hsmService, err := hsm.NewFIPSHSMService(&cfg.HSM)
        if err != nil {
                logger.Fatal("Failed to initialize HSM service", "error", err)
        }

        // Initialize Redis for rate limiting and session storage (optional)
        logger.Info("🔄 Connecting to Redis for rate limiting and session management")
        redisClient, err := redis.NewFIPSRedisClient(&cfg.Redis)
        if err != nil {
                logger.Warn("⚠️ Redis unavailable, running standalone", "error", err)
                redisClient = nil
        }
        if redisClient != nil {
                defer redisClient.Close()
        }

        // Initialize Prometheus metrics
        logger.Info("📊 Starting metrics collection with cryptographic attestation")
        metricsCollector := metrics.NewFIPSMetrics()

        // Initialize and start the API Gateway application
        logger.Info("⚙️  Initializing API Gateway application")
        application, err := app.NewApplication(cfg, logger, hsmService, redisClient, metricsCollector)
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
        if err := application.Start(ctx); err != nil {
                logger.Fatal("Application failed to start", "error", err)
        }

        logger.Info("🏁 API Gateway has been shut down gracefully")
}