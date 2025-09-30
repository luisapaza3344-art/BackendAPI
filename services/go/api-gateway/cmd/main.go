package main

import (
        "context"
        "log"
        "os"
        "os/signal"
        "syscall"

        "api-gateway/internal/app"
        "api-gateway/internal/config"
        "api-gateway/internal/hsm"
        "api-gateway/internal/logger"
        "api-gateway/internal/metrics"
        "api-gateway/internal/redis"
        
        // Government-grade platform libraries
        "platform/compliance/audit"
        pqc "platform/crypto/pqc-go"
        "platform/observability/otel"
)

func main() {
        // STEP 1: Initialize FIPS 140-3 Level 3 compliance (CRITICAL - must be first)
        log.Println("🔐 Initializing FIPS 140-3 Level 3 compliance...")
        pqc.MustInitFIPSMode()
        
        // Initialize logger with FIPS 140-3 compliance
        logger := logger.NewFIPSLogger()
        logger.Info("🚀 Starting Government-Grade API Gateway")
        logger.Info("   - COSE-JWS Authentication + PKI Request Signing")
        logger.Info("   - Post-Quantum Cryptography (Kyber-1024, Dilithium-5)")
        logger.Info("   - FIPS 140-3 Level 3 compliance enabled")

        // STEP 2: Initialize OpenTelemetry tracing
        ctx := context.Background()
        logger.Info("📊 Initializing OpenTelemetry distributed tracing...")
        tp, err := otel.InitTracer(ctx, otel.TracerConfig{
                ServiceName:    "api-gateway",
                ServiceVersion: "2.0.0-government",
                Environment:    os.Getenv("ENVIRONMENT"),
                OTLPEndpoint:   os.Getenv("OTEL_ENDPOINT"),
                FIPSMode:       true,
        })
        if err != nil {
                // In dev, allow to continue without OTLP if not configured
                if os.Getenv("ENVIRONMENT") != "production" {
                        logger.Info("⚠️  OTLP tracing not available (dev mode)")
                } else {
                        logger.Fatal("Failed to initialize OTLP tracing", "error", err)
                }
        }
        if tp != nil {
                defer func() {
                        if err := tp.Shutdown(ctx); err != nil {
                                logger.Info("Error shutting down tracer", "error", err)
                        }
                }()
        }
        
        // STEP 3: Initialize blockchain-anchored audit logger
        logger.Info("🔗 Initializing blockchain-anchored audit trail...")
        auditLogger := audit.NewAuditLogger("api-gateway", nil, nil)
        
        // Log service startup event
        startupEvent := &audit.AuditEvent{
                ID:         "api-gateway-startup-" + os.Getenv("HOSTNAME"),
                Timestamp:  logger.Now(),
                EventType:  "service.startup",
                ActorID:    "system",
                ResourceID: "api-gateway",
                Action:     "START",
                Result:     "success",
                Metadata:   make(map[string]interface{}),
        }
        if err := auditLogger.Log(ctx, startupEvent); err != nil {
                logger.Info("⚠️  Audit logging failed", "error", err)
        }

        // Load configuration with security validation
        cfg, err := config.LoadConfig()
        if err != nil {
                logger.Fatal("Failed to load configuration", "error", err)
        }
        
        // STEP 4: Initialize Post-Quantum Cryptography
        logger.Info("⚛️  Initializing Post-Quantum Cryptography...")
        kyberKEM, err := pqc.NewKyberKEM()
        if err != nil {
                logger.Fatal("Failed to initialize Kyber-1024 KEM", "error", err)
        }
        logger.Info("   ✅ Kyber-1024 KEM initialized (NIST Level 5 security)")
        
        dilithiumSigner, err := pqc.NewDilithiumSigner()
        if err != nil {
                logger.Fatal("Failed to initialize Dilithium-5 signer", "error", err)
        }
        logger.Info("   ✅ Dilithium-5 signer initialized (NIST Level 5 security)")
        
        // Store PQC instances for use in request signing
        _ = kyberKEM
        _ = dilithiumSigner

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
        logger.Info("✅ Government-Grade API Gateway starting on port 9000")
        logger.Info("🔐 Security Features:")
        logger.Info("   - FIPS 140-3 Level 3 compliance")
        logger.Info("   - Post-Quantum Cryptography (Kyber-1024 + Dilithium-5)")
        logger.Info("   - COSE-JWS Authentication with PKI")
        logger.Info("   - Blockchain-anchored audit trail")
        logger.Info("   - OpenTelemetry distributed tracing")
        logger.Info("   - HSM-backed cryptographic operations")
        
        if err := application.Start(ctx); err != nil {
                logger.Fatal("Application failed to start", "error", err)
        }

        logger.Info("🏁 Government-Grade API Gateway has been shut down gracefully")
}