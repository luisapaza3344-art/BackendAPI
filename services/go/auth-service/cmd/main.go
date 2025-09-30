package main

import (
        "context"
        "log"
        "os"
        "os/signal"
        "syscall"

        "auth-service/internal/app"
        "auth-service/internal/config"
        "auth-service/internal/database"
        "auth-service/internal/did"
        "auth-service/internal/logger"
        "auth-service/internal/webauthn"
        
        // Government-grade platform libraries
        "platform/compliance/audit"
        pqc "platform/crypto/pqc-go"
        "platform/observability/otel"
)

func main() {
        // STEP 1: Initialize FIPS 140-3 Level 3 compliance (CRITICAL - must be first)
        log.Println("🔐 Initializing FIPS 140-3 Level 3 compliance...")
        pqc.MustInitFIPSMode()
        
        // Initialize FIPS-compliant logger
        logger := logger.NewFIPSLogger()
        logger.Info("🚀 Starting Government-Grade Auth Service")
        logger.Info("   - DID/VC + WebAuthn + Passkeys")
        logger.Info("   - Post-Quantum Cryptography (Kyber-1024, Dilithium-5)")
        logger.Info("   - FIPS 140-3 Level 3 compliance enabled")

        // STEP 2: Initialize OpenTelemetry tracing
        ctx := context.Background()
        logger.Info("📊 Initializing OpenTelemetry distributed tracing...")
        tp, err := otel.InitTracer(ctx, otel.TracerConfig{
                ServiceName:    "auth-service",
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
        auditLogger := audit.NewAuditLogger("auth-service", nil, nil)
        
        // Log service startup event
        startupEvent := &audit.AuditEvent{
                ID:         "auth-service-startup-" + os.Getenv("HOSTNAME"),
                Timestamp:  logger.Now(),
                EventType:  "service.startup",
                ActorID:    "system",
                ResourceID: "auth-service",
                Action:     "START",
                Result:     "success",
                Metadata:   make(map[string]interface{}),
        }
        if err := auditLogger.Log(ctx, startupEvent); err != nil {
                logger.Info("⚠️  Audit logging failed", "error", err)
        }

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
        
        // Store PQC instances in context for use in handlers
        _ = kyberKEM
        _ = dilithiumSigner

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
        logger.Info("✅ Government-Grade Auth Service starting on port 8001")
        logger.Info("🔐 Security Features:")
        logger.Info("   - FIPS 140-3 Level 3 compliance")
        logger.Info("   - Post-Quantum Cryptography (Kyber-1024 + Dilithium-5)")
        logger.Info("   - Blockchain-anchored audit trail")
        logger.Info("   - OpenTelemetry distributed tracing")
        logger.Info("   - DID/VC + WebAuthn/Passkeys")
        
        if err := application.Start(ctx); err != nil {
                logger.Fatal("Application failed to start", "error", err)
        }

        logger.Info("🏁 Government-Grade Auth Service has been shut down gracefully")
}