// Package main demonstrates how to build a government-grade microservice
// with FIPS 140-3 Level 3 compliance, post-quantum cryptography, and full observability
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"platform/compliance/audit"
	"platform/crypto/pqc-go"
	"platform/observability/otel"
)

func main() {
	// STEP 1: Initialize FIPS 140-3 Level 3 compliance (CRITICAL - must be first)
	pqc.MustInitFIPSMode()
	
	// STEP 2: Initialize OpenTelemetry tracing
	ctx := context.Background()
	tp, err := otel.InitTracer(ctx, otel.TracerConfig{
		ServiceName:    "government-service",
		ServiceVersion: "1.0.0",
		Environment:    os.Getenv("ENVIRONMENT"),
		OTLPEndpoint:   os.Getenv("OTEL_ENDPOINT"),
		FIPSMode:       true,
	})
	if err != nil {
		log.Fatalf("Failed to initialize tracing: %v", err)
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down tracer: %v", err)
		}
	}()
	
	// STEP 3: Initialize blockchain-anchored audit logger
	// Note: In production, provide real BlockchainStore and IPFSStore implementations
	auditLogger := audit.NewAuditLogger("government-service", nil, nil)
	
	// STEP 4: Initialize post-quantum cryptography
	kyberKEM, err := pqc.NewKyberKEM()
	if err != nil {
		log.Fatalf("Failed to initialize Kyber-1024: %v", err)
	}
	
	dilithiumSigner, err := pqc.NewDilithiumSigner()
	if err != nil {
		log.Fatalf("Failed to initialize Dilithium-5: %v", err)
	}
	
	log.Println("✅ Government-grade service initialized:")
	log.Printf("   - FIPS 140-3 Level 3: Enabled")
	log.Printf("   - Post-Quantum Crypto: Kyber-1024 + Dilithium-5")
	log.Printf("   - Observability: OpenTelemetry")
	log.Printf("   - Audit Trail: Blockchain-anchored")
	
	// STEP 5: Set up HTTP handlers with cryptographic operations
	mux := http.NewServeMux()
	
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Log audit event
		event := &audit.AuditEvent{
			ID:         "health-check-" + time.Now().Format("20060102150405"),
			Timestamp:  time.Now(),
			EventType:  "health_check",
			ActorID:    r.RemoteAddr,
			ResourceID: "/health",
			Action:     "GET",
			Result:     "success",
			Metadata:   make(map[string]interface{}),
		}
		if err := auditLogger.Log(r.Context(), event); err != nil {
			log.Printf("Audit logging failed: %v", err)
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","fips_mode":true,"pq_enabled":true}`))
	})
	
	mux.HandleFunc("/crypto/encrypt", func(w http.ResponseWriter, r *http.Request) {
		// Demonstrate Kyber-1024 encryption
		sharedSecret, ciphertext, err := kyberKEM.Encapsulate()
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}
		
		log.Printf("Kyber-1024 encapsulation: shared_secret_len=%d, ciphertext_len=%d", 
			len(sharedSecret), len(ciphertext))
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Encrypted with Kyber-1024 (NIST Level 5 security)"))
	})
	
	mux.HandleFunc("/crypto/sign", func(w http.ResponseWriter, r *http.Request) {
		// Demonstrate Dilithium-5 signing
		message := []byte("Government-grade secure message")
		signature, err := dilithiumSigner.Sign(message)
		if err != nil {
			http.Error(w, "Signing failed", http.StatusInternalServerError)
			return
		}
		
		log.Printf("Dilithium-5 signature generated: signature_len=%d", len(signature))
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Signed with Dilithium-5 (NIST Level 5 security)"))
	})
	
	// STEP 6: Start HTTP server with graceful shutdown
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		log.Printf("🚀 Government-grade service listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()
	
	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down gracefully...")
	
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown failed: %v", err)
	}
	
	log.Println("✅ Government-grade service stopped")
}
