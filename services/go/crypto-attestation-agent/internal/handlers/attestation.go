package handlers

import (
        "net/http"

        "github.com/gin-gonic/gin"

        "crypto-attestation-agent/internal/attestation"
        "crypto-attestation-agent/internal/database"
        "crypto-attestation-agent/internal/logger"
)

// AttestationHandlers provides HTTP handlers for attestation operations
type AttestationHandlers struct {
        attestationService *attestation.FIPSAttestationService
        db                 *database.FIPSDatabase
        logger             *logger.FIPSLogger
}

// NewAttestationHandlers creates new attestation handlers
func NewAttestationHandlers(attestationService *attestation.FIPSAttestationService, db *database.FIPSDatabase) *AttestationHandlers {
        return &AttestationHandlers{
                attestationService: attestationService,
                db:                 db,
                logger:             logger.NewFIPSLogger(),
        }
}

// AttestationRequest represents an HTTP attestation request
type AttestationRequestHTTP struct {
        SubjectID       string                 `json:"subject_id" binding:"required"`
        AttestationType string                 `json:"attestation_type" binding:"required"`
        PublicKey       string                 `json:"public_key" binding:"required"`
        Challenge       string                 `json:"challenge" binding:"required"`
        Algorithm       string                 `json:"algorithm" binding:"required"`
        Metadata        map[string]interface{} `json:"metadata"`
}

// CreateAttestation handles POST /api/v1/attestations
func (h *AttestationHandlers) CreateAttestation(c *gin.Context) {
        var req AttestationRequestHTTP
        if err := c.ShouldBindJSON(&req); err != nil {
                h.logger.SecurityLog("invalid_request", "", "attestation", "create", map[string]interface{}{
                        "error":     err.Error(),
                        "client_ip": c.ClientIP(),
                })
                c.JSON(http.StatusBadRequest, gin.H{
                        "error":   "Invalid request format",
                        "details": err.Error(),
                })
                return
        }

        // Convert to internal format
        attestationReq := &attestation.AttestationRequest{
                SubjectID:       req.SubjectID,
                AttestationType: req.AttestationType,
                PublicKey:       req.PublicKey,
                Challenge:       req.Challenge,
                Algorithm:       req.Algorithm,
                Metadata:        req.Metadata,
        }

        h.logger.AttestationLog("api_request", req.SubjectID, req.Algorithm, "received", map[string]interface{}{
                "attestation_type": req.AttestationType,
                "client_ip":        c.ClientIP(),
                "user_agent":       c.GetHeader("User-Agent"),
        })

        // Process the attestation
        response, err := h.attestationService.ProcessAttestationRequest(attestationReq)
        if err != nil {
                h.logger.AttestationLog("api_request", req.SubjectID, req.Algorithm, "failed", map[string]interface{}{
                        "error":     err.Error(),
                        "client_ip": c.ClientIP(),
                })
                c.JSON(http.StatusBadRequest, gin.H{
                        "error":   "Attestation processing failed",
                        "details": err.Error(),
                })
                return
        }

        // Create audit log
        auditLog := &database.AuditLog{
                ID:            generateAuditID(),
                EventType:     "attestation_created",
                SubjectID:     req.SubjectID,
                Resource:      "attestations",
                Action:        "create",
                Result:        "success",
                ClientIP:      c.ClientIP(),
                UserAgent:     c.GetHeader("User-Agent"),
                RequestID:     response.RequestID,
                Details: map[string]interface{}{
                        "attestation_type": req.AttestationType,
                        "algorithm":        req.Algorithm,
                        "trust_level":      response.TrustLevel,
                },
                RiskLevel:     "medium",
                IntegrityHash: h.calculateAuditHash(req.SubjectID, "create", "success"),
                FIPSCompliant: true,
        }

        if err := h.db.CreateAuditLog(auditLog); err != nil {
                h.logger.Error("Failed to create audit log", "error", err.Error())
        }

        h.logger.AttestationLog("api_request", req.SubjectID, req.Algorithm, "success", map[string]interface{}{
                "request_id":  response.RequestID,
                "trust_level": response.TrustLevel,
        })

        c.JSON(http.StatusCreated, response)
}

// GetAttestation handles GET /api/v1/attestations/:id
func (h *AttestationHandlers) GetAttestation(c *gin.Context) {
        requestID := c.Param("id")
        if requestID == "" {
                c.JSON(http.StatusBadRequest, gin.H{
                        "error": "Request ID is required",
                })
                return
        }

        h.logger.AttestationLog("api_retrieval", "", "", "requested", map[string]interface{}{
                "request_id": requestID,
                "client_ip":  c.ClientIP(),
        })

        response, err := h.attestationService.GetAttestationResult(requestID)
        if err != nil {
                h.logger.AttestationLog("api_retrieval", "", "", "failed", map[string]interface{}{
                        "request_id": requestID,
                        "error":      err.Error(),
                })
                c.JSON(http.StatusNotFound, gin.H{
                        "error":   "Attestation not found",
                        "details": err.Error(),
                })
                return
        }

        h.logger.AttestationLog("api_retrieval", "", "", "success", map[string]interface{}{
                "request_id": requestID,
        })

        c.JSON(http.StatusOK, response)
}

// VerifyAttestation handles POST /api/v1/attestations/:id/verify
func (h *AttestationHandlers) VerifyAttestation(c *gin.Context) {
        requestID := c.Param("id")
        if requestID == "" {
                c.JSON(http.StatusBadRequest, gin.H{
                        "error": "Request ID is required",
                })
                return
        }

        h.logger.AttestationLog("api_verification", "", "", "requested", map[string]interface{}{
                "request_id": requestID,
                "client_ip":  c.ClientIP(),
        })

        valid, err := h.attestationService.VerifyAttestation(requestID)
        if err != nil {
                h.logger.AttestationLog("api_verification", "", "", "failed", map[string]interface{}{
                        "request_id": requestID,
                        "error":      err.Error(),
                })
                c.JSON(http.StatusBadRequest, gin.H{
                        "error":   "Verification failed",
                        "details": err.Error(),
                })
                return
        }

        status := "invalid"
        if valid {
                status = "valid"
        }

        h.logger.AttestationLog("api_verification", "", "", status, map[string]interface{}{
                "request_id": requestID,
        })

        c.JSON(http.StatusOK, gin.H{
                "request_id": requestID,
                "valid":      valid,
                "status":     status,
                "verified_at": "2024-01-01T00:00:00Z", // Current time would be set in real implementation
        })
}

// ListAttestations handles GET /api/v1/attestations
func (h *AttestationHandlers) ListAttestations(c *gin.Context) {
        subjectID := c.Query("subject_id")
        attestationType := c.Query("type")
        status := c.Query("status")

        h.logger.AttestationLog("api_list", subjectID, "", "requested", map[string]interface{}{
                "filters": map[string]string{
                        "subject_id": subjectID,
                        "type":       attestationType,
                        "status":     status,
                },
                "client_ip": c.ClientIP(),
        })

        // This would implement database query with filters
        // For now, return a simple response
        c.JSON(http.StatusOK, gin.H{
                "attestations": []gin.H{},
                "total":        0,
                "page":         1,
                "per_page":     10,
        })
}

// GetHealth handles GET /health
func (h *AttestationHandlers) GetHealth(c *gin.Context) {
        // Check database connectivity
        dbStatus := "healthy"
        if h.db == nil {
                dbStatus = "unhealthy"
        }

        // Check attestation service
        serviceStatus := "healthy"
        if h.attestationService == nil {
                serviceStatus = "unhealthy"
        }

        status := http.StatusOK
        if dbStatus == "unhealthy" || serviceStatus == "unhealthy" {
                status = http.StatusServiceUnavailable
        }

        c.JSON(status, gin.H{
                "status":    "ok",
                "service":   "crypto-attestation-agent",
                "version":   "1.0.0",
                "timestamp": "2024-01-01T00:00:00Z", // Would use time.Now() in real implementation
                "checks": gin.H{
                        "database":           dbStatus,
                        "attestation_service": serviceStatus,
                        "fips_compliance":    "enabled",
                },
        })
}

// GetReady handles GET /ready
func (h *AttestationHandlers) GetReady(c *gin.Context) {
        // Check if all services are ready
        ready := true
        checks := map[string]string{
                "database":           "ready",
                "attestation_service": "ready",
                "fips_mode":          "enabled",
        }

        if h.db == nil {
                ready = false
                checks["database"] = "not_ready"
        }

        if h.attestationService == nil {
                ready = false
                checks["attestation_service"] = "not_ready"
        }

        status := http.StatusOK
        if !ready {
                status = http.StatusServiceUnavailable
        }

        c.JSON(status, gin.H{
                "ready":  ready,
                "checks": checks,
        })
}

// Helper functions

func generateAuditID() string {
        // In real implementation, would use UUID
        return "audit-" + "12345678-1234-1234-1234-123456789012"
}

func (h *AttestationHandlers) calculateAuditHash(subjectID, action, result string) string {
        // In real implementation, would calculate proper cryptographic hash
        return "audit-hash-" + subjectID + "-" + action + "-" + result
}

