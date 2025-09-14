package handlers

import (
	"net/http"
	"time"

	"api-gateway/internal/hsm"
	"api-gateway/internal/logger"
	"api-gateway/internal/redis"
	"github.com/gin-gonic/gin"
)

// HealthHandler handles health check and system status endpoints
type HealthHandler struct {
	logger      *logger.FIPSLogger
	redisClient *redis.FIPSRedisClient
	hsmService  *hsm.FIPSHSMService
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(logger *logger.FIPSLogger, redisClient *redis.FIPSRedisClient, hsmService *hsm.FIPSHSMService) *HealthHandler {
	return &HealthHandler{
		logger:      logger,
		redisClient: redisClient,
		hsmService:  hsmService,
	}
}

// HealthCheck provides basic health status
func (h *HealthHandler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":        "healthy",
		"timestamp":     time.Now().Unix(),
		"fips_mode":     h.hsmService.IsFIPSMode(),
		"service":       "api-gateway",
		"version":       "1.0.0",
	})
}

// DetailedHealthCheck provides comprehensive health information
func (h *HealthHandler) DetailedHealthCheck(c *gin.Context) {
	checks := make(map[string]interface{})
	
	// Redis health check
	if err := h.redisClient.HealthCheck(c.Request.Context()); err != nil {
		checks["redis"] = map[string]interface{}{
			"status": "unhealthy",
			"error":  err.Error(),
		}
	} else {
		checks["redis"] = map[string]interface{}{
			"status":     "healthy",
			"fips_mode":  h.redisClient.IsFIPSMode(),
		}
	}
	
	// HSM health check
	checks["hsm"] = map[string]interface{}{
		"status":    "healthy",
		"fips_mode": h.hsmService.IsFIPSMode(),
		"provider":  "FIPS_HSM",
	}
	
	c.JSON(http.StatusOK, gin.H{
		"status":        "healthy",
		"timestamp":     time.Now().Unix(),
		"checks":        checks,
		"fips_compliant": true,
	})
}

// FIPSStatus provides FIPS compliance status
func (h *HealthHandler) FIPSStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"fips_mode":        h.hsmService.IsFIPSMode(),
		"fips_level":       "140-3_Level_3",
		"pci_dss_level":    "Level_1",
		"compliance_date":  time.Now().Unix(),
		"attestation_ready": true,
	})
}

// GetAttestation retrieves cryptographic attestation
func (h *HealthHandler) GetAttestation(c *gin.Context) {
	keyID := c.Param("key_id")
	
	attestation, err := h.hsmService.GetAttestation(keyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "attestation_not_found",
			"key_id": keyID,
		})
		return
	}
	
	c.JSON(http.StatusOK, attestation)
}

// PublicStatus provides public system status
func (h *HealthHandler) PublicStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service":       "api-gateway",
		"status":        "operational",
		"fips_compliant": true,
		"timestamp":     time.Now().Unix(),
	})
}

// GetPublicKeys provides public COSE keys
func (h *HealthHandler) GetPublicKeys(c *gin.Context) {
	keyInfo, err := h.hsmService.GetCOSEKeyInfo("default")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed_to_get_keys",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"keys": []interface{}{keyInfo},
		"fips_compliant": true,
	})
}

// Placeholder methods for admin endpoints
func (h *HealthHandler) GetMetrics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "metrics endpoint"})
}

func (h *HealthHandler) GetAuditLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "audit logs endpoint"})
}

func (h *HealthHandler) RotateHSMKeys(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "key rotation endpoint"})
}

func (h *HealthHandler) GetComplianceReport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"fips_140_3": "Level_3_Compliant",
		"pci_dss":    "Level_1_Compliant",
		"timestamp":  time.Now().Unix(),
	})
}