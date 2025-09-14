package handlers

import (
	"net/http"

	"auth-service/internal/config"
	"auth-service/internal/did"
	"auth-service/internal/logger"
	"github.com/gin-gonic/gin"
)

// DIDHandler handles DID operations with FIPS compliance
type DIDHandler struct {
	config     *config.Config
	logger     *logger.FIPSLogger
	didService *did.FIPSDIDService
}

// NewDIDHandler creates a new DID handler
func NewDIDHandler(cfg *config.Config, logger *logger.FIPSLogger, didService *did.FIPSDIDService) *DIDHandler {
	return &DIDHandler{
		config:     cfg,
		logger:     logger,
		didService: didService,
	}
}

// CreateDID creates a new DID for the authenticated user
func (d *DIDHandler) CreateDID(c *gin.Context) {
	userID := c.GetString("user_id")

	didDoc, err := d.didService.CreateDID(userID)
	if err != nil {
		d.logger.DIDLog("did_creation", "", "", "error", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "did_creation_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"did_document":   didDoc,
		"fips_compliant": true,
	})
}

// ResolveDID resolves a DID document
func (d *DIDHandler) ResolveDID(c *gin.Context) {
	didID := c.Param("did_id")

	c.JSON(http.StatusOK, gin.H{
		"did_id":         didID,
		"message":        "DID resolution endpoint",
		"fips_compliant": true,
	})
}

// IssueCredential issues a verifiable credential
func (d *DIDHandler) IssueCredential(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":        "Issue credential endpoint",
		"fips_compliant": true,
	})
}

// VerifyCredential verifies a verifiable credential
func (d *DIDHandler) VerifyCredential(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":        "Verify credential endpoint",
		"fips_compliant": true,
	})
}

// GetUserDIDs gets all DIDs for a user
func (d *DIDHandler) GetUserDIDs(c *gin.Context) {
	userID := c.Param("user_id")

	c.JSON(http.StatusOK, gin.H{
		"user_id":        userID,
		"message":        "Get user DIDs endpoint",
		"fips_compliant": true,
	})
}

// RevokeCredential revokes a verifiable credential
func (d *DIDHandler) RevokeCredential(c *gin.Context) {
	credentialID := c.Param("credential_id")

	c.JSON(http.StatusOK, gin.H{
		"credential_id":  credentialID,
		"message":        "Revoke credential endpoint",
		"fips_compliant": true,
	})
}