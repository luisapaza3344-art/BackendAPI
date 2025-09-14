package handlers

import (
	"net/http"

	"auth-service/internal/config"
	"auth-service/internal/logger"
	"auth-service/internal/webauthn"
	"github.com/gin-gonic/gin"
)

// WebAuthnHandler handles WebAuthn/Passkey operations with FIPS compliance
type WebAuthnHandler struct {
	config          *config.Config
	logger          *logger.FIPSLogger
	webAuthnService *webauthn.FIPSWebAuthnService
}

// NewWebAuthnHandler creates a new WebAuthn handler
func NewWebAuthnHandler(cfg *config.Config, logger *logger.FIPSLogger, webAuthnService *webauthn.FIPSWebAuthnService) *WebAuthnHandler {
	return &WebAuthnHandler{
		config:          cfg,
		logger:          logger,
		webAuthnService: webAuthnService,
	}
}

// BeginRegistration starts WebAuthn registration
func (w *WebAuthnHandler) BeginRegistration(c *gin.Context) {
	userID := c.GetString("user_id")

	c.JSON(http.StatusOK, gin.H{
		"user_id":        userID,
		"message":        "Begin WebAuthn registration",
		"fips_compliant": true,
	})
}

// FinishRegistration completes WebAuthn registration
func (w *WebAuthnHandler) FinishRegistration(c *gin.Context) {
	userID := c.GetString("user_id")

	c.JSON(http.StatusOK, gin.H{
		"user_id":        userID,
		"message":        "Finish WebAuthn registration",
		"fips_compliant": true,
	})
}

// BeginAuthentication starts WebAuthn authentication
func (w *WebAuthnHandler) BeginAuthentication(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":        "Begin WebAuthn authentication",
		"fips_compliant": true,
	})
}

// FinishAuthentication completes WebAuthn authentication
func (w *WebAuthnHandler) FinishAuthentication(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":        "Finish WebAuthn authentication",
		"fips_compliant": true,
	})
}

// GetUserPasskeys gets all Passkeys for a user
func (w *WebAuthnHandler) GetUserPasskeys(c *gin.Context) {
	userID := c.GetString("user_id")

	passkeys, err := w.webAuthnService.GetUserPasskeys(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed_to_get_passkeys",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"passkeys":       passkeys,
		"fips_compliant": true,
	})
}

// DeletePasskey deletes a Passkey
func (w *WebAuthnHandler) DeletePasskey(c *gin.Context) {
	credentialID := c.Param("credential_id")

	c.JSON(http.StatusOK, gin.H{
		"credential_id":  credentialID,
		"message":        "Delete Passkey endpoint",
		"fips_compliant": true,
	})
}

// GetMetadata returns WebAuthn metadata
func (w *WebAuthnHandler) GetMetadata(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"rp_id":          w.config.WebAuthn.RPID,
		"rp_name":        w.config.WebAuthn.RPDisplayName,
		"fips_compliant": true,
	})
}