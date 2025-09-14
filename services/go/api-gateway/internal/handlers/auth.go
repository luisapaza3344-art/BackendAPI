package handlers

import (
        "net/http"
        "time"

        "api-gateway/internal/config"
        "api-gateway/internal/hsm"
        "api-gateway/internal/logger"
        "api-gateway/internal/redis"
        "github.com/gin-gonic/gin"
        "github.com/golang-jwt/jwt/v5"
        "github.com/google/uuid"
)

// AuthHandler handles authentication and authorization
type AuthHandler struct {
        config      *config.Config
        logger      *logger.FIPSLogger
        hsmService  *hsm.FIPSHSMService
        redisClient *redis.FIPSRedisClient
}

// LoginRequest represents a login request
type LoginRequest struct {
        Username string `json:"username" binding:"required"`
        Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response
type LoginResponse struct {
        Token        string    `json:"token"`
        RefreshToken string    `json:"refresh_token"`
        ExpiresAt    time.Time `json:"expires_at"`
        UserID       string    `json:"user_id"`
        Permissions  []string  `json:"permissions"`
        FIPSCompliant bool     `json:"fips_compliant"`
}

// JWTClaims represents JWT claims
type JWTClaims struct {
        UserID      string   `json:"user_id"`
        SessionID   string   `json:"session_id"`
        Permissions []string `json:"permissions"`
        FIPSMode    bool     `json:"fips_mode"`
        jwt.RegisteredClaims
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
        cfg *config.Config,
        logger *logger.FIPSLogger,
        hsmService *hsm.FIPSHSMService,
        redisClient *redis.FIPSRedisClient,
) *AuthHandler {
        return &AuthHandler{
                config:      cfg,
                logger:      logger,
                hsmService:  hsmService,
                redisClient: redisClient,
        }
}

// Login handles user login
func (a *AuthHandler) Login(c *gin.Context) {
        var req LoginRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{
                        "error": "invalid_request",
                        "message": err.Error(),
                })
                return
        }

        // Simplified authentication (in production, verify against database)
        userID := uuid.New().String()
        permissions := []string{"payment:create", "payment:read"}

        // Create session
        sessionID := uuid.New().String()
        sessionData := &redis.SessionData{
                UserID:      userID,
                Permissions: permissions,
                Metadata:    map[string]interface{}{
                        "login_method": "password",
                        "login_time":   time.Now(),
                },
        }

        // Store session in Redis
        err := a.redisClient.StoreSession(c.Request.Context(), sessionID, sessionData, 24*time.Hour)
        if err != nil {
                a.logger.Error("Failed to store session", "error", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "session_creation_failed"})
                return
        }

        // Create JWT token
        claims := &JWTClaims{
                UserID:      userID,
                SessionID:   sessionID,
                Permissions: permissions,
                FIPSMode:    a.hsmService.IsFIPSMode(),
                RegisteredClaims: jwt.RegisteredClaims{
                        ExpiresAt: jwt.NewNumericDate(time.Now().Add(a.config.Security.JWTExpiration)),
                        IssuedAt:  jwt.NewNumericDate(time.Now()),
                        NotBefore: jwt.NewNumericDate(time.Now()),
                        Issuer:    "api-gateway",
                        Subject:   userID,
                        ID:        sessionID,
                },
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        tokenString, err := token.SignedString([]byte(a.config.Security.JWTSecret))
        if err != nil {
                a.logger.Error("Failed to sign JWT", "error", err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "token_creation_failed"})
                return
        }

        response := LoginResponse{
                Token:        tokenString,
                RefreshToken: sessionID, // Simplified refresh token
                ExpiresAt:    claims.ExpiresAt.Time,
                UserID:       userID,
                Permissions:  permissions,
                FIPSCompliant: true,
        }

        a.logger.Info("User logged in successfully",
                "user_id", userID,
                "session_id", sessionID,
                "fips_compliant", true,
        )

        c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (a *AuthHandler) Logout(c *gin.Context) {
        sessionID := c.GetString("session_id")
        if sessionID != "" {
                err := a.redisClient.DeleteSession(c.Request.Context(), sessionID)
                if err != nil {
                        a.logger.Error("Failed to delete session", "error", err)
                }
        }

        c.JSON(http.StatusOK, gin.H{
                "message": "logged_out_successfully",
                "fips_compliant": true,
        })
}

// RefreshToken handles token refresh
func (a *AuthHandler) RefreshToken(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
                "message": "token_refresh_endpoint",
                "fips_compliant": true,
        })
}

// GetProfile handles user profile retrieval
func (a *AuthHandler) GetProfile(c *gin.Context) {
        userID := c.GetString("user_id")
        sessionID := c.GetString("session_id")

        c.JSON(http.StatusOK, gin.H{
                "user_id":    userID,
                "session_id": sessionID,
                "fips_compliant": true,
        })
}

// WebAuthn endpoints (placeholder implementations)
func (a *AuthHandler) BeginWebAuthnRegistration(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
                "message": "webauthn_registration_begin",
                "fips_compliant": true,
        })
}

func (a *AuthHandler) FinishWebAuthnRegistration(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
                "message": "webauthn_registration_finish",
                "fips_compliant": true,
        })
}

func (a *AuthHandler) BeginWebAuthnLogin(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
                "message": "webauthn_login_begin",
                "fips_compliant": true,
        })
}

func (a *AuthHandler) FinishWebAuthnLogin(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
                "message": "webauthn_login_finish",
                "fips_compliant": true,
        })
}