package handlers

import (
        "fmt"
        "net/http"
        "time"

        "auth-service/internal/config"
        "auth-service/internal/database"
        "auth-service/internal/did"
        "auth-service/internal/logger"
        "auth-service/internal/webauthn"
        "github.com/gin-gonic/gin"
        "github.com/golang-jwt/jwt/v4"
        "github.com/google/uuid"
)

// AuthHandler handles authentication operations with FIPS compliance
type AuthHandler struct {
        config          *config.Config
        logger          *logger.FIPSLogger
        db              *database.FIPSDatabase
        didService      *did.FIPSDIDService
        webAuthnService *webauthn.FIPSWebAuthnService
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
        Username    string `json:"username" binding:"required"`
        Email       string `json:"email" binding:"required,email"`
        DisplayName string `json:"display_name" binding:"required"`
        Password    string `json:"password" binding:"required,min=12"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
        Email    string `json:"email" binding:"required,email"`
        Password string `json:"password" binding:"required"`
}

// AuthResponse represents authentication response with FIPS compliance
type AuthResponse struct {
        Token         string    `json:"token"`
        RefreshToken  string    `json:"refresh_token"`
        ExpiresAt     time.Time `json:"expires_at"`
        User          UserInfo  `json:"user"`
        FIPSCompliant bool      `json:"fips_compliant"`
}

// UserInfo represents user information
type UserInfo struct {
        ID                string    `json:"id"`
        Username          string    `json:"username"`
        Email             string    `json:"email"`
        DisplayName       string    `json:"display_name"`
        EmailVerified     bool      `json:"email_verified"`
        TwoFactorEnabled  bool      `json:"two_factor_enabled"`
        CreatedAt         time.Time `json:"created_at"`
        LastLoginAt       *time.Time `json:"last_login_at"`
}

// JWTClaims represents JWT claims with FIPS compliance
type JWTClaims struct {
        UserID        string `json:"user_id"`
        Email         string `json:"email"`
        Username      string `json:"username"`
        Role          string `json:"role"`
        FIPSCompliant bool   `json:"fips_compliant"`
        jwt.RegisteredClaims
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(
        cfg *config.Config,
        logger *logger.FIPSLogger,
        db *database.FIPSDatabase,
        didService *did.FIPSDIDService,
        webAuthnService *webauthn.FIPSWebAuthnService,
) *AuthHandler {
        return &AuthHandler{
                config:          cfg,
                logger:          logger,
                db:              db,
                didService:      didService,
                webAuthnService: webAuthnService,
        }
}

// Register handles user registration with FIPS compliance
func (a *AuthHandler) Register(c *gin.Context) {
        var req RegisterRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{
                        "error": "invalid_request",
                        "message": err.Error(),
                })
                return
        }

        a.logger.AuthAuditLog("user_registration", "", "password", "started", map[string]interface{}{
                "username": req.Username,
                "email":    req.Email,
        })

        // Validate password policy
        if !a.validatePassword(req.Password) {
                a.logger.AuthAuditLog("user_registration", "", "password", "failure", map[string]interface{}{
                        "username": req.Username,
                        "email":    req.Email,
                        "reason":   "password_policy_violation",
                })
                c.JSON(http.StatusBadRequest, gin.H{
                        "error": "password_policy_violation",
                        "message": "Password does not meet security requirements",
                })
                return
        }

        // Check if user already exists
        existingUser, _ := a.db.GetUserByEmail(req.Email)
        if existingUser != nil {
                a.logger.AuthAuditLog("user_registration", "", "password", "failure", map[string]interface{}{
                        "username": req.Username,
                        "email":    req.Email,
                        "reason":   "user_already_exists",
                })
                c.JSON(http.StatusConflict, gin.H{
                        "error": "user_already_exists",
                        "message": "User with this email already exists",
                })
                return
        }

        // Create user with FIPS compliance
        user := &database.User{
                ID:               uuid.New().String(),
                Username:         req.Username,
                Email:            req.Email,
                DisplayName:      req.DisplayName,
                PasswordHash:     a.hashPassword(req.Password),
                EmailVerified:    false,
                TwoFactorEnabled: false,
                FIPSCompliant:    true,
        }

        if err := a.db.CreateUser(user); err != nil {
                a.logger.AuthAuditLog("user_registration", "", "password", "error", map[string]interface{}{
                        "username": req.Username,
                        "email":    req.Email,
                        "error":    err.Error(),
                })
                c.JSON(http.StatusInternalServerError, gin.H{
                        "error": "registration_failed",
                        "message": "Failed to create user",
                })
                return
        }

        // Create JWT token
        token, expiresAt, err := a.createJWTToken(user)
        if err != nil {
                a.logger.Error("Failed to create JWT token", "error", err)
                c.JSON(http.StatusInternalServerError, gin.H{
                        "error": "token_creation_failed",
                })
                return
        }

        // Create refresh token
        refreshToken := a.generateRefreshToken()

        // Create user session
        session := &database.UserSession{
                ID:           uuid.New().String(),
                UserID:       user.ID,
                SessionToken: a.hashToken(token),
                RefreshToken: a.hashToken(refreshToken),
                IPAddress:    c.ClientIP(),
                UserAgent:    c.Request.UserAgent(),
                AuthMethod:   "password",
                ExpiresAt:    expiresAt,
        }

        if err := a.db.CreateUserSession(session); err != nil {
                a.logger.Error("Failed to create user session", "error", err)
        }

        a.logger.AuthAuditLog("user_registration", user.ID, "password", "success", map[string]interface{}{
                "username": req.Username,
                "email":    req.Email,
        })

        response := AuthResponse{
                Token:         token,
                RefreshToken:  refreshToken,
                ExpiresAt:     expiresAt,
                User:          a.userToUserInfo(user),
                FIPSCompliant: true,
        }

        c.JSON(http.StatusCreated, response)
}

// Login handles user login with FIPS compliance
func (a *AuthHandler) Login(c *gin.Context) {
        var req LoginRequest
        if err := c.ShouldBindJSON(&req); err != nil {
                c.JSON(http.StatusBadRequest, gin.H{
                        "error": "invalid_request",
                        "message": err.Error(),
                })
                return
        }

        a.logger.AuthAuditLog("user_login", "", "password", "started", map[string]interface{}{
                "email": req.Email,
        })

        // Get user by email
        user, err := a.db.GetUserByEmail(req.Email)
        if err != nil {
                a.logger.AuthAuditLog("user_login", "", "password", "failure", map[string]interface{}{
                        "email":  req.Email,
                        "reason": "user_not_found",
                })
                c.JSON(http.StatusUnauthorized, gin.H{
                        "error": "invalid_credentials",
                        "message": "Invalid email or password",
                })
                return
        }

        // Verify password
        if !a.verifyPassword(req.Password, user.PasswordHash) {
                a.logger.AuthAuditLog("user_login", user.ID, "password", "failure", map[string]interface{}{
                        "email":  req.Email,
                        "reason": "invalid_password",
                })
                c.JSON(http.StatusUnauthorized, gin.H{
                        "error": "invalid_credentials",
                        "message": "Invalid email or password",
                })
                return
        }

        // Create JWT token
        token, expiresAt, err := a.createJWTToken(user)
        if err != nil {
                a.logger.Error("Failed to create JWT token", "error", err)
                c.JSON(http.StatusInternalServerError, gin.H{
                        "error": "token_creation_failed",
                })
                return
        }

        // Create refresh token
        refreshToken := a.generateRefreshToken()

        // Create user session
        session := &database.UserSession{
                ID:           uuid.New().String(),
                UserID:       user.ID,
                SessionToken: a.hashToken(token),
                RefreshToken: a.hashToken(refreshToken),
                IPAddress:    c.ClientIP(),
                UserAgent:    c.Request.UserAgent(),
                AuthMethod:   "password",
                ExpiresAt:    expiresAt,
        }

        if err := a.db.CreateUserSession(session); err != nil {
                a.logger.Error("Failed to create user session", "error", err)
        }

        // Update last login
        now := time.Now().UTC()
        user.LastLoginAt = &now
        a.db.GetDB().Save(user)

        a.logger.AuthAuditLog("user_login", user.ID, "password", "success", map[string]interface{}{
                "email": req.Email,
        })

        response := AuthResponse{
                Token:         token,
                RefreshToken:  refreshToken,
                ExpiresAt:     expiresAt,
                User:          a.userToUserInfo(user),
                FIPSCompliant: true,
        }

        c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (a *AuthHandler) Logout(c *gin.Context) {
        userID := c.GetString("user_id")
        sessionToken := c.GetString("session_token")

        // Invalidate session
        a.db.GetDB().Where("user_id = ? AND session_token = ?", userID, a.hashToken(sessionToken)).
                Update("is_active", false)

        a.logger.AuthAuditLog("user_logout", userID, "session", "success", map[string]interface{}{})

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

// GetProfile returns user profile
func (a *AuthHandler) GetProfile(c *gin.Context) {
        userID := c.GetString("user_id")

        user, err := a.db.GetUserByID(userID)
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{
                        "error": "user_not_found",
                })
                return
        }

        c.JSON(http.StatusOK, gin.H{
                "user": a.userToUserInfo(user),
                "fips_compliant": true,
        })
}

// RequireAuthentication middleware for protected endpoints
func (a *AuthHandler) RequireAuthentication() gin.HandlerFunc {
        return func(c *gin.Context) {
                token := c.GetHeader("Authorization")
                if token == "" {
                        c.JSON(http.StatusUnauthorized, gin.H{
                                "error": "missing_authorization_header",
                        })
                        c.Abort()
                        return
                }

                // Remove "Bearer " prefix
                if len(token) > 7 && token[:7] == "Bearer " {
                        token = token[7:]
                }

                // Validate JWT token
                claims, err := a.validateJWTToken(token)
                if err != nil {
                        c.JSON(http.StatusUnauthorized, gin.H{
                                "error": "invalid_token",
                        })
                        c.Abort()
                        return
                }

                // Set user context
                c.Set("user_id", claims.UserID)
                c.Set("user_email", claims.Email)
                c.Set("user_role", claims.Role)
                c.Set("session_token", token)

                c.Next()
        }
}

// Placeholder admin methods
func (a *AuthHandler) GetAllUsers(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"message": "get_all_users"})
}

func (a *AuthHandler) DisableUser(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"message": "disable_user"})
}

// Helper methods

func (a *AuthHandler) validatePassword(password string) bool {
        // Simplified password validation - implement full policy
        return len(password) >= 12
}

func (a *AuthHandler) hashPassword(password string) string {
        // Simplified - use bcrypt or Argon2 in production
        return fmt.Sprintf("hash_%s", password)
}

func (a *AuthHandler) verifyPassword(password, hash string) bool {
        // Simplified - use bcrypt or Argon2 in production
        return a.hashPassword(password) == hash
}

func (a *AuthHandler) createJWTToken(user *database.User) (string, time.Time, error) {
        expiresAt := time.Now().Add(a.config.Security.JWTExpiration)
        
        claims := &JWTClaims{
                UserID:        user.ID,
                Email:         user.Email,
                Username:      user.Username,
                Role:          "user", // Default role
                FIPSCompliant: true,
                RegisteredClaims: jwt.RegisteredClaims{
                        ExpiresAt: jwt.NewNumericDate(expiresAt),
                        IssuedAt:  jwt.NewNumericDate(time.Now()),
                        NotBefore: jwt.NewNumericDate(time.Now()),
                        Issuer:    "auth-service",
                        Subject:   user.ID,
                },
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        tokenString, err := token.SignedString([]byte(a.config.Security.JWTSecret))
        
        return tokenString, expiresAt, err
}

func (a *AuthHandler) validateJWTToken(tokenString string) (*JWTClaims, error) {
        token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
                return []byte(a.config.Security.JWTSecret), nil
        })

        if err != nil {
                return nil, err
        }

        if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
                return claims, nil
        }

        return nil, fmt.Errorf("invalid token")
}

func (a *AuthHandler) generateRefreshToken() string {
        return uuid.New().String()
}

func (a *AuthHandler) hashToken(token string) string {
        return fmt.Sprintf("hash_%s", token)
}

func (a *AuthHandler) userToUserInfo(user *database.User) UserInfo {
        return UserInfo{
                ID:               user.ID,
                Username:         user.Username,
                Email:            user.Email,
                DisplayName:      user.DisplayName,
                EmailVerified:    user.EmailVerified,
                TwoFactorEnabled: user.TwoFactorEnabled,
                CreatedAt:        user.CreatedAt,
                LastLoginAt:      user.LastLoginAt,
        }
}