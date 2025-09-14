package database

import (
        "time"
)

// User represents a user with FIPS-compliant identity management
type User struct {
        ID                string     `gorm:"primaryKey;type:varchar(36)" json:"id"`
        Username          string     `gorm:"uniqueIndex;not null" json:"username"`
        Email             string     `gorm:"uniqueIndex;not null" json:"email"`
        DisplayName       string     `gorm:"not null" json:"display_name"`
        PasswordHash      string     `gorm:"column:password_hash" json:"-"` // Never serialize passwords
        EmailVerified     bool       `gorm:"default:false" json:"email_verified"`
        TwoFactorEnabled  bool       `gorm:"default:false" json:"two_factor_enabled"`
        FIPSCompliant     bool       `gorm:"default:true" json:"fips_compliant"`
        CreatedAt         time.Time  `json:"created_at"`
        UpdatedAt         time.Time  `json:"updated_at"`
        LastLoginAt       *time.Time `json:"last_login_at"`
        
        // Relationships
        DIDs                []DIDDocument      `gorm:"foreignKey:UserID" json:"dids,omitempty"`
        WebAuthnCredentials []WebAuthnCredential `gorm:"foreignKey:UserID" json:"webauthn_credentials,omitempty"`
        Sessions            []UserSession      `gorm:"foreignKey:UserID" json:"sessions,omitempty"`
        VerifiableCredentials []VerifiableCredential `gorm:"foreignKey:UserID" json:"verifiable_credentials,omitempty"`
}

// DIDDocument represents a W3C Decentralized Identifier Document with FIPS compliance
type DIDDocument struct {
        ID               string    `gorm:"primaryKey;type:varchar(255)" json:"id"` // DID string
        UserID           string    `gorm:"not null;index" json:"user_id"`
        Method           string    `gorm:"not null" json:"method"` // "web", "key", "ion"
        Document         string    `gorm:"type:text;not null" json:"document"` // JSON DID Document
        PrivateKeyJWK    string    `gorm:"type:text" json:"-"` // Encrypted private key (FIPS)
        PublicKeyJWK     string    `gorm:"type:text;not null" json:"public_key_jwk"`
        KeyType          string    `gorm:"not null" json:"key_type"` // "Ed25519", "secp256k1", "P-256"
        IsActive         bool      `gorm:"default:true" json:"is_active"`
        FIPSCompliant    bool      `gorm:"default:true" json:"fips_compliant"`
        CreatedAt        time.Time `json:"created_at"`
        UpdatedAt        time.Time `json:"updated_at"`
        
        // Relationships
        User                  User                   `gorm:"foreignKey:UserID" json:"user,omitempty"`
        VerifiableCredentials []VerifiableCredential `gorm:"foreignKey:DIDDocumentID" json:"verifiable_credentials,omitempty"`
}

// VerifiableCredential represents a W3C Verifiable Credential with FIPS signatures
type VerifiableCredential struct {
        ID            string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
        UserID        string    `gorm:"not null;index" json:"user_id"`
        DIDDocumentID string    `gorm:"not null;index" json:"did_document_id"`
        IssuerDID     string    `gorm:"not null" json:"issuer_did"`
        SubjectDID    string    `gorm:"not null" json:"subject_did"`
        Type          string    `gorm:"not null" json:"type"` // "VerifiableCredential", specific type
        Credential    string    `gorm:"type:text;not null" json:"credential"` // JSON-LD VC
        Proof         string    `gorm:"type:text;not null" json:"proof"` // FIPS signature proof
        Status        string    `gorm:"default:active" json:"status"` // "active", "revoked", "suspended"
        ExpiresAt     *time.Time `json:"expires_at"`
        FIPSCompliant bool      `gorm:"default:true" json:"fips_compliant"`
        CreatedAt     time.Time `json:"created_at"`
        UpdatedAt     time.Time `json:"updated_at"`
        
        // Relationships
        User        User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
        DIDDocument DIDDocument `gorm:"foreignKey:DIDDocumentID" json:"did_document,omitempty"`
}

// WebAuthnCredential represents a FIPS-compliant WebAuthn/Passkey credential
type WebAuthnCredential struct {
        ID              string    `gorm:"primaryKey;type:varchar(255)" json:"id"` // Credential ID (base64)
        UserID          string    `gorm:"not null;index" json:"user_id"`
        CredentialID    []byte    `gorm:"not null" json:"credential_id"` // Raw credential ID
        PublicKey       []byte    `gorm:"not null" json:"public_key"` // COSE public key
        AttestationType string    `gorm:"not null" json:"attestation_type"` // "none", "basic", "self", "attca", "ecdaa"
        Transport       string    `gorm:"not null" json:"transport"` // "usb", "nfc", "ble", "internal"
        AuthenticatorData []byte  `gorm:"not null" json:"authenticator_data"`
        ClientDataJSON  []byte    `gorm:"not null" json:"client_data_json"`
        SignCount       uint32    `gorm:"not null" json:"sign_count"`
        CloneWarning    bool      `gorm:"default:false" json:"clone_warning"`
        DeviceName      string    `json:"device_name"`
        IsPasskey       bool      `gorm:"default:false" json:"is_passkey"`
        FIPSCompliant   bool      `gorm:"default:true" json:"fips_compliant"`
        CreatedAt       time.Time `json:"created_at"`
        UpdatedAt       time.Time `json:"updated_at"`
        LastUsedAt      *time.Time `json:"last_used_at"`
        
        // Relationships
        User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// UserSession represents a FIPS-compliant user session
type UserSession struct {
        ID            string    `gorm:"primaryKey;type:varchar(36)" json:"id"`
        UserID        string    `gorm:"not null;index" json:"user_id"`
        SessionToken  string    `gorm:"uniqueIndex;not null" json:"-"` // Hashed session token
        RefreshToken  string    `gorm:"uniqueIndex" json:"-"` // Hashed refresh token
        DeviceInfo    string    `gorm:"type:text" json:"device_info"` // JSON device information
        IPAddress     string    `json:"ip_address"`
        UserAgent     string    `gorm:"type:text" json:"user_agent"`
        AuthMethod    string    `gorm:"not null" json:"auth_method"` // "password", "webauthn", "did"
        FIPSCompliant bool      `gorm:"default:true" json:"fips_compliant"`
        IsActive      bool      `gorm:"default:true" json:"is_active"`
        ExpiresAt     time.Time `gorm:"not null" json:"expires_at"`
        CreatedAt     time.Time `json:"created_at"`
        UpdatedAt     time.Time `json:"updated_at"`
        
        // Relationships
        User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// AuditLog represents FIPS-compliant audit logging for compliance
type AuditLog struct {
        ID            string    `gorm:"primaryKey;type:varchar(36)" json:"id"`
        UserID        *string   `gorm:"index" json:"user_id"` // Nullable for system events
        EventType     string    `gorm:"not null;index" json:"event_type"` // "login", "logout", "credential_create", etc.
        EventData     string    `gorm:"type:text" json:"event_data"` // JSON event details
        IPAddress     string    `json:"ip_address"`
        UserAgent     string    `gorm:"type:text" json:"user_agent"`
        Result        string    `gorm:"not null" json:"result"` // "success", "failure", "error"
        ErrorMessage  string    `gorm:"type:text" json:"error_message"`
        FIPSCompliant bool      `gorm:"default:true" json:"fips_compliant"`
        IntegrityHash string    `gorm:"not null" json:"integrity_hash"` // FIPS integrity protection
        CreatedAt     time.Time `gorm:"not null" json:"created_at"`
        
        // Relationships
        User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// DIDRegistry represents a decentralized identifier registry for DID resolution
type DIDRegistry struct {
        ID            string    `gorm:"primaryKey;type:varchar(255)" json:"id"` // DID string
        Method        string    `gorm:"not null;index" json:"method"`
        Document      string    `gorm:"type:text;not null" json:"document"` // JSON DID Document
        Status        string    `gorm:"default:active" json:"status"` // "active", "deactivated"
        Version       int       `gorm:"default:1" json:"version"`
        UpdateKey     string    `gorm:"type:text" json:"update_key"` // Key for updates (if applicable)
        FIPSCompliant bool      `gorm:"default:true" json:"fips_compliant"`
        CreatedAt     time.Time `json:"created_at"`
        UpdatedAt     time.Time `json:"updated_at"`
}

// WebAuthnSession represents temporary WebAuthn authentication sessions
type WebAuthnSession struct {
        ID            string    `gorm:"primaryKey;type:varchar(36)" json:"id"`
        UserID        *string   `gorm:"index" json:"user_id"` // Nullable for registration
        Challenge     string    `gorm:"not null" json:"challenge"`
        UserHandle    []byte    `json:"user_handle"`
        SessionType   string    `gorm:"not null" json:"session_type"` // "registration", "authentication"
        SessionData   string    `gorm:"type:text;not null" json:"session_data"` // JSON session data
        FIPSCompliant bool      `gorm:"default:true" json:"fips_compliant"`
        ExpiresAt     time.Time `gorm:"not null" json:"expires_at"`
        CreatedAt     time.Time `json:"created_at"`
        
        // Relationships
        User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName overrides for GORM
func (User) TableName() string                  { return "users" }
func (DIDDocument) TableName() string           { return "did_documents" }
func (VerifiableCredential) TableName() string  { return "verifiable_credentials" }
func (WebAuthnCredential) TableName() string    { return "webauthn_credentials" }
func (UserSession) TableName() string           { return "user_sessions" }
func (AuditLog) TableName() string              { return "audit_logs" }
func (DIDRegistry) TableName() string           { return "did_registry" }
func (WebAuthnSession) TableName() string       { return "webauthn_sessions" }