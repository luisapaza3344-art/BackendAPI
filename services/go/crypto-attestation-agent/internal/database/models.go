package database

import (
	"time"

	"gorm.io/gorm"
)

// AttestationRequest represents a cryptographic attestation request
type AttestationRequest struct {
	ID               string                 `gorm:"primaryKey;type:varchar(255)" json:"id"`
	SubjectID        string                 `gorm:"type:varchar(255);not null;index" json:"subject_id"`
	AttestationType  string                 `gorm:"type:varchar(100);not null" json:"attestation_type"`
	AlgorithmType    string                 `gorm:"type:varchar(50);not null" json:"algorithm_type"`
	PublicKey        []byte                 `gorm:"type:bytea;not null" json:"public_key"`
	Challenge        string                 `gorm:"type:text;not null" json:"challenge"`
	Nonce            string                 `gorm:"type:varchar(255);not null" json:"nonce"`
	Status           string                 `gorm:"type:varchar(50);not null;default:'pending'" json:"status"`
	AttestationData  []byte                 `gorm:"type:bytea" json:"attestation_data"`
	SignatureData    []byte                 `gorm:"type:bytea" json:"signature_data"`
	TrustChain       []byte                 `gorm:"type:bytea" json:"trust_chain"`
	Metadata         map[string]interface{} `gorm:"type:jsonb" json:"metadata"`
	ExpiresAt        *time.Time             `gorm:"type:timestamp" json:"expires_at"`
	FIPSCompliant    bool                   `gorm:"type:boolean;not null;default:true" json:"fips_compliant"`
	CreatedAt        time.Time              `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt        time.Time              `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt        gorm.DeletedAt         `gorm:"index" json:"deleted_at"`
}

// AttestationResult represents the result of a cryptographic attestation
type AttestationResult struct {
	ID                string                 `gorm:"primaryKey;type:varchar(255)" json:"id"`
	RequestID         string                 `gorm:"type:varchar(255);not null;index" json:"request_id"`
	SubjectID         string                 `gorm:"type:varchar(255);not null;index" json:"subject_id"`
	AttestationType   string                 `gorm:"type:varchar(100);not null" json:"attestation_type"`
	Result            string                 `gorm:"type:varchar(50);not null" json:"result"` // success, failed, revoked
	TrustLevel        int                    `gorm:"type:int;not null;default:0" json:"trust_level"` // 0-100
	Signature         []byte                 `gorm:"type:bytea;not null" json:"signature"`
	Certificate       []byte                 `gorm:"type:bytea" json:"certificate"`
	TrustChain        []byte                 `gorm:"type:bytea" json:"trust_chain"`
	Evidence          map[string]interface{} `gorm:"type:jsonb" json:"evidence"`
	Issuer            string                 `gorm:"type:varchar(255);not null" json:"issuer"`
	ValidFrom         time.Time              `gorm:"type:timestamp;not null" json:"valid_from"`
	ValidUntil        time.Time              `gorm:"type:timestamp;not null" json:"valid_until"`
	RevocationStatus  string                 `gorm:"type:varchar(50);default:'valid'" json:"revocation_status"`
	FIPSCompliant     bool                   `gorm:"type:boolean;not null;default:true" json:"fips_compliant"`
	IntegrityHash     string                 `gorm:"type:varchar(64);not null" json:"integrity_hash"`
	CreatedAt         time.Time              `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt         time.Time              `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt         gorm.DeletedAt         `gorm:"index" json:"deleted_at"`
}

// TrustAnchor represents a trusted certificate authority
type TrustAnchor struct {
	ID               string         `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Name             string         `gorm:"type:varchar(255);not null;unique" json:"name"`
	Certificate      []byte         `gorm:"type:bytea;not null" json:"certificate"`
	PublicKey        []byte         `gorm:"type:bytea;not null" json:"public_key"`
	KeyType          string         `gorm:"type:varchar(50);not null" json:"key_type"`
	Fingerprint      string         `gorm:"type:varchar(128);not null;unique" json:"fingerprint"`
	Status           string         `gorm:"type:varchar(50);not null;default:'active'" json:"status"`
	TrustLevel       int            `gorm:"type:int;not null;default:100" json:"trust_level"`
	ValidFrom        time.Time      `gorm:"type:timestamp;not null" json:"valid_from"`
	ValidUntil       time.Time      `gorm:"type:timestamp;not null" json:"valid_until"`
	RevocationURL    string         `gorm:"type:text" json:"revocation_url"`
	FIPSCompliant    bool           `gorm:"type:boolean;not null;default:true" json:"fips_compliant"`
	CreatedAt        time.Time      `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt        time.Time      `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

// HSMKey represents an HSM-managed cryptographic key
type HSMKey struct {
	ID            string         `gorm:"primaryKey;type:varchar(255)" json:"id"`
	KeyID         string         `gorm:"type:varchar(255);not null;unique" json:"key_id"`
	Label         string         `gorm:"type:varchar(255);not null" json:"label"`
	KeyType       string         `gorm:"type:varchar(50);not null" json:"key_type"`
	Algorithm     string         `gorm:"type:varchar(50);not null" json:"algorithm"`
	Purpose       string         `gorm:"type:varchar(100);not null" json:"purpose"`
	HSMProvider   string         `gorm:"type:varchar(100);not null" json:"hsm_provider"`
	SlotID        uint           `gorm:"type:int;not null" json:"slot_id"`
	PublicKey     []byte         `gorm:"type:bytea" json:"public_key"`
	Status        string         `gorm:"type:varchar(50);not null;default:'active'" json:"status"`
	UsageCount    int64          `gorm:"type:bigint;not null;default:0" json:"usage_count"`
	LastUsedAt    *time.Time     `gorm:"type:timestamp" json:"last_used_at"`
	FIPSCompliant bool           `gorm:"type:boolean;not null;default:true" json:"fips_compliant"`
	CreatedAt     time.Time      `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt     time.Time      `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

// AuditLog represents security audit events
type AuditLog struct {
	ID            string                 `gorm:"primaryKey;type:varchar(255)" json:"id"`
	EventType     string                 `gorm:"type:varchar(100);not null;index" json:"event_type"`
	SubjectID     string                 `gorm:"type:varchar(255);index" json:"subject_id"`
	UserID        string                 `gorm:"type:varchar(255);index" json:"user_id"`
	Resource      string                 `gorm:"type:varchar(255);index" json:"resource"`
	Action        string                 `gorm:"type:varchar(100);not null" json:"action"`
	Result        string                 `gorm:"type:varchar(50);not null" json:"result"`
	ClientIP      string                 `gorm:"type:varchar(45)" json:"client_ip"`
	UserAgent     string                 `gorm:"type:text" json:"user_agent"`
	RequestID     string                 `gorm:"type:varchar(255);index" json:"request_id"`
	Details       map[string]interface{} `gorm:"type:jsonb" json:"details"`
	RiskLevel    string                 `gorm:"type:varchar(50);not null;default:'low'" json:"risk_level"`
	IntegrityHash string                 `gorm:"type:varchar(64);not null" json:"integrity_hash"`
	FIPSCompliant bool                   `gorm:"type:boolean;not null;default:true" json:"fips_compliant"`
	CreatedAt     time.Time              `gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName overrides for GORM
func (AttestationRequest) TableName() string {
	return "attestation_requests"
}

func (AttestationResult) TableName() string {
	return "attestation_results"
}

func (TrustAnchor) TableName() string {
	return "trust_anchors"
}

func (HSMKey) TableName() string {
	return "hsm_keys"
}

func (AuditLog) TableName() string {
	return "audit_logs"
}