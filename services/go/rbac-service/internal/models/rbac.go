package models

import (
	"time"
)

// User represents an enterprise user with FIPS compliance
type User struct {
	ID                string    `json:"id" db:"id"`
	Username          string    `json:"username" db:"username"`
	Email             string    `json:"email" db:"email"`
	PasswordHash      string    `json:"-" db:"password_hash"`
	IsActive          bool      `json:"is_active" db:"is_active"`
	IsSuperAdmin      bool      `json:"is_super_admin" db:"is_super_admin"`
	LastLogin         *time.Time `json:"last_login" db:"last_login"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
	FIPSCompliant     bool      `json:"fips_compliant" db:"fips_compliant"`
	QuantumSignature  string    `json:"-" db:"quantum_signature"`
	HSMKeyID          string    `json:"-" db:"hsm_key_id"`
}

// Role represents an enterprise role with cryptographic attestation
type Role struct {
	ID               string    `json:"id" db:"id"`
	Name             string    `json:"name" db:"name"`
	DisplayName      string    `json:"display_name" db:"display_name"`
	Description      string    `json:"description" db:"description"`
	IsSystemRole     bool      `json:"is_system_role" db:"is_system_role"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
	FIPSCompliant    bool      `json:"fips_compliant" db:"fips_compliant"`
	AuditTrailID     string    `json:"audit_trail_id" db:"audit_trail_id"`
}

// Permission represents a granular enterprise permission
type Permission struct {
	ID              string    `json:"id" db:"id"`
	Resource        string    `json:"resource" db:"resource"`
	Action          string    `json:"action" db:"action"`
	Scope           string    `json:"scope" db:"scope"`
	Description     string    `json:"description" db:"description"`
	IsSystemPerm    bool      `json:"is_system_perm" db:"is_system_perm"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	FIPSCompliant   bool      `json:"fips_compliant" db:"fips_compliant"`
	CryptoSignature string    `json:"-" db:"crypto_signature"`
}

// UserRole represents the many-to-many relationship between users and roles
type UserRole struct {
	UserID           string    `json:"user_id" db:"user_id"`
	RoleID           string    `json:"role_id" db:"role_id"`
	AssignedAt       time.Time `json:"assigned_at" db:"assigned_at"`
	AssignedBy       string    `json:"assigned_by" db:"assigned_by"`
	ExpiresAt        *time.Time `json:"expires_at" db:"expires_at"`
	IsActive         bool      `json:"is_active" db:"is_active"`
	AuditRecordID    string    `json:"audit_record_id" db:"audit_record_id"`
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	RoleID           string    `json:"role_id" db:"role_id"`
	PermissionID     string    `json:"permission_id" db:"permission_id"`
	GrantedAt        time.Time `json:"granted_at" db:"granted_at"`
	GrantedBy        string    `json:"granted_by" db:"granted_by"`
	HSMSignature     string    `json:"-" db:"hsm_signature"`
}

// Session represents an enterprise user session with cryptographic validation
type Session struct {
	ID               string    `json:"id" db:"id"`
	UserID           string    `json:"user_id" db:"user_id"`
	Token            string    `json:"-" db:"token_hash"`
	IPAddress        string    `json:"ip_address" db:"ip_address"`
	UserAgent        string    `json:"user_agent" db:"user_agent"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	ExpiresAt        time.Time `json:"expires_at" db:"expires_at"`
	LastActivityAt   time.Time `json:"last_activity_at" db:"last_activity_at"`
	IsActive         bool      `json:"is_active" db:"is_active"`
	FIPSCompliant    bool      `json:"fips_compliant" db:"fips_compliant"`
	QuantumToken     string    `json:"-" db:"quantum_token"`
	HSMSignature     string    `json:"-" db:"hsm_signature"`
}

// AuditLog represents enterprise audit logging for RBAC operations
type AuditLog struct {
	ID               string    `json:"id" db:"id"`
	UserID           string    `json:"user_id" db:"user_id"`
	Action           string    `json:"action" db:"action"`
	Resource         string    `json:"resource" db:"resource"`
	ResourceID       string    `json:"resource_id" db:"resource_id"`
	IPAddress        string    `json:"ip_address" db:"ip_address"`
	UserAgent        string    `json:"user_agent" db:"user_agent"`
	Success          bool      `json:"success" db:"success"`
	ErrorMessage     string    `json:"error_message,omitempty" db:"error_message"`
	Timestamp        time.Time `json:"timestamp" db:"timestamp"`
	FIPSCompliant    bool      `json:"fips_compliant" db:"fips_compliant"`
	BlockchainAnchor string    `json:"blockchain_anchor" db:"blockchain_anchor"`
	HSMSignature     string    `json:"-" db:"hsm_signature"`
}

// Enterprise role constants
const (
	RoleSuperAdmin     = "super_admin"
	RoleAdmin          = "admin"
	RoleMerchant       = "merchant"
	RoleOperator       = "operator"
	RoleAuditor        = "auditor"
	RoleViewer         = "viewer"
)

// Enterprise permission constants
const (
	// Payment Gateway Permissions
	PermissionPaymentProcess     = "payment.process"
	PermissionPaymentView        = "payment.view"
	PermissionPaymentRefund      = "payment.refund"
	PermissionPaymentVoid        = "payment.void"
	
	// Security Service Permissions
	PermissionSecurityView       = "security.view"
	PermissionSecurityManage     = "security.manage"
	PermissionSecurityAudit      = "security.audit"
	
	// User Management Permissions
	PermissionUserCreate         = "user.create"
	PermissionUserView           = "user.view"
	PermissionUserUpdate         = "user.update"
	PermissionUserDelete         = "user.delete"
	
	// Role Management Permissions
	PermissionRoleCreate         = "role.create"
	PermissionRoleView           = "role.view"
	PermissionRoleUpdate         = "role.update"
	PermissionRoleDelete         = "role.delete"
	PermissionRoleAssign         = "role.assign"
	
	// System Administration Permissions
	PermissionSystemConfig       = "system.config"
	PermissionSystemMonitor      = "system.monitor"
	PermissionSystemAudit        = "system.audit"
	PermissionSystemBackup       = "system.backup"
)

// AuthContext represents the authenticated user context
type AuthContext struct {
	User        *User        `json:"user"`
	Roles       []Role       `json:"roles"`
	Permissions []Permission `json:"permissions"`
	Session     *Session     `json:"session"`
	IsValid     bool         `json:"is_valid"`
	ExpiresAt   time.Time    `json:"expires_at"`
}

// HasPermission checks if the user has a specific permission
func (ctx *AuthContext) HasPermission(resource, action string) bool {
	if !ctx.IsValid || ctx.User == nil {
		return false
	}

	// Super admin has all permissions
	if ctx.User.IsSuperAdmin {
		return true
	}

	// Check specific permissions
	for _, perm := range ctx.Permissions {
		if perm.Resource == resource && perm.Action == action {
			return true
		}
	}

	return false
}

// HasRole checks if the user has a specific role
func (ctx *AuthContext) HasRole(roleName string) bool {
	if !ctx.IsValid || ctx.User == nil {
		return false
	}

	for _, role := range ctx.Roles {
		if role.Name == roleName {
			return true
		}
	}

	return false
}

// IsExpired checks if the authentication context is expired
func (ctx *AuthContext) IsExpired() bool {
	return time.Now().After(ctx.ExpiresAt)
}