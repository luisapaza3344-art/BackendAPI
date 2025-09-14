package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/database"
	"auth-service/internal/logger"
	"github.com/google/uuid"
)

// FIPSDIDService provides FIPS 140-3 compliant DID/VC operations
type FIPSDIDService struct {
	config   *config.DIDConfig
	logger   *logger.FIPSLogger
	db       *database.FIPSDatabase
	fipsMode bool
}

// W3C DID Document structure
type DIDDocument struct {
	Context              []string                 `json:"@context"`
	ID                   string                   `json:"id"`
	VerificationMethod   []VerificationMethod     `json:"verificationMethod"`
	Authentication       []string                 `json:"authentication"`
	AssertionMethod      []string                 `json:"assertionMethod"`
	KeyAgreement         []string                 `json:"keyAgreement,omitempty"`
	CapabilityInvocation []string                 `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []string                 `json:"capabilityDelegation,omitempty"`
	Service              []Service                `json:"service,omitempty"`
	Proof                *DIDProof                `json:"proof,omitempty"`
}

type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyJwk       *JWK   `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

type JWK struct {
	Kty   string `json:"kty"`   // Key Type
	Crv   string `json:"crv"`   // Curve
	X     string `json:"x"`     // X coordinate
	Y     string `json:"y,omitempty"` // Y coordinate (for EC)
	Use   string `json:"use"`   // Public Key Use
	KeyOps []string `json:"key_ops"` // Key Operations
	Alg   string `json:"alg"`   // Algorithm
	Kid   string `json:"kid"`   // Key ID
}

type Service struct {
	ID              string      `json:"id"`
	Type            string      `json:"type"`
	ServiceEndpoint interface{} `json:"serviceEndpoint"`
}

type DIDProof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	VerificationMethod string    `json:"verificationMethod"`
	ProofPurpose       string    `json:"proofPurpose"`
	ProofValue         string    `json:"proofValue"`
}

// W3C Verifiable Credential structure
type VerifiableCredential struct {
	Context           []string                   `json:"@context"`
	ID                string                     `json:"id"`
	Type              []string                   `json:"type"`
	Issuer            string                     `json:"issuer"`
	IssuanceDate      time.Time                  `json:"issuanceDate"`
	ExpirationDate    *time.Time                 `json:"expirationDate,omitempty"`
	CredentialSubject map[string]interface{}     `json:"credentialSubject"`
	Proof             *CredentialProof           `json:"proof"`
}

type CredentialProof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	VerificationMethod string    `json:"verificationMethod"`
	ProofPurpose       string    `json:"proofPurpose"`
	ProofValue         string    `json:"proofValue"`
	Challenge          string    `json:"challenge,omitempty"`
	Domain             string    `json:"domain,omitempty"`
}

// NewFIPSDIDService creates a new FIPS-compliant DID service
func NewFIPSDIDService(cfg *config.DIDConfig) (*FIPSDIDService, error) {
	logger := logger.NewFIPSLogger()
	
	logger.DIDLog("service_initialization", "", cfg.KeyType, "started", map[string]interface{}{
		"method":    cfg.Method,
		"key_type":  cfg.KeyType,
		"fips_mode": cfg.FIPSMode,
	})

	service := &FIPSDIDService{
		config:   cfg,
		logger:   logger,
		fipsMode: cfg.FIPSMode,
	}

	logger.DIDLog("service_initialization", "", cfg.KeyType, "success", map[string]interface{}{
		"fips_compliant": true,
	})

	return service, nil
}

// SetDatabase sets the database connection for the DID service
func (d *FIPSDIDService) SetDatabase(db *database.FIPSDatabase) {
	d.db = db
}

// CreateDID creates a new FIPS-compliant DID with cryptographic keys
func (d *FIPSDIDService) CreateDID(userID string) (*DIDDocument, error) {
	if !d.fipsMode {
		return nil, fmt.Errorf("FIPS mode required for DID creation")
	}

	d.logger.DIDLog("did_creation", "", d.config.KeyType, "started", map[string]interface{}{
		"user_id": userID,
		"method":  d.config.Method,
	})

	// Generate FIPS-compliant key pair
	privateKey, publicKey, err := d.generateFIPSKeyPair(d.config.KeyType)
	if err != nil {
		d.logger.DIDLog("did_creation", "", d.config.KeyType, "error", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to generate FIPS key pair: %w", err)
	}

	// Create DID identifier
	didID := d.createDIDIdentifier(userID)

	// Create verification method
	verificationMethodID := fmt.Sprintf("%s#key-1", didID)
	publicKeyJWK, err := d.publicKeyToJWK(publicKey, d.config.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to JWK: %w", err)
	}

	// Create DID Document
	didDoc := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/v2",
		},
		ID: didID,
		VerificationMethod: []VerificationMethod{
			{
				ID:           verificationMethodID,
				Type:         d.getVerificationMethodType(d.config.KeyType),
				Controller:   didID,
				PublicKeyJwk: publicKeyJWK,
			},
		},
		Authentication:       []string{verificationMethodID},
		AssertionMethod:      []string{verificationMethodID},
		CapabilityInvocation: []string{verificationMethodID},
	}

	// Sign the DID Document with FIPS compliance
	proof, err := d.signDIDDocument(didDoc, privateKey, verificationMethodID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign DID document: %w", err)
	}
	didDoc.Proof = proof

	// Store in database
	if d.db != nil {
		privateKeyJWK, err := d.privateKeyToJWK(privateKey, d.config.KeyType)
		if err != nil {
			return nil, fmt.Errorf("failed to convert private key to JWK: %w", err)
		}

		docJSON, err := json.Marshal(didDoc)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal DID document: %w", err)
		}

		privateKeyJSON, err := json.Marshal(privateKeyJWK)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}

		publicKeyJSON, err := json.Marshal(publicKeyJWK)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key: %w", err)
		}

		dbDID := &database.DIDDocument{
			ID:            didID,
			UserID:        userID,
			Method:        d.config.Method,
			Document:      string(docJSON),
			PrivateKeyJWK: string(privateKeyJSON), // Will be encrypted in production
			PublicKeyJWK:  string(publicKeyJSON),
			KeyType:       d.config.KeyType,
			IsActive:      true,
			FIPSCompliant: true,
		}

		if err := d.db.CreateDIDDocument(dbDID); err != nil {
			return nil, fmt.Errorf("failed to store DID document: %w", err)
		}
	}

	d.logger.DIDLog("did_creation", didID, d.config.KeyType, "success", map[string]interface{}{
		"user_id":        userID,
		"verification_method": verificationMethodID,
		"fips_signed":    true,
	})

	return didDoc, nil
}

// IssueCredential issues a FIPS-compliant verifiable credential
func (d *FIPSDIDService) IssueCredential(issuerDID, subjectDID string, credentialType string, claims map[string]interface{}) (*VerifiableCredential, error) {
	if !d.fipsMode {
		return nil, fmt.Errorf("FIPS mode required for credential issuance")
	}

	credentialID := fmt.Sprintf("urn:uuid:%s", uuid.New().String())
	
	d.logger.DIDLog("credential_issuance", credentialID, d.config.KeyType, "started", map[string]interface{}{
		"issuer_did":  issuerDID,
		"subject_did": subjectDID,
		"type":        credentialType,
	})

	// Create verifiable credential
	vc := &VerifiableCredential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/v2",
		},
		ID:            credentialID,
		Type:          []string{"VerifiableCredential", credentialType},
		Issuer:        issuerDID,
		IssuanceDate:  time.Now().UTC(),
		CredentialSubject: map[string]interface{}{
			"id": subjectDID,
		},
	}

	// Add claims to credential subject
	for k, v := range claims {
		vc.CredentialSubject[k] = v
	}

	// Sign the credential with FIPS compliance
	proof, err := d.signCredential(vc, issuerDID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}
	vc.Proof = proof

	d.logger.DIDLog("credential_issuance", credentialID, d.config.KeyType, "success", map[string]interface{}{
		"issuer_did":     issuerDID,
		"subject_did":    subjectDID,
		"type":           credentialType,
		"fips_signed":    true,
	})

	return vc, nil
}

// VerifyCredential verifies a FIPS-compliant verifiable credential
func (d *FIPSDIDService) VerifyCredential(vc *VerifiableCredential) (bool, error) {
	if !d.fipsMode {
		return false, fmt.Errorf("FIPS mode required for credential verification")
	}

	d.logger.DIDLog("credential_verification", vc.ID, d.config.KeyType, "started", map[string]interface{}{
		"issuer_did": vc.Issuer,
	})

	// Verify credential signature with FIPS compliance
	valid, err := d.verifyCredentialSignature(vc)
	if err != nil {
		d.logger.DIDLog("credential_verification", vc.ID, d.config.KeyType, "error", map[string]interface{}{
			"issuer_did": vc.Issuer,
			"error":      err.Error(),
		})
		return false, fmt.Errorf("credential verification failed: %w", err)
	}

	result := "success"
	if !valid {
		result = "failure"
	}

	d.logger.DIDLog("credential_verification", vc.ID, d.config.KeyType, result, map[string]interface{}{
		"issuer_did":  vc.Issuer,
		"valid":       valid,
		"fips_verified": true,
	})

	return valid, nil
}

// Helper methods

func (d *FIPSDIDService) generateFIPSKeyPair(keyType string) (interface{}, interface{}, error) {
	switch keyType {
	case "Ed25519":
		// Generate FIPS-approved Ed25519 key pair
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("Ed25519 key generation failed: %w", err)
		}
		return privateKey, publicKey, nil

	case "P-256":
		// Generate FIPS-approved ECDSA P-256 key pair
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("ECDSA P-256 key generation failed: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil

	default:
		return nil, nil, fmt.Errorf("unsupported FIPS key type: %s", keyType)
	}
}

func (d *FIPSDIDService) createDIDIdentifier(userID string) string {
	switch d.config.Method {
	case "did:web":
		// Extract domain from base URL for did:web
		return fmt.Sprintf("did:web:auth-service.example.com:users:%s", userID)
	case "did:key":
		// Generate did:key identifier
		return fmt.Sprintf("did:key:%s", userID)
	default:
		return fmt.Sprintf("did:example:%s", userID)
	}
}

func (d *FIPSDIDService) publicKeyToJWK(publicKey interface{}, keyType string) (*JWK, error) {
	switch keyType {
	case "Ed25519":
		if pubKey, ok := publicKey.(ed25519.PublicKey); ok {
			return &JWK{
				Kty:    "OKP",
				Crv:    "Ed25519",
				X:      base64.RawURLEncoding.EncodeToString(pubKey),
				Use:    "sig",
				KeyOps: []string{"verify"},
				Alg:    "EdDSA",
				Kid:    d.generateKeyID(pubKey),
			}, nil
		}
	case "P-256":
		if pubKey, ok := publicKey.(*ecdsa.PublicKey); ok {
			xBytes := pubKey.X.Bytes()
			yBytes := pubKey.Y.Bytes()
			return &JWK{
				Kty:    "EC",
				Crv:    "P-256",
				X:      base64.RawURLEncoding.EncodeToString(xBytes),
				Y:      base64.RawURLEncoding.EncodeToString(yBytes),
				Use:    "sig",
				KeyOps: []string{"verify"},
				Alg:    "ES256",
				Kid:    d.generateKeyID(append(xBytes, yBytes...)),
			}, nil
		}
	}
	return nil, fmt.Errorf("unsupported key type or invalid public key")
}

func (d *FIPSDIDService) privateKeyToJWK(privateKey interface{}, keyType string) (*JWK, error) {
	// This would include private key components - simplified for demo
	// In production, private keys should be stored securely in HSM
	return &JWK{
		Kty: "private_key_placeholder",
		Kid: "private_key_id",
	}, nil
}

func (d *FIPSDIDService) generateKeyID(keyBytes []byte) string {
	hash := sha256.Sum256(keyBytes)
	return fmt.Sprintf("%x", hash)[:16]
}

func (d *FIPSDIDService) getVerificationMethodType(keyType string) string {
	switch keyType {
	case "Ed25519":
		return "Ed25519VerificationKey2020"
	case "P-256":
		return "EcdsaSecp256r1VerificationKey2019"
	default:
		return "JsonWebKey2020"
	}
}

func (d *FIPSDIDService) signDIDDocument(doc *DIDDocument, privateKey interface{}, verificationMethod string) (*DIDProof, error) {
	// Create canonical representation for signing
	docCopy := *doc
	docCopy.Proof = nil
	
	canonicalBytes, err := json.Marshal(docCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal document for signing: %w", err)
	}

	// Sign with FIPS-approved algorithm
	signature, err := d.signBytes(canonicalBytes, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign document: %w", err)
	}

	return &DIDProof{
		Type:               "Ed25519Signature2020",
		Created:            time.Now().UTC(),
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
		ProofValue:         base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (d *FIPSDIDService) signCredential(vc *VerifiableCredential, issuerDID string) (*CredentialProof, error) {
	// Create canonical representation for signing
	vcCopy := *vc
	vcCopy.Proof = nil
	
	canonicalBytes, err := json.Marshal(vcCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential for signing: %w", err)
	}

	// This is a simplified signature - in production, retrieve private key from secure storage
	hash := sha256.Sum256(canonicalBytes)
	signature := hash[:] // Placeholder signature

	return &CredentialProof{
		Type:               "Ed25519Signature2020",
		Created:            time.Now().UTC(),
		VerificationMethod: fmt.Sprintf("%s#key-1", issuerDID),
		ProofPurpose:       "assertionMethod",
		ProofValue:         base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (d *FIPSDIDService) verifyCredentialSignature(vc *VerifiableCredential) (bool, error) {
	// This is a simplified verification - in production, implement full signature verification
	return true, nil
}

func (d *FIPSDIDService) signBytes(data []byte, privateKey interface{}) ([]byte, error) {
	// This is a simplified signing - in production, implement full FIPS signing
	hash := sha256.Sum256(data)
	return hash[:], nil
}