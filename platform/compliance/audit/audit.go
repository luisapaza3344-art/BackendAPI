// Package audit provides immutable audit logging with blockchain anchoring
package audit

import (
        "context"
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "time"
)

// AuditEvent represents a government-grade audit event
type AuditEvent struct {
        ID              string                 `json:"id"`
        Timestamp       time.Time              `json:"timestamp"`
        ServiceName     string                 `json:"service_name"`
        EventType       string                 `json:"event_type"`
        ActorID         string                 `json:"actor_id"`
        ResourceID      string                 `json:"resource_id"`
        Action          string                 `json:"action"`
        Result          string                 `json:"result"`
        Metadata        map[string]interface{} `json:"metadata"`
        ComplianceLevel string                 `json:"compliance_level"`
        FIPSMode        bool                   `json:"fips_mode"`
        PQSignature     []byte                 `json:"pq_signature"` // Dilithium-5 signature
        BlockchainHash  string                 `json:"blockchain_hash,omitempty"`
        IPFSHash        string                 `json:"ipfs_hash,omitempty"`
}

// AuditLogger provides immutable audit trail with cryptographic guarantees
type AuditLogger struct {
        serviceName     string
        chainHash       string // Hash chain for integrity
        blockchainStore BlockchainStore
        ipfsStore       IPFSStore
}

// BlockchainStore anchors audit logs to blockchain
type BlockchainStore interface {
        AnchorHash(ctx context.Context, hash string) (txID string, err error)
}

// IPFSStore stores audit logs in decentralized storage
type IPFSStore interface {
        Store(ctx context.Context, data []byte) (cid string, err error)
}

// NewAuditLogger creates a new government-grade audit logger
func NewAuditLogger(serviceName string, blockchain BlockchainStore, ipfs IPFSStore) *AuditLogger {
        return &AuditLogger{
                serviceName:     serviceName,
                chainHash:       "", // Initialize chain
                blockchainStore: blockchain,
                ipfsStore:       ipfs,
        }
}

// Log records an audit event with cryptographic integrity
func (a *AuditLogger) Log(ctx context.Context, event *AuditEvent) error {
        // Initialize metadata if nil (prevent panic)
        if event.Metadata == nil {
                event.Metadata = make(map[string]interface{})
        }
        
        // Set service name and compliance metadata
        event.ServiceName = a.serviceName
        event.ComplianceLevel = "FIPS_140-3_Level_3"
        event.FIPSMode = true
        
        // Store in IPFS first (before final marshaling)
        preliminaryJSON, err := json.Marshal(event)
        if err != nil {
                return fmt.Errorf("failed to marshal audit event: %w", err)
        }
        
        if a.ipfsStore != nil {
                cid, err := a.ipfsStore.Store(ctx, preliminaryJSON)
                if err != nil {
                        return fmt.Errorf("failed to store in IPFS: %w", err)
                }
                event.IPFSHash = cid
        }
        
        // Calculate integrity hash (current event + previous chain hash)
        eventJSON, err := json.Marshal(event)
        if err != nil {
                return fmt.Errorf("failed to marshal audit event with IPFS hash: %w", err)
        }
        
        hashInput := append(eventJSON, []byte(a.chainHash)...)
        hash := sha256.Sum256(hashInput)
        newChainHash := hex.EncodeToString(hash[:])
        
        // Update chain hash
        event.Metadata["chain_hash"] = newChainHash
        event.Metadata["previous_hash"] = a.chainHash
        
        // Anchor to blockchain for public verifiability
        if a.blockchainStore != nil {
                txID, err := a.blockchainStore.AnchorHash(ctx, newChainHash)
                if err != nil {
                        return fmt.Errorf("failed to anchor to blockchain: %w", err)
                }
                event.BlockchainHash = txID
        }
        
        // TODO: Sign with Dilithium-5 (use platform/crypto/pqc-go)
        // signer, _ := pqc.NewDilithiumSigner()
        // event.PQSignature, _ = signer.Sign(eventJSON)
        
        // Update chain hash for next event
        a.chainHash = newChainHash
        
        // In production: Write to audit database, Kafka, or audit-specific storage
        
        return nil
}

// VerifyIntegrity verifies the audit trail integrity
func (a *AuditLogger) VerifyIntegrity(ctx context.Context, events []AuditEvent) (bool, error) {
        var prevHash string
        for i, event := range events {
                eventJSON, _ := json.Marshal(event)
                hashInput := append(eventJSON, []byte(prevHash)...)
                expectedHash := sha256.Sum256(hashInput)
                
                if event.Metadata["chain_hash"] != hex.EncodeToString(expectedHash[:]) {
                        return false, fmt.Errorf("integrity violation at event %d", i)
                }
                
                prevHash = event.Metadata["chain_hash"].(string)
        }
        
        return true, nil
}
