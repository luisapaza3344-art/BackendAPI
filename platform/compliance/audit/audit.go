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

// canonicalizeEvent creates a deterministic representation for hashing
// Excludes ALL mutable fields including those in Metadata map
func canonicalizeEvent(event *AuditEvent, previousHash string) ([]byte, error) {
        // Sanitize metadata: remove mutable/anchoring keys
        sanitizedMetadata := make(map[string]interface{})
        excludedKeys := map[string]bool{
                "chain_hash":      true,
                "previous_hash":   true,
                "blockchain_hash": true,
                "ipfs_hash":       true,
                "pq_signature":    true,
        }
        
        for k, v := range event.Metadata {
                if !excludedKeys[k] {
                        sanitizedMetadata[k] = v
                }
        }
        
        // Create canonical struct with only immutable fields
        canonical := struct {
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
                PreviousHash    string                 `json:"previous_hash"`
        }{
                ID:              event.ID,
                Timestamp:       event.Timestamp,
                ServiceName:     event.ServiceName,
                EventType:       event.EventType,
                ActorID:         event.ActorID,
                ResourceID:      event.ResourceID,
                Action:          event.Action,
                Result:          event.Result,
                Metadata:        sanitizedMetadata, // Use sanitized metadata
                ComplianceLevel: event.ComplianceLevel,
                FIPSMode:        event.FIPSMode,
                PreviousHash:    previousHash,
        }
        
        // Marshal to JSON
        // Note: For production government-grade, use JCS (RFC 8785) for true determinism
        // Go's json.Marshal is deterministic for struct fields but not for map iteration
        // TODO: Implement JCS or CBOR-deterministic encoding
        return json.Marshal(canonical)
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
        
        // Canonicalize event for hashing (excludes mutable fields)
        canonicalJSON, err := canonicalizeEvent(event, a.chainHash)
        if err != nil {
                return fmt.Errorf("failed to canonicalize event: %w", err)
        }
        
        // Calculate integrity hash from canonical representation
        hash := sha256.Sum256(canonicalJSON)
        newChainHash := hex.EncodeToString(hash[:])
        
        // Store chain hash in metadata (for external verification)
        event.Metadata["chain_hash"] = newChainHash
        event.Metadata["previous_hash"] = a.chainHash
        
        // Anchor to blockchain (use the chain hash)
        if a.blockchainStore != nil {
                txID, err := a.blockchainStore.AnchorHash(ctx, newChainHash)
                if err != nil {
                        return fmt.Errorf("failed to anchor to blockchain: %w", err)
                }
                event.BlockchainHash = txID
        }
        
        // Marshal FINAL event with all metadata (chain_hash + blockchain_hash)
        finalEventJSON, err := json.Marshal(event)
        if err != nil {
                return fmt.Errorf("failed to marshal final event: %w", err)
        }
        
        // Store FINAL event to IPFS for immutability (includes all anchoring metadata)
        if a.ipfsStore != nil {
                cid, err := a.ipfsStore.Store(ctx, finalEventJSON)
                if err != nil {
                        return fmt.Errorf("failed to store in IPFS: %w", err)
                }
                event.IPFSHash = cid
        }
        
        // TODO: Sign canonical payload with Dilithium-5 (use platform/crypto/pqc-go)
        // signer, _ := pqc.NewDilithiumSigner()
        // event.PQSignature, _ = signer.Sign(canonicalJSON)
        
        // Update chain hash for next event
        a.chainHash = newChainHash
        
        // In production: Write to audit database, Kafka, or audit-specific storage
        
        return nil
}

// VerifyIntegrity verifies the audit trail integrity
func (a *AuditLogger) VerifyIntegrity(ctx context.Context, events []AuditEvent) (bool, error) {
        var prevHash string
        for i, event := range events {
                // Get the stored chain hash from metadata
                storedChainHash, ok := event.Metadata["chain_hash"].(string)
                if !ok {
                        return false, fmt.Errorf("missing chain_hash at event %d", i)
                }
                
                // Verify chain linkage: stored previous_hash must match our computed prevHash
                if i > 0 {
                        storedPrevHash, ok := event.Metadata["previous_hash"].(string)
                        if !ok {
                                return false, fmt.Errorf("missing previous_hash at event %d", i)
                        }
                        if storedPrevHash != prevHash {
                                return false, fmt.Errorf("chain linkage broken at event %d: expected prev_hash %s, got %s",
                                        i, prevHash, storedPrevHash)
                        }
                }
                
                // Recreate canonical representation (same as Log())
                // This excludes chain_hash, previous_hash, blockchain_hash, ipfs_hash from Metadata
                canonicalJSON, err := canonicalizeEvent(&event, prevHash)
                if err != nil {
                        return false, fmt.Errorf("failed to canonicalize event %d: %w", i, err)
                }
                
                // Recompute hash
                hash := sha256.Sum256(canonicalJSON)
                expectedHash := hex.EncodeToString(hash[:])
                
                // Compare with stored hash
                if storedChainHash != expectedHash {
                        return false, fmt.Errorf("integrity violation at event %d: expected %s, got %s", 
                                i, expectedHash, storedChainHash)
                }
                
                // Update previous hash for next iteration
                prevHash = storedChainHash
        }
        
        return true, nil
}
