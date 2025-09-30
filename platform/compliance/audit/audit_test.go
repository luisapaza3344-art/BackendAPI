package audit

import (
        "context"
        "testing"
        "time"
)

// Mock stores for testing
type mockBlockchainStore struct{}

func (m *mockBlockchainStore) AnchorHash(ctx context.Context, hash string) (string, error) {
        return "mock-blockchain-tx-" + hash[:8], nil
}

type mockIPFSStore struct{}

func (m *mockIPFSStore) Store(ctx context.Context, data []byte) (string, error) {
        return "mock-ipfs-cid-" + string(data[:10]), nil
}

func TestAuditTrailIntegrity(t *testing.T) {
        ctx := context.Background()
        
        // Create audit logger with mock stores
        logger := NewAuditLogger(
                "test-service",
                &mockBlockchainStore{},
                &mockIPFSStore{},
        )
        
        // Create test events
        events := []*AuditEvent{
                {
                        ID:         "event-1",
                        Timestamp:  time.Now(),
                        EventType:  "user.login",
                        ActorID:    "user-123",
                        ResourceID: "/auth/login",
                        Action:     "POST",
                        Result:     "success",
                        Metadata:   make(map[string]interface{}),
                },
                {
                        ID:         "event-2",
                        Timestamp:  time.Now(),
                        EventType:  "payment.created",
                        ActorID:    "user-123",
                        ResourceID: "payment-456",
                        Action:     "CREATE",
                        Result:     "success",
                        Metadata:   make(map[string]interface{}),
                },
                {
                        ID:         "event-3",
                        Timestamp:  time.Now(),
                        EventType:  "payment.completed",
                        ActorID:    "system",
                        ResourceID: "payment-456",
                        Action:     "UPDATE",
                        Result:     "success",
                        Metadata:   make(map[string]interface{}),
                },
        }
        
        // Log all events (builds the chain)
        for _, event := range events {
                if err := logger.Log(ctx, event); err != nil {
                        t.Fatalf("Failed to log event %s: %v", event.ID, err)
                }
        }
        
        // Convert to slice for verification
        eventSlice := make([]AuditEvent, len(events))
        for i, e := range events {
                eventSlice[i] = *e
        }
        
        // Verify integrity (should pass)
        valid, err := logger.VerifyIntegrity(ctx, eventSlice)
        if err != nil {
                t.Fatalf("Integrity verification failed: %v", err)
        }
        if !valid {
                t.Fatal("Integrity verification returned false")
        }
        
        t.Log("✅ Audit trail integrity verified successfully")
}

func TestAuditTrailTamperDetection(t *testing.T) {
        ctx := context.Background()
        
        logger := NewAuditLogger("test-service", nil, nil)
        
        // Create and log events
        event1 := &AuditEvent{
                ID:         "event-1",
                Timestamp:  time.Now(),
                EventType:  "test.event",
                ActorID:    "user-1",
                ResourceID: "resource-1",
                Action:     "CREATE",
                Result:     "success",
                Metadata:   make(map[string]interface{}),
        }
        
        event2 := &AuditEvent{
                ID:         "event-2",
                Timestamp:  time.Now(),
                EventType:  "test.event",
                ActorID:    "user-2",
                ResourceID: "resource-2",
                Action:     "UPDATE",
                Result:     "success",
                Metadata:   make(map[string]interface{}),
        }
        
        if err := logger.Log(ctx, event1); err != nil {
                t.Fatalf("Failed to log event1: %v", err)
        }
        if err := logger.Log(ctx, event2); err != nil {
                t.Fatalf("Failed to log event2: %v", err)
        }
        
        // Tamper with event 1 (modify actor)
        event1.ActorID = "tampered-user"
        
        // Verification should fail
        valid, err := logger.VerifyIntegrity(ctx, []AuditEvent{*event1, *event2})
        if err == nil {
                t.Fatal("Expected integrity verification to fail with error, but got no error")
        }
        if valid {
                t.Fatal("Expected integrity verification to return false, but got true")
        }
        
        t.Logf("✅ Tamper detection working correctly: %v", err)
}

func TestCanonicalizeEventDeterministic(t *testing.T) {
        event := &AuditEvent{
                ID:              "test-1",
                Timestamp:       time.Date(2025, 9, 30, 12, 0, 0, 0, time.UTC),
                ServiceName:     "test-service",
                EventType:       "test.event",
                ActorID:         "user-1",
                ResourceID:      "resource-1",
                Action:          "CREATE",
                Result:          "success",
                Metadata:        map[string]interface{}{"key1": "value1", "key2": "value2"},
                ComplianceLevel: "FIPS_140-3_Level_3",
                FIPSMode:        true,
        }
        
        // Canonicalize multiple times
        canonical1, err1 := canonicalizeEvent(event, "prev-hash-123")
        canonical2, err2 := canonicalizeEvent(event, "prev-hash-123")
        
        if err1 != nil || err2 != nil {
                t.Fatalf("Canonicalization failed: %v, %v", err1, err2)
        }
        
        if string(canonical1) != string(canonical2) {
                t.Fatal("Canonicalization is not deterministic")
        }
        
        t.Log("✅ Canonicalization is deterministic (within same struct fields)")
}

func TestCanonicalizeExcludesMutableMetadata(t *testing.T) {
        event := &AuditEvent{
                ID:         "test-1",
                Timestamp:  time.Date(2025, 9, 30, 12, 0, 0, 0, time.UTC),
                EventType:  "test.event",
                ActorID:    "user-1",
                ResourceID: "resource-1",
                Action:     "CREATE",
                Result:     "success",
                Metadata: map[string]interface{}{
                        "user_data":       "important",
                        "chain_hash":      "should-be-excluded",
                        "previous_hash":   "should-be-excluded",
                        "blockchain_hash": "should-be-excluded",
                        "ipfs_hash":       "should-be-excluded",
                        "pq_signature":    "should-be-excluded",
                },
        }
        
        canonical1, err := canonicalizeEvent(event, "prev-123")
        if err != nil {
                t.Fatalf("Canonicalization failed: %v", err)
        }
        
        // Modify mutable metadata fields
        event.Metadata["chain_hash"] = "different-value"
        event.Metadata["blockchain_hash"] = "different-value"
        event.Metadata["ipfs_hash"] = "different-value"
        
        canonical2, err := canonicalizeEvent(event, "prev-123")
        if err != nil {
                t.Fatalf("Canonicalization failed: %v", err)
        }
        
        // Hashes should be IDENTICAL because mutable fields are excluded
        if string(canonical1) != string(canonical2) {
                t.Fatal("Canonicalization should exclude mutable metadata fields")
        }
        
        // Verify that "user_data" IS included (affects hash)
        event.Metadata["user_data"] = "modified"
        canonical3, err := canonicalizeEvent(event, "prev-123")
        if err != nil {
                t.Fatalf("Canonicalization failed: %v", err)
        }
        
        if string(canonical1) == string(canonical3) {
                t.Fatal("Canonicalization should include immutable metadata fields")
        }
        
        t.Log("✅ Canonicalization correctly excludes mutable metadata fields")
}
