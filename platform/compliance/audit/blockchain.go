package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type AuditEvent struct {
	ID          string
	Timestamp   time.Time
	EventType   string
	ActorID     string
	ResourceID  string
	Action      string
	Result      string
	Metadata    map[string]interface{}
	IPFSHash    string
	BlockchainTx string
}

type AuditLogger struct {
	serviceName string
	ipfsClient  interface{}
	btcClient   interface{}
}

func NewAuditLogger(serviceName string, ipfsClient interface{}, btcClient interface{}) *AuditLogger {
	return &AuditLogger{
		serviceName: serviceName,
		ipfsClient:  ipfsClient,
		btcClient:   btcClient,
	}
}

func (al *AuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	
	eventHash := al.computeHash(event)
	
	fmt.Printf("[AUDIT] Event logged: %s - %s - %s (hash: %s)\n", 
		event.EventType, event.Action, event.Result, eventHash[:8])
	
	return nil
}

func (al *AuditLogger) computeHash(event *AuditEvent) string {
	data := fmt.Sprintf("%s-%s-%s-%s-%s", 
		event.ID, event.Timestamp.Format(time.RFC3339), 
		event.EventType, event.Action, event.Result)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
