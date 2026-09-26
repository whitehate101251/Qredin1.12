package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/qredin/qredin/authentication/internal/registration"
)

// RecordRegistrationChange adapts the registration lifecycle audit contract
// to the durable append-only audit table.
func (r *AuditRepository) RecordRegistrationChange(change registration.ChangeEvent) error {
	eventID, err := uuidv4()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(change)
	if err != nil {
		return fmt.Errorf("store: encoding registration audit: %w", err)
	}
	return r.Append(context.Background(), AuditEvent{
		EventID: eventID, EventType: "registration." + change.Action,
		Payload: payload, OccurredAt: time.Now().UTC(),
	})
}

func uuidv4() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("store: generating audit event ID: %w", err)
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], bytes[0:4])
	hex.Encode(encoded[9:13], bytes[4:6])
	hex.Encode(encoded[14:18], bytes[6:8])
	hex.Encode(encoded[19:23], bytes[8:10])
	hex.Encode(encoded[24:36], bytes[10:16])
	encoded[8], encoded[13], encoded[18], encoded[23] = '-', '-', '-', '-'
	return string(encoded), nil
}
