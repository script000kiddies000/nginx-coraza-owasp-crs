package store

import (
	"errors"

	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
)

const securityEventsRecentKey = "recent"

// AppendSecurityEvent prepends an event and keeps at most maxRecentSecurityEvents.
func AppendSecurityEvent(db *bolt.DB, ev models.SecurityEvent) error {
	var list []models.SecurityEvent
	err := get(db, BucketSecurityEvents, securityEventsRecentKey, &list)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	list = append([]models.SecurityEvent{ev}, list...)
	const maxRecentSecurityEvents = 500
	if len(list) > maxRecentSecurityEvents {
		list = list[:maxRecentSecurityEvents]
	}
	return put(db, BucketSecurityEvents, securityEventsRecentKey, list)
}

// ListSecurityEvents returns the most recent events (newest first), capped by limit.
func ListSecurityEvents(db *bolt.DB, limit int) ([]models.SecurityEvent, error) {
	var list []models.SecurityEvent
	err := get(db, BucketSecurityEvents, securityEventsRecentKey, &list)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(list) > limit {
		return list[:limit], nil
	}
	return list, nil
}
