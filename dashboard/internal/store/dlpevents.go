package store

import (
	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
)

const dlpEventsRecentKey = "recent"

const maxDLPEvents = 400

// ListDLPEvents returns newest-first DLP events (up to limit).
func ListDLPEvents(db *bolt.DB, limit int) ([]models.DLPEvent, error) {
	var list []models.DLPEvent
	err := get(db, BucketDLPEvents, dlpEventsRecentKey, &list)
	if err != nil && err != ErrNotFound {
		return nil, err
	}
	if limit <= 0 || limit > len(list) {
		limit = len(list)
	}
	return list[:limit], nil
}

// AppendDLPEvent prepends an event and trims the list.
func AppendDLPEvent(db *bolt.DB, ev models.DLPEvent) error {
	var list []models.DLPEvent
	_ = get(db, BucketDLPEvents, dlpEventsRecentKey, &list)
	list = append([]models.DLPEvent{ev}, list...)
	if len(list) > maxDLPEvents {
		list = list[:maxDLPEvents]
	}
	return put(db, BucketDLPEvents, dlpEventsRecentKey, list)
}

// ClearDLPEvents removes stored DLP events.
func ClearDLPEvents(db *bolt.DB) error {
	return del(db, BucketDLPEvents, dlpEventsRecentKey)
}
