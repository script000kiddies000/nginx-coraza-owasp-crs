package store

import (
	"encoding/json"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
)

// ListBotBlocked returns all blocked IPs (sorted by IP).
func ListBotBlocked(db *bolt.DB) ([]models.BotBlockedEntry, error) {
	var out []models.BotBlockedEntry
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketBotBlocked))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var e models.BotBlockedEntry
			if json.Unmarshal(v, &e) != nil {
				e = models.BotBlockedEntry{IP: string(k), Reason: "legacy"}
			}
			if e.IP == "" {
				e.IP = string(k)
			}
			out = append(out, e)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

// PutBotBlocked upserts a block entry.
func PutBotBlocked(db *bolt.DB, ip, reason string) error {
	if ip == "" {
		return nil
	}
	e := models.BotBlockedEntry{
		IP:        ip,
		BlockedAt: time.Now().UTC().Format(time.RFC3339),
		Reason:    reason,
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketBotBlocked))
		if b == nil {
			return bolt.ErrBucketNotFound
		}
		return b.Put([]byte(ip), data)
	})
}

// RemoveBotBlocked deletes one IP from the blocklist.
func RemoveBotBlocked(db *bolt.DB, ip string) error {
	return del(db, BucketBotBlocked, ip)
}
