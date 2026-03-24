package store

import (
	"encoding/json"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"

	"flux-waf/internal/models"
)

var ErrNotFound = errors.New("not found")

const (
	BucketUsers      = "users"
	BucketSessions   = "sessions"
	BucketHosts      = "hosts"
	BucketSettings   = "settings"
	BucketStatsHourly = "stats_hourly"
	BucketAttackMap     = "attack_map"
	BucketThreatIntel    = "threat_intel"
	BucketSecurityEvents = "security_events"
	BucketBotBlocked     = "bot_blocked"
	BucketDLPEvents      = "dlp_events"
	BucketTLSCerts       = "tls_certs"
)

// Open opens the BoltDB file. Creates the file if it does not exist.
func Open(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("bolt open %q: %w", path, err)
	}
	return db, nil
}

// InitBuckets creates all required buckets if they don't exist.
func InitBuckets(db *bolt.DB) error {
	buckets := []string{
		BucketUsers, BucketSessions, BucketHosts,
		BucketSettings, BucketStatsHourly, BucketAttackMap, BucketThreatIntel,
		BucketSecurityEvents, BucketBotBlocked, BucketDLPEvents,
		BucketTLSCerts,
	}
	return db.Update(func(tx *bolt.Tx) error {
		for _, name := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %q: %w", name, err)
			}
		}
		return nil
	})
}

// BootstrapAdmin creates the default admin user if no users exist.
// Password is taken from the argument; falls back to "admin" if empty.
func BootstrapAdmin(db *bolt.DB, password string) error {
	var count int
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketUsers))
		if b != nil {
			count = b.Stats().KeyN
		}
		return nil
	})
	if count > 0 {
		return nil
	}

	if password == "" {
		password = "admin"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	user := models.UserAccount{
		Username:     "admin",
		PasswordHash: string(hash),
		Role:         "admin",
	}
	return put(db, BucketUsers, "admin", user)
}

// ── generic helpers ───────────────────────────────────────────────────────────

func put(db *bolt.DB, bucket, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %q not found", bucket)
		}
		return b.Put([]byte(key), data)
	})
}

func get(db *bolt.DB, bucket, key string, v any) error {
	return db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return ErrNotFound
		}
		data := b.Get([]byte(key))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, v)
	})
}

func del(db *bolt.DB, bucket, key string) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(key))
	})
}

func listAll(db *bolt.DB, bucket string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			cp := make([]byte, len(v))
			copy(cp, v)
			result[string(k)] = cp
			return nil
		})
	})
	return result, err
}
