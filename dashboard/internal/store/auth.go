package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"

	"flux-waf/internal/models"
)

// ── Users ─────────────────────────────────────────────────────────────────────

func GetUser(db *bolt.DB, username string) (models.UserAccount, error) {
	var u models.UserAccount
	err := get(db, BucketUsers, username, &u)
	return u, err
}

func SaveUser(db *bolt.DB, u models.UserAccount) error {
	return put(db, BucketUsers, u.Username, u)
}

func ValidatePassword(db *bolt.DB, username, password string) (models.UserAccount, error) {
	u, err := GetUser(db, username)
	if err != nil {
		return u, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return models.UserAccount{}, ErrNotFound
	}
	return u, nil
}

// ── Sessions ──────────────────────────────────────────────────────────────────

// CreateSession generates a cryptographically random token, stores it in BoltDB,
// and returns the token string.
func CreateSession(db *bolt.DB, username string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)

	s := models.Session{
		Username: username,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	if err := put(db, BucketSessions, token, s); err != nil {
		return "", err
	}
	return token, nil
}

// GetSession validates the token and returns the username if valid and not expired.
func GetSession(db *bolt.DB, token string) (string, error) {
	var s models.Session
	if err := get(db, BucketSessions, token, &s); err != nil {
		return "", err
	}
	if time.Now().After(s.Expires) {
		_ = del(db, BucketSessions, token)
		return "", ErrNotFound
	}
	return s.Username, nil
}

// DeleteSession removes a session (logout).
func DeleteSession(db *bolt.DB, token string) error {
	return del(db, BucketSessions, token)
}

// CleanExpiredSessions deletes all expired sessions — called by the session
// cleaner goroutine every hour.
func CleanExpiredSessions(db *bolt.DB) {
	rows, err := listAll(db, BucketSessions)
	if err != nil {
		return
	}
	now := time.Now()
	_ = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketSessions))
		if b == nil {
			return nil
		}
		for k, v := range rows {
			var s models.Session
			if err := json.Unmarshal(v, &s); err != nil {
				_ = b.Delete([]byte(k))
				continue
			}
			if now.After(s.Expires) {
				_ = b.Delete([]byte(k))
			}
		}
		return nil
	})
}
