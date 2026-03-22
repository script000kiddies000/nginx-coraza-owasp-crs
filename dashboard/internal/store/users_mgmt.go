package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"

	"flux-waf/internal/models"
)

var ErrUserExists = errors.New("username already exists")
var ErrLastAdmin = errors.New("cannot remove the last admin user")

// ListUsers returns all accounts without password hashes.
func ListUsers(db *bolt.DB) ([]models.UserAccount, error) {
	rows, err := listAll(db, BucketUsers)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for k := range rows {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]models.UserAccount, 0, len(names))
	for _, name := range names {
		var u models.UserAccount
		if err := json.Unmarshal(rows[name], &u); err != nil {
			continue
		}
		u.PasswordHash = ""
		out = append(out, u)
	}
	return out, nil
}

// CreateUserAccount inserts a new user with bcrypt password.
func CreateUserAccount(db *bolt.DB, username, password, role string) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return fmt.Errorf("username and password required")
	}
	if role == "" {
		role = "operator"
	}
	if _, err := GetUser(db, username); err == nil {
		return ErrUserExists
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return SaveUser(db, models.UserAccount{
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
	})
}

// DeleteUser removes a user. Prevents deleting the last admin.
func DeleteUser(db *bolt.DB, username string) error {
	u, err := GetUser(db, username)
	if err != nil {
		return err
	}
	if u.Role == "admin" {
		n, err := countRole(db, "admin")
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastAdmin
		}
	}
	return del(db, BucketUsers, username)
}

func countRole(db *bolt.DB, role string) (int, error) {
	list, err := ListUsers(db)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range list {
		if u.Role == role {
			n++
		}
	}
	return n, nil
}

// SetUserPassword updates password for an existing user.
func SetUserPassword(db *bolt.DB, username, newPassword string) error {
	if newPassword == "" {
		return fmt.Errorf("password required")
	}
	u, err := GetUser(db, username)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	return SaveUser(db, u)
}
