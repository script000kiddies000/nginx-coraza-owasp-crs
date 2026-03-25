package store

import (
	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
)

const (
	keyVirtualPatch = "virtual_patch"
	keyWPSecurity   = "wp_security"
)

func GetVirtualPatchConfig(db *bolt.DB) models.VirtualPatchConfig {
	var c models.VirtualPatchConfig
	_ = get(db, BucketSettings, keyVirtualPatch, &c)
	return c
}

func SaveVirtualPatchConfig(db *bolt.DB, c models.VirtualPatchConfig) error {
	return put(db, BucketSettings, keyVirtualPatch, c)
}

func GetWPSecurityConfig(db *bolt.DB) models.WPSecurityConfig {
	var c models.WPSecurityConfig
	err := get(db, BucketSettings, keyWPSecurity, &c)
	if err == ErrNotFound {
		return models.WPSecurityConfig{
			BlockXMLRPC:         true,
			BlockSensitiveFiles: true,
			BlockUploadsPHP:     true,
			BlockAuthorEnum:     true,
			BlockScannerUA:      true,
			StripAssetVersion:   true,
			HidePoweredBy:       true,
			RateLimitLogin:      true,
			RemindFileEdit:      true,
		}
	}
	return c
}

func SaveWPSecurityConfig(db *bolt.DB, c models.WPSecurityConfig) error {
	return put(db, BucketSettings, keyWPSecurity, c)
}
