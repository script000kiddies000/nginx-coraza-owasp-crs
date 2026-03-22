package store

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
)

func GetHost(db *bolt.DB, domain string) (models.HostConfig, error) {
	var h models.HostConfig
	err := get(db, BucketHosts, domain, &h)
	return h, err
}

func SaveHost(db *bolt.DB, h models.HostConfig) error {
	return put(db, BucketHosts, h.Domain, h)
}

func DeleteHost(db *bolt.DB, domain string) error {
	return del(db, BucketHosts, domain)
}

func ListHosts(db *bolt.DB) ([]models.HostConfig, error) {
	rows, err := listAll(db, BucketHosts)
	if err != nil {
		return nil, err
	}
	hosts := make([]models.HostConfig, 0, len(rows))
	for _, v := range rows {
		var h models.HostConfig
		if err := json.Unmarshal(v, &h); err != nil {
			continue
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}
