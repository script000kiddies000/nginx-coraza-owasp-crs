package store

import (
	"encoding/json"

	"flux-waf/internal/models"

	bolt "go.etcd.io/bbolt"
)

func SaveTLSCertificate(db *bolt.DB, c models.TLSCertificate) error {
	return put(db, BucketTLSCerts, c.ID, c)
}

func GetTLSCertificate(db *bolt.DB, id string) (models.TLSCertificate, error) {
	var c models.TLSCertificate
	err := get(db, BucketTLSCerts, id, &c)
	return c, err
}

func DeleteTLSCertificate(db *bolt.DB, id string) error {
	return del(db, BucketTLSCerts, id)
}

func ListTLSCertificates(db *bolt.DB) ([]models.TLSCertificate, error) {
	rows, err := listAll(db, BucketTLSCerts)
	if err != nil {
		return nil, err
	}
	out := make([]models.TLSCertificate, 0, len(rows))
	for _, v := range rows {
		var c models.TLSCertificate
		if err := json.Unmarshal(v, &c); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}
