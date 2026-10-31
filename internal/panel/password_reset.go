package panel

import (
	"context"
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
	"sing-box-panel/internal/config"
)

// ResetAdminPassword is invoked by the root-only server command as the service user.
// It requires the same database file access as editing the credentials on disk.
func ResetAdminPassword(c config.Config) (string, error) {
	db, err := openDB(c.DatabasePath)
	if err != nil {
		return "", err
	}
	defer db.Close()
	c, err = loadPreferences(context.Background(), db, c)
	if err != nil {
		return "", err
	}
	password := rand.Text()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	c.AdminPasswordHash = string(hash)
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err := writePreferences(context.Background(), tx, c); err != nil {
		return "", err
	}
	if _, err := tx.Exec("DELETE FROM admin_sessions"); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return password, nil
}
