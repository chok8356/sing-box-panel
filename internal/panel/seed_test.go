package panel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"sing-box-panel/internal/singbox"
	"strconv"
	"time"
)

// seedVPN creates an explicit VPN fixture for runtime tests.
func seedVPN(db *sql.DB, address, handshake string, vpnPort, panelPort int) error {
	serverJSON, clientJSON, err := singbox.InitialConfigs(handshake, vpnPort)
	if err != nil {
		return err
	}
	uuid, err := newUUID()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	ctx := context.Background()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	settings := map[string]string{
		"server_config": serverJSON,
		"base_config":   clientJSON,
		"address":       address,
		"panel_port":    strconv.Itoa(panelPort),
	}
	for key, value := range settings {
		if err := setSetting(ctx, tx, key, value); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO subscriptions(name, override_json, uuid, token, enabled, created_at, updated_at)
		VALUES('First client', '{}', ?, ?, 1, ?, ?)`, uuid, rand.Text(), now, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}
