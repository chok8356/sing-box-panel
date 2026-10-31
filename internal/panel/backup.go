package panel

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"sing-box-panel/internal/config"
	"sing-box-panel/internal/singbox"
)

const maxBackupBytes = 64 << 20

// Store bootstrap credentials in the copy too, so recovery does not depend on panel.env.
func snapshotDatabase(ctx context.Context, c config.Config, output string) error {
	if err := BackupDatabase(c.DatabasePath, output); err != nil {
		return err
	}
	db, err := openDB(output)
	if err != nil {
		return err
	}
	defer db.Close()
	if c.AdminPasswordHash == "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(c.AdminPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		c.AdminPasswordHash = string(hash)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := writePreferences(ctx, tx, c); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions"); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *app) downloadBackup(w http.ResponseWriter, r *http.Request) {
	dir, err := os.MkdirTemp("", "sbp-backup-")
	if err != nil {
		serverError(w)
		return
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "panel.db")
	a.settingsMu.Lock()
	if !a.authenticated(r) {
		a.settingsMu.Unlock()
		a.redirect(w, r, "/login")
		return
	}
	a.mu.RLock()
	err = snapshotDatabase(r.Context(), a.config(), file)
	a.mu.RUnlock()
	a.settingsMu.Unlock()
	if err != nil {
		serverError(w)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="sbp-`+time.Now().UTC().Format("20060102T150405Z")+`.db"`)
	http.ServeFile(w, r, file)
}

func (a *app) restoreBackup(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		http.Error(w, "Invalid backup upload (maximum 64 MiB)", http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll()
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	fail := func(status int, err error) {
		a.render(w, status, "settings", page{Title: "Settings", Active: "settings", Settings: a.currentSettings(r), Error: err.Error()})
	}
	if !a.allowPasswordAttempt(r) {
		w.Header().Set("Retry-After", "900")
		fail(http.StatusTooManyRequests, errors.New("Too many password attempts. Try again in 15 minutes."))
		return
	}
	if !validPassword(a.config(), r.FormValue("current_password")) {
		fail(http.StatusUnauthorized, errors.New("Incorrect current password."))
		return
	}
	a.clearPasswordAttempts(r)
	if r.FormValue("confirm_restore") != "1" {
		fail(http.StatusUnprocessableEntity, errors.New("Confirm replacement of all settings and clients."))
		return
	}
	source, _, err := r.FormFile("backup")
	if err != nil {
		fail(http.StatusBadRequest, errors.New("Choose a .db backup downloaded from Settings."))
		return
	}
	defer source.Close()
	dir, err := os.MkdirTemp("", "sbp-restore-")
	if err != nil {
		serverError(w)
		return
	}
	defer os.RemoveAll(dir)
	filename := filepath.Join(dir, "panel.db")
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		serverError(w)
		return
	}
	n, copyErr := io.Copy(file, io.LimitReader(source, maxBackupBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || n > maxBackupBytes {
		fail(http.StatusBadRequest, errors.New("Cannot read backup (maximum 64 MiB)."))
		return
	}
	nextConfig, nextSite, err := a.restoreDatabase(r.Context(), filename)
	if err != nil {
		fail(http.StatusUnprocessableEntity, fmt.Errorf("Restore failed; current settings were kept: %w", err))
		return
	}
	a.applyConfig(nextConfig)
	a.siteValue.Store(&nextSite)
	a.updateHTTP()
	a.requestCertRefresh()
	// A link also works when CSP blocks a form redirect to a different saved port.
	a.render(w, http.StatusOK, "restored", page{Title: "Backup restored", Active: "login", RestoredURL: nextSite.panelURL(nextConfig) + "login", RestoredUsername: nextConfig.AdminUsername})
}

// Read values, never execute the uploaded database's schema against the live database.
func readBackup(ctx context.Context, filename string, c config.Config) (map[string]string, []Subscription, config.Config, site, error) {
	bad := func(err error) (map[string]string, []Subscription, config.Config, site, error) {
		return nil, nil, c, site{}, err
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return bad(err)
	}
	db, err := sql.Open("sqlite", sqliteURI(abs, url.Values{"mode": {"ro"}, "_pragma": {"trusted_schema(OFF)"}}))
	if err != nil {
		return bad(err)
	}
	defer db.Close()
	var invalid int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type NOT IN ('table','index') OR (type='table' AND (name NOT IN ('settings','subscriptions','admin_sessions','sqlite_sequence') OR upper(sql) LIKE '%VIRTUAL%'))`).Scan(&invalid); err != nil || invalid != 0 {
		return bad(errors.New("unsupported backup database schema"))
	}
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return bad(errors.New("backup database is damaged"))
	}
	if _, err := getSetting(ctx, db, preferencesKey); err != nil {
		return bad(errors.New("backup must include saved admin access settings"))
	}
	next, err := loadPreferences(ctx, db, c)
	if err != nil || next.AdminPasswordHash == "" {
		return bad(errors.New("backup must include saved admin access settings"))
	}
	s, err := loadSite(ctx, db)
	if err != nil {
		return bad(err)
	}
	if err := validateAddress(s.Address); err != nil {
		return bad(err)
	}
	if s.PanelPort < 1 || s.PanelPort > 65535 || s.PanelPort == 80 {
		return bad(errors.New("invalid backup panel port"))
	}
	if next.TLSCertFile != "" {
		if !filepath.IsAbs(next.TLSCertFile) || !filepath.IsAbs(next.TLSKeyFile) {
			return bad(errors.New("backup certificate paths must be absolute"))
		}
		cert, err := tls.LoadX509KeyPair(next.TLSCertFile, next.TLSKeyFile)
		if err != nil || !covers(cert.Leaf, s.Address) {
			return bad(errors.New("backup certificate files must exist and cover its address"))
		}
	}
	settings := make(map[string]string)
	rows, err := db.QueryContext(ctx, "SELECT key,value FROM settings")
	if err != nil {
		return bad(err)
	}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			rows.Close()
			return bad(err)
		}
		settings[key] = value
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return bad(err)
	}
	for _, key := range []string{"base_config", "server_config"} {
		if raw := settings[key]; raw != "" {
			if err := singbox.ValidateJSON(raw); err != nil {
				return bad(err)
			}
		}
	}
	if settings["base_config"] == "" {
		return bad(errors.New("missing base client configuration"))
	}
	for _, listener := range singbox.Listeners(settings["server_config"]) {
		if listener.Network != "udp" && (listener.Port == s.PanelPort || listener.Port == 80 && next.TLSCertFile == "") {
			return bad(errors.New("backup has conflicting panel and inbound ports"))
		}
	}
	rows, err = db.QueryContext(ctx, "SELECT "+subscriptionColumns+" FROM subscriptions ORDER BY id")
	if err != nil {
		return bad(err)
	}
	defer rows.Close()
	var clients []Subscription
	for rows.Next() {
		client, err := scanSubscription(rows)
		if err != nil {
			return bad(err)
		}
		if err := validateName(client.Name); err != nil {
			return bad(err)
		}
		if client.ID < 1 || client.UUID == "" || client.Token == "" || strings.ContainsAny(client.Token, "/?#\\") {
			return bad(errors.New("invalid client credentials in backup"))
		}
		if err := singbox.ValidateJSON(client.OverrideJSON); err != nil {
			return bad(err)
		}
		clients = append(clients, client)
	}
	return settings, clients, next, s, rows.Err()
}

func (a *app) restoreDatabase(ctx context.Context, filename string) (config.Config, site, error) {
	settings, clients, next, s, err := readBackup(ctx, filename, a.config())
	if err != nil {
		return next, s, err
	}
	err = a.listeners.restorePort(s.PanelPort, func() error {
		return a.mutate(ctx, func(tx *sql.Tx) error {
			// Keep a recovery copy even after a successful but unwanted restore.
			dir := filepath.Join(filepath.Dir(a.config().DatabasePath), "backups")
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
			file := filepath.Join(dir, "before-restore-"+time.Now().UTC().Format("20060102T150405.000000000Z")+".db")
			if err := snapshotDatabase(ctx, a.config(), file); err != nil {
				return fmt.Errorf("cannot save recovery backup: %w", err)
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM settings; DELETE FROM subscriptions; DELETE FROM admin_sessions"); err != nil {
				return err
			}
			for key, value := range settings {
				if err := setSetting(ctx, tx, key, value); err != nil {
					return err
				}
			}
			for _, client := range clients {
				if _, err := tx.ExecContext(ctx, "INSERT INTO subscriptions("+subscriptionColumns+") VALUES(?,?,?,?,?,?,?,?)", client.ID, client.Name, client.OverrideJSON, client.Enabled, client.CreatedAt, client.UpdatedAt, client.UUID, client.Token); err != nil {
					return err
				}
			}
			return a.checkBaseForClients(ctx, tx, settings["base_config"])
		})
	})
	return next, s, err
}
