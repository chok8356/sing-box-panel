package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"sing-box-panel/internal/config"

	"golang.org/x/crypto/bcrypt"
)

const preferencesKey = "panel_preferences"

// Only user-editable values are stored; paths to databases and binaries stay in the environment.
type preferences struct {
	PanelPath        string
	SubscriptionPath string
	AdminUsername    string
	PasswordHash     string
	TLSCertFile      string
	TLSKeyFile       string
}

type runtimeSettings struct {
	config config.Config
	routes http.Handler
}

// config returns an immutable snapshot; requests can overlap a settings change.
func (a *app) config() config.Config { return a.configValue.Load().config }

func loadPreferences(ctx context.Context, q queryer, c config.Config) (config.Config, error) {
	raw, err := getSetting(ctx, q, preferencesKey)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	var p preferences
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return c, errors.New("invalid stored panel settings")
	}
	c.PanelPath, c.SubscriptionPath = p.PanelPath, p.SubscriptionPath
	c.AdminUsername, c.AdminPasswordHash = p.AdminUsername, p.PasswordHash
	c.TLSCertFile, c.TLSKeyFile = p.TLSCertFile, p.TLSKeyFile
	if p.PasswordHash != "" {
		if _, err := bcrypt.Cost([]byte(p.PasswordHash)); err != nil {
			return c, errors.New("invalid stored admin password hash")
		}
	}
	return config.Validate(c)
}

func (a *app) applyConfig(c config.Config) {
	a.configValue.Store(&runtimeSettings{config: c, routes: a.routes(c)})
}

// savePreferences commits before publishing a new routing/configuration snapshot.
// The caller holds settingsMu so concurrent forms cannot overwrite each other.
func (a *app) saveAccessPreferences(ctx context.Context, c config.Config) error {
	tx, err := a.db.BeginTx(ctx, nil)
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
	if err := tx.Commit(); err != nil {
		return err
	}
	a.applyConfig(c)
	return nil
}

func writePreferences(ctx context.Context, tx *sql.Tx, c config.Config) error {
	p := preferences{c.PanelPath, c.SubscriptionPath, c.AdminUsername, c.AdminPasswordHash, c.TLSCertFile, c.TLSKeyFile}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return setSetting(ctx, tx, preferencesKey, string(data))
}
