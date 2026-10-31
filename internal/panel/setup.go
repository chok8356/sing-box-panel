package panel

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"sing-box-panel/internal/config"
)

// Setup initializes an empty panel without proxy inbounds or clients.
// Existing installations are left unchanged.
func Setup(database, address string, panelPort int) error {
	if err := validateAddress(address); err != nil {
		return err
	}
	if panelPort < 1 || panelPort > 65535 || panelPort == 80 {
		return errors.New("invalid panel port; port 80 is reserved for certificates")
	}
	db, err := openDB(database)
	if err != nil {
		return err
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM settings WHERE key='address' OR key='server_config'").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range map[string]string{"address": address, "panel_port": strconv.Itoa(panelPort)} {
		if err := setSetting(context.Background(), tx, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// readSite opens the database read-only, for installer commands that run
// next to the live panel.
func readSite(c config.Config) (site, error) {
	abs, err := filepath.Abs(c.DatabasePath)
	if err != nil {
		return site{}, err
	}
	query := url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)"}}
	db, err := sql.Open("sqlite", sqliteURI(abs, query))
	if err != nil {
		return site{}, err
	}
	defer db.Close()
	return loadSite(context.Background(), db)
}

// PanelURL describes how to open the admin panel, for the installer's summary.
func PanelURL(c config.Config) (string, error) {
	var err error
	c, err = readPreferences(c)
	if err != nil {
		return "", err
	}
	s, err := readSite(c)
	if err != nil {
		return "", err
	}
	text := s.panelURL(c) + "\nLogin: " + c.AdminUsername
	if c.AdminPasswordHash != "" {
		text += "\nPassword: managed in panel settings; recover with sudo sbp reset-password."
	}
	if c.TLSCertFile == "" && !isDomain(s.Address) {
		certs := newCertificates(c.CertDir, func() string { return s.Address })
		if _, err := certs.cachedIP(context.Background(), s.Address); err == nil {
			return text, nil
		}
		text += "\nSelf-signed certificate: the browser shows a warning. SHA-256:"
		if data, err := os.ReadFile(filepath.Join(c.CertDir, selfSignedFile)); err == nil {
			if cert, err := tls.X509KeyPair(data, data); err == nil {
				text += "\n" + Fingerprint(cert.Certificate[0])
			}
		}
	}
	return text, nil
}

func readPreferences(c config.Config) (config.Config, error) {
	abs, err := filepath.Abs(c.DatabasePath)
	if err != nil {
		return c, err
	}
	db, err := sql.Open("sqlite", sqliteURI(abs, url.Values{"mode": {"ro"}}))
	if err != nil {
		return c, err
	}
	defer db.Close()
	return loadPreferences(context.Background(), db, c)
}

// Health asks the running panel for /healthz over loopback.
func Health(c config.Config) error {
	response, err := loopbackRequest(c, "/healthz")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("panel is unhealthy: %s", response.Status)
	}
	return nil
}

func loopbackRequest(c config.Config, path string) (*http.Response, error) {
	s, err := readSite(c)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		// Loopback to our own process; the certificate may be self-signed.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	return client.Get(fmt.Sprintf("https://127.0.0.1:%d%s", s.PanelPort, path))
}

func (a *app) serveCertificateStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.certs.status())
}
