// Package config reads the startup settings from the environment.
// Address and ports live in the database and are edited in the panel.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"unicode"
)

// Config holds everything the panel reads from the environment at startup.
type Config struct {
	DatabasePath string
	RuntimeDir   string // applied sing-box config and temporary check files
	CertDir      string // Let's Encrypt and self-signed certificates
	TLSCertFile  string // optional existing PEM chain; renewed by its owner
	TLSKeyFile   string

	// Secret path prefixes; panel and subscriptions share one address.
	PanelPath        string
	SubscriptionPath string

	AdminUsername     string
	AdminPassword     string
	AdminPasswordHash string // database override; bootstrap password stays in the environment

	// Empty SingBoxBinary means "serve subscriptions only, do not run sing-box".
	SingBoxBinary string

	// DevAssets is a directory with templates/ and static/ that replaces the
	// embedded copies and is re-read on every request, for UI work. Empty in production.
	DevAssets string
}

// Load reads and validates the configuration from environment variables.
func Load() (Config, error) {
	c := Config{
		DatabasePath:     env("DATABASE_PATH", "./data/panel.db"),
		RuntimeDir:       env("RUNTIME_DIR", "./data/runtime"),
		CertDir:          env("CERT_DIR", "./data/certs"),
		TLSCertFile:      os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:       os.Getenv("TLS_KEY_FILE"),
		AdminUsername:    os.Getenv("ADMIN_USERNAME"),
		AdminPassword:    os.Getenv("ADMIN_PASSWORD"),
		PanelPath:        os.Getenv("PANEL_PATH"),
		SubscriptionPath: os.Getenv("SUBSCRIPTION_PATH"),
		SingBoxBinary:    os.Getenv("SING_BOX_BINARY"),
		DevAssets:        os.Getenv("PANEL_DEV_ASSETS"),
	}
	return Validate(c)
}

// Validate normalizes user-editable startup and panel settings alike.
func Validate(c Config) (Config, error) {
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return c, errors.New("set both TLS_CERT_FILE and TLS_KEY_FILE")
	}
	if c.AdminUsername == "" || len(c.AdminUsername) > 128 || c.AdminPassword == "" && c.AdminPasswordHash == "" || strings.Contains(c.AdminUsername, ":") || strings.ContainsFunc(c.AdminUsername, unicode.IsControl) {
		return c, errors.New("set ADMIN_USERNAME (without a colon) and ADMIN_PASSWORD")
	}
	var err error
	if c.PanelPath, err = normalizePath(c.PanelPath); err != nil {
		return c, fmt.Errorf("PANEL_PATH: %w", err)
	}
	if c.SubscriptionPath, err = normalizePath(c.SubscriptionPath); err != nil {
		return c, fmt.Errorf("SUBSCRIPTION_PATH: %w", err)
	}
	if c.SubscriptionPath == "" {
		return c, errors.New("SUBSCRIPTION_PATH must contain a secret prefix")
	}
	if c.PanelPath == c.SubscriptionPath {
		return c, errors.New("PANEL_PATH and SUBSCRIPTION_PATH must differ")
	}
	if suffix, ok := strings.CutPrefix(c.SubscriptionPath, c.PanelPath+"/"); ok {
		first, _, _ := strings.Cut(suffix, "/")
		if slices.Contains([]string{"login", "logout", "static", "settings", "config", "server", "logs", "subscriptions"}, first) {
			return c, errors.New("subscription path overlaps a panel route")
		}
	}
	return c, nil
}

func env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// normalizePath turns "SECRET", "/SECRET/" and "//SECRET//" into "/SECRET"; "/" becomes "".
func normalizePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.ContainsAny(raw, "?#%\\") || strings.ContainsFunc(raw, unicode.IsControl) {
		return "", errors.New("use a literal path without query, fragment, percent escapes, " +
			"backslashes or control characters")
	}
	clean := path.Clean("/" + strings.Trim(raw, "/"))
	if clean == "/" {
		return "", nil
	}
	return clean, nil
}

// EscapedPrefix percent-escapes each segment of a path prefix.
func EscapedPrefix(prefix string) string {
	parts := strings.Split(prefix, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
