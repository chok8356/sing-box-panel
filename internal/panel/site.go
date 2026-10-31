package panel

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"sing-box-panel/internal/config"
)

// site is where the panel and subscriptions are reachable. It is stored in
// the settings table and edited on the Settings page.
type site struct {
	Address   string // public domain or IP
	PanelPort int    // HTTPS port of the panel and subscriptions
}

// isDomain reports whether address is a hostname rather than an IP.
func isDomain(address string) bool {
	return address != "" && net.ParseIP(address) == nil
}

// origin is https://address[:port], omitting the default port.
func (s site) origin() string {
	host := s.Address
	if s.PanelPort != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(s.PanelPort))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host
}

func (s site) panelURL(c config.Config) string {
	return s.origin() + config.EscapedPrefix(c.PanelPath) + "/"
}

func (s site) subscriptionURL(c config.Config, token string) string {
	return s.origin() + config.EscapedPrefix(c.SubscriptionPath) + "/" + url.PathEscape(token) + "?format=json"
}

func validateAddress(address string) error {
	if address == "" || len(address) > 253 || strings.ContainsAny(address, "/?#@[] \t\r\n") {
		return errors.New("address must be a domain name or an IP address")
	}
	return nil
}

// validatePorts checks the panel and proxy ports. Port 80 is reserved for
// Let's Encrypt validation and the HTTP to HTTPS redirect.
func validatePorts(panelPort, vpnPort int) error {
	for _, port := range []int{panelPort, vpnPort} {
		if port < 1 || port > 65535 || port == 80 {
			return errors.New("ports must be 1–65535 and not 80 (used for Let's Encrypt)")
		}
	}
	if panelPort == vpnPort {
		return errors.New("panel and proxy need different ports")
	}
	return nil
}

func getSetting(ctx context.Context, q queryer, key string) (string, error) {
	var value string
	err := q.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	return value, err
}

func setSetting(ctx context.Context, tx *sql.Tx, key, value string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func loadSite(ctx context.Context, q queryer) (site, error) {
	address, err := getSetting(ctx, q, "address")
	if err != nil {
		return site{}, errors.New("address is not configured; run setup first")
	}
	port, err := getSetting(ctx, q, "panel_port")
	if err != nil {
		return site{}, errors.New("panel port is not configured; run setup first")
	}
	panelPort, err := strconv.Atoi(port)
	if err != nil {
		return site{}, errors.New("invalid panel port in database")
	}
	return site{Address: address, PanelPort: panelPort}, nil
}

func (a *app) site() site { return *a.siteValue.Load() }

func (a *app) subscriptionURL(token string) string {
	return a.site().subscriptionURL(a.config(), token)
}

// ValidateSite checks installer answers before anything is written.
func ValidateSite(address string, panelPort, vpnPort int) error {
	if err := validateAddress(address); err != nil {
		return err
	}
	return validatePorts(panelPort, vpnPort)
}
