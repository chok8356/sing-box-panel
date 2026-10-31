package panel

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"sing-box-panel/internal/config"
	"sing-box-panel/internal/singbox"
)

type settingsView struct {
	Address     string
	PanelPort   int
	Automatic   bool // Let's Encrypt for domains and public IPs
	PendingPort int  // new panel port awaiting confirmation
	OnPending   bool // this page was opened through the pending port

	CertPath, KeyPath                          string             // published for TLS inbounds
	Ports                                      []singbox.Listener // what the firewall must allow
	Certificate                                certificateStatus
	TLSMode, TLSCertFile, TLSKeyFile           string
	AdminUsername, PanelPath, SubscriptionPath string
}

func (a *app) currentSettings(r *http.Request) settingsView {
	s := a.site()
	v := settingsView{
		Address:          s.Address,
		PanelPort:        s.PanelPort,
		Automatic:        a.config().TLSCertFile == "" && automaticCertificate(s.Address),
		CertPath:         a.certs.certPath(),
		KeyPath:          a.certs.keyPath(),
		Certificate:      a.certs.status(),
		TLSMode:          "auto",
		TLSCertFile:      a.config().TLSCertFile,
		TLSKeyFile:       a.config().TLSKeyFile,
		AdminUsername:    a.config().AdminUsername,
		PanelPath:        a.config().PanelPath,
		SubscriptionPath: a.config().SubscriptionPath,
	}
	if v.TLSCertFile != "" {
		v.TLSMode = "existing"
	}
	v.PendingPort, v.OnPending = a.listeners.pendingFor(r)
	v.Ports = []singbox.Listener{{Tag: "panel", Type: "https", Port: s.PanelPort, Network: "tcp"}}
	if v.Automatic {
		v.Ports = append(v.Ports, singbox.Listener{Tag: "Let's Encrypt", Type: "http", Port: 80, Network: "tcp"})
	}
	if server, err := getSetting(r.Context(), a.db, "server_config"); err == nil {
		v.Ports = append(v.Ports, singbox.Listeners(server)...)
	}
	return v
}

func (a *app) settingsPage(w http.ResponseWriter, r *http.Request) {
	data := page{Title: "Settings", Active: "settings", Settings: a.currentSettings(r)}
	if r.URL.Query().Get("saved") == "1" {
		data.Notice = "Settings saved."
	}
	if r.URL.Query().Get("certificate") == "1" {
		data.Notice = "Certificate check requested. Refresh this page to see the result."
	}
	a.render(w, http.StatusOK, "settings", data)
}

// checkPanelPort refuses port 80 (Let's Encrypt) and ports of sing-box inbounds.
func (a *app) checkPanelPort(r *http.Request, port int) error {
	if port < 1 || port > 65535 || port == 80 {
		return errors.New("panel port must be 1–65535 and not 80 (used for Let's Encrypt)")
	}
	server, _ := getSetting(r.Context(), a.db, "server_config")
	for _, listener := range singbox.Listeners(server) {
		if listener.Port == port && listener.Network != "udp" {
			return errors.New("port " + strconv.Itoa(port) + " is used by inbound " + listener.Tag)
		}
	}
	return nil
}

// saveSettings stores the address (clients connect to it; the certificate
// follows it) and opens a new panel port for confirmation.
func (a *app) saveSettings(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	current := a.currentSettings(r)
	nextConfig := a.config()
	form := current
	form.Address = strings.TrimSpace(r.PostForm.Get("address"))
	form.PanelPort, _ = strconv.Atoi(r.PostForm.Get("panel_port"))
	if r.PostForm.Has("tls_mode") {
		form.TLSMode = r.PostForm.Get("tls_mode")
		form.TLSCertFile = strings.TrimSpace(r.PostForm.Get("tls_cert_file"))
		form.TLSKeyFile = strings.TrimSpace(r.PostForm.Get("tls_key_file"))
	}
	renderError := func(message string) {
		a.render(w, http.StatusUnprocessableEntity, "settings",
			page{Title: "Settings", Active: "settings", Settings: form, Error: message})
	}
	if err := validateAddress(form.Address); err != nil {
		renderError(err.Error())
		return
	}
	if form.PanelPort != current.PanelPort {
		if err := a.checkPanelPort(r, form.PanelPort); err != nil {
			renderError(err.Error())
			return
		}
	}
	var candidate *tls.Certificate
	switch form.TLSMode {
	case "auto":
		nextConfig.TLSCertFile, nextConfig.TLSKeyFile = "", ""
	case "existing":
		if !filepath.IsAbs(form.TLSCertFile) || !filepath.IsAbs(form.TLSKeyFile) {
			renderError("Certificate and key paths must be absolute.")
			return
		}
		cert, err := tls.LoadX509KeyPair(form.TLSCertFile, form.TLSKeyFile)
		if err != nil {
			renderError("Cannot read certificate and key: " + err.Error())
			return
		}
		if !covers(cert.Leaf, form.Address) {
			renderError("The certificate is expired, not yet valid, or does not cover this address.")
			return
		}
		candidate = &cert
		nextConfig.TLSCertFile, nextConfig.TLSKeyFile = form.TLSCertFile, form.TLSKeyFile
	default:
		renderError("Choose Automatic or Existing certificate.")
		return
	}
	tlsChanged := nextConfig.TLSCertFile != a.config().TLSCertFile || nextConfig.TLSKeyFile != a.config().TLSKeyFile
	if tlsChanged && form.TLSMode == "auto" {
		if cert, err := a.certs.cached(r.Context()); err == nil && covers(cert.Leaf, form.Address) {
			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				renderError("Could not preserve the previous certificate.")
				return
			}
			data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
			for _, der := range cert.Certificate {
				data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
			}
			if err := a.certs.acme.Cache.Put(r.Context(), "previous", data); err != nil {
				renderError("Could not preserve the previous certificate: " + err.Error())
				return
			}
		}
	}

	if form.Address != current.Address || tlsChanged {
		err := a.mutate(r.Context(), func(tx *sql.Tx) error {
			if tlsChanged {
				if err := writePreferences(r.Context(), tx, nextConfig); err != nil {
					return err
				}
			}
			return setSetting(r.Context(), tx, "address", form.Address)
		})
		if err != nil {
			renderError("Could not save the address: " + err.Error())
			return
		}
		s := a.site()
		s.Address = form.Address
		a.siteValue.Store(&s)
		if candidate != nil {
			a.certs.mu.Lock()
			a.certs.manualCert = candidate
			a.certs.mu.Unlock()
		}
		if tlsChanged {
			a.applyConfig(nextConfig)
			a.updateHTTP()
		}
		a.requestCertRefresh()
	}

	if form.PanelPort != current.PanelPort {
		if err := a.listeners.propose(form.PanelPort); err != nil {
			renderError("Cannot open port " + strconv.Itoa(form.PanelPort) + ": " + err.Error())
			return
		}
		// Continue on the new port: the confirmation must come through it.
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		next := site{Address: strings.Trim(host, "[]"), PanelPort: form.PanelPort}
		http.Redirect(w, r, next.origin()+config.EscapedPrefix(a.config().PanelPath)+"/settings", http.StatusSeeOther)
		return
	}
	a.redirect(w, r, "/settings?saved=1")
}

// confirmPort keeps the new panel port. It only succeeds through that port,
// which proves the port is reachable from the admin's browser.
func (a *app) confirmPort(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	port, err := a.listeners.confirm(r)
	if err != nil {
		a.render(w, http.StatusConflict, "settings",
			page{Title: "Settings", Active: "settings", Settings: a.currentSettings(r), Error: err.Error()})
		return
	}
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO settings(key, value) VALUES('panel_port', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, strconv.Itoa(port))
	if err != nil {
		// The port works now but the panel returns to the old one after a restart.
		serverError(w)
		return
	}
	s := a.site()
	s.PanelPort = port
	a.siteValue.Store(&s)
	a.redirect(w, r, "/settings?saved=1")
}
