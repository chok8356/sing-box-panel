package panel

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmptySetupPreservesExistingData(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "panel.db")
	if err := Setup(filename, "127.0.0.1", 8443); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM subscriptions").Scan(&count); err != nil || count != 0 {
		t.Fatal("setup created clients", err)
	}
	body, err := effectiveServer(t.Context(), db)
	if err != nil || len(body) != 0 {
		t.Fatal("setup configured a VPN", err)
	}
	if err := Setup(filename, "other.example", 9443); err != nil {
		t.Fatal(err)
	}
	site, err := loadSite(t.Context(), db)
	if err != nil || site.Address != "127.0.0.1" || site.PanelPort != 8443 {
		t.Fatal("setup overwrote existing settings", err)
	}
}

func TestExplicitVPNAndPresetSetup(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	base := testOrigin + c.PanelPath
	w := request(t, h, "GET", base+"/server", nil, true)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "Create VLESS + Reality") {
		t.Fatal("missing setup action")
	}
	wantStatus(t, request(t, h, "POST", base+"/server/create-reality", form("vpn_port", "8443", "handshake", "example.com"), true), 422)
	wantStatus(t, request(t, h, "POST", base+"/server/create-reality", form("vpn_port", "443", "handshake", "example.com"), true), 303)
	before, err := getSetting(context.Background(), a.db, "server_config")
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, request(t, h, "POST", base+"/server/create-reality", form("vpn_port", "9443", "handshake", "other.example"), true), 422)
	after, _ := getSetting(context.Background(), a.db, "server_config")
	if before != after {
		t.Fatal("quick setup overwrote existing server")
	}
	var count int
	a.db.QueryRow("SELECT COUNT(*) FROM subscriptions").Scan(&count)
	if count != 0 {
		t.Fatal("quick setup created a client")
	}
	stored, _ := a.baseConfig(t.Context())
	w = request(t, h, "POST", base+"/config", form("action", "preset", "preset", "russia", "block_ads", "1"), true)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "geosite-category-ru") {
		t.Fatal("preset not loaded")
	}
	unchanged, _ := a.baseConfig(t.Context())
	if stored != unchanged {
		t.Fatal("loading a preset changed subscriptions before Save")
	}
	wantStatus(t, request(t, h, "POST", base+"/config", form("action", "preset", "preset", "unknown"), true), 400)
}
