package panel

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"sing-box-panel/internal/singbox"
)

func postWithCookie(t *testing.T, h http.Handler, target string, values url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", target, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAccessSettingsPersistenceAndRevocation(t *testing.T) {
	c := testConfig()
	a, filename := testApp(t, c)
	h := a.handler()
	addClient(t, a.db, "Existing", "TOKEN")
	cookie := loginCookie(t, h, testOrigin+c.PanelPath+"/settings")
	values := form("admin_username", "operator", "current_password", "wrong", "new_password", "a-new-secret-password", "confirm_password", "a-new-secret-password", "panel_path", "/new-panel", "subscription_path", "/new-sub", "confirm_subscription_path", "1")
	endpoint := testOrigin + c.PanelPath + "/settings/access"
	wantStatus(t, postWithCookie(t, h, endpoint, values, cookie), 422)
	if a.config().AdminUsername != "admin" {
		t.Fatal("failed confirmation changed access")
	}
	values.Set("current_password", "test-secret")
	values.Del("confirm_subscription_path")
	wantStatus(t, postWithCookie(t, h, endpoint, values, cookie), 422)
	values.Set("confirm_subscription_path", "1")
	w := postWithCookie(t, h, endpoint, values, cookie)
	wantStatus(t, w, 303)
	if w.Header().Get("Location") != "/new-panel/login?updated=1" {
		t.Fatal("wrong sign-in redirect")
	}
	if a.config().AdminPasswordHash == "" || !validPassword(a.config(), "a-new-secret-password") || validPassword(a.config(), "test-secret") {
		t.Fatal("password was not replaced")
	}
	stored, err := getSetting(t.Context(), a.db, preferencesKey)
	if err != nil || strings.Contains(stored, "a-new-secret-password") || strings.Contains(stored, "test-secret") {
		t.Fatal("plaintext password persisted", err)
	}
	wantStatus(t, request(t, h, "GET", testOrigin+c.PanelPath+"/settings", nil, false), 404)
	wantStatus(t, request(t, h, "GET", testOrigin+c.SubscriptionPath+"/TOKEN", nil, false), 404)
	wantStatus(t, request(t, h, "GET", testOrigin+"/new-sub/TOKEN", nil, false), 200)
	r := httptest.NewRequest("GET", testOrigin+"/new-panel/settings", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	wantStatus(t, w, 303)
	wantStatus(t, request(t, h, "POST", testOrigin+"/new-panel/login", form("username", "operator", "password", "a-new-secret-password"), false), 303)
	restarted, err := newApp(c, a.db)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.config().PanelPath != "/new-panel" || restarted.config().SubscriptionPath != "/new-sub" {
		t.Fatal("paths not restored")
	}
	wantStatus(t, request(t, restarted.handler(), "POST", testOrigin+"/new-panel/login", form("username", "operator", "password", "a-new-secret-password"), false), 303)
	c.DatabasePath = filename
	info, err := PanelURL(c)
	if err != nil || !strings.Contains(info, "/new-panel/") || !strings.Contains(info, "Login: operator") || !strings.Contains(info, "reset-password") {
		t.Fatal("CLI shows stale access settings", err)
	}
	password, err := ResetAdminPassword(c)
	if err != nil {
		t.Fatal(err)
	}
	afterReset, err := newApp(c, a.db)
	if err != nil {
		t.Fatal(err)
	}
	if !validPassword(afterReset.config(), password) || validPassword(afterReset.config(), "a-new-secret-password") {
		t.Fatal("SSH recovery failed")
	}
	if tokenOf(t, a.db, "Existing") != "TOKEN" {
		t.Fatal("access update rotated VPN credentials")
	}
}

// The sign-in and URL forms each post only their own fields.
func TestAccessFormsKeepOmittedFields(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	values := form("panel_path", "/urls", "subscription_path", c.SubscriptionPath, "current_password", "test-secret")
	wantStatus(t, request(t, h, "POST", testOrigin+c.PanelPath+"/settings/access", values, true), 303)
	if a.config().AdminUsername != "admin" || a.config().PanelPath != "/urls" || !validPassword(a.config(), "test-secret") {
		t.Fatal("URL form changed sign-in")
	}
	values = form("admin_username", "operator", "current_password", "test-secret", "new_password", "", "confirm_password", "")
	wantStatus(t, request(t, h, "POST", testOrigin+"/urls/settings/access", values, true), 303)
	if a.config().AdminUsername != "operator" || a.config().PanelPath != "/urls" || a.config().SubscriptionPath != c.SubscriptionPath {
		t.Fatal("sign-in form changed paths")
	}
}

func TestCertificateSettingsSwitchAndValidation(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	source := newCertificates(t.TempDir(), func() string { return "new.example" })
	cert, err := source.createSelfSigned("new.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.publish(cert); err != nil {
		t.Fatal(err)
	}
	values := form("address", "new.example", "panel_port", "8443", "tls_mode", "existing", "tls_cert_file", source.certPath(), "tls_key_file", source.keyPath())
	endpoint := testOrigin + c.PanelPath + "/settings"
	// Address and matching files change together, without an impossible intermediate configuration.
	wantStatus(t, request(t, h, "POST", endpoint, values, true), 303)
	if a.site().Address != "new.example" || a.certs.status().Mode != "External" {
		t.Fatal("external mode not applied")
	}
	loaded, err := a.certs.cached(t.Context())
	if err != nil || !covers(loaded.Leaf, "new.example") {
		t.Fatal("new certificate not served", err)
	}
	values.Set("address", "wrong.example")
	wantStatus(t, request(t, h, "POST", endpoint, values, true), 422)
	if a.site().Address != "new.example" {
		t.Fatal("invalid certificate changed address")
	}
	values.Set("address", "new.example")
	values.Set("tls_key_file", source.keyPath()+".missing")
	wantStatus(t, request(t, h, "POST", endpoint, values, true), 422)
	if a.config().TLSKeyFile != source.keyPath() {
		t.Fatal("unreadable key replaced working certificate")
	}
	restarted, err := newApp(c, a.db)
	if err != nil || restarted.config().TLSCertFile != source.certPath() {
		t.Fatal("certificate source not restored", err)
	}
	beforeKey, _ := os.ReadFile(source.keyPath())
	values.Set("tls_mode", "auto")
	wantStatus(t, request(t, h, "POST", endpoint, values, true), 303)
	if a.config().TLSCertFile != "" {
		t.Fatal("automatic mode not applied")
	}
	loaded, err = a.certs.cached(t.Context())
	if err != nil || !covers(loaded.Leaf, "new.example") {
		t.Fatal("previous valid certificate was lost on switch", err)
	}
	afterKey, _ := os.ReadFile(source.keyPath())
	if string(beforeKey) != string(afterKey) {
		t.Fatal("external private key modified")
	}
}

func TestSettingsDoNotRestartVPNAndConcurrentReaders(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	a.core = &singbox.Process{Binary: "must-not-be-executed", Dir: t.TempDir()}
	values := form("admin_username", "admin", "current_password", "test-secret", "panel_path", c.PanelPath, "subscription_path", c.SubscriptionPath)
	cookie := loginCookie(t, h, testOrigin+c.PanelPath+"/settings")
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for range 50 {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", testOrigin+c.PanelPath+"/login", nil))
		}
	}()
	wantStatus(t, postWithCookie(t, h, testOrigin+c.PanelPath+"/settings/access", values, cookie), 303)
	readers.Wait()
}

func TestAccessFormRejectsWeakPasswordsAndPathCollisions(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	endpoint := testOrigin + c.PanelPath + "/settings/access"
	for _, tc := range []struct{ password, confirm, path string }{
		{"short", "short", c.SubscriptionPath},
		{strings.Repeat("x", 73), strings.Repeat("x", 73), c.SubscriptionPath},
		{"a-new-secret-password", "different", c.SubscriptionPath},
		{"", "", c.PanelPath + "/login"},
	} {
		values := form("admin_username", "admin", "current_password", "test-secret", "new_password", tc.password, "confirm_password", tc.confirm, "panel_path", c.PanelPath, "subscription_path", tc.path, "confirm_subscription_path", "1")
		wantStatus(t, request(t, h, "POST", endpoint, values, true), 422)
	}
	if a.config().AdminPasswordHash != "" {
		t.Fatal("rejected form changed password")
	}
}
