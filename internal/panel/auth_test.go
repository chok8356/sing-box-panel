package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	target := testOrigin + c.PanelPath + "/config"
	loginURL := testOrigin + c.PanelPath + "/login"
	w := request(t, h, "GET", loginURL, nil, false)
	wantStatus(t, w, 200)
	for _, attribute := range []string{`autocomplete="username"`, `autocomplete="current-password"`} {
		if !strings.Contains(w.Body.String(), attribute) {
			t.Fatal("password manager hint missing:", attribute)
		}
	}
	wantStatus(t, request(t, h, "POST", loginURL, form("username", "admin", "password", "wrong"), false), 401)
	cookie := loginCookie(t, h, target)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != c.PanelPath+"/" || cookie.MaxAge != int(sessionLifetime.Seconds()) {
		t.Fatal("unsafe session cookie:", cookie)
	}
	var hash string
	if err := a.db.QueryRow("SELECT token_hash FROM admin_sessions").Scan(&hash); err != nil || hash != digest(cookie.Value) {
		t.Fatal("session must be stored as a digest", err)
	}
	get := func(handler http.Handler, method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, testOrigin+c.PanelPath+path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	wantStatus(t, get(h, "GET", "/config"), 200)
	// Restart keeps sessions, while changing the configured credentials revokes them.
	restarted, err := newApp(a.config(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, get(restarted.handler(), "GET", "/config"), 200)
	changed := a.config()
	changed.AdminPassword = "new-secret"
	changedApp, err := newApp(changed, a.db)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, get(changedApp.handler(), "GET", "/config"), 303)
	// A modified token never authenticates.
	original := cookie.Value
	cookie.Value += "x"
	wantStatus(t, get(h, "GET", "/config"), 303)
	cookie.Value = original
	wantStatus(t, get(h, "POST", "/logout"), 303)
	wantStatus(t, get(h, "GET", "/config"), 303)
	cookie = loginCookie(t, h, target)
	if _, err := a.db.Exec("UPDATE admin_sessions SET expires=?", time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, get(h, "GET", "/config"), 303)
}

func TestLoginAbuseProtection(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	loginURL := testOrigin + c.PanelPath + "/login"
	for range 10 {
		wantStatus(t, request(t, h, "POST", loginURL, form("username", "admin", "password", "wrong"), false), 401)
	}
	wantStatus(t, request(t, h, "POST", loginURL, form("username", "admin", "password", "test-secret"), false), 429)
	for ip, attempt := range a.loginLimits.attempts {
		attempt.until = time.Now().Add(-time.Second)
		a.loginLimits.attempts[ip] = attempt
	}
	wantStatus(t, request(t, h, "POST", loginURL, form("username", "admin", "password", "test-secret"), false), 303)
	for _, path := range []string{"/login", "/logout"} {
		r := httptest.NewRequest("POST", testOrigin+c.PanelPath+path, strings.NewReader("username=admin&password=test-secret"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		wantStatus(t, w, 403)
	}
	wantStatus(t, request(t, h, "POST", loginURL, form("password", strings.Repeat("x", 5000)), false), 400)
	wantStatus(t, request(t, h, "GET", "http://vpn.example.com"+c.PanelPath+"/login", nil, false), 403)
}
