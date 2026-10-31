package panel

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sing-box-panel/internal/config"
	"sing-box-panel/internal/singbox"
)

// testOrigin is the address seeded by testApp. Requests to https:// URLs get
// r.TLS set by httptest, like requests through the panel's own TLS listener.
const testOrigin = "https://vpn.example.com:8443"

func testConfig() config.Config {
	return config.Config{
		PanelPath:        "/SECRET_ADMIN_PATH",
		SubscriptionPath: "/SECRET_SUB_PATH",
		AdminUsername:    "admin",
		AdminPassword:    "test-secret",
	}
}

func testApp(t *testing.T, c config.Config) (*app, string) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "panel.db")
	db, err := openDB(filename)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec("INSERT INTO settings(key, value) VALUES('address', 'vpn.example.com'), ('panel_port', '8443')")
	if err != nil {
		t.Fatal(err)
	}
	if c.CertDir == "" {
		c.CertDir = filepath.Join(t.TempDir(), "certs")
	}
	a, err := newApp(c, db)
	if err != nil {
		t.Fatal(err)
	}
	return a, filename
}

func request(t *testing.T, h http.Handler, method, target string, form url.Values, auth bool,
) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if auth {
		r.AddCookie(loginCookie(t, h, target))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func loginCookie(t *testing.T, h http.Handler, target string) *http.Cookie {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	path := u.EscapedPath()
	cut := -1
	for _, part := range []string{"/config", "/server", "/settings", "/logs", "/subscriptions", "/static/"} {
		if index := strings.LastIndex(path, part); index > cut {
			cut = index
		}
	}
	if cut < 0 {
		t.Fatal("unknown admin test path:", path)
	}
	u.Scheme = "https"
	u.RawQuery = ""
	loginURL := u.Scheme + "://" + u.Host + path[:cut] + "/login"
	w := request(t, h, "POST", loginURL, form("username", "admin", "password", "test-secret"), false)
	wantStatus(t, w, 303)
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookie {
			return cookie
		}
	}
	t.Fatal("login returned no session")
	return nil
}

func normalizedJSON(t *testing.T, value []byte) string {
	t.Helper()
	var object any
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

// form builds url.Values from key, value pairs.
func form(pairs ...string) url.Values {
	values := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		values.Set(pairs[i], pairs[i+1])
	}
	return values
}

// addClient inserts an enabled client directly, bypassing the form and sing-box.
func addClient(t *testing.T, db *sql.DB, name, token string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO subscriptions(name, uuid, token, created_at, updated_at)
		VALUES (?, ?, ?, 1, 1)`, name, token, token)
	if err != nil {
		t.Fatal(err)
	}
}

func tokenOf(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	var token string
	if err := db.QueryRow("SELECT token FROM subscriptions WHERE name = ?", name).Scan(&token); err != nil || token == "" {
		t.Fatalf("token for %q: %v", name, err)
	}
	return token
}

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body.String())
	}
}

func TestSubscriptionLifecycleAndPersistence(t *testing.T) {
	c := testConfig()
	a, filename := testApp(t, c)
	h := a.handler()
	panel := testOrigin + c.PanelPath
	public := testOrigin + c.SubscriptionPath
	base := `{"route":{"final":"proxy-1","rules":[1,2]},"large":900719925474099312345,"remove":true}`
	wantStatus(t, request(t, h, "POST", panel+"/config", url.Values{"base_json": {base}, "action": {"save"}}, true), 303)
	create := func(name, override string) string {
		fields := form("name", name, "override_json", override, "enabled", "1", "action", "save")
		w := request(t, h, "POST", panel+"/subscriptions", fields, true)
		wantStatus(t, w, 303)
		return strings.Split(w.Header().Get("Location"), "?")[0]
	}
	idPath := create("Nikolai", `{"route":{"final":"proxy-2","rules":[3]},"remove":null}`)
	create("Second", `{}`)
	nikolai, second := public+"/"+tokenOf(t, a.db, "Nikolai"), public+"/"+tokenOf(t, a.db, "Second")
	// Names are not URLs: knowing the shared prefix and a name gives nothing.
	wantStatus(t, request(t, h, "GET", public+"/Nikolai", nil, false), 404)
	w := request(t, h, "GET", nikolai+"?format=json", nil, false)
	wantStatus(t, w, 200)
	if w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatal("wrong JSON content type")
	}
	expected := `{"large":900719925474099312345,"remove":true,"route":{"final":"proxy-2","rules":[3,1,2]}}`
	if normalizedJSON(t, w.Body.Bytes()) != normalizedJSON(t, []byte(expected)) {
		t.Fatal(w.Body.String())
	}
	preview := request(t, h, "GET", testOrigin+idPath+"/preview", nil, true)
	wantStatus(t, preview, 200)
	if !bytes.Equal(preview.Body.Bytes(), w.Body.Bytes()) {
		t.Fatal("preview differs from public JSON")
	}
	withoutFormat := request(t, h, "GET", nikolai, nil, false)
	if !bytes.Equal(withoutFormat.Body.Bytes(), w.Body.Bytes()) {
		t.Fatal("missing format changed result")
	}
	wantStatus(t, request(t, h, "GET", nikolai+"?format=yaml", nil, false), 400)
	wantStatus(t, request(t, h, "POST", nikolai, url.Values{}, false), 405)
	duplicate := form("name", "Nikolai", "override_json", "{}")
	wantStatus(t, request(t, h, "POST", panel+"/subscriptions", duplicate, true), 422)
	wantStatus(t, request(t, h, "POST", panel+"/config", url.Values{"base_json": {"{"}}, true), 422)
	stored, _ := a.baseConfig(t.Context())
	if stored != base {
		t.Fatal("invalid base was saved")
	}
	for _, action := range []string{"format", "validate"} {
		fields := form("base_json", `{"n":900719925474099312345}`, "action", action)
		wantStatus(t, request(t, h, "POST", panel+"/config", fields, true), 200)
		stored, _ = a.baseConfig(t.Context())
		if stored != base {
			t.Fatal("JSON tool saved base")
		}
	}
	invalid := form("name", "NewName", "override_json", "{", "enabled", "1")
	wantStatus(t, request(t, h, "POST", testOrigin+idPath, invalid, true), 422)
	wantStatus(t, request(t, h, "GET", nikolai, nil, false), 200)
	for _, action := range []string{"format", "validate", "preview"} {
		fields := form("name", "UnsavedName", "override_json", "{}", "action", action)
		w := request(t, h, "POST", testOrigin+idPath, fields, true)
		wantStatus(t, w, 200)
		if !strings.Contains(w.Body.String(), a.subscriptionURL(tokenOf(t, a.db, "Nikolai"))) {
			t.Fatal("JSON tool page lost the subscription URL")
		}
	}
	changedBase := `{"route":{"final":"proxy-3"},"version":2}`
	wantStatus(t, request(t, h, "POST", panel+"/config", url.Values{"base_json": {changedBase}}, true), 303)
	for _, target := range []string{nikolai, second} {
		w := request(t, h, "GET", target, nil, false)
		wantStatus(t, w, 200)
		if !strings.Contains(w.Body.String(), `"version": 2`) {
			t.Fatal("base change did not propagate")
		}
	}
	update := url.Values{"name": {"Nikolai"}, "override_json": {"{}"}}
	wantStatus(t, request(t, h, "POST", testOrigin+idPath, update, true), 303)
	disabled := request(t, h, "GET", nikolai+"?format=json", nil, false)
	unknown := request(t, h, "GET", public+"/missing?format=json", nil, false)
	wantStatus(t, disabled, 404)
	if disabled.Code != unknown.Code || disabled.Body.String() != unknown.Body.String() {
		t.Fatal("disabled subscription is distinguishable")
	}
	wantStatus(t, request(t, h, "GET", testOrigin+idPath+"/preview", nil, true), 200)
	update.Set("name", "Renamed")
	update.Set("enabled", "1")
	wantStatus(t, request(t, h, "POST", testOrigin+idPath, update, true), 303)
	// Renaming keeps the URL.
	wantStatus(t, request(t, h, "GET", nikolai, nil, false), 200)
	// Credential reset rotates the URL too: a leaked link must not fetch the new UUID.
	wantStatus(t, request(t, h, "POST", testOrigin+idPath+"/regenerate-token", url.Values{}, true), 303)
	wantStatus(t, request(t, h, "GET", nikolai, nil, false), 404)
	renamed := public + "/" + tokenOf(t, a.db, "Renamed")
	wantStatus(t, request(t, h, "GET", renamed, nil, false), 200)
	a.db.Close()
	db, err := openDB(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	restarted, err := newApp(c, db)
	if err != nil {
		t.Fatal(err)
	}
	h = restarted.handler()
	w = request(t, h, "GET", renamed, nil, false)
	wantStatus(t, w, 200)
	if normalizedJSON(t, w.Body.Bytes()) != normalizedJSON(t, []byte(changedBase)) {
		t.Fatal("restart lost data")
	}
	wantStatus(t, request(t, h, "POST", testOrigin+idPath+"/delete", url.Values{}, true), 303)
	wantStatus(t, request(t, h, "GET", renamed, nil, false), 404)
	wantStatus(t, request(t, h, "GET", second, nil, false), 200)
}

func TestAdminSecurity(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	path := c.PanelPath + "/config"
	w := request(t, h, "GET", testOrigin+path, nil, false)
	wantStatus(t, w, 303)
	if w.Header().Get("Location") != c.PanelPath+"/login" {
		t.Fatal("no login redirect")
	}
	wantStatus(t, request(t, h, "GET", testOrigin+path, nil, true), 200)
	// Plain HTTP never reaches the admin, even with valid credentials.
	wantStatus(t, request(t, h, "GET", "http://vpn.example.com:8443"+path, nil, true), 403)
	for _, origin := range []string{"https://evil.example", "null"} {
		r := httptest.NewRequest("POST", testOrigin+path, strings.NewReader("base_json=%7B%7D"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(loginCookie(t, h, testOrigin+path))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		wantStatus(t, w, 403)
	}
	r := httptest.NewRequest("POST", testOrigin+path, strings.NewReader("base_json=%7B%7D"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.AddCookie(loginCookie(t, h, testOrigin+path))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	wantStatus(t, w, 403)
	for _, static := range []string{"app.css", "app.js", "Inter-v4.1.woff2", "Inter-LICENSE.txt"} {
		wantStatus(t, request(t, h, "GET", testOrigin+c.PanelPath+"/static/"+static, nil, true), 200)
		wantStatus(t, request(t, h, "GET", testOrigin+c.PanelPath+"/static/"+static, nil, false), 200)
	}
}

func TestPrefixRoutingAndEscapedNames(t *testing.T) {
	// Tokens are generated, so only prefixes need escaping; names still must be HTML-escaped.
	for _, prefix := range []string{"", "/nested/panel", "/literal {panel}/space"} {
		c := testConfig()
		c.PanelPath = prefix
		c.SubscriptionPath = "/nested/subscriptions"
		a, _ := testApp(t, c)
		h := a.handler()
		wantStatus(t, request(t, h, "GET", testOrigin+config.EscapedPrefix(prefix)+"/config", nil, true), 200)
		for i, name := range []string{"Иван Петров", "a/b", "a?b#c%+&", "<script>alert(1)</script>"} {
			token := "TOKEN" + strconv.Itoa(i)
			addClient(t, a.db, name, token)
			wantStatus(t, request(t, h, "GET", a.subscriptionURL(token), nil, false), 200)
		}
		w := request(t, h, "GET", testOrigin+config.EscapedPrefix(prefix)+"/subscriptions", nil, true)
		wantStatus(t, w, 200)
		if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
			t.Fatal("unescaped subscription name")
		}
	}
}

func TestDatabasePragmasAndRequestLimits(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	for pragma, want := range map[string]string{"journal_mode": "wal", "busy_timeout": "5000", "foreign_keys": "1"} {
		var got string
		if err := a.db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil || got != want {
			t.Fatalf("%s: %s (%v)", pragma, got, err)
		}
	}
	h := a.handler()
	big := strings.Repeat("x", 3*singbox.MaxJSONBytes+4097)
	wantStatus(t, request(t, h, "POST", testOrigin+c.PanelPath+"/config", url.Values{"base_json": {big}}, true), 413)
	tooLong := `"` + strings.Repeat("x", singbox.MaxJSONBytes) + `"`
	wantStatus(t, request(t, h, "POST", testOrigin+c.PanelPath+"/config", form("base_json", tooLong), true), 422)
	// Database failures must not log paths, URLs, SQL parameters or credentials.
	var output bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(oldWriter)
	a.db.Close()
	wantStatus(t, request(t, h, "GET", a.subscriptionURL("sensitive-name"), nil, false), 500)
	secrets := []string{c.SubscriptionPath, a.subscriptionURL("sensitive-name"), "sensitive-name", c.AdminPassword}
	for _, secret := range secrets {
		if strings.Contains(output.String(), secret) {
			t.Fatal("secret appeared in log")
		}
	}
}

func TestHealthOnlyFromLoopback(t *testing.T) {
	a, _ := testApp(t, testConfig())
	h := a.handler()
	r := httptest.NewRequest("GET", testOrigin+"/healthz", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	wantStatus(t, w, 204)
	// httptest uses a public RemoteAddr by default.
	wantStatus(t, request(t, h, "GET", testOrigin+"/healthz", nil, false), 404)
}

func TestSubscriptionIDValidation(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	for _, id := range []string{"0", "-1", "abc", strconv.FormatUint(^uint64(0), 10)} {
		wantStatus(t, request(t, a.handler(), "GET", testOrigin+c.PanelPath+"/subscriptions/"+id, nil, true), 404)
	}
	row := a.db.QueryRow("SELECT " + subscriptionColumns + " FROM subscriptions WHERE id=1")
	if _, err := scanSubscription(row); err != sql.ErrNoRows {
		t.Fatal(err)
	}
}

// A change holds app.mu and a write transaction through sing-box check and
// restart; public subscriptions must still be served meanwhile.
func TestSubscriptionsServedDuringChange(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	addClient(t, a.db, "A", "T")
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE subscriptions SET name='B'"); err != nil {
		t.Fatal(err)
	}
	served := make(chan int, 1)
	go func() { served <- request(t, h, "GET", a.subscriptionURL("T"), nil, false).Code }()
	select {
	case code := <-served:
		if code != http.StatusOK {
			t.Fatalf("status %d during change", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscription blocked by a running change")
	}
}

func urlValues(query string) (url.Values, error) { return url.ParseQuery(query) }
