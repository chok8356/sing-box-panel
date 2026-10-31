package panel

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sing-box-panel/internal/singbox"
)

func backupApp(t *testing.T) *app {
	t.Helper()
	a, filename := testApp(t, testConfig())
	c := a.config()
	c.DatabasePath = filename
	a.applyConfig(c)
	return a
}

func uploadBackup(t *testing.T, a *app, data []byte, password, confirm, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, err := form.CreateFormFile("backup", "backup.db")
	if err != nil {
		t.Fatal(err)
	}
	file.Write(data)
	form.WriteField("current_password", password)
	form.WriteField("confirm_restore", confirm)
	form.Close()
	r := httptest.NewRequest("POST", testOrigin+a.config().PanelPath+"/settings/restore", &body)
	r.Header.Set("Content-Type", form.FormDataContentType())
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	return w
}

func downloadBackup(t *testing.T, a *app) []byte {
	t.Helper()
	w := request(t, a.handler(), "POST", testOrigin+a.config().PanelPath+"/settings/backup", nil, true)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Header().Get("Content-Disposition"), ".db") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("unsafe download headers")
	}
	return w.Body.Bytes()
}

func TestWebBackupRestoresAllSettingsAndClients(t *testing.T) {
	a := backupApp(t)
	if err := seedVPN(a.db, "vpn.example.com", "example.com", 443, 8443); err != nil {
		t.Fatal(err)
	}
	a.db.Exec("UPDATE subscriptions SET override_json=?", `{"route":{"rules":[]}}`)
	before, _ := effectiveServer(t.Context(), a.db)
	base, _ := a.baseConfig(t.Context())
	token := tokenOf(t, a.db, "First client")
	data := downloadBackup(t, a)
	// Change both access and configuration before returning to the saved state.
	changed := a.config()
	changed.PanelPath, changed.SubscriptionPath = "/changed", "/changed-sub"
	changed.AdminUsername, changed.AdminPassword = "changed-admin", "changed-password"
	if err := a.saveAccessPreferences(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	a.db.Exec("DELETE FROM subscriptions; UPDATE settings SET value='{}' WHERE key IN ('server_config','base_config'); UPDATE settings SET value='other.example' WHERE key='address'; UPDATE settings SET value='9443' WHERE key='panel_port'")
	oldSite := site{Address: "other.example", PanelPort: 9443}
	a.siteValue.Store(&oldSite)
	login := request(t, a.handler(), "POST", testOrigin+"/changed/login", form("username", changed.AdminUsername, "password", changed.AdminPassword), false)
	wantStatus(t, login, 303)
	cookie := login.Result().Cookies()[0]
	w := uploadBackup(t, a, data, changed.AdminPassword, "1", "", cookie)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `href="`+testOrigin+testConfig().PanelPath+`/login"`) || !strings.Contains(w.Body.String(), "Backup restored") {
		t.Fatal("restore did not show the saved address/path")
	}
	if a.site().Address != "vpn.example.com" || a.site().PanelPort != 8443 || a.config().SubscriptionPath != testConfig().SubscriptionPath || a.config().AdminUsername != "admin" || !validPassword(a.config(), "test-secret") || validPassword(a.config(), changed.AdminPassword) {
		t.Fatal("saved connection or credentials not restored")
	}
	after, _ := effectiveServer(t.Context(), a.db)
	afterBase, _ := a.baseConfig(t.Context())
	if !bytes.Equal(before, after) || base != afterBase || tokenOf(t, a.db, "First client") != token {
		t.Fatal("client credentials/server/base configuration changed")
	}
	var override string
	var sessions int
	a.db.QueryRow("SELECT override_json FROM subscriptions").Scan(&override)
	a.db.QueryRow("SELECT count(*) FROM admin_sessions").Scan(&sessions)
	if override != `{"route":{"rules":[]}}` || sessions != 0 {
		t.Fatal("override lost or sessions restored")
	}
	wantStatus(t, request(t, a.handler(), "POST", testOrigin+a.config().PanelPath+"/login", form("username", "admin", "password", "test-secret"), false), 303)
	restarted, err := newApp(changed, a.db)
	if err != nil || restarted.config().AdminUsername != "admin" || !validPassword(restarted.config(), "test-secret") {
		t.Fatal("saved access did not survive a restart", err)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(a.config().DatabasePath), "backups", "*.db"))
	if err != nil || len(files) != 1 {
		t.Fatal("missing automatic recovery backup", err)
	}
	_, _, recovery, recoverySite, err := readBackup(t.Context(), files[0], a.config())
	if err != nil || recovery.AdminUsername != changed.AdminUsername || !validPassword(recovery, changed.AdminPassword) || recoverySite.Address != "other.example" {
		t.Fatal("recovery backup does not contain replaced state", err)
	}
}

func TestBackupRestoreRejectsUnsafeInputWithoutChanges(t *testing.T) {
	a := backupApp(t)
	addClient(t, a.db, "Keep", "KEEP")
	data := downloadBackup(t, a)
	cookie := loginCookie(t, a.handler(), testOrigin+a.config().PanelPath+"/settings")
	for _, tc := range []struct {
		name, password, confirm, origin string
		data                            []byte
		cookie                          *http.Cookie
		status                          int
	}{
		{"signed out", "test-secret", "1", "", data, nil, 303},
		{"wrong password", "wrong", "1", "", data, cookie, 401},
		{"no confirmation", "test-secret", "", "", data, cookie, 422},
		{"cross site", "test-secret", "1", "https://evil.example", data, cookie, 403},
		{"corrupted", "test-secret", "1", "", []byte("broken database"), cookie, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus(t, uploadBackup(t, a, tc.data, tc.password, tc.confirm, tc.origin, tc.cookie), tc.status)
			if tokenOf(t, a.db, "Keep") != "KEEP" || !validPassword(a.config(), "test-secret") {
				t.Fatal("rejected restore changed state")
			}
		})
	}
	wantStatus(t, request(t, a.handler(), "POST", testOrigin+a.config().PanelPath+"/settings/backup", nil, false), 303)
	file := filepath.Join(t.TempDir(), "unsafe.db")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", file)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("CREATE TRIGGER unsafe AFTER DELETE ON subscriptions BEGIN DELETE FROM settings; END")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	unsafeData, _ := os.ReadFile(file)
	wantStatus(t, uploadBackup(t, a, unsafeData, "test-secret", "1", "", cookie), 422)
	if tokenOf(t, a.db, "Keep") != "KEEP" {
		t.Fatal("untrusted schema affected current database")
	}
}

func TestRestoreRejectedBySingBoxRollsBack(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BINARY for restore runtime validation")
	}
	a := backupApp(t)
	addClient(t, a.db, "Saved", "SAVED")
	a.db.Exec("INSERT INTO settings(key,value) VALUES('server_config',?)", `{"inbounds":[{"type":"does-not-exist"}]}`)
	data := downloadBackup(t, a)
	a.db.Exec("UPDATE settings SET value='{}' WHERE key='server_config'; DELETE FROM subscriptions")
	addClient(t, a.db, "Current", "CURRENT")
	a.core = &singbox.Process{Binary: binary, Dir: t.TempDir()}
	t.Cleanup(func() { a.core.Stop() })
	cookie := loginCookie(t, a.handler(), testOrigin+a.config().PanelPath+"/settings")
	w := uploadBackup(t, a, data, "test-secret", "1", "", cookie)
	wantStatus(t, w, 422)
	if tokenOf(t, a.db, "Current") != "CURRENT" || !strings.Contains(w.Body.String(), "current settings were kept") {
		t.Fatal("runtime rejection lost current state")
	}
	r := httptest.NewRequest("GET", testOrigin+a.config().PanelPath+"/settings", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	wantStatus(t, w, 200)
}

func TestRestoreChangesHTTPSPort(t *testing.T) {
	a := backupApp(t)
	first, second := freePort(t), freePort(t)
	a.db.Exec("UPDATE settings SET value=? WHERE key='panel_port'", second)
	data := downloadBackup(t, a)
	a.db.Exec("UPDATE settings SET value=? WHERE key='panel_port'", first)
	s := a.site()
	s.PanelPort = first
	a.siteValue.Store(&s)
	if err := a.listeners.start(first); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.listeners.shutdown(t.Context()) })
	cookie := loginCookie(t, a.handler(), testOrigin+a.config().PanelPath+"/settings")
	occupied, err := net.Listen("tcp", fmt.Sprintf(":%d", second))
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, uploadBackup(t, a, data, "test-secret", "1", "", cookie), 422)
	occupied.Close()
	if port, _ := getSetting(t.Context(), a.db, "panel_port"); port != fmt.Sprint(first) || a.site().PanelPort != first || !listening(first) {
		t.Fatal("unavailable saved port changed current settings")
	}
	wantStatus(t, uploadBackup(t, a, data, "test-secret", "1", "", cookie), 200)
	client := newAdminClient(t)
	response, err := client.client.Get((site{Address: "127.0.0.1", PanelPort: second}).origin() + a.config().PanelPath + "/login")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || a.site().PanelPort != second {
		t.Fatal("saved port did not serve HTTPS")
	}
	waitFor(t, "old port stayed open after restore", func() bool { return !listening(first) })
}
