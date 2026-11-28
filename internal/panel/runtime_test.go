package panel

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"sing-box-panel/internal/singbox"
)

func TestSetupAndBackup(t *testing.T) {
	existing, filename := testApp(t, testConfig())
	addClient(t, existing.db, "Existing", "t")
	if err := Setup(filename, "127.0.0.1", 8443); err != nil {
		t.Fatal(err)
	}
	if tokenOf(t, existing.db, "Existing") != "t" {
		t.Fatal("setup changed existing subscription")
	}
	copyFile := filepath.Join(t.TempDir(), "copy.db")
	if err := BackupDatabase(filename, copyFile); err != nil {
		t.Fatal(err)
	}
	if err := CheckDatabase(copyFile); err != nil {
		t.Fatal("online backup is not a valid database:", err)
	}
	if info, err := os.Stat(copyFile); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("backup must be private", err)
	}
	fresh, freshFilename := testApp(t, testConfig())
	if err := seedVPN(fresh.db, "127.0.0.1", "example.com", 443, 8443); err != nil {
		t.Fatal(err)
	}
	body, err := effectiveServer(t.Context(), fresh.db)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "xtls-rprx-vision") {
		t.Fatal("managed user missing")
	}
	tokenOf(t, fresh.db, "First client")
	var before string
	fresh.db.QueryRow("SELECT value FROM settings WHERE key='server_config'").Scan(&before)
	if err := Setup(freshFilename, "other.example", 9444); err != nil {
		t.Fatal(err)
	}
	var after string
	fresh.db.QueryRow("SELECT value FROM settings WHERE key='server_config'").Scan(&after)
	if before != after {
		t.Fatal("setup changed configured installation")
	}
}

func textHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// Opt-in integration test: uses the official sing-box binary, no external network.
func TestRealVPNLifecycle(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BINARY to run real VPN integration")
	}
	hostnameServer, hostnameClient, err := singbox.InitialConfigs("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	clientCheck := singbox.Process{Binary: binary, Dir: t.TempDir()}
	hostnameJSON, err := singbox.ClientConfig(hostnameClient, "{}", hostnameServer, checkUser,
		singbox.Endpoint{Address: "vpn.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := clientCheck.Check(t.Context(), hostnameJSON); err != nil {
		t.Fatal("hostname bootstrap DNS config:", err)
	}
	c := testConfig()
	c.SingBoxBinary = binary
	c.RuntimeDir = filepath.Join(t.TempDir(), "runtime")
	a, _ := testApp(t, c)
	port := freePort(t)
	if err := seedVPN(a.db, "127.0.0.1", "example.com", port, 8443); err != nil {
		t.Fatal(err)
	}
	// Generated clients connect to the panel's address.
	local := site{Address: "127.0.0.1", PanelPort: 8443}
	a.siteValue.Store(&local)
	tlsTarget := httptest.NewUnstartedServer(textHandler("handshake"))
	tlsTarget.Config.ErrorLog = log.New(io.Discard, "", 0)
	tlsTarget.StartTLS()
	defer tlsTarget.Close()
	_, tlsPort, _ := net.SplitHostPort(tlsTarget.Listener.Addr().String())
	tlsNumber, _ := strconv.Atoi(tlsPort)
	var serverRaw string
	a.db.QueryRow("SELECT value FROM settings WHERE key='server_config'").Scan(&serverRaw)
	var root map[string]any
	json.Unmarshal([]byte(serverRaw), &root)
	// Point Reality at the local TLS server so the test needs no internet.
	inbound := root["inbounds"].([]any)[0].(map[string]any)
	reality := inbound["tls"].(map[string]any)["reality"].(map[string]any)
	reality["handshake"] = map[string]any{"server": "127.0.0.1", "server_port": tlsNumber}
	prepared, _ := json.Marshal(root)
	serverRaw = string(prepared)
	a.db.Exec("UPDATE settings SET value=? WHERE key='server_config'", serverRaw)
	a.connectionAPI, err = singbox.NewConnectionAPI()
	if err != nil {
		t.Fatal(err)
	}
	a.core = &singbox.Process{Binary: binary, Dir: c.RuntimeDir}
	t.Cleanup(func() { a.core.Stop() })
	body, err := a.runtimeServer(t.Context(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.core.Apply(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	presenceCtx, stopPresence := context.WithCancel(t.Context())
	presenceDone := make(chan struct{})
	go func() {
		defer close(presenceDone)
		a.watchPresence(presenceCtx)
	}()
	t.Cleanup(func() { stopPresence(); <-presenceDone })
	h := a.handler()
	panel := testOrigin + c.PanelPath
	pid, runningConfig := a.core.PID(), string(a.core.Current())
	w := request(t, h, "GET", panel+"/server", nil, true)
	wantStatus(t, w, 200)
	if page := w.Body.String(); !strings.Contains(page, `<p class="core-version">sing-box <code>`) ||
		strings.Contains(page, "Environment:") {
		t.Fatal("server page should show only the sing-box version")
	}
	for _, tc := range []struct {
		action, json string
		status       int
	}{
		{"format", serverRaw, 200},
		{"validate", serverRaw, 200},
		{"validate", "{", 422},
		{"validate", `{"inbounds":[{"type":"no-such-protocol"}]}`, 422},
	} {
		w := request(t, h, "POST", panel+"/server", form("action", tc.action, "server_json", tc.json), true)
		wantStatus(t, w, tc.status)
		if !strings.Contains(w.Body.String(), `<span class="badge enabled">Running</span>`) {
			t.Fatalf("%s response lost the running status", tc.action)
		}
		if !strings.Contains(w.Body.String(), `<p class="core-version">sing-box <code>`) {
			t.Fatalf("%s response lost the sing-box version", tc.action)
		}
		if !a.core.Running() || a.core.PID() != pid || string(a.core.Current()) != runningConfig {
			t.Fatal("a JSON tool changed the running VPN")
		}
	}
	if stored, err := getSetting(t.Context(), a.db, "server_config"); err != nil || stored != serverRaw {
		t.Fatal("a JSON tool changed the stored server config:", err)
	}
	public := a.subscriptionURL(tokenOf(t, a.db, "First client"))
	final := request(t, h, "GET", public, nil, false)
	wantStatus(t, final, 200)
	if strings.Contains(final.Body.String(), "{{client_uuid}}") || strings.Contains(final.Body.String(), "private_key") {
		t.Fatal("bad client credential expansion")
	}
	holdOpen, finishResponse := context.WithCancel(t.Context())
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-holdOpen.Done()
			return
		}
		textHandler("VPN works").ServeHTTP(w, r)
	}))
	defer destination.Close()
	defer finishResponse()
	launchClient := func(config []byte) (func() bool, *http.Client) {
		var client map[string]any
		json.Unmarshal(config, &client)
		proxyPort := freePort(t)
		client["inbounds"] = []any{
			map[string]any{"type": "mixed", "tag": "test-in", "listen": "127.0.0.1", "listen_port": proxyPort},
		}
		client["route"] = map[string]any{"final": "proxy", "default_domain_resolver": "bootstrap"}
		file := filepath.Join(t.TempDir(), "client.json")
		data, _ := json.Marshal(client)
		os.WriteFile(file, data, 0600)
		checker := singbox.Process{Binary: binary, Dir: t.TempDir()}
		if err := checker.Check(t.Context(), data); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "-c", file)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		stop := func() { _ = cmd.Process.Kill(); <-done }
		t.Cleanup(stop)
		proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(proxyPort))
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		clientHTTP := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		works := func() bool {
			response, err := clientHTTP.Get(destination.URL)
			if err != nil {
				return false
			}
			defer response.Body.Close()
			value, _ := io.ReadAll(response.Body)
			return response.StatusCode == 200 && string(value) == "VPN works"
		}
		deadline := time.Now().Add(5 * time.Second)
		for !works() {
			if time.Now().After(deadline) {
				t.Fatal("real VLESS Reality connection did not work")
			}
			time.Sleep(50 * time.Millisecond)
		}
		return works, clientHTTP
	}
	works, clientHTTP := launchClient(final.Body.Bytes())
	activityURL := panel + "/subscriptions/activity"
	wantStatus(t, request(t, h, "GET", activityURL, nil, false), 303)
	cookie := loginCookie(t, h, activityURL)
	waitForActivity := func(status string, requireLastSeen bool) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for {
			req := httptest.NewRequest("GET", activityURL, nil)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			wantStatus(t, w, http.StatusOK)
			body := w.Body.String()
			var clients map[int64]struct {
				Status   string
				LastSeen *time.Time
				Upload   string
				Download string
			}
			if err := json.Unmarshal(w.Body.Bytes(), &clients); err != nil {
				t.Fatal(err)
			}
			for _, client := range clients {
				if client.Status == status && (!requireLastSeen ||
					(client.LastSeen != nil && client.Upload != "" && client.Upload != "0 B" &&
						client.Download != "" && client.Download != "0 B")) {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("want %s (persisted activity and traffic required: %v), got %s", status, requireLastSeen, body)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	hold, cancelHold := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelHold()
	req, err := http.NewRequestWithContext(hold, "GET", destination.URL+"/hold", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := clientHTTP.Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	waitForActivity("Online", false)
	finishResponse()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	waitForActivity("Offline", true)
	clientsPage := request(t, h, "GET", panel+"/subscriptions", nil, true)
	wantStatus(t, clientsPage, http.StatusOK)
	for _, label := range []string{"Last online", "Offline", "UTC", "Traffic"} {
		if !strings.Contains(clientsPage.Body.String(), label) {
			t.Fatalf("client list is missing %q", label)
		}
	}
	// Validation failure leaves the database and live VPN unchanged.
	invalid := form("server_json", `{"inbounds":[{"type":"no-such-protocol"}]}`, "action", "save")
	bad := request(t, h, "POST", panel+"/server", invalid, true)
	wantStatus(t, bad, 422)
	if !works() {
		t.Fatal("invalid config interrupted working VPN")
	}
	// A valid config that cannot bind must also roll back, not just pass check.
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	conflict := map[string]any{
		"type":        "mixed",
		"tag":         "conflict",
		"listen":      "127.0.0.1",
		"listen_port": blocked.Addr().(*net.TCPAddr).Port,
	}
	root["inbounds"] = append(root["inbounds"].([]any), conflict)
	invalidStartup, _ := json.Marshal(root)
	failing := form("server_json", string(invalidStartup), "action", "save")
	wantStatus(t, request(t, h, "POST", panel+"/server", failing, true), 422)
	if !works() {
		t.Fatal("startup failure did not restore VPN")
	}
	var stored string
	a.db.QueryRow("SELECT value FROM settings WHERE key='server_config'").Scan(&stored)
	if stored != serverRaw {
		t.Fatal("failed runtime config was committed")
	}
	var id int64
	a.db.QueryRow("SELECT id FROM subscriptions WHERE name='First client'").Scan(&id)
	edit := panel + "/subscriptions/" + strconv.FormatInt(id, 10)
	clientPage := request(t, h, "GET", edit, nil, true)
	wantStatus(t, clientPage, http.StatusOK)
	if !strings.Contains(clientPage.Body.String(), "Created <time") {
		t.Fatal("client page is missing the creation date")
	}
	fields := url.Values{"name": {"First client"}, "override_json": {"{}"}, "action": {"save"}}
	wantStatus(t, request(t, h, "POST", edit, fields, true), 303)
	wantStatus(t, request(t, h, "GET", public, nil, false), 404)
	if works() {
		t.Fatal("disabled UUID still has VPN access")
	}
	fields.Set("enabled", "1")
	wantStatus(t, request(t, h, "POST", edit, fields, true), 303)
	if !works() {
		t.Fatal("re-enabled client cannot connect")
	}
	wantStatus(t, request(t, h, "POST", edit+"/regenerate-token", url.Values{}, true), 303)
	if works() {
		t.Fatal("rotated UUID still has VPN access")
	}
	wantStatus(t, request(t, h, "GET", public, nil, false), 404)
	updated := request(t, h, "GET", a.subscriptionURL(tokenOf(t, a.db, "First client")), nil, false)
	wantStatus(t, updated, 200)
	if final.Body.String() == updated.Body.String() {
		t.Fatal("credential reset did not update subscription")
	}
	newWorks, _ := launchClient(updated.Body.Bytes())
	if !newWorks() {
		t.Fatal("new UUID does not connect")
	}
	wantStatus(t, request(t, h, "POST", edit+"/delete", url.Values{}, true), 303)
	if newWorks() {
		t.Fatal("deleted UUID still has VPN access")
	}
	// The supervisor recovers an unexpected child exit from persisted state.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.watchCore(ctx)
	a.mu.RLock()
	previousPID := a.core.PID()
	a.mu.RUnlock()
	if child, err := os.FindProcess(previousPID); err != nil || child.Kill() != nil {
		t.Fatal("cannot kill sing-box")
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		a.mu.RLock()
		recovered := a.core.Running() && a.core.PID() != previousPID
		a.mu.RUnlock()
		if recovered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("core supervisor did not recover")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	a.mu.Lock()
	a.core.Stop()
	a.mu.Unlock()
}
