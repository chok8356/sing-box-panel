//go:build linux

package installer

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fakeSystemctl stands in for systemd: it runs the panel directly as the
// service user with panel.env loaded, like the real unit does.
const fakeSystemctl = `#!/bin/sh
pidfile=/run/sing-box-panel-test.pid
running() {
    [ -f $pidfile ] || return 1
    pid=$(cat $pidfile)
    kill -0 "$pid" 2>/dev/null && [ "$(awk '{print $3}' /proc/$pid/stat)" != Z ]
}
stop() {
    if running; then
        pid=$(cat $pidfile)
        kill "$pid"
        for i in $(seq 100); do running || break; sleep 0.1; done
        kill -9 "$pid" 2>/dev/null
    fi
    rm -f $pidfile
}
start() {
    running && return
    (set -a; . /etc/sing-box-panel/panel.env; set +a; cd /var/lib/sing-box-panel
     exec setpriv --reuid=sing-box-panel --regid=sing-box-panel --init-groups /opt/sing-box-panel/sing-box-panel
    ) >>/tmp/sing-box-panel-test.log 2>&1 &
    echo $! > $pidfile
}
[ "$1" = --no-pager ] && shift
case "$1" in
    daemon-reload|enable) ;;
    disable) [ "$2" = --now ] && stop ;;
    is-active|status) running ;;
    stop) stop ;;
    start) start ;;
    restart) stop; start ;;
    *) echo "unexpected systemctl $*" >&2; exit 1 ;;
esac
`

const panelURL = "https://127.0.0.1:18080"

// TestInstallLifecycle installs into /opt, /etc and /var, so it runs only in
// a disposable root container:
//
//	docker run --rm --init -v "$PWD:/src" -w /src -v /path/to/sing-box:/sing-box \
//	  -e SBP_INSTALL_TEST=1 -e SING_BOX_TEST_BINARY=/sing-box golang:1.26 \
//	  go test -run TestInstallLifecycle -v ./internal/installer
func TestInstallLifecycle(t *testing.T) {
	if os.Getenv("SBP_INSTALL_TEST") != "1" || os.Getuid() != 0 {
		t.Skip("set SBP_INSTALL_TEST=1 and run as root in a disposable container")
	}
	singBox := os.Getenv("SING_BOX_TEST_BINARY")
	if singBox == "" {
		t.Fatal("set SING_BOX_TEST_BINARY to sing-box " + singBoxVersion)
	}

	work := t.TempDir()
	binary := filepath.Join(work, "sing-box-panel")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", binary, "../../cmd/sing-box-panel").CombinedOutput(); err != nil {
		t.Fatalf("build: %s", out)
	}
	if err := os.MkdirAll(filepath.Join(work, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "bin", "systemctl"), []byte(fakeSystemctl), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(work, "bin")+":"+os.Getenv("PATH"))
	for _, dir := range []string{"/run/systemd/system", "/run/lock", appDir} {
		os.MkdirAll(dir, 0755)
	}
	// A matching sing-box in place means install does not download it.
	if err := copyFile(singBox, singBoxPath, 0755); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"ADDRESS": "127.0.0.1", "PANEL_PORT": "18080", "TLS_MODE": "auto",
		"PANEL_PATH": "/test-panel", "SUBSCRIPTION_PATH": "/test-sub",
		"ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "test-password",
	} {
		t.Setenv(key, value)
	}
	t.Cleanup(func() { exec.Command("systemctl", "stop", service).Run() })

	sbp := func(args ...string) (string, error) {
		out, err := exec.Command(linkPath, args...).CombinedOutput()
		return string(out), err
	}
	mustSbp := func(args ...string) string {
		t.Helper()
		out, err := sbp(args...)
		if err != nil {
			t.Fatalf("sbp %v: %v\n%s\n%s", args, err, out, readText("/tmp/sing-box-panel-test.log"))
		}
		return out
	}
	failSbp := func(what string, args ...string) {
		t.Helper()
		if out, err := sbp(args...); err == nil {
			t.Fatalf("%s accepted:\n%s", what, out)
		}
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}}
	admin := func(method, path string, form url.Values) string {
		t.Helper()
		login, err := client.PostForm(panelURL+"/test-panel/login", url.Values{"username": {"admin"}, "password": {"test-password"}})
		if err != nil {
			t.Fatal(err)
		}
		login.Body.Close()
		r, _ := http.NewRequest(method, panelURL+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return string(body)
	}
	var subscription string
	public := func() int {
		t.Helper()
		response, err := client.Get(panelURL + subscription)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	wantPublic := func(status int) {
		t.Helper()
		if got := public(); got != status {
			t.Fatalf("subscription status %d, want %d", got, status)
		}
	}

	// Install.
	if out, err := exec.Command(binary, "install").CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s\n%s", err, out, readText("/tmp/sing-box-panel-test.log"))
	}
	if !strings.Contains(mustSbp("url"), "Panel: "+panelURL+"/test-panel/") {
		t.Fatal("sbp url does not show the panel address")
	}
	if info, _ := os.Stat(envPath); info.Mode().Perm() != 0600 {
		t.Fatal("panel.env must be 0600")
	}
	if body := admin("GET", "/test-panel/subscriptions", nil); !strings.Contains(body, "No clients yet") {
		t.Fatal("new install is not empty")
	}
	admin("POST", "/test-panel/server/create-reality", url.Values{"vpn_port": {"18443"}, "handshake": {"example.com"}})
	admin("POST", "/test-panel/subscriptions", url.Values{"name": {"Test"}, "override_json": {"{}"}, "enabled": {"1"}})
	subscription = regexp.MustCompile(`/test-sub/[A-Z2-7]+`).FindString(admin("GET", "/test-panel/subscriptions/1", nil))
	if subscription == "" {
		t.Fatal("new client has no subscription URL")
	}
	wantPublic(200)

	// Backup while running, then restore it.
	backup := strings.TrimSpace(strings.TrimPrefix(mustSbp("backup"), "Backup:"))
	if _, err := os.Stat(filepath.Join(stateDir, "backup-tmp")); err == nil {
		t.Fatal("backup left its work directory behind")
	}
	wantPublic(200)
	admin("POST", "/test-panel/subscriptions/1/delete", url.Values{})
	wantPublic(404)
	mustSbp("restore", backup, "--yes")
	wantPublic(200)

	// Damaged and unsafe backups are refused and leave the panel working.
	corrupt := filepath.Join(work, "corrupt.tar.gz")
	data, _ := os.ReadFile(backup)
	os.WriteFile(corrupt, append(data, "broken"...), 0600)
	copyFile(backup+".sha256", corrupt+".sha256", 0600)
	failSbp("corrupt backup", "restore", corrupt, "--yes")
	wantPublic(200)

	link := filepath.Join(work, "link")
	os.Mkdir(link, 0700)
	os.Symlink("/etc/passwd", filepath.Join(link, "panel.env"))
	unsafe := filepath.Join(work, "unsafe.tar.gz")
	exec.Command("tar", "-czf", unsafe, "-C", link, "panel.env").Run()
	sum, _ := exec.Command("sh", "-c", "cd "+work+" && sha256sum unsafe.tar.gz").Output()
	os.WriteFile(unsafe+".sha256", sum, 0600)
	failSbp("symlink backup", "restore", unsafe, "--yes")
	wantPublic(200)

	// A valid backup whose settings cannot start puts the current state back.
	broken := filepath.Join(work, "broken")
	os.Mkdir(broken, 0700)
	exec.Command("tar", "-xzf", backup, "-C", broken).Run()
	env := strings.Replace(readText(filepath.Join(broken, "panel.env")),
		`ADMIN_PASSWORD="test-password"`, `ADMIN_PASSWORD=""`, 1)
	os.WriteFile(filepath.Join(broken, "panel.env"), []byte(env), 0600)
	brokenArchive := filepath.Join(work, "broken.tar.gz")
	exec.Command("tar", "-czf", brokenArchive, "-C", broken, "panel.env", "panel.db", "VERSION").Run()
	sum, _ = exec.Command("sh", "-c", "cd "+work+" && sha256sum broken.tar.gz").Output()
	os.WriteFile(brokenArchive+".sha256", sum, 0600)
	failSbp("unstartable backup", "restore", brokenArchive, "--yes")
	wantPublic(200)

	// Update to a local binary, uninstall, reinstall over the kept data.
	mustSbp("update", "--file", binary)
	wantPublic(200)
	mustSbp("uninstall")
	for _, path := range []string{linkPath, binaryPath, unitPath} {
		if _, err := os.Stat(path); err == nil {
			t.Fatal(path, "was not removed")
		}
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatal("uninstall removed the database")
	}
	if err := copyFile(singBox, singBoxPath, 0755); err != nil { // uninstall removed it
		t.Fatal(err)
	}
	if out, err := exec.Command(binary, "install").CombinedOutput(); err != nil {
		t.Fatalf("reinstall: %v\n%s", err, out)
	}
	wantPublic(200)
	reset := mustSbp("reset-password")
	match := regexp.MustCompile(`New admin password: ([A-Z2-7]+)`).FindStringSubmatch(reset)
	if len(match) != 2 {
		t.Fatal("password recovery returned no new password")
	}
	response, err := client.PostForm(panelURL+"/test-panel/login", url.Values{"username": {"admin"}, "password": {match[1]}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || response.Request.URL.Path != "/test-panel/subscriptions" {
		t.Fatal("recovered password does not sign in")
	}
	if !strings.Contains(mustSbp("url"), "Password: managed in panel settings") {
		t.Fatal("sbp url shows bootstrap password after recovery")
	}
	wantPublic(200)
	// A backup downloaded in the browser also recovers access through SSH.
	response, err = client.PostForm(panelURL+"/test-panel/settings/backup", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	webBackup := filepath.Join(work, "web-backup.db")
	data, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 || !strings.Contains(response.Header.Get("Content-Disposition"), ".db") {
		t.Fatal("web backup download failed", readErr)
	}
	if err := os.WriteFile(webBackup, data, 0600); err != nil {
		t.Fatal(err)
	}
	mustSbp("reset-password")
	mustSbp("restore", webBackup, "--yes")
	response, err = client.PostForm(panelURL+"/test-panel/login", url.Values{"username": {"admin"}, "password": {match[1]}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || response.Request.URL.Path != "/test-panel/subscriptions" {
		t.Fatal("SSH restore did not recover the credentials saved by the web backup")
	}
	wantPublic(200)
}
