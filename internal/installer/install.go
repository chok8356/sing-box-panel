//go:build linux

package installer

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sing-box-panel/internal/config"
	"sing-box-panel/internal/panel"
)

// Pinned sing-box release; the digests come from GitHub's release page.
const singBoxVersion = "1.14.4"

var singBoxSHA256 = map[string]string{
	"amd64": "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968",
	"arm64": "436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26",
}

var semver = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$`)

// answers are the first-install settings, from the environment or prompts.
type answers struct {
	address                  string
	panelPort                int
	certFile, keyFile        string
	panelPath, subPath       string
	adminUser, adminPassword string
}

// install installs this binary, or upgrades an existing installation to it.
// An upgrade backs up first and returns to the previous binary if the new
// one does not start.
func install(version string) (err error) {
	existing := installed()
	var a answers
	if !existing {
		if a, err = ask(); err != nil {
			return err
		}
	}
	uid, gid, err := serviceUser()
	if err != nil {
		return err
	}
	for _, dir := range []struct {
		path string
		mode os.FileMode
	}{{appDir, 0755}, {configDir, 0700}, {stateDir, 0700}} {
		if err := os.MkdirAll(dir.path, dir.mode); err != nil {
			return err
		}
	}
	if err := os.Chown(stateDir, uid, gid); err != nil {
		return err
	}
	if err := ensureSingBox(); err != nil {
		return err
	}

	// Upgrade: stop, back up and keep the previous binary and unit for a rollback.
	var previous string
	if existing {
		wasActive := serviceActive()
		_ = systemctl("stop", service)
		defer func() {
			if err != nil && wasActive {
				_ = systemctl("start", service)
			}
		}()
		// After uninstall there is no binary to back up with; the data is kept as is.
		if _, statErr := os.Stat(binaryPath); statErr == nil {
			if _, err := snapshot(version); err != nil {
				return err
			}
		}
		if previous, err = os.MkdirTemp("", "sbp-previous-"); err != nil {
			return err
		}
		defer os.RemoveAll(previous)
		_ = copyFile(binaryPath, filepath.Join(previous, "sing-box-panel"), 0755)
		_ = copyFile(unitPath, filepath.Join(previous, "unit"), 0644)
	} else {
		// The database is created first; panel.env is written last and marks a finished install.
		if err := panel.Setup(dbPath, a.address, a.panelPort); err != nil {
			return err
		}
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := os.Chown(dbPath+suffix, uid, gid); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := writeEnv(a); err != nil {
			return err
		}
	}

	if err := installFiles(); err != nil {
		return err
	}
	if err := startService(); err != nil {
		if previous != "" && rollback(previous) == nil {
			return errors.New("new version failed to start; the previous version was restored (journalctl -u sing-box-panel)")
		}
		return err
	}

	fmt.Printf("sing-box-panel %s installed.\n\n", version)
	if !existing && a.certFile == "" {
		ip := net.ParseIP(a.address)
		if ip == nil || ip.IsGlobalUnicast() && !ip.IsPrivate() {
			fmt.Println("HTTPS certificate: requesting automatically. TCP 80 must be reachable in both server and provider firewalls.")
			waitCertificate()
		}
	}
	if err := printAccess(); err != nil {
		return err
	}
	if !existing {
		fmt.Printf("\nOpen TCP %d for the panel in the server/provider firewalls.\n", a.panelPort)
		if a.certFile == "" {
			fmt.Println("Keep TCP 80 open for automatic certificate issuance and renewal.")
		}
		fmt.Println("The panel is empty. Configure Server, then Client config, then create your first client.")
	}
	return nil
}

// installFiles copies this binary into place and writes the unit and the sbp link.
func installFiles() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if self != binaryPath {
		if err := copyFile(self, binaryPath, 0755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(unitPath, []byte(unitFile), 0644); err != nil {
		return err
	}
	_ = os.Remove(linkPath)
	return os.Symlink(binaryPath, linkPath)
}

func startService() error {
	for _, args := range [][]string{{"daemon-reload"}, {"enable", service}, {"restart", service}} {
		if err := systemctl(args...); err != nil {
			return err
		}
	}
	if !waitReady() {
		return errors.New("panel failed to start (journalctl -u sing-box-panel)")
	}
	return nil
}

func rollback(previous string) error {
	_ = systemctl("stop", service)
	if err := copyFile(filepath.Join(previous, "sing-box-panel"), binaryPath, 0755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(previous, "unit"), unitPath, 0644); err != nil {
		return err
	}
	return startService()
}

// ask collects first-install settings. Every answer can be preset with an
// environment variable, which also allows unattended installs.
func ask() (answers, error) {
	var tty *bufio.ReadWriter
	if file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer file.Close()
		tty = bufio.NewReadWriter(bufio.NewReader(file), bufio.NewWriter(file))
	}
	prompt := func(key, label, fallback string) (string, error) {
		if value := os.Getenv(key); value != "" {
			return value, nil
		}
		if tty == nil {
			return "", fmt.Errorf("set %s for an unattended install", key)
		}
		fmt.Fprintf(tty, "%s [%s]: ", label, fallback)
		tty.Flush()
		line, _ := tty.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			return line, nil
		}
		return fallback, nil
	}
	port := func(key, label, fallback string) (int, error) {
		value, err := prompt(key, label, fallback)
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%s must be a number", key)
		}
		return n, nil
	}

	var a answers
	var err error
	if a.address, err = prompt("ADDRESS", "Domain or public IP of this server", detectIP()); err != nil {
		return a, err
	}
	if a.panelPort, err = port("PANEL_PORT", "Panel HTTPS port", "8443"); err != nil {
		return a, err
	}
	modeDefault := "auto"
	if os.Getenv("TLS_CERT_FILE") != "" {
		modeDefault = "existing"
	}
	mode, err := prompt("TLS_MODE", "HTTPS certificate: auto (Let's Encrypt, TCP 80) or existing (PEM files)", modeDefault)
	if err != nil {
		return a, err
	}
	switch mode {
	case "auto":
	case "existing":
		if a.certFile, err = prompt("TLS_CERT_FILE", "Existing certificate chain PEM (readable by sing-box-panel user)", ""); err != nil {
			return a, err
		}
		if a.keyFile, err = prompt("TLS_KEY_FILE", "Existing private key PEM (readable by sing-box-panel user)", ""); err != nil {
			return a, err
		}
		if !filepath.IsAbs(a.certFile) || !filepath.IsAbs(a.keyFile) {
			return a, errors.New("certificate and key paths must be absolute")
		}
		cert, err := tls.LoadX509KeyPair(a.certFile, a.keyFile)
		if err != nil {
			return a, fmt.Errorf("existing certificate: %w", err)
		}
		if err := cert.Leaf.VerifyHostname(a.address); err != nil {
			return a, err
		}
		if time.Now().Before(cert.Leaf.NotBefore) || !time.Now().Before(cert.Leaf.NotAfter) {
			return a, errors.New("existing certificate is expired or not yet valid")
		}
	default:
		return a, errors.New("TLS_MODE must be auto or existing")
	}
	a.panelPath = envOr("PANEL_PATH", "/"+randomHex())
	a.subPath = envOr("SUBSCRIPTION_PATH", "/"+randomHex())
	a.adminUser = envOr("ADMIN_USERNAME", "admin")
	a.adminPassword = envOr("ADMIN_PASSWORD", randomHex())
	return a, nil
}

// detectIP returns the address of the default route, without sending anything.
func detectIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func randomHex() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// writeEnv writes panel.env. systemd reads it, so characters it would
// interpret are refused rather than escaped.
func writeEnv(a answers) error {
	values := [][2]string{
		{"DATABASE_PATH", dbPath},
		{"RUNTIME_DIR", stateDir + "/runtime"},
		{"CERT_DIR", stateDir + "/certs"},
		{"TLS_CERT_FILE", a.certFile},
		{"TLS_KEY_FILE", a.keyFile},
		{"SING_BOX_BINARY", singBoxPath},
		{"PANEL_PATH", a.panelPath},
		{"SUBSCRIPTION_PATH", a.subPath},
		{"ADMIN_USERNAME", a.adminUser},
		{"ADMIN_PASSWORD", a.adminPassword},
	}
	var out strings.Builder
	for _, kv := range values {
		if strings.ContainsAny(kv[1], "\"\\$`\r\n") {
			return fmt.Errorf("%s must not contain quotes, backslashes, $, backticks or newlines", kv[0])
		}
		os.Setenv(kv[0], kv[1]) // for the validation below
		fmt.Fprintf(&out, "%s=\"%s\"\n", kv[0], kv[1])
	}
	if _, err := config.Load(); err != nil {
		return err
	}
	return writeFileAtomic(envPath, []byte(out.String()), 0600)
}

// waitCertificate reports success or an explicit fallback; it never hides a failed issue.
func waitCertificate() {
	var status struct {
		Ready, Checking              bool
		Mode, Issuer, Expires, Error string
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		out, err := asService("certificate-status")
		if err == nil && json.Unmarshal([]byte(out), &status) == nil {
			if status.Ready {
				fmt.Printf("HTTPS ready: %s; expires %s.\n", status.Issuer, status.Expires)
				return
			}
			if !status.Checking && status.Error != "" {
				fmt.Println("Certificate issuance failed:", status.Error)
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Println("Panel is running with a temporary certificate. Remote subscriptions are not ready until a trusted certificate is issued.")
	fmt.Println("Check TCP 80 and Settings > Certificate; retry there or inspect sbp logs.")
}

// ensureSingBox downloads the pinned official sing-box unless it is already in place.
func ensureSingBox() error {
	if out, err := exec.Command(singBoxPath, "version").Output(); err == nil &&
		bytes.Contains(out, []byte("sing-box version "+singBoxVersion)) {
		return nil
	}
	sum, ok := singBoxSHA256[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("unsupported architecture %s; use amd64 or arm64", runtime.GOARCH)
	}
	name := fmt.Sprintf("sing-box-%s-linux-%s", singBoxVersion, runtime.GOARCH)
	fmt.Printf("Downloading sing-box %s...\n", singBoxVersion)
	data, err := download(fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/%s.tar.gz",
		singBoxVersion, name))
	if err != nil {
		return err
	}
	if digest := sha256.Sum256(data); hex.EncodeToString(digest[:]) != sum {
		return errors.New("sing-box download does not match its pinned SHA-256")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err != nil {
			return errors.New("sing-box binary not found in the release archive")
		}
		if header.Name == name+"/sing-box" {
			binary, err := io.ReadAll(io.LimitReader(archive, 200<<20))
			if err != nil {
				return err
			}
			return writeFileAtomic(singBoxPath, binary, 0755)
		}
	}
}

// update downloads a release (or takes --file) and hands over to its install command.
func update(args []string, unlock func()) error {
	var binary string
	switch {
	case len(args) == 2 && args[0] == "--file":
		binary = args[1]
	case len(args) <= 1:
		version := "latest"
		if len(args) == 1 {
			version = args[0]
		}
		var err error
		if binary, err = downloadRelease(version); err != nil {
			return err
		}
	default:
		return errors.New("usage: sbp update [vX.Y.Z | --file BINARY]")
	}
	if binary, err := filepath.Abs(binary); err == nil {
		unlock() // the new binary takes the lock itself
		return syscall.Exec(binary, []string{binary, "install"}, os.Environ())
	}
	return errors.New("invalid binary path")
}

// downloadRelease fetches the panel binary for this architecture and checks it against SHA256SUMS.
func downloadRelease(version string) (string, error) {
	if version == "latest" {
		client := &http.Client{Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Get("https://github.com/" + repo + "/releases/latest")
		if err != nil {
			return "", err
		}
		response.Body.Close()
		version = filepath.Base(response.Header.Get("Location"))
	}
	if !semver.MatchString(version) {
		return "", errors.New("release must be vX.Y.Z")
	}
	name := "sing-box-panel_linux_" + runtime.GOARCH
	base := "https://github.com/" + repo + "/releases/download/" + version + "/"
	sums, err := download(base + "SHA256SUMS")
	if err != nil {
		return "", err
	}
	var expected string
	for _, line := range strings.Split(string(sums), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[1] == name {
			expected = fields[0]
		}
	}
	if expected == "" {
		return "", errors.New("release has no checksum for " + name)
	}
	fmt.Printf("Downloading sing-box-panel %s...\n", version)
	data, err := download(base + name)
	if err != nil {
		return "", err
	}
	if digest := sha256.Sum256(data); hex.EncodeToString(digest[:]) != expected {
		return "", errors.New("release checksum mismatch")
	}
	file, err := os.CreateTemp("", "sing-box-panel-")
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return "", err
	}
	return file.Name(), file.Chmod(0755)
}

func download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, response.Status)
	}
	return io.ReadAll(io.LimitReader(response.Body, 200<<20))
}

func copyFile(from, to string, mode os.FileMode) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return writeFileAtomic(to, data, mode)
}

// writeFileAtomic replaces a file via rename, so a crash never leaves it half-written.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path+".new", data, mode); err != nil {
		return err
	}
	if err := os.Chmod(path+".new", mode); err != nil {
		return err
	}
	return os.Rename(path+".new", path)
}
