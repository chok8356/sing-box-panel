//go:build linux

// Package installer implements the server commands (install, update, backup,
// restore, uninstall, service control). They run as root on a Debian/Ubuntu
// VPS with systemd. The binary installs itself, downloads the official
// sing-box and is linked as the `sbp` command.
package installer

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	service   = "sing-box-panel"
	repo      = "chok8356/sing-box-panel"
	appDir    = "/opt/sing-box-panel"
	configDir = "/etc/sing-box-panel"
	stateDir  = "/var/lib/sing-box-panel"
	backupDir = "/var/backups/sing-box-panel"

	binaryPath  = appDir + "/sing-box-panel"
	singBoxPath = appDir + "/sing-box"
	envPath     = configDir + "/panel.env"
	dbPath      = stateDir + "/panel.db"
	unitPath    = "/etc/systemd/system/" + service + ".service"
	linkPath    = "/usr/local/bin/sbp"
	lockPath    = "/run/lock/sing-box-panel.lock"
)

// unitFile runs the panel as an unprivileged user. CAP_NET_BIND_SERVICE lets
// the panel and sing-box (its child) listen on ports below 1024 such as 80 and 443.
const unitFile = `[Unit]
Description=sing-box-panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=` + service + `
Group=` + service + `
EnvironmentFile=` + envPath + `
ExecStart=` + binaryPath + `
WorkingDirectory=` + stateDir + `
StateDirectory=` + service + `
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
`

const Usage = `Server commands (run as root):

  install                     install, or upgrade the installed panel to this binary
  update [vX.Y.Z]             download a release (latest by default) and install it
  update --file BINARY        install a downloaded binary
  status                      show the service status
  start | stop | restart      control the service
  logs                        follow the panel journal
  url                         show the panel address and login
  reset-password              reset the admin password and revoke sessions
  backup                      back up the database and settings (sing-box keeps running)
  restore FILE [--yes]        restore a CLI archive or a web .db backup
  uninstall                   remove the program; keep data, settings and backups

Address and ports are changed on the panel's Settings page.`

// Commands lists the server commands handled by Run.
var Commands = []string{"install", "update", "status", "start", "stop", "restart", "logs", "url",
	"backup", "restore", "uninstall", "reset-password"}

// Run executes a server command. version is the version of this binary.
func Run(version, command string, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo)")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd must be running")
	}
	if command != "install" && !installed() {
		return errors.New("sing-box-panel is not installed")
	}
	switch command {
	case "status":
		return systemctl("--no-pager", "status", service)
	case "logs":
		return runVisible("journalctl", "--no-pager", "-u", service, "-f")
	}

	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	switch command {
	case "install":
		return install(version)
	case "update":
		return update(args, unlock)
	case "start", "stop", "restart":
		return systemctl(command, service)
	case "url":
		return printAccess()
	case "reset-password":
		out, err := asService("reset-admin-password")
		if err != nil {
			return err
		}
		fmt.Print(out)
		if err := systemctl("restart", service); err != nil {
			return err
		}
		if !waitReady() {
			return errors.New("password changed, but the panel did not become ready; check sbp logs")
		}
		return nil
	case "backup":
		_, err := snapshot(version)
		return err
	case "restore":
		if len(args) == 0 || len(args) > 2 || (len(args) == 2 && args[1] != "--yes") {
			return errors.New("usage: sbp restore FILE [--yes]")
		}
		return restore(version, args[0], len(args) == 2)
	case "uninstall":
		return uninstall()
	}
	return errors.New(Usage)
}

func installed() bool {
	_, err := os.Stat(envPath)
	return err == nil
}

// lock makes sure only one server command changes the installation at a time.
func lock() (func(), error) {
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another sbp command is running")
	}
	return func() { file.Close() }, nil
}

func runVisible(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func systemctl(args ...string) error { return runVisible("systemctl", args...) }

func serviceActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", service).Run() == nil
}

// serviceUser returns the uid and gid of the panel's system user, creating it if needed.
func serviceUser() (uid, gid int, err error) {
	if _, err := user.Lookup(service); err != nil {
		err := exec.Command("useradd", "--system", "--user-group", "--home-dir", stateDir,
			"--no-create-home", "--shell", "/usr/sbin/nologin", service).Run()
		if err != nil {
			return 0, 0, fmt.Errorf("cannot create user %s: %w", service, err)
		}
	}
	u, err := user.Lookup(service)
	if err != nil {
		return 0, 0, err
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid, nil
}

// asService runs a subcommand of the installed binary as the service user
// with panel.env loaded, exactly as systemd would, and returns its output.
func asService(args ...string) (string, error) {
	uid, gid, err := serviceUser()
	if err != nil {
		return "", err
	}
	env, err := readEnv(envPath)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = stateDir
	cmd.Env = append(env, "PATH=/usr/sbin:/usr/bin:/sbin:/bin")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// readEnv parses panel.env (KEY=value or KEY="value" lines, as written by install).
func readEnv(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var env []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		env = append(env, key+"="+strings.Trim(value, `"`))
	}
	return env, scanner.Err()
}

func envValue(env []string, key string) string {
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, key+"="); ok {
			return value
		}
	}
	return ""
}

// waitReady waits up to 20s for systemd and the panel's health check.
func waitReady() bool {
	for range 20 {
		if serviceActive() {
			if _, err := asService("health"); err == nil {
				return true
			}
		}
		time.Sleep(time.Second)
	}
	return false
}

func printAccess() error {
	out, err := asService("panel-url")
	if err != nil {
		return err
	}
	fmt.Printf("Panel: %s", out)
	if !strings.Contains(out, "\nPassword:") {
		fmt.Printf("Password: sudo grep ADMIN_PASSWORD %s\n", envPath)
	}
	return nil
}

func uninstall() error {
	_ = systemctl("disable", "--now", service)
	for _, path := range []string{unitPath, binaryPath, singBoxPath, linkPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = systemctl("daemon-reload")
	fmt.Println("Application removed. Data, settings, backups and the service user were kept.")
	return nil
}
