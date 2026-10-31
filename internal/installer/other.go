//go:build !linux

package installer

import "errors"

const Usage = "Server commands (install, update, backup, ...) are available on Linux only."

var Commands = []string{"install", "update", "status", "start", "stop", "restart", "logs", "url",
	"backup", "restore", "uninstall", "reset-password"}

// Run is unavailable outside Linux; the panel itself still runs for development.
func Run(version, command string, args []string) error {
	return errors.New("server commands run on Linux with systemd")
}
