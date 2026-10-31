// Command sing-box-panel is the panel and its own installer. On a server it
// is linked as `sbp`; without arguments it runs the panel (systemd does this).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"

	"sing-box-panel/internal/config"
	"sing-box-panel/internal/installer"
	"sing-box-panel/internal/panel"
)

// version is set at release build time: -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.SetFlags(0)
		log.Print("Error: ", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "run" {
		c, err := config.Load()
		if err != nil {
			return err
		}
		return panel.Run(c)
	}
	command, args := args[0], args[1:]
	if slices.Contains(installer.Commands, command) {
		return installer.Run(version, command, args)
	}

	switch command {
	case "version", "--version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		fmt.Println("usage: sbp COMMAND\n\n" + installer.Usage)
		return nil

	// Used by the installer and by compose.yaml; not part of the documented interface.
	case "setup":
		flags := flag.NewFlagSet("setup", flag.ContinueOnError)
		database := flags.String("database", "./data/panel.db", "SQLite path")
		address := flags.String("address", "", "public domain or IP of this server")
		panelPort := flags.Int("panel-port", 8443, "panel HTTPS port")
		if err := flags.Parse(args); err != nil {
			return err
		}
		return panel.Setup(*database, *address, *panelPort)
	case "panel-url", "health", "certificate-status", "reset-admin-password":
		c, err := config.Load()
		if err != nil {
			return err
		}
		if command == "reset-admin-password" {
			password, err := panel.ResetAdminPassword(c)
			if err == nil {
				fmt.Println("New admin password:", password)
			}
			return err
		}
		if command == "health" {
			return panel.Health(c)
		}
		if command == "certificate-status" {
			text, err := panel.CertificateStatus(c)
			if err == nil {
				fmt.Println(text)
			}
			return err
		}
		text, err := panel.PanelURL(c)
		if err == nil {
			fmt.Println(text)
		}
		return err
	case "backup-db":
		if len(args) != 2 {
			return errors.New("usage: sing-box-panel backup-db DATABASE OUTPUT")
		}
		return panel.BackupDatabase(args[0], args[1])
	}
	return fmt.Errorf("unknown command %q; see sbp help", command)
}
