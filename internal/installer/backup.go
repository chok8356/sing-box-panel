//go:build linux

package installer

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sing-box-panel/internal/panel"
)

// A backup is a tar.gz with panel.env, panel.db and VERSION, plus a
// "<sha256>  <name>" file next to it.
var backupEntries = map[string]bool{"panel.env": true, "panel.db": true, "VERSION": true}

// snapshot backs up the database while the panel keeps running: the copy is
// made with VACUUM INTO by the service user, so file ownership stays intact.
func snapshot(version string) (string, error) {
	uid, gid, err := serviceUser()
	if err != nil {
		return "", err
	}
	work := filepath.Join(stateDir, "backup-tmp")
	_ = os.RemoveAll(work)
	if err := os.Mkdir(work, 0700); err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	if err := os.Chown(work, uid, gid); err != nil {
		return "", err
	}
	if _, err := asService("backup-db", dbPath, filepath.Join(work, "panel.db")); err != nil {
		return "", fmt.Errorf("backup failed, nothing changed: %w", err)
	}
	db, err := os.ReadFile(filepath.Join(work, "panel.db"))
	if err != nil {
		return "", err
	}
	env, err := os.ReadFile(envPath)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(backupDir, "backup-"+time.Now().UTC().Format("20060102T150405Z")+"-*.tar.gz")
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(file, digest))
	archive := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"panel.env", env}, {"panel.db", db}, {"VERSION", []byte(version + "\n")}} {
		header := &tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data)), ModTime: time.Now()}
		if err = archive.WriteHeader(header); err == nil {
			_, err = archive.Write(entry.data)
		}
		if err != nil {
			break
		}
	}
	if err == nil {
		err = archive.Close()
	}
	if err == nil {
		err = gz.Close()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		sum := hex.EncodeToString(digest.Sum(nil)) + "  " + filepath.Base(file.Name()) + "\n"
		err = os.WriteFile(file.Name()+".sha256", []byte(sum), 0600)
	}
	if err != nil {
		os.Remove(file.Name())
		return "", err
	}
	fmt.Println("Backup:", file.Name())
	return file.Name(), nil
}

// restore replaces the database and panel.env with a verified backup. The
// current state is backed up first and put back if the restored one does not start.
func restore(version, archivePath string, yes bool) (err error) {
	dir, err := os.MkdirTemp("", "sbp-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if strings.EqualFold(filepath.Ext(archivePath), ".db") {
		// Web backups contain all user settings in SQLite; machine paths stay in panel.env.
		if err := copyFile(archivePath, filepath.Join(dir, "panel.db"), 0600); err != nil {
			return err
		}
		if err := copyFile(envPath, filepath.Join(dir, "panel.env"), 0600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("web backup\n"), 0600); err != nil {
			return err
		}
	} else {
		if err := unpackBackup(archivePath, dir); err != nil {
			return err
		}
	}
	env, err := readEnv(filepath.Join(dir, "panel.env"))
	if err != nil || envValue(env, "DATABASE_PATH") != dbPath {
		return errors.New("backup has an unsupported DATABASE_PATH")
	}
	if err := panel.CheckDatabase(filepath.Join(dir, "panel.db")); err != nil {
		return fmt.Errorf("backup database check failed: %w", err)
	}
	if !yes && !confirm("This replaces the database and settings. Current state will be backed up. Type RESTORE: ", "RESTORE") {
		return errors.New("restore cancelled")
	}

	wasActive := serviceActive()
	if err := systemctl("stop", service); err != nil {
		return err
	}
	defer func() {
		if err != nil && wasActive {
			_ = systemctl("start", service)
			waitReady()
		}
		if !wasActive {
			_ = systemctl("stop", service)
		}
	}()
	if _, err := snapshot(version); err != nil {
		return err
	}
	current := filepath.Join(dir, "current")
	if err := os.Mkdir(current, 0700); err != nil {
		return err
	}
	if err := swapState(dbPath, envPath, current); err != nil {
		return err
	}
	// From here the live files may change, so every failure puts current back.
	if err := swapState(filepath.Join(dir, "panel.db"), filepath.Join(dir, "panel.env"), ""); err == nil {
		if err := systemctl("start", service); err == nil && waitReady() {
			fmt.Printf("Database and settings restored (backup version %s). Binary unchanged.\n",
				strings.TrimSpace(readText(filepath.Join(dir, "VERSION"))))
			return nil
		}
		_ = systemctl("stop", service)
	}
	if err := swapState(filepath.Join(current, "panel.db"), filepath.Join(current, "panel.env"), ""); err != nil {
		return fmt.Errorf("cannot put back the previous state (a backup was saved in %s): %w", backupDir, err)
	}
	return errors.New("restored settings failed to apply or start; the previous database and settings were put back")
}

// swapState installs db and env as the live state. With keep set, it first
// copies the live files there instead.
func swapState(db, env, keep string) error {
	if keep != "" {
		if err := copyFile(dbPath, filepath.Join(keep, "panel.db"), 0600); err != nil {
			return err
		}
		return copyFile(envPath, filepath.Join(keep, "panel.env"), 0600)
	}
	uid, gid, err := serviceUser()
	if err != nil {
		return err
	}
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")
	if err := copyFile(db, dbPath, 0600); err != nil {
		return err
	}
	if err := os.Chown(dbPath, uid, gid); err != nil {
		return err
	}
	return copyFile(env, envPath, 0600)
}

// unpackBackup checks the checksum and the entry list before extracting.
func unpackBackup(archivePath, dir string) error {
	data, err := os.ReadFile(archivePath)
	if err != nil {
		return err
	}
	fields := strings.Fields(readText(archivePath + ".sha256"))
	if len(fields) == 0 {
		return errors.New("provide the backup and its .sha256 file next to it")
	}
	if digest := sha256.Sum256(data); hex.EncodeToString(digest[:]) != fields[0] {
		return errors.New("backup checksum mismatch")
	}
	gz, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return errors.New("backup is not a tar.gz archive")
	}
	archive := tar.NewReader(gz)
	found := map[string]bool{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("backup archive is damaged")
		}
		if !backupEntries[header.Name] || header.Typeflag != tar.TypeReg || found[header.Name] {
			return errors.New("backup must contain only panel.env, panel.db and VERSION as regular files")
		}
		content, err := io.ReadAll(io.LimitReader(archive, 1<<30))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, header.Name), content, 0600); err != nil {
			return err
		}
		found[header.Name] = true
	}
	if len(found) != len(backupEntries) {
		return errors.New("backup is incomplete")
	}
	return nil
}

func readText(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

func confirm(question, answer string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer tty.Close()
	fmt.Fprint(tty, question)
	line, _ := bufio.NewReader(tty).ReadString('\n')
	return strings.TrimSpace(line) == answer
}
