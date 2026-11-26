package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"sing-box-panel/internal/singbox"
)

// settings keys: base_config (client Base JSON) and server_config (server JSON).
const schema = `
CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    credentials TEXT NOT NULL,
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    override_json TEXT NOT NULL DEFAULT '{}',
    uuid          TEXT NOT NULL UNIQUE, -- VLESS credential
    token         TEXT NOT NULL UNIQUE, -- secret part of the subscription URL
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    last_seen_at  INTEGER
);
INSERT OR IGNORE INTO settings (key, value) VALUES ('base_config', '{}');
`

func openDB(filename string) (*sql.DB, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	// Create the file ourselves so it gets 0600 permissions.
	file, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}

	query := url.Values{"_pragma": {"busy_timeout(5000)", "journal_mode(WAL)", "foreign_keys(ON)"}}
	db, err := sql.Open("sqlite", sqliteURI(abs, query))
	if err != nil {
		return nil, err
	}
	// WAL lets readers run while a change holds its write transaction through a
	// sing-box restart. DSN pragmas apply to every new connection.
	db.SetMaxOpenConns(4)
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func initSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schema); err != nil {
		return err
	}
	hasColumn, err := hasLastSeenColumn(context.Background(), tx)
	if err != nil {
		return err
	}
	if !hasColumn {
		if _, err := tx.Exec("ALTER TABLE subscriptions ADD COLUMN last_seen_at INTEGER"); err != nil {
			return fmt.Errorf("add client activity column: %w", err)
		}
	}
	return tx.Commit()
}

func hasLastSeenColumn(ctx context.Context, q queryer) (bool, error) {
	var exists bool
	err := q.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pragma_table_info('subscriptions') WHERE name = 'last_seen_at')").Scan(&exists)
	return exists, err
}

// sqliteURI builds a file: URI for an absolute path, including Windows drive paths.
func sqliteURI(abs string, query url.Values) string {
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath, RawQuery: query.Encode()}
	return u.String()
}

func (a *app) baseConfig(ctx context.Context) (string, error) {
	var base string
	err := a.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'base_config'").Scan(&base)
	return base, err
}

// CheckDatabase verifies that filename is an intact panel database (used before restore).
func CheckDatabase(filename string) error {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", sqliteURI(abs, url.Values{"mode": {"ro"}}))
	if err != nil {
		return err
	}
	defer db.Close()

	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return errors.New("cannot read backup database")
	}
	if result != "ok" {
		return errors.New("database integrity check failed")
	}
	if err := db.QueryRow("SELECT value FROM settings WHERE key='base_config'").Scan(&result); err != nil {
		return errors.New("not a sing-box-panel database")
	}
	if err := singbox.ValidateJSON(result); err != nil {
		return err
	}
	fmt.Println("Database integrity: OK")
	return nil
}

// BackupDatabase writes a consistent copy while the service keeps running.
func BackupDatabase(filename, output string) error {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", sqliteURI(abs, url.Values{"_pragma": {"busy_timeout(5000)"}}))
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec("VACUUM INTO ?", output); err != nil {
		return errors.New("database backup failed")
	}
	return os.Chmod(output, 0600)
}
