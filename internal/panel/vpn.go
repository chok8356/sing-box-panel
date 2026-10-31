package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"sing-box-panel/internal/singbox"
)

// startCore launches sing-box with the stored config. A failure is shown in
// the admin UI instead of stopping the panel, so the admin can fix the JSON.
func (a *app) startCore(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.core = &singbox.Process{Binary: a.config().SingBoxBinary, Dir: a.config().RuntimeDir, Logs: &a.logs}
	body, err := effectiveServer(ctx, a.db)
	if err == nil && len(body) == 0 {
		return
	}
	if err == nil {
		err = a.core.Apply(ctx, body)
	}
	if err != nil {
		a.runtimeError = "sing-box is not running. Correct the server JSON and apply it."
		_, _ = a.logs.Write([]byte("[panel] sing-box startup failed: " + err.Error() + "\n"))
		log.Print("sing-box startup failed; admin recovery is available")
	}
}

// watchCore restarts sing-box if it exits. After a failed restart it backs off
// (5s doubling to 5m) so a broken config does not hold app.mu continuously.
func (a *app) watchCore(ctx context.Context) {
	const minRetry, maxRetry = 5 * time.Second, 5 * time.Minute
	ticker := time.NewTicker(minRetry)
	defer ticker.Stop()
	var retryAt time.Time
	backoff := minRetry
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		a.mu.Lock()
		if ctx.Err() != nil {
			a.mu.Unlock()
			return
		}
		if a.core.Running() {
			retryAt, backoff = time.Time{}, minRetry
		} else if !time.Now().Before(retryAt) {
			body, err := effectiveServer(ctx, a.db)
			if err == nil && len(body) == 0 {
				a.mu.Unlock()
				continue
			}
			if err == nil {
				err = a.core.Apply(ctx, body)
			}
			if err != nil {
				a.runtimeError = "sing-box could not start. Correct the server JSON and apply it."
				retryAt = time.Now().Add(backoff)
				backoff = min(backoff*2, maxRetry)
			} else {
				a.runtimeError = ""
			}
		}
		a.mu.Unlock()
	}
}

// mutate runs change in a transaction, applies the resulting server config to
// sing-box and commits only if sing-box accepted it. If the commit itself
// fails, sing-box is returned to its previous config.
func (a *app) mutate(ctx context.Context, change func(*sql.Tx) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := change(tx); err != nil {
		return err
	}

	var previous []byte
	if a.core != nil {
		previous = a.core.Current()
		body, err := effectiveServer(ctx, tx)
		if err != nil {
			return err
		}
		if len(body) == 0 {
			a.core.Stop()
		} else if err := a.core.Apply(ctx, body); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		if a.core != nil {
			if len(previous) == 0 {
				// Nothing ran before this change; do not keep a config the database never stored.
				a.core.Stop()
			} else if rollback := a.core.Apply(context.Background(), previous); rollback != nil {
				return errors.New("database commit and runtime rollback failed")
			}
		}
		return err
	}
	if a.core != nil && a.core.Running() {
		a.runtimeError = ""
	}
	if a.core != nil && len(a.core.Current()) == 0 {
		a.runtimeError = ""
	}
	return nil
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// effectiveServer reads the stored server JSON and enabled clients (from the
// database or an open transaction) and builds the config sing-box runs.
func effectiveServer(ctx context.Context, q queryer) ([]byte, error) {
	var raw string
	err := q.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='server_config'").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (raw == "" || raw == "{}") {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("server config is missing; run setup first")
	}
	rows, err := q.QueryContext(ctx, "SELECT name, uuid FROM subscriptions WHERE enabled=1 ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []singbox.User
	for rows.Next() {
		var user singbox.User
		if err := rows.Scan(&user.Name, &user.UUID); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return singbox.ServerConfig(raw, users)
}

// checkUser stands in for real clients when a config is validated.
var checkUser = singbox.User{Name: "check", UUID: "00000000-0000-4000-8000-000000000000"}

// clientJSON builds a client's final config from the stored configs.
func (a *app) clientJSON(base, override, server string, user singbox.User) ([]byte, error) {
	return singbox.ClientConfig(base, override, server, user, a.endpoint())
}

// validateClient runs sing-box check on the client config these settings produce.
func (a *app) validateClient(ctx context.Context, base, override, server string, user singbox.User) error {
	if a.core == nil {
		return nil
	}
	if server == "" || server == "{}" {
		return errors.New("configure the server before creating clients or applying client settings")
	}
	body, err := a.clientJSON(base, override, server, user)
	if err != nil {
		return err
	}
	if err := a.core.Check(ctx, body); err != nil {
		return fmt.Errorf("client config: %w", err)
	}
	return nil
}

// storedConfigs reads the client Base and the server JSON in one transaction.
func storedConfigs(ctx context.Context, q queryer) (base, server string, err error) {
	if base, err = getSetting(ctx, q, "base_config"); err != nil {
		return "", "", err
	}
	server, err = getSetting(ctx, q, "server_config")
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return base, server, err
}

func (a *app) serverPage(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	data := page{Title: "Server config", Active: "server", RuntimeError: a.runtimeError}
	data.Running = a.core != nil && a.core.Running()
	err := a.db.QueryRowContext(r.Context(), "SELECT value FROM settings WHERE key='server_config'").
		Scan(&data.ServerJSON)
	if errors.Is(err, sql.ErrNoRows) {
		data.ServerJSON = "{}"
	} else if err != nil {
		serverError(w)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		data.Notice = "Server config applied. Existing client connections were restarted."
	}
	data.Unconfigured = data.ServerJSON == "{}" || data.ServerJSON == ""
	a.render(w, http.StatusOK, "server", data)
}

func (a *app) createReality(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	port, _ := strconv.Atoi(r.PostForm.Get("vpn_port"))
	err := ValidateSite(a.site().Address, a.site().PanelPort, port)
	var server, base string
	if err == nil {
		server, base, err = singbox.InitialConfigs(r.PostForm.Get("handshake"), port)
	}
	if err == nil {
		err = a.mutate(r.Context(), func(tx *sql.Tx) error {
			_, current, err := storedConfigs(r.Context(), tx)
			if err != nil {
				return err
			}
			if current != "" && current != "{}" {
				return errors.New("server is already configured; edit its JSON instead")
			}
			if err := setSetting(r.Context(), tx, "server_config", server); err != nil {
				return err
			}
			currentBase, err := getSetting(r.Context(), tx, "base_config")
			if err != nil {
				return err
			}
			if currentBase == "{}" {
				if err := setSetting(r.Context(), tx, "base_config", base); err != nil {
					return err
				}
				currentBase = base
			}
			return a.checkBaseForClients(r.Context(), tx, currentBase)
		})
	}
	if err != nil {
		a.render(w, http.StatusUnprocessableEntity, "server", page{Title: "Server config", Active: "server", ServerJSON: "{}", Unconfigured: true, Error: err.Error()})
		return
	}
	a.redirect(w, r, "/server?saved=1")
}

func (a *app) saveServer(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	data := page{Title: "Server config", Active: "server", ServerJSON: r.PostForm.Get("server_json")}
	render := func(status int) {
		a.mu.RLock()
		data.Running = a.core != nil && a.core.Running()
		data.RuntimeError = a.runtimeError
		a.mu.RUnlock()
		a.render(w, status, "server", data)
	}
	renderError := func(err error) {
		data.Error = err.Error()
		render(http.StatusUnprocessableEntity)
	}
	if err := singbox.ValidateJSON(data.ServerJSON); err != nil {
		renderError(err)
		return
	}

	switch r.PostForm.Get("action") {
	case "format":
		data.ServerJSON, _ = singbox.FormatJSON(data.ServerJSON)
		data.Notice = "JSON formatted. Changes have not been applied."
	case "validate":
		if a.core == nil {
			renderError(errors.New("set SING_BOX_BINARY to validate with sing-box"))
			return
		}
		if err := a.core.Check(r.Context(), []byte(data.ServerJSON)); err != nil {
			renderError(err)
			return
		}
		data.Notice = "sing-box accepted this configuration. Changes have not been applied."
	case "save":
		err := a.mutate(r.Context(), func(tx *sql.Tx) error {
			if err := setSetting(r.Context(), tx, "server_config", data.ServerJSON); err != nil {
				return err
			}
			// Clients are generated from this config, so check what they would get too.
			base, _, err := storedConfigs(r.Context(), tx)
			if err != nil {
				return err
			}
			if data.ServerJSON == "{}" {
				return nil
			}
			return a.validateClient(r.Context(), base, "{}", data.ServerJSON, checkUser)
		})
		if err != nil {
			renderError(err)
			return
		}
		a.redirect(w, r, "/server?saved=1")
		return
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}
	render(http.StatusOK)
}
