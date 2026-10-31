package panel

import (
	"context"
	"database/sql"
	"net/http"

	"sing-box-panel/internal/singbox"
)

func (a *app) configPage(w http.ResponseWriter, r *http.Request) {
	base, err := a.baseConfig(r.Context())
	if err != nil {
		serverError(w)
		return
	}
	data := page{Title: "Client config", Active: "config", BaseJSON: base}
	if r.URL.Query().Get("saved") == "1" {
		data.Notice = "Client config saved. All clients now use it."
	}
	a.render(w, http.StatusOK, "config", data)
}

func (a *app) saveConfig(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	data := page{Title: "Client config", Active: "config", BaseJSON: r.PostForm.Get("base_json")}
	if r.PostForm.Get("action") == "preset" {
		base, err := singbox.ClientPreset(r.PostForm.Get("preset"), r.PostForm.Get("block_ads") == "1")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data.BaseJSON = base
		data.Notice = "Preset loaded into the editor. Review it and Save to update clients."
		a.render(w, http.StatusOK, "config", data)
		return
	}
	if err := singbox.ValidateJSON(data.BaseJSON); err != nil {
		data.Error = err.Error()
		a.render(w, http.StatusUnprocessableEntity, "config", data)
		return
	}

	switch r.PostForm.Get("action") {
	case "format":
		data.BaseJSON, _ = singbox.FormatJSON(data.BaseJSON)
		data.Notice = "JSON formatted. Changes have not been saved."
	case "validate":
		data.Notice = "JSON is valid. Changes have not been saved."
	case "save", "":
		err := a.mutate(r.Context(), func(tx *sql.Tx) error {
			if err := a.checkBaseForClients(r.Context(), tx, data.BaseJSON); err != nil {
				return err
			}
			_, err := tx.ExecContext(r.Context(), "UPDATE settings SET value = ? WHERE key = 'base_config'", data.BaseJSON)
			return err
		})
		if err != nil {
			data.Error = "Could not apply client config: " + err.Error()
			a.render(w, http.StatusUnprocessableEntity, "config", data)
			return
		}
		a.redirect(w, r, "/config?saved=1")
		return
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}
	a.render(w, http.StatusOK, "config", data)
}

// checkBaseForClients runs sing-box check on the new Base JSON merged with
// each distinct override of enabled clients (and with no override at all).
func (a *app) checkBaseForClients(ctx context.Context, tx *sql.Tx, base string) error {
	if a.core == nil {
		return nil
	}
	_, server, err := storedConfigs(ctx, tx)
	if err != nil {
		return err
	}
	if server == "" || server == "{}" {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT override_json FROM subscriptions WHERE enabled=1")
	if err != nil {
		return err
	}
	overrides := []string{"{}"}
	for rows.Next() {
		var override string
		if err := rows.Scan(&override); err != nil {
			rows.Close()
			return err
		}
		overrides = append(overrides, override)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}

	seen := make(map[string]bool)
	for _, override := range overrides {
		if seen[override] {
			continue
		}
		seen[override] = true
		if err := a.validateClient(ctx, base, override, server, checkUser); err != nil {
			return err
		}
	}
	return nil
}
