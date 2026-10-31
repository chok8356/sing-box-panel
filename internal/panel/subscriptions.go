package panel

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"modernc.org/sqlite"

	"sing-box-panel/internal/singbox"
)

// Subscription is one proxy client.
type Subscription struct {
	ID           int64
	Name         string
	OverrideJSON string // personal configuration merged with the shared config
	UUID         string // VLESS credential
	Token        string // secret part of the public subscription URL
	Enabled      bool
	CreatedAt    int64
	UpdatedAt    int64
}

const subscriptionColumns = "id, name, override_json, enabled, created_at, updated_at, uuid, token"

const sqliteConstraintUnique = 2067

func scanSubscription(row interface{ Scan(...any) error }) (Subscription, error) {
	var s Subscription
	err := row.Scan(&s.ID, &s.Name, &s.OverrideJSON, &s.Enabled, &s.CreatedAt, &s.UpdatedAt, &s.UUID, &s.Token)
	return s, err
}

func (s Subscription) user() singbox.User { return singbox.User{Name: s.Name, UUID: s.UUID} }

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func validateName(name string) error {
	invalid := name == "" || len(name) > 255 || name == "." || name == ".." ||
		!utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl)
	if invalid {
		return errors.New("name must be 1–255 UTF-8 bytes, without control characters, and cannot be . or ..")
	}
	return nil
}

func (a *app) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(),
		"SELECT "+subscriptionColumns+" FROM subscriptions ORDER BY name COLLATE NOCASE, id")
	if err != nil {
		serverError(w)
		return
	}
	defer rows.Close()
	data := page{Title: "Clients", Active: "subscriptions"}
	if a.config().SingBoxBinary != "" {
		server, err := getSetting(r.Context(), a.db, "server_config")
		data.Unconfigured = errors.Is(err, sql.ErrNoRows) || err == nil && (server == "" || server == "{}")
	}
	for rows.Next() {
		s, err := scanSubscription(rows)
		if err != nil {
			serverError(w)
			return
		}
		data.Subscriptions = append(data.Subscriptions, s)
	}
	if rows.Err() != nil {
		serverError(w)
		return
	}
	if r.URL.Query().Get("deleted") == "1" {
		data.Notice = "Client deleted."
	}
	a.render(w, http.StatusOK, "subscriptions", data)
}

func (a *app) newSubscription(w http.ResponseWriter, r *http.Request) {
	a.render(w, http.StatusOK, "subscription", page{
		Title:        "New client",
		Active:       "subscriptions",
		IsNew:        true,
		Subscription: Subscription{OverrideJSON: "{}", Enabled: true},
	})
}

// subscriptionByID loads the {id} from the path or writes 404/500 itself.
func (a *app) subscriptionByID(w http.ResponseWriter, r *http.Request) (Subscription, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return Subscription{}, false
	}
	row := a.db.QueryRowContext(r.Context(), "SELECT "+subscriptionColumns+" FROM subscriptions WHERE id = ?", id)
	s, err := scanSubscription(row)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return s, false
	}
	if err != nil {
		serverError(w)
		return s, false
	}
	return s, true
}

func (a *app) editSubscription(w http.ResponseWriter, r *http.Request) {
	s, ok := a.subscriptionByID(w, r)
	if !ok {
		return
	}
	data := page{Title: s.Name, Active: "subscriptions", Subscription: s}
	if r.URL.Query().Get("saved") == "1" {
		data.Notice = "Client saved."
	}
	a.render(w, http.StatusOK, "subscription", data)
}

// saveSubscription handles the client form: JSON tools (format, validate,
// preview) render the page again, save creates or updates the client.
func (a *app) saveSubscription(w http.ResponseWriter, r *http.Request) {
	var s Subscription
	isNew := r.PathValue("id") == ""
	if !isNew {
		var ok bool
		if s, ok = a.subscriptionByID(w, r); !ok {
			return
		}
	}
	if !parseForm(w, r) {
		return
	}
	if isNew {
		var err error
		if s.UUID, err = newUUID(); err != nil {
			serverError(w)
			return
		}
		s.Token = rand.Text()
	}
	s.Name = strings.TrimSpace(r.PostForm.Get("name"))
	s.OverrideJSON = r.PostForm.Get("override_json")
	s.Enabled = r.PostForm.Get("enabled") == "1"

	data := page{Title: s.Name, Active: "subscriptions", Subscription: s, IsNew: isNew}
	if isNew {
		data.Title = "New client"
	}
	renderError := func(err error) {
		data.Error = err.Error()
		a.render(w, http.StatusUnprocessableEntity, "subscription", data)
	}
	// JSON tools work even before a new subscription has a name.
	if err := singbox.ValidateJSON(s.OverrideJSON); err != nil {
		renderError(err)
		return
	}

	switch r.PostForm.Get("action") {
	case "format":
		data.Subscription.OverrideJSON, _ = singbox.FormatJSON(s.OverrideJSON)
		data.Notice = "JSON formatted. Changes have not been saved."
	case "validate":
		data.Notice = "JSON is valid. Changes have not been saved."
	case "preview":
		base, server, err := storedConfigs(r.Context(), a.db)
		if err != nil {
			serverError(w)
			return
		}
		final, err := a.clientJSON(base, s.OverrideJSON, server, s.user())
		if err != nil {
			renderError(fmt.Errorf("cannot build this client's config: %w", err))
			return
		}
		data.FinalJSON = string(final)
		data.Notice = "Preview uses the current client config and this override. Changes have not been saved."
	case "save", "":
		if err := validateName(s.Name); err != nil {
			renderError(err)
			return
		}
		err := a.mutate(r.Context(), func(tx *sql.Tx) error { return a.storeSubscription(r.Context(), tx, &s, isNew) })
		var sqliteError *sqlite.Error
		switch {
		case errors.Is(err, sql.ErrNoRows):
			http.NotFound(w, r)
		case errors.As(err, &sqliteError) && sqliteError.Code() == sqliteConstraintUnique:
			renderError(errors.New("a subscription with this name already exists"))
		case err != nil:
			renderError(errors.New("could not apply client access; previous database and sing-box configuration are unchanged"))
		default:
			a.redirect(w, r, "/subscriptions/"+strconv.FormatInt(s.ID, 10)+"?saved=1")
		}
		return
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}
	a.render(w, http.StatusOK, "subscription", data)
}

// storeSubscription checks an enabled client's final JSON with sing-box, then
// inserts or updates it. A new client gets its ID assigned.
func (a *app) storeSubscription(ctx context.Context, tx *sql.Tx, s *Subscription, isNew bool) error {
	if s.Enabled && a.core != nil {
		base, server, err := storedConfigs(ctx, tx)
		if err != nil {
			return err
		}
		if err := a.validateClient(ctx, base, s.OverrideJSON, server, s.user()); err != nil {
			return err
		}
	}
	now := time.Now().Unix()
	if !isNew {
		result, err := tx.ExecContext(ctx,
			"UPDATE subscriptions SET name = ?, override_json = ?, enabled = ?, updated_at = ? WHERE id = ?",
			s.Name, s.OverrideJSON, s.Enabled, now, s.ID)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n == 0 {
			return cmp.Or(err, sql.ErrNoRows) // deleted meanwhile
		}
		return nil
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO subscriptions
		(name, override_json, enabled, created_at, updated_at, uuid, token) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		s.Name, s.OverrideJSON, s.Enabled, now, now, s.UUID, s.Token)
	if err != nil {
		return err
	}
	s.ID, err = result.LastInsertId()
	return err
}

func (a *app) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	s, ok := a.subscriptionByID(w, r)
	if !ok {
		return
	}
	if !parseForm(w, r) {
		return
	}
	err := a.mutate(r.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(r.Context(), "DELETE FROM subscriptions WHERE id = ?", s.ID)
		return err
	})
	if err != nil {
		http.Error(w, "Could not revoke proxy access; subscription was not deleted", http.StatusServiceUnavailable)
		return
	}
	a.redirect(w, r, "/subscriptions?deleted=1")
}

// rotateCredential issues a new UUID and a new URL token. Rotating both means
// a leaked subscription URL cannot be used to fetch the new UUID.
func (a *app) rotateCredential(w http.ResponseWriter, r *http.Request) {
	s, ok := a.subscriptionByID(w, r)
	if !ok {
		return
	}
	if !parseForm(w, r) {
		return
	}
	uuid, err := newUUID()
	if err != nil {
		serverError(w)
		return
	}
	err = a.mutate(r.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(r.Context(), "UPDATE subscriptions SET uuid=?, token=?, updated_at=? WHERE id=?",
			uuid, rand.Text(), time.Now().Unix(), s.ID)
		return err
	})
	if err != nil {
		http.Error(w, "Credential rotation failed; previous access is unchanged", http.StatusServiceUnavailable)
		return
	}
	a.redirect(w, r, "/subscriptions/"+r.PathValue("id")+"?saved=1")
}

// previewSubscription shows the saved client JSON to the admin.
func (a *app) previewSubscription(w http.ResponseWriter, r *http.Request) {
	s, ok := a.subscriptionByID(w, r)
	if !ok {
		return
	}
	base, server, err := storedConfigs(r.Context(), a.db)
	if err != nil {
		serverError(w)
		return
	}
	a.writeClientJSON(w, base, s.OverrideJSON, server, s.user())
}

// serveSubscription is the public endpoint clients import. Unknown and
// disabled tokens return the same 404.
func (a *app) serveSubscription(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" {
		http.Error(w, "Unsupported format", http.StatusBadRequest)
		return
	}
	// One query reads all inputs from the same snapshot.
	var base, server, override string
	var user singbox.User
	err := a.db.QueryRowContext(r.Context(), `
		SELECT base.value, COALESCE(server.value, ''), subscriptions.override_json, subscriptions.name, subscriptions.uuid
		FROM subscriptions
		JOIN settings base ON base.key = 'base_config'
		LEFT JOIN settings server ON server.key = 'server_config'
		WHERE subscriptions.token = ? AND subscriptions.enabled = 1`,
		r.PathValue("token")).Scan(&base, &server, &override, &user.Name, &user.UUID)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		serverError(w)
		return
	}
	a.writeClientJSON(w, base, override, server, user)
}

func (a *app) writeClientJSON(w http.ResponseWriter, base, override, server string, user singbox.User) {
	final, err := a.clientJSON(base, override, server, user)
	if err != nil {
		serverError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(final)
}
