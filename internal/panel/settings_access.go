package panel

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"sing-box-panel/internal/config"
)

func (a *app) saveAccessSettings(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if !parseForm(w, r) {
		return
	}
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	c := a.config()
	data := a.currentSettings(r)
	// Sign-in and URL forms post here separately; fields a form omits stay as they are.
	if r.PostForm.Has("admin_username") {
		data.AdminUsername = strings.TrimSpace(r.PostForm.Get("admin_username"))
	}
	if r.PostForm.Has("panel_path") {
		data.PanelPath = r.PostForm.Get("panel_path")
		data.SubscriptionPath = r.PostForm.Get("subscription_path")
	}
	fail := func(status int, message string) {
		a.render(w, status, "settings", page{Title: "Settings", Active: "settings", Settings: data, Error: message})
	}
	if !a.allowPasswordAttempt(r) {
		w.Header().Set("Retry-After", "900")
		fail(http.StatusTooManyRequests, "Too many password attempts. Try again in 15 minutes.")
		return
	}
	if !validPassword(c, r.PostForm.Get("current_password")) {
		fail(http.StatusUnprocessableEntity, "Current password is incorrect.")
		return
	}
	a.clearPasswordAttempts(r)
	newPassword := r.PostForm.Get("new_password")
	if newPassword != r.PostForm.Get("confirm_password") {
		fail(http.StatusUnprocessableEntity, "New passwords do not match.")
		return
	}
	if newPassword != "" {
		if len(newPassword) < 12 || len(newPassword) > 72 {
			fail(http.StatusUnprocessableEntity, "Use a password of 12–72 bytes.")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			serverError(w)
			return
		}
		c.AdminPasswordHash = string(hash)
	}
	oldPanelPath := c.PanelPath
	c.AdminUsername, c.PanelPath, c.SubscriptionPath = data.AdminUsername, data.PanelPath, data.SubscriptionPath
	var err error
	c, err = config.Validate(c)
	if err != nil {
		fail(http.StatusUnprocessableEntity, err.Error())
		return
	}
	if c.SubscriptionPath != a.config().SubscriptionPath && r.PostForm.Get("confirm_subscription_path") != "1" {
		fail(http.StatusUnprocessableEntity, "Confirm that changing the subscription path requires new URLs for every client.")
		return
	}
	if err := a.saveAccessPreferences(r.Context(), c); err != nil {
		serverError(w)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: config.EscapedPrefix(oldPanelPath) + "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	a.redirect(w, r, "/login?updated=1")
}
