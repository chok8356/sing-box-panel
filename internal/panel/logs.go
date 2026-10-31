package panel

import (
	"net/http"
	"strings"

	"sing-box-panel/internal/config"
)

// redactedLogs hides the admin password and secret URL prefixes.
func (a *app) redactedLogs() string {
	text := a.logs.String()
	secrets := []string{
		a.config().AdminPassword,
		a.config().SubscriptionPath,
		config.EscapedPrefix(a.config().SubscriptionPath),
		a.config().PanelPath,
		config.EscapedPrefix(a.config().PanelPath),
	}
	for _, secret := range secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	return text
}

// logsPage renders the log viewer; ?format=text is polled by the Live mode.
func (a *app) logsPage(w http.ResponseWriter, r *http.Request) {
	text := a.redactedLogs()
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(text))
		return
	}
	a.render(w, http.StatusOK, "logs", page{Title: "Server logs", Active: "logs", Logs: text})
}
