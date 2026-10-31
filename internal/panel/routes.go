package panel

import (
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"

	"sing-box-panel/internal/config"
)

const contentSecurityPolicy = "default-src 'none'; style-src 'self'; script-src 'self'; font-src 'self'; " +
	"connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// handler routes by path prefix:
//   - PANEL_PATH/...            admin UI behind session auth and cross-origin protection
//   - SUBSCRIPTION_PATH/{token} public client JSON
//   - /healthz                  loopback only, used by the installer
func (a *app) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { a.configValue.Load().routes.ServeHTTP(w, r) })
}

func (a *app) routes(c config.Config) http.Handler {
	p := config.EscapedPrefix(c.PanelPath)
	admin := http.NewServeMux()
	admin.HandleFunc("GET "+p+"/login", a.loginPage)
	admin.HandleFunc("POST "+p+"/login", a.login)
	admin.HandleFunc("POST "+p+"/logout", a.logout)
	admin.HandleFunc("GET "+p+"/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p+"/subscriptions", http.StatusSeeOther)
	})
	if p != "" {
		admin.HandleFunc("GET "+p, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, p+"/", http.StatusSeeOther)
		})
	}
	admin.HandleFunc("GET "+p+"/config", a.configPage)
	admin.HandleFunc("POST "+p+"/config", a.saveConfig)
	admin.HandleFunc("GET "+p+"/server", a.serverPage)
	admin.HandleFunc("POST "+p+"/server", a.saveServer)
	admin.HandleFunc("POST "+p+"/server/create-reality", a.createReality)
	admin.HandleFunc("GET "+p+"/settings", a.settingsPage)
	admin.HandleFunc("POST "+p+"/settings", a.saveSettings)
	admin.HandleFunc("POST "+p+"/settings/confirm-port", a.confirmPort)
	admin.HandleFunc("POST "+p+"/settings/certificate/retry", a.retryCertificate)
	admin.HandleFunc("POST "+p+"/settings/access", a.saveAccessSettings)
	admin.HandleFunc("POST "+p+"/settings/backup", a.downloadBackup)
	admin.HandleFunc("POST "+p+"/settings/restore", a.restoreBackup)
	admin.HandleFunc("GET "+p+"/logs", a.logsPage)
	admin.HandleFunc("GET "+p+"/subscriptions", a.listSubscriptions)
	admin.HandleFunc("GET "+p+"/subscriptions/new", a.newSubscription)
	admin.HandleFunc("POST "+p+"/subscriptions", a.saveSubscription)
	admin.HandleFunc("GET "+p+"/subscriptions/{id}", a.editSubscription)
	admin.HandleFunc("POST "+p+"/subscriptions/{id}", a.saveSubscription)
	admin.HandleFunc("POST "+p+"/subscriptions/{id}/delete", a.deleteSubscription)
	admin.HandleFunc("POST "+p+"/subscriptions/{id}/regenerate-token", a.rotateCredential)
	admin.HandleFunc("GET "+p+"/subscriptions/{id}/preview", a.previewSubscription)
	admin.HandleFunc("GET "+p+"/static/{file}", a.staticFile)
	protected := http.NewCrossOriginProtection().Handler(a.adminAuth(admin, c.PanelPath))

	subscriptions := http.NewServeMux()
	subscriptions.HandleFunc("GET "+config.EscapedPrefix(c.SubscriptionPath)+"/{token}", a.serveSubscription)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				log.Print("request handler failed")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		header := w.Header()
		header.Set("Cache-Control", "no-store")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Content-Security-Policy", contentSecurityPolicy)

		if r.URL.Path == "/healthz" && fromLoopback(r) {
			a.health(w, r)
			return
		}
		if r.URL.Path == "/healthz/certificate" && fromLoopback(r) && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			a.serveCertificateStatus(w, r)
			return
		}
		panelMatch := hasPrefix(r.URL.Path, c.PanelPath)
		subMatch := hasPrefix(r.URL.Path, c.SubscriptionPath)
		// When both match (nested prefixes), the longer prefix wins.
		switch {
		case panelMatch && (!subMatch || len(c.PanelPath) > len(c.SubscriptionPath)):
			protected.ServeHTTP(w, r)
		case subMatch:
			subscriptions.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func hasPrefix(requestPath, prefix string) bool {
	return prefix == "" || requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/")
}

func fromLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

// health returns 204 when the database answers and sing-box (if managed) runs.
func (a *app) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	body, configErr := effectiveServer(r.Context(), a.db)
	if a.db.PingContext(r.Context()) != nil || configErr != nil || (a.core != nil && len(body) > 0 && !a.core.Running()) {
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var staticTypes = map[string]string{
	"app.css":           "text/css; charset=utf-8",
	"app.js":            "text/javascript; charset=utf-8",
	"favicon.ico":       "image/x-icon",
	"favicon.svg":       "image/svg+xml",
	"Inter-v4.1.woff2":  "font/woff2",
	"Inter-LICENSE.txt": "text/plain; charset=utf-8",
	"Remix-LICENSE.txt": "text/plain; charset=utf-8",
}

func (a *app) staticFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	contentType := staticTypes[name]
	if contentType == "" {
		http.NotFound(w, r)
		return
	}
	body, err := fs.ReadFile(a.assets, "static/"+name)
	if err != nil {
		serverError(w)
		return
	}
	w.Header().Set("Content-Type", contentType)
	if name == "Inter-v4.1.woff2" {
		// The file name is versioned, so the font can be cached for good.
		w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	}
	w.Write(body)
}
