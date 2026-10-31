// Package panel serves the admin UI and the public subscription endpoint over
// its own HTTPS, stores clients in SQLite and drives the sing-box process.
package panel

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sing-box-panel/internal/config"
	"sing-box-panel/internal/singbox"
)

//go:embed templates/*.html static/*
var embedded embed.FS

type app struct {
	configValue atomic.Pointer[runtimeSettings]
	settingsMu  sync.Mutex
	httpMu      sync.Mutex
	httpServer  *http.Server
	serving     bool
	db          *sql.DB
	templates   map[string]*template.Template
	siteValue   atomic.Pointer[site] // address and panel port; see site.go
	assets      fs.FS                // embedded, or PANEL_DEV_ASSETS on disk
	certs       *certificates
	certRefresh chan struct{} // see requestCertRefresh
	listeners   *listeners

	// mu serializes changes to the database and to the sing-box process,
	// and guards core and runtimeError. Plain SQLite reads do not take it.
	mu           sync.RWMutex
	core         *singbox.Process // nil when SING_BOX_BINARY is empty
	runtimeError string
	logs         singbox.TailLog
	loginLimits  loginLimiter
}

// page is the data passed to every template.
type page struct {
	PanelPath string
	Title     string
	Active    string // highlighted navigation item
	Managed   bool   // sing-box is run by the panel
	Error     string
	Notice    string

	// Client config page.
	BaseJSON string

	// Clients pages.
	Subscription  Subscription
	Subscriptions []Subscription
	IsNew         bool
	FinalJSON     string

	// Server and logs pages.
	ServerJSON   string
	Running      bool
	RuntimeError string
	Logs         string
	Unconfigured bool

	// Settings page.
	Settings                      settingsView
	RestoredURL, RestoredUsername string
}

var pageNames = []string{"config", "subscriptions", "subscription", "server", "logs", "settings", "login", "restored"}

// newApp loads the templates and the address settings from db.
func newApp(c config.Config, db *sql.DB) (*app, error) {
	var err error
	c, err = loadPreferences(context.Background(), db, c)
	if err != nil {
		return nil, err
	}
	a := &app{db: db, templates: make(map[string]*template.Template), certRefresh: make(chan struct{}, 1)}
	a.configValue.Store(&runtimeSettings{config: c})
	s, err := loadSite(context.Background(), db)
	if err != nil {
		return nil, err
	}
	a.siteValue.Store(&s)
	a.certs = newCertificates(c.CertDir, func() string { return a.site().Address })
	a.certs.source = func() (string, string) { current := a.config(); return current.TLSCertFile, current.TLSKeyFile }
	if c.TLSCertFile != "" {
		if _, err := a.certs.manual(); err != nil {
			return nil, fmt.Errorf("existing TLS certificate: %w", err)
		}
	}
	a.listeners = &listeners{handler: a.handler(), tls: a.certs.tlsConfig(), confirmTimeout: 2 * time.Minute}

	a.assets = embedded
	if c.DevAssets != "" {
		a.assets = os.DirFS(c.DevAssets)
		log.Printf("serving templates and static files from %s (development mode)", c.DevAssets)
	}
	for _, name := range pageNames {
		t, err := a.parseTemplate(name)
		if err != nil {
			return nil, err
		}
		a.templates[name] = t
	}
	a.applyConfig(c)
	return a, nil
}

func (a *app) parseTemplate(name string) (*template.Template, error) {
	return template.New("layout.html").Funcs(template.FuncMap{"subscriptionURL": a.subscriptionURL}).
		ParseFS(a.assets, "templates/layout.html", "templates/"+name+".html")
}

// Run opens the database, starts sing-box (when configured) and serves HTTPS until SIGINT/SIGTERM.
func Run(c config.Config) error {
	db, err := openDB(c.DatabasePath)
	if err != nil {
		return errors.New("cannot open database; check DATABASE_PATH and filesystem permissions")
	}
	defer db.Close()
	a, err := newApp(c, db)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// sing-box may read the published certificate, so it exists before sing-box starts.
	if cert, err := a.certs.cached(ctx); err == nil {
		if _, err := a.certs.publish(cert); err != nil {
			log.Print("cannot publish certificate for sing-box: ", err)
		}
	}
	if c.SingBoxBinary != "" {
		a.startCore(ctx)
		defer func() {
			stop()
			a.mu.Lock()
			defer a.mu.Unlock()
			a.core.Stop()
		}()
		go a.watchCore(ctx)
	}

	port := a.site().PanelPort
	if err := a.listeners.start(port); err != nil {
		return fmt.Errorf("cannot listen on panel port %d: %w", port, err)
	}
	a.httpMu.Lock()
	a.serving = true
	a.httpServer = a.serveHTTP()
	a.httpMu.Unlock()
	go a.refreshCertificates(ctx)
	log.Printf("panel listening on port %d; request logging disabled", port)

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.httpMu.Lock()
	a.serving = false
	if a.httpServer != nil {
		_ = a.httpServer.Shutdown(shutdown)
	}
	a.httpMu.Unlock()
	a.listeners.shutdown(shutdown)
	return nil
}

func (a *app) render(w http.ResponseWriter, status int, name string, data page) {
	data.PanelPath = config.EscapedPrefix(a.config().PanelPath)
	data.Managed = a.config().SingBoxBinary != ""
	t := a.templates[name]
	if a.config().DevAssets != "" { // pick up template edits without a restart
		var err error
		if t, err = a.parseTemplate(name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	var body bytes.Buffer
	if err := t.ExecuteTemplate(&body, "layout.html", data); err != nil {
		serverError(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(body.Bytes())
}

func (a *app) redirect(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, config.EscapedPrefix(a.config().PanelPath)+path, http.StatusSeeOther)
}

// serverError never logs request details: they may contain secrets.
func serverError(w http.ResponseWriter) {
	log.Print("database or response operation failed")
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

// parseForm reads a bounded POST body. Saving can run several sing-box checks
// plus a restart, so it also extends the write deadline past the server default.
func parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 3*singbox.MaxJSONBytes+4096)
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "Form is too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid form", http.StatusBadRequest)
		}
		return false
	}
	return true
}
