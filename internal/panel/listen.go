package panel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// listeners runs the HTTPS server of the panel and handles a port change
// safely: the new port opens next to the old one, and only a request that
// arrives on the new port confirms it. Without confirmation the new port
// closes again after confirmTimeout, so a port blocked by a firewall
// cannot lock the admin out.
type listeners struct {
	handler        http.Handler
	tls            *tls.Config
	confirmTimeout time.Duration

	mu          sync.Mutex
	active      *http.Server
	activePort  int
	pending     *http.Server
	pendingPort int
	timer       *time.Timer
}

func newServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second, // POST handlers extend this, see parseForm
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0), // TLS scanners would flood the log
	}
}

// open starts an HTTPS server on port; binding errors are returned at once.
func (l *listeners) open(port int) (*http.Server, error) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	server := newServer(l.handler)
	go func() { _ = server.Serve(tls.NewListener(ln, l.tls)) }()
	return server, nil
}

func (l *listeners) start(port int) error {
	server, err := l.open(port)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active, l.activePort = server, port
	return nil
}

// A restore explicitly returns to the saved port; bind it before changing data.
func (l *listeners) restorePort(port int, apply func() error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending != nil {
		return errors.New("confirm or cancel the pending port change before restoring")
	}
	if l.active == nil || port == l.activePort {
		return apply()
	}
	server, err := l.open(port)
	if err != nil {
		return err
	}
	if err := apply(); err != nil {
		server.Close()
		return err
	}
	old := l.active
	l.active, l.activePort = server, port
	go func() {
		time.Sleep(time.Second) // allow the result page and its assets to finish loading
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = old.Shutdown(ctx)
	}()
	return nil
}

// propose opens port next to the active one until it is confirmed.
func (l *listeners) propose(port int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if port == l.activePort {
		return nil
	}
	if l.pending != nil {
		l.timer.Stop()
		l.pending.Close()
		l.pending = nil
	}
	server, err := l.open(port)
	if err != nil {
		return err
	}
	l.pending, l.pendingPort = server, port
	l.timer = time.AfterFunc(l.confirmTimeout, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.pending == server {
			server.Close()
			l.pending, l.pendingPort = nil, 0
			log.Printf("panel port %d was not confirmed; staying on %d", port, l.activePort)
		}
	})
	return nil
}

// confirm makes the pending port active when r arrived on it, and closes the old port shortly after.
func (l *listeners) confirm(r *http.Request) (int, error) {
	port := localPort(r)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == nil || port != l.pendingPort {
		return 0, errors.New("open this page on the new port to confirm it")
	}
	l.timer.Stop()
	old := l.active
	l.active, l.activePort = l.pending, l.pendingPort
	l.pending, l.pendingPort = nil, 0
	go func() {
		time.Sleep(time.Second) // let the old port finish the current responses
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = old.Shutdown(ctx)
	}()
	return port, nil
}

// pendingFor reports the port awaiting confirmation and whether r came through it.
func (l *listeners) pendingFor(r *http.Request) (port int, onIt bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pendingPort, l.pending != nil && localPort(r) == l.pendingPort
}

func (l *listeners) shutdown(ctx context.Context) {
	l.mu.Lock()
	servers := []*http.Server{l.active, l.pending}
	l.mu.Unlock()
	for _, server := range servers {
		if server != nil {
			_ = server.Shutdown(ctx)
		}
	}
}

func localPort(r *http.Request) int {
	addr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if addr == nil {
		return 0
	}
	_, port, _ := net.SplitHostPort(addr.String())
	n, _ := strconv.Atoi(port)
	return n
}

// serveHTTP answers port 80: Let's Encrypt HTTP-01 validation and a
// redirect to HTTPS. It is optional; failing to bind is only logged.
func (a *app) serveHTTP() *http.Server {
	if a.config().TLSCertFile != "" {
		return nil
	}
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Print("port 80 is unavailable; IP certificates require it, domains can also validate on port 443")
		return nil
	}
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The configured address, never the Host header: no open redirect.
		target := a.site().origin() + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
	server := newServer(a.certs.httpHandler(redirect))
	go func() { _ = server.Serve(ln) }()
	return server
}

// updateHTTP changes only the optional validation listener; HTTPS and sing-box stay up.
func (a *app) updateHTTP() {
	a.httpMu.Lock()
	defer a.httpMu.Unlock()
	if !a.serving {
		return
	}
	if a.config().TLSCertFile != "" {
		if a.httpServer != nil {
			_ = a.httpServer.Close()
			a.httpServer = nil
		}
	} else if a.httpServer == nil {
		a.httpServer = a.serveHTTP()
	}
}
