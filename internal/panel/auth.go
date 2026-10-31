package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"sing-box-panel/internal/config"
)

const sessionCookie = "__Secure-sbp-session"
const sessionLifetime = 7 * 24 * time.Hour

type loginAttempt struct {
	count int
	until time.Time
}

type loginLimiter struct {
	sync.Mutex
	attempts map[string]loginAttempt
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func credentialDigest(c config.Config) string {
	password := c.AdminPassword
	if c.AdminPasswordHash != "" {
		password = c.AdminPasswordHash
	}
	return digest(c.AdminUsername + "\x00" + password)
}

func validPassword(c config.Config, password string) bool {
	if c.AdminPasswordHash != "" {
		return bcrypt.CompareHashAndPassword([]byte(c.AdminPasswordHash), []byte(password)) == nil
	}
	got, want := sha256.Sum256([]byte(password)), sha256.Sum256([]byte(c.AdminPassword))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func (a *app) authenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || len(cookie.Value) > 128 {
		return false
	}
	var found int
	err = a.db.QueryRowContext(r.Context(), `SELECT 1 FROM admin_sessions
		WHERE token_hash=? AND credentials=? AND expires>?`,
		digest(cookie.Value), credentialDigest(a.config()), time.Now().Unix()).Scan(&found)
	return err == nil
}

func (a *app) adminAuth(next http.Handler, panelPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "HTTPS is required", http.StatusForbidden)
			return
		}
		if r.URL.Path == panelPath+"/login" || strings.HasPrefix(r.URL.Path, panelPath+"/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if !a.authenticated(r) {
			a.redirect(w, r, "/login")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) loginPage(w http.ResponseWriter, r *http.Request) {
	if a.authenticated(r) {
		a.redirect(w, r, "/subscriptions")
		return
	}
	data := page{Title: "Sign in", Active: "login"}
	if r.URL.Query().Get("updated") == "1" {
		data.Notice = "Access settings saved. Sign in again with your current credentials. Update saved links if you changed their paths."
	}
	a.render(w, http.StatusOK, "login", data)
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	data := page{Title: "Sign in", Active: "login"}
	if !a.allowPasswordAttempt(r) {
		w.Header().Set("Retry-After", "900")
		data.Error = "Too many sign-in attempts. Try again in 15 minutes."
		a.render(w, http.StatusTooManyRequests, "login", data)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid sign-in form", http.StatusBadRequest)
		return
	}
	c := a.config()
	user := sha256.Sum256([]byte(r.PostForm.Get("username")))
	wantUser := sha256.Sum256([]byte(c.AdminUsername))
	passwordOK := validPassword(c, r.PostForm.Get("password"))
	if subtle.ConstantTimeCompare(user[:], wantUser[:]) != 1 || !passwordOK {
		data.Error = "Incorrect username or password."
		a.render(w, http.StatusUnauthorized, "login", data)
		return
	}
	now := time.Now()
	token := rand.Text()
	expires := now.Add(sessionLifetime)
	if _, err := a.db.ExecContext(r.Context(), "DELETE FROM admin_sessions WHERE expires<=?", now.Unix()); err != nil {
		serverError(w)
		return
	}
	if _, err := a.db.ExecContext(r.Context(), "INSERT INTO admin_sessions(token_hash,credentials,expires) VALUES(?,?,?)", digest(token), credentialDigest(c), expires.Unix()); err != nil {
		serverError(w)
		return
	}
	a.clearPasswordAttempts(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: config.EscapedPrefix(c.PanelPath) + "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(sessionLifetime.Seconds())})
	a.redirect(w, r, "/subscriptions")
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if _, err := a.db.ExecContext(r.Context(), "DELETE FROM admin_sessions WHERE token_hash=?", digest(cookie.Value)); err != nil {
			serverError(w)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: config.EscapedPrefix(a.config().PanelPath) + "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	a.redirect(w, r, "/login")
}

// attemptKey is the peer address (never a forwarding header). IPv6 is keyed
// by /64, which one host usually owns, so it cannot fill the table alone.
func attemptKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String()
	}
	return host
}

func (a *app) allowPasswordAttempt(r *http.Request) bool {
	host := attemptKey(r)
	a.loginLimits.Lock()
	if a.loginLimits.attempts == nil {
		a.loginLimits.attempts = make(map[string]loginAttempt)
	}
	now := time.Now()
	for ip, attempt := range a.loginLimits.attempts {
		if !now.Before(attempt.until) {
			delete(a.loginLimits.attempts, ip)
		}
	}
	attempt := a.loginLimits.attempts[host]
	blocked := attempt.count >= 10 || attempt.count == 0 && len(a.loginLimits.attempts) >= 1024
	if !blocked {
		if attempt.count == 0 {
			attempt.until = now.Add(15 * time.Minute)
		}
		attempt.count++
		a.loginLimits.attempts[host] = attempt
	}
	a.loginLimits.Unlock()
	return !blocked
}

func (a *app) clearPasswordAttempts(r *http.Request) {
	a.loginLimits.Lock()
	delete(a.loginLimits.attempts, attemptKey(r))
	a.loginLimits.Unlock()
}
