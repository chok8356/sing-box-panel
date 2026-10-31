package panel

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"sing-box-panel/internal/config"
)

type certificateStatus struct {
	Mode        string
	Address     string
	Ready       bool
	Checking    bool
	Issuer      string
	Expires     string
	Fingerprint string
	LastAttempt string
	Error       string
}

func (c *certificates) status() certificateStatus {
	s := certificateStatus{Mode: "Automatic", Address: c.address()}
	if certFile, _ := c.paths(); certFile != "" {
		s.Mode = "External"
	} else if !automaticCertificate(s.Address) {
		s.Mode = "Self-signed"
	}
	c.mu.Lock()
	s.Checking, s.Error = c.checking, c.lastError
	if !c.lastAttempt.IsZero() {
		s.LastAttempt = c.lastAttempt.UTC().Format(time.RFC3339)
	}
	c.mu.Unlock()
	cert, err := c.cached(context.Background())
	if err != nil {
		s.Error = err.Error()
		return s
	}
	c.mu.Lock()
	s.Error = c.lastError
	c.mu.Unlock()
	leaf := cert.Leaf
	s.Issuer = leaf.Issuer.CommonName
	s.Expires = leaf.NotAfter.UTC().Format(time.RFC3339)
	s.Fingerprint = Fingerprint(cert.Certificate[0])
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
		return s
	}
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		if parsed, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(parsed)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: s.Address, Intermediates: intermediates})
	s.Ready = err == nil
	if err != nil && s.Error == "" {
		s.Error = "Certificate chain is not trusted: " + err.Error()
	}
	return s
}

func (a *app) retryCertificate(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r) {
		return
	}
	a.certs.mu.Lock()
	if !a.certs.lastAttempt.IsZero() && time.Since(a.certs.lastAttempt) < time.Minute {
		a.certs.mu.Unlock()
		a.render(w, http.StatusTooManyRequests, "settings", page{Title: "Settings", Active: "settings", Settings: a.currentSettings(r), Error: "Wait one minute between certificate attempts, then refresh this page."})
		return
	}
	a.certs.acmePauseTo = time.Time{}
	a.certs.mu.Unlock()
	a.updateHTTP()
	a.requestCertRefresh()
	a.redirect(w, r, "/settings?certificate=1")
}

// CertificateStatus asks the live process so installer output includes issuance errors.
func CertificateStatus(c config.Config) (string, error) {
	response, err := loopbackRequest(c, "/healthz/certificate")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("certificate status is unavailable")
	}
	var status certificateStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		return "", err
	}
	data, err := json.Marshal(status)
	return string(data), err
}
