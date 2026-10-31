package panel

import (
	"bytes"
	"crypto/tls"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestExternalCertificateReloadAndStatus(t *testing.T) {
	address := "203.0.113.7"
	source := newCertificates(t.TempDir(), func() string { return address })
	first, err := source.createSelfSigned(address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.publish(first); err != nil {
		t.Fatal(err)
	}
	certBytes, _ := os.ReadFile(source.certPath())
	keyBytes, _ := os.ReadFile(source.keyPath())
	c := newCertificates(t.TempDir(), func() string { return address })
	c.certFile, c.keyFile = source.certPath(), source.keyPath()
	c.ipClient.DirectoryURL = "http://127.0.0.1:1"
	loaded, err := c.get(&tls.ClientHelloInfo{})
	if err != nil || !bytes.Equal(loaded.Certificate[0], first.Certificate[0]) {
		t.Fatal("external cert not loaded", err)
	}
	status := c.status()
	if status.Mode != "External" || status.Ready || status.Expires == "" {
		t.Fatal("self-signed external certificate incorrectly trusted:", status)
	}
	if err := c.renewIP(t.Context()); err != nil {
		t.Fatal(err)
	}
	afterCert, _ := os.ReadFile(source.certPath())
	afterKey, _ := os.ReadFile(source.keyPath())
	if !bytes.Equal(certBytes, afterCert) || !bytes.Equal(keyBytes, afterKey) {
		t.Fatal("external files modified")
	}
	// An incomplete external renewal keeps serving the previous valid pair.
	if err := os.WriteFile(source.keyPath(), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err = c.manual()
	if err != nil || !bytes.Equal(loaded.Certificate[0], first.Certificate[0]) {
		t.Fatal("last valid certificate was lost", err)
	}
	if c.lastError == "" {
		t.Fatal("external reload failure was hidden")
	}
	second, err := source.createSelfSigned(address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.publish(second); err != nil {
		t.Fatal(err)
	}
	loaded, err = c.manual()
	if err != nil || !bytes.Equal(loaded.Certificate[0], second.Certificate[0]) {
		t.Fatal("renewed files not reloaded", err)
	}
	wrong := newCertificates(t.TempDir(), func() string { return "other.example" })
	wrong.certFile, wrong.keyFile = source.certPath(), source.keyPath()
	if _, err := wrong.manual(); err == nil {
		t.Fatal("certificate for wrong address accepted")
	}
	if c.status().Mode != "External" {
		t.Fatal("lost external mode")
	}
}

func TestCertificateStatusAndRetry(t *testing.T) {
	cfg := testConfig()
	a, _ := testApp(t, cfg)
	h := a.handler()
	w := request(t, h, "GET", testOrigin+"/healthz/certificate", nil, false)
	wantStatus(t, w, 404)
	r := httptest.NewRequest("GET", testOrigin+"/healthz/certificate", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	wantStatus(t, w, 200)
	endpoint := testOrigin + cfg.PanelPath + "/settings/certificate/retry"
	wantStatus(t, request(t, h, "POST", endpoint, nil, true), 303)
	if len(a.certRefresh) != 1 {
		t.Fatal("retry did not wake refresh worker")
	}
	a.certs.lastAttempt = time.Now()
	wantStatus(t, request(t, h, "POST", endpoint, nil, true), 429)
}

func TestEndpointPinsOwnSelfSignedCertificate(t *testing.T) {
	a, _ := testApp(t, testConfig())
	cert, err := a.certs.selfSignedFor(a.site().Address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.certs.publish(cert); err != nil {
		t.Fatal(err)
	}
	if ep := a.endpoint(); !ep.SelfSigned || ep.CertPEM == "" {
		t.Fatalf("own self-signed certificate is not pinned: %+v", ep)
	}
}
