package panel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// certificates serves Let's Encrypt certificates for domains and public IPs.
// If issuance fails, it falls back to self-signed so the admin can fix the settings.
type certificates struct {
	dir               string
	address           func() string
	acme              *autocert.Manager
	ipClient          *acme.Client
	certFile, keyFile string
	source            func() (string, string)

	mu                  sync.Mutex
	selfSigned          *tls.Certificate
	acmePauseTo         time.Time // after a failure, do not hammer Let's Encrypt
	ipCert              *tls.Certificate
	ipChallengePath     string
	ipChallengeResponse string
	ipChallengeHost     string
	lastError           string
	lastAttempt         time.Time
	checking            bool
	manualCert          *tls.Certificate
}

const selfSignedFile = "self-signed.pem"

func newCertificates(dir string, address func() string) *certificates {
	c := &certificates{dir: dir, address: address}
	c.ipClient = &acme.Client{DirectoryURL: acme.LetsEncryptURL, HTTPClient: &http.Client{Timeout: 30 * time.Second}}
	c.acme = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(dir, "acme")),
		HostPolicy: func(_ context.Context, host string) error {
			if current := address(); isDomain(current) && strings.EqualFold(host, current) {
				return nil
			}
			return errors.New("host is not the configured panel domain")
		},
	}
	return c
}

func (c *certificates) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
		GetCertificate: c.get,
	}
}

func (c *certificates) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if certFile, _ := c.paths(); certFile != "" {
		return c.manual()
	}
	address := c.address()
	if ip := net.ParseIP(address); ip != nil && (hello.ServerName == "" || net.ParseIP(hello.ServerName).Equal(ip)) {
		if cert, err := c.cachedIP(context.Background(), address); err == nil {
			return cert, nil
		}
	}
	if isDomain(address) && strings.EqualFold(hello.ServerName, address) {
		// TLS-ALPN-01 validation from Let's Encrypt must be answered by autocert.
		if slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
			return c.acme.GetCertificate(hello)
		}
		c.mu.Lock()
		paused := time.Now().Before(c.acmePauseTo)
		c.mu.Unlock()
		if !paused {
			cert, err := c.acme.GetCertificate(hello)
			if err == nil {
				return cert, nil
			}
			log.Print("Let's Encrypt certificate unavailable, serving self-signed: ", err)
			c.mu.Lock()
			c.lastError = err.Error()
			c.acmePauseTo = time.Now().Add(10 * time.Minute)
			c.mu.Unlock()
		}
	}
	return c.fallback(address)
}

func (c *certificates) paths() (string, string) {
	if c.source != nil {
		return c.source()
	}
	return c.certFile, c.keyFile
}

// A mode switch keeps the previous valid certificate until automatic issuance succeeds.
func (c *certificates) fallback(address string) (*tls.Certificate, error) {
	if data, err := c.acme.Cache.Get(context.Background(), "previous"); err == nil {
		if cert, err := tls.X509KeyPair(data, data); err == nil && covers(cert.Leaf, address) {
			return &cert, nil
		}
	}
	return c.selfSignedFor(address)
}

// manual reloads externally managed files without writing to them.
func (c *certificates) manual() (*tls.Certificate, error) {
	certFile, keyFile := c.paths()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil && !covers(cert.Leaf, c.address()) {
		err = errors.New("certificate is expired, not yet valid, or does not cover the panel address")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.lastError = err.Error()
		if c.manualCert != nil && covers(c.manualCert.Leaf, c.address()) {
			return c.manualCert, nil
		}
		return nil, err
	}
	c.manualCert = &cert
	c.lastError = ""
	return &cert, nil
}

// selfSignedFor returns a certificate valid for address, localhost and
// loopback IPs, reusing the one on disk while it still matches.
func (c *certificates) selfSignedFor(address string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.selfSigned == nil {
		c.selfSigned = c.loadSelfSigned()
	}
	if c.selfSigned != nil && covers(c.selfSigned.Leaf, address) {
		return c.selfSigned, nil
	}
	cert, err := c.createSelfSigned(address)
	if err != nil {
		return nil, err
	}
	c.selfSigned = cert
	return cert, nil
}

func covers(leaf *x509.Certificate, address string) bool {
	if leaf == nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return false
	}
	return leaf.VerifyHostname(address) == nil
}

func (c *certificates) loadSelfSigned() *tls.Certificate {
	data, err := os.ReadFile(filepath.Join(c.dir, selfSignedFile))
	if err != nil {
		return nil
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil
	}
	return &cert
}

func (c *certificates) createSelfSigned(address string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: address},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if ip := net.ParseIP(address); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else if address != "" {
		template.DNSNames = append(template.DNSNames, address)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(c.dir, selfSignedFile), data, 0600); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(data, data)
	return &cert, err
}

// fingerprint is the SHA-256 of the self-signed certificate, for checking
// the browser warning by eye. Empty when no self-signed certificate exists yet.
func (c *certificates) fingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.selfSigned == nil {
		c.selfSigned = c.loadSelfSigned()
	}
	if c.selfSigned == nil {
		return ""
	}
	return Fingerprint(c.selfSigned.Certificate[0])
}

// Fingerprint formats a certificate's SHA-256 as AA:BB:...
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
