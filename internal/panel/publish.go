package panel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"time"

	"sing-box-panel/internal/singbox"
)

// The panel's certificate is also published as plain PEM files, so sing-box
// inbounds that need TLS (Trojan, Hysteria2, ...) can use it with the
// standard certificate_path and key_path fields.
const (
	publishedCert = "cert.pem"
	publishedKey  = "key.pem"
)

func (c *certificates) certPath() string { return filepath.Join(c.dir, publishedCert) }
func (c *certificates) keyPath() string  { return filepath.Join(c.dir, publishedKey) }

// cached returns a valid cached certificate without contacting Let's Encrypt.
func (c *certificates) cached(ctx context.Context) (*tls.Certificate, error) {
	if certFile, _ := c.paths(); certFile != "" {
		return c.manual()
	}
	address := c.address()
	if isDomain(address) {
		if data, err := c.acme.Cache.Get(ctx, address); err == nil {
			if cert, err := tls.X509KeyPair(data, data); err == nil && covers(cert.Leaf, address) {
				return &cert, nil
			}
		}
	} else if cert, err := c.cachedIP(ctx, address); err == nil {
		return cert, nil
	}
	return c.fallback(address)
}

// publish writes cert to cert.pem and key.pem and reports whether they changed.
func (c *certificates) publish(cert *tls.Certificate) (bool, error) {
	var certPEM bytes.Buffer
	for _, der := range cert.Certificate {
		pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	oldCert, certErr := os.ReadFile(c.certPath())
	oldKey, keyErr := os.ReadFile(c.keyPath())
	if certErr == nil && keyErr == nil && bytes.Equal(oldCert, certPEM.Bytes()) && bytes.Equal(oldKey, keyPEM) {
		return false, nil
	}
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return false, err
	}
	// Each file is replaced whole; a reader can only see a mismatched pair
	// between the two renames, and the next refresh repairs a crash there.
	if err := writeAtomic(c.keyPath(), keyPEM); err != nil {
		return false, err
	}
	return true, writeAtomic(c.certPath(), certPEM.Bytes())
}

func writeAtomic(path string, data []byte) error {
	if err := os.WriteFile(path+".new", data, 0600); err != nil {
		return err
	}
	return os.Rename(path+".new", path)
}

// endpoint tells the client generator where clients connect and which
// certificate to pin when the published one is self-signed.
func (a *app) endpoint() singbox.Endpoint {
	ep := singbox.Endpoint{Address: a.site().Address, CertPath: a.certs.certPath()}
	data, err := os.ReadFile(ep.CertPath)
	if err != nil {
		return ep
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ep
	}
	// CheckSignatureFrom would reject the panel's own certificate: it is not a CA.
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
		ep.SelfSigned = true
		ep.CertPEM = string(pem.EncodeToMemory(block))
	}
	return ep
}

// refreshCertificates keeps the published certificate current: it asks for a
// Let's Encrypt certificate every fifteen minutes and whenever the address changes, and
// restarts sing-box when the files change and the server config uses them.
func (a *app) refreshCertificates(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		a.certs.mu.Lock()
		a.certs.checking = true
		a.certs.lastAttempt = time.Now()
		a.certs.lastError = ""
		a.certs.mu.Unlock()
		var refreshErr error
		if certFile, _ := a.certs.paths(); certFile == "" {
			refreshErr = a.certs.renewIP(ctx)
		}
		hello := &tls.ClientHelloInfo{ServerName: a.site().Address}
		if cert, err := a.certs.get(hello); err == nil {
			changed, err := a.certs.publish(cert)
			if err != nil {
				refreshErr = err
				log.Print("cannot publish certificate for sing-box: ", err)
			} else if changed {
				a.restartIfUsesCertificate(ctx)
			}
		} else {
			refreshErr = err
		}
		if refreshErr != nil {
			log.Print("certificate refresh failed: ", refreshErr)
		}
		a.certs.mu.Lock()
		a.certs.checking = false
		if refreshErr != nil {
			a.certs.lastError = refreshErr.Error()
		}
		a.certs.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.certRefresh:
		}
	}
}

func (a *app) restartIfUsesCertificate(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.core == nil || !bytes.Contains(a.core.Current(), []byte(a.certs.certPath())) {
		return
	}
	if err := a.core.Restart(ctx); err != nil {
		a.runtimeError = "sing-box could not restart with the renewed certificate: " + err.Error()
	}
}

// requestCertRefresh wakes refreshCertificates, for example after the address changed.
func (a *app) requestCertRefresh() {
	select {
	case a.certRefresh <- struct{}{}:
	default:
	}
}
