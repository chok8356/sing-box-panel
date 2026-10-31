package panel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const ipCertificateCache = "ip-certificate"

func automaticCertificate(address string) bool {
	ip := net.ParseIP(address)
	return isDomain(address) || ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func (c *certificates) cachedIP(ctx context.Context, address string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ipCert != nil && covers(c.ipCert.Leaf, address) {
		return c.ipCert, nil
	}
	data, err := c.acme.Cache.Get(ctx, ipCertificateCache)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, err
	}
	if !covers(cert.Leaf, address) {
		return nil, errors.New("cached IP certificate does not cover the current address or is expired")
	}
	c.ipCert = &cert
	return c.ipCert, nil
}

// renewIP runs only in the refresh worker; HTTPS handshakes never wait for issuance.
func (c *certificates) renewIP(ctx context.Context) error {
	if certFile, _ := c.paths(); certFile != "" {
		return nil
	}
	address := c.address()
	ip := net.ParseIP(address)
	if ip == nil || !automaticCertificate(address) {
		return nil
	}
	if cert, err := c.cachedIP(ctx, address); err == nil && time.Until(cert.Leaf.NotAfter) > 48*time.Hour {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client := c.ipClient
	if client.Key == nil {
		data, err := c.acme.Cache.Get(ctx, "ip-account")
		if errors.Is(err, autocert.ErrCacheMiss) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			data, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return err
			}
			if err := c.acme.Cache.Put(ctx, "ip-account", data); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		key, err := x509.ParsePKCS8PrivateKey(data)
		if err != nil {
			return err
		}
		var ok bool
		if client.Key, ok = key.(crypto.Signer); !ok {
			return errors.New("invalid ACME account key")
		}
	}
	if client.KID == "" {
		if _, err := client.Register(ctx, &acme.Account{}, autocert.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return err
		}
	}
	order, err := client.AuthorizeOrder(ctx, acme.IPIDs(ip.String()), acme.WithOrderIssuanceProfile("shortlived"))
	if err != nil {
		return err
	}
	for _, authURL := range order.AuthzURLs {
		if err := c.authorizeIP(ctx, authURL, ip); err != nil {
			return err
		}
	}
	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{IPAddresses: []net.IP{ip}}, key)
	if err != nil {
		return err
	}
	chain, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for _, der := range chain {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return err
	}
	if !covers(cert.Leaf, address) {
		return errors.New("issued IP certificate does not cover the current address or is expired")
	}
	if err := c.acme.Cache.Put(ctx, ipCertificateCache, data); err != nil {
		return err
	}
	c.mu.Lock()
	c.ipCert = &cert
	c.mu.Unlock()
	log.Printf("Let's Encrypt IP certificate issued for %s, expires %s", address, cert.Leaf.NotAfter.Format(time.RFC3339))
	return nil
}

func (c *certificates) authorizeIP(ctx context.Context, authURL string, ip net.IP) error {
	auth, err := c.ipClient.GetAuthorization(ctx, authURL)
	if err != nil {
		return err
	}
	if auth.Identifier.Type != "ip" || !net.ParseIP(auth.Identifier.Value).Equal(ip) {
		return errors.New("unexpected ACME authorization identifier")
	}
	if auth.Status == acme.StatusValid {
		return nil
	}
	for _, challenge := range auth.Challenges {
		if challenge.Type != "http-01" {
			continue
		}
		response, err := c.ipClient.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.ipChallengePath = c.ipClient.HTTP01ChallengePath(challenge.Token)
		c.ipChallengeResponse, c.ipChallengeHost = response, ip.String()
		c.mu.Unlock()
		defer func() {
			c.mu.Lock()
			c.ipChallengePath, c.ipChallengeResponse, c.ipChallengeHost = "", "", ""
			c.mu.Unlock()
		}()
		if _, err := c.ipClient.Accept(ctx, challenge); err != nil {
			return err
		}
		_, err = c.ipClient.WaitAuthorization(ctx, authURL)
		return err
	}
	return errors.New("ACME did not offer HTTP-01 validation for the IP address")
}

func (c *certificates) httpHandler(fallback http.Handler) http.Handler {
	domainHandler := c.acme.HTTPHandler(fallback)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		c.mu.Lock()
		path, response, address := c.ipChallengePath, c.ipChallengeResponse, c.ipChallengeHost
		c.mu.Unlock()
		if path != "" && r.URL.Path == path && net.ParseIP(host).Equal(net.ParseIP(address)) && (r.Method == "GET" || r.Method == "HEAD") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, response)
			return
		}
		domainHandler.ServeHTTP(w, r)
	})
}
