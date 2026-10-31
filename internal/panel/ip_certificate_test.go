package panel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIPCertificateLifecycle(t *testing.T) {
	address := "203.0.113.7"
	dir := t.TempDir()
	c := newCertificates(dir, func() string { return address })
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	challengeHandler := c.httpHandler(http.NotFoundHandler())
	var mu sync.Mutex
	var orders, accounts int
	var authorized, issued, fail bool
	var chain []byte
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.Header().Set("Content-Type", "application/json")
		var jws struct{ Payload string }
		var payload []byte
		if r.Method == "POST" {
			if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
				t.Error(err)
			}
			payload, _ = base64.RawURLEncoding.DecodeString(jws.Payload)
		}
		writeOrder := func() {
			status := "pending"
			if authorized {
				status = "ready"
			}
			if issued {
				status = "valid"
			}
			fmt.Fprintf(w, `{"status":%q,"authorizations":[%q],"finalize":%q,"certificate":%q}`, status,
				server.URL+"/auth", server.URL+"/finalize", server.URL+"/certificate")
		}
		switch r.URL.Path {
		case "/directory":
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q,"meta":{"profiles":{"shortlived":"test"}}}`,
				server.URL+"/nonce", server.URL+"/account", server.URL+"/new-order")
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			accounts++
			w.Header().Set("Location", server.URL+"/account/1")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"status":"valid"}`)
		case "/new-order":
			orders++
			if fail {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:connection","detail":"validation unavailable"}`)
				return
			}
			var order struct {
				Profile     string
				Identifiers []struct{ Type, Value string }
			}
			if err := json.Unmarshal(payload, &order); err != nil || order.Profile != "shortlived" ||
				len(order.Identifiers) != 1 || order.Identifiers[0].Type != "ip" || order.Identifiers[0].Value != address {
				t.Errorf("invalid IP order: %s (%v)", payload, err)
			}
			authorized, issued = false, false
			w.Header().Set("Location", server.URL+"/order")
			w.WriteHeader(http.StatusCreated)
			writeOrder()
		case "/auth":
			status := "pending"
			if authorized {
				status = "valid"
			}
			fmt.Fprintf(w, `{"status":%q,"identifier":{"type":"ip","value":%q},"challenges":[{"type":"http-01","url":%q,"token":"test-token"}]}`,
				status, address, server.URL+"/challenge")
		case "/challenge":
			request := httptest.NewRequest("GET", "http://"+address+"/.well-known/acme-challenge/test-token", nil)
			response := httptest.NewRecorder()
			challengeHandler.ServeHTTP(response, request)
			expected, _ := c.ipClient.HTTP01ChallengeResponse("test-token")
			if response.Code != 200 || response.Body.String() != expected {
				t.Errorf("HTTP-01 challenge: %d %s", response.Code, response.Body.String())
			}
			authorized = true
			fmt.Fprint(w, `{"status":"valid","type":"http-01"}`)
		case "/order":
			writeOrder()
		case "/finalize":
			var request struct{ CSR string }
			json.Unmarshal(payload, &request)
			der, _ := base64.RawURLEncoding.DecodeString(request.CSR)
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 0 ||
				len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(net.ParseIP(address)) {
				t.Errorf("invalid IP CSR: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			cert := &x509.Certificate{
				SerialNumber: big.NewInt(int64(orders + 10)), IPAddresses: csr.IPAddresses,
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(160 * time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			der, err = x509.CreateCertificate(rand.Reader, cert, ca, csr.PublicKey, caKey)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
			issued = true
			writeOrder()
		case "/certificate":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(chain)
		default:
			t.Errorf("unexpected ACME request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c.ipClient.DirectoryURL = server.URL + "/directory"

	if err := c.renewIP(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := c.renewIP(t.Context()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if orders != 1 || accounts != 1 {
		t.Errorf("fresh certificate requested again: orders=%d accounts=%d", orders, accounts)
	}
	mu.Unlock()
	// A restart loads the certificate from disk and serves it without IP SNI.
	restarted := newCertificates(dir, func() string { return address })
	cert, err := restarted.get(&tls.ClientHelloInfo{})
	if err != nil || !covers(cert.Leaf, address) || len(cert.Certificate) != 2 {
		t.Fatalf("cached IP certificate: %v", err)
	}
	if _, err := restarted.publish(cert); err != nil {
		t.Fatal(err)
	}
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	secure.Listener = tls.NewListener(secure.Listener, restarted.tlsConfig())
	secure.Start()
	defer secure.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: address}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(strings.Replace(secure.URL, "http:", "https:", 1))
	if err != nil {
		t.Fatal("IP HTTPS with certificate verification:", err)
	}
	response.Body.Close()

	// A real certificate near expiry must survive a failed renewal.
	nearExpiry := *cert.Leaf
	nearExpiry.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &nearExpiry, ca, cert.PrivateKey.(*ecdsa.PrivateKey).Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	data := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := restarted.acme.Cache.Put(t.Context(), ipCertificateCache, data); err != nil {
		t.Fatal(err)
	}
	renewer := newCertificates(dir, func() string { return address })
	renewer.ipClient.DirectoryURL = server.URL + "/directory"
	mu.Lock()
	fail = true
	mu.Unlock()
	if err := renewer.renewIP(t.Context()); err == nil {
		t.Fatal("failed renewal succeeded")
	}
	retained, err := renewer.get(&tls.ClientHelloInfo{})
	if err != nil || !bytes.Equal(retained.Certificate[0], der) {
		t.Fatalf("failed renewal discarded the valid certificate: %v", err)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	mu.Lock()
	c = renewer
	challengeHandler = c.httpHandler(http.NotFoundHandler())
	mu.Unlock()
	if err := renewer.renewIP(t.Context()); err != nil {
		t.Fatal(err)
	}
	renewed, err := renewer.get(&tls.ClientHelloInfo{})
	if err != nil || !covers(renewed.Leaf, address) || bytes.Equal(renewed.Certificate[0], der) {
		t.Fatalf("certificate not renewed: %v", err)
	}
	unknown := httptest.NewRecorder()
	challengeHandler.ServeHTTP(unknown, httptest.NewRequest("GET", "http://"+address+"/.well-known/acme-challenge/test-token", nil))
	if unknown.Code == 200 {
		t.Fatal("completed challenge is still being served")
	}
	address = "203.0.113.8"
	changed, err := renewer.get(&tls.ClientHelloInfo{})
	if err != nil || !covers(changed.Leaf, address) || bytes.Equal(changed.Certificate[0], renewed.Certificate[0]) {
		t.Fatalf("served the previous address's certificate: %v", err)
	}
	if info, err := os.Stat(renewer.certPath()); err != nil || info.Size() == 0 {
		t.Fatal("published certificate missing:", err)
	}
}

func TestAutomaticCertificateAddresses(t *testing.T) {
	for _, address := range []string{"203.0.113.7", "2001:db8::1", "vpn.example.com"} {
		if !automaticCertificate(address) {
			t.Errorf("automatic certificate disabled for %s", address)
		}
	}
	for _, address := range []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "fd00::1", "0.0.0.0", "fe80::1"} {
		c := newCertificates(t.TempDir(), func() string { return address })
		if automaticCertificate(address) {
			t.Errorf("automatic certificate enabled for private address %s", address)
		}
		c.ipClient.DirectoryURL = "http://127.0.0.1:1"
		if err := c.renewIP(t.Context()); err != nil {
			t.Errorf("attempted issuance for %s: %v", address, err)
		}
	}
}

func TestIPChallengeHostAndIPv6(t *testing.T) {
	c := newCertificates(t.TempDir(), func() string { return "2001:db8::1" })
	c.ipChallengePath, c.ipChallengeResponse, c.ipChallengeHost = "/.well-known/acme-challenge/token", "proof", "2001:db8::1"
	h := c.httpHandler(http.NotFoundHandler())
	for _, host := range []string{"[2001:db8::1]", "[2001:db8::1]:80", "[2001:db8::2]", "example.com"} {
		r := httptest.NewRequest("GET", "http://"+host+c.ipChallengePath, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if strings.Contains(host, "2001:db8::1") != (w.Code == 200 && w.Body.String() == "proof") {
			t.Errorf("challenge Host %s: %d %s", host, w.Code, w.Body.String())
		}
	}
}
