package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// selfSigned writes a certificate for 127.0.0.1 and returns its paths and PEM.
func selfSigned(t *testing.T) (certPath, keyPath, certPEM string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	os.WriteFile(certPath, []byte(certPEM), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	return certPath, keyPath, certPEM
}

// everyProtocol is a server config the way an admin or an AI would write it:
// plain sing-box JSON with example users that the panel replaces.
func everyProtocol(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	server, _, err := InitialConfigs("example.com", 20001)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	json.Unmarshal([]byte(server), &root)
	tls := map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}
	example := []any{map[string]any{"name": "example", "uuid": "00000000-0000-4000-8000-000000000000"}}
	add := func(inbound map[string]any) {
		inbound["listen"] = "127.0.0.1"
		root["inbounds"] = append(root["inbounds"].([]any), inbound)
	}
	add(map[string]any{"type": "vless", "tag": "vless-ws", "listen_port": 20002, "users": example, "tls": tls,
		"transport": map[string]any{"type": "ws", "path": "/ws"}})
	add(map[string]any{"type": "vmess", "tag": "vmess", "listen_port": 20003,
		"transport": map[string]any{"type": "ws", "path": "/vmess"}})
	add(map[string]any{"type": "trojan", "tag": "trojan", "listen_port": 20004, "tls": tls})
	add(map[string]any{"type": "hysteria2", "tag": "hy2", "listen_port": 20005, "tls": tls,
		"obfs": map[string]any{"type": "salamander", "password": "obfs-secret"}})
	tuicTLS := map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath, "alpn": []any{"h3"}}
	add(map[string]any{"type": "tuic", "tag": "tuic", "listen_port": 20006, "tls": tuicTLS, "congestion_control": "bbr"})
	add(map[string]any{"type": "naive", "tag": "naive", "listen_port": 20007, "tls": tls})
	add(map[string]any{"type": "shadowsocks", "tag": "ss", "listen_port": 20008,
		"method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA=="})
	add(map[string]any{"type": "anytls", "tag": "anytls", "listen_port": 20009, "tls": tls})
	add(map[string]any{"type": "mixed", "tag": "local-proxy", "listen_port": 20010}) // no users: untouched
	data, _ := json.Marshal(root)
	return string(data)
}

func TestEveryProtocol(t *testing.T) {
	certPath, keyPath, certPEM := selfSigned(t)
	raw := everyProtocol(t, certPath, keyPath)
	users := []User{{Name: "alice", UUID: "11111111-1111-4111-8111-111111111111"},
		{Name: "bob", UUID: "22222222-2222-4222-8222-222222222222"}}

	server, err := ServerConfig(raw, users)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(server), "00000000-0000-4000-8000-000000000000") {
		t.Fatal("example user from the admin's JSON was kept")
	}
	var root struct{ Inbounds []map[string]any }
	json.Unmarshal(server, &root)
	for _, inbound := range root.Inbounds {
		users, has := inbound["users"].([]any)
		if inbound["type"] == "mixed" {
			if has {
				t.Fatal("inbound without users got users")
			}
			continue
		}
		if len(users) != 2 {
			t.Fatalf("%s: %d users", inbound["tag"], len(users))
		}
	}

	ep := Endpoint{Address: "127.0.0.1", CertPath: certPath, CertPEM: certPEM, SelfSigned: true}
	client, err := ClientConfig(DefaultClientBase, "{}", raw, users[0], ep)
	if err != nil {
		t.Fatal(err)
	}
	var config struct{ Outbounds []map[string]any }
	json.Unmarshal(client, &config)
	proxy := findTag(toAny(config.Outbounds), "proxy")
	if proxy == nil || len(proxy["outbounds"].([]any)) != 9 {
		t.Fatalf("selector over 9 protocols expected: %s", client)
	}
	reality := findTag(toAny(config.Outbounds), "proxy-reality")
	public := reality["tls"].(map[string]any)["reality"].(map[string]any)["public_key"].(string)
	var serverRoot struct {
		Inbounds []struct {
			TLS struct {
				Reality struct {
					PrivateKey string `json:"private_key"`
				}
			}
		}
	}
	json.Unmarshal([]byte(raw), &serverRoot)
	if want, _ := realityPublicKey(serverRoot.Inbounds[0].TLS.Reality.PrivateKey); public != want {
		t.Fatal("client Reality public key does not match the server private key")
	}
	if !strings.Contains(string(client), "BEGIN CERTIFICATE") {
		t.Fatal("self-signed certificate is not pinned in the client")
	}

	binary := os.Getenv("SING_BOX_TEST_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BINARY to check both configs with sing-box")
	}
	check := Process{Binary: binary, Dir: t.TempDir()}
	if err := check.Check(t.Context(), server); err != nil {
		t.Fatal("server:", err)
	}
	if err := check.Check(t.Context(), client); err != nil {
		t.Fatal("client:", err)
	}
}

func toAny(list []map[string]any) []any {
	result := make([]any, len(list))
	for i, item := range list {
		result[i] = item
	}
	return result
}

func TestListenersForFirewall(t *testing.T) {
	certPath, keyPath, _ := selfSigned(t)
	got := fmt.Sprint(Listeners(everyProtocol(t, certPath, keyPath)))
	for _, want := range []string{"{reality vless :: 20001 tcp}", "{hy2 hysteria2 127.0.0.1 20005 udp}",
		"{ss shadowsocks 127.0.0.1 20008 tcp+udp}"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
}

// TestEveryProtocolCarriesTraffic runs the server and, for each protocol, a
// client built by ClientConfig, then fetches a page through it.
func TestEveryProtocolCarriesTraffic(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BINARY to run real traffic through every protocol")
	}
	certPath, keyPath, certPEM := selfSigned(t)
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("VPN works"))
	}))
	defer destination.Close()
	// Reality borrows the TLS handshake of a real site; a local one keeps the test offline.
	handshake := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer handshake.Close()
	_, handshakePort, _ := net.SplitHostPort(handshake.Listener.Addr().String())

	raw := everyProtocol(t, certPath, keyPath)
	var root map[string]any
	json.Unmarshal([]byte(raw), &root)
	reality := root["inbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["reality"].(map[string]any)
	port, _ := strconv.Atoi(handshakePort)
	reality["handshake"] = map[string]any{"server": "127.0.0.1", "server_port": port}
	data, _ := json.Marshal(root)
	raw = string(data)

	user := User{Name: "alice", UUID: "11111111-1111-4111-8111-111111111111"}
	body, err := ServerConfig(raw, []User{user})
	if err != nil {
		t.Fatal(err)
	}
	server := &Process{Binary: binary, Dir: t.TempDir()}
	if err := server.Apply(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	time.Sleep(500 * time.Millisecond) // UDP inbounds have no port to probe

	ep := Endpoint{Address: "127.0.0.1", CertPath: certPath, CertPEM: certPEM, SelfSigned: true}
	outbounds, err := ClientOutbounds(raw, user, ep)
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range outbounds {
		outbound := item.(map[string]any)
		t.Run(outbound["tag"].(string), func(t *testing.T) {
			proxyPort := 21000 + i
			client := map[string]any{
				"log":       map[string]any{"level": "error"},
				"inbounds":  []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": proxyPort}},
				"outbounds": []any{outbound},
				"route":     map[string]any{"final": outbound["tag"]},
			}
			config, _ := json.Marshal(client)
			file := filepath.Join(t.TempDir(), "client.json")
			os.WriteFile(file, config, 0600)
			cmd := exec.Command(binary, "run", "-c", file)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()

			proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
			httpClient := &http.Client{Timeout: 3 * time.Second,
				Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
			deadline := time.Now().Add(10 * time.Second)
			for {
				response, err := httpClient.Get(destination.URL)
				if err == nil {
					page, _ := io.ReadAll(response.Body)
					response.Body.Close()
					if string(page) == "VPN works" {
						return
					}
				}
				if time.Now().After(deadline) {
					t.Fatalf("no traffic through %s: %v", outbound["type"], err)
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
}
