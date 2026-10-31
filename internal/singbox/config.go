package singbox

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// User is one enabled client. Every protocol derives its credentials from the UUID.
type User struct {
	Name string
	UUID string
}

// Password is the client's password for protocols that use one.
func (u User) Password() string { return u.UUID }

// shadowsocksKey derives a Shadowsocks 2022 key of the size the method needs.
func shadowsocksKey(secret, method string) string {
	size := 32
	if strings.Contains(method, "aes-128") {
		size = 16
	}
	sum := sha256.Sum256([]byte(secret))
	return base64.StdEncoding.EncodeToString(sum[:size])
}

// userInbounds are the inbound types whose users the panel manages.
var userInbounds = []string{"vless", "vmess", "trojan", "hysteria2", "tuic", "naive", "shadowsocks", "anytls"}

// managesUsers reports whether the panel fills the users of this inbound.
// Shadowsocks has users only with the 2022 methods.
func managesUsers(inbound map[string]any) bool {
	kind, _ := inbound["type"].(string)
	if kind == "shadowsocks" {
		method, _ := inbound["method"].(string)
		return strings.HasPrefix(method, "2022-")
	}
	return slices.Contains(userInbounds, kind)
}

// vlessFlow is the flow the admin chose (taken from the first example user),
// or xtls-rprx-vision for plain TCP with TLS/Reality, where it is the usual choice.
func vlessFlow(inbound map[string]any) string {
	if users, ok := inbound["users"].([]any); ok && len(users) > 0 {
		if first, ok := users[0].(map[string]any); ok {
			flow, _ := first["flow"].(string)
			return flow
		}
	}
	tls, _ := inbound["tls"].(map[string]any)
	if tls != nil && tls["enabled"] == true && inbound["transport"] == nil {
		return "xtls-rprx-vision"
	}
	return ""
}

// serverUser is one entry of an inbound's users in the format of its protocol.
func serverUser(inbound map[string]any, flow string, user User) map[string]any {
	kind, _ := inbound["type"].(string)
	switch kind {
	case "vless":
		entry := map[string]any{"name": user.Name, "uuid": user.UUID}
		if flow != "" {
			entry["flow"] = flow
		}
		return entry
	case "vmess":
		return map[string]any{"name": user.Name, "uuid": user.UUID, "alterId": 0}
	case "tuic":
		return map[string]any{"name": user.Name, "uuid": user.UUID, "password": user.Password()}
	case "naive":
		return map[string]any{"username": user.UUID, "password": user.Password()}
	case "shadowsocks":
		method, _ := inbound["method"].(string)
		return map[string]any{"name": user.Name, "password": shadowsocksKey(user.UUID, method)}
	default: // trojan, hysteria2, anytls
		return map[string]any{"name": user.Name, "password": user.Password()}
	}
}

// ServerConfig takes the admin's server JSON as is and replaces the users of
// every inbound that has users (VLESS, VMess, Trojan, Hysteria2, TUIC, Naive,
// Shadowsocks 2022, AnyTLS) with the panel's clients. Whatever users the JSON
// contained are examples and are dropped. Other inbounds are untouched.
func ServerConfig(raw string, users []User) ([]byte, error) {
	root, err := decodeObject(raw)
	if err != nil {
		return nil, errors.New("server config must be a JSON object")
	}
	inbounds, _ := root["inbounds"].([]any)
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok || !managesUsers(inbound) {
			continue
		}
		flow := vlessFlow(inbound)
		entries := []any{}
		for _, user := range users {
			entries = append(entries, serverUser(inbound, flow, user))
		}
		inbound["users"] = entries
	}
	return json.MarshalIndent(root, "", "  ")
}

// Listener is a port an inbound listens on, for the firewall hint.
type Listener struct {
	Tag     string
	Type    string
	Listen  string
	Port    int
	Network string // "tcp", "udp" or "tcp+udp"
}

// Listeners lists the inbounds that listen on a port.
func Listeners(serverJSON string) []Listener {
	root, err := decodeObject(serverJSON)
	if err != nil {
		return nil
	}
	var result []Listener
	inbounds, _ := root["inbounds"].([]any)
	for _, item := range inbounds {
		inbound, _ := item.(map[string]any)
		port := intField(inbound, "listen_port")
		if port == 0 {
			continue
		}
		kind, _ := inbound["type"].(string)
		tag, _ := inbound["tag"].(string)
		listen, _ := inbound["listen"].(string)
		network := "tcp"
		switch kind {
		case "hysteria", "hysteria2", "tuic":
			network = "udp"
		case "shadowsocks", "mixed", "socks", "direct":
			network = "tcp+udp"
		}
		if value, _ := inbound["network"].(string); value != "" {
			network = value
		}
		result = append(result, Listener{Tag: tag, Type: kind, Listen: listen, Port: port, Network: network})
	}
	return result
}

// probeAddress is a local TCP address where sing-box accepts connections once
// started. ok is false when no inbound listens on TCP.
func probeAddress(body []byte) (address string, ok bool) {
	for _, listener := range Listeners(string(body)) {
		if listener.Network == "udp" {
			continue
		}
		host := listener.Listen
		switch host {
		case "", "::":
			host = "::1"
		case "0.0.0.0":
			host = "127.0.0.1"
		}
		return net.JoinHostPort(host, strconv.Itoa(listener.Port)), true
	}
	return "", false
}

func intField(object map[string]any, key string) int {
	switch value := object[key].(type) {
	case json.Number:
		n, _ := value.Int64()
		return int(n)
	case float64:
		return int(value)
	case int:
		return value
	}
	return 0
}

func decodeObject(value string) (map[string]any, error) {
	decoded, err := decode(value)
	object, ok := decoded.(map[string]any)
	if err != nil || !ok {
		return nil, errors.New("not a JSON object")
	}
	return object, nil
}

// InitialConfigs returns the starting server config (VLESS + Reality with a
// fresh key pair, works without a domain) and the client skeleton.
func InitialConfigs(handshake string, port int) (serverJSON, clientJSON string, err error) {
	if handshake == "" || strings.ContainsAny(handshake, "/?#@: \t\r\n") {
		return "", "", errors.New("Reality handshake must be a TLS hostname")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return "", "", err
	}
	server := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type":        "vless",
			"tag":         "reality",
			"listen":      "::",
			"listen_port": port,
			"users":       []any{},
			"tls": map[string]any{
				"enabled":     true,
				"server_name": handshake,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": handshake, "server_port": 443},
					"private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()),
					"short_id":    []string{hex.EncodeToString(sid[:])},
				},
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	s, err := json.MarshalIndent(server, "", "  ")
	if err != nil {
		return "", "", err
	}
	return string(s), DefaultClientBase, nil
}

// DefaultClientBase is the client skeleton: TUN, DNS through the tunnel and
// routing. The panel adds an outbound for every server inbound and a
// "proxy" selector over them.
const DefaultClientBase = `{
  "log": {"level": "warn"},
  "dns": {
    "servers": [
      {"type": "https", "tag": "remote-dns", "server": "1.1.1.1", "detour": "proxy"},
      {"type": "local", "tag": "bootstrap"}
    ],
    "final": "remote-dns",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": true, "strict_route": true, "stack": "mixed"}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "bootstrap",
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "action": "route", "outbound": "direct"}
    ],
    "final": "proxy"
  }
}`

// realityPublicKey derives the client's public key from the server's private key.
func realityPublicKey(private string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(private)
	if err != nil {
		return "", fmt.Errorf("invalid Reality private_key: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid Reality private_key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
