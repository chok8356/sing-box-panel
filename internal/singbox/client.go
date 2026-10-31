package singbox

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Endpoint is how clients reach the server.
type Endpoint struct {
	Address string // public domain or IP from the panel's Settings
	// CertPath is where the panel publishes its certificate for sing-box.
	// Inbounds that use it get the certificate pinned in clients when it is
	// self-signed (CertPEM), so TLS works without a domain.
	CertPath   string
	CertPEM    string
	SelfSigned bool
}

// ClientConfig builds a client's JSON: shared config + additive override, plus an
// outbound for every server inbound with users and a "proxy" selector over
// them unless Base defines "proxy" itself.
func ClientConfig(base, override, serverJSON string, user User, ep Endpoint) ([]byte, error) {
	merged, err := mergeClientJSON(base, override)
	if err != nil {
		return nil, err
	}
	generated, err := ClientOutbounds(serverJSON, user, ep)
	if err != nil || len(generated) == 0 {
		return merged, err
	}
	root, err := decodeObject(string(merged))
	if err != nil {
		return merged, nil // not an object: nothing to add outbounds to
	}
	existing, _ := root["outbounds"].([]any)
	outbounds := generated
	if findTag(existing, "proxy") == nil {
		var tags []any
		for _, outbound := range generated {
			tags = append(tags, outbound.(map[string]any)["tag"])
		}
		outbounds = append([]any{map[string]any{"type": "selector", "tag": "proxy", "outbounds": tags}}, outbounds...)
	}
	root["outbounds"] = append(outbounds, existing...)
	return json.MarshalIndent(root, "", "  ")
}

// Personal routing policy follows the shared setup actions and precedes shared
// routing decisions. DNS exceptions precede broad regional DNS rules.
func mergeClientJSON(base, override string) ([]byte, error) {
	target, err := decode(base)
	if err != nil {
		return nil, err
	}
	patch, err := decode(override)
	if err != nil {
		return nil, err
	}
	baseRoot, _ := target.(map[string]any)
	patchRoot, _ := patch.(map[string]any)
	ordered := make(map[string][]any)
	for _, section := range []string{"route", "dns"} {
		baseSection, _ := baseRoot[section].(map[string]any)
		patchSection, _ := patchRoot[section].(map[string]any)
		shared, _ := baseSection["rules"].([]any)
		personal, _ := patchSection["rules"].([]any)
		if len(personal) == 0 {
			continue
		}
		prefix := 0
		if section == "route" {
		leading:
			for prefix < len(shared) {
				rule, _ := shared[prefix].(map[string]any)
				switch rule["action"] {
				case "sniff", "hijack-dns", "resolve", "route-options":
					prefix++
				default:
					break leading
				}
			}
		}
		list := append([]any{}, shared[:prefix]...)
		list = append(list, personal...)
		ordered[section] = append(list, shared[prefix:]...)
	}
	// First-input priority gives scalar settings to the client's override.
	merged := mergeValue(patch, target)
	if root, ok := merged.(map[string]any); ok {
		for section, rules := range ordered {
			root[section].(map[string]any)["rules"] = rules
		}
	}
	return json.MarshalIndent(merged, "", "  ")
}

func findTag(list []any, tag string) map[string]any {
	for _, item := range list {
		if entry, ok := item.(map[string]any); ok && entry["tag"] == tag {
			return entry
		}
	}
	return nil
}

// ClientOutbounds returns the client outbounds matching the server inbounds
// whose users the panel manages, with this user's credentials.
func ClientOutbounds(serverJSON string, user User, ep Endpoint) ([]any, error) {
	if serverJSON == "" {
		return nil, nil
	}
	root, err := decodeObject(serverJSON)
	if err != nil {
		return nil, fmt.Errorf("server config: %w", err)
	}
	var result []any
	inbounds, _ := root["inbounds"].([]any)
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok || !managesUsers(inbound) {
			continue
		}
		outbound, err := clientOutbound(inbound, user, ep)
		if err != nil {
			return nil, err
		}
		result = append(result, outbound)
	}
	return result, nil
}

func clientOutbound(inbound map[string]any, user User, ep Endpoint) (map[string]any, error) {
	kind, _ := inbound["type"].(string)
	port := intField(inbound, "listen_port")
	tag, _ := inbound["tag"].(string)
	if tag == "" {
		tag = kind + "-" + strconv.Itoa(port)
	}
	out := map[string]any{"type": kind, "tag": "proxy-" + tag, "server": ep.Address, "server_port": port}

	switch kind {
	case "vless":
		out["uuid"] = user.UUID
		if flow := vlessFlow(inbound); flow != "" {
			out["flow"] = flow
		}
	case "vmess":
		out["uuid"], out["security"], out["alter_id"] = user.UUID, "auto", 0
	case "tuic":
		out["uuid"], out["password"] = user.UUID, user.Password()
		copyField(out, inbound, "congestion_control")
	case "naive":
		out["username"], out["password"] = user.UUID, user.Password()
	case "shadowsocks":
		method, _ := inbound["method"].(string)
		serverKey, _ := inbound["password"].(string)
		out["method"] = method
		out["password"] = serverKey + ":" + shadowsocksKey(user.UUID, method)
	default: // trojan, hysteria2, anytls
		out["password"] = user.Password()
	}
	copyField(out, inbound, "obfs")      // hysteria2
	copyField(out, inbound, "transport") // same shape on both sides
	if multiplex, _ := inbound["multiplex"].(map[string]any); multiplex != nil && multiplex["enabled"] == true {
		out["multiplex"] = map[string]any{"enabled": true}
	}

	serverTLS, _ := inbound["tls"].(map[string]any)
	if serverTLS == nil || serverTLS["enabled"] != true {
		return out, nil
	}
	tls := map[string]any{"enabled": true}
	serverName, _ := serverTLS["server_name"].(string)
	if reality, _ := serverTLS["reality"].(map[string]any); reality != nil && reality["enabled"] == true {
		private, _ := reality["private_key"].(string)
		public, err := realityPublicKey(private)
		if err != nil {
			return nil, fmt.Errorf("inbound %s: %w", tag, err)
		}
		shortID := ""
		if ids, _ := reality["short_id"].([]any); len(ids) > 0 {
			shortID, _ = ids[0].(string)
		} else if id, ok := reality["short_id"].(string); ok {
			shortID = id
		}
		tls["server_name"] = serverName
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		tls["reality"] = map[string]any{"enabled": true, "public_key": public, "short_id": shortID}
	} else {
		if serverName == "" {
			serverName = ep.Address
		}
		tls["server_name"] = serverName
		copyField(tls, serverTLS, "alpn")
		// The panel's self-signed certificate is pinned instead of trusted blindly.
		if path, _ := serverTLS["certificate_path"].(string); ep.SelfSigned && path == ep.CertPath && ep.CertPEM != "" {
			tls["certificate"] = ep.CertPEM
		}
	}
	out["tls"] = tls
	return out, nil
}

func copyField(to, from map[string]any, key string) {
	if value, ok := from[key]; ok {
		to[key] = value
	}
}
