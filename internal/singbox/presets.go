package singbox

import (
	"encoding/json"
	"errors"
)

// ClientPreset builds a public template; credentials always come from the server.
func ClientPreset(name string, blockAds bool) (string, error) {
	if name != "proxy" && name != "russia" {
		return "", errors.New("unknown client preset")
	}
	root, err := decodeObject(DefaultClientBase)
	if err != nil {
		return "", err
	}
	route := root["route"].(map[string]any)
	rules := route["rules"].([]any)
	var sets []any
	addSet := func(tag, repo string) {
		sets = append(sets, map[string]any{"type": "remote", "tag": tag, "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + tag + ".srs", "update_interval": "1d", "http_client": "rule-sets"})
	}
	if blockAds {
		addSet("geosite-category-ads-all", "sing-geosite")
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-category-ads-all"}, "action": "reject"})
	}
	if name == "russia" {
		addSet("geosite-category-ru", "sing-geosite")
		addSet("geoip-ru", "sing-geoip")
		suffixes := []string{"ru", "su", "xn--p1ai"}
		rules = append(rules, map[string]any{"domain_suffix": suffixes, "action": "route", "outbound": "direct"}, map[string]any{"rule_set": []string{"geosite-category-ru", "geoip-ru"}, "action": "route", "outbound": "direct"})
		dns := root["dns"].(map[string]any)
		dns["rules"] = []any{map[string]any{"domain_suffix": suffixes, "action": "route", "server": "bootstrap"}, map[string]any{"rule_set": []string{"geosite-category-ru"}, "action": "route", "server": "bootstrap"}}
	}
	route["rules"] = rules
	if len(sets) > 0 {
		route["rule_set"] = sets
		root["http_clients"] = []any{map[string]any{"tag": "rule-sets", "detour": "proxy"}}
		root["experimental"] = map[string]any{"cache_file": map[string]any{"enabled": true}}
	}
	data, err := json.MarshalIndent(root, "", "  ")
	return string(data), err
}
