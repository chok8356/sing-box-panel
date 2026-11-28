package singbox

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestClientPresets(t *testing.T) {
	server, _, err := InitialConfigs("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proxy", "russia"} {
		for _, ads := range []bool{false, true} {
			base, err := ClientPreset(name, ads)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(base, "geoip-ru") != (name == "russia") || strings.Contains(base, "geosite-category-ads-all") != ads {
				t.Fatal("incorrect preset options")
			}
			root, err := decodeObject(base)
			if err != nil {
				t.Fatal(err)
			}
			tun := root["inbounds"].([]any)[0].(map[string]any)
			if tun["stack"] != "gvisor" {
				t.Fatalf("%s ads=%v: expected gVisor TUN stack", name, ads)
			}
			if (name == "russia" || ads) && !reflect.DeepEqual(root["http_clients"], []any{map[string]any{"tag": "rule-sets"}}) {
				t.Fatalf("%s ads=%v: expected a direct rule-set HTTP client", name, ads)
			}
			if !reflect.DeepEqual(tun["address"], []any{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}) {
				t.Fatalf("%s ads=%v: dual-stack TUN addresses missing", name, ads)
			}
			if !reflect.DeepEqual(tun["route_exclude_address"], []any{"127.0.0.0/8", "::1/128"}) {
				t.Fatalf("%s ads=%v: loopback exclusions missing", name, ads)
			}
			route := root["route"].(map[string]any)
			if route["final"] != "proxy" {
				t.Fatal("preset bypasses VPN by default")
			}
			rules := route["rules"].([]any)
			if rules[2].(map[string]any)["ip_is_private"] != true {
				t.Fatal("local network rule missing")
			}
			if name == "russia" {
				want, err := decodeObject(`{
				  "dns": {
				    "strategy": "ipv4_only",
				    "rules": [
				      {"action":"route","domain_suffix":["ru","su","xn--p1ai"],"server":"bootstrap"},
				      {"action":"route","rule_set":["geosite-category-ru"],"server":"bootstrap"}
				    ]
				  },
			  "inbounds": [{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true,"stack":"gvisor","strict_route":true,"route_exclude_address":["127.0.0.0/8","::1/128"]}]
				}`)
				if err != nil {
					t.Fatal(err)
				}
				dns := root["dns"].(map[string]any)
				wantDNS := want["dns"].(map[string]any)
				if dns["strategy"] != wantDNS["strategy"] || !reflect.DeepEqual(dns["rules"], wantDNS["rules"]) {
					t.Fatal("regional DNS policy differs from the Russia template")
				}
				if !reflect.DeepEqual(root["inbounds"], want["inbounds"]) {
					t.Fatal("TUN settings differ from the Russia template")
				}
			}
			for _, private := range []string{"openvpn.exe", "steam.exe", "aircampaign.ru", "nike.com.co", "private_key", "uuid"} {
				if strings.Contains(base, private) {
					t.Fatal("personal setting leaked into preset", private)
				}
			}
			for _, address := range []string{"vpn.example.com", "192.0.2.1"} {
				body, err := ClientConfig(base, "{}", server, User{Name: "Test", UUID: "00000000-0000-4000-8000-000000000000"}, Endpoint{Address: address})
				if err != nil {
					t.Fatal(err)
				}
				if binary := os.Getenv("SING_BOX_TEST_BINARY"); binary != "" {
					p := Process{Binary: binary, Dir: t.TempDir()}
					if err := p.Check(t.Context(), body); err != nil {
						t.Fatalf("%s ads=%v address=%s: %v", name, ads, address, err)
					}
				}
			}
		}
	}
	if _, err := ClientPreset("unknown", false); err == nil {
		t.Fatal("unknown preset accepted")
	}
}
