package singbox

import (
	"os"
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
			route := root["route"].(map[string]any)
			if route["final"] != "proxy" {
				t.Fatal("preset bypasses VPN by default")
			}
			rules := route["rules"].([]any)
			if rules[2].(map[string]any)["ip_is_private"] != true {
				t.Fatal("local network rule missing")
			}
			if name == "russia" && len(root["dns"].(map[string]any)["rules"].([]any)) != 2 {
				t.Fatal("split DNS missing")
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
