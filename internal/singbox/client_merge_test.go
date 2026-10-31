package singbox

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientRuleInheritanceAndPriority(t *testing.T) {
	base, err := ClientPreset("russia", true)
	if err != nil {
		t.Fatal(err)
	}
	patch := `{"route":{"rules":[{"domain_suffix":["exception.example"],"action":"route","outbound":"direct"},{"process_name":["example.exe"],"action":"route","outbound":"direct"}]},"dns":{"rules":[{"domain_suffix":["example.ru"],"action":"route","server":"remote-dns"}]}}`
	server, _, err := InitialConfigs("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	user := User{Name: "Test", UUID: "00000000-0000-4000-8000-000000000000"}
	body, err := ClientConfig(base, patch, server, user, Endpoint{Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeObject(string(body))
	if err != nil {
		t.Fatal(err)
	}
	baseRoot, _ := decodeObject(base)
	baseRules := baseRoot["route"].(map[string]any)["rules"].([]any)
	rules := root["route"].(map[string]any)["rules"].([]any)
	if len(rules) != len(baseRules)+2 {
		t.Fatalf("shared rules were replaced: got %d, want %d", len(rules), len(baseRules)+2)
	}
	if rules[0].(map[string]any)["action"] != "sniff" || rules[1].(map[string]any)["action"] != "hijack-dns" {
		t.Fatal("personal rules bypass DNS interception or sniffing")
	}
	if rules[2].(map[string]any)["domain_suffix"] == nil || rules[3].(map[string]any)["process_name"] == nil {
		t.Fatal("personal rules did not take priority")
	}
	if !reflect.DeepEqual(rules[4:], baseRules[2:]) {
		t.Fatal("shared policy changed")
	}
	dnsRules := root["dns"].(map[string]any)["rules"].([]any)
	if len(dnsRules) != 3 || dnsRules[0].(map[string]any)["server"] != "remote-dns" {
		t.Fatal("personal DNS rule does not precede regional DNS")
	}
	other, err := ClientConfig(base, "{}", server, user, Endpoint{Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, _ := decodeObject(string(other))
	if !reflect.DeepEqual(otherRoot["route"].(map[string]any)["rules"], baseRules) {
		t.Fatal("personal rules leaked to another client")
	}
	baseRoot["route"].(map[string]any)["rules"] = append(baseRules, map[string]any{"domain": "new.example", "action": "reject"})
	changed, _ := json.Marshal(baseRoot)
	updated, err := ClientConfig(string(changed), patch, server, user, Endpoint{Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	updatedRoot, _ := decodeObject(string(updated))
	if len(updatedRoot["route"].(map[string]any)["rules"].([]any)) != len(rules)+1 {
		t.Fatal("shared policy updates no longer propagate")
	}
	if binary := os.Getenv("SING_BOX_TEST_BINARY"); binary != "" {
		p := Process{Binary: binary, Dir: t.TempDir()}
		if err := p.Check(t.Context(), body); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPersonalRuleCarriesTrafficBeforeSharedBlock(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BINARY for real routing proof")
	}
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "personal exception works")
	}))
	defer origin.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	base := fmt.Sprintf(`{"log":{"level":"error"},"dns":{"strategy":"ipv4_only","servers":[{"type":"local","tag":"bootstrap"}]},"inbounds":[{"type":"mixed","tag":"test","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_domain_resolver":"bootstrap","rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"},{"domain":["localhost","blocked.test"],"action":"reject"}],"final":"direct"}}`, port)
	p := Process{Binary: binary, Dir: t.TempDir()}
	defer p.Stop()
	if err := p.Apply(t.Context(), []byte(base)); err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	originURL, _ := url.Parse(origin.URL)
	_, originPort, _ := net.SplitHostPort(originURL.Host)
	fetch := func(host string) (string, error) {
		r, err := http.NewRequest("GET", origin.URL, nil)
		if err != nil {
			return "", err
		}
		// Keep the origin port when using a domain Host through the HTTP proxy.
		r.Host = net.JoinHostPort(host, originPort)
		response, err := client.Do(r)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return string(body), err
	}
	_, _ = fetch("localhost")
	if hits.Load() != 0 {
		t.Fatal("shared domain block did not apply after sniffing")
	}
	patch := `{"route":{"rules":[{"domain_suffix":["localhost"],"action":"route","outbound":"direct"}]}}`
	body, err := ClientConfig(base, patch, "", User{}, Endpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	got, err := fetch("localhost")
	if err != nil || got != "personal exception works" {
		t.Fatalf("personal exception did not override the shared block: %q %v", got, err)
	}
	_, _ = fetch("blocked.test")
	if hits.Load() != 1 {
		t.Fatal("personal exception disabled unrelated shared blocking")
	}
}

func TestConfigMergeMatchesSingBox(t *testing.T) {
	cases := [][2]string{
		{`{"log":{"level":"warn"},"route":{"final":"first","rules":[{"domain":"base.example","action":"reject"}]}}`, `{"log":{"level":"error"},"route":{"final":"second","rules":[{"domain":"personal.example","action":"reject"}]}}`},
		{`{"route":{"final":"direct","rules":[{"domain":"base.example","action":"reject"}]}}`, `{"route":{"final":null,"rules":[]}}`},
		{`{"outbounds":[{"type":"direct","tag":"first"}]}`, `{"outbounds":[{"type":"direct","tag":"second"}]}`},
	}
	for _, tc := range cases {
		got, err := MergeJSON(tc[0], tc[1])
		if err != nil {
			t.Fatal(err)
		}
		if binary := os.Getenv("SING_BOX_TEST_BINARY"); binary != "" {
			work := t.TempDir()
			first, second, out := filepath.Join(work, "00-base.json"), filepath.Join(work, "01-personal.json"), filepath.Join(work, "out.json")
			if err := os.WriteFile(first, []byte(tc[0]), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(second, []byte(tc[1]), 0600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(binary, "merge", out, "-c", first, "-c", second).CombinedOutput(); err != nil {
				t.Fatalf("native merge: %v %s", err, output)
			}
			want, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if normalizedJSON(t, got) != normalizedJSON(t, want) {
				t.Fatalf("different from sing-box merge:\ngot %s\nwant %s", got, want)
			}
		}
	}
}
