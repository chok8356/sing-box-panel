package panel

import (
	"strings"
	"testing"
)

func TestFontCachingKeepsPrivatePagesUncached(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	w := request(t, h, "GET", testOrigin+c.PanelPath+"/static/Inter-v4.1.woff2", nil, true)
	wantStatus(t, w, 200)
	cached := w.Header().Get("Cache-Control") == "private, max-age=31536000, immutable"
	if !cached || !strings.HasPrefix(w.Body.String(), "wOF2") {
		t.Fatal("versioned font must be cached WOFF2")
	}
	w = request(t, h, "GET", testOrigin+c.PanelPath+"/config", nil, true)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private HTML must stay uncached")
	}
	if !strings.Contains(w.Body.String(), `rel="preload"`) || !strings.Contains(w.Body.String(), "Inter-v4.1.woff2") {
		t.Fatal("font preload missing")
	}
}

func TestClientOverrideDisclosure(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	h := a.handler()
	for _, tc := range []struct {
		name, override string
		open           bool
		status         int
	}{
		{"shared config", "{}", false, 200},
		{"custom override", `{"route":{"final":"direct"}}`, true, 200},
		{"invalid JSON stays editable", "{", true, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(t, h, "POST", testOrigin+c.PanelPath+"/subscriptions",
				form("name", "Laptop", "override_json", tc.override, "action", "validate"), true)
			wantStatus(t, w, tc.status)
			body := w.Body.String()
			if got := strings.Contains(body, `<details class="advanced-settings" open>`); got != tc.open {
				t.Fatalf("override disclosure open = %v, want %v", got, tc.open)
			}
			// The default submit must save even while the JSON tools are collapsed.
			save, format := strings.Index(body, `value="save"`), strings.Index(body, `value="format"`)
			if save < 0 || format < 0 || save > format {
				t.Fatal("JSON tool takes precedence over saving on Enter")
			}
		})
	}
}
