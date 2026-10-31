package panel

import (
	"strings"
	"testing"
)

func TestLogAccessAndRedaction(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	payload := "<script>alert(1)</script> https://sub.example.com:2096" + c.SubscriptionPath +
		"/Client?format=json " + c.AdminPassword + " " + c.PanelPath
	a.logs.Write([]byte(payload))
	h := a.handler()
	endpoint := testOrigin + c.PanelPath + "/logs"
	wantStatus(t, request(t, h, "GET", endpoint, nil, false), 303)
	w := request(t, h, "GET", endpoint+"?format=text", nil, true)
	wantStatus(t, w, 200)
	if w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal("logs must be plain text")
	}
	for _, secret := range []string{c.SubscriptionPath, c.PanelPath, c.AdminPassword} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("secret leaked in logs")
		}
	}
	w = request(t, h, "GET", endpoint, nil, true)
	wantStatus(t, w, 200)
	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("log HTML was not escaped")
	}
}
