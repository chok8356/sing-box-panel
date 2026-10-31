package panel

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// adminClient talks to a real panel listener: self-signed TLS, session auth, no redirects.
type adminClient struct {
	t      *testing.T
	client *http.Client
}

func newAdminClient(t *testing.T) adminClient {
	return adminClient{t: t, client: &http.Client{
		Timeout:       3 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c adminClient) do(method, target, body string) (*http.Response, string) {
	c.t.Helper()
	r, _ := http.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if strings.HasPrefix(r.URL.Path, "/SECRET_ADMIN_PATH/") {
		response, err := c.client.PostForm("https://"+r.URL.Host+"/SECRET_ADMIN_PATH/login", url.Values{"username": {"admin"}, "password": {"test-secret"}})
		if err != nil {
			c.t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 303 {
			c.t.Fatalf("login: %d", response.StatusCode)
		}
		for _, cookie := range response.Cookies() {
			r.AddCookie(cookie)
		}
	}
	response, err := c.client.Do(r)
	if err != nil {
		c.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response, string(data)
}

func listening(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err == nil {
		conn.Close()
	}
	return err == nil
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !done(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
	}
}

func TestHTTPSListenerAndPanelPortChange(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	first, second, third := freePort(t), freePort(t), freePort(t)
	if err := seedVPN(a.db, "vpn.example.com", "example.com", 443, first); err != nil {
		t.Fatal(err)
	}
	addClient(t, a.db, "Client", "TOKEN")
	a.listeners.confirmTimeout = 500 * time.Millisecond
	if err := a.listeners.start(first); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.listeners.shutdown(t.Context()) })
	client := newAdminClient(t)
	base := func(port int) string { return fmt.Sprintf("https://127.0.0.1:%d", port) }

	// Without a domain in the SNI the panel serves its self-signed certificate.
	response, body := client.do("GET", base(first)+c.SubscriptionPath+"/TOKEN", "")
	if response.StatusCode != 200 || !strings.Contains(body, "{") {
		t.Fatalf("subscription over TLS: %d", response.StatusCode)
	}
	if err := response.TLS.PeerCertificates[0].VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal("self-signed certificate does not cover loopback:", err)
	}

	// A new port opens next to the old one and waits for confirmation.
	settings := c.PanelPath + "/settings"
	form := fmt.Sprintf("address=vpn.example.com&vpn_port=443&panel_port=%d", second)
	response, _ = client.do("POST", base(first)+settings, form)
	if response.StatusCode != 303 || response.Header.Get("Location") != base(second)+settings {
		t.Fatalf("port change redirect: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	if _, body := client.do("GET", base(second)+settings, ""); !strings.Contains(body, "Keep port") {
		t.Fatal("new port does not offer confirmation")
	}
	if response, _ := client.do("POST", base(first)+settings+"/confirm-port", ""); response.StatusCode != 409 {
		t.Fatal("confirmation through the old port accepted")
	}
	if response, _ := client.do("POST", base(second)+settings+"/confirm-port", ""); response.StatusCode != 303 {
		t.Fatal("confirmation through the new port rejected")
	}
	if port, _ := getSetting(t.Context(), a.db, "panel_port"); port != fmt.Sprint(second) {
		t.Fatal("confirmed port not stored:", port)
	}
	waitFor(t, "old port stayed open", func() bool { return !listening(first) })

	// An unconfirmed port closes again by itself.
	form = fmt.Sprintf("address=vpn.example.com&vpn_port=443&panel_port=%d", third)
	if response, _ := client.do("POST", base(second)+settings, form); response.StatusCode != 303 {
		t.Fatal("second port change failed")
	}
	if !listening(third) {
		t.Fatal("proposed port is not open")
	}
	waitFor(t, "unconfirmed port stayed open", func() bool { return !listening(third) })
	if !listening(second) || a.site().PanelPort != second {
		t.Fatal("panel left the confirmed port")
	}
}

func TestSettingsAddressAndValidation(t *testing.T) {
	c := testConfig()
	a, _ := testApp(t, c)
	if err := seedVPN(a.db, "vpn.example.com", "example.com", 443, 8443); err != nil {
		t.Fatal(err)
	}
	h := a.handler()
	settings := testOrigin + c.PanelPath + "/settings"
	for _, invalid := range []string{
		"address=vpn.example.com&panel_port=80",  // reserved for Let's Encrypt
		"address=vpn.example.com&panel_port=443", // used by the Reality inbound
		"address=vpn.example.com&panel_port=70000",
		"address=bad/address&panel_port=8443",
	} {
		values, _ := urlValues(invalid)
		wantStatus(t, request(t, h, "POST", settings, values, true), 422)
	}

	values, _ := urlValues("address=203.0.113.7&panel_port=8443")
	wantStatus(t, request(t, h, "POST", settings, values, true), 303)
	if a.site().Address != "203.0.113.7" || !strings.HasPrefix(a.subscriptionURL("T"), "https://203.0.113.7:8443/") {
		t.Fatal("subscription URL does not use the new address")
	}
	// Clients are generated from the server config and connect to the new address.
	w := request(t, h, "GET", a.subscriptionURL(tokenOf(t, a.db, "First client")), nil, false)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"server": "203.0.113.7"`) || !strings.Contains(w.Body.String(), `"type": "selector"`) {
		t.Fatal("client config was not generated for the new address:", w.Body.String())
	}
	if page := request(t, h, "GET", settings, nil, true).Body.String(); !strings.Contains(page, "443") ||
		!strings.Contains(page, a.certs.certPath()) {
		t.Fatal("settings do not show inbound ports and the certificate path")
	}
}
