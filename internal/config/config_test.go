package config

import "testing"

func TestNormalizePath(t *testing.T) {
	for _, raw := range []string{"SECRET", "/SECRET", "/SECRET/", "//SECRET///", " /SECRET/ "} {
		got, err := normalizePath(raw)
		if err != nil || got != "/SECRET" {
			t.Fatalf("normalize %q = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"/secret?x", "/secret#x", "/secret%2F", "/secret\\x", "/secret\nx"} {
		if _, err := normalizePath(raw); err == nil {
			t.Fatalf("unsafe path accepted: %q", raw)
		}
	}
	if got := EscapedPrefix("/a b/{c}"); got != "/a%20b/%7Bc%7D" {
		t.Fatal(got)
	}
}

func TestLoad(t *testing.T) {
	valid := map[string]string{
		"ADMIN_USERNAME":    "admin",
		"ADMIN_PASSWORD":    "test-secret",
		"PANEL_PATH":        "/a/",
		"SUBSCRIPTION_PATH": "s/",
	}
	for key, value := range valid {
		t.Setenv(key, value)
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.PanelPath != "/a" || c.SubscriptionPath != "/s" {
		t.Fatalf("wrong config: %#v", c)
	}

	invalid := [][2]string{
		{"ADMIN_PASSWORD", ""},
		{"ADMIN_USERNAME", "a:b"},
		{"SUBSCRIPTION_PATH", "/"},
		{"SUBSCRIPTION_PATH", "/a"},
		{"PANEL_PATH", "/a?b"},
	}
	for _, change := range invalid {
		t.Run(change[0]+change[1], func(t *testing.T) {
			t.Setenv(change[0], change[1])
			if _, err := Load(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
