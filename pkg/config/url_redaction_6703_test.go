package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// #6703. The config-READ surfaces rendered URL-bearing leaves with no redaction
// at all — they leaked even a userinfo credential, which RedactURL has stripped
// since #2781, because nothing on those paths ever called it. These tests pin
// both halves of the property: a credential-bearing URL is redacted, AND a
// credential-free one renders UNCHANGED. Only asserting the first cannot detect
// over-redaction, which for these leaves would destroy the diagnostic value the
// #6703 acceptance criteria explicitly require be kept.

// TestURLLeafIndicesGatesGenericKeywords_6703 pins the context gate directly.
// `server` is also an NTP leaf (schema_system.go) and `url` is not, so the two
// keywords must be scoped differently. A render-level test cannot discriminate
// here: RedactURL is a no-op on a bare NTP address, so a wrongly-ungated
// `server` would still render unchanged and the test would pass for the wrong
// reason.
func TestURLLeafIndicesGatesGenericKeywords_6703(t *testing.T) {
	for _, tc := range []struct {
		name string
		path []string
		want []int
	}{
		{"ddns server is a url leaf",
			[]string{"system", "services", "dynamic-dns", "provider", "p1", "server", "VALUE"}, []int{6}},
		{"ddns update-server is a url leaf",
			[]string{"system", "services", "dynamic-dns", "provider", "p1", "update-server", "VALUE"}, []int{6}},
		{"NTP server is NOT a url leaf",
			[]string{"system", "ntp", "server", "VALUE"}, nil},
		{"url matches in every context — feed",
			[]string{"security", "dynamic-address", "feed-server", "f1", "url", "VALUE"}, []int{5}},
		{"url matches in every context — license autoupdate",
			[]string{"system", "license", "autoupdate", "url", "VALUE"}, []int{4}},
		{"url-template is distinctive, no gate needed",
			[]string{"system", "services", "dynamic-dns", "provider", "p1", "url-template", "VALUE"}, []int{6}},
		{"checkip-url is distinctive, no gate needed",
			[]string{"system", "services", "dynamic-dns", "provider", "p1", "checkip-url", "VALUE"}, []int{6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := urlLeafIndices(tc.path)
			if len(got) != len(tc.want) {
				t.Fatalf("urlLeafIndices(%v) = %v, want %v", tc.path, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("urlLeafIndices(%v) = %v, want %v", tc.path, got, tc.want)
				}
			}
		})
	}
}

// TestDDNSProviderMarshalJSONRedactsURLs_6703 asserts the JSON render both
// redacts and preserves. GET /api/v1/config json-encodes the compiled *Config,
// so this marshaller is the whole fix for that route.
func TestDDNSProviderMarshalJSONRedactsURLs_6703(t *testing.T) {
	p := &DDNSProvider{
		Name:        "p1",
		Backend:     "generic",
		Server:      "https://user:SUPERSECRET@dyn.example/upd",
		URLTemplate: "https://tmpl.example/upd?token=TOKENSECRET&host=%h",
		CheckIPURL:  "https://checkip.example/plain",
		Username:    "operator",
		Password:    NewSecret("PASSWORDSECRET"),
		OKResponse:  "good",
		RFC2136Endpoint: RFC2136Endpoint{
			UpdateServer: "ns1.example.com:53",
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out := string(b)

	for _, leak := range []string{"SUPERSECRET", "TOKENSECRET", "PASSWORDSECRET"} {
		if strings.Contains(out, leak) {
			t.Errorf("marshalled provider leaked %q: %s", leak, out)
		}
	}
	// Assert what the values BECAME, not merely that they changed.
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if want := "https://<redacted>@dyn.example/upd"; got["Server"] != want {
		t.Errorf("Server = %q, want %q", got["Server"], want)
	}
	if want := "https://tmpl.example/upd?<redacted>"; got["URLTemplate"] != want {
		t.Errorf("URLTemplate = %q, want %q", got["URLTemplate"], want)
	}
	// NO credential -> UNCHANGED. This half is what detects over-redaction.
	if want := "https://checkip.example/plain"; got["CheckIPURL"] != want {
		t.Errorf("credential-free CheckIPURL = %q, want it rendered unchanged as %q", got["CheckIPURL"], want)
	}
	if want := "ns1.example.com:53"; got["UpdateServer"] != want {
		t.Errorf("plain host:port UpdateServer = %q, want it rendered unchanged as %q", got["UpdateServer"], want)
	}
	// Non-URL fields must survive: the alias-copy exists so a field added to
	// DDNSProvider later is still marshalled rather than silently dropped.
	if got["Username"] != "operator" || got["OKResponse"] != "good" || got["Backend"] != "generic" {
		t.Errorf("marshaller dropped or altered a non-URL field: %s", out)
	}
}

// TestFeedServerMarshalJSONRedactsURL_6703 is the same property for the feed
// leaf, whose token conventionally rides in the query string.
func TestFeedServerMarshalJSONRedactsURL_6703(t *testing.T) {
	withTok := &FeedServer{Name: "threat", URL: "https://feeds.example/list.txt?key=FEEDSECRET", UpdateInterval: 900}
	b, err := json.Marshal(withTok)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if strings.Contains(string(b), "FEEDSECRET") {
		t.Errorf("feed URL leaked its token: %s", b)
	}
	if want := "https://feeds.example/list.txt?<redacted>"; got["URL"] != want {
		t.Errorf("URL = %q, want %q", got["URL"], want)
	}
	if got["UpdateInterval"] != float64(900) {
		t.Errorf("marshaller dropped a non-URL field: %s", b)
	}

	clean := &FeedServer{Name: "threat", URL: "https://feeds.example/list.txt"}
	cb, err := json.Marshal(clean)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := json.Unmarshal(cb, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if want := "https://feeds.example/list.txt"; got["URL"] != want {
		t.Errorf("credential-free feed URL = %q, want it rendered unchanged as %q", got["URL"], want)
	}
}

// TestRedactedCloneTransformsURLLeaves_6703 covers the AST render path backing
// /config/export and /config/show. Unlike a secret leaf, a URL leaf is
// TRANSFORMED rather than masked, so scheme/host/path stay visible.
func TestRedactedCloneTransformsURLLeaves_6703(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		`set system services dynamic-dns provider p1 server "https://user:ASTSECRET@dyn.example/upd"`,
		`set security dynamic-address feed-server threat url "https://feeds.example/list.txt?key=ASTFEEDSECRET"`,
		`set security dynamic-address feed-server clean url "https://feeds.example/plain.txt"`,
		`set system ntp server 192.0.2.1`,
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	out := tree.RedactedClone().FormatSet()

	for _, leak := range []string{"ASTSECRET", "ASTFEEDSECRET"} {
		if strings.Contains(out, leak) {
			t.Errorf("redacted AST render leaked %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "https://<redacted>@dyn.example/upd") {
		t.Errorf("ddns server not transformed as expected:\n%s", out)
	}
	if !strings.Contains(out, "https://feeds.example/list.txt?<redacted>") {
		t.Errorf("feed url not transformed as expected:\n%s", out)
	}
	// Both no-op halves: a credential-free URL and a non-URL `server` leaf.
	if !strings.Contains(out, "https://feeds.example/plain.txt") {
		t.Errorf("credential-free feed url must render UNCHANGED:\n%s", out)
	}
	if !strings.Contains(out, "192.0.2.1") {
		t.Errorf("NTP server must be untouched by URL redaction:\n%s", out)
	}
	// The live tree is never mutated — RedactedClone is display-only.
	if !strings.Contains(tree.FormatSet(), "ASTSECRET") {
		t.Error("RedactedClone mutated the live tree; the cleartext SSOT backs HA sync and persistence")
	}
}

// TestRedactedURLIngestIsRefused_6703 pins the round-trip guard. Redacting a
// URL leaf produces something that still LOOKS like a valid URL, so without
// this an operator re-applying a redacted export would silently install a
// broken endpoint instead of failing loudly.
func TestRedactedURLIngestIsRefused_6703(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand(`set system services dynamic-dns provider p1 server "https://dyn.example/upd?<redacted>"`)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	err = checkRedactionPlaceholder(tree)
	if err == nil {
		t.Fatal("a redacted URL value must be refused on commit-ingest")
	}
	if !strings.Contains(err.Error(), "redacted URL") {
		t.Errorf("error must identify the cause, got %v", err)
	}

	// A cleartext URL must still ingest cleanly — the guard is not a blanket ban.
	clean := &ConfigTree{}
	p2, _ := ParseSetCommand(`set system services dynamic-dns provider p1 server "https://dyn.example/upd"`)
	if err := clean.SetPath(p2); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if err := checkRedactionPlaceholder(clean); err != nil {
		t.Errorf("a cleartext URL must ingest cleanly, got %v", err)
	}
}
