package config

import (
	"strings"
	"testing"
)

// #9497: DHCPDynamicDNSConfig.String() printed update-server verbatim while
// MarshalJSON and RedactedClone redact it, so a %v / slog of the struct leaked
// a userinfo-bearing value.
func TestDHCPDynamicDNSConfigStringRedactsUpdateServer_9497(t *testing.T) {
	got := (&DHCPDynamicDNSConfig{UpdateServer: "user:s3cr3t@dns.example.com"}).String()
	if strings.Contains(got, "s3cr3t") {
		t.Fatalf("#9497: String() leaked the update-server credential: %s", got)
	}
	if !strings.Contains(got, "<redacted>@dns.example.com") {
		t.Fatalf("String() must keep the redacted host: %s", got)
	}
	if clean := (&DHCPDynamicDNSConfig{UpdateServer: "ns1.example.com:53"}).String(); !strings.Contains(clean, `update-server="ns1.example.com:53"`) {
		t.Fatalf("control: a clean host:port must print unchanged: %s", clean)
	}
}
