package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9497: `show dhcp-server dynamic-dns[-detail]` and
// `show services dynamic-dns[-detail]` are priced at PermView and printed the
// DDNS update-server verbatim, while show configuration, String and
// MarshalJSON all redact the same field. A userinfo-bearing value reached
// read-only clients and command-output logs.
func TestShowDDNSUpdateServerIsRedacted_9497(t *testing.T) {
	const secret = "s3cr3t"
	cred := "user:" + secret + "@dns.example.com"

	dhcp := func(update string) *config.Config {
		cfg := &config.Config{}
		cfg.System.DHCPServer.DynamicDNS = &config.DHCPDynamicDNSConfig{Enabled: true, UpdateServer: update, TSIGKeyName: "k1"}
		return cfg
	}
	svc := func(update string) *config.Config {
		cfg := &config.Config{}
		cfg.System.Services = &config.SystemServicesConfig{DynamicDNS: &config.DDNSServicesConfig{
			Providers: map[string]*config.DDNSProvider{"p1": {Name: "p1", UpdateServer: update}},
		}}
		return cfg
	}
	s := &Server{}
	for _, detail := range []bool{false, true} {
		for _, surface := range []struct {
			name   string
			render func(cfg *config.Config, buf *strings.Builder)
			build  func(string) *config.Config
		}{
			{"dhcp-server dynamic-dns", func(c *config.Config, b *strings.Builder) { s.showDHCPDynamicDNS(c, b, detail) }, dhcp},
			{"services dynamic-dns", func(c *config.Config, b *strings.Builder) { s.showServicesDynamicDNS(c, b, detail) }, svc},
		} {
			var buf strings.Builder
			surface.render(surface.build(cred), &buf)
			out := buf.String()
			if strings.Contains(out, secret) {
				t.Errorf("#9497: %s (detail=%v) leaked the update-server credential:\n%s", surface.name, detail, out)
			}
			if !strings.Contains(out, "<redacted>@dns.example.com") {
				t.Errorf("%s (detail=%v): expected the redacted update-server with its host kept:\n%s", surface.name, detail, out)
			}
			// CONTROL: a clean host:port renders unchanged, so redaction is not
			// hiding the field altogether.
			var clean strings.Builder
			surface.render(surface.build("ns1.example.com:53"), &clean)
			if !strings.Contains(clean.String(), "ns1.example.com:53") {
				t.Errorf("%s (detail=%v): a clean host:port update-server must render unchanged:\n%s", surface.name, detail, clean.String())
			}
		}
	}
}
