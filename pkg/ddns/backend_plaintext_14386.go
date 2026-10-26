package ddns

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_plaintext_14386.go: runtime belt for #14386 (DR6-H2). The compiler
// drops credentialed plaintext providers on lenient load and hard-rejects
// them on strict commit, but a backend constructed directly (bypassing the
// compiler) must not issue a cleartext request carrying a credential either.
// Refusal happens at construction so the manager degrades to the no-op
// backend and no request is ever issued.
// Credential classification at construction and issuance delegates to
// config.DDNSCredentialBearing and config.DDNSCredentialBearingFields.
//
// Loopback endpoints (127.0.0.0/8, ::1, "localhost") are exempt for test
// harnesses such as httptest, which can only serve its local HTTP listener.
// Production configuration rejects credentialed plaintext providers during
// compilation (or drops them on lenient load) before any backend is built.
// Non-loopback http:// endpoints carrying any credential form are refused.

// plaintextEndpointRefusal returns a refusal error when rawURL is an
// explicit non-https URL to a non-loopback host. The error never echoes the
// credential: it renders through config.RedactURL.
func plaintextEndpointRefusal(backend, name, rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil // malformed URLs are rejected by the caller's own validation
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return nil // https (or scheme-less, composed over https) is fine
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("ddns %s: provider %q endpoint %q must be an https:// endpoint — refusing to transmit the update credential in cleartext (#14386)",
		backend, name, config.RedactURL(rawURL))
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
		return addr.IsLoopback()
	}
	return false
}
