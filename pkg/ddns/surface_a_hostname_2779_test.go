package ddns

// #2779 cross-package contract: the commit-time hostname validator
// (config.ValidateDDNSHostname) and the Surface A publish-path sanitizer
// (surfaceAName -> sanitizeFQDN) must agree about which operator hostnames are
// silently rewritten.
//
//   - Every name the validator ACCEPTS must be a FIXED POINT of the sanitizer
//     (modulo lower-casing + a single trailing-dot strip, both benign DNS
//     canonicalizations) — so a name that commits is published as the operator
//     typed it, never a different DNS name.
//   - Every name the validator REJECTS must actually be CHANGED by the
//     sanitizer — so the commit error fires exactly on the silent-rewrite set,
//     not on harmless input.
//
// This binds the two packages so a future drift in either the validator or the
// sanitizer (e.g. sanitize starts mapping a new character) breaks the build's
// tests rather than silently reintroducing the publish-wrong-name bug.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// canonicalIntent is the only transform the publish path may legitimately
// apply to an operator name: lower-case + strip a single trailing dot.
func canonicalIntent(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func TestSurfaceAHostname_2779_ValidatorAgreesWithSanitizer(t *testing.T) {
	accepted := []string{
		"wan.example.net",
		"wan1.example.net",
		"a.b.c.example.com",
		"host-01.sub.example.org",
		"WAN.Example.NET",
		"wan.example.net.",
		"bare-label",
	}
	rewritten := []string{
		"wan_1.example.net",
		"wan@1.example.net",
		"wan 1.example.net",
		"wan..example.net",
		".example.net",
		"-wan.example.net",
		"wan-.example.net",
	}

	for _, h := range accepted {
		if err := config.ValidateDDNSHostname(h); err != nil {
			t.Errorf("validator rejected accepted name %q: %v", h, err)
			continue
		}
		// A validator-accepted name must be a sanitizer fixed point: the
		// published form equals the operator's canonical intent.
		got := surfaceAName(h)
		want := canonicalIntent(h)
		if got != want {
			t.Errorf("accepted name %q: publish path rewrote it to %q (want %q) — "+
				"validator accepted a name the sanitizer changes", h, got, want)
		}
	}

	for _, h := range rewritten {
		// The validator must reject every name the sanitizer would change.
		if err := config.ValidateDDNSHostname(h); err == nil {
			t.Errorf("validator accepted name %q that the publish path rewrites", h)
		}
		// And confirm the publish path really does change it (so the reject is
		// guarding a real silent rewrite, not a phantom).
		if got := surfaceAName(h); got == canonicalIntent(h) {
			t.Errorf("name %q: expected the sanitizer to change it, but it is a "+
				"fixed point (%q) — reject case is stale", h, got)
		}
	}
}
