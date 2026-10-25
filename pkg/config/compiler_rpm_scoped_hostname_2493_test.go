package config

import (
	"strings"
	"testing"
)

// TestRPMScopedHostnameAccepted pins the #2614 change: a HOSTNAME target on
// a SCOPED test (routing-instance or destination-interface) is now ACCEPTED
// at commit. The #2493 gate that rejected this combination was removed
// because the runtime resolver now binds the DNS socket to the probe's
// VRF/path scope (rpm.resolveProbeTarget / probeDialer.Resolver use the
// same SO_BINDTODEVICE / SO_MARK as the probe socket), so the hostname
// resolves in-context instead of escaping the scope.
//
// fail-on-revert: restoring validateRPMScopedHostnameStrict to the commit
// pipeline turns these CompileConfig calls red again.
func TestRPMScopedHostnameAccepted(t *testing.T) {
	cases := []struct {
		name  string
		scope string // the scoping set-line tail
	}{
		{"routing-instance", "set services rpm probe P test t routing-instance ISP-B"},
		{"destination-interface", "set services rpm probe P test t destination-interface ge-0/0/1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set routing-instances ISP-B instance-type virtual-router",
				"set services rpm probe P test t probe-type icmp-ping",
				"set services rpm probe P test t target example.com",
				tc.scope,
			}
			tree := buildTree(t, lines)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("scoped hostname target must be accepted (#2614): %v", err)
			}
		})
	}
}

// TestRPMNextHopHostnameStillRejected confirms the next-hop pin still
// requires an IP-literal target — this is enforced by validateRPMTest (the
// pinned <target>/32 route via <next-hop> needs an IP-literal of the same
// family), NOT the removed #2493 scoped-hostname gate. The #2614 VRF-bound
// resolver does not change next-hop pinning, so this rejection is unchanged.
func TestRPMNextHopHostnameStillRejected(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target example.com",
		"set services rpm probe P test t destination-interface ge-0/0/1",
		"set services rpm probe P test t next-hop 10.0.0.1",
	}
	tree := buildTree(t, lines)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted next-hop hostname target; want reject (pin needs IP literal)")
	}
	if !strings.Contains(err.Error(), "next-hop pinning requires an IP-literal target") {
		t.Fatalf("err = %v, want substring %q", err, "next-hop pinning requires an IP-literal target")
	}
}

// TestRPMScopedHostnameLenientNoWarn confirms the lenient load / peer-sync
// path also accepts the scoped hostname with NO downgraded warning — the
// gate (and its warning) was removed entirely in #2614.
func TestRPMScopedHostnameLenientNoWarn(t *testing.T) {
	lines := []string{
		"set routing-instances ISP-B instance-type virtual-router",
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target example.com",
		"set services rpm probe P test t routing-instance ISP-B",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must accept scoped hostname: %v", err)
	}
	if hasWarningSubstr(cfg.Warnings, "rpm scoped hostname") {
		t.Fatalf("scoped-hostname warning should be gone (#2614), warnings=%v", cfg.Warnings)
	}
}

// TestRPMScopedIPLiteralAccepted confirms an IP-literal target on a scoped
// test stays accepted — the legitimate scoped-probe shape used for
// multi-WAN path health (no resolution involved).
func TestRPMScopedIPLiteralAccepted(t *testing.T) {
	t.Run("routing-instance + IP literal accepted", func(t *testing.T) {
		lines := []string{
			"set routing-instances ISP-B instance-type virtual-router",
			"set services rpm probe P test t probe-type icmp-ping",
			"set services rpm probe P test t target 8.8.8.8",
			"set services rpm probe P test t routing-instance ISP-B",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("scoped IP-literal target must be accepted: %v", err)
		}
	})

	t.Run("destination-interface + IPv6 literal accepted", func(t *testing.T) {
		lines := []string{
			"set services rpm probe P test t probe-type icmp-ping",
			"set services rpm probe P test t target 2001:db8::1",
			"set services rpm probe P test t destination-interface ge-0/0/1",
		}
		tree := buildTree(t, lines)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("scoped IPv6-literal target must be accepted: %v", err)
		}
	})
}

// TestRPMUnscopedHostnameAccepted confirms NO regression: a hostname target
// on an UNSCOPED (default-context) test stays accepted.
func TestRPMUnscopedHostnameAccepted(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type icmp-ping",
		"set services rpm probe P test t target example.com",
	}
	tree := buildTree(t, lines)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("unscoped hostname target must be accepted (no regression): %v", err)
	}
}
