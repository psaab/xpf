package config

import (
	"strings"
	"testing"
)

// staticNATMatchPortTree9988 builds a host static-NAT rule with an optional
// destination-port and mapped-port. Flat set syntax must use ParseSetCommand +
// SetPath, matching the production ingress path.
func staticNATMatchPortTree9988(t *testing.T, matchPort, mappedPort string) *ConfigTree {
	t.Helper()
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs9988 from zone untrust",
		"set security nat static rule-set rs9988 rule r9988 match destination-address 203.0.113.10/32",
	}
	if matchPort != "" {
		lines = append(lines, "set security nat static rule-set rs9988 rule r9988 match destination-port "+matchPort)
	}
	then := "set security nat static rule-set rs9988 rule r9988 then static-nat prefix 10.0.0.5/32"
	if mappedPort != "" {
		then += " mapped-port " + mappedPort
	}
	lines = append(lines, then)
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// TestStaticNATNonNumericMatchPortRejectedByName9988 is RED-on-revert: before
// #9988, Atoi failure leaves the match port at its zero wildcard sentinel, so
// CompileConfig accepts the rule without naming the authored token.
func TestStaticNATNonNumericMatchPortRejectedByName9988(t *testing.T) {
	for _, token := range []string{"http", "443-444"} {
		t.Run(token, func(t *testing.T) {
			_, err := CompileConfig(staticNATMatchPortTree9988(t, token, ""))
			if err == nil {
				t.Fatalf("CompileConfig accepted non-numeric destination-port %q", token)
			}
			if !strings.Contains(err.Error(), token) {
				t.Fatalf("error %q does not name non-numeric destination-port %q", err, token)
			}
		})
	}
}

// TestStaticNATNonNumericMatchPortLenientWarns9988 proves the tolerant
// load/peer-sync path keeps booting while surfacing the raw token. The
// mapped-port variant also guards against a contradictory missing-map warning.
func TestStaticNATNonNumericMatchPortLenientWarns9988(t *testing.T) {
	for _, tc := range []struct {
		name, token, mapped string
	}{
		{name: "http", token: "http"},
		{name: "http-with-mapped-port", token: "http", mapped: "443"},
		{name: "443-444", token: "443-444"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(staticNATMatchPortTree9988(t, tc.token, tc.mapped))
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected %q: %v", tc.token, err)
			}
			found := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, tc.token) {
					found = true
				}
				if tc.mapped != "" && strings.Contains(warning, "requires a matching") {
					t.Fatalf("mapped-port warning contradicts invalid match exclusion: %q", warning)
				}
			}
			if !found {
				t.Fatalf("lenient warnings %q do not name non-numeric destination-port %q", cfg.Warnings, tc.token)
			}
		})
	}
}

// TestStaticNATNumericMatchPortUnaffected9988 is the numeric positive control.
func TestStaticNATNumericMatchPortUnaffected9988(t *testing.T) {
	cfg, err := CompileConfig(staticNATMatchPortTree9988(t, "443", "80"))
	if err != nil {
		t.Fatalf("CompileConfig rejected numeric destination-port: %v", err)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.MatchDestinationPort != 443 || rule.MappedPort != 80 {
		t.Fatalf("numeric ports changed: match=%d mapped=%d, want 443/80",
			rule.MatchDestinationPort, rule.MappedPort)
	}
}
