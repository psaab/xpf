package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func staticNATLenientConfig9988(t *testing.T, matchPort, mappedPort string) *config.Config {
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
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// TestBuildStaticNATSnapshotNonNumericMatchPortFailsClosed9988 is
// RED-on-revert: before #9988, the invalid token is discarded to 0 and the
// builder emits a whole-address snapshot instead of dropping the rule.
func TestBuildStaticNATSnapshotNonNumericMatchPortFailsClosed9988(t *testing.T) {
	for _, tc := range []struct {
		name, token, mapped string
	}{
		{name: "http", token: "http"},
		{name: "http-with-mapped-port", token: "http", mapped: "443"},
		{name: "443-444", token: "443-444"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := staticNATLenientConfig9988(t, tc.token, tc.mapped)
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.MatchDestinationPort != 0 {
				t.Fatalf("precondition: malformed token should not parse as a port, got %d", rule.MatchDestinationPort)
			}
			snaps := buildStaticNATSnapshots(cfg, nil)
			if len(snaps) != 0 {
				t.Fatalf("non-numeric destination-port %q widened to %d snapshot(s): %+v; want fail-closed drop (warnings=%s)",
					tc.token, len(snaps), snaps, strings.Join(cfg.Warnings, " | "))
			}
		})
	}
}

// TestBuildStaticNATSnapshotNumericMatchPortUnaffected9988 is the numeric
// positive control for the fail-closed parser path.
func TestBuildStaticNATSnapshotNumericMatchPortUnaffected9988(t *testing.T) {
	cfg := staticNATLenientConfig9988(t, "443", "80")
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("numeric destination-port produced %d snapshots, want 1: %+v", len(snaps), snaps)
	}
	if snaps[0].MatchDestinationPort != 443 || snaps[0].MappedPort != 80 {
		t.Fatalf("numeric ports changed: match=%d mapped=%d, want 443/80",
			snaps[0].MatchDestinationPort, snaps[0].MappedPort)
	}
}

// TestBuildStaticNATSnapshotAbsentPortStillWildcard9988 is the explicit
// positive control: no destination-port statement remains a legitimate
// whole-address mapping and must not be dropped by the new invalid-token guard.
func TestBuildStaticNATSnapshotAbsentPortStillWildcard9988(t *testing.T) {
	cfg := staticNATLenientConfig9988(t, "", "")
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("absent destination-port produced %d snapshots, want 1: %+v", len(snaps), snaps)
	}
	if snaps[0].MatchDestinationPort != 0 || snaps[0].MappedPort != 0 {
		t.Fatalf("absent destination-port changed wildcard mapping: match=%d mapped=%d, want 0/0",
			snaps[0].MatchDestinationPort, snaps[0].MappedPort)
	}
}
