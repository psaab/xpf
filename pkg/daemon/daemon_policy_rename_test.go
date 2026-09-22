package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestZoneRenamePathRequiresTerminalSecurityZone(t *testing.T) {
	tests := []struct {
		name string
		path []string
		want string
		ok   bool
	}{
		{
			name: "full config path",
			path: []string{"security", "zones", "security-zone", "trust"},
			want: "trust",
			ok:   true,
		},
		{
			name: "nested leaf is not a zone rename",
			path: []string{"security", "zones", "security-zone", "trust", "interfaces", "ge-0/0/0.0"},
		},
		{
			name: "missing zone name",
			path: []string{"security", "zones", "security-zone"},
		},
		{
			name: "wrong parent",
			path: []string{"security", "zones", "zone", "trust"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := zoneRenamePath(tt.path)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("zoneRenamePath(%q) = (%q, %v), want (%q, %v)", tt.path, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestPolicyRulePathKeyRequiresTerminalPolicy(t *testing.T) {
	valid := []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "web"}
	if from, to, name, ok := policyRulePathKey(valid); !ok || from != "trust" || to != "untrust" || name != "web" {
		t.Fatalf("policyRulePathKey(%q) = (%q, %q, %q, %v), want trust/untrust/web/true", valid, from, to, name, ok)
	}
	nested := append(append([]string(nil), valid...), "match", "source-address")
	if _, _, _, ok := policyRulePathKey(nested); ok {
		t.Fatalf("policyRulePathKey(%q) accepted a nested policy leaf", nested)
	}
	global := []string{"security", "policies", "global", "policy", "web"}
	if from, to, name, ok := policyRulePathKey(global); !ok ||
		from != config.JunosGlobalZoneName || to != config.JunosGlobalZoneName || name != "web" {
		t.Fatalf("policyRulePathKey(%q) = (%q, %q, %q, %v), want global/global/web/true", global, from, to, name, ok)
	}
}

func TestRenameZoneWireIdentityKeepsSpecialScopesExplicit(t *testing.T) {
	zones := map[uint16]string{config.StableZoneID("trust"): "trust"}
	tests := []struct {
		name string
		zone string
		id   uint16
		any  bool
		ok   bool
	}{
		{name: "concrete", zone: "trust", id: config.StableZoneID("trust"), ok: true},
		{name: "wildcard", zone: "any", any: true, ok: true},
		{name: "global", zone: config.JunosGlobalZoneName, id: ^uint16(0), ok: true},
		{name: "host", zone: "junos-host", id: config.ZoneIDReservedMin, ok: true},
		{name: "unknown concrete", zone: "missing", id: config.StableZoneID("missing")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, any, ok := renameZoneWireIdentity(tt.zone, zones)
			if id != tt.id || any != tt.any || ok != tt.ok {
				t.Fatalf("renameZoneWireIdentity(%q) = (%d, %v, %v), want (%d, %v, %v)", tt.zone, id, any, ok, tt.id, tt.any, tt.ok)
			}
		})
	}
}
