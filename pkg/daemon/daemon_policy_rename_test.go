package daemon

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
	"golang.org/x/sync/semaphore"
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

func policyRenameEvaluatorConfig(ruleName string, action config.PolicyAction) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan":   {Name: "lan"},
		"other": {Name: "other"},
		"wan":   {Name: "wan"},
	}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.PolicyRematchExtensive = true
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "other",
			ToZone:   "wan",
			Policies: []*config.Policy{{Name: "p-seed", Action: config.PolicyDeny}},
		},
		{
			FromZone: "lan",
			ToZone:   "wan",
			Policies: []*config.Policy{
				{Name: ruleName, Action: action},
				{Name: "p-alternate", Action: config.PolicyPermit},
			},
		},
	}
	return cfg
}

func policyRenameDescriptor(source, destination string) configstore.RenameDescriptor {
	return configstore.RenameDescriptor{
		SourcePath: []string{
			"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", source,
		},
		DestinationPath: []string{
			"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", destination,
		},
	}
}

func policyZoneDescriptor(source, destination string) configstore.RenameDescriptor {
	return configstore.RenameDescriptor{
		SourcePath:      []string{"security", "zones", "security-zone", source},
		DestinationPath: []string{"security", "zones", "security-zone", destination},
	}
}

// zoneRenameEvaluatorConfigs returns old/new configs differing only by a
// lan->lan2 zone rename (zone map + lan->wan policy pairs rewritten,
// rule names and content identical so fingerprints match).
func zoneRenameEvaluatorConfigs() (oldCfg, newCfg *config.Config) {
	oldCfg = policyRenameEvaluatorConfig("p", config.PolicyPermit)
	newCfg = policyRenameEvaluatorConfig("p", config.PolicyPermit)
	newCfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan2":  {Name: "lan2"},
		"other": {Name: "other"},
		"wan":   {Name: "wan"},
	}
	for _, pair := range newCfg.Security.Policies {
		if pair.FromZone == "lan" {
			pair.FromZone = "lan2"
		}
		if pair.ToZone == "lan" {
			pair.ToZone = "lan2"
		}
	}
	return oldCfg, newCfg
}

// N3a: zone-descriptor expansion — the fan-out over policy identities
// touching the renamed zone. Each reject branch below fails closed (!ok);
// the happy path yields one pair per touching identity with wire IDs.
func TestExpandZoneRenameEvaluator10592(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		oldCfg, newCfg := zoneRenameEvaluatorConfigs()
		bindings, wire, ok := expandPolicyRenameAncestry(
			oldCfg, newCfg, []configstore.RenameDescriptor{policyZoneDescriptor("lan", "lan2")},
		)
		if !ok {
			t.Fatal("valid zone rename was rejected")
		}
		// Two lan-touching identities (p, p-alternate); p-seed (other->wan)
		// does not fan out.
		if len(bindings) != 2 || len(wire) != 2 {
			t.Fatalf("want 2 bindings+wire rows, got %d+%d", len(bindings), len(wire))
		}
		for _, w := range wire {
			if w.SourceFromZone != "lan" || w.DestinationFromZone != "lan2" {
				t.Fatalf("wire row misattributes zones: %+v", w)
			}
			if w.SourceFromZoneID != config.StableZoneID("lan") ||
				w.DestinationFromZoneID != config.StableZoneID("lan2") {
				t.Fatalf("wire row misattributes zone IDs: %+v", w)
			}
		}
	})
	t.Run("malformed", func(t *testing.T) {
		oldCfg, newCfg := zoneRenameEvaluatorConfigs()
		bad := configstore.RenameDescriptor{
			SourcePath:      []string{"security", "zones", "security-zone", "lan"},
			DestinationPath: []string{"security", "zones", "security-zone"},
		}
		if _, _, ok := expandPolicyRenameAncestry(oldCfg, newCfg, []configstore.RenameDescriptor{bad}); ok {
			t.Fatal("malformed zone descriptor was accepted")
		}
	})
	t.Run("self", func(t *testing.T) {
		oldCfg, newCfg := zoneRenameEvaluatorConfigs()
		if _, _, ok := expandPolicyRenameAncestry(oldCfg, newCfg, []configstore.RenameDescriptor{policyZoneDescriptor("lan", "lan")}); ok {
			t.Fatal("self zone rename was accepted")
		}
	})
	t.Run("untouched", func(t *testing.T) {
		oldCfg, newCfg := zoneRenameEvaluatorConfigs()
		// dmz exists in neither config's policies: no identity fans out.
		if _, _, ok := expandPolicyRenameAncestry(oldCfg, newCfg, []configstore.RenameDescriptor{policyZoneDescriptor("dmz", "dmz2")}); ok {
			t.Fatal("untouched zone rename was accepted")
		}
	})
}

// N3b: default-permit must never retain a renamed session through the
// evaluator. A renamed-away query falls to the default path (Matched=false,
// PolicyID 0 — never the sentinel, which no configured rule carries per
// #9584), rejected by permittedRenameResult's first gate. Only a matched
// non-sentinel permit retains.
func TestPermittedRenameResultRejectsDefaultPermit10592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	newCfg.Security.DefaultPolicy = config.PolicyPermit
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding, ok := bindings[oldID]
	if !ok {
		t.Fatalf("missing binding for old policy id %d", oldID)
	}
	t.Run("default-path", func(t *testing.T) {
		// No pair covers other->lan: falls to default-permit, must not retain.
		q := policymatch.Query{FromZone: "other", ToZone: "lan", DstPort: 9999}
		if _, permitted := permittedRenameResult(newCfg, binding, q); permitted {
			t.Fatal("default-permit fallback retained a renamed session")
		}
	})
	t.Run("other-pair", func(t *testing.T) {
		// Matches p-seed (Deny) on other->wan, not the renamed rule.
		q := policymatch.Query{FromZone: "other", ToZone: "wan", DstPort: 443}
		if _, permitted := permittedRenameResult(newCfg, binding, q); permitted {
			t.Fatal("non-renamed pair retained through the evaluator")
		}
	})
	t.Run("renamed-permit-control", func(t *testing.T) {
		q := policymatch.Query{FromZone: "lan", ToZone: "wan", DstPort: 443}
		record, permitted := permittedRenameResult(newCfg, binding, q)
		if !permitted {
			t.Fatal("renamed permit was not retained")
		}
		if record.RuleID != "lan->wan/p-new" {
			t.Fatalf("retained wrong rule: %+v", record)
		}
		if record.PolicyID == dataplane.DefaultPolicySentinelID || record.PolicyID == 0 {
			t.Fatalf("retained sentinel/zero policy id: %+v", record)
		}
	})
}

// N3d: port byte-order through the rematch path. networkPort converts
// between wire (network) and host order; the rematch query AND the recorded
// row must both carry host-order ports. Cells: unit + v4/v6 record-exactness
// + v4/v6 port-scoped query + v4 DNAT translated-port query (v6-DNAT-port is
// textually identical modulo address width, and v6-DNAT address handling is
// pinned by the 10511 DNAT test).
func TestNetworkPortByteOrder10592(t *testing.T) {
	if got := networkPort(0x1234); got != 0x3412 {
		t.Fatalf("networkPort(0x1234) = %#x, want 0x3412", got)
	}
	for _, port := range []uint16{0, 1, 80, 443, 8443, 0xFFFF} {
		if got := networkPort(uint16(networkPort(port))); got != int(port) {
			t.Fatalf("networkPort round-trip of %d gave %d", port, got)
		}
	}
}

func TestRematchRenamedV4PreservesPortsExactly10592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	// Wire-native ports (BPF yields network bytes read natively: host 0x1234
	// arrives as 0x3412); the record must carry host order.
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 0x3412, DstPort: 0x0015, Protocol: 6,
	}
	value := dataplane.SessionValue{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
	}
	record, permitted := rematchRenamedV4(oldCfg, newCfg, bindings[oldID], key, value)
	if !permitted {
		t.Fatal("matching renamed session was not retained")
	}
	// Distinctive non-palindromic ports: dropping the record conversion reds.
	// Query-side reverts stay green under match-any (pinned instead by the
	// port-scoped cell below, which fails when the query consult breaks).
	if record.SrcPort != 0x1234 || record.DstPort != 0x1500 {
		t.Fatalf("record ports not exact host order: got %d/%d", record.SrcPort, record.DstPort)
	}
}

func TestRematchRenamedV6PreservesPortsExactly10592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	key := dataplane.SessionKeyV6{
		SrcIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a},
		DstIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14},
		SrcPort: 0x3412, DstPort: 0x0015, Protocol: 6,
	}
	value := dataplane.SessionValueV6{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
	}
	record, permitted := rematchRenamedV6(oldCfg, newCfg, bindings[oldID], key, value)
	if !permitted {
		t.Fatal("matching renamed v6 session was not retained")
	}
	if record.SrcPort != 0x1234 || record.DstPort != 0x1500 {
		t.Fatalf("v6 record ports not exact host order: got %d/%d", record.SrcPort, record.DstPort)
	}
}

func TestRematchRenamedV4DNATPortQueriesTranslatedRecordsWire10592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses =
			[]string{"10.0.0.1/32", "2001:db8::30/128"}
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	// Wire-native ports (see above): the record must carry host order.
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 0x3412, DstPort: 0x0015, Protocol: 6,
	}
	value := dataplane.SessionValue{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		Flags: dataplane.SessFlagDNAT, NATDstIP: 0x0100000a, NATDstPort: userspaceHostToNetwork16(8443),
	}
	record, permitted := rematchRenamedV4(oldCfg, newCfg, bindings[oldID], key, value)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("DNAT row not rematched through renamed permit: %+v permitted=%v", record, permitted)
	}
	// The QUERY consults the translated port, but the RECORD carries the
	// wire ports. Dropping the record conversion reds this assert; dropping
	// the translated-port consult is pinned by the scoped DNAT cell below.
	if record.SrcPort != 0x1234 || record.DstPort != 0x1500 {
		t.Fatalf("DNAT record carries translated ports instead of wire: got %d/%d", record.SrcPort, record.DstPort)
	}
}

// N3e: permittedRenameResult accepts ANY non-sentinel permit (no
// RuleID==destination check), and `any` wire identity is parser-only. A
// renamed-away query served by an alternate permit retains under the
// alternate's identity; removing the alternate (default-deny) retains nothing.
func TestPermittedRenameResultAnyPermitAlternate10592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	// Scope the renamed rule identically in both generations (fingerprints
	// must match for expand): only 10.0.0.1/32. Queries outside the scope
	// miss it and fall to p-alternate (match-any Permit).
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses = []string{"10.0.0.1/32"}
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding, ok := bindings[oldID]
	if !ok {
		t.Fatalf("missing binding for old policy id %d", oldID)
	}
	// Outside the renamed scope: served by p-alternate. Assert the RETURNED
	// identity names the alternate, proving no RuleID==destination restriction.
	q := policymatch.Query{FromZone: "lan", ToZone: "wan", DstIP: net.ParseIP("10.0.0.20"), DstPort: 444}
	record, permitted := permittedRenameResult(newCfg, binding, q)
	if !permitted {
		t.Fatal("alternate permit did not retain")
	}
	if record.RuleID != "lan->wan/p-alternate" {
		t.Fatalf("retained wrong rule identity: %+v", record)
	}
	if record.PolicyID == 0 || record.PolicyID == dataplane.DefaultPolicySentinelID {
		t.Fatalf("retained zero/sentinel policy id: %+v", record)
	}
}

func TestPermittedRenameResultAlternateRemovedDenies10592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	// Scope the renamed rule to 10.0.0.1/32 in both generations (fingerprints
	// must match for expand), then remove the alternate: the 10.0.0.20 query
	// below misses the renamed rule and, with no alternate, falls to
	// default-deny. Reverting the removal (keeping alternate) retains.
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses = []string{"10.0.0.1/32"}
	}
	newCfg.Security.Policies[1].Policies = newCfg.Security.Policies[1].Policies[:1]
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding, ok := bindings[oldID]
	if !ok {
		t.Fatalf("missing binding for old policy id %d", oldID)
	}
	q := policymatch.Query{FromZone: "lan", ToZone: "wan", DstIP: net.ParseIP("10.0.0.20"), DstPort: 444}
	if _, permitted := permittedRenameResult(newCfg, binding, q); permitted {
		t.Fatal("query retained without the alternate permit")
	}
}

// N3e-expand: a rename pair scoped to from-zone "any" expands with the
// *ZoneAny wire flags set (renameZoneWireIdentity short-circuits "any" to
// id 0 + any=true without consulting the zone map).
func TestExpandAnyZoneRenameSetsWireAnyFlags10592(t *testing.T) {
	mkCfg := func(rule string) *config.Config {
		cfg := &config.Config{}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"wan": {Name: "wan"},
		}
		cfg.Security.DefaultPolicy = config.PolicyDeny
		cfg.Security.PolicyRematchExtensive = true
		cfg.Security.Policies = []*config.ZonePairPolicies{
			{
				FromZone: "any",
				ToZone:   "wan",
				Policies: []*config.Policy{{Name: rule, Action: config.PolicyPermit}},
			},
		}
		return cfg
	}
	oldCfg, newCfg := mkCfg("p-old"), mkCfg("p-new")
	desc := configstore.RenameDescriptor{
		SourcePath:      []string{"security", "policies", "from-zone", "any", "to-zone", "wan", "policy", "p-old"},
		DestinationPath: []string{"security", "policies", "from-zone", "any", "to-zone", "wan", "policy", "p-new"},
	}
	_, wire, ok := expandPolicyRenameAncestry(oldCfg, newCfg, []configstore.RenameDescriptor{desc})
	if !ok || len(wire) != 1 {
		t.Fatalf("any-zone rename rejected: wire=%v ok=%v", wire, ok)
	}
	w := wire[0]
	if !w.SourceFromZoneAny || w.SourceFromZoneID != 0 {
		t.Fatalf("any from-zone not flagged on the wire: %+v", w)
	}
	if w.SourceToZoneAny || w.DestinationToZoneAny {
		t.Fatalf("non-any legs misflagged: %+v", w)
	}
	if !w.DestinationFromZoneAny {
		t.Fatalf("destination any from-zone not flagged: %+v", w)
	}
}

// N3f: expandPolicyRenameAncestry validator table — every reachable reject
// branch fails closed (!ok, nil, nil) on its trigger, and only its trigger.
// Row order follows source order (:108 → :220). Fingerprint + dup-source are
// covered by the existing 10511 ambiguous-proof test (not duplicated here);
// zero-pairs (:164) by the N3a untouched cell. :117 (empty fingerprints with
// non-empty IDs) is defensive-only: IDs and fingerprints diverge solely on
// snapshot-builder errors (scheduler/feed resolution, JSON), uncraftable via
// config shapes (probed: inactive schedulers + unresolvable feed names still
// yield fingerprints).
// findStableZoneIDCollision brute-forces any StableZoneID collision (u16
// space: found in milliseconds) so collision cells stay self-maintaining
// across hash changes — no magic constants.
func findStableZoneIDCollision(t *testing.T) (string, string) {
	t.Helper()
	for i := 0; i < 100000; i++ {
		a := "zone-a-" + string(rune(i))
		for j := i + 1; j < 100000; j++ {
			b := "zone-b-" + string(rune(j))
			if config.StableZoneID(a) == config.StableZoneID(b) {
				return a, b
			}
		}
	}
	t.Fatal("no collision found in brute-force window")
	return "", ""
}

func TestExpandValidatorsRejectBranchTable10592(t *testing.T) {
	collideA, collideB := findStableZoneIDCollision(t)
	fresh := func() (oldCfg, newCfg *config.Config) {
		return policyRenameEvaluatorConfig("p-old", config.PolicyPermit),
			policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	}
	tests := []struct {
		name  string
		build func() (old, new *config.Config, desc []configstore.RenameDescriptor)
	}{
		{"nil-descriptors", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			return o, n, nil
		}},
		{"nil-old", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			_, n := fresh()
			return nil, n, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")}
		}},
		{"nil-new", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, _ := fresh()
			return o, nil, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")}
		}},
		{"empty-policies", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			o.Security.Policies = nil
			return o, n, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")}
		}},
		{"empty-policies-new", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			n.Security.Policies = nil
			return o, n, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")}
		}},
		{"zone-collision", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			o.Security.Zones[collideA] = &config.ZoneConfig{Name: collideA}
			o.Security.Zones[collideB] = &config.ZoneConfig{Name: collideB}
			return o, n, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")}
		}},
		{"half-policy", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			mixed := configstore.RenameDescriptor{
				SourcePath:      []string{"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", "p-old"},
				DestinationPath: []string{"security", "zones", "security-zone", "lan2"},
			}
			return o, n, []configstore.RenameDescriptor{mixed}
		}},
		{"malformed-both", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			garbage := configstore.RenameDescriptor{
				SourcePath:      []string{"security", "nonsense"},
				DestinationPath: []string{"security", "nonsense"},
			}
			return o, n, []configstore.RenameDescriptor{garbage}
		}},
		{"unknown-zone", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			ghost := configstore.RenameDescriptor{
				SourcePath:      []string{"security", "policies", "from-zone", "ghost", "to-zone", "wan", "policy", "p-old"},
				DestinationPath: []string{"security", "policies", "from-zone", "ghost", "to-zone", "wan", "policy", "p-new"},
			}
			return o, n, []configstore.RenameDescriptor{ghost}
		}},
		{"missing-source", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			return o, n, []configstore.RenameDescriptor{policyRenameDescriptor("p-ghost", "p-new")}
		}},
		{"missing-destination", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			return o, n, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-ghost")}
		}},
		{"policy-self", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
			n := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
			return o, n, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-old")}
		}},
		{"dup-destination", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			o, n := fresh()
			return o, n, []configstore.RenameDescriptor{
				policyRenameDescriptor("p-old", "p-new"),
				policyRenameDescriptor("p-alternate", "p-new"),
			}
		}},
		{"chain", func() (*config.Config, *config.Config, []configstore.RenameDescriptor) {
			mkPair := func(rule string) *config.Config {
				cfg := &config.Config{}
				cfg.Security.Zones = map[string]*config.ZoneConfig{
					"lan": {Name: "lan"}, "wan": {Name: "wan"},
				}
				cfg.Security.DefaultPolicy = config.PolicyDeny
				cfg.Security.PolicyRematchExtensive = true
				cfg.Security.Policies = []*config.ZonePairPolicies{{
					FromZone: "lan", ToZone: "wan",
					Policies: []*config.Policy{{Name: rule, Action: config.PolicyPermit}},
				}}
				return cfg
			}
			o := mkPair("p-old")
			o.Security.Policies = append(o.Security.Policies, &config.ZonePairPolicies{
				FromZone: "lan", ToZone: "wan",
				Policies: []*config.Policy{{Name: "p-mid", Action: config.PolicyPermit}},
			})
			n := mkPair("p-mid")
			n.Security.Policies = append(n.Security.Policies, &config.ZonePairPolicies{
				FromZone: "lan", ToZone: "wan",
				Policies: []*config.Policy{{Name: "p-new", Action: config.PolicyPermit}},
			})
			return o, n, []configstore.RenameDescriptor{
				policyRenameDescriptor("p-old", "p-mid"),
				policyRenameDescriptor("p-mid", "p-new"),
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old, new, desc := tc.build()
			bindings, wire, ok := expandPolicyRenameAncestry(old, new, desc)
			if ok || bindings != nil || wire != nil {
				t.Fatalf("expected fail-closed reject, got ok=%v bindings=%v wire=%v", ok, bindings, wire)
			}
		})
	}
}

// N3f-global: global-policy renames expand through the same validator
// (global/global pseudo-zones). Mismatch (destination absent) fails closed.
func TestExpandGlobalPolicyRename10592(t *testing.T) {
	mkGlobal := func(rule string) *config.Config {
		cfg := &config.Config{}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"lan": {Name: "lan"}, "wan": {Name: "wan"},
		}
		cfg.Security.DefaultPolicy = config.PolicyDeny
		cfg.Security.PolicyRematchExtensive = true
		cfg.Security.GlobalPolicies = []*config.Policy{{Name: rule, Action: config.PolicyPermit}}
		return cfg
	}
	gdesc := func(source, destination string) configstore.RenameDescriptor {
		return configstore.RenameDescriptor{
			SourcePath:      []string{"global", "policy", source},
			DestinationPath: []string{"global", "policy", destination},
		}
	}
	t.Run("happy", func(t *testing.T) {
		bindings, wire, ok := expandPolicyRenameAncestry(
			mkGlobal("g-old"), mkGlobal("g-new"),
			[]configstore.RenameDescriptor{gdesc("g-old", "g-new")},
		)
		if !ok || len(wire) != 1 {
			t.Fatalf("valid global rename rejected: wire=%v ok=%v", wire, ok)
		}
		// Global-only configs yield numeric ID 0 (PolicySetID 0 with no
		// zone-pair sets; with N sets globals get N*256+idx and DO bind), so
		// expand yields wire-only here by design (`if oldID != 0` skips the
		// binding). Whether global-only wire-only is intended is tracked in
		// #10621; this pins the current contract either way.
		if len(bindings) != 0 {
			t.Fatalf("global rename bound locally, want wire-only: %v", bindings)
		}
		if wire[0].SourceFromZone != config.JunosGlobalZoneName {
			t.Fatalf("global wire misattributes zones: %+v", wire[0])
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		_, _, ok := expandPolicyRenameAncestry(
			mkGlobal("g-old"), mkGlobal("g-other"),
			[]configstore.RenameDescriptor{gdesc("g-old", "g-new")},
		)
		if ok {
			t.Fatal("global rename with absent destination was accepted")
		}
	})
}

// N3f-collision: zoneNamesByID fails closed on StableZoneID collisions. The
// colliding pair is brute-forced at runtime (u16 space, instant) so the cell
// is self-maintaining across hash changes — no magic constants.
func TestZoneNamesByIDRejectsCollisions10592(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"}, "wan": {Name: "wan"},
	}
	if _, ok := zoneNamesByID(cfg); !ok {
		t.Fatal("distinct zones rejected")
	}
	first, second := findStableZoneIDCollision(t)
	cfg.Security.Zones[first] = &config.ZoneConfig{Name: first}
	cfg.Security.Zones[second] = &config.ZoneConfig{Name: second}
	if _, ok := zoneNamesByID(cfg); ok {
		t.Fatalf("colliding zones %q/%q accepted", first, second)
	}
}

// N3d-query: port-scoped rematch through the evaluator. The renamed rule
// admits only junos-https (TCP/443): 443 retains, 444 falls to default-deny.
// Dropping networkPort at the rematch query sites (:356/:389) breaks the
// app match (ports arrive network-order) and flips both directions.
// N3d-DNAT: the rematch query consults the TRANSLATED port for DNAT rows
// (daemon_policy_rename.go:360/:392), while the record keeps wire ports. The
// renamed rule admits only junos-https (TCP/443): a row translated to 443
// retains even though its wire port is 444; translated 444 denies. Dropping
// the translated-port consult queries wire 444 for both and flips retained→denied.
func TestRematchDNATTranslatedPortScoped10592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses = []string{"10.0.0.1/32"}
		cfg.Security.Policies[1].Policies[0].Match.Applications = []string{"junos-https"}
		cfg.Security.Policies[1].Policies = cfg.Security.Policies[1].Policies[:1]
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding := bindings[oldID]
	dnatRow := func(wirePort, xlatedPort uint16) (dataplane.SessionKey, dataplane.SessionValue) {
		key := dataplane.SessionKey{
			SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
			SrcPort: 40000, DstPort: wirePort, Protocol: 6,
		}
		value := dataplane.SessionValue{
			PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
			Flags: dataplane.SessFlagDNAT, NATDstIP: 0x0100000a, NATDstPort: xlatedPort,
		}
		return key, value
	}
	// Wire 444 (0xBC01), translated 443 (network order): query consults the
	// translation and matches junos-https.
	key, value := dnatRow(0xBC01, userspaceHostToNetwork16(443))
	record, permitted := rematchRenamedV4(oldCfg, newCfg, binding, key, value)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("translated-443 DNAT row not retained: %+v permitted=%v", record, permitted)
	}
	if record.DstPort != 444 {
		t.Fatalf("DNAT record must carry the host-order wire port (444 from 0xBC01), got %d", record.DstPort)
	}
	// Translated 444: no covering rule (alternate removed) → denied.
	key444, value444 := dnatRow(0xBC01, userspaceHostToNetwork16(444))
	if _, permitted := rematchRenamedV4(oldCfg, newCfg, binding, key444, value444); permitted {
		t.Fatal("translated-444 DNAT row retained despite no covering rule")
	}
}

func TestRematchPortScopedV4V610592(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.Applications = []string{"junos-https"}
		cfg.Security.Policies[1].Policies = cfg.Security.Policies[1].Policies[:1]
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding, ok := bindings[oldID]
	if !ok {
		t.Fatalf("missing binding for old policy id %d", oldID)
	}
	mkValue := func() dataplane.SessionValue {
		return dataplane.SessionValue{
			PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		}
	}
	// Wire-native ports (BPF yields network bytes read natively): host 443
	// arrives as 0xBB01, host 444 as 0xBC01. Dropping networkPort at the
	// rematch query sites (:356/:389) breaks the app match both ways.
	v4key := func(wirePort uint16) dataplane.SessionKey {
		return dataplane.SessionKey{
			SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
			SrcPort: 40000, DstPort: wirePort, Protocol: 6,
		}
	}
	if record, permitted := rematchRenamedV4(oldCfg, newCfg, binding, v4key(0xBB01), mkValue()); !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("v4 443 not retained through renamed junos-https: %+v permitted=%v", record, permitted)
	}
	if _, permitted := rematchRenamedV4(oldCfg, newCfg, binding, v4key(0xBC01), mkValue()); permitted {
		t.Fatal("v4 444 retained despite no covering rule")
	}
	v6key := func(wirePort uint16) dataplane.SessionKeyV6 {
		return dataplane.SessionKeyV6{
			SrcIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a},
			DstIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14},
			SrcPort: 40000, DstPort: wirePort, Protocol: 6,
		}
	}
	v6value := func() dataplane.SessionValueV6 {
		return dataplane.SessionValueV6{
			PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		}
	}
	if record, permitted := rematchRenamedV6(oldCfg, newCfg, binding, v6key(0xBB01), v6value()); !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("v6 443 not retained through renamed junos-https: %+v permitted=%v", record, permitted)
	}
	if _, permitted := rematchRenamedV6(oldCfg, newCfg, binding, v6key(0xBC01), v6value()); permitted {
		t.Fatal("v6 444 retained despite no covering rule")
	}
}

func TestExpandAndRematchPolicyRenameEvaluator10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	bindings, wire, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok || len(bindings) != 1 || len(wire) != 1 {
		t.Fatalf("valid policy rename was rejected: bindings=%v wire=%v ok=%v", bindings, wire, ok)
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding, ok := bindings[oldID]
	if !ok {
		t.Fatalf("missing binding for old policy id %d: %v", oldID, bindings)
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 0, 10},
		DstIP:    [4]byte{10, 0, 0, 20},
		SrcPort:  1234,
		DstPort:  443,
		Protocol: 6,
	}
	value := dataplane.SessionValue{
		PolicyID:    oldID,
		IngressZone: config.StableZoneID("lan"),
		EgressZone:  config.StableZoneID("wan"),
	}
	record, permitted := rematchRenamedV4(oldCfg, newCfg, binding, key, value)
	if !permitted {
		t.Fatal("matching renamed session was not retained")
	}
	if record.RuleID != "lan->wan/p-new" || record.PolicyID == 0 ||
		record.IngressZone != config.StableZoneID("lan") ||
		record.EgressZone != config.StableZoneID("wan") {
		t.Fatalf("renamed record lost identity: %+v", record)
	}
	if record.SrcIP != "10.0.0.10" || record.DstIP != "10.0.0.20" ||
		record.Protocol != 6 {
		t.Fatalf("renamed record lost tuple: %+v", record)
	}
}

func TestPolicyRenameEvaluatorHonorsInjectedSchedulerState10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldCfg.Security.Policies[1].Policies[0].SchedulerName = "all-day"
	newCfg.Security.Policies[1].Policies[0].SchedulerName = "all-day"
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	value := dataplane.SessionValue{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
	}
	binding := bindings[oldID]
	binding.policyInactiveFn = func(string) bool { return true }
	if _, permitted := rematchRenamedV4(oldCfg, newCfg, binding, key, value); permitted {
		t.Fatal("scheduler-inactive renamed policy was retained")
	}
	binding.policyInactiveFn = func(string) bool { return false }
	if _, permitted := rematchRenamedV4(oldCfg, newCfg, binding, key, value); !permitted {
		t.Fatal("scheduler-active renamed policy was not retained")
	}
}

func TestPolicyRenameEvaluatorHandlesDNATV4AndV6Rows10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	// Scope the renamed rule to the TRANSLATED dsts only: the wire dsts must
	// not match, so a revert that drops the DNAT-dst consult queries the wire
	// dst, misses, and fails this cell instead of passing on match-any.
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses =
			[]string{"10.0.0.1/32", "2001:db8::30/128"}
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding := bindings[oldID]
	v4Key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	v4Value := dataplane.SessionValue{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		Flags: dataplane.SessFlagDNAT, NATDstIP: 0x0100000a, NATDstPort: 8443,
	}
	record, permitted := rematchRenamedV4(oldCfg, newCfg, binding, v4Key, v4Value)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("DNAT v4 row was not rematched through the renamed permit: %+v permitted=%v", record, permitted)
	}
	// Fixture guard: without translation the wire tuple must NOT match the
	// renamed rule. If the scope above ever widens to cover it, this reds;
	// without it the positive assertion would pass vacuously on the wire.
	plainV4 := v4Value
	plainV4.Flags, plainV4.NATDstIP, plainV4.NATDstPort = 0, 0, 0
	if record, _ := rematchRenamedV4(oldCfg, newCfg, binding, v4Key, plainV4); record.RuleID == "lan->wan/p-new" {
		t.Fatalf("untranslated v4 wire tuple matched the renamed rule: %+v", record)
	}
	v6Key := dataplane.SessionKeyV6{
		SrcIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a},
		DstIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	v6Value := dataplane.SessionValueV6{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		Flags:      dataplane.SessFlagDNAT,
		NATDstIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30},
		NATDstPort: 8443,
	}
	record, permitted = rematchRenamedV6(oldCfg, newCfg, binding, v6Key, v6Value)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("DNAT v6 row was not rematched through the renamed permit: %+v permitted=%v", record, permitted)
	}
	plainV6 := v6Value
	plainV6.Flags, plainV6.NATDstPort = 0, 0
	plainV6.NATDstIP = [16]byte{}
	if record, _ := rematchRenamedV6(oldCfg, newCfg, binding, v6Key, plainV6); record.RuleID == "lan->wan/p-new" {
		t.Fatalf("untranslated v6 wire tuple matched the renamed rule: %+v", record)
	}
}

// Inbound NPTv6 populates decision.nat.rewrite_dst with the translated
// internal dst and no port rewrite
// (userspace-dp/src/afxdp/poll_descriptor/mod.rs, MissingNeighbor cold-path
// comment), and session flags derive solely from rewrite_src/rewrite_dst
// (bpf_map/mod.rs: no SESS_FLAG_NPTV6 exists on the helper; the Go constant is
// ABI width documentation only and nothing stamps it). So an NPTv6 row reaches
// the capture indistinguishable from DNAT — DNAT flag, translated NATDstIP,
// zero port — and rematches through the same translated-dst path. This cell
// pins that shape explicitly: dropping the DNAT-dst consult would fail to
// retain it, while a port-rewrite requirement would wrongly reject it.
func TestPolicyRenameEvaluatorRematchesNPTv6ShapedRow10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	// Scope the renamed rule to the translated internal dst: the public wire
	// dst must not match, so the cell reds unless the rematch consults the
	// translated dst carried on the DNAT channel.
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses =
			[]string{"fd00::20/128"}
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	key := dataplane.SessionKeyV6{
		SrcIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a},
		DstIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	value := dataplane.SessionValueV6{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		Flags:    dataplane.SessFlagDNAT,
		NATDstIP: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20},
	}
	record, permitted := rematchRenamedV6(oldCfg, newCfg, bindings[oldID], key, value)
	if !permitted {
		t.Fatal("NPTv6-shaped row (translated dst, no port rewrite) was not rematched")
	}
	if record.RuleID != "lan->wan/p-new" {
		t.Fatalf("NPTv6-shaped row rebound unexpected rule: %+v", record)
	}
	// Fixture guard: the same row without translation must NOT match the
	// renamed rule (it falls through to the alternate/default verdict). If
	// the scope above ever widens to cover the wire dst, this reds — without
	// it the positive assertion above would pass vacuously on the wire tuple.
	plain := value
	plain.Flags = 0
	plain.NATDstIP = [16]byte{}
	if record, _ := rematchRenamedV6(oldCfg, newCfg, bindings[oldID], key, plain); record.RuleID == "lan->wan/p-new" {
		t.Fatalf("untranslated wire tuple matched the renamed rule; the scope no longer discriminates: %+v", record)
	}
}

func TestPolicyRenameEvaluatorRejectsAmbiguousOrChangedProof10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	changed := policyRenameEvaluatorConfig("p-new", config.PolicyDeny)
	if bindings, wire, ok := expandPolicyRenameAncestry(
		oldCfg, changed, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	); ok || bindings != nil || wire != nil {
		t.Fatalf("fingerprint-changing rename was retained: bindings=%v wire=%v ok=%v", bindings, wire, ok)
	}
	duplicate := []configstore.RenameDescriptor{
		policyRenameDescriptor("p-old", "p-new"),
		policyRenameDescriptor("p-old", "p-alternate"),
	}
	if bindings, wire, ok := expandPolicyRenameAncestry(oldCfg, policyRenameEvaluatorConfig("p-new", config.PolicyPermit), duplicate); ok || bindings != nil || wire != nil {
		t.Fatalf("duplicate source ancestry was retained: bindings=%v wire=%v ok=%v", bindings, wire, ok)
	}
}

func TestRematchRenamedV4RejectsUnknownGREDiscriminator10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	value := dataplane.SessionValue{
		PolicyID:            oldID,
		IngressZone:         config.StableZoneID("lan"),
		EgressZone:          config.StableZoneID("wan"),
		TunnelDiscriminator: 0,
	}
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 47,
	}
	if _, permitted := rematchRenamedV4(oldCfg, newCfg, bindings[oldID], key, value); permitted {
		t.Fatal("GRE discriminator zero must fail closed because BPF omitted the discriminator")
	}
}

// Ownership of rename lineage transfers from the store to the daemon copy at
// bind time in commitWithGenBinding: the consumed store generation retires
// immediately, and no apply outcome — converged, terminally failed, or fatal
// — retains store-side state. Retiring only on success leaked one dead entry
// per failed rename commit: promotion already advanced the candidate past the
// consumed generation, and the mutation carry moves only the current
// generation's entry, so a retained entry is unreachable by every future
// commit (#10511 MIN-14). The daemon-side copy is the sole post-bind owner,
// retained for peer retry/reconnect and pruned by the next commit's bind.
func TestRenameAncestryOwnershipTransfersAtBindTime10511(t *testing.T) {
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"security zones security-zone lan",
		"security zones security-zone wan",
		"security policies default-policy deny-all",
		"security policies from-zone lan to-zone wan policy p-old match source-address any",
		"security policies from-zone lan to-zone wan policy p-old match destination-address any",
		"security policies from-zone lan to-zone wan policy p-old match application any",
		"security policies from-zone lan to-zone wan policy p-old then permit",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("initial Commit: %v", err)
	}
	oldActive := store.ActiveConfig()
	src := []string{"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", "p-old"}
	dst := []string{"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", "p-new"}
	if err := store.Rename(src, dst); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	_, candGen, err := store.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if got := store.PendingRenameAncestryForGeneration(candGen); len(got) != 1 {
		t.Fatalf("rename did not record exactly one lineage descriptor: %#v", got)
	}
	d := &Daemon{store: store, applyBodyForTest: func(*config.Config) {}}
	d.applySem = semaphore.NewWeighted(1)
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("applySem acquire: %v", err)
	}
	defer d.applySem.Release(1)
	oldActive, compiled, err := d.commitWithGenBinding(
		func(*config.Config) error { return nil },
		func(gen uint64) (*config.Config, error) { return store.CommitWithDescriptionGen("", gen) },
	)
	if err != nil {
		t.Fatalf("commitWithGenBinding: %v", err)
	}
	activeGen, _ := store.ActiveSnapshot()
	// The bind transferred ownership: the daemon holds the descriptors and
	// the store holds nothing — for this generation or any other.
	pending, ok := d.pendingRenameApplies[activeGen]
	if !ok || len(pending.descriptors) != 1 {
		t.Fatalf("bind did not transfer the descriptor to the daemon copy: %#v", d.pendingRenameApplies)
	}
	if got := store.PendingRenameAncestryForGeneration(candGen); len(got) != 0 {
		t.Fatalf("bind left the consumed store generation behind: %#v", got)
	}
	if got := store.PendingRenameAncestry(); len(got) != 0 {
		t.Fatalf("bind left store-side lineage behind: %#v", got)
	}
	// Every apply outcome retains the daemon copy and resurrects nothing
	// store-side: fatal (publication skipped), non-fatal tail error, success.
	for _, tc := range []struct {
		name     string
		applyErr error
		wantNil  bool
	}{
		{"fatal", dpuserspace.ErrPolicySchedulerProtocolIncompatible, true},
		{"non-fatal", errors.New("apply networkd config: simulated best-effort failure"), false},
		{"success", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.applyErrForTest = tc.applyErr
			got, err := d.applyAndSyncCommitted(oldActive, compiled, peerSyncNever)
			if tc.applyErr == nil && err != nil {
				t.Fatalf("converging apply returned %v", err)
			}
			if tc.applyErr != nil && err == nil {
				t.Fatal("failing apply returned nil; the retention below is untested")
			}
			if tc.wantNil && got != nil {
				t.Fatal("fatal apply must fail without a commit result")
			}
			if _, ok := d.pendingRenameApplies[activeGen]; !ok {
				t.Fatalf("%s apply dropped the daemon-side descriptor copy", tc.name)
			}
			if got := store.PendingRenameAncestry(); len(got) != 0 {
				t.Fatalf("%s apply resurrected store-side lineage: %#v", tc.name, got)
			}
		})
	}
}

// Each promotion's bind prunes every daemon-side rename entry except the new
// active generation (commitWithGenBinding): a superseded entry is unreachable
// — every reader (applyAndSyncCommitted, activeConfigSnapshotForPeer,
// activeConfigSnapshotAndReserveForPeer) consults only the CURRENT activeGen —
// so retaining it leaks one dead entry per rename commit, unbounded on
// rename-heavy nodes (#10592 N2). The ownership test above pins the single-bind
// transfer; this cell pins the SECOND bind: a rename→rename promotion must
// replace the entry, and a rename→plain promotion must evict it to empty.
// RED-on-revert: delete the prune loop (daemon_apply_commit.go) and the second
// bind leaves both generations behind (len==2), failing the exact-one and
// stale-absent asserts below while the ownership test stays green.
func TestRenameAncestryPrunedOnNextBind(t *testing.T) {
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"security zones security-zone lan",
		"security zones security-zone wan",
		"security policies default-policy deny-all",
		"security policies from-zone lan to-zone wan policy p-old match source-address any",
		"security policies from-zone lan to-zone wan policy p-old match destination-address any",
		"security policies from-zone lan to-zone wan policy p-old match application any",
		"security policies from-zone lan to-zone wan policy p-old then permit",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("initial Commit: %v", err)
	}
	d := &Daemon{store: store, applyBodyForTest: func(*config.Config) {}}
	d.applySem = semaphore.NewWeighted(1)
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("applySem acquire: %v", err)
	}
	defer d.applySem.Release(1)
	bind := func(t *testing.T) uint64 {
		t.Helper()
		if _, _, err := d.commitWithGenBinding(
			func(*config.Config) error { return nil },
			func(gen uint64) (*config.Config, error) { return store.CommitWithDescriptionGen("", gen) },
		); err != nil {
			t.Fatalf("commitWithGenBinding: %v", err)
		}
		activeGen, _ := store.ActiveSnapshot()
		return activeGen
	}
	rename := func(t *testing.T, source, destination string) {
		t.Helper()
		src := []string{"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", source}
		dst := []string{"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", destination}
		if err := store.Rename(src, dst); err != nil {
			t.Fatalf("Rename(%s->%s): %v", source, destination, err)
		}
	}

	// Bind 1 (rename): the daemon holds exactly the first generation.
	rename(t, "p-old", "p-new")
	gen1 := bind(t)
	if len(d.pendingRenameApplies) != 1 {
		t.Fatalf("bind 1 holds %d entries, want exactly one: %#v", len(d.pendingRenameApplies), d.pendingRenameApplies)
	}
	if pending, ok := d.pendingRenameApplies[gen1]; !ok || len(pending.descriptors) != 1 {
		t.Fatalf("bind 1 did not stage the first generation's descriptor: %#v", d.pendingRenameApplies)
	}

	// Bind 2 (rename→rename): the second promotion replaces the first — the
	// stale generation is gone and the peer snapshot sees only the new one.
	rename(t, "p-new", "p-new2")
	gen2 := bind(t)
	if gen2 == gen1 {
		t.Fatalf("second promotion did not advance the active generation (gen=%d); the prune below is untested", gen1)
	}
	if len(d.pendingRenameApplies) != 1 {
		t.Fatalf("bind 2 holds %d entries, want exactly one: %#v", len(d.pendingRenameApplies), d.pendingRenameApplies)
	}
	if _, ok := d.pendingRenameApplies[gen1]; ok {
		t.Fatalf("bind 2 retained the superseded generation %d: %#v", gen1, d.pendingRenameApplies)
	}
	pending, ok := d.pendingRenameApplies[gen2]
	if !ok || len(pending.descriptors) != 1 {
		t.Fatalf("bind 2 did not stage the current generation's descriptor: %#v", d.pendingRenameApplies)
	}
	if got := pending.descriptors[0].DestinationPath; len(got) == 0 || got[len(got)-1] != "p-new2" {
		t.Fatalf("bind 2 staged the wrong lineage: %#v", pending.descriptors)
	}
	if _, _, ancestry := d.activeConfigSnapshotForPeer(); len(ancestry) != 1 {
		t.Fatalf("peer snapshot after bind 2 carries %d descriptors, want only the current one: %#v", len(ancestry), ancestry)
	}

	// Bind 3 (rename→plain): a promotion with no rename evicts to empty.
	if err := store.SetFromInput("security policies from-zone lan to-zone wan policy p-new2 description prune-probe"); err != nil {
		t.Fatalf("SetFromInput(description): %v", err)
	}
	gen3 := bind(t)
	if gen3 == gen2 {
		t.Fatalf("third promotion did not advance the active generation (gen=%d); the eviction below is untested", gen2)
	}
	if len(d.pendingRenameApplies) != 0 {
		t.Fatalf("plain bind left %d stale entries, want empty: %#v", len(d.pendingRenameApplies), d.pendingRenameApplies)
	}
	if _, _, ancestry := d.activeConfigSnapshotForPeer(); len(ancestry) != 0 {
		t.Fatalf("peer snapshot after the plain bind carries stale lineage: %#v", ancestry)
	}
}
