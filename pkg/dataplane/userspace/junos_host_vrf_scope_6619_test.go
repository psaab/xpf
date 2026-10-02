package userspace

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// junos_host_vrf_scope_6619_test.go locks two coupled properties of the #4146
// junos-host DENY projection's iifname scope.
//
// #6619 — an interface enslaved to an l3mdev VRF cannot be scoped by its own
// name. The daemon binds every member of every non-`forwarding` routing instance
// to `vrf-<name>` (pkg/daemon/daemon_apply_interfaces.go, applyVRFReconcile ->
// BindInterfaceToVRF -> LinkSetMaster), and at the netfilter LOCAL_IN hook the
// l3mdev rcv handler has already replaced skb->dev with the VRF device. Measured
// firsthand at the exact hook and priority xpf_hostinbound installs (inet base
// chain, hook input, priority 10), on the kernel floor this project targets:
//
//	c_slave(veth1)=0  c_master(vrf-t)=3  c_any=3
//
// Zero hits on the enslaved name, three on the master — and `c_any=3` for three
// packets proves the hook runs EXACTLY ONCE, so `c_slave=0` is "it does not
// happen", not "we missed a second pass". Before this fix such a zone emitted a
// representable program whose rules matched nothing, and because the program WAS
// representable it also SUPPRESSED its own #4168 warning: config commits clean,
// rules present in the ruleset, nothing enforced.
//
// #6564 member 8 — `enforceable := len(netdevs) > 0` asked an EXISTENCE question
// where COVERAGE was required. A zone that resolved only SOME of its ingress
// netdevs emitted a rule covering the survivors and suppressed its warning,
// reporting as fully enforced. The projection now reads a coverage record, and
// the two decisions are separated: rules are emitted whenever anything resolved
// (protection that works is never withdrawn), while the warning is suppressed
// only when every OWN ingress netdev resolved.
//
// The two are one change because the VRF filter ENLARGES the population of
// partially-resolved zones — fixing #6619 alone would have grown the set of
// configs hitting member 8.
//
// Rows assert BOTH halves in ONE cell — the resolved scope, whether a kernel
// rule was emitted, AND the warning count. Two tests, one per half, could drift
// apart in exactly the way the projection and the advisory already had.

// vrfScopeBase is the interface/zone scaffolding. `trust` exists so the config
// always has a second, untouched zone: a row that accidentally emptied every
// zone's scope would otherwise look the same as one that emptied the zone under
// test.
var vrfScopeBase = []string{
	"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	"set interfaces ge-0/0/1 unit 50 vlan-id 50",
	"set interfaces ge-0/0/1 unit 50 family inet address 10.0.50.1/24",
	"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
	"set security zones security-zone trust interfaces ge-0/0/0.0",
	"set security address-book global address bad-host 10.0.0.5/32",
}

// vrfScopeDeny is a plainly representable junos-host deny — source-scoped,
// destination any, application any — so a row that renders nothing renders
// nothing because of the SCOPE, not because the policy was un-representable.
func vrfScopeDeny(fromZone, name string) []string {
	p := fmt.Sprintf("set security policies from-zone %s to-zone junos-host policy %s ", fromZone, name)
	return []string{
		p + "match source-address bad-host",
		p + "match destination-address any",
		p + "match application any",
		p + "then deny",
	}
}

func vrfScopeProgram(t *testing.T, cfg *config.Config, zone string) (JunosHostProgram, bool) {
	t.Helper()
	for _, p := range BuildJunosHostPrograms(cfg) {
		if p.Zone == zone {
			return p, true
		}
	}
	return JunosHostProgram{}, false
}

// compileLegacyVRFScopeConfig6619 uses the tolerant load path for legacy
// routing-instance shapes that strict commits now reject. Persisted configs
// can still reach this runtime projection.
func compileLegacyVRFScopeConfig6619(t *testing.T, cmds []string) *config.Config {
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// TestJunosHostIngressScopeCoverage6619 walks the scope-resolution states.
func TestJunosHostIngressScopeCoverage6619(t *testing.T) {
	rows := []struct {
		name string
		// zone / policyName are explicit rather than derived: a heuristic that
		// picks the subject from the expected values makes the row's assertions
		// depend on the answer they are checking.
		zone           string
		policyName     string
		cmds           []string
		compileLenient bool
		// wantConfigWarning is the expected tolerant-load warning for a legacy
		// shape that strict commits now reject.
		wantConfigWarning string
		// wantScoped is the zone's resolved iifname set, asserted exactly: a
		// count would pass for the right number of wrong netdevs, and the whole
		// defect is that a rule names a netdev traffic never arrives on.
		wantScoped []string
		// wantRules is whether a kernel DROP rule is emitted at all.
		wantRules bool
		// wantWarn is the #4168 warning count for the zone's deny.
		wantWarn int
	}{
		{
			// CONTROL. Without a row that resolves fully, emits a rule and stays
			// silent, every assertion below is satisfiable by a projection that
			// resolved nothing and warned about everything.
			name:       "fully scoped — rule emitted, warning suppressed",
			zone:       "zoneA",
			policyName: "denyA",
			cmds: concat(vrfScopeBase,
				[]string{"set security zones security-zone zoneA interfaces ge-0/0/1.0"},
				vrfScopeDeny("zoneA", "denyA")),
			wantScoped: []string{"ge-0-0-1"},
			wantRules:  true,
			wantWarn:   0,
		},
		{
			// A VRF member's kernel iifname is the LOCAL_IN-visible master.
			// The deny remains scoped and enforceable there, suppressing its
			// former #4168 coverage warning.
			name:       "VRF-enslaved, only interface — master scoped, warning suppressed",
			zone:       "zoneA",
			policyName: "denyA",
			cmds: concat(vrfScopeBase,
				[]string{
					"set security zones security-zone zoneA interfaces ge-0/0/1.0",
					"set routing-instances vrA instance-type virtual-router",
					"set routing-instances vrA interface ge-0/0/1.0",
				},
				vrfScopeDeny("zoneA", "denyA")),
			wantScoped: []string{"vrf-vrA"},
			wantRules:  true,
			wantWarn:   0,
		},
		{
			// The VRF member is now covered by vrf-vrA and the ordinary
			// interface by ge-0-0-2. Both ingress paths are scoped, so the
			// legacy mixed-routing config keeps its rule without a gap warning.
			name:       "legacy mixed-routing zone — both scopes emitted, warning suppressed",
			zone:       "zoneA",
			policyName: "denyA",
			cmds: concat(vrfScopeBase,
				[]string{
					"set security zones security-zone zoneA interfaces ge-0/0/1.0",
					"set security zones security-zone zoneA interfaces ge-0/0/2.0",
					"set routing-instances vrA instance-type virtual-router",
					"set routing-instances vrA interface ge-0/0/1.0",
				},
				vrfScopeDeny("zoneA", "denyA")),
			compileLenient: true,
			wantScoped:     []string{"ge-0-0-2", "vrf-vrA"},
			wantRules:      true,
			wantWarn:       0,
		},
		{
			// A bare RI member fans down to the configured tagged unit too.
			// Since that sibling is unzoned, LOCAL_IN cannot distinguish it
			// from the zoneA unit-0 member; the master must stay unscopable.
			name:       "bare physical with unzoned VLAN sibling — master stays unscopable",
			zone:       "zoneA",
			policyName: "denyA",
			cmds: concat(vrfScopeBase,
				[]string{
					"set security zones security-zone zoneA interfaces ge-0/0/1.0",
					"set routing-instances vrA instance-type virtual-router",
					"set routing-instances vrA interface ge-0/0/1",
				},
				vrfScopeDeny("zoneA", "denyA")),
			wantScoped: nil,
			wantRules:  false,
			wantWarn:   1,
		},
		{
			// #11312 rejects forwarding-instance interface members on strict
			// commits. Persisted configs still reach this runtime projection
			// through tolerant load, where the warning records the new contract.
			// The member is not VRF-bound, so its kernel device remains scopable.
			// Keep this control to distinguish instance-type forwarding from
			// virtual-router membership without relying on newly committed config.
			name:       "instance-type forwarding is not a VRF — scope intact",
			zone:       "zoneA",
			policyName: "denyA",
			cmds: concat(vrfScopeBase,
				[]string{
					"set security zones security-zone zoneA interfaces ge-0/0/1.0",
					"set routing-instances fwd instance-type forwarding",
					"set routing-instances fwd interface ge-0/0/1.0",
				},
				vrfScopeDeny("zoneA", "denyA")),
			compileLenient:    true,
			wantConfigWarning: "forwarding-instance interface membership",
			wantScoped:        []string{"ge-0-0-1"},
			wantRules:         true,
			wantWarn:          0,
		},
		{
			// member 8 via AMBIGUITY on an OWN netdev, no VRF involved. zoneA
			// owns the untagged unit-0 (its own netdev ge-0-0-1) and ge-0/0/2.0;
			// zoneB's tagged subunit nominates ge-0-0-1 as a parent candidate and
			// makes it ambiguous. zoneA loses one of its OWN ingress paths and
			// keeps the other.
			name:       "own netdev lost to cross-zone ambiguity — partial scope, rule AND warning",
			zone:       "zoneA",
			policyName: "denyA",
			cmds: concat(vrfScopeBase,
				[]string{
					"set security zones security-zone zoneA interfaces ge-0/0/1.0",
					"set security zones security-zone zoneA interfaces ge-0/0/2.0",
					"set security zones security-zone zoneB interfaces ge-0/0/1.50",
				},
				vrfScopeDeny("zoneA", "denyA")),
			wantScoped: []string{"ge-0-0-2"},
			wantRules:  true,
			wantWarn:   1,
		},
		{
			// THE OVER-WARNING GUARD. zoneB holds only the tagged subunit. Its
			// physical parent is contributed as a conservative superset candidate
			// (the bondless-RETH case) and is dropped here — but a plain 802.1Q
			// subunit's frames are demuxed to ge-0-0-1.50, so losing the parent
			// costs zoneB nothing and must NOT warn. Counting a dropped parent as
			// a coverage gap would fire on every trunk carrying an untagged
			// unit-0 in one zone and tagged subunits in others: an ordinary
			// correct config, and an advisory that fires on those stops being
			// read at all.
			name:       "parent superset candidate dropped — not a gap, no warning",
			zone:       "zoneB",
			policyName: "denyB",
			cmds: concat(vrfScopeBase,
				[]string{
					"set security zones security-zone zoneA interfaces ge-0/0/1.0",
					"set security zones security-zone zoneB interfaces ge-0/0/1.50",
				},
				vrfScopeDeny("zoneB", "denyB")),
			wantScoped: []string{"ge-0-0-1.50"},
			wantRules:  true,
			wantWarn:   0,
		},
		{
			// A VLAN subunit is a distinct kernel device with its own master,
			// so an explicit unit-0 RI member enslaves the parent but not
			// ge-0-0-1.50. Both the subunit and the parent master are covered.
			name:       "explicit parent unit enslaved, subunit is not — both scopes stay enforceable",
			zone:       "zoneB",
			policyName: "denyB",
			cmds: concat(vrfScopeBase,
				[]string{
					"set security zones security-zone zoneB interfaces ge-0/0/1.50",
					"set routing-instances vrA instance-type virtual-router",
					"set routing-instances vrA interface ge-0/0/1.0",
				},
				vrfScopeDeny("zoneB", "denyB")),
			wantScoped: []string{"ge-0-0-1.50", "vrf-vrA"},
			wantRules:  true,
			wantWarn:   0,
		},
		{
			// A bare routing-instance member fans down to every configured unit
			// in the daemon binder. The subunit therefore shares the master scope
			// even though the raw interface ref is not itself its device name.
			name:       "bare parent member fans tagged subunit into master scope",
			zone:       "zoneB",
			policyName: "denyB",
			cmds: concat(vrfScopeBase,
				[]string{
					"set security zones security-zone zoneB interfaces ge-0/0/1.50",
					"set routing-instances vrA instance-type virtual-router",
					"set routing-instances vrA interface ge-0/0/1",
				},
				vrfScopeDeny("zoneB", "denyB")),
			wantScoped: []string{"vrf-vrA"},
			wantRules:  true,
			wantWarn:   0,
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			zone, policyName := row.zone, row.policyName
			var cfg *config.Config
			if row.compileLenient {
				cfg = compileLegacyVRFScopeConfig6619(t, row.cmds)
			} else {
				cfg = residualCfg(t, row.cmds)
			}
			if row.wantConfigWarning != "" {
				found := false
				for _, warning := range cfg.Warnings {
					if strings.Contains(warning, row.wantConfigWarning) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("tolerant compile did not report %q; warnings=%v",
						row.wantConfigWarning, cfg.Warnings)
				}
			}

			if got := config.JunosHostZoneIngressNetdevs(cfg)[zone]; !slices.Equal(got, row.wantScoped) {
				t.Errorf("scope for %s = %v, want %v — the iifname set is the mechanism; a rule naming a netdev LOCAL_IN never reports enforces nothing",
					zone, got, row.wantScoped)
			}
			prog, ok := vrfScopeProgram(t, cfg, zone)
			rules := 0
			if ok {
				rules = len(prog.RulesV4) + len(prog.RulesV6)
			}
			if row.wantRules && rules == 0 {
				t.Errorf("no kernel DROP rule emitted for %s; a partially-resolved zone must keep the protection that DOES work", zone)
			}
			if !row.wantRules && rules != 0 {
				t.Errorf("%d kernel DROP rule(s) emitted for %s with nothing scopable", rules, zone)
			}
			if ok && !slices.Equal(prog.IngressIfnames, row.wantScoped) {
				t.Errorf("program iifnames = %v, want %v", prog.IngressIfnames, row.wantScoped)
			}
			if got := residualWarnings(cfg, policyName); len(got) != row.wantWarn {
				t.Errorf("#4168 warnings naming %q = %d, want %d — a deny that is not enforced on every ingress path of its zone must say so, and one that IS must stay quiet; got %v",
					policyName, len(got), row.wantWarn, got)
			}
		})
	}
}
