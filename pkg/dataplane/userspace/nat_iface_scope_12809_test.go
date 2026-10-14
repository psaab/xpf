// #12809 lab-fixture pin for the wire-nat-frag-needed capture gate
// (test/incus/wire-nat-frag-needed.sh). The exact set-lines that gate
// commits on the loss userspace cluster must, on the production path:
//
//  1. compile STRICTLY — the #12525 compiler gate accepts a source-NAT
//     rule-set whose to-scope is `to interface reth0.80` (empty ToZone)
//     alongside a named from-zone;
//  2. snapshot as an interface-mode rule carrying ToInterface (so the
//     #12085 to-side registration matrix sees the non-zone row); and
//  3. register reth0.80's 172.16.80.8 in the interface-NAT map entries,
//     the desired map sets, and the translated-local exclusions for the
//     lab topology — with the standing zone-scoped catch-all (`rule
//     snat`) REMOVED, which is precisely the lab's deletion, so the
//     non-zone rule-set is the SOLE registrar of that address.
//
// The negative cell keeps the pool rule and nothing else: nothing
// registers 172.16.80.8. That is the pre-#12085 posture the lab capture
// exists to distinguish on the wire, pinned here so the committed config
// cannot silently stop compiling or registering (a repeat of the #12525
// class, where the capture could not run at all) between lab runs.
//
// Keep the set-lines byte-identical to the gate's configure block.
package userspace

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// lab12809Interfaces and lab12809Zones model the runtime shape the cluster
// presents for the capture: reth0.80 (172.16.80.8, zoned wan, live ifindex)
// is the non-zone SNAT egress; reth1 is the client-side LAN leg.
func lab12809Snapshot(rules []SourceNATRuleSnapshot) *ConfigSnapshot {
	return &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:       "reth0.80",
				Zone:       "wan",
				EgressZone: "wan",
				Ifindex:    40,
				Addresses:  []InterfaceAddressSnapshot{{Family: "inet", Address: "172.16.80.8/24"}},
			},
			{
				Name:       "reth1.0",
				Zone:       "lan",
				EgressZone: "lan",
				Ifindex:    41,
				Addresses:  []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.61.1/24"}},
			},
		},
		Zones: []ZoneSnapshot{
			{Name: "wan", ID: 1},
			{Name: "lan", ID: 3},
		},
		SourceNAT: rules,
	}
}

func lab12809Tree(t *testing.T, cmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// The cluster's standing pool rule, shared by every cell below.
var lab12809PoolLines = []string{
	"set security nat source pool pool-snat-pool address 172.16.80.7/32",
	"set security nat source rule-set lan-to-wan from zone lan",
	"set security nat source rule-set lan-to-wan to zone wan",
	"set security nat source rule-set lan-to-wan rule pool-snat match source-address 10.0.61.240/28",
	"set security nat source rule-set lan-to-wan rule pool-snat then source-nat pool pool-snat-pool",
}

// The gate's committed non-zone rule-set (rule `snat` of lan-to-wan is
// deleted in the same commit — mirrored by the cells that omit it).
var lab12809NonZoneLines = []string{
	"set security nat source rule-set lab-12809 from zone lan",
	"set security nat source rule-set lab-12809 to interface reth0.80",
	"set security nat source rule-set lab-12809 rule probe match source-address 10.0.61.102/32",
	"set security nat source rule-set lab-12809 rule probe then source-nat interface",
}

// The cluster's standing zone-scoped catch-all (present outside the cell).
var lab12809CatchAllLines = []string{
	"set security nat source rule-set lan-to-wan rule snat match source-address 0.0.0.0/0",
	"set security nat source rule-set lan-to-wan rule snat then source-nat interface",
}

var lab12809ZoneLines = []string{
	"set interfaces reth0 unit 80 vlan-id 80 family inet address 172.16.80.8/24",
	"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
	"set security zones security-zone wan interfaces reth0.80",
	"set security zones security-zone lan interfaces reth1.0",
}

// lab12809RegisteredAddresses returns the addresses registered for the
// snapshot by each #12085 map builder, as strings.
func lab12809RegisteredAddresses(t *testing.T, snapshot *ConfigSnapshot) (excl, entries, desired []string) {
	t.Helper()
	v4, _ := buildNATTranslatedLocalAddressExclusions(snapshot)
	for key := range v4 {
		var octets [4]byte
		binary.BigEndian.PutUint32(octets[:], key)
		excl = append(excl, netip.AddrFrom4(octets).String())
	}
	for _, entry := range buildInterfaceNATAddressEntries(snapshot) {
		if entry.v4 {
			var octets [4]byte
			binary.BigEndian.PutUint32(octets[:], entry.v4Key)
			entries = append(entries, netip.AddrFrom4(octets).String())
		}
	}
	desiredV4, _, _, _ := buildDesiredInterfaceNATAddressSets(snapshot)
	for key := range desiredV4 {
		var octets [4]byte
		binary.BigEndian.PutUint32(octets[:], key)
		desired = append(desired, netip.AddrFrom4(octets).String())
	}
	for _, s := range [][]string{excl, entries, desired} {
		sort.Strings(s)
	}
	return excl, entries, desired
}

func TestLab12809NonZoneScopeRuleSetCompilesAndRegisters(t *testing.T) {
	lines := append(append(append([]string{}, lab12809ZoneLines...), lab12809PoolLines...), lab12809NonZoneLines...)
	cfg, err := config.CompileConfig(lab12809Tree(t, lines...))
	if err != nil {
		t.Fatalf("the #12809 lab rule-set must compile strictly (non-zone to-scope with named from-zone), got: %v", err)
	}

	rules := buildSourceNATSnapshots(cfg, nil)
	var probe *SourceNATRuleSnapshot
	for i := range rules {
		if rules[i].Name == "probe" {
			probe = &rules[i]
			break
		}
	}
	if probe == nil {
		t.Fatalf("compiled config lost the lab-12809 probe rule; snapshots: %+v", rules)
	}
	if probe.FromZone != "lan" || probe.ToZone != "" || probe.ToInterface != "reth0.80" {
		t.Fatalf("lab rule scope not captured: FromZone=%q ToZone=%q ToInterface=%q", probe.FromZone, probe.ToZone, probe.ToInterface)
	}
	if !probe.InterfaceMode {
		t.Fatal("lab rule must snapshot as interface-mode (`then source-nat interface`)")
	}

	excl, entries, desired := lab12809RegisteredAddresses(t, lab12809Snapshot([]SourceNATRuleSnapshot{*probe}))
	want := []string{"172.16.80.8"}
	for name, got := range map[string][]string{
		"translated-local exclusions": excl,
		"interface-NAT map entries":   entries,
		"desired interface-NAT map":   desired,
	} {
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("non-zone lab rule-set: %s = %v, want exactly %v — without this registration the shim routes ICMP errors for the NAT address to the kernel (#12085)", name, got, want)
		}
	}
}

func TestLab12809PoolOnlyCellRegistersNothing(t *testing.T) {
	// Inside the lab cell, if the non-zone rule-set failed to apply, the
	// standing config is pool-only: NOTHING registers 172.16.80.8. That is
	// the regression signature the wire gate must read as FAIL, pinned here
	// at the map layer.
	lines := append(append([]string{}, lab12809ZoneLines...), lab12809PoolLines...)
	cfg, err := config.CompileConfig(lab12809Tree(t, lines...))
	if err != nil {
		t.Fatalf("pool-only baseline must compile: %v", err)
	}
	rules := buildSourceNATSnapshots(cfg, nil)
	excl, entries, desired := lab12809RegisteredAddresses(t, lab12809Snapshot(rules))
	for name, got := range map[string][]string{
		"translated-local exclusions": excl,
		"interface-NAT map entries":   entries,
		"desired interface-NAT map":   desired,
	} {
		for _, addr := range got {
			if addr == "172.16.80.8" {
				t.Fatalf("pool-only cell: %s registered 172.16.80.8 (%v) — the non-zone rule-set is not the sole registrar", name, got)
			}
		}
	}
}

func TestLab12809ZoneCatchAllStillRegisters(t *testing.T) {
	// Contrast cell: with the catch-all restored (post-lab posture) the
	// zone-scoped rule registers the same address via the egress-zone row.
	// Proves the negative cell above is about scope KIND, not a broken
	// fixture, and pins the restore the gate's cleanup must reach.
	lines := append(append(append([]string{}, lab12809ZoneLines...), lab12809PoolLines...), lab12809CatchAllLines...)
	cfg, err := config.CompileConfig(lab12809Tree(t, lines...))
	if err != nil {
		t.Fatalf("restored standing config must compile: %v", err)
	}
	rules := buildSourceNATSnapshots(cfg, nil)
	var found bool
	for _, r := range rules {
		if r.Name == "snat" && r.InterfaceMode && r.ToZone == "wan" {
			found = true
		}
	}
	if !found {
		t.Fatal("catch-all rule did not snapshot as the zone-scoped interface-mode rule")
	}
	_, entries, _ := lab12809RegisteredAddresses(t, lab12809Snapshot(rules))
	if !reflect.DeepEqual(entries, []string{"172.16.80.8"}) {
		t.Fatalf("zone catch-all interface-NAT entries = %v, want [172.16.80.8]", entries)
	}
}
