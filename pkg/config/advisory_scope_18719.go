package config

import (
	"fmt"
	"sort"
	"strings"
)

// #18719: change-scoped constraint reminders.
//
// A commit warning is either a FINDING ("your config has a problem") or a
// constraint REMINDER ("this config is only safe if something outside xpf's
// view holds"). A finding belongs on every commit until the config changes.
// A reminder repeated on every commit, whatever the commit touched, trains
// operators to skip the warning block, and the next real finding is missed.
// So a reminder must be acknowledgeable (a config knob that records the
// operator's attestation silences it) and change-scoped: it is printed on a
// commit that adds or changes the config it is about, and `commit check`
// shows it whenever its condition holds.
//
// changeScopedAdvisories18719 is the registry of reminders the commit path
// scopes. Each entry pairs the exact warning text with the fingerprint of
// the config region it is about. The text is matched exactly, so a reworded
// constant cannot silently fall out of scoping: the registry cell
// (TestChangeScopedAdvisoryRegistryMatchesEmitters18719) pins that every
// registered text is one the compiler emits.
var changeScopedAdvisories18719 = []struct {
	text  string
	scope func(*Config) string
}{
	{text: fabricZoneStampAdvisory10105, scope: fabricAdvisoryScope18719},
	{text: fabricBAFallbackAdvisory13967, scope: fabricBAFallbackScope18719},
}

// DropUnchangedScopedAdvisories removes from next.Warnings every registered
// change-scoped reminder whose config region is identical in prev, the
// previously committed config. A nil prev (first commit, or no compiled
// active config) keeps everything: an added region is a change. Only the
// operator commit paths call this; `commit check` does not, so a check
// always reports a reminder whose condition holds.
func DropUnchangedScopedAdvisories(prev, next *Config) {
	if prev == nil || next == nil || len(next.Warnings) == 0 {
		return
	}
	drop := map[string]bool{}
	for _, adv := range changeScopedAdvisories18719 {
		if adv.scope(prev) == adv.scope(next) {
			drop[adv.text] = true
		}
	}
	if len(drop) == 0 {
		return
	}
	kept := next.Warnings[:0:0]
	for _, w := range next.Warnings {
		if drop[w] {
			continue
		}
		kept = append(kept, w)
	}
	next.Warnings = kept
}

// fabricAdvisoryScope18719 fingerprints everything the #10105 reminder is
// about: whether a cluster fabric exists, which links it uses, their peers,
// their #16023 attestations, and the fab0/fab1 member and address config.
// Removing an attestation is a change, so the reminder returns on that
// commit.
func fabricAdvisoryScope18719(cfg *Config) string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return "no-cluster"
	}
	cc := cfg.Chassis.Cluster
	var b strings.Builder
	fmt.Fprintf(&b, "fabric=%q/%q peer=%q/%q attested=%t/%t",
		cc.FabricInterface, cc.Fabric1Interface,
		cc.FabricPeerAddress, cc.Fabric1PeerAddress,
		cc.FabricLinkAuthenticated, cc.Fabric1LinkAuthenticated)
	for _, fab := range []string{"fab0", "fab1"} {
		var ifc *InterfaceConfig
		if cfg.Interfaces.Interfaces != nil {
			ifc = cfg.Interfaces.Interfaces[fab]
		}
		if ifc == nil {
			fmt.Fprintf(&b, " %s=absent", fab)
			continue
		}
		members := append([]string(nil), ifc.FabricMembers...)
		sort.Strings(members)
		fmt.Fprintf(&b, " %s members=%q local=%q", fab, members, ifc.LocalFabricMember)
		units := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			units = append(units, n)
		}
		sort.Ints(units)
		for _, n := range units {
			u := ifc.Units[n]
			if u == nil {
				continue
			}
			addrs := append([]string(nil), u.Addresses...)
			sort.Strings(addrs)
			fmt.Fprintf(&b, " unit%d=%q", n, addrs)
		}
	}
	return b.String()
}

// fabricBAFallbackScope18719 fingerprints the #13967 reminder's region: the
// fabric, plus the fabric-reachable BA classifier bindings. Editing a
// classifier's code points is not a change of this region (the fallback's
// hazard does not depend on them); binding or unbinding one is.
func fabricBAFallbackScope18719(cfg *Config) string {
	return fabricAdvisoryScope18719(cfg) + " ba=" + strings.Join(fabricReachableBAClassifierBindings18719(cfg), ";")
}
