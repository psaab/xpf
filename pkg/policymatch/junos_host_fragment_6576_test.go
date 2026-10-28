package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6576 fail-on-revert artifacts.
//
// PR #6505 taught the dataplane's junos-host gate the #4569 fragment-associated
// deny (issue #6465): a flowless non-first fragment that SKIPS an overlapping
// port-bearing DENY fails closed against it, and — because the host
// fall-through DELIVERS (the management lifeline, a permit-like posture) — that
// also applies when nothing else matched. #6505 touched five files and none of
// them was pkg/policymatch, so the Go simulator kept reporting PERMIT / "local
// delivery" for a host-bound fragment the box DROPS.
//
// RED on revert: drop the frag tracking from matchJunosHost (remove the
// frag.override / frag.note calls and the overridePermissiveTerminal on the
// final return). Both fragment assertions below flip to permit / unmatched.
//
// matchJunosHost walks THREE tiers and each has its own `frag.note` call site,
// so each is pinned separately — deleting any ONE of the three must be RED:
//
//	exact  `from-zone <ingress> to-zone junos-host` -> junosHostFragmentCfg
//	from-any `from-zone any to-zone junos-host`     -> junosHostFragmentFromAnyCfg
//	global   `match to-zone junos-host` (#3639)     -> junosHostFragmentGlobalCfg
//
// plus TestJunosHostFragmentCarriesCandidateAcrossTiers_6576, which notes the
// candidate in the exact tier and matches the permit in the GLOBAL tier, so the
// accumulator really is shared across the whole walk rather than per-tier.

// junosHostFragmentCfg mirrors fragmentDenyCfg onto the HOST path: an earlier
// source-scoped port-bearing `deny junos-ssh` to junos-host, then a permit-any.
// The deny is source-scoped so overlap vs non-overlap is exercisable.
func junosHostFragmentCfg(withPermit bool) *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		AddressBook:   hostFragAddressBook(),
		Policies: []*config.ZonePairPolicies{
			{FromZone: "trust", ToZone: JunosHostZone, Policies: hostFragPolicies(withPermit)},
		},
	}, config.ApplicationsConfig{})
}

func hostFragQuery() Query {
	return Query{
		FromZone:         "trust",
		ToZone:           JunosHostZone,
		SrcIP:            net.ParseIP("10.1.2.3"),
		DstIP:            net.ParseIP("10.0.0.1"),
		Protocol:         "tcp",
		NonFirstFragment: true,
	}
}

// TestJunosHostFragmentInheritsPortBearingDeny_6576 is the headline shape: a
// later `application any` PERMIT must not certify a fragment that skipped an
// overlapping port-bearing DENY.
func TestJunosHostFragmentInheritsPortBearingDeny_6576(t *testing.T) {
	res := Match(junosHostFragmentCfg(true), hostFragQuery())

	if res.Action != config.PolicyDeny {
		t.Fatalf("host-bound non-first fragment must inherit the overlapping port-bearing deny "+
			"(the dataplane drops it since #6465); got %+v", res)
	}
	if res.PolicyName != "block-host-ssh" {
		t.Fatalf("the deny must be attributed to the enforcing policy so incident response sees "+
			"the real rule; want block-host-ssh, got %q", res.PolicyName)
	}
	if !res.FragmentAssociatedDeny {
		t.Fatalf("FragmentAssociatedDeny must be set so FragmentDenyNote renders; got %+v", res)
	}
	if res.FragmentDenyNote() == "" {
		t.Fatalf("a fragment-associated deny must carry its advisory note; got %+v", res)
	}
}

// TestJunosHostFragmentDeniesOnPermissiveFallThrough_6576 pins the #6465
// post-walk arm, which is the half a naive port of the transit override would
// MISS: with no permit rule at all the host walk falls through to local
// delivery — a permit-LIKE posture — so the skipped deny must still win.
// Reporting HostInboundUnmatched here tells the operator "delivered" for a
// packet the box drops.
func TestJunosHostFragmentDeniesOnPermissiveFallThrough_6576(t *testing.T) {
	res := Match(junosHostFragmentCfg(false), hostFragQuery())

	if res.HostInboundUnmatched {
		t.Fatalf("an unmatched host walk that SKIPPED an overlapping port-bearing deny must not "+
			"report local delivery — the dataplane returns the fragment-associated DROP; got %+v", res)
	}
	if res.Action != config.PolicyDeny || !res.FragmentAssociatedDeny {
		t.Fatalf("want fragment-associated deny on the permissive fall-through, got %+v", res)
	}
	if res.PolicyName != "block-host-ssh" {
		t.Fatalf("want the skipped deny attributed, got %q", res.PolicyName)
	}
}

// TestJunosHostL4LifelineUnchanged_6576 is the over-reach guard. The whole
// point of the host gate is that an unmatched host-bound flow is DELIVERED —
// the management lifeline. An ordinary L4 query records no candidate, so the
// terminal must be byte-identical to before this change. If this ever fails,
// the fix has started denying management traffic.
func TestJunosHostL4LifelineUnchanged_6576(t *testing.T) {
	q := hostFragQuery()
	q.NonFirstFragment = false
	q.DstPort = PortPtr(12345) // not ssh — matches neither the deny nor (absent) permit

	res := Match(junosHostFragmentCfg(false), q)
	if !res.HostInboundUnmatched {
		t.Fatalf("an ordinary L4 host-bound flow matching no rule must still fall through to "+
			"local delivery (the lifeline); got %+v", res)
	}
	if res.FragmentAssociatedDeny {
		t.Fatalf("an L4 query must never record a fragment candidate; got %+v", res)
	}
}

// TestJunosHostFragmentNonOverlappingStillDelivers_6576 is the second
// over-reach guard: a fragment whose SOURCE is outside the deny's scope did not
// skip anything, so it must still be delivered. Without this a blunt fix that
// denies every host-bound fragment would pass the two tests above.
func TestJunosHostFragmentNonOverlappingStillDelivers_6576(t *testing.T) {
	q := hostFragQuery()
	q.SrcIP = net.ParseIP("192.0.2.7") // outside trust-net (10.0.0.0/8)

	res := Match(junosHostFragmentCfg(false), q)
	if !res.HostInboundUnmatched {
		t.Fatalf("a fragment that overlaps NO port-bearing deny must still be delivered; got %+v", res)
	}
	if res.FragmentAssociatedDeny {
		t.Fatalf("no deny was skipped, so no fragment-associated deny may be reported; got %+v", res)
	}
}

// hostFragPolicies builds the shared two-rule body: a source-scoped
// port-bearing DENY followed by an optional permit-any.
func hostFragPolicies(withPermit bool) []*config.Policy {
	pols := []*config.Policy{
		{
			Name:   "block-host-ssh",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"trust-net"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"junos-ssh"},
			},
		},
	}
	if withPermit {
		pols = append(pols, &config.Policy{
			Name:   "permit-host-all",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		})
	}
	return pols
}

func hostFragAddressBook() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"trust-net": {Name: "trust-net", Value: "10.0.0.0/8"},
		},
	}
}

// junosHostFragmentFromAnyCfg puts the SAME deny/permit pair in the
// `from-zone any to-zone junos-host` WILDCARD tier — the second of the three
// tiers, and the very wildcard whose omission from the host path was the #3018
// silent fail-open. junosHostFragmentCfg's deny sits in the exact tier only, so
// without this fixture the from-any `frag.note` call site is unpinned.
func junosHostFragmentFromAnyCfg(withPermit bool) *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		AddressBook:   hostFragAddressBook(),
		Policies: []*config.ZonePairPolicies{
			{FromZone: "any", ToZone: JunosHostZone, Policies: hostFragPolicies(withPermit)},
		},
	}, config.ApplicationsConfig{})
}

// junosHostFragmentGlobalCfg puts the SAME pair in a host-scoped GLOBAL tier
// (`match to-zone junos-host`, #3639 / #3611 Piece B) — the third tier, and the
// last `frag.note` call site.
func junosHostFragmentGlobalCfg(withPermit bool) *config.Config {
	pols := hostFragPolicies(withPermit)
	for _, p := range pols {
		p.Match.ToZones = []string{JunosHostZone}
	}
	return cfgWith(config.SecurityConfig{
		DefaultPolicy:  config.PolicyDeny,
		Zones:          zones("trust", "untrust"),
		AddressBook:    hostFragAddressBook(),
		GlobalPolicies: pols,
	}, config.ApplicationsConfig{})
}

// TestJunosHostFragmentFromAnyTierNotesCandidate_6576 pins the from-any tier's
// frag.note. Both arms are exercised: the later permit in the same tier
// (override) and the permit-like fall-through (overridePermissiveTerminal).
func TestJunosHostFragmentFromAnyTierNotesCandidate_6576(t *testing.T) {
	res := Match(junosHostFragmentFromAnyCfg(true), hostFragQuery())
	if res.Action != config.PolicyDeny || res.PolicyName != "block-host-ssh" || !res.FragmentAssociatedDeny {
		t.Fatalf("a deny skipped in the `from-zone any to-zone junos-host` tier must still override "+
			"the later permit — that wildcard governs the host path (#3018); got %+v", res)
	}

	res = Match(junosHostFragmentFromAnyCfg(false), hostFragQuery())
	if res.HostInboundUnmatched || res.Action != config.PolicyDeny || !res.FragmentAssociatedDeny {
		t.Fatalf("a from-any-tier skipped deny must also beat the permit-like fall-through; got %+v", res)
	}
	if res.PolicyName != "block-host-ssh" {
		t.Fatalf("want the skipped deny attributed, got %q", res.PolicyName)
	}
}

// TestJunosHostFragmentGlobalTierNotesCandidate_6576 pins the host-scoped
// global tier's frag.note, the third and last call site.
func TestJunosHostFragmentGlobalTierNotesCandidate_6576(t *testing.T) {
	res := Match(junosHostFragmentGlobalCfg(true), hostFragQuery())
	if res.Action != config.PolicyDeny || res.PolicyName != "block-host-ssh" || !res.FragmentAssociatedDeny {
		t.Fatalf("a deny skipped in the host-scoped GLOBAL tier must override the later permit; got %+v", res)
	}

	res = Match(junosHostFragmentGlobalCfg(false), hostFragQuery())
	if res.HostInboundUnmatched || res.Action != config.PolicyDeny || !res.FragmentAssociatedDeny {
		t.Fatalf("a global-tier skipped deny must also beat the permit-like fall-through; got %+v", res)
	}
	if res.PolicyName != "block-host-ssh" {
		t.Fatalf("want the skipped deny attributed, got %q", res.PolicyName)
	}
}

// TestJunosHostFragmentCarriesCandidateAcrossTiers_6576 pins that the tracker
// is ONE accumulator for the whole host walk, not a per-tier one: the candidate
// is noted in the EXACT tier (which has no permit) and the permit that must be
// overridden is matched two tiers later, in the GLOBAL tier. A per-tier
// accumulator would report permit-global here.
func TestJunosHostFragmentCarriesCandidateAcrossTiers_6576(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		AddressBook:   hostFragAddressBook(),
		Policies: []*config.ZonePairPolicies{
			// Exact tier: the port-bearing deny ONLY — the fragment skips it and
			// falls through to the next tier.
			{FromZone: "trust", ToZone: JunosHostZone, Policies: hostFragPolicies(false)},
		},
		GlobalPolicies: []*config.Policy{
			{
				Name:   "permit-host-global",
				Action: config.PolicyPermit,
				Match: config.PolicyMatch{
					ToZones:              []string{JunosHostZone},
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
			},
		},
	}, config.ApplicationsConfig{})

	res := Match(cfg, hostFragQuery())
	if res.Action != config.PolicyDeny || !res.FragmentAssociatedDeny {
		t.Fatalf("a candidate noted in the EXACT tier must still override a permit matched in the "+
			"GLOBAL tier — the fragDenyTracker spans the whole host walk; got %+v", res)
	}
	if res.PolicyName != "block-host-ssh" {
		t.Fatalf("want the cross-tier skipped deny attributed to the enforcing rule, got %q", res.PolicyName)
	}
}
