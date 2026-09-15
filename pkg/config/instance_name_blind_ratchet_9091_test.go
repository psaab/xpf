package config

import (
	"sort"
	"strings"
	"testing"
)

// The schema walk does not close a world around instance-name containers, so an
// unknown keyword in one's body commits clean and is silently ignored (#9091).
//
//	system login class c1 { xpfbogus 5; }           -> ACCEPTED (unknown keyword)
//	system login class c1 { idle-timeout notanum; } -> REJECTED (declared leaf, bad value)
//	security ike gateway g1 { bogus-token 5; }      -> ACCEPTED
//	security flow tcp-session { bogus-token 5; }    -> REJECTED (closed world)
//
// So the operator-facing consequence is narrower than an unqualified reading: a
// mistyped KEYWORD is silent, a bad VALUE on a correctly-spelled leaf is still
// caught. It is still #8928's shape — no value and no complaint — reached by
// schema blindness rather than by elision.
//
// WHY A RATCHET RATHER THAN A FIX. Making the walk descend strictly would turn
// every one of these containers strict AT ONCE, so every config that commits
// today with a typo in one starts failing at commit. That is the correct
// direction and the loud one, but it is exactly what #1960's no-brick doctrine
// exists to stage — and it is ASYMMETRIC: Store.Commit takes the strict path
// while Store.Load (boot from the persisted DB) and Store.SyncApply (HA config
// sync) take compileTreeLenient, which downgrades the identical violation to a
// warning. A config that stopped committing would still boot, warn, and
// silently truncate. The useful shape is per-container opt-in (closedWorld),
// worked down with evidence per container — which is what this ratchet makes
// visible and safe to do.

// instanceNameBlind9091 splits instance-name containers into those a
// closed-world subtree covers and those it does not.
//
// Predicate: args>=1 && len(children)>0 && wildcard==nil, with closedWorld
// INHERITED exactly as walkSchemaNode inherits it
// (childClosed := closed || childSchema.closedWorld).
//
// Path-keyed `seen`, `groups` skipped at the root, depth capped — the same
// three precautions inert_validator_ratchet_test.go takes and for the same
// three reasons: a node-keyed walk plus a path filter is non-deterministic
// under Go's randomised map order and gives a different count per run while
// looking stable within one; the groups/ mirror re-hosts the SAME schema node
// objects and would double every hit (#8921); and a deep or cyclic schema
// would not terminate. Measured stable at 156/7 over five consecutive runs.
func instanceNameBlind9091() (blind, armed []string) {
	seen := map[string]bool{}
	var walk func(n *schemaNode, path string, closed bool)
	walk = func(n *schemaNode, path string, closed bool) {
		if n == nil || seen[path] || strings.Count(path, "/") > 14 {
			return
		}
		seen[path] = true
		for k, c := range n.children {
			if c == nil || (path == "" && k == "groups") {
				continue
			}
			p := path + "/" + k
			childClosed := closed || c.closedWorld
			if c.args >= 1 && len(c.children) > 0 && c.wildcard == nil {
				if childClosed {
					armed = append(armed, p)
				} else {
					blind = append(blind, p)
				}
			}
			walk(c, p, childClosed)
		}
		if n.wildcard != nil {
			walk(n.wildcard, path+"/*", closed || n.wildcard.closedWorld)
		}
	}
	walk(setSchema, "", setSchema.closedWorld)
	sort.Strings(blind)
	sort.Strings(armed)
	return blind, armed
}

// instanceNameBlindCeiling9091 is the measured schema-blind population.
//
// WHAT THIS NUMBER IS NOT. #9091's headline is 102, and this is deliberately a
// DIFFERENT measurement — conflating them would misreport the state. 102 is the
// set that fails open END TO END at configstore.CheckText. This is the
// SCHEMA-SIDE set, which is a strict SUPERSET: the issue's own correction
// records 246 schema-blind collapsing to 205 end-to-end, because a later
// compiler gate catches some of them (`applications application`, `chassis
// cluster redundancy-group`). Schema blindness is an UPPER BOUND on fail-open,
// not the fail-open set, and a walk result is a claim about the walk.
//
// The upper bound is nonetheless the right thing to bound here, because the
// anti-regression property the issue asks for is "a new instance-name container
// cannot be added silently" — and a new container enters this set whether or
// not some later compiler gate happens to catch it. Bounding the superset
// cannot miss one.
//
// Lowering it is the goal: arming a container's closedWorld moves it from blind
// to armed and this number drops. The equality assertion is deliberate — a
// DROP fails too, so the ceiling cannot silently stop tracking reality after
// someone does the work.
// instanceNameBlindBaseline9091 is the measured schema-blind population, stored
// as the SET of paths rather than as a count.
//
// It was a bare `const ... = 156` until #9351, and the count is not the part
// that failed. The failure report called `added9091`, which returned
// `blind[ceiling:]` — the ALPHABETIC TAIL of the sorted slice, not the paths
// that actually arrived. When #9351 added two entries it named
// `/system/services/dhcpv6-local-server/group/pool/static-binding` and
// `/system/services/dynamic-dns/provider`, which had not moved at all, and said
// nothing about the two that had. A wrong diagnostic is worse than a missing
// one: it points the next person at innocent paths and away from the real ones,
// and the doc comment on that helper claimed the opposite ("turns a bare count
// into something reviewable"). Holding the set makes the claim true.
//
// The two assertions below are unchanged in spirit — equality in both
// directions, so a DROP fails too and the baseline cannot silently stop
// tracking reality after someone arms a container.
var instanceNameBlindBaseline9091 = []string{
	"/applications/application",
	"/applications/application-set",
	"/chassis/cluster/redundancy-group",
	"/class-of-service/classifiers/dscp",
	"/class-of-service/classifiers/dscp/forwarding-class",
	"/class-of-service/classifiers/dscp/forwarding-class/loss-priority",
	"/class-of-service/classifiers/ieee-802.1",
	"/class-of-service/classifiers/ieee-802.1/forwarding-class",
	"/class-of-service/classifiers/ieee-802.1/forwarding-class/loss-priority",
	"/class-of-service/classifiers/inet-precedence",
	"/class-of-service/classifiers/inet-precedence/forwarding-class",
	"/class-of-service/classifiers/inet-precedence/forwarding-class/loss-priority",
	"/class-of-service/fairness/rss-expectation/interface",
	"/class-of-service/fairness/rss-expectation/interface/queue",
	"/class-of-service/interfaces",
	"/class-of-service/interfaces/shaping-rate",
	"/class-of-service/interfaces/unit",
	"/class-of-service/interfaces/unit/shaping-rate",
	"/class-of-service/rewrite-rules/dscp",
	"/class-of-service/rewrite-rules/dscp/forwarding-class",
	"/class-of-service/rewrite-rules/dscp/forwarding-class/loss-priority",
	"/class-of-service/rewrite-rules/exp",
	"/class-of-service/rewrite-rules/exp/forwarding-class",
	"/class-of-service/rewrite-rules/exp/forwarding-class/loss-priority",
	"/class-of-service/rewrite-rules/ieee-802.1",
	"/class-of-service/rewrite-rules/ieee-802.1/forwarding-class",
	"/class-of-service/rewrite-rules/ieee-802.1/forwarding-class/loss-priority",
	"/class-of-service/rewrite-rules/inet-precedence",
	"/class-of-service/rewrite-rules/inet-precedence/forwarding-class",
	"/class-of-service/rewrite-rules/inet-precedence/forwarding-class/loss-priority",
	"/class-of-service/scheduler-maps",
	"/class-of-service/schedulers",
	"/class-of-service/schedulers/buffer-size",
	"/class-of-service/schedulers/transmit-rate",
	"/class-of-service/traffic-control-profiles",
	"/event-options/policy",
	"/event-options/policy/within",
	"/firewall/family/any/filter",
	"/firewall/family/any/filter/term",
	"/firewall/family/any/filter/term/from/flexible-match-range/range",
	"/firewall/family/inet/filter",
	"/firewall/family/inet/filter/term",
	"/firewall/family/inet/filter/term/from/flexible-match-range/range",
	"/firewall/family/inet6/filter",
	"/firewall/family/inet6/filter/term",
	"/firewall/family/inet6/filter/term/from/flexible-match-range/range",
	"/firewall/policer",
	"/firewall/three-color-policer",
	"/forwarding-options/dhcp-relay/group",
	"/forwarding-options/port-mirroring/instance",
	"/forwarding-options/sampling/instance",
	"/forwarding-options/sampling/instance/family/inet/output/flow-server",
	"/forwarding-options/sampling/instance/family/inet6/output/flow-server",
	"/interfaces/*/tunnel/wireguard/peer",
	"/interfaces/*/unit",
	"/interfaces/*/unit/family/inet/address",
	"/interfaces/*/unit/family/inet/address/vrrp-group",
	"/interfaces/*/unit/family/inet6/address",
	"/interfaces/*/unit/family/inet6/address/vrrp-group",
	"/interfaces/*/unit/tunnel/wireguard/peer",
	"/policy-options/policy-statement",
	"/policy-options/policy-statement/term",
	"/protocols/bgp/group",
	"/protocols/bgp/group/neighbor",
	"/protocols/isis/interface",
	"/protocols/lldp/interface",
	"/protocols/ospf/area",
	"/protocols/ospf/area/interface",
	"/protocols/ospf/area/virtual-link",
	"/protocols/ospf3/area",
	"/protocols/ospf3/area/interface",
	"/protocols/router-advertisement/interface",
	"/protocols/router-advertisement/interface/nat-prefix",
	"/protocols/router-advertisement/interface/nat64prefix",
	"/protocols/router-advertisement/interface/prefix",
	"/routing-instances/*/protocols/bgp/group",
	"/routing-instances/*/protocols/bgp/group/neighbor",
	"/routing-instances/*/protocols/isis/interface",
	"/routing-instances/*/protocols/ospf/area",
	"/routing-instances/*/protocols/ospf/area/interface",
	"/routing-instances/*/protocols/ospf/area/virtual-link",
	"/routing-instances/*/protocols/ospf3/area",
	"/routing-instances/*/protocols/ospf3/area/interface",
	"/routing-instances/*/routing-options/rib",
	"/routing-instances/*/routing-options/rib/static/route",
	"/routing-instances/*/routing-options/rib/static/route/next-hop",
	"/routing-instances/*/routing-options/rib/static/route/qualified-next-hop",
	"/routing-instances/*/routing-options/static/route",
	"/routing-instances/*/routing-options/static/route/next-hop",
	"/routing-instances/*/routing-options/static/route/qualified-next-hop",
	"/routing-options/generate/route",
	"/routing-options/rib",
	"/routing-options/rib/static/route",
	"/routing-options/rib/static/route/next-hop",
	"/routing-options/rib/static/route/qualified-next-hop",
	"/routing-options/static/route",
	"/routing-options/static/route/next-hop",
	"/routing-options/static/route/qualified-next-hop",
	"/schedulers/scheduler",
	"/security/dynamic-address/address-name",
	"/security/dynamic-address/feed-server",
	"/security/dynamic-address/feed-server/feed-name",
	"/security/flow/traceoptions/packet-filter",
	"/security/ike/gateway",
	"/security/ike/policy",
	"/security/ipsec/gateway",
	"/security/ipsec/policy",
	"/security/ipsec/vpn",
	"/security/log/profile",
	"/security/log/stream",
	"/security/nat/destination/pool",
	"/security/nat/destination/rule-set",
	"/security/nat/destination/rule-set/rule",
	"/security/nat/source/pool",
	"/security/nat/source/rule-set",
	"/security/nat/source/rule-set/rule",
	"/security/nat/static/rule-set",
	"/security/nat/static/rule-set/rule",
	"/security/screen/ids-option",
	"/services/flow-monitoring/version-ipfix/template",
	"/services/flow-monitoring/version9/template",
	"/services/ip-monitoring/policy",
	"/services/ip-monitoring/policy/then/preferred-route/route",
	"/services/ip-monitoring/policy/then/preferred-route/routing-instance",
	"/services/ip-monitoring/policy/then/preferred-route/routing-instance/route",
	"/services/rpm/probe",
	"/services/rpm/probe/test",
	"/snmp/community",
	"/snmp/trap-group",
	"/snmp/v3/usm/local-engine/user",
	"/system/login/user",
	"/system/ntp/server",
	"/system/ntp/threshold",
	"/system/services/dhcp-local-server/group",
	"/system/services/dhcp-local-server/group/interface",
	"/system/services/dhcp-local-server/group/pool",
	"/system/services/dhcpv6-local-server/group",
	"/system/services/dhcpv6-local-server/group/interface",
	"/system/services/dhcpv6-local-server/group/pool",
	"/system/services/dynamic-dns/provider",
}

// instanceNameBlindCeiling9091 is derived so the two can never disagree.
var instanceNameBlindCeiling9091 = len(instanceNameBlindBaseline9091)

// instanceNameArmedFloor9091 is the count of instance-name containers already
// covered by a closed-world subtree. Asserted so the instrument cannot report
// "nothing is blind" by having stopped finding anything.
// instanceNameArmedFloor9091 is the count of instance-name containers already
// covered by a closed-world subtree, with the SET beside it for the same reason
// as above.
//
// #9351 moved it 7 -> 8: making `routing-instances <n> protocols` the GLOBAL
// protocols node brought `rip group` — which carries closedWorld — into the
// per-instance grammar, so `/routing-instances/*/protocols/rip/group` is armed
// there too. That is the ratchet moving in the direction it wants.
// #9878 moved it 23 -> 27: arming `security zones` + `security policies`
// brings four instance-name containers inside a closed world
// (from-zone, from-zone/policy, global/policy, zones/security-zone).
// #9416 moved it 8 -> 9: `snmp community <c> routing-instance <ri>` is a new
// instance-name container, and every keyword it can absorb is a SOURCE
// RESTRICTION (`clients`, `client-list-name`). An unmodelled keyword there
// would commit clean and leave the community answering EVERY source — the
// defect #9416 exists to close, one level deeper — so the body was declared
// leaf-complete and armed rather than added to the blind baseline.
var instanceNameArmedBaseline9091 = []string{
	"/chassis/cluster/control-ports/fpc",
	"/chassis/cluster/redundancy-group/node",
	"/chassis/device-map/interface",
	"/class-of-service/scheduler-maps/forwarding-class",
	"/interfaces/*/unit/family/inet/address/vrrp-group/track-interface",
	"/interfaces/*/unit/family/inet6/address/vrrp-group/track-interface",
	"/policy-options/community",
	"/protocols/ospf/area/interface/authentication/md5",
	"/protocols/rip/group",
	"/routing-instances/*/protocols/ospf/area/interface/authentication/md5",
	"/routing-instances/*/protocols/rip/group",
	"/security/address-book/global/address-set",
	"/security/ike/proposal",
	"/security/ipsec/proposal",
	"/security/ipsec/vpn/traffic-selector",
	"/security/nat/nat64/rule-set",
	"/security/nat/proxy-arp/interface",
	"/security/policies/from-zone",
	"/security/policies/from-zone/policy",
	"/security/policies/global/policy",
	"/security/zones/security-zone",
	"/security/zones/security-zone/address-book/address-set",
	"/snmp/community/routing-instance",
	"/system/backup-router",
	"/system/login/class",
	"/system/services/dhcp-local-server/group/pool/static-binding",
	"/system/services/dhcpv6-local-server/group/pool/static-binding",
}

var instanceNameArmedFloor9091 = len(instanceNameArmedBaseline9091)

func TestInstanceNameBlindPopulationIsRatcheted9091(t *testing.T) {
	blind, armed := instanceNameBlind9091()

	// SET comparison, not count comparison (#9351). A count is blind to a SWAP:
	// one container armed and one added in the same change leaves 158 == 158 and
	// the ratchet stays green while a new blind site landed.
	if arrived := added9091(blind); len(arrived) > 0 {
		t.Errorf("#9091: the schema-blind instance-name container population GREW to "+
			"%d (baseline %d). A new container that takes an instance name, declares "+
			"children and sits outside a closed world accepts an unknown keyword in "+
			"its body at commit — the operator gets no value and no complaint. Arm "+
			"it (closedWorld) or, if it is genuinely open-world, add it to "+
			"instanceNameBlindBaseline9091 WITH the reason.\nnew: %v",
			len(blind), instanceNameBlindCeiling9091, arrived)
	}
	if gone := removed9091(blind); len(gone) > 0 {
		t.Errorf("#9091: the population SHRANK to %d (baseline %d) — good, but drop "+
			"these from instanceNameBlindBaseline9091 in the same change. A baseline "+
			"left above reality stops being a ratchet: it silently re-admits every "+
			"container it still lists.\ngone: %v",
			len(blind), instanceNameBlindCeiling9091, gone)
	}
	if a := diff9091(armed, instanceNameArmedBaseline9091); len(a) > 0 {
		t.Errorf("#9091: newly ARMED: %v. Arming is the remedy, so this moving is "+
			"expected — record it in instanceNameArmedBaseline9091 in the same "+
			"change.", a)
	}
	if g := diff9091(instanceNameArmedBaseline9091, armed); len(g) > 0 {
		t.Errorf("#9091: no longer ARMED: %v. A DROP means a closed world was "+
			"disarmed and its container silently went back to accepting unknown "+
			"keywords.", g)
	}
	if len(armed) != instanceNameArmedFloor9091 {
		t.Errorf("#9091: the ARMED count moved to %d (expected %d). Arming is the "+
			"remedy, so it moving is expected — but it must move deliberately, and "+
			"a DROP means a closed world was disarmed and its container silently "+
			"went back to accepting unknown keywords.\narmed: %v",
			len(armed), instanceNameArmedFloor9091, armed)
	}
}

// TestInstanceNameBlindInstrumentStillDiscriminates9091 is the control, and it
// runs in BOTH directions on purpose.
//
// A ratchet that goes green because its population emptied is indistinguishable
// from one that went green because it stopped looking. A count assertion alone
// cannot tell those apart: break the predicate, the walk, or the closedWorld
// inheritance and the number simply changes, which reads as news about the
// schema rather than about the instrument.
//
// So the instrument is pinned against containers whose classification #9091
// established INDEPENDENTLY, by measuring commit behaviour end-to-end at
// configstore.CheckText rather than by reading the schema. That the two
// instruments agree on these six is a cross-check, not a restatement.
func TestInstanceNameBlindInstrumentStillDiscriminates9091(t *testing.T) {
	blind, armed := instanceNameBlind9091()
	if len(blind) == 0 || len(armed) == 0 {
		t.Fatalf("#9091: the enumeration returned blind=%d armed=%d. An empty side "+
			"makes every verdict below vacuous — the instrument is broken, not the "+
			"schema clean.", len(blind), len(armed))
	}
	set := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, p := range l {
			m[p] = true
		}
		return m
	}
	blindSet, armedSet := set(blind), set(armed)

	// Direction 1 — known BLIND. #9091 measured each of these accepting a bogus
	// keyword at CheckText.
	// #9265 re-anchored this list rather than shortening it. `/system/login/class`
	// was here as a third known-BLIND witness and is now ARMED, so it moves to
	// direction 2 below — the move this cell's own failure message prescribes
	// ("Either it was armed (then lower the ceiling and say so) or the instrument
	// stopped detecting blindness"). Both witnesses that remain are DEEP
	// containers, and `closedWorld` INHERITS, so arming either would close its
	// whole subtree (the measured #9017 lesson). That is why they are still blind,
	// and it makes them durable anchors rather than the next ones to go.
	for _, p := range []string{
		"/security/ike/gateway", // security ike gateway g1 { bogus-token 5; } -> ACCEPTED
		"/security/ipsec/vpn",   // security ipsec vpn v1   { bogus-token 5; } -> ACCEPTED
	} {
		if !blindSet[p] {
			t.Errorf("#9091: %s is no longer classified blind. Either it was armed "+
				"(then lower the ceiling and say so) or the instrument stopped "+
				"detecting blindness — and those two look identical in the count.", p)
		}
	}

	// Direction 2 — known ARMED. Without this, a predicate that classified
	// EVERYTHING as blind would pass direction 1 completely.
	for _, p := range []string{
		"/protocols/rip/group",   // armed by #9206
		"/security/ike/proposal", // armed by an earlier closed-world flip
		// #9265, and it carries the cross-check this direction needs: #9091
		// measured `system login class c1 { xpfbogus 5; }` ACCEPTED at
		// configstore.CheckText, and #9265 re-measured it REJECTED there after
		// arming, with the same container's declared body still committing. So
		// this entry is pinned by an end-to-end measurement in BOTH states, not
		// by re-reading the schema flag this function already reads.
		"/system/login/class",
	} {
		if !armedSet[p] {
			t.Errorf("#9091: %s is no longer classified armed. If a closed world was "+
				"disarmed that is a real regression; if not, the instrument has "+
				"stopped seeing closedWorld inheritance and every 'armed' verdict "+
				"it reports is unearned.", p)
		}
	}

	// A path in NEITHER set that should be in one would be invisible above, so
	// pin that the two sets are disjoint and that a non-candidate stays out.
	for _, p := range blind {
		if armedSet[p] {
			t.Errorf("#9091: %s is in both sets — the classification is not a partition", p)
		}
	}
	// `security flow tcp-session` has args==0, so it is not a candidate at all.
	// #9091 measured it REJECTING a bogus keyword; if it ever appears here the
	// predicate has drifted off "takes an instance name".
	if blindSet["/security/flow/tcp-session"] || armedSet["/security/flow/tcp-session"] {
		t.Error("#9091: /security/flow/tcp-session is args==0 and must not be a " +
			"candidate — the predicate has drifted off 'takes an instance name'")
	}
}

// added9091 reports the paths that would need justifying if the ceiling were
// raised. Cheap to compute and it turns a bare count into something reviewable:
// an aggregate count is not reviewable, the list is.
func added9091(blind []string) []string {
	return diff9091(blind, instanceNameBlindBaseline9091)
}

// removed9091 is the other half, and it has to exist for the same reason the
// SHRANK branch does: a container leaving the population is news too.
func removed9091(blind []string) []string {
	return diff9091(instanceNameBlindBaseline9091, blind)
}

// diff9091 returns the members of a that are not in b.
func diff9091(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
