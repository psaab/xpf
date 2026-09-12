package config

import (
	"fmt"
	"net/netip"
	"sort"
)

// vrfOverlapPrefix records one L3 prefix carried by a routing-instance together
// with a human-readable origin (the interface or the PBR filter/term that put
// it there) so the overlap warning can name where each side comes from.
type vrfOverlapPrefix struct {
	prefix netip.Prefix // masked network prefix
	origin string       // e.g. `interface "ge-0/0/1.0"` or `filter "fbf" term "t1"`
	// steered marks space a PBR `then routing-instance` term put here, as
	// opposed to a member interface's address.
	steered bool
	// steeredAll marks the MATCH-ALL space of a steering term written with
	// `any`, with no address match, or with an empty `except` list (#9809). It
	// pairs only with steered space from ANOTHER filter; see validateVRFOverlap.
	steeredAll bool
	// filter names the firewall filter a steered prefix came from.
	filter string
}

const (
	// vrfOverlapMaxWarnings caps how many cross-routing-instance overlap
	// advisories one compile emits (#5194 A3-b3-F5). A config with a large
	// number of overlapping prefixes must not flood commit output; the (N+1)th
	// overlap collapses into a single truncation notice.
	vrfOverlapMaxWarnings = 64
	// vrfOverlapMaxComparisons bounds the total prefix-pair comparisons this
	// advisory-only scan performs (#5194 A3-b3-F5). The pairwise scan is O(P^2)
	// across every routing-instance prefix; on a pathological config (thousands
	// of prefixes per RI across many RIs) that is millions of Overlaps() calls
	// on EVERY strict AND tolerant compile, including HA peer-sync. This is a
	// cold advisory path (a warning, never a reject), so once the budget is
	// spent the scan stops and emits a truncation notice rather than letting the
	// cross-VRF advisory dominate commit latency.
	vrfOverlapMaxComparisons = 1 << 20 // ~1M
)

// validateVRFOverlap warns when two DISTINCT routing-instances carry
// overlapping L3 address space, and refuses that overlap combined with a PBR
// `then routing-instance` term (#7924).
//
// What the session identity separates today (#9809 rewrote this from the #2387
// original, which predates #7160 and #9519):
//   - SessionKey carries a routing domain derived from the LOGICAL INGRESS
//     interface (userspace-dp/src/afxdp/forwarding/mod.rs), so flows arriving on
//     member interfaces of different instances do not share an entry.
//   - Flows PBR steers in from default-instance ingress stay routing domain 0 in
//     both directions, so two steered flows that share a 5-tuple resolve one
//     entry. The established-session fast path runs before the PBR table
//     override, and the second flow inherits the first one's cached egress and
//     NAT.
//   - Policy is evaluated again only when the colliding hit arrives from another
//     zone (#9519); a same-zone collider inherits the policy decision too.
//
// That steered residual is what the #7924 refusal covers. Whether a member
// overlap combined with an unrelated PBR term still needs refusing, now that
// such flows are domain-separated, is a maintainer question recorded on #9809;
// this function still refuses it. See userspace-dp/src/afxdp/forwarding/README.md.
//
// The warning text below therefore states the CURRENT limitation and points at
// the tracking issue; it must not promise a fix, nor rule one out. It used to
// say colliding 5-tuples may cross-forward "until the session identity is
// VRF-aware", which asserted an outcome the open decision may never produce —
// and which the #2387 plan then cited back as evidence for that same outcome.
// TestVRFOverlapWarningStatesStatusNotPromise enforces that in BOTH format
// strings below — but enforces it PARTIALLY, and the difference matters if you
// are editing this text. It pins the closing status sentence verbatim, so the
// tail cannot be reworded or dropped, and nothing can be appended after it
// EXCEPT text that itself re-terminates with the tail verbatim — a contrived
// escape, recorded so nobody reasons from "appends are impossible". Wording
// spliced into the
// MIDDLE of the message is caught only if it uses a spelling on that test's
// token lists, which are blocklists and incomplete by construction. A forecast
// in either direction, phrased in a way nobody listed, will commit green. The
// text is neutral today because it was written to be, not because the test
// would stop you.
//
// Detection builds routing-instance -> set-of-prefixes from two sources:
//  1. native RI membership — each member interface unit's configured addresses
//     (the connected L3 space that lives in that VRF). A bare member is every
//     configured unit (RoutingInstanceMemberUnits, #9809), as the FIB binds it;
//  2. PBR filter terms — the space a `then routing-instance <name>` term steers
//     INTO that VRF, as the PBR rule builder realises it (PBRDirectionSteers,
//     #9809): prefix-lists expand, a bare host is a /32 or /128, and a term the
//     builder drops contributes nothing. A term that matches every address
//     (`any`, no address match, an empty `except`) adds MATCH-ALL steered space,
//     which pairs only with steered space from ANOTHER filter. The residual
//     above is one 5-tuple steered into two instances. A member prefix against
//     steered space is the domain-separated pair, and two terms of ONE filter
//     cannot both steer a packet, because the first match wins: a DSCP-only
//     catch-all after an address term (TestFirewallFilter's multi-WAN filter)
//     is not a collision. A literal 0.0.0.0/0 or ::/0 keeps its pre-#9809
//     behaviour and pairs with everything.
//
// then compares the prefix sets of every unordered pair of distinct
// routing-instances for overlap (net/netip Prefix.Overlaps — contains-or-equal).
// Deterministic ordering (sorted RI names, sorted filter names, sorted
// prefixes) so the warning set is stable across commits.
func validateVRFOverlap(cfg *Config, lenientPBR bool) ([]string, []VRFOverlapAdmission, error) {
	if cfg == nil {
		return nil, nil, nil
	}
	// #7991: the structured findings the runtime reporter exports. Built at the
	// SAME points the warnings are, and the warnings are rendered FROM them, so a
	// metric and an advisory can never describe different detections.
	var admissions []VRFOverlapAdmission
	// #7924: does ANY PBR term steer into a routing-instance? This is the second
	// half of the narrow rejection condition, and it is deliberately a
	// config-level fact rather than a property of the overlapping pair.
	//
	// The defect needs PBR to be steering at all: the established-session fast
	// path short-circuits before `ingress_route_table_override`
	// (poll_descriptor/mod.rs), and that override is what a `then
	// routing-instance` term sets. With no such term nothing re-homes a flow's
	// table mid-path, so two overlapping RIs cannot collide through it and the
	// pre-#7924 warning is the correct disposition.
	sawPBRRoutingInstance := false

	// riPrefixes[riName] = de-duplicated, origin-tagged prefix set.
	riPrefixes := map[string][]vrfOverlapPrefix{}
	// seen[riName][maskedPrefixString] dedupes a prefix that appears from more
	// than one origin (e.g. a native interface AND a PBR term). The first origin
	// encountered wins; native interfaces are processed before PBR terms and both
	// in deterministic order, so the retained origin is stable.
	seen := map[string]map[string]bool{}
	addPrefix := func(riName, cidr, origin, filter string, steered, steeredAll bool) {
		if riName == "" || cidr == "" {
			return
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return
		}
		p = p.Masked()
		key := p.String()
		if steeredAll {
			key += "|all"
		}
		if seen[riName] == nil {
			seen[riName] = map[string]bool{}
		}
		if seen[riName][key] {
			return
		}
		seen[riName][key] = true
		riPrefixes[riName] = append(riPrefixes[riName], vrfOverlapPrefix{prefix: p, origin: origin, steered: steered, steeredAll: steeredAll, filter: filter})
	}

	// Source 1: native routing-instance membership -> member interface unit
	// addresses. cfg.RoutingInstances is a slice (deterministic order); each
	// ri.Interfaces entry is a Junos interface name, optionally `.unit`.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, member := range ri.Interfaces {
			// #9809: a bare member is every configured unit, not unit 0.
			for _, mu := range RoutingInstanceMemberUnits(cfg, member) {
				origin := fmt.Sprintf("interface %q", mu.Ref)
				for _, addr := range mu.Addresses {
					addPrefix(ri.Name, addr, origin, "", false, false)
				}
			}
		}
	}

	// Source 2: PBR `then routing-instance <name>` filter terms. A family-agnostic
	// filter is duplicated into both FiltersInet and FiltersInet6; process both
	// maps in sorted-name order and let the per-RI prefix de-dup collapse the
	// repeat.
	pls := cfg.PolicyOptions.PrefixLists
	addFilterTerms := func(filterName string, filter *FirewallFilter, matchAll netip.Prefix) {
		if filter == nil {
			return
		}
		for _, term := range filter.Terms {
			if term == nil || term.RoutingInstance == "" {
				continue
			}
			// #7924: a `then routing-instance` term exists. Recorded even when the
			// term carries no source/destination prefixes and so contributes
			// nothing to the overlap sets — it still installs the table override
			// the fast path skips, which is the mechanism, so gating on "the term
			// contributed a prefix" would miss a match-all steering term.
			sawPBRRoutingInstance = true
			origin := fmt.Sprintf("filter %q term %q", filterName, term.Name)
			// #9809: the space the builder steers, not only literals that parse.
			srcs, srcAll, srcNone := PBRDirectionSteers(term.SourceAddresses, term.SourcePrefixLists, pls)
			dsts, dstAll, dstNone := PBRDirectionSteers(term.DestAddresses, term.DestPrefixLists, pls)
			if srcNone || dstNone {
				continue // the builder installs no rule for this term
			}
			for _, addr := range srcs {
				addPrefix(term.RoutingInstance, addr, origin, filterName, true, false)
			}
			for _, addr := range dsts {
				addPrefix(term.RoutingInstance, addr, origin, filterName, true, false)
			}
			if srcAll && dstAll {
				addPrefix(term.RoutingInstance, matchAll.String(), origin, filterName, true, true)
			}
		}
	}
	for _, fam := range []struct {
		filters  map[string]*FirewallFilter
		matchAll netip.Prefix
	}{
		{cfg.Firewall.FiltersInet, netip.MustParsePrefix("0.0.0.0/0")},
		{cfg.Firewall.FiltersInet6, netip.MustParsePrefix("::/0")},
	} {
		names := make([]string, 0, len(fam.filters))
		for name := range fam.filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			addFilterTerms(name, fam.filters[name], fam.matchAll)
		}
	}

	// Compare every unordered pair of distinct routing-instances. Sort RI names
	// and each RI's prefixes so the pairwise scan is deterministic.
	riNames := make([]string, 0, len(riPrefixes))
	for name := range riPrefixes {
		riNames = append(riNames, name)
	}
	sort.Strings(riNames)
	for _, name := range riNames {
		set := riPrefixes[name]
		sort.Slice(set, func(i, j int) bool {
			return set[i].prefix.String() < set[j].prefix.String()
		})
		riPrefixes[name] = set
	}

	var warnings []string
	// #5194 A3-b3-F5: bound this O(P^2) advisory scan. `comparisons` spends the
	// operation budget; the warning cap stops once enough advisories are
	// collected. Either limit trips `truncated`, which appends one notice so the
	// operator knows the scan was incomplete rather than silently under-reporting.
	comparisons := 0
	truncated := false
Scan:
	for i := 0; i < len(riNames); i++ {
		for j := i + 1; j < len(riNames); j++ {
			riA, riB := riNames[i], riNames[j]
			for _, a := range riPrefixes[riA] {
				for _, b := range riPrefixes[riB] {
					if comparisons >= vrfOverlapMaxComparisons {
						truncated = true
						break Scan
					}
					comparisons++
					// Family-separated: an IPv4 and an IPv6 prefix never overlap,
					// so skip the pair cheaply before the Overlaps() call.
					if a.prefix.Addr().Is4() != b.prefix.Addr().Is4() {
						continue
					}
					// #9809: match-all steered space pairs only with steered space
					// from ANOTHER filter. Against a member prefix it is the
					// domain-separated pair, and within one filter the first
					// matching term wins, so its terms never steer one packet twice.
					if (a.steeredAll || b.steeredAll) && !(a.steered && b.steered && a.filter != b.filter) {
						continue
					}
					if !a.prefix.Overlaps(b.prefix) {
						continue
					}
					if len(warnings) >= vrfOverlapMaxWarnings {
						truncated = true
						break Scan
					}
					found := VRFOverlapAdmission{
						InstanceA: riA, InstanceB: riB,
						PrefixA: a.prefix.String(), PrefixB: b.prefix.String(),
						OriginA: a.origin, OriginB: b.origin,
					}
					admissions = append(admissions, found)
					warnings = append(warnings, found.warning())
				}
			}
		}
	}
	if truncated {
		warnings = append(warnings, fmt.Sprintf(
			"cross-routing-instance overlap validation was truncated after %d prefix "+
				"comparisons / %d advisories (config exceeds the advisory scan budget); "+
				"some overlaps may be unreported",
			comparisons, len(warnings)))
	}
	// #7924: promote to a REJECTION for the narrow combination that is already
	// silently wrong — overlap AND PBR steering. See lenientVRFOverlapPBR for the
	// #1960 no-brick reasoning behind the lenient downgrade.
	//
	// This is a WORKAROUND WITH A DEBT, not the fix. The real fix is #7160: widen
	// the session key with a routing-domain discriminator
	// (StableRoutingInstanceTableID) so the two flows stop colliding at all,
	// staged behind #7925. This gate refuses a configuration the dataplane cannot
	// currently forward correctly; it does not make that configuration work, and
	// it must not become a substitute for #7160.
	if len(warnings) > 0 && sawPBRRoutingInstance && !lenientPBR {
		return warnings, admissions, fmt.Errorf(
			"overlapping L3 across routing-instances combined with a PBR `then "+
				"routing-instance` term is refused: flows PBR steers in from "+
				"default-instance ingress share routing domain 0 in the session "+
				"identity (#7160 separates flows on member interfaces, not steered "+
				"ones), and the established-session fast path runs BEFORE the PBR "+
				"table override, so a second flow sharing a 5-tuple inherits the first "+
				"flow's cached egress and NAT, and its POLICY decision unless it "+
				"arrives from another zone (#9519), across the tenant boundary "+
				"(#7924). Overlapping VRF address space WITHOUT PBR steering still "+
				"commits with a warning. First overlap: %s", warnings[0])
	}
	// #7991: the findings are reported ONLY when PBR steering is present — that
	// is the combination the strict path refuses, and therefore the only one a
	// tolerant load can be said to have ADMITTED. Plain VRF overlap with no PBR
	// term commits on the strict path too, so reporting it would make the metric
	// fire on configurations that are not in the tolerant-admitted state at all.
	if !sawPBRRoutingInstance {
		admissions = nil
	}
	return warnings, admissions, nil
}

// VRFOverlapAdmission is one cross-routing-instance L3 overlap that the STRICT
// commit path refuses when combined with PBR `then routing-instance` steering,
// but that a TOLERANT load (an already-persisted config at upgrade, or HA
// peer-sync — `lenientVRFOverlapPBR`) admits (#7991).
//
// It exists so the tolerant-admitted state has a machine-readable runtime
// signal, mirroring #3718's AmbiguousHostInboundAddress. #3718 is the
// structurally identical case — "the tolerant path admitted something strict
// rejects" — and it has a metric; an operator who knows to look for that metric
// reads its absence here as the condition being absent, when it means nobody
// exported it.
type VRFOverlapAdmission struct {
	// InstanceA, InstanceB are the two routing-instance names, in the scan's
	// deterministic (sorted) order.
	InstanceA, InstanceB string
	// PrefixA, PrefixB are the overlapping prefixes, masked. Equal when the two
	// instances carry the identical prefix.
	PrefixA, PrefixB string
	// OriginA, OriginB record where each prefix came from (a member interface,
	// or a PBR `then routing-instance` term), for the warning text.
	OriginA, OriginB string
}

// warning renders the operator-facing advisory for one overlap. The warning and
// the metric are produced from the SAME finding so they can never disagree about
// what was detected — the failure mode that a second copy of the scan would
// have, and the reason this is a formatter rather than an inline Sprintf.
func (o VRFOverlapAdmission) warning() string {
	if o.PrefixA == o.PrefixB {
		return fmt.Sprintf(
			"routing-instance %q (%s) and %q (%s) both carry %s: "+
				"overlapping L3 across routing-instances is forwarded via "+
				"PBR but is NOT session-isolated (#2387) — flows PBR steers "+
				"in from default-instance ingress share routing domain 0 in "+
				"the session identity, so "+
				"colliding 5-tuples may cross-forward. See #2387 for the "+
				"status of this limitation",
			o.InstanceA, o.OriginA, o.InstanceB, o.OriginB, o.PrefixA)
	}
	return fmt.Sprintf(
		"routing-instance %q (%s, %s) and %q (%s, %s) carry "+
			"overlapping L3: overlapping L3 across routing-instances is "+
			"forwarded via PBR but is NOT session-isolated (#2387) — flows "+
			"PBR steers in from default-instance ingress share routing "+
			"domain 0 in the session identity, "+
			"so colliding 5-tuples may cross-forward. See #2387 for the "+
			"status of this limitation",
		o.InstanceA, o.OriginA, o.PrefixA, o.InstanceB, o.OriginB, o.PrefixB)
}

// TolerantVRFOverlapAdmissions returns the overlaps that make this config one
// the STRICT commit path would refuse — cross-routing-instance L3 overlap AND a
// PBR `then routing-instance` term — in the detector's deterministic order.
// Empty for every config the strict path would accept.
//
// WHAT A NON-EMPTY RESULT MEANS, because a metric nobody can interpret is not an
// improvement: on such a box a second steered flow sharing a 5-tuple (both in
// routing domain 0, #9809) hits the FIRST flow's conntrack entry and inherits
// its cached egress and NAT. The established-session fast path runs before the
// PBR table override. A hit from the same zone is treated as the owner and
// inherits the policy decision too; a hit from another zone is re-evaluated
// against that zone's policy (#9519) and, on permit, still forwards with the
// first flow's egress and NAT. So tenant-b's packets can leave via tenant-a's
// egress with tenant-a's NAT. That is a cross-tenant forwarding path, not a
// configuration-hygiene advisory.
//
// Runs the SAME detector the commit gate runs (leniently, so it reports rather
// than errors), for the reason #3718's reporter states about its own builder:
// the observability signal can never disagree with what the gate decided,
// because there is only one scan. It is bounded by the same
// vrfOverlapMaxComparisons budget, so a pathological config cannot make a
// metrics scrape expensive.
func TolerantVRFOverlapAdmissions(cfg *Config) []VRFOverlapAdmission {
	if cfg == nil {
		return nil
	}
	_, admissions, _ := validateVRFOverlap(cfg, true)
	return admissions
}
