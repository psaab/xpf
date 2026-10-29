package userspace

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// unsupportedApplicationSentinel is the reserved protocol/name token emitted in
// a policy rule's application terms (#2124) when the userspace matcher cannot
// represent the rule's configured applications. It is deliberately not a valid
// protocol name or 0..255 numeric, so the Rust matcher drops it and the rule's
// all-dropped non-empty term list is rejected as a SnapshotIntegrityError
// (fail closed) instead of decoding to genuine match-any. Must stay unparseable
// by both appid.ProtocolNumber and userspace-dp parse_protocol.
const unsupportedApplicationSentinel = "__unsupported__"

// dnsUnavailableApplicationSentinel marks one rule for Rust-side
// fail-closed quarantine when its DNS address constraint is unavailable.
// Unlike unsupportedApplicationSentinel, Rust recognizes this marker, drops
// only the marker term, and enforces the containing rule as deny.
const dnsUnavailableApplicationSentinel = "__dns_unavailable__"

// lenientDroppedConstraintToken is the synthetic offending-token label recorded
// for a policy the lenient / HA-sync compile path poisons because the compiler
// silently dropped enforcement content (#5575, #11013, #11014). There is no
// single unrepresentable token to name (the authored constraint was dropped,
// not left behind), so this label stands in for
// collectPolicyContentRejections' #3376 per-side reason. It is a build-time
// diagnostic only, never emitted on the wire.
const lenientDroppedConstraintToken = "lenient-dropped-policy-enforcement-constraint"

// unsupportedAddressSentinel is the reserved address literal emitted in a policy
// rule's source/destination address fields (#3261) when the userspace matcher
// cannot represent the rule's configured addresses — an undefined address-book
// name, or a defined book whose value is a non-literal (Junos dns-name /
// wildcard-address / range-address). It is the ADDRESS analog of
// unsupportedApplicationSentinel: without it the raw address strings fall
// through to the Rust matcher, which silently drops an unparseable literal
// (parse_literal_cidr_into) or empties a non-literal book, collapsing the side
// to MatchNone. A `deny <unrepresentable-address>` rule would then match
// nothing and fall through to a later permit / default-permit — a deny
// fail-OPEN. Emitting this sentinel makes the Rust integrity preflight raise
// SnapshotIntegrityError::UnrepresentableAddress, rejecting the WHOLE snapshot
// (previous-good retained; fresh-boot default-deny), symmetric to the
// application path. It is deliberately not a valid CIDR/IP so it can never
// match real traffic even on an older helper that lacks the preflight arm.
// Must stay in lock-step with userspace-dp policy.rs UNREPRESENTABLE_ADDRESS_SENTINEL.
const unsupportedAddressSentinel = "__unsupported_address__"

// PolicyCounterID returns the slice-index COUNTER handle for the policy at
// (policySetID, sliceIndex): policySetID*MaxRulesPerPolicy + sliceIndex.
// This is the ONLY positional encoding left after #16560 and it is a
// handle, not an identity: the counter store is name-keyed, so the handle
// only needs caller/resolver agreement. It stays in the legacy 256-wide
// block geometry so the retired eBPF policy_counters map (MAX_POLICIES
// entries) keeps working; MaxPolicySets bounds policySetID. Runtime
// PolicyIDs (policyID below) are a different namespace: contiguous
// per-set ranges, span-accumulated.
func PolicyCounterID(policySetID uint32, sliceIndex uint32) uint32 {
	return policySetID*dataplane.MaxRulesPerPolicy + sliceIndex
}

// policyRuleSlot describes a single configured policy's assignment within
// the runtime policy-ID namespace. The numeric runtime policy ID is
// BaseID + RuleIndex, where BaseID is the cumulative expanded-rule offset
// of all earlier non-quarantined sets (#16560 contiguous allocation), and
// the policy occupies Span contiguous IDs starting there (one per
// application-set expansion term). PolicySetID remains the raw config
// ordinal, used only for the slice-index counter handle.
type policyRuleSlot struct {
	PolicySetID uint32
	BaseID      uint32 // cumulative expanded offset of this slot's set
	RuleIndex   uint32 // start index within the policy set's expanded range
	SliceIndex  uint32 // raw position within the set's policy slice (display key)
	Span        uint32 // expansion slots consumed (>=1)
	FromZone    string
	ToZone      string
	Policy      *config.Policy
	// Global is true for a `security policies global` rule. It is carried
	// because FromZone/ToZone cannot say it: a global rule gets the
	// `junos-global` sentinel on both sides, and so does a leniently-loaded
	// zone-pair stanza that names it on both sides (#9570).
	Global bool
}

func (s policyRuleSlot) policyID() uint32 {
	return s.BaseID + s.RuleIndex
}

// walkPolicyRuleSlots invokes fn for every configured policy in config order,
// assigning each policy its slot in the runtime policy-ID namespace. It is the
// SHARED contract behind the snapshot builder (the ID-WRITE side, #3145),
// the runtime-ID maps, and the daemon invalidation diff so they can never
// drift on how a policy ID maps to a configured policy.
//
// Since #16560 IDs are allocated as contiguous per-set ranges: each set's
// first expanded rule starts at the cumulative expanded-rule offset of all
// earlier non-quarantined sets, and each policy's application-set expansion
// advances its set-local rule index by userspacePolicyRuleExpansionCount.
// A set may therefore hold far more than the legacy 256-ID block; the only
// expansion bound is MaxTotalPolicyRuleExpansion across all sets, plus
// MaxPolicySets on the number of sets (the legacy counter-handle geometry).
// MaxTotalPolicyRuleExpansion caps the TOTAL expanded rule count across all
// zone-pair sets and globals (#11081): the Rust evaluator scans pair +
// wildcard + global tiers linearly per new flow — an unbounded set list is
// per-packet CPU amplification under new-flow flood with no ceiling.
// 65536 expanded rules is far above legitimate configs and catches
// runaway application expansion with a clear error instead of a silent
// slowdown. Overflow is rejected fail-closed so the apply path retains
// the prior good dataplane state.
const MaxTotalPolicyRuleExpansion = 65536

func walkPolicyRuleSlots(cfg *config.Config, fn func(slot policyRuleSlot) error) error {
	if cfg == nil {
		return nil
	}
	var totalExpanded uint64
	var setCount uint32
	var nextID uint32
	policySetID := uint32(0)
	// The snapshot quarantine later removes collision losers and poisoned
	// zones' zone-pair rules. Exclude those sets before expansion accounting
	// too: discarded rules must neither overflow a namespace / total cap nor
	// appear in policy-ID maps. Keep the raw set index stable for survivors.
	quarantined := config.ZoneQuarantineExclusionsForConfig(cfg)
	// #14329: reserved policy sentinels are never policy-quarantine members.
	// A poisoned reserved definition (DroppedEnforcementChild) must go
	// through its dedicated poison path (#9570 zone-pair junos-global,
	// #12249 defined-any) rather than silently erasing global rules
	// (From/To == junos-global), wildcard rules (any) or host rules
	// (junos-host). Delete unconditionally, even when poisoned.
	for _, name := range []string{config.JunosGlobalZoneName, config.ReservedWildcardZoneName, "junos-host"} {
		delete(quarantined, name)
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			policySetID++
			continue
		}
		if _, drop := quarantined[zpp.FromZone]; drop {
			policySetID++
			continue
		}
		if _, drop := quarantined[zpp.ToZone]; drop {
			policySetID++
			continue
		}
		setCount++
		baseID := nextID
		ruleIndex := uint32(0)
		for sliceIdx, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			span := userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
			if err := fn(policyRuleSlot{
				PolicySetID: policySetID,
				BaseID:      baseID,
				RuleIndex:   ruleIndex,
				SliceIndex:  uint32(sliceIdx),
				Span:        span,
				FromZone:    zpp.FromZone,
				ToZone:      zpp.ToZone,
				Policy:      pol,
			}); err != nil {
				return err
			}
			ruleIndex += span
			totalExpanded += uint64(span)
		}
		nextID = baseID + ruleIndex
		policySetID++
	}
	globalRuleIndex := uint32(0)
	// #14330/#14329: the snapshot quarantine (scrubPoliciesForQuarantinedZones)
	// drops a scoped-global rule whose configured match side has NO
	// surviving member after pruning quarantined zones. Such a rule is
	// never published, so it must not consume a global slot, appear in
	// PolicyIDsByStableKey/PoliciesByStableKey/RuntimePolicyIDs, or count
	// toward expansion caps. A partially quarantined side survives pruned
	// and keeps its slot/ID (fingerprint change is signalled by
	// PolicyResolvedFingerprints). policyQuarantined (quarantinedZoneNamesForConfig:
	// collision losers + poisoned zones, reserved sentinels excluded so
	// defined-`any` / junos-host scope handling stays with its own poison
	// paths) matches the scrub's effective semantics in the integrated
	// state, and the zone-pair `quarantined` set above likewise has the
	// reserved sentinels deleted (#14329 unconditional delete). A wildcard
	// scope (empty or containing "any") is all-zones, not a concrete
	// quarantined member, so it never triggers a skip; unscoped globals
	// are unaffected.
	policyQuarantined := quarantinedZoneNamesForConfig(cfg)
	globalScopeFullyQuarantined := func(zones []string) bool {
		if len(zones) == 0 || len(policyQuarantined) == 0 || config.IsWildcardZoneSet(zones) {
			return false
		}
		for _, z := range zones {
			if _, drop := policyQuarantined[z]; !drop {
				return false
			}
		}
		return true
	}
	globalBase := nextID
	globalCounted := false
	for sliceIdx, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		if globalScopeFullyQuarantined(pol.Match.FromZones) || globalScopeFullyQuarantined(pol.Match.ToZones) {
			continue
		}
		if !globalCounted {
			setCount++
			globalCounted = true
		}
		span := userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
		if err := fn(policyRuleSlot{
			PolicySetID: policySetID,
			BaseID:      globalBase,
			RuleIndex:   globalRuleIndex,
			SliceIndex:  uint32(sliceIdx),
			Span:        span,
			FromZone:    "junos-global",
			ToZone:      "junos-global",
			Policy:      pol,
			Global:      true,
		}); err != nil {
			return err
		}
		globalRuleIndex += span
		totalExpanded += uint64(span)
	}
	if setCount > dataplane.MaxPolicySets {
		return fmt.Errorf("policy: %d policy sets exceed MaxPolicySets (%d)", setCount, dataplane.MaxPolicySets)
	}
	if totalExpanded > MaxTotalPolicyRuleExpansion {
		return fmt.Errorf("policy: total expanded rules %d exceed MaxTotalPolicyRuleExpansion (%d); the dataplane evaluates tiers linearly per new flow — split, prune, or collapse application expansions",
			totalExpanded, MaxTotalPolicyRuleExpansion)
	}
	return nil
}

func isV4CIDR(s string) bool {
	ip, _, err := net.ParseCIDR(s)
	return err == nil && ip.To4() != nil
}

func isV6CIDR(s string) bool {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	// To4 returning non-nil means the string parsed as a 4-byte
	// address (or v4-mapped); only return true if the underlying
	// representation is 16 bytes (v6).
	return ip.To4() == nil && len(ipnet.IP) == net.IPv6len
}

// Silence unused-import warnings when this build is ever stripped
// of address-book content.
var _ = hex.EncodeToString
