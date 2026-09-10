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

// lenientDroppedConstraintToken is the synthetic offending-token label recorded
// for a rule the lenient / HA-sync compile path poisons because the compiler
// SILENTLY DROPPED a match / then-permit constraint (#5575) — a missing required
// match dimension, an unsupported `match` leaf, or an unsupported `then permit`
// modifier (config.Policy.LenientContentDropped). There is no single
// unrepresentable token to name (the offending constraint was dropped, not left
// behind), so this label stands in for collectPolicyContentRejections' #3376
// per-side reason. It is a build-time diagnostic only, never emitted on the wire.
const lenientDroppedConstraintToken = "lenient-dropped-match-or-then-permit-constraint"

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

// policyRuleSlot describes a single configured policy's assignment within the
// runtime policy-ID namespace. The numeric runtime policy ID is
// PolicySetID*MaxRulesPerPolicy + RuleIndex, and the policy occupies Span
// contiguous IDs starting at that base (one per application-set expansion term).
type policyRuleSlot struct {
	PolicySetID uint32
	RuleIndex   uint32 // start index within the policy set's 256-slot namespace
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
	return s.PolicySetID*dataplane.MaxRulesPerPolicy + s.RuleIndex
}

// walkPolicyRuleSlots invokes fn for every configured policy in config order,
// assigning each policy its slot in the runtime policy-ID namespace. It is the
// SHARED contract behind both the snapshot builder (the ID-WRITE side, #3145)
// and the counter resolver (the ID-READ side, #3143) so the two can never
// drift on how a policy ID maps to a (policy-set, rule-index) pair.
//
// Each policy's application-set expansion advances the per-set rule index by
// userspacePolicyRuleExpansionCount. A policy set may exactly fill its 256-slot
// namespace (indices 0..255, the full MaxRulesPerPolicy range) — every such ID
// stays inside the set's own namespace. Only a policy whose expansion would
// advance the per-set rule index PAST MaxRulesPerPolicy (256) — i.e. require an
// ID at index >= 256 — would cross into the following set's namespace; that is
// rejected fail-closed so the apply path retains the prior good dataplane state.
// This mirrors the legacy compiler guard (pkg/dataplane/compiler.go).
func walkPolicyRuleSlots(cfg *config.Config, fn func(slot policyRuleSlot) error) error {
	if cfg == nil {
		return nil
	}
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			policySetID++
			continue
		}
		ruleIndex := uint32(0)
		for sliceIdx, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			span := userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
			if ruleIndex+span > dataplane.MaxRulesPerPolicy {
				return fmt.Errorf("policy %s->%s: expanded rules exceed MaxRulesPerPolicy (%d) and would spill into the next policy set's ID namespace",
					zpp.FromZone, zpp.ToZone, dataplane.MaxRulesPerPolicy)
			}
			if err := fn(policyRuleSlot{
				PolicySetID: policySetID,
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
		}
		policySetID++
	}
	globalRuleIndex := uint32(0)
	for sliceIdx, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		span := userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
		if globalRuleIndex+span > dataplane.MaxRulesPerPolicy {
			return fmt.Errorf("global policy: expanded rules exceed MaxRulesPerPolicy (%d) and would spill into the next policy set's ID namespace",
				dataplane.MaxRulesPerPolicy)
		}
		if err := fn(policyRuleSlot{
			PolicySetID: policySetID,
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
