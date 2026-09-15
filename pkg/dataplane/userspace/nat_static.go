package userspace

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// clampPort narrows a compiler-stored port (int; 0 = port ABSENT / match-any,
// the whole-address 1:1 wildcard sentinel) into the u16 wire slot. Callers MUST
// first reject a PRESENT-but-out-of-range value with
// config.StaticNATRuleExcludedReason —
// buildStaticNATSnapshots drops such a rule so it fails CLOSED — because the
// only in-band "no port" value here is 0, which the Rust side reads as the
// whole-address wildcard. Coercing an invalid port to 0 would therefore
// fail OPEN (expose every port of the external address), not closed (#5101).
// The residual out-of-range guard below is a belt-and-suspenders narrow;
// it should be unreachable given the upstream drop.
func clampPort(p int) uint16 {
	if p < 1 || p > 65535 {
		return 0
	}
	return uint16(p)
}

func buildStaticNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []StaticNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	out := make([]StaticNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			// Fail-closed drops (#5859 `then static-nat inet`, #5101
			// out-of-range destination/mapped port). Both verdicts come from
			// config.StaticNATRuleExcludedReason so this builder and the
			// natshow renderers cannot disagree about which rules are armed
			// (#6534) — the rationale for each clause lives with the
			// predicate. Strict commit rejects both outright; this is the
			// lenient load / peer-sync backstop.
			if reason := config.StaticNATRuleExcludedReason(rule); reason != "" {
				slog.Warn("userspace snapshot: dropping static NAT rule (fail-closed, #5859/#5101/#9877)",
					"ruleset", rs.Name, "rule", rule.Name, "reason", reason,
					"then", rule.Then,
					"match_destination_port", rule.MatchDestinationPort,
					"mapped_port", rule.MappedPort)
				continue
			}
			// #3435: carry the `match source-address` constraint into the
			// snapshot. Prefer the full bracket-list (SourceAddresses); fall
			// back to the singular SourceAddress for an older typed config.
			// Empty = match any source (unscoped, pre-#3435 behavior).
			sourceAddrs := append([]string(nil), rule.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.SourceAddress)
			}
			out = append(out, StaticNATRuleSnapshot{
				Name:                 rule.Name,
				FromZone:             rs.FromZone,
				FromInterface:        rs.FromInterface,
				FromRoutingInstance:  rs.FromRoutingInstance,
				SourceAddresses:      sourceAddrs,
				ExternalIP:           rule.Match,
				InternalIP:           rule.Then,
				MatchDestinationPort: clampPort(rule.MatchDestinationPort),
				MappedPort:           clampPort(rule.MappedPort),
				CounterID:            natCounterID(natCounterIDs, dataplane.NATCounterTypeStatic, rs.Name, rule.Name),
			})
		}
	}
	return out
}
