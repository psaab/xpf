package userspace

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

func buildNptv6Snapshots(cfg *config.Config) []Nptv6RuleSnapshot {
	if cfg == nil {
		return nil
	}
	var out []Nptv6RuleSnapshot
	var loggedDroppedSet *config.StaticNATRuleSet
	for _, member := range config.NPTv6Rules(cfg) {
		rs, rule := member.RuleSet, member.Rule
		if member.UndefinedZone {
			if loggedDroppedSet != rs {
				slog.Warn("userspace snapshot: dropping NPTv6 rule-set with undefined from-zone (fail-closed, #16008)",
					"rule_set", rs.Name, "from_zone", rs.FromZone)
				loggedDroppedSet = rs
			}
			continue
		}
		if member.ExcludedReason != "" {
			slog.Warn("userspace snapshot: dropping NPTv6 rule with dropped match leaves (fail-closed, #9877)",
				"rule_set", rs.Name, "rule", rule.Name, "reason", member.ExcludedReason)
			continue
		}
		if member.ScopeUnsupported {
			slog.Warn("userspace snapshot: dropping NPTv6 rule carrying an unsupported match scope "+
				"(from-interface/from-routing-instance/source-address/destination-port); the NPTv6 dataplane "+
				"honors only from-zone, so installing it would widen the rewrite (fail-closed, #5818)",
				"rule_set", rs.Name, "rule", rule.Name,
				"from_interface", rs.FromInterface, "from_routing_instance", rs.FromRoutingInstance)
			continue
		}
		if !member.Installed {
			continue
		}
		out = append(out, Nptv6RuleSnapshot{
			Name:           rule.Name,
			FromZone:       rs.FromZone,
			ExternalPrefix: rule.Match,
			InternalPrefix: rule.Then,
		})
	}
	return out
}
