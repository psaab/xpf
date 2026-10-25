package cli

import (
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/natshow"
)

// #7473: the shared NOT-INSTALLED verdict for the NAT summary renderers.
//
// THE LIE THIS FIXES. The summary family (`show security nat source` and its
// destination twin) rendered rules straight from configuration with no
// indication that the snapshot builder refused to install them. Several of
// them are worse than a plain config echo: they attach a translation-hit
// counter to a rule the dataplane never installed, so
//
//	Rule-set: rs1  Rule: r1  trust -> untrust  Action: pool p1
//	  Translation hits: 0
//
// reads as "no traffic matched" when the truth is "this rule is not armed".
// That points the operator at their traffic instead of their config, which is
// the #6534 archetype.
//
// ONE VERDICT SOURCE. These helpers do not decide anything themselves — they
// call the same pkg/config predicates the snapshot builder and pkg/natshow's
// detail renderers call. The formatter for the summary views remains separate
// from natshow's (consolidating those is a larger refactor), but the VERDICT
// cannot diverge, because there is only one implementation of it and it is not
// here.

// sourceNATRuleNotInstalled reports why a source NAT rule is not installed, or
// "" when it is armed.
//
// A rule translating via `interface` (no pool) has no pool to be unusable, so
// it is reported armed — the pool predicate is the only builder exclusion this
// family has, and inventing a verdict for the interface case would be a claim
// the builder never made.
func sourceNATRuleNotInstalled(cfg *config.Config, rule *config.NATRule) string {
	// #7473: the composition moved to pkg/config so the CLI, REST and gRPC
	// surfaces share it rather than each deciding which pool map to consult.
	return config.SourceNATRuleNotInstalledReason(cfg, rule)
}

// sourceNATPoolNotInstalled reports why a source NAT pool is unusable, or "".
func sourceNATPoolNotInstalled(pool *config.NATPool) string {
	if pool == nil {
		return ""
	}
	return config.SourceNATPoolUnusableReason(pool)
}

// natRuntimeVerdicts reads the applied snapshot's runtime disarm verdicts
// through the published dataplane (#16547). Reads only cached manager
// state — no control-socket I/O. An unavailable view yields empty maps,
// so every surface falls back to the config-only verdict exactly.
func (c *CLI) natRuntimeVerdicts() dpuserspace.AppliedNATSnapshotVerdicts {
	if c == nil || c.dp == nil {
		return dpuserspace.AppliedNATSnapshotVerdicts{}
	}
	provider, ok := c.dpProbe().(interface {
		AppliedNATSnapshotVerdicts() dpuserspace.AppliedNATSnapshotVerdicts
	})
	if !ok {
		return dpuserspace.AppliedNATSnapshotVerdicts{}
	}
	return provider.AppliedNATSnapshotVerdicts()
}

// sourceNATRuleNotInstalledRuntime is sourceNATRuleNotInstalled with the
// applied snapshot's runtime quarantine folded in (#16547).
func (c *CLI) sourceNATRuleNotInstalledRuntime(cfg *config.Config, rule *config.NATRule, v dpuserspace.AppliedNATSnapshotVerdicts) string {
	var rt string
	if v.Available && rule != nil {
		rt = v.SourceNATRules[rule.Name]
	}
	return config.SourceNATRuleNotInstalledReasonWithRuntime(cfg, rule, rt)
}

// sourceNATPoolNotInstalledRuntime is the pool-level analogue (#16547):
// config definition verdict wins, runtime quarantine fills the gap.
func (c *CLI) sourceNATPoolNotInstalledRuntime(cfg *config.Config, pool *config.NATPool, poolName string, v dpuserspace.AppliedNATSnapshotVerdicts) string {
	var rt string
	if v.Available {
		rt = v.SourceNATPools[poolName]
	}
	return config.SourceNATPoolNotInstalledReasonWithRuntime(cfg, pool, poolName, config.SourceNATAggregateOverBudgetPools(cfg), rt)
}

// natRuntimeVerdictsForShow adapts the snapshot verdicts to the
// natshow detail renderer's runtime map.
func natRuntimeVerdictsForShow(v dpuserspace.AppliedNATSnapshotVerdicts) natshow.RuntimeVerdicts {
	if !v.Available || len(v.SourceNATRules) == 0 {
		return nil
	}
	return natshow.RuntimeVerdicts(v.SourceNATRules)
}

// destNATRuleNotInstalled reports why a destination NAT rule is excluded, or "".
func destNATRuleNotInstalled(cfg *config.Config, rule *config.NATRule) string {
	// #7473: shared composition — see sourceNATRuleNotInstalled.
	return config.DestinationNATRuleNotInstalledReason(cfg, rule)
}

// natNotInstalledLine renders the operator-facing annotation for a non-empty
// reason, or "" when the rule is armed.
//
// The wording leads with NOT INSTALLED rather than burying the state after the
// reason, because the summary views print one line per rule and the operator is
// scanning, not reading. SourceNATDisarmReasonText expands the raw reason token
// into the remedy-bearing sentence; the destination predicate already returns
// operator prose.
func natNotInstalledLine(reason string, expand bool) string {
	if reason == "" {
		return ""
	}
	if expand {
		return "  NOT INSTALLED — " + config.SourceNATDisarmReasonText(reason)
	}
	return "  NOT INSTALLED — " + reason
}

// destNATPoolNotInstalled reports a reason when EVERY rule referencing the pool
// is excluded, or "" otherwise.
//
// A pool is not itself a builder exclusion on the destination family — the
// predicate is per-rule — so the honest verdict for a pool is derived: it is
// not translating only when nothing that could reach it is installed. A pool
// referenced by no rule at all is reported armed rather than not-installed,
// because "unreferenced" is a different statement from "the builder refused
// it", and conflating them would put a NOT INSTALLED banner on a pool the
// operator simply has not wired up yet.
func destNATPoolNotInstalled(cfg *config.Config, poolName string) string {
	if cfg == nil || cfg.Security.NAT.Destination == nil || poolName == "" {
		return ""
	}
	dnat := cfg.Security.NAT.Destination
	referencing, excluded := 0, 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			if rule.Then.PoolName != poolName {
				continue
			}
			referencing++
			if config.DestinationNATRuleExcludedReason(dnat, rule) != "" {
				excluded++
			}
		}
	}
	if referencing == 0 || excluded < referencing {
		return ""
	}
	return "every referencing rule is excluded"
}
