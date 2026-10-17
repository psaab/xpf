package config

import (
	"fmt"
	"strconv"
)

// compiler_nat_source_persistent_rule_14626.go — #14626.
//
// Junos places `persistent-nat` at rule level:
// `security nat source rule-set RS rule R then source-nat pool P persistent-nat ...`
// (and `... interface persistent-nat ...`, which has no pool to bind to).
// xpf models persistence per-pool (`security nat source pool P persistent-nat`),
// and the rule-level tail used to be skipped entirely: recordSourceNATUnknownThen
// returned on `pool <name>` and the pool parser — the only writer of
// PersistentNAT — never saw the tail. The config committed clean and the
// snapshot carried persistent_nat=false with no warning (Y23-05).
//
// This file parses the tail into NATRule.rulePersistentNAT (per-rule, never
// mutating the shared pool) and validates it. Fields the operator did not
// author stay at the -1 sentinel so "absent" (inherit the pool/default) is
// distinguishable from an authored value. The strict gate rejects a tail that
// disagrees with the pool definition or with another rule sharing the pool,
// a malformed tail, and a tail on `interface`/`off`; the tolerant path warns
// and falls back to the pool's own config (see EffectivePersistentNAT).

// rulePersistentNATState14626 is the parse/validity state of one rule's
// persistent-nat tail (#14626).
type rulePersistentNATState14626 struct {
	Present   bool
	PermitSet bool
	Permit    PersistentNATPermit
	Timeout   int // -1 = not authored
	// Invalid records why a malformed tail must not take effect. The strict
	// gate rejects on it; the tolerant path warns and ignores the tail.
	Invalid string
}

// parseRulePersistentTailTokens14626 parses a packed token run starting at the
// `persistent-nat` keyword (tokens[i] == "persistent-nat"). Unknown or
// value-less sub-tokens mark the tail invalid and stop the run.
func parseRulePersistentTailTokens14626(st *rulePersistentNATState14626, tokens []string, i int) {
	st.Present = true
	for j := i + 1; j < len(tokens); j++ {
		switch tokens[j] {
		case "permit":
			if j+1 >= len(tokens) {
				st.Invalid = "`persistent-nat permit` declares a value and none was given"
				return
			}
			switch PersistentNATPermit(tokens[j+1]) {
			case PersistentNATPermitAnyRemoteHost, PersistentNATPermitTargetHost, PersistentNATPermitTargetHostPort:
				st.Permit = PersistentNATPermit(tokens[j+1])
				st.PermitSet = true
			default:
				st.Invalid = fmt.Sprintf("invalid persistent-nat permit %q (want any-remote-host, target-host, or target-host-port)", tokens[j+1])
				return
			}
			j++
		case "inactivity-timeout":
			if j+1 >= len(tokens) {
				st.Invalid = "`persistent-nat inactivity-timeout` declares a value and none was given"
				return
			}
			n, err := strconv.Atoi(tokens[j+1])
			if err != nil || n < 1 || n > 86400 {
				st.Invalid = fmt.Sprintf("invalid persistent-nat inactivity-timeout %q (want 1..86400 seconds)", tokens[j+1])
				return
			}
			st.Timeout = n
			j++
		default:
			st.Invalid = fmt.Sprintf("unknown persistent-nat keyword %q (the compiler reads only permit and inactivity-timeout)", tokens[j])
			return
		}
	}
}

// parseRulePersistentTailNode14626 parses a `persistent-nat` node across the
// flat-set (#2419) and hierarchical shapes:
//   - packed Keys: ["persistent-nat","permit","any-remote-host", ...]
//   - flat-set nested children: a child carrying the packed run, or chained
//     children (`[permit any-remote-host] > [inactivity-timeout 900]`)
//   - hierarchical children: `permit <v>;` / `inactivity-timeout <n>;` leaves
//
// Children are first expanded with the pool-level persistent-nat schema
// (expandRunChildren9235, the #9235 mechanism) so a chained flat run reads as
// sibling leaves, exactly as the pool parser reads its own stanza.
func parseRulePersistentTailNode14626(st *rulePersistentNATState14626, node *Node) {
	if node == nil {
		return
	}
	st.Present = true
	if len(node.Keys) > 1 {
		parseRulePersistentTailTokens14626(st, append([]string{"persistent-nat"}, node.Keys[1:]...), 0)
		if st.Invalid != "" {
			return
		}
		if len(node.Children) == 0 {
			return
		}
	}
	applyLeaf := func(name, v string) bool {
		if v == "" {
			st.Invalid = fmt.Sprintf("`persistent-nat %s` declares a value and none was given", name)
			return false
		}
		scratch := *st
		parseRulePersistentTailTokens14626(&scratch, []string{"persistent-nat", name, v}, 0)
		*st = scratch
		return st.Invalid == ""
	}
	for _, child := range expandRunChildren9235(node.Children, persistentNATSchema9235()) {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		switch child.Keys[0] {
		case "permit", "inactivity-timeout":
			if !applyLeaf(child.Keys[0], nodeVal(child)) {
				return
			}
		case "persistent-nat":
			parseRulePersistentTailNode14626(st, child)
			if st.Invalid != "" {
				return
			}
		default:
			st.Invalid = fmt.Sprintf("unknown persistent-nat keyword %q (the compiler reads only permit and inactivity-timeout)", child.Keys[0])
			return
		}
	}
}

// scanRulePersistentTail14626 extracts the rule-level persistent-nat tail from
// one `then` container across all AST shapes (#2419 dual-shape class):
// fully-compact Keys on `then`, packed Keys on the `source-nat` child,
// flat-set pool children, and hierarchical source-nat/pool children.
// It also reports a tail authored on `interface`/`off` (no pool to bind to).
func scanRulePersistentTail14626(thenNode *Node) rulePersistentNATState14626 {
	st := rulePersistentNATState14626{Timeout: -1}
	if thenNode == nil {
		return st
	}
	scanTokens := func(tokens []string, from int) {
		for i := from; i < len(tokens); i++ {
			switch tokens[i] {
			case "persistent-nat":
				parseRulePersistentTailTokens14626(&st, tokens, i)
				return
			case "pool":
				i++ // skip pool name; keep scanning for persistent-nat
			case "interface", "off":
				if i+1 < len(tokens) && tokens[i+1] == "persistent-nat" {
					st.Present = true
					st.Invalid = "`persistent-nat` is only valid after `source-nat pool <name>`; an interface/off rule has no pool to bind persistence to"
					return
				}
			default:
				return
			}
		}
	}
	// Fully compact: `then source-nat pool P persistent-nat ...` on then.Keys.
	if len(thenNode.Keys) >= 2 && thenNode.Keys[1] == "source-nat" {
		scanTokens(thenNode.Keys, 2)
		if st.Present {
			return st
		}
	}
	var scanNode func(n *Node)
	scanNode = func(n *Node) {
		if n == nil || st.Present {
			return
		}
		switch n.Name() {
		case "persistent-nat":
			parseRulePersistentTailNode14626(&st, n)
		case "pool":
			// Packed on the pool node itself: Keys = ["pool", <name>,
			// "persistent-nat", ...]. Find persistent-nat past the name and
			// parse from there — scanTokens cannot be reused here because it
			// expects a leading mode keyword, not a bare pool name.
			for idx := range n.Keys {
				if idx < 2 {
					continue
				}
				if n.Keys[idx] == "persistent-nat" {
					parseRulePersistentTailTokens14626(&st, n.Keys, idx)
					return
				}
			}
			for _, c := range n.Children {
				scanNode(c)
			}
		case "interface", "off":
			for _, c := range n.Children {
				if c != nil && c.Name() == "persistent-nat" {
					st.Present = true
					st.Invalid = "`persistent-nat` is only valid after `source-nat pool <name>`; an interface/off rule has no pool to bind persistence to"
					return
				}
			}
		default:
			for _, c := range n.Children {
				scanNode(c)
			}
		}
	}
	for _, child := range thenNode.Children {
		if child == nil || child.Name() != "source-nat" {
			continue
		}
		if len(child.Keys) >= 2 {
			scanTokens(child.Keys, 1)
			if st.Present {
				return st
			}
		}
		for _, leaf := range child.Children {
			scanNode(leaf)
			if st.Present {
				return st
			}
		}
	}
	return st
}

// resolved14626 returns the tail as a concrete config: authored fields win,
// the rest take the pool-level defaults (permit target-host-port, 300s).
func (s rulePersistentNATState14626) resolved14626() *PersistentNATConfig {
	out := &PersistentNATConfig{InactivityTimeout: 300, Permit: PersistentNATPermitTargetHostPort}
	if s.PermitSet {
		out.Permit = s.Permit
	}
	if s.Timeout >= 0 {
		out.InactivityTimeout = s.Timeout
	}
	return out
}

// EffectivePersistentNAT returns the persistent-NAT config that applies to
// this rule: the rule-level tail (#14626) layered over the referenced pool's
// own `persistent-nat`, or the pool's alone when the rule authors no tail.
// ok=false means no persistence applies. A malformed or conflicting tail
// NEVER overrides the pool: on the tolerant path it is warned about and the
// pool fallback applies.
func (r *NATRule) EffectivePersistentNAT(cfg *Config) (*PersistentNATConfig, bool) {
	if r == nil || cfg == nil || r.Then.PoolName == "" {
		return nil, false
	}
	pool := cfg.Security.NAT.SourcePools[r.Then.PoolName]
	var poolCfg *PersistentNATConfig
	if pool != nil {
		poolCfg = pool.PersistentNAT
	}
	st := r.rulePersistentNAT
	if !st.Present {
		if poolCfg != nil {
			return poolCfg, true
		}
		return nil, false
	}
	if st.Invalid != "" || rulePersistentTailConflicts14626(st, poolCfg) {
		if poolCfg != nil {
			return poolCfg, true
		}
		return nil, false
	}
	res := st.resolved14626()
	if poolCfg != nil {
		if !st.PermitSet {
			res.Permit = poolCfg.Permit
		}
		if st.Timeout < 0 {
			res.InactivityTimeout = poolCfg.InactivityTimeout
		}
	}
	return res, true
}

// rulePersistentTailConflicts14626 reports whether an authored tail field
// disagrees with the pool's own persistent-nat (both present).
func rulePersistentTailConflicts14626(st rulePersistentNATState14626, poolCfg *PersistentNATConfig) bool {
	if poolCfg == nil {
		return false
	}
	if st.PermitSet && st.Permit != poolCfg.Permit {
		return true
	}
	if st.Timeout >= 0 && st.Timeout != poolCfg.InactivityTimeout {
		return true
	}
	return false
}

// validateSourceNATRulePersistentNATStrict14626 rejects, at strict commit:
// a malformed rule-level tail, a tail on interface/off, a tail disagreeing
// with the referenced pool, and two rules sharing one pool with disagreeing
// tails. The caller downgrades to a warning on tolerant load (#1960).
func validateSourceNATRulePersistentNATStrict14626(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	type tailKey struct {
		permitSet bool
		permit    PersistentNATPermit
		timeout   int
	}
	byPool := map[string]tailKey{}
	byPoolRule := map[string]string{}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || !rule.rulePersistentNAT.Present {
				continue
			}
			st := rule.rulePersistentNAT
			where := fmt.Sprintf("security nat source rule-set %q rule %q", rs.Name, rule.Name)
			if st.Invalid != "" {
				return fmt.Errorf("%s: rule-level `then source-nat ... persistent-nat` is invalid (#14626): %s; configure persistence on the pool (`security nat source pool <name> persistent-nat`) or fix the rule tail", where, st.Invalid)
			}
			if rule.Then.PoolName == "" {
				return fmt.Errorf("%s: rule-level `persistent-nat` requires `then source-nat pool <name>` (#14626): an interface/off rule has no pool to bind persistence to; configure `security nat source pool <name> persistent-nat` instead", where)
			}
			pool := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
			var poolCfg *PersistentNATConfig
			if pool != nil {
				poolCfg = pool.PersistentNAT
			}
			if pool != nil && pool.Deterministic != nil {
				return fmt.Errorf("%s: rule-level `persistent-nat` on deterministic pool %q (#14626): deterministic and persistent-nat are mutually exclusive", where, rule.Then.PoolName)
			}
			if rulePersistentTailConflicts14626(st, poolCfg) {
				res := st.resolved14626()
				return fmt.Errorf("%s: rule-level `persistent-nat` (permit=%s timeout=%d) conflicts with pool %q persistent-nat (permit=%s timeout=%d) (#14626): align the rule tail with the pool or remove it", where, res.Permit, res.InactivityTimeout, rule.Then.PoolName, poolCfg.Permit, poolCfg.InactivityTimeout)
			}
			key := tailKey{permitSet: st.PermitSet, permit: st.Permit, timeout: st.Timeout}
			if prev, dup := byPool[rule.Then.PoolName]; dup && prev != key {
				return fmt.Errorf("%s: rule-level `persistent-nat` conflicts with rule %q on shared pool %q (#14626): two rules referencing one pool must agree on persistence; configure it once on the pool (`security nat source pool %s persistent-nat`)", where, byPoolRule[rule.Then.PoolName], rule.Then.PoolName, rule.Then.PoolName)
			}
			byPool[rule.Then.PoolName] = key
			byPoolRule[rule.Then.PoolName] = rule.Name
		}
	}
	return nil
}
