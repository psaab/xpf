package config

import (
	"fmt"
	"strings"
)

// #9939: an `event-options policy … then change-configuration commands "…"`
// payload was never authorized against anyone.
//
// The line that PLANTS it is adjudicated — as a path under `event-options` — but
// the payload it carries is DATA, and nothing looks inside. When the policy
// fires, `pkg/eventengine` applies the embedded `set`/`delete` and commits with
// explicit INTERNAL (root) authority: `commit_authority.go` answers
// `case authorityInternal: return nil`, so no authority check runs on that path
// at all.
//
// A class denied `security policies` but permitted `event-options` could
// therefore delete a guard policy autonomously, on a routine RPM event, as root.
//
// The absence was a MEASUREMENT: `AuthorizeConfigMutation` had exactly four
// non-test call sites — the two gRPC gates, REST, and the on-box CLI — and zero
// in `pkg/eventengine`. The same grep finding all four surfaces is what makes
// "none in the engine" evidence rather than a failed search.
//
// ── WHY THE GATE IS HERE AND NOT IN THE ENGINE ──────────────────────────────
//
// At fire time there is no principal. The payload is applied by the daemon on
// its own behalf, so there is nobody to charge — which is exactly what makes it
// an escalation. The only moment a class is in scope is the COMMIT that plants
// the payload, and every surface already routes its config mutations through
// AuthorizeConfigMutation, including `load` (#9892 renders content to set lines
// and adjudicates each). Putting the check here means all of them get it from
// one implementation rather than four that agree today.
//
// ── WHAT THIS DOES NOT CLOSE, STATED RATHER THAN IMPLIED ────────────────────
//
// A payload ALREADY PERSISTED before this gate existed still fires as root. The
// engine cannot re-adjudicate it, because the policy does not record who planted
// it — closing that needs the authoring class stored WITH the policy, which is a
// config-type change on the HA wire with repo-wide blast radius. Filed as
// #9984 rather than bundled here, with the reachability bounded: an UNANCHORED
// deny catches the plant incidentally (the payload text is part of the planting
// line), so only an ANCHORED deny leaves a persisted payload unadjudicated.

// changeConfigRecursionLimit9939 bounds the payload walk.
//
// A payload may itself plant another `change-configuration`, and an operator who
// writes that deserves each level adjudicated — but a bound is cheaper than
// reasoning about whether the lexer can produce a cycle, and two levels is
// already past anything anyone writes deliberately.
const changeConfigRecursionLimit9939 = 4

// embeddedChangeConfigCommands9939 returns the command lines carried by a
// `change-configuration commands` payload on this line, or nil.
//
// The token boundary is the SAME rule `eventChangeConfigCommands` applies when
// the compiler reads the stanza (#6659): a QUOTED value is one command per
// token, an UNQUOTED tail is a single command that must be re-joined. Using a
// different rule here would adjudicate a command the engine never runs, or miss
// one it does — the #9938 defect, one layer in.
func embeddedChangeConfigCommands9939(parts []string, quoted []bool) []string {
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] != "change-configuration" || parts[i+1] != "commands" {
			continue
		}
		tail := parts[i+2:]
		if len(tail) == 0 {
			return nil
		}
		if len(quoted) == len(parts) && quoted[i+2] {
			return append([]string(nil), tail...)
		}
		return []string{strings.Join(tail, " ")}
	}
	return nil
}

// authorizeEmbeddedChangeConfig9939 adjudicates every command a payload on this
// line carries, against the planting class's own regexes.
func authorizeEmbeddedChangeConfig9939(cfg *Config, class string, parts []string, quoted []bool, depth int) error {
	if depth >= changeConfigRecursionLimit9939 {
		// Refuse rather than allow. A payload nested deeper than anyone writes
		// on purpose is not something to wave through because the walk ran out
		// of budget — "we stopped looking" must not read as "we found nothing".
		return fmt.Errorf("permission denied: login class %q plants a change-configuration payload "+
			"nested deeper than %d levels, which cannot be adjudicated",
			class, changeConfigRecursionLimit9939)
	}
	for _, cmd := range embeddedChangeConfigCommands9939(parts, quoted) {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		if err := authorizeConfigMutationDepth9939(cfg, class, nil, cmd, depth+1); err != nil {
			// The inner error already names the class and the denied path's
			// ROOT only, under the same audit rule — so it is safe to wrap, and
			// wrapping is what tells the operator WHY a line about
			// `event-options` was refused for a path that is not under it.
			return fmt.Errorf("%w — planted as a `then change-configuration` payload, which the "+
				"daemon would apply with internal (root) authority (#9939)", err)
		}
	}
	return nil
}
