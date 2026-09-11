package config

import "sort"

// #8189: the commit-time half of #7172's unenforceable-deny finding.
//
// A `deny-commands` pattern that matches no command a dispatch surface can
// produce can never fire there. #7172 cut 5b answers that question, but it
// answers it from the AUTHORIZATION path — logged once per class when someone
// first makes a restricted call. That is the wrong moment and the wrong
// surface: the feedback arrives detached from the edit that caused it, possibly
// days later and possibly on the other node, it lands in the journal rather
// than in `commit` output where every other #7172 advisory speaks, and an
// operator who never exercises the class never learns at all.
//
// THE IMPORT DIRECTION IS WHY IT WAS NOT DONE IN CUT 5b, and why this is a
// registry rather than a moved table. The command tables live in pkg/grpcapi,
// which imports pkg/config and not the reverse. Relocating them is not
// available either: `showTextTopicCommand` is DERIVED from
// `cmdtree.ShowTextTopicCommands()` (#8058), and pkg/cmdtree imports pkg/config
// too — so no package holding all three can be imported from here. Inverting
// the dependency is the way out: a surface registers what it can produce, and
// this package reasons over whatever registered.
//
// THE NAMING IS LOAD-BEARING. This is the REGISTERED command set, not "every
// command the surface can present", and the advisory must say so. Measured
// while writing this: of the three tables feeding the gRPC registration,
// `showTextTopicCommand` is derived from cmdtree but `methodCanonicalCommand`
// and `systemActionVerbCommand` are still hand-maintained literals — one of
// three. #8058 is CLOSED, but a closed dependency is not a satisfied one, and
// the population inherits the drift of the two that are still transcribed. A
// wording that implied completeness would be a claim the data cannot back.
//
// AND THE FAILURE DIRECTION DECIDES THE DEFAULT. If a command is reachable but
// missing from a table, a pattern matching only it is reported unenforceable —
// telling the operator at COMMIT that a restriction which actually works does
// nothing. An operator who believes that removes the pattern or broadens it,
// and both are worse than the silence this replaces. Moving the finding to
// commit output raises the cost of it being wrong, so every ambiguous case here
// resolves to SILENCE: no registered surface, or a registered surface that
// reports an empty set, produces no advisory at all rather than declaring
// everything unenforceable.

// commandSurface is a named set of the commands one dispatch surface can
// produce, registered by that surface's own package.
type commandSurface struct {
	name     string
	commands func() []string
}

var registeredCommandSurfaces []commandSurface

// RegisterCommandSurface records that a dispatch surface can produce the
// commands `commands` returns, so commit-time advisories can ask whether a
// restriction is expressible there.
//
// Called from a surface package's init (pkg/grpcapi). Not concurrency-guarded
// because registration happens during package initialisation, before any
// compile can run; a caller that registers later is a bug this does not try to
// paper over.
func RegisterCommandSurface(name string, commands func() []string) {
	if name == "" || commands == nil {
		return
	}
	registeredCommandSurfaces = append(registeredCommandSurfaces, commandSurface{name: name, commands: commands})
}

// UnenforceableDenySurfaces returns the names of registered surfaces on which
// this class's deny pattern can never fire — it matches nothing in that
// surface's registered command set.
//
// SINGLE IMPLEMENTATION. pkg/grpcapi's unenforceableDenyPatterns delegates
// here rather than keeping its own loop, because two implementations of "can
// this pattern ever fire" would be two things to keep in agreement, and the
// authorization-path answer and the commit-path answer disagreeing is exactly
// the confusion this advisory exists to remove.
//
// A surface reporting ZERO commands is skipped, not reported as unenforceable:
// an empty set makes every pattern vacuously unmatched, which is the false
// advisory in the dangerous direction.
//
// The question is EXISTENTIAL over the whole pattern, so one enforceable
// alternative answers it for the rest. UnenforceableDenyAlternatives
// (login_deny_alternatives_9340.go) asks it per alternative, on exactly the
// surfaces this function does not report.
func UnenforceableDenySurfaces(rules CompiledLoginRegexes) []string {
	if _, ok := rules.DenySource(); !ok {
		return nil
	}
	var out []string
	for _, s := range registeredCommandSurfaces {
		cmds := s.commands()
		if len(cmds) == 0 {
			continue
		}
		matched := false
		for _, cmd := range cmds {
			if denyPatternDecides(rules, cmd) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, s.name)
		}
	}
	sort.Strings(out)
	return out
}

// denyPatternDecides reports whether the class's DENY pattern is what refuses
// cmd. It is not the same as "cmd is refused". A class with an allow pattern
// also refuses every command outside its allow list, and before #9340 that
// allow-list refusal counted as the deny pattern firing. So allow `^show` with
// deny `^show route table secret-vrf` reported nothing: `request system reboot`
// is refused on the gRPC surface, by the allow list, although the deny pattern
// can never decide anything there.
func denyPatternDecides(rules CompiledLoginRegexes, cmd string) bool {
	d := rules.Evaluate(cmd)
	return !d.Allowed && d.DecidedBy == LoginRegexDeny
}
