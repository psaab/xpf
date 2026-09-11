package config

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// #9340: the #8189 advisory asks, per PATTERN, whether a class's deny can ever
// fire on a registered surface. One enforceable alternative answers "yes" for
// the whole pattern. So `^(show route table secret-vrf|request system reboot)$`
// reported nothing, although its first alternative is argument text the gRPC
// surface never sees. The operator wrote one rule for two restrictions and was
// told nothing about the half that is console-only.
//
// This asks the same question per ALTERNATIVE. The bar is the one
// unenforceableDenyPatterns (pkg/grpcapi) records against pattern inspection: a
// guard that works on one spelling of an intent is worse than none. So the
// alternatives are not found by reading the source text. The pattern is parsed
// in the dialect CompileLoginRegexes uses (POSIX ERE), simplified the way the
// compiler simplifies it, and expanded over the parse tree:
//
//   - an alternation is the union of its branches;
//   - an optional `x?` is the union of the empty match and `x`;
//   - a concatenation distributes over both;
//   - a capture group is transparent.
//
// Repeats (`*`, `+`, `{n,m}`) stay atomic, because `(a|b)*` is not the union
// of `a*` and `b*`. Every step preserves which strings match, so the union of
// the alternatives matches exactly what the pattern matches, whether the
// operator anchors each branch, anchors a shared group, factors a common
// prefix, or writes an optional group. The parser's own prefix factoring and
// character-class merging are undone or harmless by the same argument.
//
// Each alternative is judged with the class's real allow pattern and its
// ORIGINAL deny source, so the precedence tiers in EvaluateForms (including
// the identical-pattern tie) decide exactly as they do for the whole pattern.
//
// An alternative is reported only on a surface where the whole pattern CAN
// fire. Where it cannot, the #8189 whole-pattern advisory already speaks, and
// a second message would repeat it. A pattern that does not parse, or that
// expands past maxDenyAlternatives9340, is not split and resolves to silence,
// the #8189 doctrine for every ambiguous case.

const maxDenyAlternatives9340 = 64

// DenyAlternativeFinding names the alternatives of a class's deny pattern that
// can never fire on one registered surface on which the whole pattern can.
type DenyAlternativeFinding struct {
	Surface      string
	Alternatives []string
}

type denyAlternative9340 struct {
	display string
	re      *regexp.Regexp
}

// UnenforceableDenyAlternatives returns, per registered surface on which the
// class's deny pattern can fire, the alternatives of that pattern that match
// no command in the surface's registered set. It is empty for a pattern with a
// single alternative.
func UnenforceableDenyAlternatives(rules CompiledLoginRegexes) []DenyAlternativeFinding {
	if !rules.denySet {
		return nil
	}
	alts, ok := denyPatternAlternatives9340(rules.denySrc)
	if !ok || len(alts) < 2 {
		return nil
	}
	wholeDead := make(map[string]bool)
	for _, name := range UnenforceableDenySurfaces(rules) {
		wholeDead[name] = true
	}
	var out []DenyAlternativeFinding
	for _, s := range registeredCommandSurfaces {
		if wholeDead[s.name] {
			continue
		}
		cmds := s.commands()
		if len(cmds) == 0 {
			continue
		}
		var dead []string
		for _, alt := range alts {
			branch := alternativeRules9340(rules, alt)
			fires := false
			for _, cmd := range cmds {
				if denyPatternDecides(branch, cmd) {
					fires = true
					break
				}
			}
			if !fires {
				dead = append(dead, alt.display)
			}
		}
		if len(dead) > 0 {
			out = append(out, DenyAlternativeFinding{Surface: s.name, Alternatives: dead})
		}
	}
	return out
}

// alternativeRules9340 is rules with its deny matcher narrowed to one
// alternative. The deny SOURCE stays the original on purpose: EvaluateForms'
// identical-pattern tier compares sources, and an alternative that happened to
// spell the allow pattern must be judged the way the whole pattern is (a tie at
// different sources denies), not as an identical pair (allow wins).
func alternativeRules9340(rules CompiledLoginRegexes, alt denyAlternative9340) CompiledLoginRegexes {
	rules.deny = alt.re
	return rules
}

// denyPatternAlternatives9340 splits src into alternatives whose union matches
// exactly what src matches (see the file comment). ok=false when src does not
// parse, expands past the cap, or an alternative does not recompile.
func denyPatternAlternatives9340(src string) ([]denyAlternative9340, bool) {
	parsed, err := syntax.Parse(src, syntax.POSIX)
	if err != nil {
		return nil, false
	}
	branches, ok := expandDenyAlternatives9340(parsed.Simplify())
	if !ok {
		return nil, false
	}
	out := make([]denyAlternative9340, 0, len(branches))
	seen := make(map[string]bool, len(branches))
	for _, b := range branches {
		rendered := b.String()
		if seen[rendered] {
			continue
		}
		seen[rendered] = true
		// The rendering is Go's Perl syntax (`(?m:^...$)`, `(?:...)`), which
		// CompilePOSIX rejects. Compile plus Longest() is the same matcher
		// CompilePOSIX builds from the same tree: leftmost-longest.
		re, err := regexp.Compile(rendered)
		if err != nil {
			return nil, false
		}
		re.Longest()
		out = append(out, denyAlternative9340{display: displayDenyAlternative9340(rendered), re: re})
	}
	return out, true
}

func expandDenyAlternatives9340(re *syntax.Regexp) ([]*syntax.Regexp, bool) {
	switch re.Op {
	case syntax.OpAlternate:
		var out []*syntax.Regexp
		for _, sub := range re.Sub {
			b, ok := expandDenyAlternatives9340(sub)
			if !ok {
				return nil, false
			}
			out = append(out, b...)
			if len(out) > maxDenyAlternatives9340 {
				return nil, false
			}
		}
		return out, true
	case syntax.OpCapture:
		return expandDenyAlternatives9340(re.Sub[0])
	case syntax.OpQuest:
		b, ok := expandDenyAlternatives9340(re.Sub[0])
		if !ok || len(b)+1 > maxDenyAlternatives9340 {
			return nil, false
		}
		return append([]*syntax.Regexp{{Op: syntax.OpEmptyMatch}}, b...), true
	case syntax.OpConcat:
		acc := []*syntax.Regexp{{Op: syntax.OpEmptyMatch}}
		for _, sub := range re.Sub {
			b, ok := expandDenyAlternatives9340(sub)
			if !ok {
				return nil, false
			}
			if len(acc)*len(b) > maxDenyAlternatives9340 {
				return nil, false
			}
			next := make([]*syntax.Regexp, 0, len(acc)*len(b))
			for _, head := range acc {
				for _, tail := range b {
					next = append(next, concatDenyAlternative9340(head, tail))
				}
			}
			acc = next
		}
		return acc, true
	default:
		return []*syntax.Regexp{re}, true
	}
}

// concatDenyAlternative9340 joins two expanded pieces without nesting empty
// matches or concatenations.
func concatDenyAlternative9340(head, tail *syntax.Regexp) *syntax.Regexp {
	var subs []*syntax.Regexp
	for _, part := range []*syntax.Regexp{head, tail} {
		switch part.Op {
		case syntax.OpEmptyMatch:
		case syntax.OpConcat:
			subs = append(subs, part.Sub...)
		default:
			subs = append(subs, part)
		}
	}
	switch len(subs) {
	case 0:
		return &syntax.Regexp{Op: syntax.OpEmptyMatch}
	case 1:
		return subs[0]
	}
	return &syntax.Regexp{Op: syntax.OpConcat, Sub: subs}
}

// displayDenyAlternative9340 drops the `(?m:...)` wrapper Go's renderer puts
// around a POSIX-parsed anchor, so the operator sees `^show route$` rather
// than Perl flag syntax. Display only; matching uses the full rendering.
func displayDenyAlternative9340(rendered string) string {
	if strings.HasPrefix(rendered, "(?m:") && strings.HasSuffix(rendered, ")") {
		return rendered[len("(?m:") : len(rendered)-1]
	}
	return rendered
}
