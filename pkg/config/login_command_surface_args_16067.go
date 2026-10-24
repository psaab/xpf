package config

import "strings"

// #16067: the registered command sets are argument-free, but since
// #16067 the remote gates reconstruct the argument-bearing command
// (`show route table secret-vrf`, `ping 10.99.1.1`) and match patterns
// against it. An advisory that asks only "does the pattern match an
// argument-free command" would keep telling operators that an
// argument-scoped restriction is on-box-only after it started firing
// remotely — the false advisory in the dangerous direction (#8189's
// doctrine: silence over a wrong warning, and never a warning for a
// restriction that works).
//
// So a surface may also register ARGUMENT SAMPLES: exemplar
// argument-bearing commands it can produce, one per argument slot
// shape. The advisory then asks the question against the argument-free
// set, the samples, and literal candidates derived from the pattern
// itself: a pattern whose literal spelling extends a registered
// command (`^show route table secret-vrf$` extends `show route table`)
// names a command the surface can now produce with that argument, and
// a pattern whose longest literal word can occupy an argument slot
// (`.*secret-vrf`) can fire on a sample carrying that word.
//
// The candidate is a WITNESS, judged by the real compiled rules, never
// by pattern inspection alone: it counts only when denyPatternDecides
// (or the allow verdict) actually fires on it, exactly the
// spelling-independence bar #7172 set.

var registeredArgumentSamples = map[string]func() []string{}

// RegisterCommandSurfaceArgumentSamples records the argument-bearing
// exemplar commands a registered surface can produce, so commit-time
// advisories can ask whether an argument-scoped restriction is
// expressible there. Called from a surface package's init alongside
// RegisterCommandSurface.
func RegisterCommandSurfaceArgumentSamples(name string, samples func() []string) {
	if name == "" || samples == nil {
		return
	}
	registeredArgumentSamples[name] = samples
}

// candidateSet returns the surface's argument-free commands plus its
// argument samples, and the samples on their own (literal candidates
// may only occupy a slot a sample proves exists).
func (s commandSurface) candidateSet() (all, samples []string) {
	base := s.commands()
	if fn := registeredArgumentSamples[s.name]; fn != nil {
		samples = fn()
	}
	all = make([]string, 0, len(base)+len(samples))
	all = append(all, base...)
	all = append(all, samples...)
	return all, samples
}

// patternCandidateCommands derives witness strings for an
// argument-scoped pattern from the pattern's own literal text and the
// surface's samples. A surface with no registered samples has not
// proven it can produce argument-bearing commands, so no witness is
// derived there and the #8189 advisory keeps speaking for it.
func patternCandidateCommands(src string, cmds, samples []string) []string {
	if len(samples) == 0 {
		return nil
	}
	var out []string
	if lit, ok := literalPatternString(src); ok && lit != "" {
		// The literal is a witness only where a sample proves an
		// argument slot under the same command: either the literal is
		// itself sample-shaped (appending words to a sampled command),
		// or a sampled command extends a registered command the
		// literal also extends (`show route table …`).
		for _, s := range samples {
			if lit == s || strings.HasPrefix(lit, s+" ") {
				out = append(out, lit)
				break
			}
			for _, c := range cmds {
				if (lit == c || strings.HasPrefix(lit, c+" ")) && strings.HasPrefix(s, c+" ") {
					out = append(out, lit)
					break
				}
			}
			if len(out) > 0 {
				break
			}
		}
	}
	if seg := longestLiteralSegment(src); seg != "" && !strings.Contains(seg, " ") &&
		!strings.HasPrefix(src, "^") {
		// An anchored pattern cannot fire on a witness that merely
		// CONTAINS its literal segment at an argument position the
		// anchor forbids (`^qqq-…` never matches `ping qqq-…`), so the
		// segment shape is derived only for unanchored patterns. The
		// literal shape above already covers anchored literals.
		for _, s := range samples {
			words := strings.Fields(s)
			if len(words) < 2 {
				continue
			}
			out = append(out, strings.Join(words[:len(words)-1], " ")+" "+seg)
			out = append(out, s+" "+seg)
		}
	}
	return out
}

// literalPatternString returns the plain string a pattern matches
// exactly when the pattern is (after unescaping `\.`) an optionally
// anchored literal with at most a wildcard tail. ok=false for any
// pattern with real regex structure, where no single witness exists.
func literalPatternString(src string) (string, bool) {
	s := strings.ReplaceAll(src, `\.`, ".")
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimSuffix(s, "$")
	s = strings.TrimSuffix(s, ".*")
	s = strings.TrimSuffix(s, ".+")
	if s == "" || strings.ContainsAny(s, `\.[]{}()*+?|`) {
		return "", false
	}
	return s, true
}

// longestLiteralSegment returns the longest run of literal text in the
// pattern (the operator's own words, anchors and metacharacters
// removed). Empty when the pattern has no literal word at all.
func longestLiteralSegment(src string) string {
	s := strings.ReplaceAll(src, `\.`, ".")
	best := ""
	var cur strings.Builder
	flush := func() {
		if seg := strings.TrimSpace(cur.String()); len(seg) > len(best) {
			best = seg
		}
		cur.Reset()
	}
	for _, r := range s {
		switch r {
		case '\\', '.', '[', ']', '{', '}', '(', ')', '*', '+', '?', '|', '^', '$':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return best
}
