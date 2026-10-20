package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Leaf iteration uses loginClassRegexLeaves15712 order (see below).

// login_class_regex_15712.go — #15712 commit-time gate for the four
// `system login class` regex leaves (allow-commands, deny-commands,
// allow-configuration, deny-configuration).
//
// Two defects, one gate, evaluated on the COMPILED (post-#8436-merge,
// post-group-expansion) classes so every spelling is judged identically:
//
//  1. No POSIX-ERE validation. The compiler stored nodeVal(prop) verbatim
//     (compiler_system.go) and CompileLoginRegexes ran only at enforcement
//     time, where an invalid pattern fails closed per-command. A non-POSIX
//     pattern such as `(?:show|ping).*` (Go/PCRE non-capturing group, not
//     POSIX ERE) therefore committed clean and only surfaced as runtime
//     denials. Strict commit now rejects it naming class, leaf and pattern;
//     the tolerant load/peer-sync path warns and keeps the value (#1960) —
//     enforcement still fails closed on it, so boot is not bricked and no
//     restriction is silently dropped.
//
//  2. Conflicting duplicate of the SAME leaf. The #8436 find-or-create
//     merge folds duplicate `class <name>` blocks into one LoginClass, but
//     each regex leaf assignment overwrote the previous value, so an
//     earlier `deny-commands "request system zeroize"` vanished when a
//     second block wrote `deny-commands "request system reboot"`. The
//     compiler records every distinct authored value per leaf in
//     LoginClass.RegexValues15712 (author order). Strict commit rejects a
//     leaf with >1 distinct value naming both; tolerant warns and keeps
//     the last-authored value, which is exactly what the overwrite already
//     installed — now flagged instead of silent. Identical repeats and
//     different leaves across blocks are NOT conflicts: they merge as
//     #8436 intended.

// loginClassRegexLeaves15712 is the canonical leaf order for deterministic
// diagnostics.
var loginClassRegexLeaves15712 = []string{
	"allow-commands",
	"deny-commands",
	"allow-configuration",
	"deny-configuration",
}

func loginClassRegexValue15712(lc *LoginClass, leaf string) string {
	switch leaf {
	case "allow-commands":
		return lc.AllowCommands
	case "deny-commands":
		return lc.DenyCommands
	case "allow-configuration":
		return lc.AllowConfiguration
	case "deny-configuration":
		return lc.DenyConfiguration
	}
	return ""
}

// recordLoginClassRegexValue15712 records one authored regex leaf occurrence
// for #15712 duplicate detection. Distinct values only, author order;
// identical repeats collapse (they are not conflicts).
func recordLoginClassRegexValue15712(lc *LoginClass, leaf, value string) {
	if lc == nil {
		return
	}
	if lc.RegexValues15712 == nil {
		lc.RegexValues15712 = map[string][]string{}
	}
	for _, v := range lc.RegexValues15712[leaf] {
		if v == value {
			return
		}
	}
	lc.RegexValues15712[leaf] = append(lc.RegexValues15712[leaf], value)
}

// validateLoginClassRegexes15712 checks every compiled login class.
// Strict: first defect is an error. Lenient: every defect is a warning and
// compilation continues with the last-authored values already in place.
func validateLoginClassRegexes15712(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil || cfg.System.Login == nil {
		return nil, nil
	}
	var warnings []string
	emit := func(msg string) error {
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg+" (downgraded to warning on tolerant path; last authored value wins, enforcement fails closed on an invalid pattern)")
		return nil
	}
	// Deterministic order: classes as compiled (author order is already
	// deterministic), leaves in canonical order.
	for _, lc := range cfg.System.Login.Classes {
		if lc == nil {
			continue
		}
		for _, leaf := range loginClassRegexLeaves15712 {
			// Conflicting duplicate: >1 distinct authored value.
			if distinct := lc.RegexValues15712[leaf]; len(distinct) > 1 {
				quoted := make([]string, len(distinct))
				for i, v := range distinct {
					quoted[i] = fmt.Sprintf("%q", v)
				}
				msg := fmt.Sprintf(
					"system login class %q: conflicting duplicate %q values %s — "+
						"a single-valued login-class regex leaf may be authored only once per class; "+
						"the later value silently overwrote the earlier restriction (#15712)",
					lc.Name, leaf, strings.Join(quoted, " and "))
				if err := emit(msg); err != nil {
					return nil, err
				}
			}
			// POSIX-ERE validation of the effective (last-authored) value,
			// only when the leaf was actually written. Presence lists carry
			// that distinction: an absent leaf has no pattern to validate,
			// while a written empty pattern is valid POSIX (matches
			// everywhere) and CompilePOSIX("") succeeds.
			present := containsLoginLeaf(lc.AllowLeavesPresent, leaf) ||
				containsLoginLeaf(lc.DenyLeavesPresent, leaf)
			if !present {
				continue
			}
			value := loginClassRegexValue15712(lc, leaf)
			if _, err := regexp.CompilePOSIX(value); err != nil {
				msg := fmt.Sprintf(
					"system login class %q: %q value %q is not a valid POSIX extended regular expression: %v (#15712)",
					lc.Name, leaf, value, err)
				if err := emit(msg); err != nil {
					return nil, err
				}
			}
		}
	}
	return warnings, nil
}

// validateLoginClassRegexesStrictView is the peer-effective view re-check
// (#5876 registry): same gate, strict only, on an already-compiled config.
func validateLoginClassRegexesStrictView(cfg *Config) error {
	_, err := validateLoginClassRegexes15712(cfg, false)
	return err
}
