package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ValidateSyslogSourceInterface accepts a `security log source-interface`
// value: an interface name with an optional `.<unit>` suffix where the unit,
// when present, MUST be a non-negative integer within [0, MaxLogicalUnit]
// (#3349, #6218 item 7). The source resolver (ResolveSyslogSourceAddr,
// pkg/config/syslog_source.go) splits on the FIRST '.' and strconv.Atoi's the
// remainder; a non-numeric unit is an ignored error that silently falls back
// to unit 0 — binding the syslog source to the WRONG logical unit's address.
// Rejecting it at commit makes the typo operator-visible instead of
// misrouting the audit source IP. The split rule (first '.') mirrors
// ResolveSyslogSourceAddr's strings.Cut exactly.
//
// #6218 item 7: the original #3349 fix rejected a non-numeric unit but never
// bounded the numeric range, so a value like `ge-0-0-0.50000` committed even
// though no REAL interface unit can exceed MaxLogicalUnit
// (compiler_interfaces.go caps `unit <n>` there). Such a source-interface can
// never resolve to a configured unit, so ResolveSyslogSourceAddr silently
// falls through to its kernel-interface fallback (almost always a miss for a
// "base.unit"-shaped name) and returns "" — the exact silent audit-source-IP
// loss #3349 set out to close, just reached via an out-of-range unit instead
// of a non-numeric one.
func ValidateSyslogSourceInterface(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected an interface name, e.g. ge-0-0-0 or reth1.100)")
	}
	base, unit, hasUnit := strings.Cut(trimmed, ".")
	if base == "" {
		return fmt.Errorf("invalid interface name %q (empty name before '.')", raw)
	}
	if hasUnit {
		n, err := strconv.Atoi(unit)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid logical unit %q in %q (expected a non-negative "+
				"integer; a non-numeric unit silently binds the syslog source to unit 0)", unit, raw)
		}
		if n > MaxLogicalUnit {
			return fmt.Errorf("invalid logical unit %q in %q (must be <= %d; no configured "+
				"interface unit can exceed this, so the syslog source could never resolve)",
				unit, raw, MaxLogicalUnit)
		}
	}
	return nil
}
