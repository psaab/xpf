package config

import "fmt"

// This file is the single source of truth for the #12507 CIDR mask-alias
// doctrine, shared by static routes (#12507) and generate routes (#15658,
// #17211). Before #17211 each holder carried a name-swapped copy of the
// three helpers below, so a doctrine change (helper digit limit, alias
// order, message wording) had to be made twice and could silently drift.

// canonicalizeMaskAliases writes *primary in the mask spelling every
// consumer parses. Helper-supported zero padding ("/08", "/032") is
// written canonically via normalizeHelperSupportedCIDRMaskPadding.
// Helper-refused padding ("/008") is kept verbatim — the strict gates
// (helperRefusedMaskSpellings) reject it and a tolerant load publishes it
// so the helper fails the snapshot closed — unless a folded alias the
// helper parses can take its place. Every authored spelling other than
// the final primary stays in *aliases for diagnostics.
func canonicalizeMaskAliases(primary *string, aliases *[]string) {
	if primary == nil || aliases == nil {
		return
	}
	authored := *primary
	canonical := authored
	if CIDRMaskHelperRefusesPadding(canonical) {
		for _, alias := range *aliases {
			if alias != "" && !CIDRMaskHelperRefusesPadding(alias) {
				canonical = alias
				break
			}
		}
	}
	canonical = normalizeHelperSupportedCIDRMaskPadding(canonical)
	if canonical == authored {
		return
	}
	spellings := append([]string{authored}, (*aliases)...)
	*primary = canonical
	*aliases = nil
	for _, spelling := range spellings {
		appendMaskAlias(*primary, aliases, spelling)
	}
}

// appendMaskAlias records v as an authored alias spelling of primary.
// Empty-string policy (#17211, chosen explicitly where the two cloned
// appenders disagreed): an empty spelling is never recorded. The generate
// appender already refused ""; the static appender did not, but no static
// caller passes "" — its destinations come from route statements — so the
// refuse-empty policy is the unified one. A spelling equal to the primary
// or already recorded is likewise skipped.
func appendMaskAlias(primary string, aliases *[]string, v string) {
	if aliases == nil || v == "" || v == primary {
		return
	}
	for _, alias := range *aliases {
		if alias == v {
			return
		}
	}
	*aliases = append(*aliases, v)
}

// helperRefusedMaskSpellings reports every spelling in
// (primary, aliases...) whose zero-padded mask the userspace helper
// cannot parse, one message per spelling. scope names the route family
// (e.g. "routing-options static route") and tag is the owning issue tag
// ("#12507" or "#15658"); apart from those two strings the static and
// generate gates emit identical messages for identical spellings.
func helperRefusedMaskSpellings(scope, tag, primary string, aliases []string) []string {
	var out []string
	for i, spelling := range append([]string{primary}, aliases...) {
		if !CIDRMaskHelperRefusesPadding(spelling) {
			continue
		}
		merged := ""
		if i > 0 {
			merged = fmt.Sprintf(" (merged into %q)", primary)
		}
		out = append(out, fmt.Sprintf(
			"%s %q%s has redundant leading-zero CIDR mask digits the userspace helper cannot parse; write it as %q (%s)",
			scope, spelling, merged, normalizeCIDRMaskPadding(spelling), tag))
	}
	return out
}
