package config

import (
	"fmt"
	"strconv"
)

// bgpPrefixLimitTeardown15010 is the parsed Junos prefix-limit action
// beyond `maximum` (#15010). Junos: `maximum` alone is log-only; the
// optional `teardown [pct] [idle-timeout (forever|minutes)]` drops the
// session on overflow. `drop-excess`/`hide-excess` are deliberately not
// modelled — FRR 10.6 has no equivalent (its maximum-prefix either warns
// or CEASEs), so they are rejected rather than silently dropped.
type bgpPrefixLimitTeardown15010 struct {
	present  bool // a prefix-limit node exists at all
	teardown bool
	pct      int  // 0 = no warning threshold
	idle     int  // minutes 1..2400; 0 when unset or forever
	forever  bool // idle-timeout forever
}

// parseTeardownTokens15010 validates the teardown tail grammar:
// `[pct] [idle-timeout (forever|minutes)]` where pct is 1..100 and
// minutes is 1..2400. Shared by the schema tailValidator and the
// compiler so the two cannot drift.
func parseTeardownTokens15010(tokens []string) (bgpPrefixLimitTeardown15010, error) {
	var out bgpPrefixLimitTeardown15010
	out.teardown = true
	i := 0
	// Optional percentage (a bare integer token).
	if i < len(tokens) && tokens[i] != "idle-timeout" {
		n, err := strconv.ParseUint(tokens[i], 10, 32)
		if err != nil {
			return out, fmt.Errorf("teardown percentage %q is not an unsigned integer", tokens[i])
		}
		if n < 1 || n > 100 {
			return out, fmt.Errorf("teardown percentage must be in [1..100], got %q", tokens[i])
		}
		out.pct = int(n)
		i++
	}
	if i < len(tokens) {
		if tokens[i] != "idle-timeout" {
			return out, fmt.Errorf("teardown: unexpected token %q (want [percentage] [idle-timeout (forever|minutes)])", tokens[i])
		}
		i++
		if i >= len(tokens) {
			return out, fmt.Errorf("teardown idle-timeout is missing its value (forever or minutes)")
		}
		if tokens[i] == "forever" {
			out.forever = true
			i++
		} else {
			n, err := strconv.ParseUint(tokens[i], 10, 32)
			if err != nil {
				return out, fmt.Errorf("teardown idle-timeout %q is not \"forever\" or an unsigned integer", tokens[i])
			}
			if n < 1 || n > 2400 {
				return out, fmt.Errorf("teardown idle-timeout must be in [1..2400] minutes or forever, got %q", tokens[i])
			}
			out.idle = int(n)
			i++
		}
	}
	if i < len(tokens) {
		return out, fmt.Errorf("teardown: unexpected trailing token %q", tokens[i])
	}
	return out, nil
}

// ValidateBGPPrefixLimitTeardownTail15010 is the schema tailValidator for
// the `teardown` leaf. tokens excludes the `teardown` keyword itself.
func ValidateBGPPrefixLimitTeardownTail15010(tokens []string, _ [][]string) error {
	_, err := parseTeardownTokens15010(tokens)
	return err
}

// validatePrefixLimitChildren15010 rejects unmodelled prefix-limit
// children (drop-excess/hide-excess and any typo) on the compiler path.
// The schema closed world does not cover this subtree, so without this
// an authored drop-excess would commit and be silently ignored — the
// exact fail-open shape #15010 forbids. Runs in parsePrefixLimitFull15010.
func validatePrefixLimitChildren15010(pl *Node) error {
	for _, c := range pl.Children {
		switch c.Name() {
		case "maximum", "teardown":
		default:
			return fmt.Errorf("prefix-limit %q is not supported (only maximum and teardown are modelled; drop-excess/hide-excess have no FRR equivalent)", c.Name())
		}
	}
	// Flat-set shape: children may be packed onto the prefix-limit node's
	// Keys tail in some spellings; gatherLeafTailTokens covers the leaf
	// reads, and unknown packed keywords surface via the child loop above
	// after expansion. Also scan Keys for drop/hide tokens defensively.
	for _, k := range pl.Keys {
		if k == "drop-excess" || k == "hide-excess" {
			return fmt.Errorf("prefix-limit %q is not supported (only maximum and teardown are modelled)", k)
		}
	}
	return nil
}

// parsePrefixLimitFull15010 extends parsePrefixLimit with the teardown
// action. Returns the maximum (0 when absent), whether the prefix-limit
// node is present, the teardown model, and any error.
func parsePrefixLimitFull15010(famNode *Node) (int, bgpPrefixLimitTeardown15010, error) {
	var td bgpPrefixLimitTeardown15010
	unicast := famNode.FindChild("unicast")
	if unicast == nil {
		return 0, td, nil
	}
	pl := unicast.FindChild("prefix-limit")
	if pl == nil {
		return 0, td, nil
	}
	td.present = true
	if err := validatePrefixLimitChildren15010(pl); err != nil {
		return 0, td, err
	}
	limit, _, err := parsePrefixLimit(famNode)
	if err != nil {
		return 0, td, err
	}
	if tdn := pl.FindChild("teardown"); tdn != nil {
		parsed, err := parseTeardownTokens15010(gatherLeafTailTokens(tdn))
		if err != nil {
			return 0, td, err
		}
		parsed.present = true
		td = parsed
	}
	return limit, td, nil
}

// bgpPrefixLimitTarget15010 bundles the per-family typed destinations so
// applyPrefixLimitFull15010 has one signature for group and neighbor.
type bgpPrefixLimitTarget15010 struct {
	maximum  *int
	teardown *bool
	pct      *int
	idle     *int
	forever  *bool
}

func (t bgpPrefixLimitTarget15010) set(limit int, td bgpPrefixLimitTeardown15010) {
	*t.maximum = limit
	*t.teardown = td.teardown
	*t.pct = td.pct
	*t.idle = td.idle
	*t.forever = td.forever
}

// applyPrefixLimitFull15010 is applyPrefixLimit11793 plus the teardown
// action. clearWhenAbsent mirrors the 11793 contract: group scope clears
// on absent, neighbor scope preserves the inherited group model when it
// supplies no prefix-limit of its own. On the tolerant path a malformed
// override warns and preserves the ENTIRE inherited model (maximum and
// teardown), so a bad line can neither remove the cap nor silently flip
// its action.
func applyPrefixLimitFull15010(famNode *Node, target bgpPrefixLimitTarget15010, clearWhenAbsent bool, scope string, opts compileOpts, warnings *[]string) error {
	limit, td, err := parsePrefixLimitFull15010(famNode)
	if err != nil {
		msg := fmt.Sprintf("%s: %v", scope, err)
		if !opts.lenientBGPPrefixLimit11793 {
			return fmt.Errorf("%s", msg)
		}
		if warnings != nil {
			*warnings = append(*warnings, msg+" (downgraded to warning on tolerant path; inherited maximum retained)")
		}
		return nil
	}
	if td.present || clearWhenAbsent {
		target.set(limit, td)
	}
	return nil
}
