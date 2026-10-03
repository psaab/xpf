package config

import (
	"fmt"
	"strconv"
)

// nodeVal returns the value for a property node, handling both AST shapes.
// Hierarchical: Keys: ["prop", "value"] → returns "value"
// Flat set:     Keys: ["prop"], Children: [Node{Keys:["value"]}] → returns "value"
// parsePrefixLimit extracts the optional maximum from a family inet/inet6
// node. It distinguishes an absent prefix-limit (zero = unlimited) from an
// authored but malformed value, so parse failures can never erase a cap.
func parsePrefixLimit(famNode *Node) (int, bool, error) {
	unicast := famNode.FindChild("unicast")
	if unicast == nil {
		return 0, false, nil
	}
	pl := unicast.FindChild("prefix-limit")
	if pl == nil {
		return 0, false, nil
	}
	mx := pl.FindChild("maximum")
	if mx == nil {
		return 0, true, fmt.Errorf("prefix-limit maximum is missing")
	}
	v := nodeVal(mx)
	if v == "" {
		return 0, true, fmt.Errorf("prefix-limit maximum is missing an integer value")
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, true, fmt.Errorf("prefix-limit maximum %q is not an unsigned 32-bit integer", v)
	}
	if n == 0 {
		return 0, true, fmt.Errorf("prefix-limit maximum must be in [1..4294967295], got %q", v)
	}
	return int(n), true, nil
}

// applyPrefixLimit11793 updates one compiled limit while preserving an
// inherited neighbor limit when that neighbor supplies no override. Invalid
// inputs fail strict compilation; tolerant loads warn and keep the prior
// value, so a bad per-neighbor override cannot silently remove the group cap.
func applyPrefixLimit11793(famNode *Node, target *int, clearWhenAbsent bool, scope string, opts compileOpts, warnings *[]string) error {
	limit, present, err := parsePrefixLimit(famNode)
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
	if present || clearWhenAbsent {
		*target = limit
	}
	return nil
}
