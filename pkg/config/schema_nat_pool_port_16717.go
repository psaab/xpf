package config

import (
	"fmt"
	"strings"
)

// #16717: validateSourcePoolPortRangeTail16717 is the schema tail validator
// for the source-NAT pool `port range` leaf. Range operands belong to this
// value node; sibling port modifiers remain in their own schema nodes and
// receive their own validation. This uses parseSourcePoolPortRange — the same
// parser the compiler stamps from. Empty ranges retain the compiler's
// fail-closed sentinel handling (#15675).
func validateSourcePoolPortRangeTail16717(tokens []string, _ [][]string) error {
	if len(tokens) == 0 {
		return nil // empty range: compiler <empty> sentinel + strict gate (#15675)
	}
	rangeTokens := tokens
	switch tokens[len(tokens)-1] {
	case "random-allocation", "no-random-allocation":
		rangeTokens = tokens[:len(tokens)-1]
	}
	if len(rangeTokens) == 0 {
		return nil // preserve empty-range handling when followed by a modifier
	}
	if _, _, ok := parseSourcePoolPortRange(rangeTokens); !ok {
		return fmt.Errorf("port range %q is invalid; source-pool ports must be 1-65535 and the range non-decreasing", strings.Join(tokens, " "))
	}
	return nil
}
