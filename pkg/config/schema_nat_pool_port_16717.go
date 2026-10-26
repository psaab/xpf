package config

import (
	"fmt"
	"strings"
)

// #16717: validateSourcePoolPortTail16717 is the schema tail validator
// for the source-NAT pool `port` node. Its tokens after `port` are
// values in a compiler-owned grammar, not schema keywords: the
// flat-set AST splits `port range low 1024 high 2047` into child nodes
// ([range], [low] -> [1024 high 2047]) and the hierarchical form nests
// them likewise, so the closed-world walker must judge the flattened
// tail as a unit instead of reading each token as an unknown keyword.
// Range tails are judged by parseSourcePoolPortRange — the same
// parser the compiler stamps from. The allocation modifiers are
// recognized trailing tokens on a range; all other port forms pass
// here untouched, and an empty tail carries no range to judge.
func validateSourcePoolPortTail16717(tokens []string, _ [][]string) error {
	if len(tokens) == 0 || tokens[0] != "range" {
		return nil
	}
	rest := tokens[1:]
	if len(rest) == 0 {
		return nil // empty range: compiler <empty> sentinel + strict gate (#15675)
	}
	rangeTokens := rest
	switch rest[len(rest)-1] {
	case "random-allocation", "no-random-allocation":
		rangeTokens = rest[:len(rest)-1]
	}
	if len(rangeTokens) == 0 {
		return nil // preserve empty-range handling when followed by a modifier
	}
	if _, _, ok := parseSourcePoolPortRange(rangeTokens); !ok {
		return fmt.Errorf("port range %q is invalid; source-pool ports must be 1-65535 and the range non-decreasing", strings.Join(rest, " "))
	}
	return nil
}
