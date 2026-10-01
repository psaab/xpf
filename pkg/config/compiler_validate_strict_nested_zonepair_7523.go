package config

import "fmt"

// compiler_validate_strict_nested_zonepair_7523.go — #7523 and #11346.
//
// Two unsupported zone-pair brace spellings were accepted and silently
// omitted: direct nesting, `from-zone X { to-zone Y { ... } }` (#7523), and
// the mixed container/keyed spelling, `from-zone { X { to-zone Y { ... } } }`
// (#11346). The mixed form can be interpreted as `from-zone X to-zone policy`
// and compile an empty pair if a zone named `policy` exists; otherwise an
// unrelated undefined-zone warning hides the malformed shape.
//
// Junos models one combined hierarchy, `from-zone X to-zone Y { ... }`.
// xpf also supports the fully nested container spelling
// `from-zone { X { to-zone { Y { ... } } } }`. That shape has a `from-zone`
// node with one key and an unkeyed `to-zone` container, so neither key count
// alone nor a recursive name-only search can distinguish it from #11346.
//
// The relevant tree shapes are:
//
//	DIRECT-NESTED     Keys=[from-zone X]                children=[to-zone]
//	COMBINED          Keys=[from-zone X to-zone Y]      children=[policy]
//	FLAT-SET          Keys=[from-zone X to-zone Y]      children=[policy]
//	MIXED-CONTAINER   Keys=[from-zone] -> [X] -> [to-zone Y]
//	FULL-CONTAINER    Keys=[from-zone] -> [X] -> [to-zone] -> [Y]
//
// Reject-only on strict commit. The tolerant path retains its #1960
// no-brick behavior and downgrades the same specific diagnostic to a warning.
func validateNestedZonePairStrict(tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	for _, root := range tree.Children {
		if root.Name() != "security" {
			continue
		}
		for _, policies := range root.Children {
			if policies.Name() != "policies" {
				continue
			}
			for _, fz := range policies.Children {
				if fz.Name() != "from-zone" {
					continue
				}
				if len(fz.Keys) == 1 {
					for _, fromNode := range fz.Children {
						from := fromNode.Name()
						for i := 1; i+1 < len(fromNode.Keys); i++ {
							if fromNode.Keys[i] == "to-zone" {
								to := fromNode.Keys[i+1]
								return mixedKeyedZonePairError11346(from, to)
							}
						}
						for _, sub := range fromNode.Children {
							if sub.Name() != "to-zone" || len(sub.Keys) < 2 {
								continue
							}
							return mixedKeyedZonePairError11346(from, sub.Keys[1])
						}
					}
				}
				for _, sub := range fz.Children {
					if sub.Name() != "to-zone" {
						continue
					}
					from := ""
					if len(fz.Keys) >= 2 {
						from = fz.Keys[1]
					}
					to := ""
					if len(sub.Keys) >= 2 {
						to = sub.Keys[1]
					}
					return fmt.Errorf(
						"security policies from-zone %q contains a NESTED `to-zone %s { ... }` "+
							"block. Junos models one COMBINED hierarchy, so this spelling is not "+
							"implemented: it compiles to zero zone-pairs and zero policies, and the "+
							"pair falls through to the default policy with nothing said. Write it as "+
							"`set security policies from-zone %s to-zone %s policy <name> ...` "+
							"(or the block form `from-zone %s to-zone %s { ... }`) (#7523)",
						from, to, from, to, from, to)
				}
			}
		}
	}
	return nil
}

func mixedKeyedZonePairError11346(from, to string) error {
	return fmt.Errorf(
		"security policies contain a MIXED zone-pair brace spelling: `to-zone %s { ... }` "+
			"under `from-zone { %s { ... } }` is not implemented and can compile as "+
			"`from-zone %s to-zone policy` with zero policies. Write the combined "+
			"`from-zone %s to-zone %s` form or the fully nested `from-zone { %s { "+
			"to-zone { %s { ... } } } }` container form (#11346)",
		to, from, from, from, to, from, to)
}
