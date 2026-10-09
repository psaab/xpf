package config

import (
	"fmt"
	"strings"
)

const bgpSAFIUnicast11815 = "unicast"

// bgpSAFIWarning11815 captures warning details so merged activation can be
// finalized without parsing the rendered diagnostic.
type bgpSAFIWarning11815 struct {
	index int
	afi   string
	scope string
	safi  string
}

// applyBGPFamilySAFI11815 preserves only the route family xpf can render.
// A bare `family inet|inet6` retains Junos's unicast default. The gate sees
// every AST shape, including a hierarchical one-liner's packed Keys tail.
// Strict compilation rejects unsupported SAFIs. Lenient wording is finalized
// after sibling and inherited activation is merged; unsupported SAFIs stay
// inert without discarding a supported unicast activation (#11815).
func applyBGPFamilySAFI11815(famNode *Node, afi, scope string, opts compileOpts, warnings *[]string, warningRecords *[]bgpSAFIWarning11815) (unicast, unsupported bool, err error) {
	if famNode == nil {
		return true, false, nil
	}

	sawSAFI := false
	unsupportedNames := make([]string, 0, 1)
	accept := func(safi string) {
		sawSAFI = true
		if safi == bgpSAFIUnicast11815 {
			unicast = true
			return
		}
		unsupported = true
		for _, name := range unsupportedNames {
			if name == safi {
				return
			}
		}
		unsupportedNames = append(unsupportedNames, safi)
	}

	// The compound family node is Keys=[family, inet|inet6]. The first tail
	// token, if any, is its SAFI; later tokens belong to that SAFI's body (for
	// example, unicast prefix-limit maximum 100).
	if len(famNode.Keys) >= 3 && famNode.Keys[0] == "family" {
		accept(famNode.Keys[2])
	} else if len(famNode.Keys) >= 2 && (famNode.Keys[0] == "inet" || famNode.Keys[0] == "inet6") {
		// Split family shape: family -> inet|inet6 -> SAFI.
		accept(famNode.Keys[1])
	}
	// A compound family node's direct children are SAFIs. In the split shape,
	// this helper receives the inet/inet6 node whose direct children are SAFIs.
	for _, child := range famNode.Children {
		if child != nil && child.Name() != "" {
			accept(child.Name())
		}
	}
	if !sawSAFI {
		// Existing Junos configs commonly use bare family inet|inet6; that is
		// shorthand for unicast and remains an explicit unicast activation.
		unicast = true
	}
	if !unsupported {
		return unicast, false, nil
	}

	// Lenient mixed-family warnings are finalized after sibling and inherited
	// activation has been merged by the group/neighbor compiler.
	if !opts.lenientBGPSAFI11815 {
		quotedNames := make([]string, len(unsupportedNames))
		for i, name := range unsupportedNames {
			quotedNames[i] = fmt.Sprintf("%q", name)
		}
		noun, verb := "SAFI", "is"
		if len(quotedNames) != 1 {
			noun, verb = "SAFIs", "are"
		}
		return false, true, fmt.Errorf(
			"%s: BGP address-family %s %s %s unsupported; the configured family is rejected on strict compilation (#11815)",
			scope, noun, strings.Join(quotedNames, ", "), verb,
		)
	}
	if warnings != nil {
		for _, name := range unsupportedNames {
			index := len(*warnings)
			*warnings = append(*warnings, formatBGPFamilySAFIWarning11815(scope, name, unicast))
			if warningRecords != nil {
				*warningRecords = append(*warningRecords, bgpSAFIWarning11815{
					index: index,
					afi:   afi,
					scope: scope,
					safi:  name,
				})
			}
		}
	}
	return unicast, true, nil
}

func formatBGPFamilySAFIWarning11815(scope, safi string, unicast bool) string {
	quotedSAFI := fmt.Sprintf("%q", safi)
	if unicast {
		return fmt.Sprintf("%s: BGP address-family SAFI %s is unsupported and is skipped; unicast remains activated in the merged configuration (#11815)", scope, quotedSAFI)
	}
	return fmt.Sprintf("%s: BGP address-family SAFI %s is unsupported; only unicast is compiled, so this family is not activated (#11815)", scope, quotedSAFI)
}

func setBGPFamilySAFIWarningActivation11815(warnings *[]string, record bgpSAFIWarning11815, unicast bool) {
	if warnings == nil || record.index < 0 || record.index >= len(*warnings) {
		return
	}
	(*warnings)[record.index] = formatBGPFamilySAFIWarning11815(record.scope, record.safi, unicast)
}

// isBGPSAFIWarningOwned11815 reports whether keyword is a BGP family SAFI
// whose diagnostic the SAFI gate owns. The open-world child-keyword walk
// (warnUnknownRoutingLeaves10707) skips these: the gate warns at its call
// sites, which see every spelling including a hierarchical one-liner's packed
// Keys tail that the child walk cannot see (#11815).
func isBGPSAFIWarningOwned11815(path []string, keyword string) bool {
	if keyword == bgpSAFIUnicast11815 || len(path) < 2 {
		return false
	}
	if path[len(path)-2] != "family" || (path[len(path)-1] != "inet" && path[len(path)-1] != "inet6") {
		return false
	}
	for i := 0; i+1 < len(path); i++ {
		if path[i] == "protocols" && path[i+1] == "bgp" {
			return true
		}
	}
	return false
}
