package config

import "fmt"

const bgpSAFIUnicast11815 = "unicast"

// applyBGPFamilySAFI11815 preserves only the route family xpf can render.
// A bare `family inet|inet6` retains Junos's unicast default. An explicit
// unsupported SAFI is rejected on strict compilation; on lenient load/sync
// the gate warns here — its call sites see every AST shape, including a
// hierarchical one-liner's packed Keys tail — and the family stays inert,
// never activating unicast (#11815).
func applyBGPFamilySAFI11815(famNode *Node, scope string, opts compileOpts, warnings *[]string) (unicast, unsupported bool, err error) {
	if famNode == nil {
		return true, false, nil
	}

	sawSAFI := false
	unsupportedName := ""
	accept := func(safi string) {
		sawSAFI = true
		if safi == bgpSAFIUnicast11815 {
			unicast = true
			return
		}
		unsupported = true
		if unsupportedName == "" {
			unsupportedName = safi
		}
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

	// A mixed family still activates its explicitly configured unicast; only
	// the unsupported SAFI is dropped. Say which, so a lenient boot/sync
	// warning never reads as "this family is not activated" when unicast is.
	var msg string
	if unicast {
		msg = fmt.Sprintf("%s: BGP address-family SAFI %q is unsupported and is skipped; explicitly configured unicast remains activated (#11815)", scope, unsupportedName)
	} else {
		msg = fmt.Sprintf("%s: BGP address-family SAFI %q is unsupported; only unicast is compiled, so this family is not activated (#11815)", scope, unsupportedName)
	}
	if !opts.lenientBGPSAFI11815 {
		return false, true, fmt.Errorf("%s", msg)
	}
	if warnings != nil {
		*warnings = append(*warnings, msg)
	}
	return unicast, true, nil
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
