package config

import (
	"fmt"
	"strconv"
)

// #9156 (V020): the `tunnel` container's compiler reads
// `tunnelNode.Children` directly, so a flat-set run whose head is an UNTYPED
// leaf carries every later statement past the strict commit gate and then
// loses it.
//
// The gate does not fire because `validateModifierChild` (schema_walk.go)
// rejects a run whose head leaf is TYPED. `keepalive-retry` and
// `routing-instance` declare no valueType and no validator, so they are
// ADMISSION HEADS: the run is admitted, and the reader never expands it.
// Measured before this change, all four commit with err=<nil>:
//
//	CONTROL  source A / destination B on separate lines   src=A  dst=B
//	A        tunnel keepalive-retry 5 source A destination B   src=""  dst=""
//	B        source A on its own line, then
//	         tunnel keepalive-retry 5 destination B       src=A  dst=""
//	C        destination B on its own line, then
//	         tunnel keepalive-retry 5 source A            src=""  dst=B
//	         tunnel routing-instance destination VR1 source A   ri=VR1 src=""
//
// while the TYPED head is rejected:
//
//	tunnel destination B keepalive-retry 5
//	  -> `interfaces gr-0/0/0 unit 0 tunnel destination: unknown modifier
//	     "keepalive-retry"`
//
// B is the harmful one. `Source != ""` is the only endpoint screen on the
// routing side, so B creates the TUN, brings it up and addresses it — while
// EmitTunnelEndpointNames, which requires BOTH endpoints, emitted nothing. The
// operator gets an interface they can zone and route into that blackholes every
// packet.
//
// `packedStatements: true` is ALREADY declared on this container
// (schema_interfaces.go) and does not help: it splits a packed tail on ONE
// node's Keys, and SetPath builds these as a nested CHAIN
// (`[keepalive-retry 5] > [destination 10.0.0.2]`). Measured, not assumed.
//
// hoistAndSplitRun8939 is the remedy that covers both shapes — it lifts a
// statement SetPath nested under an earlier one AND splits a node whose Keys
// carry several statements — and it is the one of the three remedies in this
// tree that carries a coverage guard.

// tunnelSchema9156 resolves the `interfaces <name> tunnel` container out of
// setSchema rather than rebuilding it, so the run expansion is driven by the
// same declaration SetPath walked.
//
// The interface-level and unit-level `tunnel` nodes share tunnelSchemaChildren(),
// so one resolver serves both readers; TestTunnelSchemaResolvesBothPositions9156
// asserts that rather than assuming it.
func tunnelSchema9156() *schemaNode {
	return refTunnel.resolve()
}

// tunnelRunChildren9156 is what both tunnel readers iterate.
func tunnelRunChildren9156(tunnelNode *Node) []*Node {
	if tunnelNode == nil {
		return nil
	}
	return hoistAndSplitRun8939(tunnelNode.Children, tunnelSchema9156())
}

// applyTunnelProps17236 is the single tunnel-property reader shared by the
// interface-level and unit-level tunnel sites in compileInterfaces
// (#17236, R4-Q23-04). It supersedes the two mirrored switches that
// diverged once already: #13215 fixed the pre-pass in the interface copy
// only and the unit twin shipped the inherited-peer / plaintext-GRE bug
// until #14440 extracted the shared pre-pass but left the main switch
// duplicated. The property read is identical at both levels after
// normalisation; the only caller-owned differences are the setup that
// produced tc (default mode at interface level, cloneForUnit at unit
// level) and what a numeric quarantine means, which the caller expresses
// via where/suffix: where prefixes every numeric error
// ("interfaces <ifname>:" / "interfaces <ifname> unit <n>:") and suffix
// completes the lenient warning ("; quarantining interface %q" /
// "; skipping unit %d"). nodes are the tunnel nodes in merge order
// (#14450: scalars last-win across blocks, peers accumulate); the
// #9156/#14440 pre-pass runs per block, in order, before that block's
// flattened loop (#14440 ordering: after cloneForUnit at unit level).
// Returns quarantine=true when a lenient numeric failure asks the caller
// to skip the owning interface/unit; a strict numeric failure is
// returned as err with quarantine=false.
func applyTunnelProps17236(tc *TunnelConfig, nodes []*Node, where string, suffix string, lenient bool, warnings *[]string) (quarantine bool, err error) {
	for _, tunnelNode := range nodes {
		// #14440: retain braced scalars before the flattening loop.
		applyTunnelBracedScalars14440(tc, tunnelNode)
		// #9156: expand the flat-set run before reading it.
		for _, prop := range tunnelRunChildren9156(tunnelNode) {
			switch prop.Name() {
			case "source":
				if v := nodeVal(prop); v != "" {
					tc.Source = v
				}
			case "destination":
				if v := nodeVal(prop); v != "" {
					tc.Destination = v
				}
			case "mode":
				if v := nodeVal(prop); v != "" {
					tc.Mode = TunnelMode(v)
				}
			case "key":
				raw := nodeVal(prop)
				v, perr := parseInterfaceNumeric9899(raw, 0, 4294967295)
				if perr != nil {
					msg := fmt.Sprintf("%s tunnel key %s", where, perr.Error())
					if lenient {
						if warnings != nil {
							*warnings = append(*warnings, msg+suffix)
						}
						return true, nil
					}
					return false, fmt.Errorf("%s", msg)
				}
				tc.Key = uint32(v)
			case "ttl":
				raw := nodeVal(prop)
				v, perr := parseInterfaceNumeric9899(raw, 1, 255)
				if perr != nil {
					msg := fmt.Sprintf("%s tunnel ttl %s", where, perr.Error())
					if lenient {
						if warnings != nil {
							*warnings = append(*warnings, msg+suffix)
						}
						return true, nil
					}
					return false, fmt.Errorf("%s", msg)
				}
				tc.TTL = int(v)
			case "keepalive":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						tc.Keepalive = n
					}
				}
			case "keepalive-retry":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						tc.KeepaliveRetry = n
					}
				}
			case "routing-instance":
				// routing-instance { destination <name>; }
				if destNode := prop.FindChild("destination"); destNode != nil {
					tc.RoutingInstance = nodeVal(destNode)
				} else if v, packed := packedTunnelRoutingInstance8936(prop); packed {
					tc.RoutingInstance = v
				} else if v := nodeVal(prop); v != "" {
					tc.RoutingInstance = v
				}
			case "wireguard":
				parseTunnelWireguard(tc, prop)
			case "clear-dont-fragment-bit":
				tc.ClearDontFragmentBit = true
			}
		}
	}
	return false, nil
}

// applyTunnelBracedScalars14440 retains braced-scalar tunnel leaves
// (`source { X; }`, `destination { X; }`, `mode { X; }`,
// `keepalive { N; }`, `keepalive-retry { N; }`) from the RAW tunnel
// children before tunnelRunChildren9156 flattens them into an empty
// leaf plus a stray value sibling the reader's v != "" guard skips
// (#14440, extending the #13215 interface-level pre-pass). Both the
// interface-level and unit-level readers call it; the flattened loop
// that follows re-asserts flat spellings idempotently. key/ttl are
// deliberately NOT handled here: their braced forms must still fail
// parseInterfaceNumeric9899 in the flattened loop (strict error /
// lenient quarantine), not be silently adopted.
func applyTunnelBracedScalars14440(tc *TunnelConfig, tunnelNode *Node) {
	if tc == nil || tunnelNode == nil {
		return
	}
	for _, rawProp := range tunnelNode.Children {
		switch rawProp.Name() {
		case "source":
			if v := nodeVal(rawProp); v != "" {
				tc.Source = v
			}
		case "destination":
			if v := nodeVal(rawProp); v != "" {
				tc.Destination = v
			}
		case "mode":
			if v := nodeVal(rawProp); v != "" {
				tc.Mode = TunnelMode(v)
			}
		case "keepalive":
			if v := nodeVal(rawProp); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					tc.Keepalive = n
				}
			}
		case "keepalive-retry":
			if v := nodeVal(rawProp); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					tc.KeepaliveRetry = n
				}
			}
		}
	}
}
