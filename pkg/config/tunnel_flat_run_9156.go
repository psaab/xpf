package config

import "strconv"

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
	ifaces := resolveSchemaChild(setSchema, "interfaces")
	if ifaces == nil || ifaces.wildcard == nil {
		return nil
	}
	return resolveSchemaChild(ifaces.wildcard, "tunnel")
}

// tunnelRunChildren9156 is what both tunnel readers iterate.
func tunnelRunChildren9156(tunnelNode *Node) []*Node {
	if tunnelNode == nil {
		return nil
	}
	return hoistAndSplitRun8939(tunnelNode.Children, tunnelSchema9156())
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
				tc.Mode = v
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
