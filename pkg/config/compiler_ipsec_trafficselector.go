package config

import (
	"fmt"
	"net"
	"strings"
)

// compiler_ipsec_trafficselector.go carries two reject-at-commit gates for
// IPsec `traffic-selector local-ip / remote-ip` values, both in
// validateIPsecTrafficSelectorsStrict: the #4098 swanctl-injection value gate
// (below) and the #5692 duplicate-selector gate (repeated local-ip / remote-ip
// leaves under one traffic-selector pass admission but the compiler keeps only
// the last — see the inline note at the value-count loop).
//
// The defect: `security ipsec vpn <name> traffic-selector <ts> local-ip` and
// `remote-ip` are free-form 1-arg strings (schema_security.go). The IPsec
// renderer (pkg/ipsec/policy.go effectiveTrafficSelectors → renderConfig)
// interpolates them directly into the swanctl.conf children{} block as
// `local_ts = <value>` / `remote_ts = <value>`. Unlike the sibling child SA
// name (rendered through sanitizeSwanctlValue), these two values were emitted
// raw. The Junos lexer materializes a `\n` escape inside a quoted value
// (lexer.go), so a selector such as
//
//	set security ipsec vpn v1 traffic-selector ts1 local-ip \
//	    "10.0.0.0/24\n        updown = /tmp/x.sh"
//
// injected a real newline plus an arbitrary `key = value` line into the
// children{} block. charon runs as ROOT, so an injected `updown = <script>`
// is a remote-config → root-RCE; an injected `esp_proposals` / `mode` /
// `mark_*` silently rewrites the crypto posture. This is the traffic-selector
// instance of the swanctl-injection class the module already closes for the
// connection name / IKE identity / certificate / PSK (#1798/#2126).
//
// Two-layer fix (mirrors the FRR auth-value gate, #2889):
//
//   - Render belt: pkg/ipsec/policy.go now runs local_ts/remote_ts through
//     sanitizeSwanctlValue (control chars → spaces), so even a value that
//     reaches the renderer on the lenient load path cannot inject a line.
//   - Commit gate (this file): a well-formed traffic selector is a CIDR
//     prefix, a bare host address, or an IP range — never carries a control
//     character or whitespace. Reject anything else at commit so the operator
//     sees the malformed / malicious value instead of a silently mangled
//     (sanitized-to-spaces) selector.
//
// This is an AST pre-walk (like validateSecureTunnelBindInterfaceAST) rather
// than a typed-Config validator so it runs on the group-expanded,
// inactive-pruned tree in compileExpanded: an apply-groups-inherited selector
// is covered, an `inactive:` VPN is ignored, and — critically — it inspects
// EVERY value token on the leaf (both parser shapes, plus a bracketed
// `[ a b ]` list that the lexer collapses onto the leaf Keys, #2419), not just
// the first token the typed compiler keeps (nodeVal reads only Keys[1], so a
// malicious second token would otherwise be dropped from the typed config yet
// escape validation).
//
// Strict path (commit / commit-check, lenient=false): the first offending
// value is a hard compile error naming the VPN, the selector, the leaf, and
// the reason.
//
// Lenient path (load / peer-sync, lenient=true): every offending value is
// returned as a warning and compilation continues — an already-persisted or
// peer-synced config that an older binary silently accepted still BOOTS (#1960
// fail-closed-on-load class); the render belt keeps the value inert. Commit /
// commit-check stay strict.
func validateIPsecTrafficSelectorsStrict(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// Iterate EVERY top-level `security` node and EVERY `ipsec` sibling — the
	// parser APPENDS a repeated top-level block rather than merging it, and
	// compileExpanded compiles every one (mirrors #3562 in the bind-interface
	// gate). A stable per-VPN, per-selector walk keeps error ordering
	// deterministic.
	walkErr := forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "ipsec", func(ipsec *Node) error {
			for _, vpnInst := range namedInstances(ipsec.FindChildren("vpn")) {
				for _, tsInst := range namedInstances(vpnInst.node.FindChildren("traffic-selector")) {
					// #5692: count local-ip / remote-ip VALUES across all such
					// leaves in the selector. Junos models each as a SINGLE-value
					// leaf (schema_security.go: the traffic-selector grammar is
					// exactly one `local-ip <prefix>` and one `remote-ip <prefix>`),
					// but the hierarchical / load-merge / HA-config-sync parse path
					// keeps REPEATED sibling leaves (the flat-set path collapses them
					// last-wins in SetPath). The typed compiler
					// (compiler_ipsec.go traffic-selector loop) reads them last-wins
					// too, so every prefix but the last is SILENTLY dropped — even
					// though each passed this admission gate. Reject so the operator
					// sees the truncation instead of a selector that enforces only
					// its last prefix. Multiple prefixes are expressed the Junos way,
					// as SEPARATE named traffic-selectors (each renders its own
					// swanctl child — effectiveTrafficSelectors), which are already
					// accumulated correctly.
					valueCounts := map[string]int{}
					// #8939: the flat spelling
					//   set … traffic-selector ts1 local-ip 10.0.0.0/8 remote-ip 172.16.0.0/12
					// nests the remote-ip node UNDER local-ip, so
					// trafficSelectorValues read `remote-ip` as a SECOND local-ip
					// VALUE and this gate rejected the command with a message
					// naming the wrong problem. Segmenting first makes the gate
					// see the two leaves the operator typed. Repeated sibling
					// leaves -- the #5692 case this gate exists for -- are
					// untouched: expandFlatRun only splits a node whose Keys
					// carry a further schema sibling.
					for _, leaf := range expandFlatRun(tsInst.node.Children, ipsecTrafficSelectorSchema8939()) {
						leafName := leaf.Name()
						if leafName != "local-ip" && leafName != "remote-ip" {
							continue
						}
						vals := trafficSelectorValues(leaf)
						valueCounts[leafName] += len(vals)
						for _, val := range vals {
							if reason := trafficSelectorValueReject(val); reason != "" {
								if err := emit(
									"security ipsec vpn %q traffic-selector %q %s %q %s "+
										"(a traffic selector must be a CIDR prefix, a host "+
										"address, or an IP range; a control character or "+
										"whitespace would inject an arbitrary line — e.g. "+
										"`updown = <script>`, run by charon as root, or an "+
										"`esp_proposals` override — into the rendered "+
										"swanctl.conf children block, #4098)",
									vpnInst.name, tsInst.name, leafName, val, reason,
								); err != nil {
									return err
								}
							}
						}
					}
					// Deterministic leaf order for the first-error (strict) path.
					for _, leafName := range []string{"local-ip", "remote-ip"} {
						if valueCounts[leafName] > 1 {
							if err := emit(
								"security ipsec vpn %q traffic-selector %q specifies %d %s "+
									"prefixes, but Junos allows exactly ONE %s per "+
									"traffic-selector; the compiler keeps only the LAST and "+
									"silently drops the earlier prefix(es) even though each "+
									"passed admission — express multiple prefixes as separate "+
									"named traffic-selectors (each renders its own SA child), "+
									"#5692",
								vpnInst.name, tsInst.name, valueCounts[leafName], leafName, leafName,
							); err != nil {
								return err
							}
						}
					}
				}

				// #8003: `local-identity` / `remote-identity` can become
				// swanctl selectors. effectiveTrafficSelectors uses them when
				// there are no explicit selectors and as per-side fallbacks
				// for explicit children missing local-ip / remote-ip. These
				// VPN-level leaves are not under a traffic-selector node, so
				// validate them separately below.
				//
				// Measured on strongSwan 6.0.5: a non-selector value here does not
				// degrade, it takes the WHOLE connection with it.
				//
				//   loading connection 'm_fqdnts' failed: invalid value for:
				//   local_ts, config discarded
				//
				// "config discarded" is the entire connection, so the VPN never
				// establishes — the same signature policy.go already records for
				// #7165 item 2, in the same generated block, and charon's log is
				// not a place an operator looks.
				//
				// The trap is that the field is named for one thing and filled from
				// a statement meaning another: IPsecVPN.LocalID is declared "local
				// traffic selector (CIDR)", but the only statement that populates it
				// is spelled `local-identity`, which in Junos is an IDENTITY and is
				// normally an FQDN or DN. The operator who writes the Junos-shaped
				// value is the one who gets a silently dead tunnel.
				for _, leafName := range []string{"local-identity", "remote-identity"} {
					for _, leaf := range vpnInst.node.FindChildren(leafName) {
						for _, val := range trafficSelectorValues(leaf) {
							reason := trafficSelectorValueReject(val)
							if reason == "" {
								continue
							}
							if err := emit(
								"security ipsec vpn %q %s %q %s — the renderer can use this as "+
									"the swanctl local_ts/remote_ts when the VPN has no "+
									"traffic-selector or an explicit child omits that side; "+
									"strongSwan DISCARDS THE WHOLE CONNECTION for a "+
									"non-selector value, so the tunnel silently never "+
									"establishes; use a CIDR prefix, host address, or IP range "+
									"(#8003)",
								vpnInst.name, leafName, val, reason,
							); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// trafficSelectorValues returns every value token carried by a `local-ip` /
// `remote-ip` leaf across BOTH parser AST shapes and a bracketed `[ a b ]`
// list — mirrors firewallMatchValues (#2419). Reading Keys[1:] AND the child
// names guarantees a malicious token in any list position is validated even
// though the typed compiler's nodeVal keeps only Keys[1].
func trafficSelectorValues(leaf *Node) []string {
	var vals []string
	for _, k := range leaf.Keys[1:] {
		if k != "" {
			vals = append(vals, k)
		}
	}
	for _, vn := range leaf.Children {
		if len(vn.Keys) >= 1 && vn.Keys[0] != "" {
			vals = append(vals, vn.Keys[0])
		}
	}
	return vals
}

// trafficSelectorValueReject returns a human-readable reason a traffic-selector
// value is unacceptable, or "" if it is a well-formed CIDR prefix, host
// address, or IP range. The control-character / whitespace check runs first so
// the injection case gets an explicit reason; a value that clears it but is
// not a routable selector shape is still rejected (operator hygiene).
func trafficSelectorValueReject(v string) string {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Sprintf("contains a control character (byte offset %d)", i)
		}
		if c == ' ' || c == '\t' {
			return fmt.Sprintf("contains whitespace (byte offset %d)", i)
		}
	}
	if !isTrafficSelectorShape(v) {
		return "is not a valid CIDR prefix, host address, or IP range"
	}
	return ""
}

// IsTrafficSelectorShape is the exported form of isTrafficSelectorShape, for
// the render-side belts in pkg/ipsec (#8003/#10884). They and this commit gate
// MUST apply the SAME rule: two surfaces enforcing one rule from two
// predicates is how they drift, which is the exact defect diagcmd.MaxArgLen
// was created to end (#6904). One predicate, both surfaces.
func IsTrafficSelectorShape(v string) bool { return isTrafficSelectorShape(v) }

// isTrafficSelectorShape reports whether v is a CIDR prefix (v4/v6), a bare
// host address (v4/v6), or an inclusive IP range `start-end` — the shapes a
// swanctl local_ts / remote_ts value may take.
func isTrafficSelectorShape(v string) bool {
	if v == "" {
		return false
	}
	// IP range: start-end (both endpoints bare addresses). Split on the FIRST
	// '-' only; an IPv6 address never contains '-', and a v4 range uses a
	// single separator.
	if i := strings.IndexByte(v, '-'); i >= 0 {
		start := v[:i]
		end := v[i+1:]
		return net.ParseIP(start) != nil && net.ParseIP(end) != nil
	}
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	return net.ParseIP(v) != nil
}
