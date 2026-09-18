package config

import (
	"fmt"
	"strconv"
)

// validSyslogPort reports whether n is a dial-able TCP/UDP port. The strict
// commit path DOES range-gate the syslog-stream port at commit / commit-check
// (validateSecurityLogStreamPortsAST, #3349, which hard-rejects an out-of-range
// value), but the lenient tolerant-load / peer-sync path (#1960) downgrades
// that same gate to a warning so an already-persisted or peer-synced config
// still boots — so an out-of-range value like 70000 can still reach compileLog
// on that path. Guarding the parse here keeps the dial-able 514 default (or any
// prior valid value) rather than storing an unusable port that would fail every
// syslog dial and silently lose audit records (#5250 A3-b2 F2).
func validSyslogPort(n int) bool { return n >= 1 && n <= 65535 }

// securityLogTransportSchema resolves the schema node for
// `security log stream <s> transport` (#6821).
//
// Both readers of that container's packed tail — compileLog and the #3350
// tls-profile strict check — expand it through `packedBodyChildren` with THIS
// node, and `walkSchemaNode` validates the same expansion because the node sets
// `packedTail: true`. Resolving it in one place is what stops the three from
// drifting: a schema move that broke the lookup would make the expansion
// silently return the unexpanded children again, which is the original defect.
// TestSecurityLogTransportSchemaResolves6821 fails loudly if the path moves.
// securityLogStreamSchema9391 resolves the `security log stream <s>` body — the
// container itself, not one of its children — so a flat-set run of its own
// leaves can be expanded before the reader walks it.
//
// #9391: `port` declares no valueType and no validator, so it is an ADMISSION
// HEAD. `set security log stream s1 port 5514 category policy` COMMITS CLEAN
// with the category dropped, and Categories == 0 means ALL
// (pkg/logging/syslog.go), so the operator's narrowing is silently inverted
// into "export everything" — a collector scoped for one category receives every
// category. Same for `severity`.
//
// This is the ONE operator-reachable row of the 26 in #9391's register: the
// strict commit walk ADMITS it. The other 25 are rejected at commit and reach
// the compiler only through a config file or an HA sync, where
// Store.compileTreeLenient logs a warning naming the leaf.
func securityLogStreamSchema9391() *schemaNode {
	n := setSchema
	for _, k := range []string{"security", "log", "stream"} {
		if n == nil {
			return nil
		}
		n = n.children[k]
	}
	if n == nil {
		return nil
	}
	if n.wildcard != nil {
		return n.wildcard
	}
	return n
}

func securityLogTransportSchema() *schemaNode {
	n := setSchema
	for _, k := range []string{"security", "log", "stream"} {
		if n == nil {
			return nil
		}
		n = n.children[k]
	}
	if n == nil {
		return nil
	}
	// `stream` is a named instance: its per-instance body hangs off the
	// wildcard when one is declared, otherwise off the node itself.
	if n.wildcard != nil {
		n = n.wildcard
	}
	if n == nil {
		return nil
	}
	return n.children["transport"]
}

func compileLog(node *Node, sec *SecurityConfig) error {
	if sec.Log.Streams == nil {
		sec.Log.Streams = make(map[string]*SyslogStream)
	}

	// #9235: `security log mode event format sd-syslog source-interface fxp0` is
	// ONE command nested into a chain, so the FindChild reads below saw `mode`
	// and missed `format` and `source-interface` -- the box logged in the wrong
	// format from the wrong source address. Expanded ONCE here rather than at
	// each lookup, for the same reason compileFlow does it once: a per-lookup fix
	// is one chance to miss each lookup, and the next leaf added is the next miss.
	// Lenient path only (the schema gate refuses this spelling at commit).
	node = expandRun9235(node, securityLogSchema9235())

	// Top-level log settings
	if modeNode := node.FindChild("mode"); modeNode != nil {
		sec.Log.Mode = nodeVal(modeNode)
	}
	if fmtNode := node.FindChild("format"); fmtNode != nil {
		sec.Log.Format = nodeVal(fmtNode)
	}
	if srcNode := node.FindChild("source-interface"); srcNode != nil {
		sec.Log.SourceInterface = nodeVal(srcNode)
	}
	if node.FindChild("report") != nil {
		sec.Log.Report = true
	}

	for _, inst := range namedInstances(node.FindChildren("stream")) {
		stream := &SyslogStream{
			Name: inst.name,
			Port: 514, // default
		}
		// #9391: expand the flat-set run before reading it — `port` is an
		// untyped ADMISSION HEAD, so `port 5514 category policy` arrived as a
		// nested chain and this loop kept only the head.
		for _, prop := range expandFlatRun(inst.node.Children, securityLogStreamSchema9391()) {
			switch prop.Name() {
			case "host":
				// Flat: host 192.168.99.3;
				if v := nodeVal(prop); v != "" {
					stream.Host = v
				}
				// Nested: host { 192.168.99.3; port 9006; }
				for _, hc := range prop.Children {
					switch hc.Name() {
					case "port":
						if v := nodeVal(hc); v != "" {
							if n, err := strconv.Atoi(v); err == nil && validSyslogPort(n) {
								stream.Port = n
							}
						}
					default:
						// IP address as a bare child node
						if stream.Host == "" && len(hc.Keys) >= 1 {
							stream.Host = hc.Keys[0]
						}
					}
				}
			case "port":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil && validSyslogPort(n) {
						stream.Port = n
					}
				}
			case "severity":
				stream.Severity = nodeVal(prop)
			case "facility":
				stream.Facility = nodeVal(prop)
			case "format":
				stream.Format = nodeVal(prop)
			case "category":
				stream.Category = nodeVal(prop)
			case "source-address":
				stream.SourceAddress = nodeVal(prop)
			case "source-interface":
				// #6875: compiled so the per-stream spelling reaches the apply
				// path. It is resolved to an address there, not here, because
				// resolution reads interface addresses that the compiler does
				// not own.
				stream.SourceInterface = nodeVal(prop)
			case "transport":
				// #6821: read BOTH spellings. `transport { protocol tls; }`
				// arrives as children; `transport protocol tls;` packs the
				// value onto this node's own Keys with NO children, so a
				// Children-only loop ran zero times and left Protocol and
				// TLSProfile empty on a config that committed cleanly.
				//
				// This arm used to be Children-only DELIBERATELY, because
				// compiling a packed tail the gate does not validate turns
				// "not compiled" into "compiled, unvalidated" — measured:
				// `transport { protocol tpc; }` was rejected by the enum while
				// `transport protocol tpc;` was ACCEPTED. That is why the
				// schema's `transport` node now sets `packedTail: true`, which
				// makes the walker validate this same expansion. The gate and
				// the compiler move together, which is the rule
				// docs/config-schema.md states; neither half is correct alone.
				for _, tc := range packedBodyChildren(prop, securityLogTransportSchema()) {
					switch tc.Name() {
					case "protocol":
						stream.Transport.Protocol = nodeVal(tc)
					case "tls-profile":
						stream.Transport.TLSProfile = nodeVal(tc)
					}
				}
			}
		}
		if stream.Host != "" {
			sec.Log.Streams[stream.Name] = stream
		}
	}

	// H7 (#2008): `security log profile <name>` log-routing objects. Each
	// names a target stream (`stream-name`), may be marked the default
	// (`default-profile`), and may carry per-category field config. Reads
	// via namedInstances + nodeVal so both hierarchical and flat-set AST
	// shapes work (same as the stream loop). The stream-name cross-
	// reference is enforced after full compile in
	// validateLogProfileStreamReferencesStrict — schema_walk per-leaf
	// validators cannot see sibling stream nodes. `category` is accepted
	// for parse/validation parity; per-category field-extra-name selection
	// is not yet used to alter the emitted structured data (out of scope).
	for _, inst := range namedInstances(node.FindChildren("profile")) {
		p := &LogProfile{Name: inst.name}
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "stream-name":
				p.StreamName = nodeVal(prop)
			case "default-profile":
				p.DefaultProfile = true
			case "category":
				// Accepted for parity; field-extra-name emission is out of
				// scope for this increment (xpf already emits per-stream
				// structured data).
			}
		}
		if sec.Log.Profiles == nil {
			sec.Log.Profiles = make(map[string]*LogProfile)
		}
		sec.Log.Profiles[p.Name] = p
	}
	return nil
}

// validateSecurityLogStreamPortsAST is the #3349 commit-time range gate for
// `security log stream <s> port <p>` and the nested `host { port <p>; }`
// spelling. The syslog port value lives in TWO AST locations — a direct
// `port` child of the stream and a `port` child of a nested `host` block
// (compileLog reads both) — a dual value-location the declarative
// SchemaValidate walker cannot express, the same rationale as tcp-mss
// (validateTCPMSSRanges). compileLog ignores a non-numeric or out-of-range
// port (strconv.Atoi error path) and silently keeps the default 514, so a typo
// such as `port 6514x` commits and quietly logs audit to the wrong port. This
// pass reads the raw tokens before that swallowing and range-checks them.
//
// It mirrors compileLog's traversal exactly (FindChild("log") +
// namedInstances(stream) + per-child switch on host/port) so it validates
// precisely the tokens the compiler consumes. Runs on the group-expanded tree
// so apply-groups-inherited ports are covered.
//
// Strict path (commit / commit-check, lenient=false): a non-numeric or
// out-of-range port is a hard compile error. Lenient path (load / peer-sync,
// lenient=true): downgraded to a warning so an already-persisted or
// peer-synced config that an older binary accepted (and that the compiler
// still maps to 514) still boots (#1960 / #3261 fail-closed-on-load class).
func validateSecurityLogStreamPortsAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	check := func(path, raw string) error {
		if raw == "" {
			// No value token: the compiler keeps the default 514. The
			// missing-value case is the schema walker's concern, not this
			// range gate.
			return nil
		}
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 65535 {
			return nil
		}
		msg := fmt.Sprintf("%s: invalid syslog port %q (expected an integer in "+
			"[1..65535]; an invalid value silently keeps the default 514)", path, raw)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	for _, n := range nodes {
		if n.Name() != "security" {
			continue
		}
		secPath := joinNodePath(prefix, n.Keys)
		for _, logNode := range n.FindChildren("log") {
			logPath := joinNodePath(secPath, []string{"log"})
			for _, inst := range namedInstances(logNode.FindChildren("stream")) {
				streamPath := joinNodePath(logPath, []string{"stream", inst.name})
				// #9391: the same expansion the compile reader uses. If this
				// walk saw the UNexpanded children it would validate a
				// different set of statements than the one that gets compiled
				// — which is how a value can be both checked and dropped.
				for _, prop := range expandFlatRun(inst.node.Children, securityLogStreamSchema9391()) {
					switch prop.Name() {
					case "port":
						if err := check(joinNodePath(streamPath, []string{"port"}), nodeVal(prop)); err != nil {
							return warnings, err
						}
					case "host":
						for _, hc := range prop.Children {
							if hc.Name() == "port" {
								if err := check(joinNodePath(streamPath, []string{"host", "port"}), nodeVal(hc)); err != nil {
									return warnings, err
								}
							}
						}
					}
				}
			}
		}
	}
	return warnings, nil
}

// validateSecurityLogStreamTLSProfileAST is the #3350 commit-time gate for
// `security log stream <s> transport tls-profile <name>`. The token is parsed
// (schema_security.go), validated for syntax, and stored on
// stream.Transport.TLSProfile (compileLog) — but it is NEVER resolved into a
// *tls.Config at runtime: daemon_system.go applyLogStreams always passes a nil
// *tls.Config to logging.NewSyslogClientTransport, so the TLS dialer falls back
// to the system CA roots (pkg/logging/syslog.go dialTLS). There is also no
// `tls-profile` DEFINITION stanza anywhere in the config (no local-certificate /
// trusted-ca / SNI source for syslog — only IPsec/IKE define certs), so the
// named profile has nothing to resolve to. An operator who configures
// `tls-profile` believes mutual TLS / a pinned CA is in force when it is not —
// a secure-syslog posture silently downgraded to system roots (a fail-open).
//
// Because the profile can never be honored, this gate REJECTS any
// `transport tls-profile` at commit rather than letting it silently no-op.
// `transport protocol tls` ON ITS OWN is left intact: a TLS stream that trusts
// the system CA roots is a legitimate, fully-honored configuration — only the
// named-but-unapplied profile is rejected.
//
// It descends compileLog's traversal (log + namedInstances(stream) + the
// `transport` child loop) with forEachChild at EVERY container level so it
// gates the token wherever it lives, including a duplicate security/log
// sub-block (#3566, the sub-level sibling of the #3562 duplicate-top-level
// class). Runs on the group-expanded tree so an apply-groups-inherited
// tls-profile is covered.
//
// Strict path (commit / commit-check, lenient=false): a present tls-profile is
// a hard compile error. Lenient path (load / peer-sync, lenient=true):
// downgraded to a warning so an already-persisted or peer-synced config that an
// older binary accepted (and that silently used system roots) still boots
// (#1960 / #3261 fail-closed-on-load class). The runtime behavior is unchanged
// by the lenient downgrade — the profile was never applied either way — so a
// leniently-loaded value is inert, now flagged.
func validateSecurityLogStreamTLSProfileAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	// Descend security > log with forEachChild at EVERY level (and
	// namedInstances over every `stream`) so a tls-profile carried by a stream
	// in a duplicate security/log sub-block is still rejected (#3566); the inner
	// transport / tls-profile checks are unchanged.
	walkErr := forEachChild(nodes, "security", func(n *Node) error {
		secPath := joinNodePath(prefix, n.Keys)
		return forEachChild(n.Children, "log", func(logNode *Node) error {
			logPath := joinNodePath(secPath, []string{"log"})
			for _, inst := range namedInstances(logNode.FindChildren("stream")) {
				streamPath := joinNodePath(logPath, []string{"stream", inst.name})
				for _, prop := range inst.node.Children {
					if prop.Name() != "transport" {
						continue
					}
					// #6821: the SAME expansion the compiler reads. This check
					// was Children-only too, so `transport tls-profile X;`
					// slipped past the rejection that `transport { tls-profile
					// X; }` gets — and then the compiler dropped the value, so
					// the operator got neither the profile nor the error saying
					// it is unimplemented.
					for _, tc := range packedBodyChildren(prop, securityLogTransportSchema()) {
						if tc.Name() != "tls-profile" {
							continue
						}
						profile := nodeVal(tc)
						path := joinNodePath(streamPath, []string{"transport", "tls-profile"})
						msg := fmt.Sprintf("%s: tls-profile %q is not applied at runtime — "+
							"xpf has no TLS profile definition (certificate / trusted-ca / "+
							"SNI) to resolve it to, so the TLS syslog stream silently falls "+
							"back to the system CA roots instead of the named profile. Remove "+
							"the tls-profile (a `transport protocol tls` stream that trusts the "+
							"system CA roots is honored) until profile resolution is implemented",
							path, profile)
						if lenient {
							warnings = append(warnings, msg)
							continue
						}
						return fmt.Errorf("%s", msg)
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return warnings, walkErr
	}
	return warnings, nil
}
