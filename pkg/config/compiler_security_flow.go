package config

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

// flowTraceFileNameError reports why an operator-supplied
// `security flow traceoptions file <name>` value is unsafe, or nil if the
// value is an acceptable bare basename. The persistent flow-trace file always
// lives directly under /var/log (NewTraceWriter), so only a bare filename is
// permitted: an absolute path, a path separator, or a "." / ".." component
// would let a committed config steer root-written flow telemetry (internal
// addresses, ports, zones, actions, policy IDs) outside the appliance log area
// — e.g. `file /tmp/x` is kept verbatim and `file ../../tmp/x` cleans to
// /tmp/x (#3420, Codex audit 097 H02). This is the persistent-config sibling
// of the interactive `monitor security flow file` hardening (#3378).
func flowTraceFileNameError(name string) error {
	if name == "" {
		// A missing value token is the schema walker's concern, not this gate.
		return nil
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%q is not a valid trace filename", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("trace filename %q must be a bare name, not a path "+
			"(the file is written under /var/log)", name)
	}
	if filepath.IsAbs(name) || name != filepath.Base(name) {
		return fmt.Errorf("trace filename %q must be a bare name, not a path "+
			"(the file is written under /var/log)", name)
	}
	return nil
}

// Flow-trace rotation bounds (#3424). The persistent `security flow
// traceoptions file <name> size <s> files <n>` knob was copied verbatim by the
// compiler with no range check, so a committed `size 1 files 1000000000` made
// every matching trace line exceed the threshold and turned each rotation into
// a ~1e9-iteration rename loop run synchronously from the event callback under
// the writer mutex (a per-event CPU storm). These bounds match the interactive
// `monitor security flow file` limits (pkg/cli/monitor.go) so the persistent
// and on-demand trace paths agree: a minimum size large enough that a normal
// burst of trace lines does not rotate on every write, a 1 GiB ceiling, and a
// small generation count whose rename loop is bounded. They are the single
// source of truth for both the commit-time gate (validateFlowTraceSizeFilesAST)
// and the runtime fail-safe clamp (logging.NewTraceWriter).
const (
	FlowTraceMinFileSize  = 10240      // bytes (10 KiB)
	FlowTraceMaxFileSize  = 1073741824 // bytes (1 GiB)
	FlowTraceMinFileCount = 2
	FlowTraceMaxFileCount = 1000
)

// validateFlowTraceFileAST is the #3420 commit-time path-traversal gate for
// `security flow traceoptions file <name>`. The compiler stores the filename
// verbatim (compileFlow traceoptions: to.File = nodeVal(fileNode)) and
// NewTraceWriter then joins/opens it under /var/log without rejecting an
// absolute path or a ".." escape, so a committed config can append flow trace
// records anywhere the daemon user can write. The filename is a single AST
// value the declarative SchemaValidate walker treats as opaque free text, so —
// like the syslog port and tls-profile gates — it is checked here on the
// group-expanded tree, descending compileFlow's traversal
// (flow > traceoptions > file) with forEachChild at EVERY level so an
// offending value in a duplicate flow/traceoptions/file sub-block is rejected
// (#3566, the sub-level sibling of the #3562 duplicate-top-level class).
//
// Strict path (commit / commit-check, lenient=false): an absolute,
// separator-bearing, or dot-component filename is a hard compile error.
// Lenient path (load / peer-sync, lenient=true): downgraded to a warning so an
// already-persisted or peer-synced config an older binary accepted still boots;
// NewTraceWriter independently refuses the unsafe path at runtime, so a
// leniently-loaded value simply disables tracing rather than writing outside
// /var/log (#1960 / #3261 fail-closed-on-load class).
func validateFlowTraceFileAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	// Descend security > flow > traceoptions > file with forEachChild at EVERY
	// level: the parser appends a repeated block as a sibling, and a first-only
	// FindChild at any level would let an offending `file` value hide in a
	// duplicate flow/traceoptions/file sub-block (#3566). The inner basename
	// check is unchanged.
	walkErr := forEachChild(nodes, "security", func(n *Node) error {
		secPath := joinNodePath(prefix, n.Keys)
		return forEachChild(n.Children, "flow", func(flowNode *Node) error {
			return forEachChild(flowNode.Children, "traceoptions", func(toNode *Node) error {
				return forEachChild(toNode.Children, "file", func(fileNode *Node) error {
					name := nodeVal(fileNode)
					if err := flowTraceFileNameError(name); err != nil {
						path := joinNodePath(secPath, []string{"flow", "traceoptions", "file"})
						msg := fmt.Sprintf("%s: %s", path, err.Error())
						if lenient {
							warnings = append(warnings, msg+
								" (ignored: tracing disabled, not written outside /var/log)")
							return nil
						}
						return fmt.Errorf("%s", msg)
					}
					return nil
				})
			})
		})
	})
	if walkErr != nil {
		return warnings, walkErr
	}
	return warnings, nil
}

// flowTraceImplementedFlags is the set of `security flow traceoptions flag`
// values the persistent trace writer actually honours
// (logging.TraceWriter.matchFlags recognizes exactly these two). Any other
// token is fail-silent at runtime: NewTraceWriter installs it into a non-empty
// flag map, which suppresses the basic-datapath/session defaults, and
// matchFlags then never matches — the daemon reports flow tracing enabled while
// the trace file stays empty (#3422 M02, false evidence during an incident).
// Keep in sync with logging.matchFlags / logging.traceFlagImplemented.
var flowTraceImplementedFlags = map[string]bool{
	"basic-datapath": true,
	"session":        true,
}

// validateFlowTraceFlagsAndFiltersAST is the #3422 commit-time gate for
// `security flow traceoptions { flag <name>; packet-filter <n> { source-prefix
// / destination-prefix <prefix>; } }`. The compiler copies both flag tokens
// (compileFlow: to.Flags = append(...)) and filter prefixes
// (pf.SourcePrefix/DestinationPrefix = nodeVal(...)) verbatim with no
// validation, and the runtime then fails silently in two directions:
//
//   - M01: NewTraceWriter drops a filter whose prefix does not parse, so a
//     config whose every filter is a typo (`source-prefix 10.0.0.999/32`)
//     leaves tw.filters empty and HandleEvent traces EVERYTHING — a filter
//     meant to narrow tracing broadens it.
//   - M02: an unknown flag (`flag sesson`) makes the flag map non-empty,
//     suppressing the defaults, so matchFlags never matches and nothing is
//     traced while the daemon reports tracing enabled.
//
// Both values are single AST leaves SchemaValidate treats as opaque free text,
// so — like the file gate above — they are checked here on the group-expanded
// tree, descending compileFlow's traversal (flow > traceoptions > flag /
// packet-filter children) with forEachChild at EVERY container level so an
// offending stanza in a duplicate flow/traceoptions sub-block is rejected
// (#3566).
//
// Strict path (commit / commit-check, lenient=false): an unparseable
// source/destination prefix or an unimplemented flag is a hard compile error.
// Lenient path (load / peer-sync, lenient=true): downgraded to a warning so an
// already-persisted or peer-synced config an older binary accepted still boots;
// the runtime fixes (NewTraceWriter marks an invalid filter match-none and
// drops an unknown flag so defaults still apply) keep a leniently-loaded value
// fail-safe rather than fail-open (#1960 / #3261 fail-closed-on-load class).
func validateFlowTraceFlagsAndFiltersAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	// Descend security > flow > traceoptions with forEachChild at EVERY level
	// so a flag / packet-filter stanza in a duplicate flow/traceoptions
	// sub-block is still checked (#3566); the inner flag and prefix checks are
	// unchanged.
	walkErr := forEachChild(nodes, "security", func(n *Node) error {
		secPath := joinNodePath(prefix, n.Keys)
		return forEachChild(n.Children, "flow", func(flowNode *Node) error {
			return forEachChild(flowNode.Children, "traceoptions", func(toNode *Node) error {
				toPath := joinNodePath(secPath, []string{"flow", "traceoptions"})

				// flag tokens
				//
				// #6659: read EVERY value, not just the first. `flag` is a
				// multi-value leaf, and reading it via nodeVal made this gate
				// fail OPEN: `flag [ basic-datapath totally-bogus ]` validated
				// only `basic-datapath` and committed clean, so an unknown flag
				// in any slot but the first was never rejected — while the same
				// one-sided read in the compiler silently dropped it. The two
				// halves of the contract have to walk the same value set.
				for _, flagNode := range toNode.FindChildren("flag") {
					for _, v := range firewallMatchValues(flagNode) {
						if v == "" || flowTraceImplementedFlags[v] {
							continue
						}
						path := joinNodePath(toPath, []string{"flag"})
						msg := fmt.Sprintf("%s: unknown flow trace flag %q "+
							"(supported: basic-datapath, session)", path, v)
						if lenient {
							warnings = append(warnings, msg+
								" (ignored: unknown flag dropped, defaults apply)")
							continue
						}
						return fmt.Errorf("%s", msg)
					}
				}

				// packet-filter source/destination prefixes
				for _, pf := range namedInstances(toNode.FindChildren("packet-filter")) {
					pfPath := joinNodePath(toPath, []string{"packet-filter", pf.name})
					for _, leaf := range []string{"source-prefix", "destination-prefix"} {
						pn := pf.node.FindChild(leaf)
						if pn == nil {
							// Absent prefix: a protocol-only filter is legitimate, so
							// leave it alone. This is AST-distinguishable from the
							// present-but-empty case below (node missing vs node
							// present with an empty value).
							continue
						}
						v := nodeVal(pn)
						if v == "" {
							// Present-but-empty (`source-prefix ""`): the node exists
							// but carries no prefix. Accepting it lets the runtime
							// append a fully-unconstrained filter (zero srcNet/dstNet,
							// no proto) that matches EVERY event — the #3422 M01
							// fail-open in a smaller costume. Reject at strict; downgrade
							// to a warning on the lenient load / peer-sync path, where
							// the compiler marks the filter InvalidPrefix and the
							// runtime fails it closed (match-none).
							path := joinNodePath(pfPath, []string{leaf})
							msg := fmt.Sprintf("%s: %s is present but empty; an empty "+
								"prefix would match every event (omit %s for a "+
								"protocol-only filter, or set a CIDR prefix)",
								path, leaf, leaf)
							if lenient {
								warnings = append(warnings, msg+
									" (ignored: filter set to match-none)")
								continue
							}
							return fmt.Errorf("%s", msg)
						}
						if _, err := netip.ParsePrefix(v); err != nil {
							path := joinNodePath(pfPath, []string{leaf})
							msg := fmt.Sprintf("%s: invalid %s %q: %v",
								path, leaf, v, err)
							if lenient {
								warnings = append(warnings, msg+
									" (ignored: filter set to match-none)")
								continue
							}
							return fmt.Errorf("%s", msg)
						}
					}
				}
				return nil
			})
		})
	})
	if walkErr != nil {
		return warnings, walkErr
	}
	return warnings, nil
}

// flowTraceSizeFilesValues extracts the configured `size` and `files` raw
// token strings (and whether each was present) from a
// `security flow traceoptions file <name>` node, across every AST shape the
// parser can produce:
//
//   - single-line hierarchical (`file foo size 100000 files 2;`, NewParser):
//     the tokens land directly in fileNode.Keys[2:].
//   - block hierarchical (`file foo { size 100000; files 2; }`): each token is
//     a separate child node (Keys=["size","100000"], Keys=["files","2"]).
//   - flat set (`set ... file foo size 100000 files 2`): the bracket/flat lexer
//     COLLAPSES the trailing tokens onto ONE child node's Keys
//     (Keys=["size","100000","files","2"]) — the #2419 multi-value-leaf shape.
//
// A single keyword scan over fileNode.Keys[2:] followed by every child node's
// full Keys covers all three: in each shape the `size`/`files` keyword is
// immediately followed by its value in the same Keys slice. The last
// occurrence wins (a child-node value overrides a same-named flat token),
// matching the original compileFlow ordering (children read after the flat
// Keys loop). This is the single source of truth shared by compileFlow (what
// the compiler stores) and validateFlowTraceSizeFilesAST (what the gate
// checks), so the two cannot diverge.
func flowTraceSizeFilesValues(fileNode *Node) (size string, sizeSet bool, files string, filesSet bool) {
	scan := func(keys []string, from int) {
		for i := from; i+1 < len(keys); i++ {
			switch keys[i] {
			case "size":
				size, sizeSet = keys[i+1], true
			case "files":
				files, filesSet = keys[i+1], true
			}
		}
	}
	scan(fileNode.Keys, 2)
	for _, child := range fileNode.Children {
		scan(child.Keys, 0)
	}
	return size, sizeSet, files, filesSet
}

// validateFlowTraceSizeFilesAST is the #3424 commit-time range gate for
// `security flow traceoptions file <name> size <s> files <n>`. The compiler
// (compileFlow) parsed both tokens with strconv.Atoi and stored any positive
// integer with no bounds, so a committed `size 1 files 1000000000` made every
// matching trace line exceed the rotation threshold and turned each rotation
// into a ~1e9-iteration rename loop run synchronously from the event callback
// under the writer mutex — a per-event CPU storm (codex-review-097 M03). Both
// tokens are single AST values SchemaValidate treats as opaque free text and
// live in EITHER the file node's flat Keys[2:] or hierarchical size/files
// children (a dual value-location SchemaValidate cannot express), so — like
// the file/flag/filter gates above — they are range-checked here on the
// group-expanded tree, descending flowTraceSizeFilesValues / compileFlow's
// traversal (flow > traceoptions > file) with forEachChild at EVERY level so a
// duplicate flow/traceoptions/file sub-block cannot hide an out-of-range value
// (#3566).
//
// The bounds (FlowTraceMin/MaxFileSize, FlowTraceMin/MaxFileCount) match the
// interactive `monitor security flow file` limits so the persistent and
// on-demand trace paths agree.
//
// Strict path (commit / commit-check, lenient=false): a non-integer or
// out-of-range size/files is a hard compile error. Lenient path (load /
// peer-sync, lenient=true): downgraded to a warning so an already-persisted or
// peer-synced config an older binary accepted still boots — NewTraceWriter
// clamps an out-of-range value to the same bounds at runtime, so a
// leniently-loaded value cannot trigger the CPU storm (#1960 / #3261
// fail-closed-on-load class).
func validateFlowTraceSizeFilesAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	// Descend security > flow > traceoptions > file with forEachChild at EVERY
	// level so an out-of-range size/files in a duplicate flow/traceoptions/file
	// sub-block is range-checked (#3566); the inner bounds checks are unchanged.
	walkErr := forEachChild(nodes, "security", func(n *Node) error {
		secPath := joinNodePath(prefix, n.Keys)
		return forEachChild(n.Children, "flow", func(flowNode *Node) error {
			return forEachChild(flowNode.Children, "traceoptions", func(toNode *Node) error {
				return forEachChild(toNode.Children, "file", func(fileNode *Node) error {
					filePath := joinNodePath(secPath, []string{"flow", "traceoptions", "file"})

					size, sizeSet, files, filesSet := flowTraceSizeFilesValues(fileNode)

					if sizeSet {
						v, err := strconv.ParseInt(size, 10, 64)
						if err != nil || v < FlowTraceMinFileSize || v > FlowTraceMaxFileSize {
							path := joinNodePath(filePath, []string{"size"})
							msg := fmt.Sprintf("%s: invalid trace file size %q "+
								"(must be %d..%d bytes)",
								path, size, FlowTraceMinFileSize, FlowTraceMaxFileSize)
							if lenient {
								warnings = append(warnings, msg+
									" (ignored: clamped to a safe size at runtime)")
							} else {
								return fmt.Errorf("%s", msg)
							}
						}
					}
					if filesSet {
						v, err := strconv.Atoi(files)
						if err != nil || v < FlowTraceMinFileCount || v > FlowTraceMaxFileCount {
							path := joinNodePath(filePath, []string{"files"})
							msg := fmt.Sprintf("%s: invalid trace file count %q "+
								"(must be %d..%d)",
								path, files, FlowTraceMinFileCount, FlowTraceMaxFileCount)
							if lenient {
								warnings = append(warnings, msg+
									" (ignored: clamped to a safe count at runtime)")
							} else {
								return fmt.Errorf("%s", msg)
							}
						}
					}
					return nil
				})
			})
		})
	})
	if walkErr != nil {
		return warnings, walkErr
	}
	return warnings, nil
}

// tcpMSSKinds are the four tcp-mss sub-kinds the compiler reads
// (compileFlow MSS switch). Each carries a u16 MSS value that lands in a
// Rust u16 wire field (TCPMSS{IPsecVPN,GreIn,GreOut}; all-tcp fans out into
// all three) via buildFlowSnapshot (Layer A coerceWireU16, #1977).
var tcpMSSKinds = []string{"ipsec-vpn", "gre-in", "gre-out", "all-tcp"}

// validateTCPMSSRanges is the #1979 Layer-B Tier-3 commit-time range gate
// for `security flow tcp-mss {ipsec-vpn|gre-in|gre-out|all-tcp} <n>`. It is
// the compiler AST pre-walk counterpart of validateVRRPTrackInterfaceAST:
// tcp-mss's MSS value can live in EITHER the kind node's own flat Keys[1]
// (`gre-in 1400`) OR a hierarchical `mss` sub-child (`gre-in { mss 1360; }`),
// a dual value-location the declarative schema walker (SchemaValidate)
// cannot express — so tcp-mss stays OPAQUE in setSchema and is validated
// here instead.
//
// It range-checks the COMPILER-SELECTED token (selectMSSToken, shared with
// parseMSSValue) against [0, 65535] — the same Layer-A bound (coerceWireU16
// out-of-range -> 0). Validating only the selected value means a mixed shape
// like `gre-in 70000 { mss 1360; }` PASSES (the compiler selects the child
// 1360; the flat 70000 is discarded), exactly matching what compileFlow
// reads.
//
// Strict path (commit / commit-check, lenient=false): an out-of-range or
// non-integer selected value is a hard compile error. Lenient path (load /
// peer-sync, lenient=true): it is downgraded to a warning and Layer A coerces
// it — a legacy persisted/peer config carrying `tcp-mss gre-in 70000` (a
// value an older binary accepted) must still boot, exactly like the VRRP
// lenient gate. Runs on the group-expanded tree so apply-groups-inherited
// MSS values are covered.
// tcpMSSOptionNodes returns the per-kind option nodes under a `tcp-mss` node,
// in EITHER AST shape (#6564).
//
// A `;`-terminated statement is packed onto ONE node with no children, so the
// four spellings differ structurally:
//
//	flow { tcp-mss { all-tcp { mss 1350; } } }  -> tcp-mss > all-tcp > [mss 1350]
//	flow { tcp-mss { all-tcp mss 1350; } }      -> tcp-mss > [all-tcp mss 1350]
//	flow { tcp-mss all-tcp 1350; }              -> ONE leaf [tcp-mss all-tcp 1350]
//	set security flow tcp-mss all-tcp 1350      -> tcp-mss > [all-tcp 1350]
//
// The compiler and validateTCPMSSRanges both walked mssNode.Children, so the
// fully-packed leaf presented an EMPTY slice: the range validator iterated
// nothing and passed VACUOUSLY while the compiler assigned nothing. MSS
// clamping silently did not happen on a config that committed clean.
//
// The packed leaf's trailing keys are surfaced as a synthetic option node so
// BOTH readers see the same thing — one source of truth for the shape, rather
// than two loops that would drift. The synthetic node carries the tokens
// VERBATIM: `tcp-mss all-tcp mss 1350` yields Keys=["all-tcp","mss","1350"].
//
// #8824 CORRECTED WHAT HAPPENS NEXT. This comment used to say that spelling
// "inherits the SAME rejection the half-packed form already gives ... because
// `mss` is the hierarchical keyword and is a typo when inline". That reasoning
// does not hold: flat set IS hierarchical keywords written inline, which is
// what CLAUDE.md's dual-AST rule says, and xpf accepts the braced
// `all-tcp { mss 1350; }` — so it has to accept the flattening of it.
// selectMSSToken now consumes the exact keyword `mss` followed by a token.
//
// A genuine typo is still refused, and that is the distinction the old
// reasoning conflated with this one: `all-tcp msss 1350` selects "msss" and
// fails, and `all-tcp mss` with no value selects "mss" and fails. Only the
// exact keyword plus a value is consumed.
func tcpMSSOptionNodes(mssNode *Node) []*Node {
	out := mssNode.Children
	if len(mssNode.Keys) > 1 {
		out = append(append([]*Node{}, out...), &Node{Keys: mssNode.Keys[1:], IsLeaf: true})
	}
	return out
}

func validateTCPMSSRanges(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		nodePath := joinNodePath(prefix, n.Keys)
		if n.Name() == "security" {
			for _, flow := range n.FindChildren("flow") {
				flowPath := joinNodePath(nodePath, []string{"flow"})
				for _, mss := range flow.FindChildren("tcp-mss") {
					mssPath := joinNodePath(flowPath, []string{"tcp-mss"})
					opts := tcpMSSOptionNodes(mss)
					for _, kind := range tcpMSSKinds {
						for _, kn := range opts {
							if kn.Name() != kind {
								continue
							}
							kindPath := joinNodePath(mssPath, []string{kind})
							// #2486: `tcp-mss ipsec-vpn` is rejected at
							// commit. There is no IPsec context in the
							// userspace forward-build path — ESP/AH/IKE is
							// local-delivered to the kernel XFRM stack and the
							// decrypted inner packets re-enter as plain
							// traffic with no IPsec marker — so the clamp can
							// never be enforced. Carrying it silently as dead
							// config (the prior behavior) is worse than
							// rejecting it. Strict (commit/commit-check) is a
							// hard error; lenient (load/peer-sync) downgrades
							// to a warning so a legacy persisted/peer config
							// still boots.
							if kind == "ipsec-vpn" {
								if _, ok := selectMSSToken(kn); ok {
									msg := fmt.Sprintf("%s: tcp-mss ipsec-vpn is not "+
										"supported in the userspace forwarding path "+
										"(IPsec is processed by the kernel XFRM stack, "+
										"so no IPsec context reaches the MSS clamp); "+
										"use 'all-tcp' to clamp all forwarded TCP", kindPath)
									if !lenient {
										return nil, fmt.Errorf("%s", msg)
									}
									warnings = append(warnings, msg+
										" (ignored: clamp not enforced)")
								}
								continue
							}
							w, err := checkTCPMSSKind(kn, kindPath, lenient)
							warnings = append(warnings, w...)
							if err != nil {
								return nil, err
							}
						}
					}
				}
			}
		}
		w, err := validateTCPMSSRanges(n.Children, nodePath, lenient)
		warnings = append(warnings, w...)
		if err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// checkTCPMSSKind range-checks one tcp-mss kind node's compiler-selected MSS
// value. See validateTCPMSSRanges.
func checkTCPMSSKind(node *Node, nodePath string, lenient bool) ([]string, error) {
	tok, ok := selectMSSToken(node)
	if !ok {
		// No value token in either position — the compiler reads 0 (the
		// "unset" sentinel). Not a range violation; leave it.
		return nil, nil
	}
	if err := ValidateInteger(0, maxWireU16)(tok, nil); err != nil {
		msg := fmt.Sprintf("%s: invalid tcp-mss value: %v", nodePath, err)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		// Tailor the lenient suffix to the failure kind (Codex/Copilot
		// review). Only a parseable POSITIVE-but-too-large integer reaches
		// Layer A to be clamped (flow.go coerceWireU16) — compileFlow only
		// assigns the MSS when v > 0. A non-integer token OR a negative
		// value yields no MSS: the compiler reads 0 (unset), nothing
		// reaches the dataplane, so "the dataplane coerces it" would
		// mislead. Branch on the parsed value, not just parseability.
		suffix := " (kept; the dataplane coerces it — a strict commit would reject this)"
		if v, perr := strconv.Atoi(tok); perr != nil || v < 0 {
			suffix = " (treated as unset/0 by the compiler — a strict commit would reject this)"
		}
		return []string{msg + suffix}, nil
	}
	return nil, nil
}

func compileFlow(node *Node, sec *SecurityConfig) error {
	// #8939: SPLIT A PACKED RUN BEFORE ANY LOOKUP. This function asks
	// node.FindChild(...) once per flag, and `set security flow
	// allow-dns-reply allow-embedded-icmp force-ip-reassembly` is ONE child
	// node carrying all three on its Keys — so the FIRST flag matched and every
	// other lookup missed:
	//
	//	packed  AllowDNSReply=true  AllowEmbeddedICMP=false  ForceIPReassembly=false
	//	split   AllowDNSReply=true  AllowEmbeddedICMP=true   ForceIPReassembly=true
	//
	// `force-ip-reassembly` is the one that matters most: without it fragments
	// are not reassembled before inspection, which is a classic evasion path —
	// so the packed spelling silently removed a control the operator enabled.
	//
	// Expanded ONCE here rather than at each of ~20 lookups: a per-lookup fix
	// would be twenty chances to miss one, and the next flag added would be the
	// twenty-first.
	if expanded := expandFlatRun(node.Children, securityFlowSchema8939()); len(expanded) != len(node.Children) {
		clone := *node
		clone.Children = expanded
		node = &clone
	}

	// Aggressive session aging
	if agingNode := node.FindChild("aging"); agingNode != nil {
		// #9235: the `security flow` expansion above covers `flow`'s OWN
		// children; `aging`'s are a separate container and were never expanded,
		// so `aging early-ageout 10 high-watermark 80 low-watermark 60` set
		// early-ageout and left both watermarks at 0 (aggressive aging disabled).
		// Lenient path only.
		for _, opt := range expandRunChildren9235(agingNode.Children, flowAgingSchema9235()) {
			name := opt.Name()
			switch name {
			case "early-ageout", "high-watermark", "low-watermark":
			default:
				// #3440 H2: record an unrecognized aging leaf so
				// validateFlowAgingStrict can reject it at commit instead of
				// the pre-#3440 silent drop (which let `set security flow
				// aging bogus 5` commit cleanly with no effect).
				sec.Flow.AgingUnknownLeaves = append(sec.Flow.AgingUnknownLeaves, name)
				continue
			}
			if len(opt.Keys) < 2 {
				continue
			}
			val, err := strconv.Atoi(opt.Keys[1])
			if err != nil {
				// The schema typed-leaf gate (SchemaValidate) rejects a
				// non-integer / out-of-range value at commit; on the tolerant
				// load path it is left at the zero default (disabled).
				continue
			}
			switch name {
			case "early-ageout":
				sec.Flow.AgingEarlyAgeout = val
			case "high-watermark":
				sec.Flow.AgingHighWatermark = val
			case "low-watermark":
				sec.Flow.AgingLowWatermark = val
			}
		}
	}

	tcpNode := node.FindChild("tcp-session")
	if tcpNode != nil {
		sec.Flow.TCPSession = &TCPSessionConfig{}
		// #8939: a flat `set` command naming several tcp-session leaves is ONE
		// command, and SetPath nests them rather than making them siblings, so
		// this loop saw the first and nothing else. Measured: `closing-timeout
		// 10 established-timeout 20 initial-timeout 30` compiled to
		// closing=10 established=0 initial=0.
		//
		// `initial-timeout` is the sharp one (#8971): a dropped value turns the
		// half-open window from its configured bound back to the default, and a
		// large configured value exists precisely to pin sessions the operator
		// wants held -- so losing it is a resource-exhaustion surface rather
		// than a cosmetic loss.
		for _, opt := range expandFlatRun(tcpNode.Children, flowTCPSessionSchema8939()) {
			// Handle leaf flags (no value)
			switch opt.Name() {
			case "no-syn-check":
				sec.Flow.TCPSession.NoSynCheck = true
				continue
			case "no-syn-check-in-tunnel":
				sec.Flow.TCPSession.NoSynCheckInTunnel = true
				continue
			case "rst-invalidate-session":
				sec.Flow.TCPSession.RstInvalidateSession = true
				continue
			case "no-sequence-check":
				sec.Flow.TCPSession.NoSequenceCheck = true
				continue
			case "strict-syn-check":
				// #8296: accepted-only, and now ADVISED as such. Reading it
				// here is what lets validateAcceptedOnlyWarnings see it.
				sec.Flow.TCPSession.StrictSynCheck = true
				continue
			}
			if len(opt.Keys) < 2 {
				continue
			}
			val, err := strconv.Atoi(opt.Keys[1])
			if err != nil {
				continue
			}
			switch opt.Name() {
			case "established-timeout":
				sec.Flow.TCPSession.EstablishedTimeout = val
			case "initial-timeout":
				sec.Flow.TCPSession.InitialTimeout = val
			case "closing-timeout":
				sec.Flow.TCPSession.ClosingTimeout = val
			case "time-wait-timeout":
				sec.Flow.TCPSession.TimeWaitTimeout = val
			}
		}
	}

	udpNode := node.FindChild("udp-session")
	if udpNode != nil {
		for _, opt := range udpNode.Children {
			if opt.Name() == "timeout" && len(opt.Keys) >= 2 {
				if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
					sec.Flow.UDPSessionTimeout = v
				}
			}
		}
	}

	icmpNode := node.FindChild("icmp-session")
	if icmpNode != nil {
		for _, opt := range icmpNode.Children {
			if opt.Name() == "timeout" && len(opt.Keys) >= 2 {
				if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
					sec.Flow.ICMPSessionTimeout = v
				}
			}
		}
	}

	// TCP MSS clamping
	mssNode := node.FindChild("tcp-mss")
	if mssNode != nil {
		for _, opt := range tcpMSSOptionNodes(mssNode) {
			switch opt.Name() {
			case "ipsec-vpn":
				// #2486: strict commit rejects this via
				// validateTCPMSSRanges (no IPsec context in the userspace
				// forward path). In lenient load/peer-sync contexts the
				// value IS retained on the typed config below, so `show`
				// output and config round-trip preserve it — but it is
				// NEVER serialized to the dataplane wire (flow.go drops it)
				// and NEVER enforced (no dataplane consumer reads it).
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSIPsecVPN = v
				}
			case "gre-in":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSGreIn = v
				}
			case "gre-out":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSGreOut = v
				}
			case "all-tcp":
				// #2486: all-tcp is the context-agnostic clamp — it lands in
				// its own wire field (tcp_mss_all_tcp) and the dataplane
				// applies it to every forwarded TCP SYN (plain + the fallback
				// for gre-in / tunnel egress). Previously it fanned out into
				// IPsecVPN/GreIn/GreOut, but only gre-out was ever enforced,
				// so all-tcp silently behaved as gre-out-only.
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSAllTCP = v
				}
			}
		}
	}

	// allow-dns-reply
	if node.FindChild("allow-dns-reply") != nil {
		sec.Flow.AllowDNSReply = true
	}

	// allow-embedded-icmp
	if node.FindChild("allow-embedded-icmp") != nil {
		sec.Flow.AllowEmbeddedICMP = true
	}

	// gre-performance-acceleration
	if node.FindChild("gre-performance-acceleration") != nil {
		sec.Flow.GREPerformanceAcceleration = true
	}

	// power-mode-disable
	if node.FindChild("power-mode-disable") != nil {
		sec.Flow.PowerModeDisable = true
	}

	// #4231 (fable-167 P-3): five accepted-only knobs. Record presence so
	// validateSecurityFlowAcceptedOnly (compiler_validate_warn.go) can emit
	// the #2078-style advisory. A non-integer value on the two duration knobs
	// is rejected at strict commit by the schema typed-leaf validator; on the
	// tolerant load path it is left at 0 (treated as unset). None of these
	// reach the dataplane wire — they capture operator intent only.
	if n := node.FindChild("route-change-timeout"); n != nil {
		if len(n.Keys) >= 2 {
			if v, err := strconv.Atoi(n.Keys[1]); err == nil {
				sec.Flow.RouteChangeTimeout = v
			}
		}
	}
	if node.FindChild("sync-icmp-session") != nil {
		sec.Flow.SyncICMPSession = true
	}
	if node.FindChild("force-ip-reassembly") != nil {
		sec.Flow.ForceIPReassembly = true
	}
	if n := node.FindChild("multicast-session-lifetime"); n != nil {
		if len(n.Keys) >= 2 {
			if v, err := strconv.Atoi(n.Keys[1]); err == nil {
				sec.Flow.MulticastSessionLifetime = v
			}
		}
	}
	if node.FindChild("preserve-incoming-fragment-size") != nil {
		sec.Flow.PreserveIncomingFragmentSize = true
	}

	// syn-flood-protection-mode
	if spNode := node.FindChild("syn-flood-protection-mode"); spNode != nil {
		if len(spNode.Keys) >= 2 {
			sec.Flow.SynFloodProtectionMode = spNode.Keys[1]
		}
	}

	// traceoptions
	if toNode := node.FindChild("traceoptions"); toNode != nil {
		to := &FlowTraceoptions{}
		if fileNode := toNode.FindChild("file"); fileNode != nil {
			to.File = nodeVal(fileNode)
			// Read size/files across every AST shape (single-line hierarchical,
			// block hierarchical, and the #2419 flat-set collapsed child). The
			// shared helper is the SSOT with validateFlowTraceSizeFilesAST so the
			// gate checks exactly what is stored here. A non-integer value is left
			// at zero (default applied downstream); the strict commit gate rejects
			// it loudly before reaching here (#3424).
			sizeStr, sizeSet, filesStr, filesSet := flowTraceSizeFilesValues(fileNode)
			if sizeSet {
				if n, err := strconv.Atoi(sizeStr); err == nil {
					to.FileSize = n
				}
			}
			if filesSet {
				if n, err := strconv.Atoi(filesStr); err == nil {
					to.FileCount = n
				}
			}
		}
		for _, flagNode := range toNode.FindChildren("flag") {
			// #6659: `flag` is a multi-value leaf — `flag [ basic-datapath
			// session ]` collapses onto Keys[1:] and `flag { basic-datapath;
			// session; }` onto Children. nodeVal read only the FIRST value, so
			// every flag after the first was silently dropped and the operator
			// debugging a live problem got less tracing than they asked for
			// with no diagnostic. Worse, the strict validator below
			// (validateFlowTraceFlagsAndFiltersAST) read the same one side, so an
			// UNKNOWN flag in any slot but the first committed CLEAN — a
			// validation fail-open. firewallMatchValues accumulates both sides.
			to.Flags = append(to.Flags, firewallMatchValues(flagNode)...)
		}
		for _, pfInst := range namedInstances(toNode.FindChildren("packet-filter")) {
			// #9792: expand a lenient-path packed run (#9235) so every leaf below is
			// read from the expanded body, not only the head of the chain.
			pfNode := expandResolvingRun9792(pfInst.node, packetFilterSchema9792())
			pf := &TracePacketFilter{Name: pfInst.name}
			// A prefix node that is PRESENT but empty (`source-prefix ""`) is
			// malformed: an empty prefix is not "no constraint" but a typo that
			// must narrow tracing to nothing, not broaden it to everything
			// (#3422 M01). Record the distinction here (present-but-empty vs the
			// absent protocol-only case) so the runtime can fail it closed; the
			// strict commit gate rejects it outright before it ever lands here.
			if spNode := pfNode.FindChild("source-prefix"); spNode != nil {
				pf.SourcePrefix = nodeVal(spNode)
				if pf.SourcePrefix == "" {
					pf.InvalidPrefix = true
				}
			}
			if dpNode := pfNode.FindChild("destination-prefix"); dpNode != nil {
				pf.DestinationPrefix = nodeVal(dpNode)
				if pf.DestinationPrefix == "" {
					pf.InvalidPrefix = true
				}
			}
			if protoNode := pfNode.FindChild("protocol"); protoNode != nil {
				pf.Protocol = nodeVal(protoNode)
			}
			to.PacketFilters = append(to.PacketFilters, pf)
		}
		sec.Flow.Traceoptions = to
	}

	return nil
}

// flowTCPSessionSchema8939 resolves the `security flow tcp-session` leaf set so
// expandFlatRun can tell one of its leaves from a value token.
func flowTCPSessionSchema8939() *schemaNode {
	sec := resolveSchemaChild(setSchema, "security")
	flow := resolveSchemaChild(sec, "flow")
	return resolveSchemaChild(flow, "tcp-session")
}
