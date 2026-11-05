// Package clusterfailover is the single, side-effect-free source of truth for
// the chassis-cluster failover command/action grammar. Before this package the
// grammar was parsed independently at three layers — the remote CLI
// (cmd/cli/request.go), the in-process CLI (pkg/cli/cli_request_chassis.go),
// and the gRPC loopback handler (pkg/grpcapi/server_diag_system_action.go) —
// plus a fourth, stricter parser for the fabric allowlist
// (pkg/grpcapi/server.go parseProxiedFailoverAction). The independent parsers
// disagreed about malformed input: a misspelled or truncated `node` selector
// (`redundancy-group 1 nod 0`, `redundancy-group 1 node`) or an empty gRPC
// node suffix (`cluster-failover:1:node`) silently DEGRADED to the broader,
// untargeted ManualFailover(rg) instead of failing before the side effect. On
// an HA router that moves redundancy-group ownership in an unintended
// direction (#5810, #5851).
//
// Every layer now routes through this package so a single typed operation and a
// single accept/reject verdict govern the privileged failover surface. The
// parser is pure (no cluster calls, no peer dials) so it can reject malformed
// input BEFORE any destructive side effect and be exhaustively unit-tested with
// shared token-vector tables (pkg/clusterfailover/grammarvectors).
//
// The grammar is closed: unknown, missing, duplicate, signed, whitespace-laden,
// or trailing tokens are rejected. There are exactly five forms:
//
//	plain RG failover     redundancy-group <rg>            cluster-failover:<rg>
//	targeted RG failover  redundancy-group <rg> node <n>   cluster-failover:<rg>:node<n>
//	data failover         data node <n>                    cluster-failover-data:node<n>
//	reset                 reset redundancy-group <rg>      cluster-failover-reset:<rg>
//	force primary         force-primary redundancy-group <rg> override unkeyed-recovery
//	                                                     cluster-failover-force-primary:<rg>
//
// where <rg> is a non-negative decimal group ID and <n> is a supported chassis
// node (0 or 1, see SupportedNode).
package clusterfailover

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Kind identifies which of the five cluster-failover operations a parsed
// grammar denotes.
type Kind int

const (
	// KindInvalid is the zero value; a parsed Op never carries it.
	KindInvalid Kind = iota
	// KindRGFailover is the plain, untargeted redundancy-group failover:
	// `redundancy-group <rg>` / `cluster-failover:<rg>`. It maps to
	// Manager.ManualFailover(rg) — it does not name a target node.
	KindRGFailover
	// KindRGFailoverNode is the targeted redundancy-group failover:
	// `redundancy-group <rg> node <n>` / `cluster-failover:<rg>:node<n>`.
	KindRGFailoverNode
	// KindDataFailover is the all-data-group failover to a node:
	// `data node <n>` / `cluster-failover-data:node<n>`.
	KindDataFailover
	// KindReset clears a forced failover: `reset redundancy-group <rg>` /
	// `cluster-failover-reset:<rg>`.
	KindReset
	// KindForcePrimary is the local-only recovery override:
	// `force-primary redundancy-group <rg> override unkeyed-recovery` /
	// `cluster-failover-force-primary:<rg>`.
	KindForcePrimary
)

// Op is a fully validated cluster-failover operation. It is produced only by
// ParseCommand / ParseAction (or the exported constructors) and therefore
// always carries a well-formed RG (>= 0) and, where applicable, a supported
// node (0 or 1).
type Op struct {
	Kind Kind
	// RG is the redundancy-group ID for KindRGFailover, KindRGFailoverNode,
	// KindReset, and KindForcePrimary. It is unused (0) for KindDataFailover.
	RG int
	// Node is the target chassis node for KindRGFailoverNode and
	// KindDataFailover. It is unused (0) for KindRGFailover, KindReset, and
	// KindForcePrimary.
	Node int
}

// RGFailover builds a plain, untargeted redundancy-group failover op.
func RGFailover(rg int) Op { return Op{Kind: KindRGFailover, RG: rg} }

// TargetedRGFailover builds a node-targeted redundancy-group failover op.
func TargetedRGFailover(rg, node int) Op {
	return Op{Kind: KindRGFailoverNode, RG: rg, Node: node}
}

// DataFailover builds an all-data-group failover op targeting a node.
func DataFailover(node int) Op { return Op{Kind: KindDataFailover, Node: node} }

// ResetFailover builds a failover-reset op for a redundancy group.
func ResetFailover(rg int) Op { return Op{Kind: KindReset, RG: rg} }

// ForcePrimary builds a local-only recovery override op for a redundancy group.
func ForcePrimary(rg int) Op { return Op{Kind: KindForcePrimary, RG: rg} }

// Targeted reports whether the op names an explicit target node — the two forms
// (targeted RG failover, data failover) a node legitimately proxies to its peer
// over the fabric link. The plain RG failover, reset, and force-primary forms
// are local-only and never proxied (the fabric allowlist denies them by policy).
func (o Op) Targeted() bool {
	return o.Kind == KindRGFailoverNode || o.Kind == KindDataFailover
}

// Action renders the op as the wire action string carried by
// pb.SystemActionRequest.Action. It is the inverse of ParseAction for every
// valid op. An Op with an unknown Kind renders "" (callers only format ops they
// obtained from a constructor or a successful parse).
func (o Op) Action() string {
	switch o.Kind {
	case KindRGFailover:
		return "cluster-failover:" + strconv.Itoa(o.RG)
	case KindRGFailoverNode:
		return "cluster-failover:" + strconv.Itoa(o.RG) + ":node" + strconv.Itoa(o.Node)
	case KindDataFailover:
		return "cluster-failover-data:node" + strconv.Itoa(o.Node)
	case KindReset:
		return "cluster-failover-reset:" + strconv.Itoa(o.RG)
	case KindForcePrimary:
		return "cluster-failover-force-primary:" + strconv.Itoa(o.RG)
	default:
		return ""
	}
}

// CommandUsage is the operator-facing usage string for the five command forms.
const CommandUsage = "usage: request chassis cluster failover " +
	"{redundancy-group <N> [node <N>] | data node <N> | reset redundancy-group <N> | " +
	"force-primary redundancy-group <N> override unkeyed-recovery}"

// SupportedNode reports whether n is a valid chassis failover target node.
// Cluster failover targets are limited to the two chassis nodes. This mirrors
// cluster.IsSupportedClusterNodeID; a parity test in pkg/grpcapi pins the two
// together so the grammar and the runtime range cannot drift.
func SupportedNode(n int) bool { return n == 0 || n == 1 }

// Action-string prefixes. These four are disjoint: "cluster-failover:" is
// followed by a ':' where the other three carry a '-'.
const (
	actionRGPrefix           = "cluster-failover:"
	actionDataPrefix         = "cluster-failover-data:"
	actionResetPrefix        = "cluster-failover-reset:"
	actionForcePrimaryPrefix = "cluster-failover-force-primary:"
)

// IsFailoverAction reports whether action belongs to the cluster-failover
// family (and therefore must be validated by ParseAction rather than treated as
// an unrelated system action). It intentionally uses broad family prefixes so a
// malformed member (e.g. "cluster-failover-data:bogus") is routed to ParseAction
// and rejected as an invalid failover action rather than a generic "unknown
// action".
func IsFailoverAction(action string) bool {
	return strings.HasPrefix(action, actionRGPrefix) ||
		strings.HasPrefix(action, actionDataPrefix) ||
		strings.HasPrefix(action, actionResetPrefix) ||
		strings.HasPrefix(action, actionForcePrimaryPrefix)
}

// ParseCommand parses the operator token vector that follows
// `request chassis cluster failover` (i.e. args with the leading verbs already
// consumed) into a typed Op. It is closed over the grammar: a misspelled
// selector, a missing/extra operand, a non-numeric or negative RG, or an
// unsupported node is rejected with a usage/validation error and no Op.
func ParseCommand(args []string) (Op, error) {
	if len(args) == 0 {
		return Op{}, errors.New(CommandUsage)
	}
	switch args[0] {
	case "force-primary":
		// Exactly: force-primary redundancy-group <rg> override unkeyed-recovery
		if len(args) != 5 || args[1] != "redundancy-group" ||
			args[3] != "override" || args[4] != "unkeyed-recovery" {
			return Op{}, errors.New(CommandUsage)
		}
		rg, err := parseRG(args[2])
		if err != nil {
			return Op{}, err
		}
		return Op{Kind: KindForcePrimary, RG: rg}, nil

	case "reset":
		// Exactly: reset redundancy-group <rg>
		if len(args) != 3 || args[1] != "redundancy-group" {
			return Op{}, errors.New("usage: request chassis cluster failover reset redundancy-group <N>")
		}
		rg, err := parseRG(args[2])
		if err != nil {
			return Op{}, err
		}
		return Op{Kind: KindReset, RG: rg}, nil

	case "data":
		// Exactly: data node <n>
		if len(args) != 3 || args[1] != "node" {
			return Op{}, errors.New("usage: request chassis cluster failover data node <N>")
		}
		node, err := parseNode(args[2])
		if err != nil {
			return Op{}, err
		}
		return Op{Kind: KindDataFailover, Node: node}, nil

	case "redundancy-group":
		// Either: redundancy-group <rg>            (plain)
		//     or: redundancy-group <rg> node <n>   (targeted)
		if len(args) < 2 {
			return Op{}, errors.New(CommandUsage)
		}
		rg, err := parseRG(args[1])
		if err != nil {
			return Op{}, err
		}
		if len(args) == 2 {
			return Op{Kind: KindRGFailover, RG: rg}, nil
		}
		// Anything past the RG must be exactly the `node <n>` selector — no
		// misspelling ("nod"), no missing value, no trailing operands. The
		// old loose gates dropped a malformed selector and degraded to the
		// untargeted plain failover (#5810).
		if len(args) != 4 || args[2] != "node" {
			return Op{}, errors.New(CommandUsage)
		}
		node, err := parseNode(args[3])
		if err != nil {
			return Op{}, err
		}
		return Op{Kind: KindRGFailoverNode, RG: rg, Node: node}, nil

	default:
		return Op{}, errors.New(CommandUsage)
	}
}

// ParseAction parses a wire action string (pb.SystemActionRequest.Action) of
// the cluster-failover family into a typed Op. It is the inverse of Op.Action
// and rejects — fail-closed — an empty node suffix ("cluster-failover:1:node"),
// a duplicate/trailing segment ("cluster-failover:1:node0:node1"), a signed or
// non-numeric RG/node, and any action outside the family.
func ParseAction(action string) (Op, error) {
	if rest, ok := strings.CutPrefix(action, actionForcePrimaryPrefix); ok {
		rg, err := parseRG(rest)
		if err != nil {
			return Op{}, err
		}
		return Op{Kind: KindForcePrimary, RG: rg}, nil
	}
	if rest, ok := strings.CutPrefix(action, actionResetPrefix); ok {
		rg, err := parseRG(rest)
		if err != nil {
			return Op{}, err
		}
		return Op{Kind: KindReset, RG: rg}, nil
	}
	if rest, ok := strings.CutPrefix(action, actionDataPrefix); ok {
		nodeStr, ok := strings.CutPrefix(rest, "node")
		if !ok {
			return Op{}, fmt.Errorf("invalid data failover action: %q", action)
		}
		node, err := parseNode(nodeStr)
		if err != nil {
			return Op{}, err
		}
		return Op{Kind: KindDataFailover, Node: node}, nil
	}
	if rest, ok := strings.CutPrefix(action, actionRGPrefix); ok {
		if idx := strings.Index(rest, ":node"); idx >= 0 {
			rg, err := parseRG(rest[:idx])
			if err != nil {
				return Op{}, err
			}
			node, err := parseNode(rest[idx+len(":node"):])
			if err != nil {
				return Op{}, err
			}
			return Op{Kind: KindRGFailoverNode, RG: rg, Node: node}, nil
		}
		rg, err := parseRG(rest)
		if err != nil {
			return Op{}, err
		}
		return Op{Kind: KindRGFailover, RG: rg}, nil
	}
	return Op{}, fmt.Errorf("unrecognized cluster-failover action: %q", action)
}

// parseRG parses a non-negative decimal redundancy-group ID. It rejects an
// empty string, a sign, whitespace, and any embedded non-digit (e.g. a ':node'
// that leaked into the RG segment), so the grammar cannot be widened by
// strconv.Atoi's tolerance of "+1" or its acceptance of a "-1" negative.
func parseRG(s string) (int, error) {
	if !isDigits(s) {
		return 0, fmt.Errorf("invalid redundancy-group ID: %q", s)
	}
	rg, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid redundancy-group ID: %q", s)
	}
	return rg, nil
}

// parseNode parses a chassis node ID and rejects anything outside the supported
// {0,1} range with the same message the handlers historically used.
func parseNode(s string) (int, error) {
	if !isDigits(s) {
		return 0, fmt.Errorf("invalid node ID: %q", s)
	}
	node, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid node ID: %q", s)
	}
	if !SupportedNode(node) {
		return 0, fmt.Errorf("unsupported cluster failover target node %d", node)
	}
	return node, nil
}

// isDigits reports whether s is a non-empty run of ASCII decimal digits. This
// is stricter than strconv.Atoi (no sign, no surrounding whitespace) so the
// closed grammar cannot admit "+1", "-1", " 1", or "1:node2".
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
