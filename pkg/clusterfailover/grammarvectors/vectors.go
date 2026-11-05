// Package grammarvectors holds the shared accept/reject token-vector tables for
// the cluster-failover grammar. Every layer that parses the grammar — the
// clusterfailover package itself, the remote CLI (cmd/cli), the in-process CLI
// (pkg/cli), and the gRPC handler/fabric interceptor (pkg/grpcapi) — imports
// these tables in its tests so the accept/reject sets cannot drift apart again
// (#5810, #5851). It is an ordinary package that only test code references, so
// it is never linked into a production binary.
package grammarvectors

import "github.com/psaab/xpf/pkg/clusterfailover"

// CommandAccept is an operator token vector (args after `... failover`) that
// MUST parse, together with the typed op it yields and the wire action string
// the remote CLI emits for it.
type CommandAccept struct {
	Name   string
	Args   []string
	Op     clusterfailover.Op
	Action string
}

// CommandAccepts enumerates every well-formed command form.
var CommandAccepts = []CommandAccept{
	{"plain-rg", []string{"redundancy-group", "1"}, clusterfailover.RGFailover(1), "cluster-failover:1"},
	{"plain-rg-0", []string{"redundancy-group", "0"}, clusterfailover.RGFailover(0), "cluster-failover:0"},
	{"targeted-node0", []string{"redundancy-group", "1", "node", "0"}, clusterfailover.TargetedRGFailover(1, 0), "cluster-failover:1:node0"},
	{"targeted-node1", []string{"redundancy-group", "2", "node", "1"}, clusterfailover.TargetedRGFailover(2, 1), "cluster-failover:2:node1"},
	{"data-node0", []string{"data", "node", "0"}, clusterfailover.DataFailover(0), "cluster-failover-data:node0"},
	{"data-node1", []string{"data", "node", "1"}, clusterfailover.DataFailover(1), "cluster-failover-data:node1"},
	{"reset", []string{"reset", "redundancy-group", "3"}, clusterfailover.ResetFailover(3), "cluster-failover-reset:3"},
	{"force-primary", []string{"force-primary", "redundancy-group", "4", "override", "unkeyed-recovery"}, clusterfailover.ForcePrimary(4), "cluster-failover-force-primary:4"},
}

// CommandReject is a token vector that MUST be rejected before any side effect.
type CommandReject struct {
	Name string
	Args []string
}

// CommandRejects enumerates the malformed command forms that historically
// degraded to an untargeted failover or accepted trailing garbage.
var CommandRejects = []CommandReject{
	{"misspelled-selector", []string{"redundancy-group", "1", "nod", "0"}},
	{"missing-node-value", []string{"redundancy-group", "1", "node"}},
	{"unsupported-node", []string{"redundancy-group", "1", "node", "2"}},
	{"trailing-after-targeted", []string{"redundancy-group", "1", "node", "0", "extra"}},
	{"trailing-after-plain", []string{"redundancy-group", "1", "extra"}},
	{"duplicate-node-selector", []string{"redundancy-group", "1", "node", "0", "node", "1"}},
	{"negative-rg", []string{"redundancy-group", "-1"}},
	{"plus-signed-rg", []string{"redundancy-group", "+1"}},
	{"nonnumeric-rg", []string{"redundancy-group", "abc"}},
	{"reset-missing-rg", []string{"reset", "redundancy-group"}},
	{"reset-trailing", []string{"reset", "redundancy-group", "1", "extra"}},
	{"reset-wrong-keyword", []string{"reset", "rg", "1"}},
	{"reset-nonnumeric-rg", []string{"reset", "redundancy-group", "abc"}},
	{"data-missing-value", []string{"data", "node"}},
	{"data-unsupported-node", []string{"data", "node", "2"}},
	{"data-trailing", []string{"data", "node", "0", "extra"}},
	{"data-wrong-keyword", []string{"data", "nod", "0"}},
	{"force-primary-missing-rg", []string{"force-primary", "redundancy-group", "override", "unkeyed-recovery"}},
	{"force-primary-nonnumeric-rg", []string{"force-primary", "redundancy-group", "bad", "override", "unkeyed-recovery"}},
	{"force-primary-wrong-keyword", []string{"force-primary", "redundancy-group", "4", "unkeyed-recovery"}},
	{"force-primary-wrong-override", []string{"force-primary", "redundancy-group", "4", "overide", "unkeyed-recovery"}},
	{"force-primary-wrong-recovery-keyword", []string{"force-primary", "redundancy-group", "4", "override", "unkeyed"}},
	{"force-primary-trailing", []string{"force-primary", "redundancy-group", "4", "override", "unkeyed-recovery", "extra"}},
	{"unknown-verb", []string{"frobnicate"}},
	{"bare-node", []string{"node", "0"}},
	{"empty", []string{}},
}

// ActionAccept is a wire action string that MUST parse, with the typed op it
// yields.
type ActionAccept struct {
	Name   string
	Action string
	Op     clusterfailover.Op
}

// ActionAccepts enumerates every well-formed wire action form.
var ActionAccepts = []ActionAccept{
	{"plain-rg", "cluster-failover:1", clusterfailover.RGFailover(1)},
	{"plain-rg-0", "cluster-failover:0", clusterfailover.RGFailover(0)},
	{"targeted-1-0", "cluster-failover:1:node0", clusterfailover.TargetedRGFailover(1, 0)},
	{"targeted-2-1", "cluster-failover:2:node1", clusterfailover.TargetedRGFailover(2, 1)},
	{"data-0", "cluster-failover-data:node0", clusterfailover.DataFailover(0)},
	{"data-1", "cluster-failover-data:node1", clusterfailover.DataFailover(1)},
	{"reset", "cluster-failover-reset:1", clusterfailover.ResetFailover(1)},
	{"force-primary", "cluster-failover-force-primary:4", clusterfailover.ForcePrimary(4)},
}

// ActionRejects enumerates the malformed / out-of-range / non-family wire
// actions that MUST fail-closed before any cluster call or peer dial. The
// empty-node forms (`cluster-failover:1:node`, `cluster-failover-data:node`)
// are the specific #5851 fall-through.
var ActionRejects = []string{
	"cluster-failover:1:node",                // empty node suffix (#5851)
	"cluster-failover:1:node2",               // unsupported node
	"cluster-failover:1:node99",              // out-of-range node
	"cluster-failover:1:node0:node1",         // duplicate / trailing node segment
	"cluster-failover:1:nodeX",               // non-numeric node
	"cluster-failover:1:nod0",                // misspelled selector -> non-numeric RG segment
	"cluster-failover:garbage:node1",         // non-numeric RG
	"cluster-failover:-1",                    // negative RG
	"cluster-failover:+1",                    // signed RG
	"cluster-failover:1 ",                    // trailing whitespace
	"cluster-failover:",                      // empty RG
	"cluster-failover-data:node",             // empty node (#5851)
	"cluster-failover-data:node2",            // unsupported node
	"cluster-failover-data:nodeX",            // non-numeric node
	"cluster-failover-data:node0:x",          // trailing garbage after node
	"cluster-failover-data:bogus",            // malformed data suffix
	"cluster-failover-reset:",                // empty RG
	"cluster-failover-reset:1:extra",         // trailing garbage
	"cluster-failover-reset:-1",              // negative RG
	"cluster-failover-force-primary:",        // empty RG
	"cluster-failover-force-primary:-1",      // negative RG
	"cluster-failover-force-primary:+1",      // signed RG
	"cluster-failover-force-primary:bad",     // non-numeric RG
	"cluster-failover-force-primary:4 ",      // trailing whitespace
	"cluster-failover-force-primary:4:extra", // trailing garbage
}
