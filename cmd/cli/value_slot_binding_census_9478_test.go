package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
)

// #9478: a binding census for every operational VALUE SLOT the command tree
// offers, adjudicated against the remote CLI.
//
// #9065 was one ordering defect at several tokens: cmd/cli branched on a
// positional args[i] ladder before extracting selectors, so a value the tree
// offers as a completion could be dropped or mis-bound by the remote client.
// Fixing members one at a time re-opened the class at the next unhandled word.
// A node carrying DynamicFn or ContextDynamicFn is exactly such a slot: the tree
// offers the operator a set of names to type there.
//
// This gate records, for each slot, HOW the remote CLI binds it and WHERE. The
// declared set must EQUAL the discovered set, so a value slot added to the tree
// later reds this until someone reads the cmd/cli path and declares it, and a
// removed command reds it until its entry goes too.
//
// The entries are FACTS read at the site on origin/master 580d959e0, not risk
// verdicts. A lane's census cell stranded by #9065 (preserved under
// /var/tmp/xpf-preserved-untracked/9065-positional-ladder/) declared the same
// 44-slot set, but its dispositions were wrong for most exempt entries. It
// labelled keyword-bound selectors "local-only or forwarded verbatim", and it
// said the deterministic-NAT RPC "carries no selector" although
// GetNATDeterministicRequest.Pool is bound. That is why each entry below names
// its site.

type slotBinding string

const (
	// bindKeyword: the handler scans the argument vector for the keyword and
	// binds the value that follows it, wherever it appears.
	bindKeyword slotBinding = "keyword"
	// bindSharedParser: a parser shared with the local CLI or the gRPC handler
	// owns the grammar.
	bindSharedParser slotBinding = "shared parser"
	// bindModifierSplit: cmdtree.SplitModifiers/SplitModifiersAt separates the
	// selector from modifiers by the tree, position-independently.
	bindModifierSplit slotBinding = "tree modifier split"
	// bindFixedPosition: the value is read from a fixed index after literal
	// keywords. Correct for today's grammar; this is the shape #9065 was about
	// when a modifier can precede the value.
	bindFixedPosition slotBinding = "fixed position"
	// bindTextForwarded: the full argument string is forwarded to the daemon's
	// text renderer, which parses it.
	bindTextForwarded slotBinding = "forwarded to the daemon"
	// bindRejectedRemotely: the remote CLI refuses the command or the token
	// with an error; nothing is silently dropped.
	bindRejectedRemotely slotBinding = "refused by the remote CLI"
)

type slotAdjudication struct {
	binding slotBinding
	site    string
}

var valueSlotBindings = map[string]slotAdjudication{
	"clear security flow session interface":       {bindKeyword, "clear.go handleClearSecurity flow-session loop: req.Interface"},
	"clear security flow session source-nat-pool": {bindKeyword, "clear.go handleClearSecurity flow-session loop: req.SourceNatPool"},
	"clear security flow session zone":            {bindKeyword, "clear.go handleClearSecurity flow-session loop: req.Zone"},

	"monitor interface":                      {bindFixedPosition, "monitor.go handleMonitorInterface: req.InterfaceName = args[0] (after the `traffic` check)"},
	"monitor security flow filter interface": {bindRejectedRemotely, "monitor.go handleMonitorSecurity: `monitor security flow is only available on the local CLI`"},
	"monitor security packet-drop from-zone": {bindKeyword, "monitor.go handleMonitorSecurityPacketDrop selector loop"},
	"monitor security packet-drop interface": {bindKeyword, "monitor.go handleMonitorSecurityPacketDrop selector loop: req.Interface"},
	"monitor traffic interface":              {bindRejectedRemotely, "monitor.go handleMonitor: `monitor traffic is only available on the local CLI`"},

	"ping routing-instance":       {bindKeyword, "main.go handlePing option loop"},
	"traceroute routing-instance": {bindKeyword, "main.go handleTraceroute option loop"},

	"request chassis cluster data-plane userspace binding slot":       {bindSharedParser, "request.go handleRequestChassisClusterDataPlane: dpuserspace.ParseBindingCommand"},
	"request chassis cluster data-plane userspace inject-packet slot": {bindSharedParser, "request.go handleRequestChassisClusterDataPlane: dpuserspace.ParseInjectPacketCommand"},
	"request chassis cluster data-plane userspace queue":              {bindSharedParser, "request.go handleRequestChassisClusterDataPlane: dpuserspace.ParseQueueCommand"},
	"request chassis cluster failover data node":                      {bindSharedParser, "request.go handleRequestChassisClusterFailover: clusterfailover.ParseCommand"},
	"request chassis cluster failover redundancy-group":               {bindSharedParser, "request.go handleRequestChassisClusterFailover: clusterfailover.ParseCommand"},
	"request chassis cluster failover redundancy-group node":          {bindSharedParser, "request.go handleRequestChassisClusterFailover: clusterfailover.ParseCommand"},
	"request chassis cluster failover reset redundancy-group":         {bindSharedParser, "request.go handleRequestChassisClusterFailover: clusterfailover.ParseCommand"},
	"request dhcp renew": {bindFixedPosition, "request.go handleRequestDHCP: Target: args[1]"},

	"show class-of-service classifier":           {bindSharedParser, "show.go cosNameTypeTopic: cmdtree.ParseCoSNameTypeArgs"},
	"show class-of-service classifier name":      {bindSharedParser, "show.go cosNameTypeTopic: cmdtree.ParseCoSNameTypeArgs"},
	"show class-of-service rewrite-rule":         {bindSharedParser, "show.go cosNameTypeTopic: cmdtree.ParseCoSNameTypeArgs"},
	"show class-of-service rewrite-rule name":    {bindSharedParser, "show.go cosNameTypeTopic: cmdtree.ParseCoSNameTypeArgs"},
	"show class-of-service scheduler-map":        {bindFixedPosition, "show.go handleShow: topic += \":\" + args[2]"},
	"show firewall filter":                       {bindFixedPosition, "show.go handleShow: \"firewall-filter:\" + args[2]"},
	"show interfaces":                            {bindModifierSplit, "show_interfaces.go showInterfaces: cmdtree.SplitModifiersAt"},
	"show interfaces queue":                      {bindModifierSplit, "show_interfaces.go showInterfaces: cmdtree.SplitModifiersAt, topic interfaces-queue"},
	"show route instance":                        {bindFixedPosition, "show.go handleShow: showTextFiltered(\"route-instance\", args[2])"},
	"show route protocol":                        {bindFixedPosition, "show.go handleShow: \"route-protocol:\" + args[2]"},
	"show route table":                           {bindFixedPosition, "show.go handleShow: \"route-table:\" + args[2]"},
	"show security flow session source-nat-pool": {bindKeyword, "show_flow.go parseFlowSessionArgs: req.SourceNatPool"},
	"show security flow session zone":            {bindKeyword, "show_flow.go parseFlowSessionArgs zoneName, resolved by resolveSessionZone (#9065)"},
	"show security log zone":                     {bindTextForwarded, "show_security.go showEvents: full argument string to security-log (#3547)"},
	"show security nat source deterministic-nat internal-host <address> pool":          {bindFixedPosition, "show_nat.go natPoolArg: trailing `pool <name>` into GetNATDeterministicRequest.Pool"},
	"show security nat source deterministic-nat nat-ip <address> nat-port <port> pool": {bindFixedPosition, "show_nat.go natPoolArg: trailing `pool <name>` into GetNATDeterministicRequest.Pool"},
	"show security policies from-zone":                                                 {bindKeyword, "show_security.go handleShowSecurity policies: from-zone/to-zone pair extraction after validatePolicyZoneSelectors"},
	"show security policies from-zone to-zone":                                         {bindKeyword, "show_security.go handleShowSecurity policies: from-zone/to-zone pair extraction after validatePolicyZoneSelectors"},
	"show security policies from-zone to-zone policy":                                  {bindRejectedRemotely, "show_security.go validatePolicyZoneSelectors: `policy` is not an admitted filter token"},
	"show security screen ids-option":                                                  {bindFixedPosition, "show_security.go handleShowSecurity screen: args[2]"},
	"show security screen statistics zone":                                             {bindFixedPosition, "show_security.go handleShowSecurity screen statistics: args[3]"},
	"show security zones":                                                              {bindModifierSplit, "show_security.go handleShowSecurity zones: cmdtree.SplitModifiers (#9065)"},

	"test policy from-zone":         {bindSharedParser, "main.go testPolicy: policymatch.ParseSelectorArgs"},
	"test policy from-zone to-zone": {bindSharedParser, "main.go testPolicy: policymatch.ParseSelectorArgs"},
	"test routing instance":         {bindKeyword, "main.go testRouting loop"},
	"test security-zone interface":  {bindKeyword, "main.go testSecurityZone loop"},
}

// discoverValueSlots walks the operational tree and returns every path whose
// node offers dynamic completions.
func discoverValueSlots() []string {
	var paths []string
	var walk func(n *cmdtree.Node, prefix []string)
	walk = func(n *cmdtree.Node, prefix []string) {
		if n == nil {
			return
		}
		if n.DynamicFn != nil || n.ContextDynamicFn != nil {
			paths = append(paths, strings.Join(prefix, " "))
		}
		keys := make([]string, 0, len(n.Children))
		for k := range n.Children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(n.Children[k], append(append([]string{}, prefix...), k))
		}
	}
	roots := make([]string, 0, len(cmdtree.OperationalTree))
	for k := range cmdtree.OperationalTree {
		roots = append(roots, k)
	}
	sort.Strings(roots)
	for _, k := range roots {
		walk(cmdtree.OperationalTree[k], []string{k})
	}
	sort.Strings(paths)
	return paths
}

func TestEveryOperationalValueSlotHasARemoteBinding_9478(t *testing.T) {
	discovered := discoverValueSlots()
	// Fixture first: an empty discovery would make every check below vacuous.
	if len(discovered) == 0 {
		t.Fatal("discovered no value slots in the operational tree; the walk or the " +
			"DynamicFn predicate is broken, and a green verdict would assert nothing")
	}

	var undeclared []string
	for _, p := range discovered {
		if _, ok := valueSlotBindings[p]; !ok {
			undeclared = append(undeclared, p)
		}
	}
	if len(undeclared) > 0 {
		t.Errorf("%d operational value slot(s) have no recorded remote-CLI binding:\n  %s\n\n"+
			"Read the cmd/cli path for each and record how the value reaches the request "+
			"(keyword, shared parser, tree modifier split, fixed position, forwarded to the "+
			"daemon) or that the remote CLI refuses it. A value the tree offers and the "+
			"remote client silently drops is the #9065 class.",
			len(undeclared), strings.Join(undeclared, "\n  "))
	}

	inTree := make(map[string]bool, len(discovered))
	for _, p := range discovered {
		inTree[p] = true
	}
	var dead []string
	for p, adj := range valueSlotBindings {
		if !inTree[p] {
			dead = append(dead, p)
		}
		if adj.binding == "" || strings.TrimSpace(adj.site) == "" {
			t.Errorf("%q: an entry must name both its binding and the site it was read at", p)
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Errorf("%d recorded value slot(s) are no longer in the operational tree:\n  %s\n"+
			"Remove each in the same change that removed the command.",
			len(dead), strings.Join(dead, "\n  "))
	}
}
