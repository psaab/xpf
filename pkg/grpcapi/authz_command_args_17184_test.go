package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// #17184: rpcArgumentForms fell back to the bare charge for every RPC
// not in its hand-enumerated switch, with no census. Four RPCs with
// operator-typed arguments escaped argument-scoped denies
// (GetNATDeterministic, ClearDHCPClientIdentifier, MonitorPacketDrop,
// GetNATRuleStats), and the #16378 fold had already caught five more
// in the same default. The fix removes the default (unlisted =>
// return nil, false), adds arms for the four, names every other
// method in methodsWithoutArgumentForms with a reason, and pins the
// whole decision with the census below.
//
// FAIL-ON-REVERT: restoring `return chargeForms16472(base), true` as
// the default makes every wantDeny cell ALLOWED again and fails the
// census's switch/map agreement arm (GetZonePairSummary's explicit
// bare-charge arm would be indistinguishable from a fallback).

func TestArgumentFormsFourRPCs17184(t *testing.T) {
	fwd := pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD
	rev := pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_REVERSE
	for _, tc := range []struct {
		name, pattern, method string
		req                   any
		wantDeny              bool
	}{
		{"deterministic forward host denied", `^show security nat source deterministic-nat internal-host 10\.0\.0\.5`, "GetNATDeterministic", &pb.GetNATDeterministicRequest{Direction: fwd, InternalHost: "10.0.0.5"}, true},
		{"deterministic forward other allowed", `^show security nat source deterministic-nat internal-host 10\.0\.0\.5`, "GetNATDeterministic", &pb.GetNATDeterministicRequest{Direction: fwd, InternalHost: "10.0.0.6"}, false},
		{"deterministic forward pool denied", `^show security nat source deterministic-nat internal-host 10\.0\.0\.5 pool p1$`, "GetNATDeterministic", &pb.GetNATDeterministicRequest{Direction: fwd, InternalHost: "10.0.0.5", Pool: "p1"}, true},
		{"deterministic unanchored host denied", `internal-host 10\.0\.0\.5`, "GetNATDeterministic", &pb.GetNATDeterministicRequest{Direction: fwd, InternalHost: "10.0.0.5"}, true},
		{"deterministic reverse denied", `^show security nat source deterministic-nat nat-ip 192\.0\.2\.1 nat-port 1234$`, "GetNATDeterministic", &pb.GetNATDeterministicRequest{Direction: rev, NatIp: "192.0.2.1", NatPort: 1234}, true},
		{"deterministic bare charge still denied", `^show security nat source deterministic-nat$`, "GetNATDeterministic", &pb.GetNATDeterministicRequest{Direction: fwd, InternalHost: "10.0.0.5"}, true},
		{"clear dhcp interface denied", `^clear dhcp client-identifier interface ge-0/0/1$`, "ClearDHCPClientIdentifier", &pb.ClearDHCPClientIdentifierRequest{Interface: "ge-0/0/1"}, true},
		{"clear dhcp other allowed", `^clear dhcp client-identifier interface ge-0/0/1$`, "ClearDHCPClientIdentifier", &pb.ClearDHCPClientIdentifierRequest{Interface: "ge-0/0/2"}, false},
		{"clear dhcp unanchored denied", `ge-0/0/1`, "ClearDHCPClientIdentifier", &pb.ClearDHCPClientIdentifierRequest{Interface: "ge-0/0/1"}, true},
		{"clear dhcp bare denied", `^clear dhcp client-identifier$`, "ClearDHCPClientIdentifier", &pb.ClearDHCPClientIdentifierRequest{}, true},
		{"clear dhcp interface under bare deny", `^clear dhcp client-identifier$`, "ClearDHCPClientIdentifier", &pb.ClearDHCPClientIdentifierRequest{Interface: "ge-0/0/1"}, true},
		{"packet-drop prefix denied", `^monitor security packet-drop source-prefix 10\.`, "MonitorPacketDrop", &pb.MonitorPacketDropRequest{SourcePrefix: "10.0.0.0/8"}, true},
		{"packet-drop other allowed", `^monitor security packet-drop source-prefix 10\.`, "MonitorPacketDrop", &pb.MonitorPacketDropRequest{SourcePrefix: "192.0.2.0/24"}, false},
		{"packet-drop combined denied", `^monitor security packet-drop interface ge-0/0/1 count 5$`, "MonitorPacketDrop", &pb.MonitorPacketDropRequest{Interface: "ge-0/0/1", Count: 5}, true},
		{"packet-drop unfiltered allowed", `^monitor security packet-drop source-prefix 10\.`, "MonitorPacketDrop", &pb.MonitorPacketDropRequest{}, false},
		{"nat rule-set source denied", `^show security nat source rule-set rs1`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{RuleSet: "rs1"}, true},
		{"nat rule-set other allowed", `^show security nat source rule-set rs1`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{RuleSet: "rs2"}, false},
		{"nat rule-set unanchored denied", `rs1`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{RuleSet: "rs1"}, true},
		{"nat rule-set destination denied", `^show security nat destination rule-set rs1`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "destination", RuleSet: "rs1"}, true},
		{"nat rule denied", `^show security nat source rule r1$`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{Rule: "r1"}, true},
		{"nat rule other allowed", `^show security nat source rule r1$`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{Rule: "r2"}, false},
		{"nat bare denied", `^show security nat source rule$`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{}, true},
		{"nat both selectors rule-set denied", `^show security nat source rule-set rs1$`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{RuleSet: "rs1", Rule: "r1"}, true},
		{"nat both selectors rule denied", `^show security nat source rule r1$`, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{RuleSet: "rs1", Rule: "r1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern, "")
			err := gateDecide7172(t, cfg, tc.method, tc.req)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over %s was ALLOWED on gRPC; the argument must be reconstructed (#17184)", tc.pattern, tc.method)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over %s refused a command it does not name: %v", tc.pattern, tc.method, err)
			}
		})
	}
}

// Unnameable argument shapes deny for a restricted class rather than
// being judged on the bare charge.
func TestArgumentFormsUnnameable17184(t *testing.T) {
	cfg := cfg16067(t, `^show version$`, "")
	for name, tc := range map[string]struct {
		method string
		req    any
	}{
		"deterministic no direction":     {"GetNATDeterministic", &pb.GetNATDeterministicRequest{}},
		"deterministic forward no host":  {"GetNATDeterministic", &pb.GetNATDeterministicRequest{Direction: pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD}},
		"deterministic reverse bad port": {"GetNATDeterministic", &pb.GetNATDeterministicRequest{Direction: pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_REVERSE, NatIp: "192.0.2.1", NatPort: 70000}},
		"packet-drop bad port":           {"MonitorPacketDrop", &pb.MonitorPacketDropRequest{SourcePort: 70000}},
		"packet-drop bad count":          {"MonitorPacketDrop", &pb.MonitorPacketDropRequest{Count: 9000}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := gateDecide7172(t, cfg, tc.method, tc.req); err == nil {
				t.Errorf("%s was ALLOWED for a restricted class; an unnameable argument shape must deny (#17184)", tc.method)
			}
		})
	}
}

// rpcArgumentFormsCases17184 reads the rpcArgumentForms switch's own
// case labels out of the production source (the #5278 discipline: the
// switch is the thing that decides which methods reconstruct, so any
// other source of truth is a second copy that can drift). Constant
// labels (showTextMethodName) resolve through the file's const decls.
func rpcArgumentFormsCases17184(t *testing.T) map[string]bool {
	t.Helper()
	const src = "authz_command_args_16067.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	// The only non-literal label is showTextMethodName, declared in
	// authz_methods.go; resolve it through the production const
	// directly (same package), never a copied string.
	consts := map[string]string{"showTextMethodName": showTextMethodName}
	var fn *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		if node, ok := n.(*ast.FuncDecl); ok && node.Name.Name == "rpcArgumentForms" {
			fn = node
		}
		return true
	})
	if fn == nil {
		t.Fatalf("%s: rpcArgumentForms not found; the census source is broken", src)
	}
	cases := map[string]bool{}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		found = true
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok || cc.List == nil {
				continue
			}
			for _, expr := range cc.List {
				switch e := expr.(type) {
				case *ast.BasicLit:
					if e.Kind != token.STRING {
						t.Errorf("%s: rpcArgumentForms has a non-string case label; the census cannot read it", src)
						continue
					}
					v, err := strconv.Unquote(e.Value)
					if err != nil {
						t.Fatalf("unquote %s: %v", e.Value, err)
					}
					cases[v] = true
				case *ast.Ident:
					v, ok := consts[e.Name]
					if !ok {
						t.Errorf("%s: rpcArgumentForms case label %q is not a resolvable const; the census cannot read it", src, e.Name)
						continue
					}
					cases[v] = true
				default:
					t.Errorf("%s: rpcArgumentForms has a non-literal case label; the census cannot read it", src)
				}
			}
		}
		return false
	})
	if !found || len(cases) == 0 {
		t.Fatalf("%s: no rpcArgumentForms switch cases found; the census source is broken", src)
	}
	return cases
}

// TestEveryRequestFieldIsReconstructedOrNamedAbsent17184 is the census
// (acceptance (3) of #17184, adapted: the descriptor walk classifies
// per METHOD, honouring the per-request reconstruction families).
//
// Every served method must be decided in exactly one place: a
// rpcArgumentForms case (it reconstructs argument text) xor a
// methodsWithoutArgumentForms entry (its fields carry no operator
// argument text) with a non-empty reason and a non-blank field
// decision. Both directions fail: a new method in neither (an
// accidental bare-charge fallback), a case/map entry naming a method
// that is not served (stale), and a method in BOTH (unreadable
// decision) all fail here.
//
// Sub-check, the original per-field strictness: a request field whose
// proto name is spelled as an option keyword of the method's OWN
// canonical command in cmdtree (deterministic-nat internal-host,
// packet-drop source-prefix, client-identifier interface, nat
// rule-set/rule, ...) may not sit in the named-absent map; it must be
// reconstructed by name. Keyword names are harvested from the
// command's subtree in the real operational tree, never hand-listed,
// so adding a selector field named after an existing option keyword
// to a named-absent request fails here without a code change here.
// Request-decoded families whose charge cmd is request-dependent
// (ShowText/SystemAction/GetSystemInfo/GetBGPStatus) and methods
// with no resolved charge (config-mode/plumbing/no-tree-command) are
// classified by their named-absent reasons instead.
func TestEveryRequestFieldIsReconstructedOrNamedAbsent17184(t *testing.T) {
	methods := pb.File_xpf_proto.Services().ByName("BpfrxService").Methods()
	if methods.Len() == 0 {
		t.Fatal("the service descriptor lists no methods — the census source is broken")
	}
	served := make([]string, 0, methods.Len())
	byName := map[string]protoreflect.MethodDescriptor{}
	for i := range methods.Len() {
		m := methods.Get(i)
		served = append(served, string(m.Name()))
		byName[string(m.Name())] = m
	}
	sort.Strings(served)

	cases := rpcArgumentFormsCases17184(t)
	for _, method := range served {
		_, inCases := cases[method]
		reason, named := methodsWithoutArgumentForms[method]
		switch {
		case inCases && named:
			t.Errorf("%s is BOTH a rpcArgumentForms case and named absent in methodsWithoutArgumentForms; one decision must win", method)
		case !inCases && !named:
			t.Errorf("%s is served but decided nowhere: add a rpcArgumentForms arm reconstructing its argument text, or name it in methodsWithoutArgumentForms with why its fields carry no operator argument text (#17184)", method)
		case named && strings.TrimSpace(reason) == "":
			t.Errorf("%s is named absent with an empty reason, which is the same as an unnamed absence", method)
		}
	}
	for method := range cases {
		if _, ok := byName[method]; !ok {
			t.Errorf("rpcArgumentForms has a case for %q, which BpfrxService does not serve — stale arm", method)
		}
	}
	for method := range methodsWithoutArgumentForms {
		if _, ok := byName[method]; !ok {
			t.Errorf("methodsWithoutArgumentForms names %q, which BpfrxService does not serve — stale entry", method)
		}
	}

	// Vocab sub-check over named-absent methods with a FIXED charge in
	// methodCanonicalCommand: a field named (as-is or hyphenated) after
	// an option keyword in the charge's cmdtree subtree must be
	// reconstructed, not named absent. Request-decoded families are
	// absent from that map by construction, so they never reach here.
	for _, method := range served {
		if _, named := methodsWithoutArgumentForms[method]; !named {
			continue
		}
		cmd, fixed := methodCanonicalCommand[method]
		if !fixed {
			continue
		}
		fields := byName[method].Input().Fields()
		if fields.Len() == 0 {
			continue
		}
		vocab := subtreeOptionVocab17184(t, cmd)
		for i := range fields.Len() {
			name := string(fields.Get(i).Name())
			for _, spelling := range []string{name, strings.ReplaceAll(name, "_", "-")} {
				if _, hit := vocab[spelling]; hit {
					t.Errorf("%s is named absent but request field %q is spelled as an option keyword of its charge %q; the field must be reconstructed by a rpcArgumentForms arm, not named absent (#17184)", method, name, cmd)
				}
			}
		}
	}
}

// subtreeOptionVocab17184 returns the keyword names that take a value
// or open a dynamic slot anywhere in the subtree of cmd in the real
// operational tree (typed leaves, RequiresValue nodes, dynamic-slot
// parents). Plain subcommand keywords (detail/all/summary...) are NOT
// option keywords: a field named `detail` selects a sibling command,
// not an argument. The charge itself is asserted canonical first.
func subtreeOptionVocab17184(t *testing.T, cmd string) map[string]bool {
	t.Helper()
	words := strings.Fields(cmd)
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words)
	if res != cmdtree.CanonicalOK || strings.Join(canon, " ") != cmd {
		t.Fatalf("charge %q does not canonicalise to itself; the census vocab source is broken", cmd)
	}
	level := cmdtree.OperationalTree
	var node *cmdtree.Node
	for _, w := range words {
		next, ok := level[w]
		if !ok {
			t.Fatalf("charge %q word %q not in tree", cmd, w)
		}
		node = next
		level = next.Children
	}
	vocab := map[string]bool{}
	var walk func(n *cmdtree.Node)
	walk = func(n *cmdtree.Node) {
		for name, child := range n.Children {
			if strings.HasPrefix(name, "<") {
				continue
			}
			if child.IsTypedLeaf() || child.RequiresValue || child.HasDynamic() || child.Options {
				vocab[name] = true
			}
			walk(child)
		}
	}
	if node != nil {
		walk(node)
	}
	return vocab
}
