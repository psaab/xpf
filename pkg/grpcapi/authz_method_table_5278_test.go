package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// Completeness of the #5278 authorization tables.
//
// These two tests are the reason the gate can be trusted at all. An
// authorization table that is merely LONG proves nothing: the failure mode is a
// method (or a SystemAction verb) that nobody remembered to price, and a guard
// that compares a hand-written list against a hand-written count can never
// observe that — it is the shape that let the enumeration guard in
// pkg/dataplane/userspace/ingress_exclusions.go pass while blind. Both tests
// below therefore derive the EXPECTED set from generated or production source
// (the protobuf service descriptor; the handler's own switch statement) and
// compare it against the table in BOTH directions.

// serviceMethodNames returns every method name registered on BpfrxService,
// taken from the GENERATED descriptor — the same structure grpc-go dispatches
// on, so a method that exists at runtime cannot be absent from this list.
func serviceMethodNames(t *testing.T) []string {
	t.Helper()
	desc := pb.BpfrxService_ServiceDesc
	names := make([]string, 0, len(desc.Methods)+len(desc.Streams))
	for _, m := range desc.Methods {
		names = append(names, m.MethodName)
	}
	for _, sd := range desc.Streams {
		names = append(names, sd.StreamName)
	}
	sort.Strings(names)
	return names
}

// TestEveryServiceMethodHasAPermission_5278 is the completeness guard: every
// RPC the server actually serves must be priced, and nothing that is not an RPC
// may sit in the table pretending to be one.
//
// RED on revert: delete any entry from methodPermissions (the "missing" arm) or
// add one naming a method that does not exist / rename an RPC in the proto (the
// "stale" arm).
func TestEveryServiceMethodHasAPermission_5278(t *testing.T) {
	registered := serviceMethodNames(t)
	if len(registered) == 0 {
		t.Fatal("the service descriptor lists no methods — the enumeration " +
			"source is broken, and a vacuous pass here would certify nothing")
	}

	inDescriptor := make(map[string]bool, len(registered))
	for _, name := range registered {
		inDescriptor[name] = true
		if _, ok := methodPermissions[name]; !ok {
			t.Errorf("RPC %q is served but has no entry in methodPermissions: it "+
				"would be charged %s (super-user only) at runtime. Add it to "+
				"pkg/grpcapi/authz_methods.go with the permission pkg/cli "+
				"requiredPermission charges for the command that reaches it (#5278)",
				name, permName(unmappedMethodPermission))
		}
	}
	for name := range methodPermissions {
		if !inDescriptor[name] {
			t.Errorf("methodPermissions prices %q, which BpfrxService does not "+
				"serve — a stale entry hides the fact that some real method is "+
				"unpriced (#5278)", name)
		}
	}

	// A permission outside the model would be evaluated by
	// config.ClassHasPermission as "no class holds it", i.e. a silent
	// super-user-only method that reads as a deliberate tier.
	for name, perm := range methodPermissions {
		switch perm {
		case config.PermView, config.PermClear, config.PermControl,
			config.PermConfig, config.PermMaint, config.PermAll:
		default:
			t.Errorf("RPC %q is priced at an unknown permission %d", name, int(perm))
		}
	}
}

// TestMethodPermissionIsResolvedForEveryServedMethod_5278 drives the LOOKUP
// rather than the map, so a method that is present in the table but unreachable
// through methodPermission (a service-name mismatch, a broken split) still
// fails. The table being complete and the lookup finding it are two properties.
func TestMethodPermissionIsResolvedForEveryServedMethod_5278(t *testing.T) {
	for _, name := range serviceMethodNames(t) {
		full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/" + name
		if _, mapped := methodPermission(full, nil); !mapped {
			t.Errorf("methodPermission(%q) reports UNMAPPED; the interceptor "+
				"would charge %s for a method the table prices explicitly (#5278)",
				full, permName(unmappedMethodPermission))
		}
	}
}

// TestUnknownMethodFallsToTheStrictestPermission_5278 pins the fail-closed
// default itself, including for a well-formed method on a foreign service.
//
// RED on revert: change unmappedMethodPermission to anything a non-super class
// holds, or make methodPermission return mapped=true for an unknown method.
func TestUnknownMethodFallsToTheStrictestPermission_5278(t *testing.T) {
	cases := []string{
		"/" + pb.BpfrxService_ServiceDesc.ServiceName + "/FutureDestructiveRPC",
		"/some.other.Service/GetStatus",
		"/malformed",
		"",
	}
	for _, full := range cases {
		perm, mapped := methodPermission(full, nil)
		if mapped {
			t.Errorf("methodPermission(%q) reported MAPPED; an unknown method "+
				"must be unmapped so the miss is logged (#5278)", full)
		}
		if perm != unmappedMethodPermission {
			t.Errorf("methodPermission(%q) = %s, want %s (fail-closed default)",
				full, permName(perm), permName(unmappedMethodPermission))
		}
		if config.ClassHasPermission(nil, "read-only", perm) ||
			config.ClassHasPermission(nil, "operator", perm) ||
			config.ClassHasPermission(nil, "config-viewer", perm) {
			t.Errorf("methodPermission(%q) = %s, which a NON-super predefined "+
				"class holds — an unmapped method must not be reachable by the "+
				"population #5278 exists to constrain", full, permName(perm))
		}
	}
}

// systemActionVerbsFromHandler reads the SystemAction handler's own switch
// labels out of the production source.
//
// It parses the file rather than importing a list because the list is exactly
// what could be wrong: the handler's switch is the thing that decides which
// verbs EXIST, so any other source of truth is a second copy that can drift.
func systemActionVerbsFromHandler(t *testing.T) []string {
	t.Helper()
	const src = "server_diag_system_action.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}

	var verbs []string
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "SystemAction" || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || !isReqActionSelector(sw.Tag) {
				return true
			}
			found = true
			for _, stmt := range sw.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range cc.List { // nil List == the default clause
					lit, ok := expr.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("%s: SystemAction switch has a non-literal case "+
							"label; the verb table can no longer be proven complete", src)
						continue
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("unquote %s: %v", lit.Value, err)
					}
					verbs = append(verbs, v)
				}
			}
			return false
		})
		return false
	})
	if !found {
		t.Fatalf("%s: no `switch req.Action` found inside SystemAction — the "+
			"enumeration source moved, and a vacuous pass here would certify "+
			"nothing about verb coverage", src)
	}
	sort.Strings(verbs)
	return verbs
}

// isReqActionSelector reports whether e is the `req.Action` switch tag.
func isReqActionSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Action" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "req"
}

// TestEverySystemActionVerbHasAPermission_5278 pins the verb table against the
// handler's switch in both directions.
//
// The direction that matters is "missing": a verb the handler serves but the
// table does not price falls back to PermMaint, which is safe but silently
// takes an operator-class verb away. The reverse direction ("stale") matters
// because a stale entry is how a reader concludes the table is complete.
//
// RED on revert: drop any entry from systemActionPermissions, or add a `case
// "something-new":` to the handler without pricing it.
func TestEverySystemActionVerbHasAPermission_5278(t *testing.T) {
	verbs := systemActionVerbsFromHandler(t)
	if len(verbs) == 0 {
		t.Fatal("no SystemAction verbs parsed out of the handler")
	}
	inHandler := make(map[string]bool, len(verbs))
	for _, v := range verbs {
		inHandler[v] = true
		if _, ok := systemActionPermissions[v]; !ok {
			t.Errorf("SystemAction verb %q is served but unpriced: it falls back "+
				"to %s, so any class below super-user loses it. Price it in "+
				"systemActionPermissions (#5278)", v, permName(systemActionPermission(v)))
		}
	}
	for v := range systemActionPermissions {
		if !inHandler[v] {
			t.Errorf("systemActionPermissions prices %q, which the SystemAction "+
				"handler does not serve — a stale entry hides an unpriced real "+
				"verb (#5278)", v)
		}
	}
}

// TestPrefixFormSystemActionsCostMaintenance_5278 covers the verbs the handler
// resolves in its DEFAULT branch (parsed by prefix, so they have no case label
// and cannot appear in the table): the cluster-failover grammar and the
// userspace dataplane control forms. They must reach the destructive floor.
func TestPrefixFormSystemActionsCostMaintenance_5278(t *testing.T) {
	for _, action := range []string{
		"cluster-failover:1",
		"cluster-failover:1:node0",
		"cluster-failover-data:node1",
		"cluster-failover-reset:1",
		"userspace-forwarding:disarm",
		"userspace-forwarding:arm",
		"userspace-queue:3:unregister",
		"userspace-binding:2:disarm",
		"userspace-inject:0:tx",
		"a-verb-nobody-has-written-yet",
	} {
		if got := systemActionPermission(action); got != config.PermMaint {
			t.Errorf("systemActionPermission(%q) = %s, want maintenance "+
				"(the destructive floor for an action the gate cannot price "+
				"exactly) (#5278)", action, permName(got))
		}
	}
}

// TestSystemActionPermissionIsReadFromTheDecodedRequest_5278 pins the one place
// methodPermission consults the request: a decoded SystemAction is priced by
// its verb, and a SystemAction the gate cannot decode falls back to the
// method-level floor rather than to something cheaper.
func TestSystemActionPermissionIsReadFromTheDecodedRequest_5278(t *testing.T) {
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/SystemAction"

	if perm, _ := methodPermission(full, &pb.SystemActionRequest{Action: "clear-arp"}); perm != config.PermClear {
		t.Errorf("SystemAction{clear-arp} priced %s, want clear — an operator "+
			"class must keep `clear arp` (#5278)", permName(perm))
	}
	if perm, _ := methodPermission(full, &pb.SystemActionRequest{Action: "zeroize"}); perm != config.PermMaint {
		t.Errorf("SystemAction{zeroize} priced %s, want maintenance", permName(perm))
	}
	// No request at all (the stream path, or a decode the gate did not get):
	// the method-level entry is the floor.
	for _, req := range []any{nil, (*pb.SystemActionRequest)(nil), &pb.GetStatusRequest{}} {
		if perm, _ := methodPermission(full, req); perm != config.PermMaint {
			t.Errorf("SystemAction with request %T priced %s, want maintenance "+
				"(the floor when the verb cannot be read) (#5278)", req, permName(perm))
		}
	}
}

func TestDynamicAddressShrinkAckRequiresConfigurePermission11059(t *testing.T) {
	usePasswdFixture5278(t)
	s := NewServer("", Config{Store: authzStore5278(t, authzConfig5278)})
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/SystemAction"
	req := &pb.SystemActionRequest{Action: "dynamic-address-shrink-ack"}
	for _, uid := range []uint32{authzUIDReadOnly, authzUIDOperator} {
		if err := s.authorizeRPC(ctxWithPeerUID(uid), full, req); err == nil {
			t.Errorf("uid %d without configure permission was admitted for shrink acknowledgement", uid)
		}
	}
	if err := s.authorizeRPC(ctxWithPeerUID(authzUIDSuperuser), full, req); err != nil {
		t.Fatalf("super-user with configure permission was denied: %v", err)
	}
}

// TestPrimaryAndFabricChainsAreDistinct_5278 is the structural half of "do not
// touch the fabric listener": the two servers are built by different functions
// and the #5278 interceptors appear only in the primary one.
//
// It reads the SOURCE rather than the built *grpc.Server because grpc.Server
// exposes neither its interceptors nor its stats handlers; a behavioural
// discriminator lives in TestFabricListenerDoesNotApplyThePrincipalGate_5278.
func TestPrimaryAndFabricChainsAreDistinct_5278(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	want := map[string][]string{
		// loopbackServerInterceptors is #5883's, not #5278's, and is required
		// here because THIS function is now its only production consumer: the
		// #5278 chain wraps it, so #5883's own wiring test (which only calls
		// the constructor) can no longer observe its removal from the listener.
		"buildPrimaryServer": {
			"principalUnaryInterceptor", "principalStreamInterceptor",
			"peerAuthStatsHandler", "loopbackServerInterceptors",
		},
		"buildFabricServer": {"fabricAuthUnaryInterceptor", "fabricAllowlistUnaryInterceptor"},
	}
	forbid := map[string][]string{
		"buildPrimaryServer": {"fabricAuthUnaryInterceptor", "fabricAllowlistUnaryInterceptor"},
		"buildFabricServer":  {"principalUnaryInterceptor", "principalStreamInterceptor", "peerAuthStatsHandler"},
	}
	seen := map[string]map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if _, interesting := want[fn.Name.Name]; !interesting {
			return true
		}
		names := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				names[v.Name] = true
			case *ast.SelectorExpr:
				names[v.Sel.Name] = true
			}
			return true
		})
		seen[fn.Name.Name] = names
		return false
	})
	for fn, required := range want {
		names, ok := seen[fn]
		if !ok {
			t.Fatalf("server.go no longer declares %s — the chain split this test "+
				"pins has moved", fn)
		}
		for _, sym := range required {
			if !names[sym] {
				t.Errorf("%s no longer installs %s (#5278/#4107/#4122)", fn, sym)
			}
		}
		for _, sym := range forbid[fn] {
			if names[sym] {
				t.Errorf("%s installs %s, which belongs to the OTHER listener's "+
					"chain — the primary gate authorizes a local login user and "+
					"the fabric gate authenticates a cluster NODE; neither is a "+
					"substitute for the other (#5278)", fn, sym)
			}
		}
	}
}

// permName renders a permission for a failure message.
func permName(p config.LoginClassPermission) string {
	switch p {
	case config.PermView:
		return "view"
	case config.PermClear:
		return "clear"
	case config.PermControl:
		return "control"
	case config.PermConfig:
		return "configure"
	case config.PermMaint:
		return "maintenance"
	case config.PermAll:
		return "all"
	default:
		return "permission(" + strconv.Itoa(int(p)) + ")"
	}
}

// compile-time assertion that the interceptors keep the shapes grpc.NewServer
// requires; a signature drift would otherwise surface only where they are
// installed.
var (
	_ grpc.UnaryServerInterceptor  = (*Server)(nil).principalUnaryInterceptor
	_ grpc.StreamServerInterceptor = (*Server)(nil).principalStreamInterceptor
)

// showTextTopicsFromDispatcher reads every topic literal the ShowText
// dispatcher branches on, out of the production source.
//
// Three dispatch shapes carry a topic in server_show.go and all three are
// collected: `strings.HasPrefix(req.Topic, "x")`, `req.Topic == "x"`, and the
// case labels of `switch req.Topic`. A literal reached any other way would be
// invisible here, so the walk is keyed on the IDENTIFIER req.Topic rather than
// on string literals in general — a literal that is not compared against the
// topic is not a topic.
func showTextTopicsFromDispatcher(t *testing.T) []string {
	t.Helper()
	const src = "server_show.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}

	seen := map[string]bool{}
	lit := func(e ast.Expr) (string, bool) {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(bl.Value)
		if err != nil {
			return "", false
		}
		return v, true
	}

	var sawSwitch bool
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			// strings.HasPrefix(req.Topic, "x")
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "HasPrefix" || len(v.Args) != 2 {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
				return true
			}
			if !isReqTopicSelector(v.Args[0]) {
				return true
			}
			if s, ok := lit(v.Args[1]); ok {
				seen[s] = true
			}
		case *ast.BinaryExpr:
			// req.Topic == "x"
			if v.Op != token.EQL {
				return true
			}
			if isReqTopicSelector(v.X) {
				if s, ok := lit(v.Y); ok {
					seen[s] = true
				}
			}
			if isReqTopicSelector(v.Y) {
				if s, ok := lit(v.X); ok {
					seen[s] = true
				}
			}
		case *ast.SwitchStmt:
			// switch req.Topic { case "a", "b": }
			if !isReqTopicSelector(v.Tag) {
				return true
			}
			sawSwitch = true
			for _, stmt := range v.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, e := range cc.List {
					s, ok := lit(e)
					if !ok {
						t.Errorf("%s: `switch req.Topic` has a non-literal case "+
							"label; topic coverage can no longer be proven", src)
						continue
					}
					seen[s] = true
				}
			}
		}
		return true
	})
	if !sawSwitch {
		t.Fatalf("%s: no `switch req.Topic` found — the enumeration source moved, "+
			"and a vacuous pass here would certify nothing about topic coverage", src)
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// isReqTopicSelector reports whether e is the `req.Topic` expression.
func isReqTopicSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Topic" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "req"
}

// TestEveryShowTextTopicHasAPermission_5278 is the sibling of the method-table
// guard, and it exists because that guard is VACUOUS for this property: it
// enumerates the service DESCRIPTOR, so a complete method table says nothing
// about whether ShowText's 127 topics were classified. That is precisely how
// the `test-*` topics shipped priced at view in the first revision.
//
// RED on revert: drop a topic from showTextViewTopics (the "unpriced" arm), or
// price one that the dispatcher does not serve (the "stale" arm).
func TestEveryShowTextTopicHasAPermission_5278(t *testing.T) {
	topics := showTextTopicsFromDispatcher(t)
	if len(topics) < 50 {
		t.Fatalf("only %d ShowText topics parsed out of the dispatcher; the "+
			"extraction is broken and a pass would certify nothing", len(topics))
	}

	inDispatcher := make(map[string]bool, len(topics))
	for _, topic := range topics {
		inDispatcher[topic] = true
		_, elevated := showTextElevatedTopics[topic]
		if !elevated && !showTextViewTopics[topic] {
			t.Errorf("ShowText topic %q is dispatched but unpriced: it would be "+
				"charged %s (super-user only). Add it to showTextViewTopics, or "+
				"to showTextElevatedTopics if a non-`show` command emits it (#5278)",
				topic, permName(unmappedMethodPermission))
		}
		if elevated && showTextViewTopics[topic] {
			t.Errorf("ShowText topic %q is in BOTH tables; the lookup order would "+
				"decide its tier silently", topic)
		}
	}
	for topic := range showTextViewTopics {
		if !inDispatcher[topic] {
			t.Errorf("showTextViewTopics prices %q, which the ShowText dispatcher "+
				"does not serve — a stale entry hides an unpriced real topic (#5278)", topic)
		}
	}
	for topic := range showTextElevatedTopics {
		if !inDispatcher[topic] {
			t.Errorf("showTextElevatedTopics prices %q, which the ShowText "+
				"dispatcher does not serve (#5278)", topic)
		}
	}
}

// TestTestFamilyShowTextTopicsCostControl_5278 pins the specific tier confusion
// the first revision shipped: the topics emitted by the top-level word `test`
// must cost what pkg/cli/permissions.go charges for `test` (PermControl), not
// what it charges for `show`.
//
// RED on revert: move any test-* key back to PermView.
func TestTestFamilyShowTextTopicsCostControl_5278(t *testing.T) {
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/ShowText"
	for _, topic := range []string{
		"test-policy:from=trust,to=untrust,src=10.0.1.5,dst=10.0.2.5,proto=tcp,port=443",
		"test-routing:dest=10.0.0.0/24",
		"test-routing:dest=10.0.0.0/24,instance=dmz-vr",
		"test-zone:interface=ge-0/0/0.0",
	} {
		perm, mapped := methodPermission(full, &pb.ShowTextRequest{Topic: topic})
		if !mapped {
			t.Errorf("ShowText topic %q is unmapped", topic)
		}
		if perm != config.PermControl {
			t.Errorf("ShowText topic %q priced %s, want control — cmd/cli emits it "+
				"from `test ...`, which pkg/cli requiredPermission charges at "+
				"control (#5278)", topic, permName(perm))
		}
		if config.ClassHasPermission(nil, "read-only", perm) ||
			config.ClassHasPermission(nil, "config-viewer", perm) {
			t.Errorf("ShowText topic %q is reachable by a view-only class; "+
				"`test policy` is policy reconnaissance", topic)
		}
	}
}

// TestShowTopicsStayAtView_5278 is the negative control for the case above: the
// correction must not sweep the ~124 genuine `show` topics up a tier. Without
// it, pricing EVERY topic at control would pass the test-family assertions and
// silently take `show chassis cluster` away from read-only.
func TestShowTopicsStayAtView_5278(t *testing.T) {
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/ShowText"
	for _, topic := range []string{
		"version", "chassis-cluster-information", "chassis-forwarding", "buffers",
		"route-all", "firewall", "sessions-top:bytes", "log:messages",
		"class-of-service", "class-of-service:ge-0/0/0", "screen-statistics:untrust",
		"firewall-effective", "firewall-effective-filter:f1",
	} {
		perm, mapped := methodPermission(full, &pb.ShowTextRequest{Topic: topic})
		if !mapped {
			t.Errorf("ShowText topic %q is unmapped", topic)
		}
		if perm != config.PermView {
			t.Errorf("ShowText topic %q priced %s, want view — it is a `show ...` "+
				"topic and read-only must keep it (#5278)", topic, permName(perm))
		}
	}
}

// TestUnknownShowTextTopicIsStrict_5278 pins the fail-closed default for the
// topic dimension, and the floor used when the topic cannot be read at all.
func TestUnknownShowTextTopicIsStrict_5278(t *testing.T) {
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/ShowText"

	for _, topic := range []string{"a-topic-nobody-serves", "", "test-", "log"} {
		perm, mapped := methodPermission(full, &pb.ShowTextRequest{Topic: topic})
		if topic == "log" {
			// "log" IS a served topic; it is here as the control that proves the
			// loop is not passing because every input is unknown.
			if !mapped || perm != config.PermView {
				t.Errorf("control topic %q: perm=%s mapped=%v, want view/true",
					topic, permName(perm), mapped)
			}
			continue
		}
		if mapped {
			t.Errorf("unknown ShowText topic %q reported MAPPED; the miss must be "+
				"logged (#5278)", topic)
		}
		if perm != unmappedMethodPermission {
			t.Errorf("unknown ShowText topic %q priced %s, want %s (fail-closed)",
				topic, permName(perm), permName(unmappedMethodPermission))
		}
	}

	// No request, or a request of the wrong type: the method-level FLOOR, which
	// must be the highest tier any topic needs — never the view floor.
	for _, req := range []any{nil, (*pb.ShowTextRequest)(nil), &pb.GetStatusRequest{}} {
		perm, _ := methodPermission(full, req)
		if perm != config.PermControl {
			t.Errorf("ShowText with request %T priced %s, want control (the floor "+
				"when the topic cannot be read) (#5278)", req, permName(perm))
		}
	}
}

// TestShowTextPrefixRulesAreUnambiguous_5278 asserts no prefix rule is a prefix
// of another, so the longest-first ordering never has to arbitrate a genuine
// overlap — if it ever did, a topic's tier would depend on table ordering
// rather than on its classification.
func TestShowTextPrefixRulesAreUnambiguous_5278(t *testing.T) {
	if len(showTextPrefix) == 0 {
		t.Fatal("no prefix rules built; init did not run or the tables are empty")
	}
	for i, a := range showTextPrefix {
		for j, b := range showTextPrefix {
			if i == j {
				continue
			}
			if strings.HasPrefix(a.prefix, b.prefix) {
				t.Errorf("prefix rule %q is shadowed by %q; a topic matching both "+
					"would be priced by table ordering", a.prefix, b.prefix)
			}
		}
	}
}

// TestShowTextDispatchLivesInOneFile_5278 guards the guard.
//
// TestEveryShowTextTopicHasAPermission_5278 parses ONE file. That is only a
// coverage claim if that file is where every topic decision is made — a topic
// dispatched from any other file would be invisible to it, and the guard would
// go on passing while a whole family of topics was unpriced. That is the same
// wrong-property failure the topic guard exists to correct, one level up.
//
// The dispatch SSOT is server_show.go. server_show_interfaces_text.go is the
// one allowed exception: it re-tests an already-dispatched `class-of-service:`
// topic to pick a rendering, not to decide which topic is served.
//
// RED on revert: dispatch a new topic (`req.Topic == "x"`,
// `strings.HasPrefix(req.Topic, ...)` or `switch req.Topic`) from any other
// production file in this package.
func TestShowTextDispatchLivesInOneFile_5278(t *testing.T) {
	allowed := map[string]bool{
		"server_show.go":                 true,
		"server_show_interfaces_text.go": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		if allowed[name] {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", name, perr)
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BinaryExpr:
				if v.Op == token.EQL && (isReqTopicSelector(v.X) || isReqTopicSelector(v.Y)) {
					t.Errorf("%s dispatches on req.Topic; ShowText topic coverage is "+
						"proven by parsing server_show.go alone, so a topic decided "+
						"here is invisible to TestEveryShowTextTopicHasAPermission_5278 "+
						"(#5278)", name)
				}
			case *ast.SwitchStmt:
				if isReqTopicSelector(v.Tag) {
					t.Errorf("%s contains `switch req.Topic`; see above (#5278)", name)
				}
			case *ast.CallExpr:
				sel, ok := v.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "HasPrefix" || len(v.Args) != 2 {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
					return true
				}
				if isReqTopicSelector(v.Args[0]) {
					t.Errorf("%s prefix-dispatches on req.Topic; see above (#5278)", name)
				}
			}
			return true
		})
	}
	if checked < 20 {
		t.Fatalf("only %d production files scanned; the walk is broken and a pass "+
			"would certify nothing", checked)
	}
	for name := range allowed {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("allowlisted dispatcher %s no longer exists; the topic guard's "+
				"enumeration source has moved (#5278)", name)
		}
	}
}
