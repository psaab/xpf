package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #7172 cut 5b — the command tables are now READ and `deny-commands` is
// enforced on the gRPC listener.

// gateCfg7172 builds a config whose class `ops` carries the given
// deny-commands pattern. DenyLeavesPresent is set explicitly because PRESENCE,
// not value, is what admits the leaf — `deny-commands ""` denies everything and
// an absent leaf denies nothing, and only this list separates them.
func gateCfg7172(t *testing.T, pattern string, present bool) *config.Config {
	t.Helper()
	lc := &config.LoginClass{Name: "ops", DenyCommands: pattern}
	if present {
		lc.DenyLeavesPresent = []string{"deny-commands"}
	}
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{lc}}
	return cfg
}

func gateDecide7172(t *testing.T, cfg *config.Config, method string, req any) error {
	t.Helper()
	s := &Server{}
	return s.authorizeRPCCommand(cfg, "ops", "/"+serviceName+"/"+method, req)
}

// A class with NO regexes is untouched by every rule in this file, including
// the fail-closed ones. FIRES IF: any of the deny arms is evaluated before the
// admission check — which would make an unmapped RPC start failing for classes
// that never asked for fine-grained rules.
func TestUnrestrictedClassIsUnaffected7172(t *testing.T) {
	cfg := gateCfg7172(t, "", false)
	for _, tc := range []struct {
		method string
		req    any
	}{
		{"GetStatus", &pb.GetStatusRequest{}},
		{"Commit", nil}, // no canonical command
		{"SystemAction", &pb.SystemActionRequest{Action: "cluster-failover:1"}}, // prefix-form verb
		{"ShowText", &pb.ShowTextRequest{Topic: "zzbogus-topic"}},               // unknown topic
	} {
		if err := gateDecide7172(t, cfg, tc.method, tc.req); err != nil {
			t.Errorf("%s must be unaffected for a class with no regexes, got: %v", tc.method, err)
		}
	}
}

// A PATH-level deny is enforced here exactly as it is on the box.
func TestPathLevelDenyIsEnforced7172(t *testing.T) {
	cfg := gateCfg7172(t, "request system reboot", true)
	if err := gateDecide7172(t, cfg, "SystemAction",
		&pb.SystemActionRequest{Action: "reboot"}); err == nil {
		t.Error("SystemAction{reboot} maps to `request system reboot` and must be denied")
	}
	// ...and nothing else is.
	if err := gateDecide7172(t, cfg, "GetStatus", &pb.GetStatusRequest{}); err != nil {
		t.Errorf("a narrow deny must stay narrow; GetStatus was denied: %v", err)
	}
}

// THE ASYMMETRY, ASSERTED RATHER THAN DESCRIBED.
//
// This is the cell the issue comment demands: 5b must not read a populated
// table as meaning the two surfaces match the same thing. They do not, and the
// difference is stated here in one place so it is a fact the suite carries
// rather than folklore in a comment.
//
// The SAME compiled rules object denies the full canonicalized line (what
// pkg/cli's cut-3 gate matches, via this same Evaluate call) and ALLOWS the
// command path (what this surface can produce), because the remote CLI parses
// the line client-side and the argument never crosses the wire.
//
// RED on change: make the tables carry arguments, or make this gate deny an
// argument-bearing request, and this cell must be rewritten deliberately rather
// than the asymmetry quietly moving.
func TestArgumentLevelDenyIsOnBoxOnly7172(t *testing.T) {
	const pattern = "show route table secret-vrf"
	cfg := gateCfg7172(t, pattern, true)

	rules, ok, err := config.OperationalLoginRegexesFor(cfg, "ops")
	if err != nil || !ok {
		t.Fatalf("precondition: the class must have compiled deny rules (ok=%v err=%v)", ok, err)
	}
	// The ON-BOX surface matches the full canonicalized line, arguments and all.
	if rules.Evaluate("show route table secret-vrf").Allowed {
		t.Fatal("precondition: the on-box surface must DENY the full line, or this cell " +
			"is comparing two allows and proves nothing")
	}
	// THIS surface matches the path, which the pattern does not match.
	if err := gateDecide7172(t, cfg, "ShowText",
		&pb.ShowTextRequest{Topic: "route-table:secret-vrf"}); err != nil {
		t.Errorf("the gRPC surface matches the command PATH (`show route table`), which this "+
			"argument-level pattern does not match — so it is enforced on the box and NOT "+
			"here. That is #7172's named, accepted gap; if this now denies, the gap was "+
			"closed and this cell must be rewritten, not deleted. got: %v", err)
	}
}

// unenforceableDenyPatterns must be SPELLING-INDEPENDENT, and this is the cell
// that pins the lesson.
//
// The obvious implementation inspects the pattern with regexp.LiteralPrefix and
// flags one that extends a mapped command. Measured, LiteralPrefix returns ""
// for `^show route table secret-vrf` — so that version would cover the
// unanchored spelling and MISS the anchored one, which is the spelling
// Juniper's guidance tells operators to use for anything complex. A guard that
// covers one spelling of the same intent reads as coverage and is not.
//
// FIRES IF: the check is rewritten to inspect the pattern instead of matching
// it against the command set.
func TestUnenforceableDenyDetectionIsSpellingIndependent7172(t *testing.T) {
	for _, pattern := range []string{
		"show route table secret-vrf",  // unanchored
		"^show route table secret-vrf", // anchored — LiteralPrefix returns "" here
		".*secret-vrf",                 // no literal prefix at all
	} {
		rules, ok, err := config.OperationalLoginRegexesFor(gateCfg7172(t, pattern, true), "ops")
		if err != nil || !ok {
			t.Fatalf("%q: precondition failed (ok=%v err=%v)", pattern, ok, err)
		}
		if got := unenforceableDenyPatterns(rules); len(got) != 1 {
			t.Errorf("%q matches no command this surface can produce, so it must be reported "+
				"as on-box-only; got %v", pattern, got)
		}
	}
	// And a pattern that DOES match a mapped command is not reported, or the
	// warning would fire for every class and mean nothing.
	rules, _, _ := config.OperationalLoginRegexesFor(
		gateCfg7172(t, "request system reboot", true), "ops")
	if got := unenforceableDenyPatterns(rules); len(got) != 0 {
		t.Errorf("a pattern that matches a mapped command is enforced on BOTH surfaces and "+
			"must not be reported; got %v", got)
	}
}

// FAIL CLOSED on an RPC with no canonical command — but only for a restricted
// class (the unrestricted case is covered above).
//
// #9633 took the CONFIG-MODE methods out of this rule, and the reason is a
// changed premise, not a relaxed check. The rule is "not knowing which command
// we hold, we cannot know a deny regex fails to match it". For config-mode RPCs
// the right regexes are the `*-configuration` ones, and #9633 gave that gate an
// answer for every one of them: per written path for Set, Delete, Load set and
// Load merge; a refusal of load override and rollback n>0 for a restricted
// class. So the operational regexes no longer decide them, as on the console.
// Commit was the row here; TestDocumentedDenyCommandsClassCanConfigureOverGRPC9633
// and TestLoadAndRollbackMeetTheConfigurationRegexes9633 now bind those methods,
// and the rows below still bind every other method with no canonical command.
func TestUnmappedRPCDeniesARestrictedClass7172(t *testing.T) {
	cfg := gateCfg7172(t, "request system reboot", true)
	for _, tc := range []struct {
		name   string
		method string
		req    any
	}{
		{"method named absent: no cmdtree command exists", "GetOSPFStatus", &pb.GetOSPFStatusRequest{}},
		{"unknown ShowText topic", "ShowText", &pb.ShowTextRequest{Topic: "zzbogus-topic"}},
		{"ShowText whose request cannot be read", "ShowText", nil},
	} {
		if err := gateDecide7172(t, cfg, tc.method, tc.req); err == nil {
			t.Errorf("%s: an RPC with no canonical command must DENY a class that configured "+
				"regexes — not knowing which command we hold, we cannot know a deny regex "+
				"fails to match it", tc.name)
		}
	}
}

// THE PREFIX-FORM VERB TRAP, asserted explicitly because the verb table looks
// complete and its guard enumerates CASE LABELS — a floor over what the handler
// dispatches, not a census of what it accepts.
//
// `cluster-failover*` and the `userspace-*` forms are parsed in the handler's
// default branch, have no case label, and CANNOT be added to the table. They
// must deny a restricted class rather than fall through as allow-by-omission.
func TestPrefixFormSystemActionVerbsDeny7172(t *testing.T) {
	cfg := gateCfg7172(t, "request system reboot", true)
	for _, action := range []string{
		"cluster-failover:1",
		"cluster-failover:1:node0",
		"cluster-failover-data:node1",
		"cluster-failover-reset:1",
		"userspace-forwarding:disarm",
		"userspace-queue:3:unregister",
		"userspace-binding:2:disarm",
		"userspace-inject:0:tx",
		"a-verb-nobody-has-written-yet",
	} {
		if err := gateDecide7172(t, cfg, "SystemAction",
			&pb.SystemActionRequest{Action: action}); err == nil {
			t.Errorf("prefix-form verb %q has no table entry and cannot get one; it must DENY "+
				"a restricted class rather than be allowed by omission", action)
		}
	}
}

// A prefix-keyed topic resolves through the same exact-then-longest-prefix rule
// that PRICES it. FIRES IF: the command lookup uses plain map indexing, which
// would make every parameter-packed topic unresolvable and deny it.
func TestPrefixKeyedTopicResolvesToItsCommand7172(t *testing.T) {
	for topic, want := range map[string]string{
		"route-table:mgmt-vrf":              "show route table",
		"screen-statistics:untrust":         "show security screen statistics zone",
		"test-policy:from=a,to=b":           "test policy",
		"log:messages":                      "show log",
		"firewall-effective-filter:f1:inet": "show firewall filter",
		"version":                           "show version",
	} {
		got, ok := showTextTopicCanonicalCommand(topic)
		if !ok || got != want {
			t.Errorf("topic %q resolved to (%q, %v), want (%q, true)", topic, got, ok, want)
		}
	}
}

// The command lookup and the PERMISSION lookup must resolve the same topic to
// the same KEY, over the dispatcher's own topic list. If they disagreed, a
// request could be priced by one rule and command-matched by another.
func TestTopicCommandAndPermissionResolveTheSameKey7172(t *testing.T) {
	topics := showTextTopicsFromDispatcher(t)
	if len(topics) < 50 {
		t.Fatalf("only %d topics parsed; a pass would certify nothing", len(topics))
	}
	for _, topic := range topics {
		// Drive both lookups with a REALISTIC value for a prefix key: the bare
		// key alone would exercise only the exact arm on both sides and the
		// cell would be vacuous for exactly the rule it exists to check.
		probe := topic
		if strings.HasSuffix(topic, ":") {
			probe = topic + "probe-value"
		}
		_, pricedOK := showTextTopicPermission(probe)
		_, cmdOK := showTextTopicCanonicalCommand(probe)
		if pricedOK != cmdOK {
			t.Errorf("topic %q: priced=%v but command-resolved=%v — one lookup finds it and "+
				"the other does not, so a request would be charged a permission with no "+
				"command to match, or the reverse", probe, pricedOK, cmdOK)
		}
	}
}

// A class whose regex does not COMPILE denies. They are validated at commit, so
// reaching here means a config arrived by a path that did not validate.
func TestInvalidRegexDenies7172(t *testing.T) {
	cfg := gateCfg7172(t, "show (unclosed", true)
	if err := gateDecide7172(t, cfg, "GetStatus", &pb.GetStatusRequest{}); err == nil {
		t.Error("a class whose deny regex does not compile must be refused, not evaluated")
	}
}

// An EMPTY deny pattern denies EVERYTHING — an empty POSIX regex matches every
// string. FIRES IF: someone adds the "defensive" empty-pattern guard that
// pkg/config's ValidASPathRegex has, which would turn the most restrictive
// thing an operator can write into the least.
func TestEmptyDenyPatternDeniesEverything7172(t *testing.T) {
	cfg := gateCfg7172(t, "", true)
	if err := gateDecide7172(t, cfg, "GetStatus", &pb.GetStatusRequest{}); err == nil {
		t.Error("`deny-commands \"\"` is an empty POSIX regex, which matches every command — " +
			"it must deny, not be treated as no restriction")
	}
}

// THE WIRING, now BEHAVIOURAL — the conversion #7172 cut 6 unblocks.
//
// Cut 5b bound this with a comment-stripped source scan, and said so: no
// supported path could put a `deny-commands` class into ActiveConfig, because
// #5831/#6838's admission gate rejected it at commit. That was the right
// stand-in then and the wrong one forever. Cut 6 retired the gate, so the class
// commits and the gate can be driven through a REAL client on a REAL listener.
//
// Why it had to be replaced rather than kept alongside: a source scan asserts a
// call EXISTS in a function body. It cannot see that the call is reached, that
// the principal's class is the one resolved from the peer UID, or that the
// denial actually reaches the caller. All three are asserted here, and the
// escape that motivated the original guard — replacing the call with
// `error(nil)` and watching every unit cell stay green — reds this too.
//
// The `limited` class holds `permissions all`, so the #5278 coarse gate admits
// the RPC and anything refused here is refused by the COMMAND regex and nothing
// else. That separation is the point: a denial from the coarse gate would prove
// nothing about this one.
const authzDenyConfig7172 = `
system {
    host-name authz-deny-test;
    login {
        class limited {
            permissions all;
            deny-commands "request system reboot";
        }
        user opsuser {
            class limited;
        }
    }
}
`

func TestAuthorizeRPCEnforcesDenyCommandsEndToEnd7172(t *testing.T) {
	usePasswdFixture5278(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzDenyConfig7172)})
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/SystemAction"

	// PRECONDITION: the class committed and carries the pattern. Without this
	// the cell would pass against a config that never held the deny at all —
	// which is exactly the state cut 6 changed, so it is worth asserting rather
	// than assuming.
	cfg := s.activeConfig()
	rules, ok, err := config.OperationalLoginRegexesFor(cfg, "limited")
	if err != nil || !ok {
		t.Fatalf("the committed class must yield compiled rules (ok=%v err=%v) — if this "+
			"fails, #6838's admission gate is back and the config never reached "+
			"ActiveConfig", ok, err)
	}
	_ = rules

	// DENIED by the command regex, through the real authorization path.
	if err := s.authorizeRPC(ctxWithPeerUID(authzUIDReadOnly), full,
		&pb.SystemActionRequest{Action: "reboot"}); err == nil {
		t.Error("SystemAction{reboot} maps to `request system reboot`, which this class " +
			"denies — authorizeRPC admitted it, so the command gate is not reached")
	}

	// ADMITTED: same class, same coarse permission, a command the pattern does
	// not match. Without this arm the cell would also pass if the gate denied
	// everything, which is not the property under test.
	if err := s.authorizeRPC(ctxWithPeerUID(authzUIDReadOnly),
		"/"+pb.BpfrxService_ServiceDesc.ServiceName+"/GetStatus",
		&pb.GetStatusRequest{}); err != nil {
		t.Errorf("GetStatus maps to `show version`, which the pattern does not match, and "+
			"the class holds `permissions all` — it must be admitted: %v", err)
	}
}
