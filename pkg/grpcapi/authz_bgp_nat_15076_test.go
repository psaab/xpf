package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15076 (A41-01): GetBGPStatus and GetNATRuleStats were charged one fixed
// command whatever selector the request carried, so destination-NAT and
// non-summary BGP reads escaped path-scoped allow/deny rules (and the
// summary/source reads were over-denied by rules for the other family).

func allowCfg15076(t *testing.T, allow string) *config.Config {
	t.Helper()
	lc := &config.LoginClass{Name: "ops", AllowCommands: allow, AllowLeavesPresent: []string{"allow-commands"}}
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{lc}}
	return cfg
}

func TestBGPAndNATSelectorsAreChargedPerRequest15076(t *testing.T) {
	// ALLOW direction is the fail-open leg: a class that permits only the
	// source-rule / bgp-summary commands must not receive the other reads.
	srcOnly := allowCfg15076(t, "^show security nat source rule$|^show bgp summary$|^show protocols bgp summary$")
	for _, tc := range []struct {
		name   string
		method string
		req    any
	}{
		{"destination NAT rules", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "destination"}},
		{"destination NAT rules with rule-set", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "destination", RuleSet: "rs1"}},
		{"BGP neighbor", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "neighbor"}},
		{"BGP neighbor detail", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "neighbor:10.0.0.1"}},
		{"BGP advertised routes", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "advertised-routes:10.0.0.1"}},
		{"BGP received routes", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "received-routes:10.0.0.1"}},
		{"BGP routes", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "routes"}},
		{"BGP groups", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "groups"}},
		{"unknown NAT type", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "static"}},
		{"bogus NAT type", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "src"}},
		{"unknown BGP type", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "bogus"}},
		{"wrong-type request", "GetBGPStatus", &pb.GetNATRuleStatsRequest{}},
		{"nil-typed request", "GetNATRuleStats", nil},
	} {
		if err := gateDecide7172(t, srcOnly, tc.method, tc.req); err == nil {
			t.Errorf("%s: %s allowed under source/summary-only allow-commands; selector was charged the fixed summary/source command (#15076)", tc.name, tc.method)
		}
	}
	// Controls: the permitted selections stay admitted.
	for _, tc := range []struct {
		name   string
		method string
		req    any
	}{
		{"source NAT default", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{}},
		{"source NAT explicit", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "source"}},
		{"source NAT rule-set", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{RuleSet: "rs1"}},
		{"BGP default", "GetBGPStatus", &pb.GetBGPStatusRequest{}},
		{"BGP summary", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "summary"}},
	} {
		if err := gateDecide7172(t, srcOnly, tc.method, tc.req); err != nil {
			t.Errorf("%s: control refused under its own allow: %v", tc.name, err)
		}
	}

	// DENY direction: a destination / neighbor deny must fire on those
	// selections and not on the source / summary controls.
	dstDeny := gateCfg7172(t, "^show security nat destination rule$|^show protocols bgp neighbor", true)
	if err := gateDecide7172(t, dstDeny, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "destination"}); err == nil {
		t.Error("GetNATRuleStats{destination} bypassed deny on destination rule (#15076)")
	}
	if err := gateDecide7172(t, dstDeny, "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "neighbor:10.0.0.1"}); err == nil {
		t.Error("GetBGPStatus{neighbor} bypassed deny on bgp neighbor (#15076)")
	}
	if err := gateDecide7172(t, dstDeny, "GetNATRuleStats", &pb.GetNATRuleStatsRequest{}); err != nil {
		t.Errorf("source NAT control refused by destination deny: %v", err)
	}
	if err := gateDecide7172(t, dstDeny, "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "summary"}); err != nil {
		t.Errorf("BGP summary control refused by neighbor deny: %v", err)
	}
	// Unrestricted class pays nothing, even for unknown selectors.
	open := gateCfg7172(t, "", false)
	for _, tc := range []struct {
		method string
		req    any
	}{
		{"GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "bogus"}},
		{"GetBGPStatus", &pb.GetBGPStatusRequest{Type: "bogus"}},
		{"GetBGPStatus", &pb.GetBGPStatusRequest{Type: "neighbor:10.0.0.1"}},
	} {
		if err := gateDecide7172(t, open, tc.method, tc.req); err != nil {
			t.Errorf("%s unrestricted control refused: %v", tc.method, err)
		}
	}
}

// TestBGPAndNATCanonicalCommandsAreKeywordPrefixes15076 is the census the
// issue asks for: for every remote-cli call site, the RPC's charged command
// must be a keyword prefix of that line's canonical form, and every charged
// value must itself be a pure canonical command path. The canonical form
// drops argument VALUES by name (the rule-set name and the neighbor IP the
// cli packs into the selector) — the charge is the keyword path with those
// values removed, which is exactly the surface's argument-free contract.
// The destination-summary leg shares the destination-rule RPC with the
// destination-rule line (one RPC, two lines), so it is censused against
// the rule line that owns the RPC.
func TestBGPAndNATCanonicalCommandsAreKeywordPrefixes15076(t *testing.T) {
	cases := []struct {
		name   string
		method string
		req    any
		line   string // operator line at the cli call site
	}{
		{"source rule", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{}, "show security nat source rule"},
		{"source rule-set", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{RuleSet: "rs1"}, "show security nat source rule-set rs1"},
		{"destination rule", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "destination"}, "show security nat destination rule"},
		{"destination rule-set", "GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "destination", RuleSet: "rs1"}, "show security nat destination rule-set rs1"},
		{"bgp summary", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "summary"}, "show protocols bgp summary"},
		{"bgp routes", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "routes"}, "show protocols bgp routes"},
		{"bgp neighbor", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "neighbor"}, "show protocols bgp neighbor"},
		{"bgp neighbor ip", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "neighbor:10.0.0.1"}, "show protocols bgp neighbor 10.0.0.1"},
		{"bgp advertised", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "advertised-routes:10.0.0.1"}, "show protocols bgp neighbor 10.0.0.1 advertised-routes"},
		{"bgp received", "GetBGPStatus", &pb.GetBGPStatusRequest{Type: "received-routes:10.0.0.1"}, "show protocols bgp neighbor 10.0.0.1 received-routes"},
	}
	// canonicalForm drops the named argument values from a line. A
	// rule-set line charges its rule sibling: `rule` and `rule-set <name>`
	// perform the same family RPC, and `rule-set` alone cannot be charged
	// because it is an incomplete command (it awaits its name, #14687).
	canonicalForm := func(line string) string {
		words := strings.Fields(line)
		out := make([]string, 0, len(words))
		for _, w := range words {
			if w == "rs1" || w == "10.0.0.1" {
				continue
			}
			if w == "rule-set" {
				w = "rule"
			}
			out = append(out, w)
		}
		return strings.Join(out, " ")
	}
	for _, tc := range cases {
		cmd, resolved := rpcCanonicalCommand("/"+serviceName+"/"+tc.method, tc.req)
		if !resolved {
			t.Errorf("%s: rpcCanonicalCommand unresolved", tc.name)
			continue
		}
		if !cmdtree.EveryWordIsAKeyword(cmdtree.OperationalTree, strings.Fields(cmd)) {
			t.Errorf("%s: charged %q is not a pure keyword path", tc.name, cmd)
		}
		if canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(cmd)); res != cmdtree.CanonicalOK || strings.Join(canon, " ") != cmd {
			t.Errorf("%s: charged %q does not canonicalize to itself (%v)", tc.name, cmd, res)
		}
		form := canonicalForm(tc.line)
		cmdWords := strings.Fields(cmd)
		formWords := strings.Fields(form)
		if len(cmdWords) > len(formWords) {
			t.Errorf("%s: charged %q is not a keyword prefix of canonical form %q (line %q)", tc.name, cmd, form, tc.line)
			continue
		}
		for i, w := range cmdWords {
			if formWords[i] != w {
				t.Errorf("%s: charged %q is not a keyword prefix of canonical form %q (line %q)", tc.name, cmd, form, tc.line)
				break
			}
		}
	}
	// Unknown selectors must stay unresolved (fail closed), never fall back
	// to the summary/source charge.
	for _, tc := range []struct {
		method string
		req    any
	}{
		{"GetNATRuleStats", &pb.GetNATRuleStatsRequest{NatType: "static"}},
		{"GetBGPStatus", &pb.GetBGPStatusRequest{Type: "bogus"}},
		{"GetBGPStatus", &pb.GetBGPStatusRequest{Type: "neighbor:not-an-ip"}},
		{"GetBGPStatus", &pb.GetBGPStatusRequest{Type: "neighbor:"}},
	} {
		if cmd, resolved := rpcCanonicalCommand("/"+serviceName+"/"+tc.method, tc.req); resolved {
			t.Errorf("%s %v resolved to %q; unknown selector must be unresolved (#15076)", tc.method, tc.req, cmd)
		}
	}
	if _, resolved := rpcCanonicalCommand("/"+serviceName+"/GetBGPStatus", &pb.GetBGPStatusRequest{Type: "groups"}); resolved {
		t.Error("GetBGPStatus{groups} resolved; it has no cmdtree command and must fail closed (#15076)")
	}
	// The advertised command set must contain the new charges so the
	// commit-time advisory can see destination/neighbor denies as enforceable.
	set := map[string]bool{}
	for _, c := range allCanonicalCommands() {
		set[c] = true
	}
	for _, want := range []string{"show security nat destination rule", "show protocols bgp neighbor", "show protocols bgp routes", "show protocols bgp neighbor advertised-routes", "show protocols bgp neighbor received-routes"} {
		if !set[want] {
			t.Errorf("allCanonicalCommands missing %q; commit advisory would call its deny unenforceable (#15076)", want)
		}
	}
}
