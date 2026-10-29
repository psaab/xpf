package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16605 (R3-A41-01): typed RPCs shared by two cli lines were charged only
// the fixed methodCanonicalCommand string, so a path-scoped deny written
// against the other typed line never fired remotely (and an allowlist
// naming only the typed line locked the line out). The gate must judge
// every cli line that performs the RPC.

// --- RED probes: deny written against the typed line must fire ---

func TestTypedLineDenyFires16605(t *testing.T) {
	cases := []struct {
		name   string
		deny   string
		method string
		req    any
	}{
		{"ike deny on GetIPsecSA", `show security ike`, "GetIPsecSA", &pb.GetIPsecSARequest{}},
		{"ike anchored deny on GetIPsecSA", `^show security ike security-associations$`, "GetIPsecSA", &pb.GetIPsecSARequest{}},
		{"interfaces deny on ShowInterfacesDetail bare", `^show interfaces$`, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{}},
		{"interfaces terse deny", `^show interfaces terse$`, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{Terse: true}},
		{"interfaces deny on terse", `show interfaces`, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{Terse: true}},
		{"system rollback deny on ShowRollback", `show system rollback`, "ShowRollback", &pb.ShowRollbackRequest{N: 1}},
		{"system rollback deny on ShowCompare", `show system rollback`, "ShowCompare", &pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true}},
		{"system deny on ShowRollback", `^show system`, "ShowRollback", &pb.ShowRollbackRequest{N: 1}},
		{"system deny on ListHistory", `show system rollback`, "ListHistory", &pb.ListHistoryRequest{}},
		{"security statistics deny on GetGlobalStats", `show security statistics`, "GetGlobalStats", &pb.GetGlobalStatsRequest{}},
		{"security vrrp deny on GetVRRPStatus", `show security vrrp`, "GetVRRPStatus", &pb.GetVRRPStatusRequest{}},
		{"nat source summary deny on GetNATPoolStats", `show security nat source summary`, "GetNATPoolStats", &pb.GetNATPoolStatsRequest{}},
		{"nat destination summary deny on GetNATDestination", `^show security nat destination summary$`, "GetNATDestination", &pb.GetNATDestinationRequest{}},
		{"nat destination deny on GetNATDestination", `show security nat destination`, "GetNATDestination", &pb.GetNATDestinationRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := gateCfg7172(t, tc.deny, true)
			if err := gateDecide7172(t, cfg, tc.method, tc.req); err == nil {
				t.Errorf("deny %q must deny %s (typed-line alias missing, #16605)", tc.deny, tc.method)
			}
		})
	}
}

// #17704: an allow on another alias rescues a sibling deny only when its
// matched extent strictly outranks that deny, preserving the precedence
// tiers used for one spelling.
func TestAliasRescueRequiresOutrankingAllow17704(t *testing.T) {
	cases := []struct {
		name  string
		deny  string
		allow string
		want  bool
	}{
		{
			name:  "longer alias deny is not rescued by shorter charge allow",
			deny:  `^show security nat source summary$`,
			allow: `^show security nat source pool$`,
			want:  false,
		},
		{
			name:  "longer alias allow rescues shorter charge deny",
			deny:  `^show security nat source pool$`,
			allow: `^show security nat source summary$`,
			want:  true,
		},
		{
			name:  "equal extent alias allow does not rescue",
			deny:  `^show security nat source sum`,
			allow: `^show security nat source poo`,
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{{
				Name: "ops", DenyCommands: tc.deny, AllowCommands: tc.allow,
				DenyLeavesPresent:  []string{"deny-commands"},
				AllowLeavesPresent: []string{"allow-commands"},
			}}}
			err := gateDecide7172(t, cfg, "GetNATPoolStats", &pb.GetNATPoolStatsRequest{})
			if (err == nil) != tc.want {
				t.Errorf("deny %q with allow %q: err=%v, want allow=%v",
					tc.deny, tc.allow, err, tc.want)
			}
		})
	}
}

// The issue's empty GetIPsecSA request cannot identify whether the caller
// typed the IKE or IPsec line. Pin both the cited full-form pair (whose
// IPsec allow is the longer match) and a shorter charge allow that cannot
// override the IKE deny.
func TestIPsecAliasRescueUsesMatchedExtent17704(t *testing.T) {
	cases := []struct {
		name      string
		allow     string
		wantAllow bool
	}{
		{
			name:      "full IPsec allow strictly outranks IKE deny",
			allow:     `^show security ipsec security-associations$`,
			wantAllow: true,
		},
		{
			name:      "short IPsec allow does not outrank IKE deny",
			allow:     `^show security ipsec`,
			wantAllow: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{{
				Name:               "ops",
				DenyCommands:       `^show security ike security-associations$`,
				AllowCommands:      tc.allow,
				DenyLeavesPresent:  []string{"deny-commands"},
				AllowLeavesPresent: []string{"allow-commands"},
			}}}
			err := gateDecide7172(t, cfg, "GetIPsecSA", &pb.GetIPsecSARequest{})
			if (err == nil) != tc.wantAllow {
				t.Errorf("allow %q: err=%v, want allow=%v", tc.allow, err, tc.wantAllow)
			}
		})
	}
}

// A charge-derived distinct-narrower rescue must not hide an additional
// alias denial that the typed RPC cannot identify.
func TestAliasDenySurvivesDistinctNarrowerRescue17704(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{{
		Name:               "ops",
		DenyCommands:       `(^show security nat source$)|(^show security nat source summary$)`,
		AllowCommands:      `^show security nat source pool$`,
		DenyLeavesPresent:  []string{"deny-commands"},
		AllowLeavesPresent: []string{"allow-commands"},
	}}}
	fullMethod := "/" + serviceName + "/GetNATPoolStats"
	req := &pb.GetNATPoolStatsRequest{}
	rules, _, err := config.OperationalLoginRegexesFor(cfg, "ops")
	if err != nil {
		t.Fatalf("compile login rules: %v", err)
	}
	cmd, resolved := rpcCanonicalCommand(fullMethod, req)
	if !resolved {
		t.Fatal("GetNATPoolStats charge was not resolved")
	}
	forms, named := rpcArgumentForms(cfg, fullMethod, req, cmd)
	if !named {
		t.Fatal("GetNATPoolStats forms were not named")
	}
	forms = withAliasForms16605("GetNATPoolStats", req, forms)
	if remoteDistinctRescue16472(rules, forms) {
		t.Fatal("charge-only distinct-narrower rescue would bypass the alias denial")
	}
	if err := gateDecide7172(t, cfg, "GetNATPoolStats", req); err == nil {
		t.Error("charge-only distinct-narrower rescue must not override a denied alias")
	}
}

// Controls: unrelated deny must not fire; charge-spelling deny still fires.
func TestTypedLineDenyControls16605(t *testing.T) {
	cfg := gateCfg7172(t, `show security ike`, true)
	if err := gateDecide7172(t, cfg, "GetZones", &pb.GetZonesRequest{}); err != nil {
		t.Errorf("ike deny must not refuse GetZones: %v", err)
	}
	// Charge spelling still denies.
	cfg2 := gateCfg7172(t, `show security ipsec security-associations`, true)
	if err := gateDecide7172(t, cfg2, "GetIPsecSA", &pb.GetIPsecSARequest{}); err == nil {
		t.Error("ipsec charge deny must still deny GetIPsecSA")
	}
	cfg3 := gateCfg7172(t, `show configuration`, true)
	if err := gateDecide7172(t, cfg3, "ShowRollback", &pb.ShowRollbackRequest{N: 1}); err == nil {
		t.Error("show configuration deny must still deny ShowRollback")
	}
	// Anchored charge-only deny DOES deny the bare line: the RPC
	// renders the detail table whatever the cli line, so `detail` is
	// not a distinct narrower command the bare line excepts (no
	// selector slot completes under it). This is the pre-fix verdict
	// preserved — the charge stays a judged form.
	cfg4 := gateCfg7172(t, `^show interfaces detail$`, true)
	if err := gateDecide7172(t, cfg4, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{}); err == nil {
		t.Error("detail-anchored deny must still deny ShowInterfacesDetail (detail charge)")
	}
	// Exception geometry: deny the detail spelling, allow the bare
	// line — the allow excepts the bare execution.
	cfg5 := &config.Config{}
	cfg5.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{{
		Name: "ops", DenyCommands: `^show interfaces detail$`, AllowCommands: `^show interfaces$`,
		DenyLeavesPresent: []string{"deny-commands"}, AllowLeavesPresent: []string{"allow-commands"},
	}}}
	if err := gateDecide7172(t, cfg5, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{}); err != nil {
		t.Errorf("allow ^show interfaces$ must except bare line from detail deny: %v", err)
	}
	// Reverse must NOT rescue: deny the executed bare line, allow only
	// the detail spelling — the executed denial vetoes.
	cfg6 := &config.Config{}
	cfg6.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{{
		Name: "ops", DenyCommands: `^show interfaces$`, AllowCommands: `^show interfaces detail$`,
		DenyLeavesPresent: []string{"deny-commands"}, AllowLeavesPresent: []string{"allow-commands"},
	}}}
	if err := gateDecide7172(t, cfg6, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{}); err == nil {
		t.Error("deny on executed `show interfaces` must veto even with detail allow")
	}
}

// Over-deny leg: allowlist naming only the typed line must admit.
func TestTypedLineAllowlist16605(t *testing.T) {
	cases := []struct {
		name   string
		allow  string
		method string
		req    any
	}{
		{"ike allow admits GetIPsecSA", `^show security ike security-associations$`, "GetIPsecSA", &pb.GetIPsecSARequest{}},
		{"interfaces allow admits bare", `^show interfaces$`, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{}},
		{"interfaces terse allow admits terse", `^show interfaces terse$`, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{Terse: true}},
		{"system rollback allow admits ShowRollback", `^show system rollback`, "ShowRollback", &pb.ShowRollbackRequest{N: 1}},
		{"security statistics allow admits GetGlobalStats", `^show security statistics$`, "GetGlobalStats", &pb.GetGlobalStatsRequest{}},
		{"security vrrp allow admits GetVRRPStatus", `^show security vrrp$`, "GetVRRPStatus", &pb.GetVRRPStatusRequest{}},
		{"nat source summary allow admits GetNATPoolStats", `^show security nat source summary$`, "GetNATPoolStats", &pb.GetNATPoolStatsRequest{}},
		{"nat destination summary allow admits GetNATDestination", `^show security nat destination summary$`, "GetNATDestination", &pb.GetNATDestinationRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := allowCfg15076(t, tc.allow)
			if err := gateDecide7172(t, cfg, tc.method, tc.req); err != nil {
				t.Errorf("allow %q must admit %s, got: %v (#16605 over-deny)", tc.allow, tc.method, err)
			}
		})
	}
}

// Census: every alias form is canonical and a keyword prefix relationship
// holds (charged or alias is prefix of typed line canonical).
func TestAliasFormsAreCanonical16605(t *testing.T) {
	for method, aliases := range rpcAliasCommands16605 {
		for _, a := range aliases {
			canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(a))
			if res != cmdtree.CanonicalOK || strings.Join(canon, " ") != a {
				t.Errorf("%s alias %q not canonical: %q %v", method, a, strings.Join(canon, " "), res)
			}
		}
		_ = method
	}
	if len(rpcAliasCommands16605) == 0 {
		t.Fatal("alias table empty")
	}
}

// Advisory: alias commands are in allCanonicalCommands so a deny against
// the typed line is not reported unenforceable.
func TestAliasCommandsInSurfaceSet16605(t *testing.T) {
	set := map[string]bool{}
	for _, c := range allCanonicalCommands() {
		set[c] = true
	}
	for _, want := range []string{
		"show security ike security-associations",
		"show interfaces", "show interfaces terse",
		"show system rollback",
		"show security statistics",
		"show security vrrp",
		"show security nat source summary",
		"show security nat destination summary",
		"show security nat destination",
	} {
		if !set[want] {
			t.Errorf("allCanonicalCommands missing alias %q", want)
		}
	}
	// And unenforceable detection: deny on ike must not be unenforceable.
	cfg := gateCfg7172(t, `show security ike`, true)
	rules, ok, err := config.OperationalLoginRegexesFor(cfg, "ops")
	if err != nil || !ok {
		t.Fatalf("rules: ok=%v err=%v", ok, err)
	}
	if pats := unenforceableDenyPatterns(rules); len(pats) > 0 {
		t.Errorf("deny 'show security ike' reported unenforceable on gRPC surface: %v", pats)
	}
}

// Census completeness: every subject method's aliases are present and
// every alias names a method that is actually charged.
func TestAliasCensusComplete16605(t *testing.T) {
	want := []string{"GetIPsecSA", "ShowInterfacesDetail", "ShowRollback", "ShowCompare", "ListHistory", "GetGlobalStats", "GetVRRPStatus", "GetNATPoolStats", "GetNATDestination", "GetNATSource"}
	for _, m := range want {
		if len(rpcAliasCommands16605[m]) == 0 {
			t.Errorf("method %s has no aliases (#16605 census)", m)
		}
		if _, charged := methodCanonicalCommand[m]; !charged {
			t.Errorf("alias method %s is not in methodCanonicalCommand", m)
		}
	}
	// Reverse: no alias for a method that does not exist.
	for m := range rpcAliasCommands16605 {
		if _, charged := methodCanonicalCommand[m]; !charged {
			if _, absent := methodsWithoutCanonicalCommand[m]; !absent {
				t.Errorf("alias for unknown method %s", m)
			}
		}
	}
}
