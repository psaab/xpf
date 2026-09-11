package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func loginCfg9633(lc *config.LoginClass) *config.Config {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{lc}}
	return cfg
}

func method9633(m string) string { return "/" + serviceName + "/" + m }

// TestDocumentedDenyCommandsClassCanConfigureOverGRPC9633 is the V069 cell: the
// docs/system-login.md `limited` class must be able to configure over gRPC, and
// must still be refused what its operational pattern denies.
func TestDocumentedDenyCommandsClassCanConfigureOverGRPC9633(t *testing.T) {
	cfg := loginCfg9633(&config.LoginClass{
		Name: "ops", Permissions: []string{"all"},
		DenyCommands: "request system zeroize", DenyLeavesPresent: []string{"deny-commands"},
	})
	s := &Server{}
	for _, tc := range []struct {
		method string
		req    any
	}{
		{"EnterConfigure", &pb.EnterConfigureRequest{}},
		{"Set", &pb.SetRequest{Input: "system host-name x"}},
		{"Delete", &pb.DeleteRequest{Input: "system host-name"}},
		{"Load", &pb.LoadRequest{Mode: "merge", Content: "system { host-name x; }"}},
		{"Commit", &pb.CommitRequest{}},
		{"CommitCheck", nil},
		{"Rollback", &pb.RollbackRequest{N: 1}},
		{"ExitConfigure", nil},
	} {
		if err := s.authorizeRPCCommand(cfg, "ops", method9633(tc.method), tc.req); err != nil {
			t.Errorf("%s: an operational deny-commands pattern must not govern a config-mode RPC: %v", tc.method, err)
		}
	}
	if err := s.authorizeRPCCommand(cfg, "ops", method9633("SystemAction"), &pb.SystemActionRequest{Action: "zeroize"}); err == nil {
		t.Error("the class's own deny-commands pattern must still refuse zeroize")
	}
}

// reviewedConfigModeMethods9633 is the config-mode RPC list as reviewed for
// #9633, spelled independently of the production exempt set so the cells
// below can detect a change to that set in either direction.
var reviewedConfigModeMethods9633 = map[string]bool{
	"EnterConfigure": true, "ExitConfigure": true, "Set": true, "Delete": true,
	"Load": true, "Commit": true, "CommitCheck": true, "CommitConfirmed": true,
	"ConfirmCommit": true, "Rollback": true, "Complete": true,
}

// TestUnresolvedOperationalMethodsStayDenied9633: the exemption is the
// config-mode set only. Every other method without a canonical command is still
// refused for a class with operational regexes.
func TestUnresolvedOperationalMethodsStayDenied9633(t *testing.T) {
	cfg := loginCfg9633(&config.LoginClass{
		Name: "ops", DenyCommands: "request system zeroize", DenyLeavesPresent: []string{"deny-commands"},
	})
	s := &Server{}
	checked := 0
	for method := range methodsWithoutCanonicalCommand {
		// Skip by the REVIEWED literal, never by configModeMethods9633: a cell
		// that reads the set it guards cannot see a method wrongly added to it
		// (the matrix's A2 mutant exempted GetOSPFStatus and this cell skipped it).
		if reviewedConfigModeMethods9633[method] || method == "ShowText" || method == "SystemAction" {
			continue
		}
		checked++
		if err := s.authorizeRPCCommand(cfg, "ops", method9633(method), nil); err == nil {
			t.Errorf("%s has no canonical command and is not config-mode; it must stay denied", method)
		}
	}
	if checked == 0 {
		t.Fatal("no non-config unresolved method was checked; this cell would pass having checked nothing")
	}
}

// TestConfigModeMethodsAreDeliberatelyUnmapped9633 binds the exemption set to
// the reviewed table, so a method cannot enter it without a stated reason.
func TestConfigModeMethodsAreDeliberatelyUnmapped9633(t *testing.T) {
	if len(configModeMethods9633) != len(reviewedConfigModeMethods9633) {
		t.Errorf("exempt set has %d methods, the reviewed list %d", len(configModeMethods9633), len(reviewedConfigModeMethods9633))
	}
	for method := range reviewedConfigModeMethods9633 {
		if !configModeMethods9633[method] {
			t.Errorf("%s is a config-mode RPC but is not exempted from the operational gate", method)
		}
	}
	for method := range configModeMethods9633 {
		if !reviewedConfigModeMethods9633[method] {
			t.Errorf("%s is exempted from the operational gate but is not in the reviewed config-mode list", method)
		}
		if _, ok := methodsWithoutCanonicalCommand[method]; !ok {
			t.Errorf("%s is exempted from the operational gate but has no entry in methodsWithoutCanonicalCommand", method)
		}
	}
}

// TestLoadAndRollbackMeetTheConfigurationRegexes9633 is the other half: with
// config-mode RPCs out of the operational gate, a class whose deny-configuration
// forbids a path cannot write it through ANY config RPC.
func TestLoadAndRollbackMeetTheConfigurationRegexes9633(t *testing.T) {
	cfg := loginCfg9633(&config.LoginClass{
		Name: "ops", Permissions: []string{"all"},
		DenyConfiguration: "system host-name", DenyLeavesPresent: []string{"deny-configuration"},
	})
	s := &Server{}
	for _, tc := range []struct {
		name  string
		req   any
		deny  bool
		label string
	}{
		{"set-format load writing the denied path", &pb.LoadRequest{Mode: "set", Content: "set interfaces ge-0/0/0 description y\nset system host-name x"}, true, "Load"},
		{"hierarchical merge writing the denied path", &pb.LoadRequest{Mode: "merge", Content: "system {\n    host-name x;\n}\n"}, true, "Load"},
		{"merge that avoids the denied path", &pb.LoadRequest{Mode: "merge", Content: "interfaces {\n    ge-0/0/0 {\n        description y;\n    }\n}\n"}, false, "Load"},
		{"override", &pb.LoadRequest{Mode: "override", Content: "interfaces {\n    ge-0/0/0 {\n        description y;\n    }\n}\n"}, true, "Load"},
		{"rollback 1", &pb.RollbackRequest{N: 1}, true, "Rollback"},
		{"rollback 0", &pb.RollbackRequest{N: 0}, false, "Rollback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.authorizeRPCConfigMutation(cfg, "ops", method9633(tc.label), tc.req)
			if tc.deny && err == nil {
				t.Fatalf("%s must be refused for a class whose deny-configuration forbids system host-name", tc.name)
			}
			if !tc.deny && err != nil {
				t.Fatalf("%s must be allowed: %v", tc.name, err)
			}
			if tc.deny && !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("refusal must read as a permission denial: %v", err)
			}
		})
	}
	// Control: a class with no configuration regexes is not restricted by any of it.
	open := loginCfg9633(&config.LoginClass{Name: "ops", Permissions: []string{"all"}})
	for _, req := range []any{&pb.LoadRequest{Mode: "override", Content: "system { host-name x; }"}, &pb.RollbackRequest{N: 3}} {
		label := "Load"
		if _, ok := req.(*pb.RollbackRequest); ok {
			label = "Rollback"
		}
		if err := s.authorizeRPCConfigMutation(open, "ops", method9633(label), req); err != nil {
			t.Errorf("an unrestricted class must not be refused %s: %v", label, err)
		}
	}
}
