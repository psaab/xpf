package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/natshow"
)

// natViewGRPC10437CommitStore builds a committed config from flat set lines.
func natViewGRPC10437CommitStore(t *testing.T, lines []string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

func natViewGRPC10438SyncStore(t *testing.T, content string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(content, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	return store
}

func natViewGRPC10437FindDestRule(t *testing.T, cfg *config.Config, name string) *config.NATRule {
	t.Helper()
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		t.Fatal("PREMISE: destination NAT config must be present")
	}
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, rule := range rs.Rules {
			if rule.Name == name {
				return rule
			}
		}
	}
	t.Fatalf("PREMISE: destination rule %q must be present in compiled config", name)
	return nil
}

func natViewGRPC10438FindSourceRule(t *testing.T, cfg *config.Config, name string) *config.NATRule {
	t.Helper()
	if cfg == nil {
		t.Fatal("PREMISE: config must be present")
	}
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Name == name {
				return rule
			}
		}
	}
	t.Fatalf("PREMISE: source rule %q must be present in compiled config", name)
	return nil
}

// TestGetNATDestinationCarriesCompleteMatch_10437 is the fail-on-revert guard
// for #10437: GetNATDestination copied only the singular destination CIDR.
func TestGetNATDestinationCarriesCompleteMatch_10437(t *testing.T) {
	store := natViewGRPC10437CommitStore(t, []string{
		"set security address-book global address web-net 203.0.113.0/24",
		"set security nat destination pool dp1 address 10.0.0.5",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule dr-plural match destination-address [ 203.0.113.10/32 203.0.113.11/32 ]",
		"set security nat destination rule-set drs rule dr-plural then destination-nat pool dp1",
		"set security nat destination rule-set drs rule dr-name match destination-address-name web-net",
		"set security nat destination rule-set drs rule dr-name then destination-nat pool dp1",
	})
	s := &Server{store: store}
	cfg := store.ActiveConfig()
	pluralRule := natViewGRPC10437FindDestRule(t, cfg, "dr-plural")
	nameRule := natViewGRPC10437FindDestRule(t, cfg, "dr-name")
	if len(pluralRule.Match.DestinationAddresses) != 2 {
		t.Fatalf("PREMISE: dr-plural must compile 2 destination addresses, got %q",
			pluralRule.Match.DestinationAddresses)
	}
	if nameRule.Match.DestinationAddressName != "web-net" {
		t.Fatalf("PREMISE: dr-name must be scoped by address-book name web-net, got %q",
			nameRule.Match.DestinationAddressName)
	}

	resp, err := s.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
	if err != nil {
		t.Fatalf("GetNATDestination: %v", err)
	}
	byName := map[string]*pb.NATDestInfo{}
	for _, info := range resp.GetRules() {
		byName[info.GetName()] = info
	}
	for _, tc := range []struct {
		name string
		rule *config.NATRule
		want []string
	}{
		{"dr-plural", pluralRule, []string{"203.0.113.10/32", "203.0.113.11/32"}},
		{"dr-name", nameRule, []string{"web-net"}},
	} {
		got, ok := byName[tc.name]
		if !ok {
			t.Errorf("#10437: gRPC destination view omits rule %q entirely", tc.name)
			continue
		}
		want := natshow.RuleMatchDestination(tc.rule)
		if got.GetDstAddr() != want {
			t.Errorf("#10437: gRPC reports dst_addr %q for rule %q where "+
				"pkg/natshow renders %q", got.GetDstAddr(), tc.name, want)
		}
		for _, criterion := range tc.want {
			if !strings.Contains(got.GetDstAddr(), criterion) {
				t.Errorf("#10437: gRPC dst_addr %q for rule %q silently drops "+
					"match criterion %q", got.GetDstAddr(), tc.name, criterion)
			}
		}
		if got.GetTranslateIp() != "10.0.0.5" {
			t.Errorf("#10437 control: rule %q translate_ip = %q, want 10.0.0.5",
				tc.name, got.GetTranslateIp())
		}
		wantNotInstalled := config.DestinationNATRuleNotInstalledReason(cfg, tc.rule) != ""
		if got.GetNotInstalled() != wantNotInstalled {
			t.Errorf("#10437 control: rule %q not_installed = %v, predicate says %v",
				tc.name, got.GetNotInstalled(), wantNotInstalled)
		}
	}
}

// TestGetNATSourceActionAndMatch_10438 is the fail-on-revert guard for #10438.
func TestGetNATSourceActionAndMatch_10438(t *testing.T) {
	committed := natViewGRPC10437CommitStore(t, []string{
		"set security address-book global address trusted 10.0.0.0/8",
		"set security address-book global address corp 172.16.0.0/12",
		"set security nat source pool p1 address 203.0.113.10/32",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r-off match source-address 10.1.0.0/16",
		"set security nat source rule-set rs rule r-off then source-nat off",
		"set security nat source rule-set rs rule r-multi match source-address [ 10.2.0.0/16 10.3.0.0/16 ]",
		"set security nat source rule-set rs rule r-multi then source-nat interface",
		"set security nat source rule-set rs rule r-book match source-address-name [ trusted corp ]",
		"set security nat source rule-set rs rule r-book then source-nat pool p1",
	})
	actionless := natViewGRPC10438SyncStore(t,
		"security {\nnat {\nsource {\n"+
			"rule-set rs2 {\nfrom zone trust;\nto zone untrust;\n"+
			"rule r-none {\nmatch { source-address 10.9.0.0/16; }\n}\n}\n}\n}\n}\n")

	type sourceCase struct {
		store       *configstore.Store
		rule        string
		row         int
		wantType    string
		wantPool    string
		wantMatches []string
	}
	for _, tc := range []sourceCase{
		{committed, "r-off", 0, "off", "", []string{"10.1.0.0/16"}},
		{committed, "r-multi", 1, "interface", "", []string{"10.2.0.0/16", "10.3.0.0/16"}},
		{committed, "r-book", 2, "pool", "p1", []string{"trusted", "corp"}},
		{actionless, "r-none", 0, "none", "", []string{"10.9.0.0/16"}},
	} {
		cfg := tc.store.ActiveConfig()
		rule := natViewGRPC10438FindSourceRule(t, cfg, tc.rule)
		s := &Server{store: tc.store}
		resp, err := s.GetNATSource(context.Background(), &pb.GetNATSourceRequest{})
		if err != nil {
			t.Fatalf("GetNATSource(%s): %v", tc.rule, err)
		}
		if len(resp.GetRules()) <= tc.row {
			t.Fatalf("#10438: rule %q fixture must render row %d (got %d rows)",
				tc.rule, tc.row, len(resp.GetRules()))
		}
		got := resp.GetRules()[tc.row]
		if got.GetType() != tc.wantType {
			t.Errorf("#10438: gRPC reports type %q for rule %q, want %q (natshow renders %q)",
				got.GetType(), tc.rule, tc.wantType, natshow.SourceRuleAction(rule))
		}
		if got.GetPool() != tc.wantPool {
			t.Errorf("#10438: gRPC reports pool %q for rule %q, want %q",
				got.GetPool(), tc.rule, tc.wantPool)
		}
		wantMatch := natshow.RuleMatchSource(rule)
		if got.GetSourceMatch() != wantMatch {
			t.Errorf("#10438: gRPC reports source_match %q for rule %q where "+
				"pkg/natshow renders %q", got.GetSourceMatch(), tc.rule, wantMatch)
		}
		for _, criterion := range tc.wantMatches {
			if !strings.Contains(got.GetSourceMatch(), criterion) {
				t.Errorf("#10438: gRPC source_match %q for rule %q silently drops "+
					"match criterion %q", got.GetSourceMatch(), tc.rule, criterion)
			}
		}
		wantNotInstalled := config.SourceNATRuleNotInstalledReason(cfg, rule) != ""
		if got.GetNotInstalled() != wantNotInstalled {
			t.Errorf("#10438 control: rule %q not_installed = %v, predicate says %v",
				tc.rule, got.GetNotInstalled(), wantNotInstalled)
		}
		switch tc.rule {
		case "r-off":
			if !rule.Then.Off {
				t.Errorf("#10438 control: r-off compiled Then.Off = false")
			}
		case "r-multi":
			if !rule.Then.Interface {
				t.Errorf("#10438 control: r-multi compiled Then.Interface = false")
			}
		case "r-book":
			if rule.Then.PoolName != "p1" {
				t.Errorf("#10438 control: r-book compiled Then.PoolName = %q", rule.Then.PoolName)
			}
		case "r-none":
			if rule.Then.Off || rule.Then.Interface || rule.Then.PoolName != "" {
				t.Errorf("#10438 control: r-none must stay actionless, got %+v", rule.Then)
			}
		}
	}
}
