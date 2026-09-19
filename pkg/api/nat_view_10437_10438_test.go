package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/natshow"
)

// natView10437CommitStore builds a committed config from flat set lines. Shapes
// the strict gate accepts (plural lists, address-book names, off/interface/pool
// actions) go through here; the actionless shape #7640 rejects at commit uses
// natView10438SyncStore instead.
func natView10437CommitStore(t *testing.T, lines []string) *configstore.Store {
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

// natView10438SyncStore applies hierarchical config through the TOLERANT
// peer-sync ingress (the path by which an actionless rule actually reaches an
// operator surface: HA peer-sync, boot, rollback), mirroring natRESTServer.
func natView10438SyncStore(t *testing.T, content string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(content, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	return store
}

func natView10437FindDestRule(t *testing.T, cfg *config.Config, name string) *config.NATRule {
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
	t.Fatalf("PREMISE: destination rule %q must be present in the compiled config", name)
	return nil
}

func natView10438FindSourceRule(t *testing.T, cfg *config.Config, name string) *config.NATRule {
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
	t.Fatalf("PREMISE: source rule %q must be present in the compiled config", name)
	return nil
}

// TestRESTNATDestCarriesCompleteMatch_10437 is the fail-on-revert guard for
// #10437: natDestHandler copied only rule.Match.DestinationAddress, so a rule
// matching a bracketed prefix list rendered first-only and a rule scoped by an
// address-book name rendered blank. Both must carry the shared canonical
// rendering from natshow.RuleMatchDestination.
func TestRESTNATDestCarriesCompleteMatch_10437(t *testing.T) {
	store := natView10437CommitStore(t, []string{
		"set security address-book global address web-net 203.0.113.0/24",
		"set security nat destination pool dp1 address 10.0.0.5",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule dr-plural match destination-address [ 203.0.113.10/32 203.0.113.11/32 ]",
		"set security nat destination rule-set drs rule dr-plural then destination-nat pool dp1",
		"set security nat destination rule-set drs rule dr-name match destination-address-name web-net",
		"set security nat destination rule-set drs rule dr-name then destination-nat pool dp1",
	})
	s := NewServer(Config{Addr: "127.0.0.1:0", Store: store})

	cfg := store.ActiveConfig()
	pluralRule := natView10437FindDestRule(t, cfg, "dr-plural")
	nameRule := natView10437FindDestRule(t, cfg, "dr-name")
	// Fixture sanity, not code under test: the comparison below is vacuous
	// unless the compiled rules actually carry the plural/name shapes.
	if len(pluralRule.Match.DestinationAddresses) != 2 {
		t.Fatalf("PREMISE: dr-plural must compile 2 destination addresses, got %q",
			pluralRule.Match.DestinationAddresses)
	}
	if nameRule.Match.DestinationAddressName != "web-net" {
		t.Fatalf("PREMISE: dr-name must be scoped by address-book name web-net, got %q",
			nameRule.Match.DestinationAddressName)
	}

	rec := httptest.NewRecorder()
	s.natDestHandler(rec, httptest.NewRequest(http.MethodGet, "/nat/destination", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("natDestHandler status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var env struct {
		Data []NATDestInfo `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	byName := map[string]NATDestInfo{}
	for _, info := range env.Data {
		byName[info.Name] = info
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
			t.Errorf("#10437: REST destination view omits rule %q entirely", tc.name)
			continue
		}
		want := natshow.RuleMatchDestination(tc.rule)
		if got.DstAddr != want {
			t.Errorf("#10437: REST reports dst_addr %q for rule %q where "+
				"pkg/natshow renders %q", got.DstAddr, tc.name, want)
		}
		for _, criterion := range tc.want {
			if !strings.Contains(got.DstAddr, criterion) {
				t.Errorf("#10437: REST dst_addr %q for rule %q silently drops "+
					"match criterion %q", got.DstAddr, tc.name, criterion)
			}
		}
		// Controls: reporting-only. The translation action and the #7473
		// verdict wiring must be untouched by the match-rendering fix.
		if got.TranslateIP != "10.0.0.5" {
			t.Errorf("#10437 control: rule %q translate_ip = %q, want 10.0.0.5 "+
				"(the fix must not alter the reported action)", tc.name, got.TranslateIP)
		}
		wantNotInstalled := config.DestinationNATRuleNotInstalledReason(cfg, tc.rule) != ""
		if got.NotInstalled != wantNotInstalled {
			t.Errorf("#10437 control: rule %q not_installed = %v, predicate says %v",
				tc.name, got.NotInstalled, wantNotInstalled)
		}
		if tc.rule.Then.PoolName != "dp1" {
			t.Errorf("#10437 control: rule %q compiled Then.PoolName = %q, want dp1 "+
				"(the handler must not mutate the rule)", tc.name, tc.rule.Then.PoolName)
		}
	}
}

// TestRESTNATSourceActionAndMatch_10438 is the fail-on-revert guard for #10438:
// natSourceHandler set Type only for Then.Interface/Then.PoolName (Then.Off and
// actionless rules serialized with an empty Type) and exposed no source match
// at all. Type must come from natshow.SourceRuleAction and the canonical
// source match from natshow.RuleMatchSource.
func TestRESTNATSourceActionAndMatch_10438(t *testing.T) {
	committed := natView10437CommitStore(t, []string{
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
	// Actionless: no `then` at all. The strict gate rejects it, so it arrives
	// via the tolerant ingress like every other rule of this shape.
	actionless := natView10438SyncStore(t,
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
		rule := natView10438FindSourceRule(t, cfg, tc.rule)
		s := NewServer(Config{Addr: "127.0.0.1:0", Store: tc.store})
		rec := httptest.NewRecorder()
		s.natSourceHandler(rec, httptest.NewRequest(http.MethodGet, "/nat/source", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("natSourceHandler(%s) status = %d, want 200 (body %s)",
				tc.rule, rec.Code, rec.Body.String())
		}
		var env struct {
			Data []NATSourceInfo `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode(%s): %v (body %s)", tc.rule, err, rec.Body.String())
		}
		// Raw decode for the additive match field: typed access cannot express
		// "key absent", which is exactly the pre-fix defect.
		var raw struct {
			Data []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("raw decode(%s): %v", tc.rule, err)
		}
		if len(env.Data) <= tc.row || len(raw.Data) <= tc.row {
			t.Fatalf("#10438: rule %q fixture must render row %d (got %d rows)",
				tc.rule, tc.row, len(env.Data))
		}
		got := env.Data[tc.row]
		rawRow := raw.Data[tc.row]
		if got.Type != tc.wantType {
			t.Errorf("#10438: REST reports type %q for rule %q, want %q "+
				"(natshow renders %q)", got.Type, tc.rule, tc.wantType,
				natshow.SourceRuleAction(rule))
		}
		if got.Pool != tc.wantPool {
			t.Errorf("#10438: REST reports pool %q for rule %q, want %q",
				got.Pool, tc.rule, tc.wantPool)
		}
		wantMatch := natshow.RuleMatchSource(rule)
		rawMatch, ok := rawRow["source_match"].(string)
		if !ok || rawMatch == "" {
			t.Errorf("#10438: REST source row for rule %q carries no source_match "+
				"(natshow renders %q)", tc.rule, wantMatch)
		} else {
			if rawMatch != wantMatch {
				t.Errorf("#10438: REST reports source_match %q for rule %q where "+
					"pkg/natshow renders %q", rawMatch, tc.rule, wantMatch)
			}
			for _, criterion := range tc.wantMatches {
				if !strings.Contains(rawMatch, criterion) {
					t.Errorf("#10438: REST source_match %q for rule %q silently "+
						"drops match criterion %q", rawMatch, tc.rule, criterion)
				}
			}
		}
		// Controls: reporting-only. The compiled action and the #7473 verdict
		// wiring must be untouched by the rendering fix.
		wantNotInstalled := config.SourceNATRuleNotInstalledReason(cfg, rule) != ""
		if got.NotInstalled != wantNotInstalled {
			t.Errorf("#10438 control: rule %q not_installed = %v, predicate says %v",
				tc.rule, got.NotInstalled, wantNotInstalled)
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
