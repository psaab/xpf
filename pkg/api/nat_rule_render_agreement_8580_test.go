package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/natshow"
)

// #8580: the REST rule-stats handler computed a rule's action and address match
// from its own copy of the switch, so two fixes that landed in `pkg/natshow`
// were live-defective here — `then source-nat off` reported as `"interface"`,
// its exact opposite (#7640), and an address-book-scoped rule reported as
// `0.0.0.0/0`, i.e. matching every source (#7363).
//
// This cell drives the REAL handler and compares against `pkg/natshow`'s
// answer, not against a literal. Comparing to a literal would encode which
// surface is trusted, and the defect is precisely that the surfaces disagreed
// (#8258's predicate). Comparing to the shared computation also means the cell
// keeps holding if the rendered spelling ever changes deliberately.

func natRenderStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address trusted 10.0.0.0/8",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		// The two shapes the private copy got wrong, in ONE rule.
		"set security nat source rule-set rs1 rule r-off match source-address-name trusted",
		"set security nat source rule-set rs1 rule r-off then source-nat off",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

func TestRESTNATRuleStatsAgreesWithNatshow_8580(t *testing.T) {
	store := natRenderStore(t)
	s := NewServer(Config{Addr: "127.0.0.1:0", Store: store})

	rec := httptest.NewRecorder()
	s.natRuleStatsHandler(rec, httptest.NewRequest(http.MethodGet, "/nat/rule-stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("rule-stats status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var env struct {
		Data []NATRuleStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if len(env.Data) == 0 {
		t.Fatal("PREMISE: the handler must render the configured rule, or this cell is vacuous")
	}

	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("PREMISE: the committed config must be active")
	}
	var found bool
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Name != "r-off" {
				continue
			}
			found = true
			wantAction := natshow.SourceRuleAction(rule)
			wantSrc := natshow.RuleMatchSource(rule)
			// Sanity on the FIXTURE, not the code under test: if the config did
			// not actually carry `off` and an address-book name, the comparison
			// below would be between two copies of the same wrong answer.
			if wantAction != "off" {
				t.Fatalf("PREMISE: the fixture rule must carry `then source-nat off`; "+
					"natshow renders it as %q", wantAction)
			}
			if wantSrc != "trusted" {
				t.Fatalf("PREMISE: the fixture rule must be scoped by an address-book NAME; "+
					"natshow renders its source match as %q", wantSrc)
			}
			for _, got := range env.Data {
				if got.RuleName != "r-off" {
					continue
				}
				if got.Action != wantAction {
					t.Errorf("#8580: REST reports action %q for a rule pkg/natshow renders as %q. "+
						"`then source-nat off` is a no-NAT EXEMPTION; reporting it as %q says the "+
						"rule does the opposite of what it does.", got.Action, wantAction, got.Action)
				}
				if got.SrcMatch != wantSrc {
					t.Errorf("#8580: REST reports source match %q where pkg/natshow renders %q. "+
						"An address-book-scoped rule reported as 0.0.0.0/0 reads as matching "+
						"EVERY source.", got.SrcMatch, wantSrc)
				}
			}
		}
	}
	if !found {
		t.Fatal("PREMISE: rule r-off must be present in the compiled config")
	}
}
