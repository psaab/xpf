package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6853 WIRING. The config compiler recording `then syslog` is worth nothing
// if the bit stops at the compiler, so this binds the two hops that carry it:
// the compiled term -> FirewallTermSnapshot, and the snapshot -> its rendered
// form. Asserting only the compiler would leave a deleted assignment in
// filters.go completely invisible.
func TestThenSyslogReachesTheSnapshot_6853(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {
			Name: "f",
			Terms: []*config.FirewallFilterTerm{
				{Name: "only_log", Action: config.FilterActionAccept, Log: true},
				{Name: "only_syslog", Action: config.FilterActionAccept, Log: true, Syslog: true},
			},
		},
	}

	snaps := BuildFirewallFilterSnapshots(cfg)
	var terms []FirewallTermSnapshot
	for _, s := range snaps {
		if s.Name == "f" {
			terms = s.Terms
		}
	}
	if len(terms) != 2 {
		t.Fatalf("expected 2 terms in the snapshot, got %d: %+v", len(terms), terms)
	}
	byName := map[string]FirewallTermSnapshot{}
	for _, tm := range terms {
		byName[tm.Name] = tm
	}
	if got := byName["only_log"]; got.Syslog {
		t.Errorf("term only_log: Syslog = true, want false")
	}
	if got := byName["only_syslog"]; !got.Syslog {
		t.Errorf("term only_syslog: Syslog = false — the compiled bit did not reach the "+
			"snapshot, so the dataplane cannot tell the two actions apart. Got %+v", got)
	}
	if got := byName["only_syslog"]; !got.Log {
		t.Errorf("term only_syslog: Log = false — Log is what makes the term emit a " +
			"filter-log event at all; dropping it stops `then syslog` producing anything")
	}
}

// The field must be ADDITIVE on the wire: a helper that predates it, and one
// that has it, must both stay compatible. `omitempty` means a term without
// syslog serialises exactly as it did before the field existed, which is what
// keeps a mixed-version HA pair working (#1961).
func TestThenSyslogIsAdditiveOnTheWire_6853(t *testing.T) {
	plain, err := json.Marshal(FirewallTermSnapshot{Name: "t", Log: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(plain), "syslog") {
		t.Errorf("a term with no syslog action must serialise with NO syslog key, or an "+
			"older helper sees a field it cannot parse. Got: %s", plain)
	}
	withSyslog, err := json.Marshal(FirewallTermSnapshot{Name: "t", Log: true, Syslog: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(withSyslog), `"syslog":true`) {
		t.Errorf("a syslog term must carry the key. Got: %s", withSyslog)
	}
}

// The rendered snapshot must show `then syslog` IN ADDITION to `then log`,
// not instead of it — the term genuinely carries both bits, and rendering only
// one would misdescribe what the dataplane was given.
func TestThenSyslogRenders_6853(t *testing.T) {
	snap := &FirewallFilterSnapshot{
		Name: "f",
		Terms: []FirewallTermSnapshot{
			{Name: "only_log", Action: "accept", Log: true},
			{Name: "only_syslog", Action: "accept", Log: true, Syslog: true},
		},
	}
	out := RenderFirewallFilterSnapshot(snap)
	if strings.Count(out, "then syslog") != 1 {
		t.Errorf("expected exactly one `then syslog` line, got %d.\n%s",
			strings.Count(out, "then syslog"), out)
	}
	if strings.Count(out, "then log") != 2 {
		t.Errorf("expected `then log` on BOTH terms (the syslog term carries Log too), "+
			"got %d.\n%s", strings.Count(out, "then log"), out)
	}
}
