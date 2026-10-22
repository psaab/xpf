package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6854 WIRING. The compiler storing the message-type is worth nothing if it
// stops at the compiler — which is exactly the state the issue describes, where
// three writers stored the field and no reader existed. This binds the hop from
// the compiled term to the snapshot the dataplane receives.
func TestRejectMessageTypeReachesTheSnapshot_6854(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {
			Name: "f",
			Terms: []*config.FirewallFilterTerm{
				{Name: "plain", Action: config.FilterActionReject},
				{Name: "typed", Action: config.FilterActionReject, RejectMessageType: "host-unreachable"},
			},
		},
	}
	var terms []FirewallTermSnapshot
	for _, s := range BuildFirewallFilterSnapshots(cfg) {
		if s.Name == "f" {
			terms = s.Terms
		}
	}
	if len(terms) != 2 {
		t.Fatalf("expected 2 terms, got %d: %+v", len(terms), terms)
	}
	byName := map[string]FirewallTermSnapshot{}
	for _, tm := range terms {
		byName[tm.Name] = tm
	}
	if got := byName["plain"].RejectMessageType; got != "" {
		t.Errorf("term plain: RejectMessageType = %q, want empty", got)
	}
	if got := byName["typed"].RejectMessageType; got != "host-unreachable" {
		t.Errorf("term typed: RejectMessageType = %q, want host-unreachable — the compiled "+
			"token did not reach the snapshot, so the dataplane still sends "+
			"administratively-prohibited", got)
	}
}

// Additive on the wire in BOTH directions, so a mixed-version HA pair is
// unaffected (#1961). A term with no message-type must serialise exactly as it
// did before the field existed.
func TestRejectMessageTypeIsAdditiveOnTheWire_6854(t *testing.T) {
	plain, err := json.Marshal(FirewallTermSnapshot{Name: "t", Action: "reject"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(plain), "reject_message_type") {
		t.Errorf("a term with no message-type must serialise with NO reject_message_type key, "+
			"or an older helper sees a field it cannot parse. Got: %s", plain)
	}
	typed, err := json.Marshal(FirewallTermSnapshot{
		Name: "t", Action: "reject", RejectMessageType: "host-unreachable",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(typed), `"reject_message_type":"host-unreachable"`) {
		t.Errorf("a typed reject must carry the key. Got: %s", typed)
	}
}

// The rendered snapshot must show the message-type, so a `then reject
// host-unreachable` term is distinguishable from a bare `then reject` in the
// dataplane's own view of what it was given.
func TestRejectMessageTypeRenders_6854(t *testing.T) {
	out := RenderFirewallFilterSnapshot(&FirewallFilterSnapshot{
		Name: "f",
		Terms: []FirewallTermSnapshot{
			{Name: "plain", Action: "reject"},
			{Name: "typed", Action: "reject", RejectMessageType: "host-unreachable"},
		},
	})
	if !strings.Contains(out, "then reject host-unreachable") {
		t.Errorf("expected the message-type on the rendered reject line.\n%s", out)
	}
	// The bare term must still render a bare `then reject` — asserting only the
	// typed line would pass a render that appended the message-type to every
	// term.
	if strings.Count(out, "then reject\n") != 1 {
		t.Errorf("expected exactly one BARE `then reject` line, got %d.\n%s",
			strings.Count(out, "then reject\n"), out)
	}
}
