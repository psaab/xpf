package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2544 (as narrowed by #14632): fall-through is ONLY the authored
// `then next term` (NextTerm set, Action == ""). A modifier-only term
// (Action == "" with only count/log/forwarding-class/policer/dscp, no
// authored bit) carries Junos nonterminating actions with an implicit
// accept and TERMINATES — the snapshot must NOT mark it fall-through.
// These tests pin (1) the authored NextTerm bit is copied into the
// snapshot, (2) a routing-instance (PBR) term is NOT marked fall-through,
// and (3) the JSON wire tag is exactly `next_term` (one-sided rename =
// #1961 no-transit; the Rust side reads `#[serde(rename="next_term")]`).

func nextTermCfg(terms []*config.FirewallFilterTerm) *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {Name: "edge", Terms: terms},
	}
	return cfg
}

func TestFilterSnapshotExplicitNextTermFallsThrough(t *testing.T) {
	cfg := nextTermCfg([]*config.FirewallFilterTerm{
		{Name: "count-then-next", Protocols: []string{"tcp"}, NextTerm: true,
			Count: "hits", Action: ""},
		{Name: "drop", Protocols: []string{"tcp"}, Action: "discard"},
	})
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 2 {
		t.Fatalf("expected 1 filter with 2 terms, got %#v", snaps)
	}
	if !snaps[0].Terms[0].NextTerm {
		t.Error("explicit `then next term` was not recorded as fall-through")
	}
	if snaps[0].Terms[1].NextTerm {
		t.Error("a terminating discard term must NOT be marked fall-through")
	}
}

// #14632 supersedes the modifier-only half of #2544: a modifier-only term
// (empty Action, NextTerm NOT authored) carries Junos nonterminating actions
// with an implicit accept — the snapshot must NOT mark it fall-through.
// Detailed cells live in filters_modifier_only_14632_test.go.
func TestFilterSnapshotModifierOnlyTermFallsThrough(t *testing.T) {
	cfg := nextTermCfg([]*config.FirewallFilterTerm{
		{Name: "count-only", Protocols: []string{"tcp"}, Count: "hits",
			Action: ""},
	})
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	if snaps[0].Terms[0].NextTerm {
		t.Error("modifier-only term (empty action, no authored `next term`) must NOT be marked fall-through (#14632 implicit accept)")
	}
}

func TestFilterSnapshotRoutingInstanceTermIsNotFallThrough(t *testing.T) {
	// A PBR term (routing-instance) takes its own routing decision; an empty
	// Action there must NOT be treated as a fall-through.
	cfg := nextTermCfg([]*config.FirewallFilterTerm{
		{Name: "pbr", Protocols: []string{"tcp"}, RoutingInstance: "vrf-a",
			Action: ""},
	})
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	if snaps[0].Terms[0].NextTerm {
		t.Error("routing-instance term must NOT be marked fall-through")
	}
}

func TestFilterSnapshotTerminatingTermNotFallThrough(t *testing.T) {
	cfg := nextTermCfg([]*config.FirewallFilterTerm{
		{Name: "accept-web", Protocols: []string{"tcp"}, Action: "accept"},
	})
	snaps := buildFirewallFilterSnapshots(cfg)
	if snaps[0].Terms[0].NextTerm {
		t.Error("a terminating accept term must NOT be marked fall-through")
	}
}

// TestFilterSnapshotNextTermWireTag pins the exact JSON key the Rust decoder
// reads (`next_term`). A rename on either side silently drops the field and
// reverts to the broken fall-through-as-Accept behavior (#1961 wire-parity
// class of bug).
func TestFilterSnapshotNextTermWireTag(t *testing.T) {
	term := FirewallTermSnapshot{Name: "t", NextTerm: true}
	b, err := json.Marshal(term)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := m["next_term"]
	if !ok {
		t.Fatalf("missing `next_term` wire key in %s", b)
	}
	if string(raw) != "true" {
		t.Errorf("next_term wire value = %s, want true", raw)
	}

	// omitempty: a false NextTerm is omitted (wire parity with an older Go
	// control plane / Rust serde(default)).
	b2, _ := json.Marshal(FirewallTermSnapshot{Name: "t"})
	var m2 map[string]json.RawMessage
	if err := json.Unmarshal(b2, &m2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := m2["next_term"]; present {
		t.Errorf("next_term should be omitted when false, got %s", b2)
	}
}
