// #5323: the LOCAL interactive `show security flow session summary` rendered a
// HARDCODED Maximum-sessions:10000000. It now renders the live helper's dynamic
// max (worker_count x per-worker capacity) via userspaceDataplaneStatus(), and
// "unknown" when no userspace status is available.
package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// summaryMaxCLIDP is an empty-session dataplane that exposes a userspace
// ProcessStatus carrying max_sessions (satisfies cliUserspaceStatusProvider).
type summaryMaxCLIDP struct {
	*dataplane.Manager
	maxSessions uint64
}

func (d *summaryMaxCLIDP) IsLoaded() bool { return true }

func (d *summaryMaxCLIDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}

func (d *summaryMaxCLIDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *summaryMaxCLIDP) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{MaxSessions: d.maxSessions}, nil
}

// noStatusCLIDP is the same but WITHOUT a Status() surface, so
// userspaceDataplaneStatus() fails and the render falls back to "unknown".
type noStatusCLIDP struct {
	*dataplane.Manager
}

func (d *noStatusCLIDP) IsLoaded() bool { return true }
func (d *noStatusCLIDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}
func (d *noStatusCLIDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

// TestLocalFlowSessionSummaryDynamicMax asserts the local summary renders the
// helper's dynamic max, not the retired hardcoded 10000000 (#5323).
//
// FAIL-ON-REVERT: restoring `Maximum-sessions: 10000000` makes the 786432
// assertion go red.
func TestLocalFlowSessionSummaryDynamicMax(t *testing.T) {
	c := &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    &summaryMaxCLIDP{Manager: dataplane.New(), maxSessions: 786432},
	}
	out := captureStdout(t, func() {
		if err := c.showFlowSession([]string{"summary"}); err != nil {
			t.Fatalf("showFlowSession summary: %v", err)
		}
	})
	if !strings.Contains(out, "Maximum-sessions: 786432") {
		t.Fatalf("local summary missing dynamic max:\n%s", out)
	}
	if strings.Contains(out, "10000000") {
		t.Fatalf("local summary still prints the retired hardcoded max:\n%s", out)
	}
}

// TestLocalFlowSessionSummaryUnknownMax asserts a dataplane with no userspace
// status renders "unknown" instead of a fabricated authoritative bound (#5323).
func TestLocalFlowSessionSummaryUnknownMax(t *testing.T) {
	c := &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    &noStatusCLIDP{Manager: dataplane.New()},
	}
	out := captureStdout(t, func() {
		if err := c.showFlowSession([]string{"summary"}); err != nil {
			t.Fatalf("showFlowSession summary: %v", err)
		}
	})
	if !strings.Contains(out, "Maximum-sessions: unknown") {
		t.Fatalf("local summary missing unknown fallback:\n%s", out)
	}
}

type quarantineSummaryCLIDP10530 struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
	id     uint16
}

func (d *quarantineSummaryCLIDP10530) IsLoaded() bool { return true }

func (d *quarantineSummaryCLIDP10530) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func (d *quarantineSummaryCLIDP10530) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{IngressZone: d.id, EgressZone: d.id}
	fn(key, val)
	return nil
}

func (d *quarantineSummaryCLIDP10530) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func TestLocalFlowSessionSummaryQuarantineDisplayAtPrint10530(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
	}
	id := config.StableZoneID("z174")
	result := &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
		"trust": config.StableZoneID("trust"),
		"z174":  id,
		"z214":  id,
	}}
	c := &CLI{
		store: store,
		dp: &quarantineSummaryCLIDP10530{
			Manager: dataplane.New(),
			result:  result,
			id:      id,
		},
	}
	out := captureStdout(t, func() {
		if err := c.showFlowSession([]string{"summary", "zone", "z214"}); err != nil {
			t.Fatalf("showFlowSession summary: %v", err)
		}
	})
	wantPair := "z174 " + config.ZoneQuarantineReferenceQualifier + "->z174 " + config.ZoneQuarantineReferenceQualifier
	if !strings.Contains(out, wantPair) {
		t.Fatalf("quarantined summary did not annotate resolved survivor pair at print time:\n%s", out)
	}
	if !strings.Contains(out, "1\n") {
		t.Fatalf("quarantined summary lost the admitted session count:\n%s", out)
	}
}
