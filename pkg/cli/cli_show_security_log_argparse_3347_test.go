package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// #3347: `show security log` argument parsing must fail CLOSED. Before the fix
// an unknown token (a typo like `zon trust`) or a filter keyword with no value
// (`action` with nothing after it) was silently ignored, and the empty filter
// fell through to Latest(n) — dumping every event instead of the scoped
// forensic query the operator asked for. M02: a `zone <name>` filter requested
// while no dataplane apply result exists (early startup / after a failed apply)
// likewise dropped the filter and widened to all events.
//
// FAIL-ON-REVERT: reverting the parse-loop guards (unknown-token rejection,
// missing-value rejection, or the cr==nil zone refusal) makes the matching
// subtest see a nil error instead of a rejection.

// applyCLIDP is a CLI dataplane stub that returns a fixed ApplyResult so the
// zone-name -> ID lookup in showSecurityLog has a non-nil cr to consult.
type applyCLIDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *applyCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func newLogCLI(withApply bool) *CLI {
	buf := logging.NewEventBuffer(16)
	// Seed events in two zones so a zone filter is observably narrower than
	// an unfiltered dump.
	buf.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: 1})
	buf.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: 2})
	c := &CLI{eventBuf: buf}
	if withApply {
		c.dp = &applyCLIDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
				"trust": 1, "untrust": 2,
			}},
		}
	}
	return c
}

func TestShowSecurityLogRejectsBadArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string // substring the error must contain
	}{
		{"unknown token", []string{"zon", "trust"}, "unknown argument"},
		{"bogus single token", []string{"bogus"}, "unknown argument"},
		{"missing zone value", []string{"zone"}, "missing value"},
		{"missing protocol value", []string{"protocol"}, "missing value"},
		{"missing action value", []string{"action"}, "missing value"},
		{"unknown zone", []string{"zone", "nonexistent"}, "not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newLogCLI(true)
			err := captureErr(t, func() error { return c.showSecurityLog(tt.args) })
			if err == nil {
				t.Fatalf("showSecurityLog(%q) = nil error, want one containing %q", tt.args, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("showSecurityLog(%q) error = %q, want substring %q", tt.args, err.Error(), tt.wantErr)
			}
		})
	}
}

// M02: a zone filter requested with no apply result must be refused, not
// silently widened to an unfiltered dump.
func TestShowSecurityLogZoneNoApplyResult(t *testing.T) {
	c := newLogCLI(false) // dp nil -> applyResult() == nil
	err := captureErr(t, func() error { return c.showSecurityLog([]string{"zone", "trust"}) })
	if err == nil {
		t.Fatalf("showSecurityLog([zone trust]) with no apply result = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "apply result") {
		t.Fatalf("error = %q, want it to mention the missing apply result", err.Error())
	}
}

// Valid filters and a valid count must still work — the fail-closed parsing
// must not reject the legitimate forensic queries.
func TestShowSecurityLogValidArgs(t *testing.T) {
	for _, args := range [][]string{
		{"10"},
		{"zone", "trust"},
		{"protocol", "tcp"},
		{"action", "permit"},
		{"5", "zone", "untrust", "protocol", "udp"},
	} {
		c := newLogCLI(true)
		err := captureErr(t, func() error { return c.showSecurityLog(args) })
		if err != nil {
			t.Errorf("showSecurityLog(%q) = %v, want nil", args, err)
		}
	}
}

// captureErr runs fn with stdout redirected to /dev/null-equivalent discard so
// the formatted event lines do not pollute test output, returning fn's error.
func captureErr(t *testing.T, fn func() error) error {
	t.Helper()
	var err error
	captureStdout(t, func() { err = fn() })
	return err
}
