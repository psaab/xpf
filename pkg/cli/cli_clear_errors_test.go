// #2468: session clear must surface — not silently discard — failures
// from the iterator, reverse/companion deletes, and (covered in the
// grpcapi package) the HA peer-clear RPC. These tests inject failures
// via a cliRuntime that embeds *dataplane.Manager and overrides the
// session methods, then assert the CLI prints a WARNING tail. They are
// fail-on-revert: restoring the old `_ =`/fire-and-forget discards makes
// the failures invisible and the WARNING assertions go RED.
package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

// clearFaultCLIDP is a cliRuntime that reports IsLoaded()==true and lets
// a test seed one matching v4 session plus per-operation error
// injection. It embeds *dataplane.Manager so it satisfies the full
// cliRuntime surface; only the session methods are overridden.
type clearFaultCLIDP struct {
	*dataplane.Manager

	v4Sessions map[dataplane.SessionKey]dataplane.SessionValue

	iterErr   error // returned by IterateSessions
	iterV6Err error // returned by IterateSessionsV6
	// fwdDelErr is returned only for a DeleteSession on a seeded
	// (forward) key. revDelErr is returned for any other DeleteSession
	// key — i.e. the computed reverse companion. This split lets a test
	// inject ErrKeyNotExist on the reverse delete (a successful NAT'd
	// clear) without affecting the forward delete.
	fwdDelErr error
	revDelErr error
}

func (d *clearFaultCLIDP) IsLoaded() bool { return true }

func (d *clearFaultCLIDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range d.v4Sessions {
		if !fn(k, v) {
			break
		}
	}
	return d.iterErr
}

func (d *clearFaultCLIDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.iterV6Err
}

// #4886: cursor overrides for the bounded CLI clear — the table is under
// cliClearFilteredBatch, so it clears in one chunk; delegate to the full scans
// (preserving iterErr/iterV6Err so the enumeration-failure tests still fire).
func (d *clearFaultCLIDP) IterateSessionsFrom(_ *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return d.IterateSessions(fn)
}

func (d *clearFaultCLIDP) IterateSessionsV6From(_ *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.IterateSessionsV6(fn)
}

func (d *clearFaultCLIDP) DeleteSession(key dataplane.SessionKey) error {
	if _, isForward := d.v4Sessions[key]; isForward {
		return d.fwdDelErr
	}
	return d.revDelErr
}
func (d *clearFaultCLIDP) DeleteSessionV6(dataplane.SessionKeyV6) error { return nil }
func (d *clearFaultCLIDP) ClearAllSessions() (int, int, error)          { return 0, 0, nil }

// one matching TCP session (proto-only filter), optionally SNAT. A
// reverse companion (val.ReverseKey) is always populated with a tuple
// distinct from the forward key so the clear issues a reverse delete the
// mock routes to revDelErr (#2733: the clear now keys the reverse delete
// on val.ReverseKey, skipping it entirely when ReverseKey.Protocol == 0).
func seedV4(snat bool) map[dataplane.SessionKey]dataplane.SessionValue {
	key := dataplane.SessionKey{Protocol: 6, SrcPort: 0x3930} // network-order, irrelevant to proto filter
	val := dataplane.SessionValue{
		ReverseKey: dataplane.SessionKey{Protocol: 6, SrcPort: 0x0050, DstPort: 0x3930},
	}
	if snat {
		val.Flags = dataplane.SessFlagSNAT
	}
	return map[dataplane.SessionKey]dataplane.SessionValue{key: val}
}

func newClearCLI(t *testing.T, dp cliRuntime) *CLI {
	t.Helper()
	return &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
		// cluster intentionally nil — standalone, so the peer-clear path
		// is a clean no-op and these tests isolate the dataplane-side
		// failure surfacing.
	}
}

func TestClearFilteredSessionsReportsIteratorFailure(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(false),
		iterErr:    fmt.Errorf("map dump truncated"),
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		// proto-only filter -> hasFilter() true -> clearFilteredSessions
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "v4 iterate") {
		t.Fatalf("iterator failure not surfaced in output:\n%s", out)
	}
}

func TestClearFilteredSessionsReportsForwardDeleteFailure(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(false),
		fwdDelErr:  fmt.Errorf("kernel map delete EBUSY"),
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "forward delete") {
		t.Fatalf("forward delete failure not surfaced:\n%s", out)
	}
}

// A NON-not-found reverse-delete error (EIO etc.) is a real failure and
// MUST still be aggregated — guards against swinging from over-reporting
// to under-reporting.
func TestClearFilteredSessionsReportsReverseDeleteRealError(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(false),
		revDelErr:  fmt.Errorf("map delete EIO"),
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "reverse delete") {
		t.Fatalf("real reverse-delete error not surfaced:\n%s", out)
	}
}

// Happy path: every sub-operation succeeds -> clean cleared line, no
// WARNING. Guards against a regression that warns spuriously.
func TestClearFilteredSessionsHappyPathNoWarning(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(true),
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("happy path emitted a spurious WARNING:\n%s", out)
	}
	if !strings.Contains(out, "matching sessions cleared") {
		t.Fatalf("happy path missing cleared line:\n%s", out)
	}
}

// #2468 finding 6: a NAT'd session's reverse companion is keyed on the
// TRANSLATED tuple (val.ReverseKey), not the naive src/dst swap the
// clear computes, so the reverse delete AND the DNAT-companion delete
// hit ErrKeyNotExist on a fully-successful clear. That must NOT be
// reported as a failure. Fail-on-revert: switch addExceptNotFound back
// to add() and this goes RED (spurious WARNING).
func TestClearFilteredSessionsNATReverseNotFoundNotReported(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(true),        // SNAT session
		revDelErr:  ebpf.ErrKeyNotExist, // naive-swap reverse key absent
		// fwdDelErr nil -> forward delete succeeds (key came from iteration)
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("benign ErrKeyNotExist on reverse delete spuriously reported:\n%s", out)
	}
	if !strings.Contains(out, "1 IPv4 and 0 IPv6 matching sessions cleared") {
		t.Fatalf("cleared-count line wrong:\n%s", out)
	}
}
