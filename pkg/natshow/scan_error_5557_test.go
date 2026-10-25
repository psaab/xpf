package natshow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"net/netip"

	"github.com/psaab/xpf/pkg/dataplane"
)

// scanErrReader is a Reader whose forward-session scan fails, so the NAT
// detail renderers exercise their session-count error path (#5557).
type scanErrReader struct {
	pnat *dataplane.PersistentNATTable
}

func (r *scanErrReader) IsLoaded() bool { return true }

func (r *scanErrReader) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return errors.New("helper restart: session map closed")
}

func (r *scanErrReader) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (r *scanErrReader) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (r *scanErrReader) GetPersistentNAT() *dataplane.PersistentNATTable { return r.pnat }

// v6ScanErrReader is a Reader whose FORWARD (v4) session scan succeeds but whose
// v6 session scan fails, so the NAT detail renderers exercise their v6-specific
// session-count error path (#5557). The v4 scan returning nil isolates the v6
// capture branch: the caveat can only be surfaced by the v6 `else if scanErr ==
// nil` accumulation.
type v6ScanErrReader struct {
	pnat *dataplane.PersistentNATTable
}

func (r *v6ScanErrReader) IsLoaded() bool { return true }

func (r *v6ScanErrReader) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}

func (r *v6ScanErrReader) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return errors.New("helper restart: v6 session map closed")
}

func (r *v6ScanErrReader) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (r *v6ScanErrReader) GetPersistentNAT() *dataplane.PersistentNATTable { return r.pnat }

const scanErrCaveat = "active session counts may be incomplete"

// TestRenderPersistentDetail_SurfacesScanError_5557 pins that a transient
// dataplane session-scan error is surfaced as a caveat rather than silently
// understating the per-binding "Current sessions" count.
//
// FAIL-ON-REVERT: restore the `_ = dp.IterateSessions(...)` error discards in
// RenderPersistentDetail and the caveat vanishes.
func TestRenderPersistentDetail_SurfacesScanError_5557(t *testing.T) {
	pnat := dataplane.NewPersistentNATTable()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.1.5"),
		SrcPort:  1111,
		NatIP:    netip.MustParseAddr("203.0.113.1"),
		NatPort:  40000,
		PoolName: "p-src",
		LastSeen: time.Now(),
		Timeout:  600 * time.Second,
	})
	var b strings.Builder
	RenderPersistentDetail(context.Background(), &b, &scanErrReader{pnat: pnat})
	if !strings.Contains(b.String(), scanErrCaveat) {
		t.Fatalf("persistent detail did not surface the session-scan error; got:\n%s", b.String())
	}
}

// TestRenderSourceRuleDetail_SurfacesScanError_5557 mirrors the assertion for
// the source-NAT rule detail renderer.
//
// FAIL-ON-REVERT: restore the `_ = dp.IterateSessions(...)` discards in
// RenderSourceRuleDetail and the caveat vanishes.
func TestRenderSourceRuleDetail_SurfacesScanError_5557(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, natFixtureConfig(), &scanErrReader{},
		func() *dataplane.ApplyResult { return &dataplane.ApplyResult{ZoneIDs: map[string]uint32{}} })
	if !strings.Contains(b.String(), scanErrCaveat) {
		t.Fatalf("source detail did not surface the session-scan error; got:\n%s", b.String())
	}
}

// TestRenderDestRuleDetail_SurfacesScanError_5557 mirrors the assertion for the
// destination-NAT rule detail renderer.
//
// FAIL-ON-REVERT: restore the `_ = dp.IterateSessions(...)` discards in
// RenderDestRuleDetail and the caveat vanishes.
func TestRenderDestRuleDetail_SurfacesScanError_5557(t *testing.T) {
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, natFixtureConfig(), &scanErrReader{},
		func() *dataplane.ApplyResult { return &dataplane.ApplyResult{ZoneIDs: map[string]uint32{}} })
	if !strings.Contains(b.String(), scanErrCaveat) {
		t.Fatalf("dest detail did not surface the session-scan error; got:\n%s", b.String())
	}
}

// The v4 scan succeeds and only the v6 scan fails, so the caveat below can only
// come from the v6 capture branch (`else if scanErr == nil { scanErr = err }`)
// in each renderer.
//
// FAIL-ON-REVERT: drop the v6 error accumulation in RenderPersistentDetail /
// RenderSourceRuleDetail / RenderDestRuleDetail and the caveat vanishes for the
// v6-only-error reader.

func TestRenderPersistentDetail_SurfacesV6ScanError_5557(t *testing.T) {
	pnat := dataplane.NewPersistentNATTable()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.1.5"),
		SrcPort:  1111,
		NatIP:    netip.MustParseAddr("203.0.113.1"),
		NatPort:  40000,
		PoolName: "p-src",
		LastSeen: time.Now(),
		Timeout:  600 * time.Second,
	})
	var b strings.Builder
	RenderPersistentDetail(context.Background(), &b, &v6ScanErrReader{pnat: pnat})
	if !strings.Contains(b.String(), scanErrCaveat) {
		t.Fatalf("persistent detail did not surface the v6 session-scan error; got:\n%s", b.String())
	}
}

func TestRenderSourceRuleDetail_SurfacesV6ScanError_5557(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, natFixtureConfig(), &v6ScanErrReader{},
		func() *dataplane.ApplyResult { return &dataplane.ApplyResult{ZoneIDs: map[string]uint32{}} })
	if !strings.Contains(b.String(), scanErrCaveat) {
		t.Fatalf("source detail did not surface the v6 session-scan error; got:\n%s", b.String())
	}
}

func TestRenderDestRuleDetail_SurfacesV6ScanError_5557(t *testing.T) {
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, natFixtureConfig(), &v6ScanErrReader{},
		func() *dataplane.ApplyResult { return &dataplane.ApplyResult{ZoneIDs: map[string]uint32{}} })
	if !strings.Contains(b.String(), scanErrCaveat) {
		t.Fatalf("dest detail did not surface the v6 session-scan error; got:\n%s", b.String())
	}
}
