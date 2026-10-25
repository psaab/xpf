// #3408: the gRPC TEXT mirrors (show security policies hit-count/detail, show
// security zones, show firewall, show security screen statistics all-zones)
// must print a warning when a per-policy / per-zone / filter / flood counter
// read fails, rather than rendering clean-zero / silently-omitted counts.
//
// FAIL-ON-REVERT: dropping the readErr capture + the trailing warning line in
// each renderer removes the warning and the want-"warning" assertions go RED.
package grpcapi

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// filterErrGRPCDP fails filter counter reads (config read succeeds so the
// per-term read is reached).
type filterErrGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *filterErrGRPCDP) IsLoaded() bool                          { return true }
func (d *filterErrGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *filterErrGRPCDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{RuleStart: 0}, nil
}
func (d *filterErrGRPCDP) ReadFilterCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

// floodErrGRPCDP fails per-zone flood counter reads.
type floodErrGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *floodErrGRPCDP) IsLoaded() bool                          { return true }
func (d *floodErrGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *floodErrGRPCDP) ReadFloodCounters(uint32) (dataplane.FloodState, error) {
	return dataplane.FloodState{}, errors.New("counter bridge degraded")
}

func TestShowPoliciesHitCountTextWarnsOnReadError(t *testing.T) {
	s := &Server{store: newSchedulerCounterGRPCStore(t), dp: &policyZoneErrGRPCDP{Manager: dataplane.New()}}
	var buf strings.Builder
	s.showPoliciesHitCount("", &buf)
	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("showPoliciesHitCount text lacks a counter-read warning; got:\n%s", buf.String())
	}
}

func TestShowPoliciesDetailTextWarnsOnReadError(t *testing.T) {
	s := &Server{store: newSchedulerCounterGRPCStore(t), dp: &policyZoneErrGRPCDP{Manager: dataplane.New()}}
	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("showPoliciesDetail text lacks a counter-read warning; got:\n%s", buf.String())
	}
}

func TestShowZonesDetailTextWarnsOnReadError(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &policyZoneErrGRPCDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1, "untrust": 2, "dmz": 3}},
		},
	}
	var buf strings.Builder
	s.showZonesDetail(store.ActiveConfig(), "", &buf)
	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("showZonesDetail text lacks a counter-read warning; got:\n%s", buf.String())
	}
}

func TestShowFirewallTextWarnsOnReadError(t *testing.T) {
	store := newFirewallFilterShowStore(t)
	s := &Server{
		store: store,
		dp: &filterErrGRPCDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{FilterIDs: map[string]uint32{
				"inet:bandwidth-output": 0, "inet6:bandwidth-output": 100,
			}},
		},
	}
	var buf strings.Builder
	s.showFirewall(store.ActiveConfig(), &buf)
	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("showFirewall text lacks a filter counter-read warning; got:\n%s", buf.String())
	}
}

func TestShowScreenStatisticsAllTextWarnsOnReadError(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &floodErrGRPCDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1, "untrust": 2, "dmz": 3}},
		},
	}
	var buf strings.Builder
	if _, err := s.showScreenStatisticsAll(store.ActiveConfig(), &buf); err != nil {
		t.Fatalf("showScreenStatisticsAll() error = %v", err)
	}
	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("showScreenStatisticsAll text lacks a flood counter-read warning; got:\n%s", buf.String())
	}
}

// partialFloodErrGRPCDP succeeds zone ID 1 and fails zone ID 2, modelling the
// #3344 partial-failure case for the gRPC ShowText all-zones path.
type partialFloodErrGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *partialFloodErrGRPCDP) IsLoaded() bool                          { return true }
func (d *partialFloodErrGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *partialFloodErrGRPCDP) ReadFloodCounters(zoneID uint32) (dataplane.FloodState, error) {
	if zoneID == 2 {
		return dataplane.FloodState{}, errors.New("counter bridge degraded")
	}
	return dataplane.FloodState{SynCount: 7}, nil
}

// #3344: the gRPC ShowText all-zones path must emit a per-zone error row naming
// the failing zone instead of silently dropping it.
//
// FAIL-ON-REVERT: restoring the bare `continue` removes the
// "Screen statistics for zone 'untrust'" header for the failing zone -> RED.
func TestShowScreenStatisticsAllTextSurfacesPerZoneReadError(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &partialFloodErrGRPCDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1, "untrust": 2}},
		},
	}
	var buf strings.Builder
	if _, err := s.showScreenStatisticsAll(store.ActiveConfig(), &buf); err != nil {
		t.Fatalf("showScreenStatisticsAll() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Screen statistics for zone 'trust':") {
		t.Fatalf("good zone 'trust' missing from output; got:\n%s", out)
	}
	if !strings.Contains(out, "Screen statistics for zone 'untrust':") {
		t.Fatalf("failing zone 'untrust' silently dropped (no per-zone row); got:\n%s", out)
	}
	if !strings.Contains(out, "Error reading flood counters") {
		t.Fatalf("failing zone lacks an inline 'Error reading flood counters' row; got:\n%s", out)
	}
	if !strings.Contains(out, "warning") {
		t.Fatalf("output lacks the trailing aggregate counter-read warning; got:\n%s", out)
	}
}
