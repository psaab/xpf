// #3345: the gRPC text `show security flow statistics` and `show chassis
// cluster ... fabric` views must print a warning when a global-counter read
// fails, rather than rendering clean zeros that hide a degraded counter bridge.
//
// FAIL-ON-REVERT: restoring `v, _ := s.dp.ReadGlobalCounter(idx)` (dropping the
// readErr capture + the warning line) makes both renderers emit only the
// zero-valued rows and the want-"warning" assertions go RED.
package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestShowFlowStatisticsTextWarnsOnCounterReadError(t *testing.T) {
	dp := &counterFaultGRPCDP{Manager: dataplane.New()}
	s := newViewServer(t, dp)

	var buf strings.Builder
	if err := s.showFlowStatistics(context.Background(), &buf); err != nil {
		t.Fatalf("showFlowStatistics: %v", err)
	}

	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("showFlowStatistics output lacks a counter-read warning; got:\n%s", buf.String())
	}
}

func TestShowClusterFabricTextWarnsOnCounterReadError(t *testing.T) {
	dp := &counterFaultGRPCDP{Manager: dataplane.New()}
	s := newViewServer(t, dp)

	var buf strings.Builder
	s.showChassisClusterFabricStatistics(&buf)

	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("showChassisClusterFabricStatistics output lacks a counter-read warning; got:\n%s", buf.String())
	}
}
