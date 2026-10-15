package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestUserspaceOperationalAndHACountersEmit13280(t *testing.T) {
	c := newCollector(nil)
	status := dpuserspace.ProcessStatus{
		CosNoOwnerBindingDropsTotal:        11,
		IoUringWriteRefusedTotal:           12,
		IoUringWriteRefusedBytesTotal:      13,
		RouteChangeUnrejudgedSessionsTotal: 14,
		OwnerRGFilingsDeclinedTotal:        15,
		HATransitionDemoteDropped:          16,
		HATransitionRefreshDropped:         17,
		HATransitionVacateDropped:          18,
		HATransitionDemoteStaleSkipped:     19,
		HATransitionRefreshStaleSkipped:    20,
		SessionDeleteRefusedIdentity:       21,
		SessionDeleteDroppedReleased:       22,
		TunnelPurgeReservationsReleased:    23,
		SyncedReverseRederived:             24,
		PeerDeleteRefusedLocalOwned:        25,
		SessionDeleteReplicaDropped:        26,
		SessionDeleteReplicaDropRepaired:   27,
		S5Reinject: &dpuserspace.S5ReinjectStatus{
			Reinjected:         28,
			CompletedPermitted: 29,
			CompletedFenced:    30,
			CompletedDenied:    31,
			CompletedRefused:   32,
		},
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceStatus13280(ch, status)
		close(ch)
	}()
	var got []prometheus.Metric
	for metric := range ch {
		got = append(got, metric)
	}
	if len(got) != 30 {
		t.Fatalf("emitted %d metrics, want 30 counters / labeled series", len(got))
	}
	for _, counter := range []struct {
		desc  *prometheus.Desc
		value float64
	}{
		{c.userspaceCosNoOwnerBindingDrops, 11},
		{c.userspaceIoUringWriteRefused, 12},
		{c.userspaceIoUringWriteRefusedBytes, 13},
		{c.userspaceRouteChangeUnrejudgedSessions, 14},
		{c.userspaceOwnerRGFilingsDeclined, 15},
		{c.userspaceSessionDeleteRefusedIdentity, 21},
		{c.userspaceSessionDeleteDroppedReleased, 22},
		{c.userspaceTunnelPurgeReservationsReleased, 23},
		{c.userspaceSyncedReverseRederived, 24},
		{c.userspacePeerDeleteRefusedLocalOwned, 25},
		{c.userspaceSessionDeleteReplicaDropped, 26},
		{c.userspaceSessionDeleteReplicaDropRepaired, 27},
		{c.userspaceS5Reinject, 28},
	} {
		assertCounterClose(t, got, counter.desc, nil, counter.value)
	}
	for _, counter := range []struct {
		outcome string
		value   float64
	}{
		{"permitted", 29}, {"fenced", 30}, {"denied", 31}, {"refused", 32},
	} {
		assertCounterClose(t, got, c.userspaceS5ReinjectCompletions,
			map[string]string{"outcome": counter.outcome}, counter.value)
	}
	for _, counter := range []struct {
		op    string
		value float64
	}{
		{"demote", 16}, {"refresh", 17}, {"vacate", 18},
	} {
		assertCounterClose(t, got, c.userspaceHATransitionDropped,
			map[string]string{"op": counter.op}, counter.value)
	}
	for _, counter := range []struct {
		op    string
		value float64
	}{
		{"demote", 19}, {"refresh", 20},
	} {
		assertCounterClose(t, got, c.userspaceHATransitionStaleSkipped,
			map[string]string{"op": counter.op}, counter.value)
	}
}
