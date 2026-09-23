package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestProcessStatusIpsecSaWireFields(t *testing.T) {
	status := dpuserspace.ProcessStatus{
		IpsecSAMissDroppedPacketsTotal:    1,
		IpsecSAMissNoSATotal:              2,
		IpsecSAMissTruncatedTotal:         3,
		IpsecSAMissMalformedIKETotal:      4,
		IpsecSAMissKeepaliveTotal:         5,
		IpsecSASnapshotStaleDenyTotal:     6,
		IpsecSAInsertsTotal:               7,
		IpsecSARemovesTotal:               8,
		IpsecSAExpiryRemovesTotal:         9,
		IpsecSAEvictionsTotal:             10,
		IpsecSAMultiSourceCollisionsTotal: 11,
		IpsecSANetlinkEnobufsTotal:        12,
		IpsecSANetlinkRedumpsTotal:        13,
		IpsecSANetlinkRedumpUpsertsTotal:  14,
	}
	payload, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal ProcessStatus: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatalf("unmarshal ProcessStatus JSON: %v", err)
	}
	want := map[string]uint64{
		"ipsec_sa_miss_dropped_packets_total":    1,
		"ipsec_sa_miss_no_sa_total":              2,
		"ipsec_sa_miss_truncated_total":          3,
		"ipsec_sa_miss_malformed_ike_total":      4,
		"ipsec_sa_miss_keepalive_total":          5,
		"ipsec_sa_snapshot_stale_deny_total":     6,
		"ipsec_sa_inserts_total":                 7,
		"ipsec_sa_removes_total":                 8,
		"ipsec_sa_expiry_removes_total":          9,
		"ipsec_sa_evictions_total":               10,
		"ipsec_sa_multi_source_collisions_total": 11,
		"ipsec_sa_netlink_enobufs_total":         12,
		"ipsec_sa_netlink_redumps_total":         13,
		"ipsec_sa_netlink_redump_upserts_total":  14,
	}
	for name, value := range want {
		var got uint64
		if err := json.Unmarshal(wire[name], &got); err != nil {
			t.Errorf("%s is not a numeric counter: %v", name, err)
			continue
		}
		if got != value {
			t.Errorf("%s = %d, want %d", name, got, value)
		}
	}
}

func TestProcessStatusIpsecSaRustWireDecode(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join(
		"..",
		"..",
		"userspace-dp",
		"tests",
		"fixtures",
		"protocol_wire_v1.json",
	))
	if err != nil {
		t.Fatalf("read Rust protocol fixture: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(fixture, &envelope); err != nil {
		t.Fatalf("decode Rust protocol fixture: %v", err)
	}
	rawStatus, ok := envelope["process_status"]
	if !ok {
		t.Fatal("Rust protocol fixture has no process_status payload")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawStatus, &fields); err != nil {
		t.Fatalf("decode Rust process_status object: %v", err)
	}
	for _, name := range []string{
		"ipsec_sa_miss_dropped_packets_total",
		"ipsec_sa_miss_no_sa_total",
		"ipsec_sa_miss_truncated_total",
		"ipsec_sa_miss_malformed_ike_total",
		"ipsec_sa_miss_keepalive_total",
		"ipsec_sa_snapshot_stale_deny_total",
		"ipsec_sa_inserts_total",
		"ipsec_sa_removes_total",
		"ipsec_sa_expiry_removes_total",
		"ipsec_sa_evictions_total",
		"ipsec_sa_multi_source_collisions_total",
		"ipsec_sa_netlink_enobufs_total",
		"ipsec_sa_netlink_redumps_total",
		"ipsec_sa_netlink_redump_upserts_total",
	} {
		if _, ok := fields[name]; !ok {
			t.Errorf("Rust fixture process_status is missing %q", name)
		}
	}
	var fixtureStatus dpuserspace.ProcessStatus
	if err := json.Unmarshal(rawStatus, &fixtureStatus); err != nil {
		t.Fatalf("decode Rust process_status into Go status: %v", err)
	}
	if fixtureStatus.IpsecSAMissDroppedPacketsTotal != 0 ||
		fixtureStatus.IpsecSAMissNoSATotal != 0 ||
		fixtureStatus.IpsecSAMissTruncatedTotal != 0 ||
		fixtureStatus.IpsecSAMissMalformedIKETotal != 0 ||
		fixtureStatus.IpsecSAMissKeepaliveTotal != 0 ||
		fixtureStatus.IpsecSASnapshotStaleDenyTotal != 0 ||
		fixtureStatus.IpsecSAInsertsTotal != 0 ||
		fixtureStatus.IpsecSARemovesTotal != 0 ||
		fixtureStatus.IpsecSAExpiryRemovesTotal != 0 ||
		fixtureStatus.IpsecSAEvictionsTotal != 0 ||
		fixtureStatus.IpsecSAMultiSourceCollisionsTotal != 0 ||
		fixtureStatus.IpsecSANetlinkEnobufsTotal != 0 ||
		fixtureStatus.IpsecSANetlinkRedumpsTotal != 0 ||
		fixtureStatus.IpsecSANetlinkRedumpUpsertsTotal != 0 {
		t.Fatalf("zero-valued Rust fixture counters decoded nonzero: %+v", fixtureStatus)
	}

	const rustShaped = `{
		"ipsec_sa_miss_dropped_packets_total": 101,
		"ipsec_sa_miss_no_sa_total": 102,
		"ipsec_sa_miss_truncated_total": 103,
		"ipsec_sa_miss_malformed_ike_total": 104,
		"ipsec_sa_miss_keepalive_total": 105,
		"ipsec_sa_snapshot_stale_deny_total": 106,
		"ipsec_sa_inserts_total": 107,
		"ipsec_sa_removes_total": 108,
		"ipsec_sa_expiry_removes_total": 109,
		"ipsec_sa_evictions_total": 110,
		"ipsec_sa_multi_source_collisions_total": 111,
		"ipsec_sa_netlink_enobufs_total": 112,
		"ipsec_sa_netlink_redumps_total": 113,
		"ipsec_sa_netlink_redump_upserts_total": 114
	}`
	var decoded dpuserspace.ProcessStatus
	if err := json.Unmarshal([]byte(rustShaped), &decoded); err != nil {
		t.Fatalf("decode Rust-shaped IPsec counters: %v", err)
	}
	if decoded.IpsecSAMissDroppedPacketsTotal != 101 ||
		decoded.IpsecSAMissNoSATotal != 102 ||
		decoded.IpsecSAMissTruncatedTotal != 103 ||
		decoded.IpsecSAMissMalformedIKETotal != 104 ||
		decoded.IpsecSAMissKeepaliveTotal != 105 ||
		decoded.IpsecSASnapshotStaleDenyTotal != 106 ||
		decoded.IpsecSAInsertsTotal != 107 ||
		decoded.IpsecSARemovesTotal != 108 ||
		decoded.IpsecSAExpiryRemovesTotal != 109 ||
		decoded.IpsecSAEvictionsTotal != 110 ||
		decoded.IpsecSAMultiSourceCollisionsTotal != 111 ||
		decoded.IpsecSANetlinkEnobufsTotal != 112 ||
		decoded.IpsecSANetlinkRedumpsTotal != 113 ||
		decoded.IpsecSANetlinkRedumpUpsertsTotal != 114 {
		t.Fatalf("Rust-shaped IPsec counters decoded incorrectly: %+v", decoded)
	}
	var absent dpuserspace.ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &absent); err != nil {
		t.Fatalf("decode absent IPsec counters: %v", err)
	}
	if absent.IpsecSAMissDroppedPacketsTotal != 0 ||
		absent.IpsecSAMissNoSATotal != 0 ||
		absent.IpsecSAMissTruncatedTotal != 0 ||
		absent.IpsecSAMissMalformedIKETotal != 0 ||
		absent.IpsecSAMissKeepaliveTotal != 0 ||
		absent.IpsecSASnapshotStaleDenyTotal != 0 ||
		absent.IpsecSAInsertsTotal != 0 ||
		absent.IpsecSARemovesTotal != 0 ||
		absent.IpsecSAExpiryRemovesTotal != 0 ||
		absent.IpsecSAEvictionsTotal != 0 ||
		absent.IpsecSAMultiSourceCollisionsTotal != 0 ||
		absent.IpsecSANetlinkEnobufsTotal != 0 ||
		absent.IpsecSANetlinkRedumpsTotal != 0 ||
		absent.IpsecSANetlinkRedumpUpsertsTotal != 0 {
		t.Fatalf("absent IPsec counters did not decode to zero: %+v", absent)
	}
}

func TestEmitIpsecSaCounters(t *testing.T) {
	newDesc := func(name string) *prometheus.Desc {
		return prometheus.NewDesc(name, name, nil, nil)
	}
	c := &xpfCollector{
		ipsecSAMissDroppedPacketsTotal: newDesc("xpf_userspace_ipsec_sa_miss_dropped_packets_total"),
		ipsecSAMissNoSATotal:           newDesc("xpf_userspace_ipsec_sa_miss_no_sa_total"),
		ipsecSAMissTruncatedTotal:      newDesc("xpf_userspace_ipsec_sa_miss_truncated_total"),
		ipsecSAMissMalformedIKETotal:   newDesc("xpf_userspace_ipsec_sa_miss_malformed_ike_total"),
		ipsecSAMissKeepaliveTotal:      newDesc("xpf_userspace_ipsec_sa_miss_keepalive_total"),
		ipsecSASnapshotStaleDenyTotal:  newDesc("xpf_userspace_ipsec_sa_snapshot_stale_deny_total"),
		ipsecSAInsertsTotal:            newDesc("xpf_userspace_ipsec_sa_inserts_total"),
		ipsecSARemovesTotal:            newDesc("xpf_userspace_ipsec_sa_removes_total"),
		ipsecSAExpiryRemovesTotal:      newDesc("xpf_userspace_ipsec_sa_expiry_removes_total"),
		ipsecSAEvictionsTotal:          newDesc("xpf_userspace_ipsec_sa_evictions_total"),
		ipsecSAMultiSourceCollisionsTotal: newDesc(
			"xpf_userspace_ipsec_sa_multi_source_collisions_total"),
		ipsecSANetlinkEnobufsTotal: newDesc(
			"xpf_userspace_ipsec_sa_netlink_enobufs_total"),
		ipsecSANetlinkRedumpsTotal: newDesc(
			"xpf_userspace_ipsec_sa_netlink_redumps_total"),
		ipsecSANetlinkRedumpUpsertsTotal: newDesc(
			"xpf_userspace_ipsec_sa_netlink_redump_upserts_total"),
	}
	status := dpuserspace.ProcessStatus{
		IpsecSAMissDroppedPacketsTotal:    1,
		IpsecSAMissNoSATotal:              2,
		IpsecSAMissTruncatedTotal:         3,
		IpsecSAMissMalformedIKETotal:      4,
		IpsecSAMissKeepaliveTotal:         5,
		IpsecSASnapshotStaleDenyTotal:     6,
		IpsecSAInsertsTotal:               7,
		IpsecSARemovesTotal:               8,
		IpsecSAExpiryRemovesTotal:         9,
		IpsecSAEvictionsTotal:             10,
		IpsecSAMultiSourceCollisionsTotal: 11,
		IpsecSANetlinkEnobufsTotal:        12,
		IpsecSANetlinkRedumpsTotal:        13,
		IpsecSANetlinkRedumpUpsertsTotal:  14,
	}

	ch := make(chan prometheus.Metric, 16)
	c.emitIpsecSaCounters(ch, status)
	close(ch)
	var got []prometheus.Metric
	for metric := range ch {
		got = append(got, metric)
	}

	assertCounterClose(t, got, c.ipsecSAMissDroppedPacketsTotal, nil, 1)
	assertCounterClose(t, got, c.ipsecSAMissNoSATotal, nil, 2)
	assertCounterClose(t, got, c.ipsecSAMissTruncatedTotal, nil, 3)
	assertCounterClose(t, got, c.ipsecSAMissMalformedIKETotal, nil, 4)
	assertCounterClose(t, got, c.ipsecSAMissKeepaliveTotal, nil, 5)
	assertCounterClose(t, got, c.ipsecSASnapshotStaleDenyTotal, nil, 6)
	assertCounterClose(t, got, c.ipsecSAInsertsTotal, nil, 7)
	assertCounterClose(t, got, c.ipsecSARemovesTotal, nil, 8)
	assertCounterClose(t, got, c.ipsecSAExpiryRemovesTotal, nil, 9)
	assertCounterClose(t, got, c.ipsecSAEvictionsTotal, nil, 10)
	assertCounterClose(t, got, c.ipsecSAMultiSourceCollisionsTotal, nil, 11)
	assertCounterClose(t, got, c.ipsecSANetlinkEnobufsTotal, nil, 12)
	assertCounterClose(t, got, c.ipsecSANetlinkRedumpsTotal, nil, 13)
	assertCounterClose(t, got, c.ipsecSANetlinkRedumpUpsertsTotal, nil, 14)
}
