package api

import (
	"fmt"
	"strings"
	"testing"
)

// #4800: pin the EXACT Prometheus metric names of the new-flow contention
// surface.
//
// These names are the contract with everything outside this repo — the
// analyzer's scrape (`newflow_ceiling_analyze.py` greps them by name), any
// dashboard, and any alert. Nothing bound them: the emit tests match on
// DESCRIPTOR POINTER (deliberately, so they survive a client_golang change),
// which is exactly the right choice for those tests and exactly why it cannot
// see a rename. Misspell a name and every one of them stays green while the
// series silently disappears from the scrape.
//
// The fqName is EXTRACTED and compared with `!=`, not matched as a substring.
// `Desc.String()` renders as `Desc{fqName: "...", help: "...", ...}` and the
// help text of these metrics cross-references sibling metric names, so ANY
// `strings.Contains` shape can be satisfied by a name appearing in a
// neighbour's prose rather than by the metric under test actually carrying it.
// Extraction has no substring semantics to abuse.
//
// RED on revert: change any name literal in metrics_descriptors_worker.go,
// metrics_descriptors_nat.go or metrics_descriptors_userspace_session.go and
// this fails naming the metric that lost its name.
func TestNewFlowContentionMetricNamesAreStable_4800(t *testing.T) {
	c := newCollector(nil)

	for _, tc := range []struct {
		want string
		desc fmt.Stringer
	}{
		// Per-worker install distribution — the sole input to both
		// cross-worker analyzer gates.
		{"xpf_userspace_worker_new_flow_installs_total", c.workerNewFlowInstalls},
		// SNAT allocator lock pairs, per pool (#17036 split + legacy sum).
		{"xpf_userspace_source_nat_pool_flow_shard_lock_acquisitions_total", c.userspaceSNATPoolFlowShardLockAcquisitionsTotal},
		{"xpf_userspace_source_nat_pool_flow_shard_lock_contended_total", c.userspaceSNATPoolFlowShardLockContendedTotal},
		{"xpf_userspace_source_nat_pool_live_write_lock_acquisitions_total", c.userspaceSNATPoolLiveWriteLockAcquisitionsTotal},
		{"xpf_userspace_source_nat_pool_live_write_lock_contended_total", c.userspaceSNATPoolLiveWriteLockContendedTotal},
		{"xpf_userspace_source_nat_pool_live_lock_acquisitions_total", c.userspaceSNATPoolLiveLockAcquisitionsTotal},
		{"xpf_userspace_source_nat_pool_live_lock_contended_total", c.userspaceSNATPoolLiveLockContendedTotal},
		// Publish leg: call count + lock pair.
		{"xpf_userspace_shared_session_publishes_total", c.userspaceSharedSessionPublishes},
		{"xpf_userspace_shared_session_publish_lock_acquisitions_total", c.userspaceSharedSessionPublishLockAcquired},
		{"xpf_userspace_shared_session_publish_lock_contended_total", c.userspaceSharedSessionPublishLockBlocked},
		// Replication leg: fan-out pair, contention, and both depth shapes.
		{"xpf_userspace_session_replication_upserts_total", c.userspaceSessionReplicationUpserts},
		{"xpf_userspace_session_replication_enqueued_total", c.userspaceSessionReplicationEnqueued},
		{"xpf_userspace_session_replication_lock_contended_total", c.userspaceSessionReplicationLockBlocked},
		{"xpf_userspace_session_replication_queue_depth_sum", c.userspaceSessionReplicationQueueDepthSum},
		{"xpf_userspace_session_replication_queue_depth_max", c.userspaceSessionReplicationQueueDepthMax},
		// #9169 — SITE 4: the event-stream producer-seq lock pair. Named here
		// with the other three because the analyzer keys its site table on
		// these exact strings, and a rename is a silent attribution loss: the
		// site would report `ratio: None` ("never taken") rather than an error.
		{"xpf_userspace_event_stream_producer_seq_lock_acquisitions_total", c.userspaceEventStreamProducerSeqLockAcquired},
		{"xpf_userspace_event_stream_producer_seq_lock_contended_total", c.userspaceEventStreamProducerSeqLockBlocked},
	} {
		if tc.desc == nil {
			t.Errorf("%s: descriptor is nil — it is not initialised by newCollector", tc.want)
			continue
		}
		got, ok := fqNameOf(tc.desc.String())
		if !ok {
			t.Errorf("%s: could not extract fqName from %s — the Desc rendering "+
				"changed and this guard is no longer reading what it thinks",
				tc.want, tc.desc.String())
			continue
		}
		if got != tc.want {
			t.Errorf("metric is exposed as %q, want %q. Renaming a series breaks "+
				"the analyzer scrape and every dashboard built on it, with no "+
				"error at runtime — the series just stops existing", got, tc.want)
		}
	}
}

// fqNameOf extracts the fqName from a `Desc.String()` rendering
// (`Desc{fqName: "...", help: "...", ...}`), returning ok=false if the
// rendering does not have that shape. Extraction rather than substring
// matching is the whole point: it cannot be satisfied by help-text prose.
func fqNameOf(desc string) (string, bool) {
	const open = `fqName: "`
	i := strings.Index(desc, open)
	if i < 0 {
		return "", false
	}
	rest := desc[i+len(open):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}
