package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// statusErrDrainer15217 returns one prepared response: deltas together with
// an error, mirroring Manager.DrainSessionDeltas when the helper response
// already popped the batch and applyHelperStatusLocked then fails
// (manager_status.go returns resp.SessionDeltas, status, err).
type statusErrDrainer15217 struct {
	deltas []dpuserspace.SessionDeltaInfo
	status dpuserspace.ProcessStatus
	err    error
	calls  int
}

func (f *statusErrDrainer15217) DrainSessionDeltas(uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	f.calls++
	return f.deltas, f.status, f.err
}

func drainFixture15217(t *testing.T) (*Daemon, *cluster.SessionSync, *config.Config) {
	t.Helper()
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return true },
		IsPrimaryForRGFn: func(rgID int) bool { return rgID == 1 },
	}
	d := &Daemon{sessionSync: ss}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"},
		"wan": {Name: "wan"},
	}
	return d, ss, cfg
}

// TestDrainQueuesDeltasReturnedWithStatusError15217 is the #15217 defect arm:
// the fallback drain must queue a batch the helper already popped even when
// the same response carries a status-apply error, and only then propagate
// the error. On base, queued=0 because the error return ran before queueing.
func TestDrainQueuesDeltasReturnedWithStatusError15217(t *testing.T) {
	d, ss, cfg := drainFixture15217(t)
	delta := transitOpen9767()
	zoneIDs := buildZoneIDs(cfg)
	key, _, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("setup: transit delta did not convert")
	}
	wantErr := errors.New("status apply failed 15217")
	drainer := &statusErrDrainer15217{deltas: []dpuserspace.SessionDeltaInfo{delta}, err: wantErr}

	queued, err := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 8)
	if !errors.Is(err, wantErr) {
		t.Fatalf("drain error = %v, want the status-apply error to propagate", err)
	}
	if queued != 1 {
		t.Fatalf("#15217: queued = %d, want 1 — the popped batch was discarded with the status error", queued)
	}
	if stamp := ss.SentInstallGenerationV4ForTesting(key); stamp == 0 {
		t.Fatal("#15217: queued delta never reached QueueSessionV4 (no install generation stamp)")
	}
	if got := d.UserspaceDeltaDrainStatusErrorCount(); got != 1 {
		t.Fatalf("#15217: drain status-error count = %d, want 1", got)
	}
	if drainer.calls != 1 {
		t.Fatalf("drain calls = %d, want 1 (error stops further batches)", drainer.calls)
	}
}

// TestDrainStatusErrorControls15217 pins the neighbouring behaviour the fix
// must not change: a clean drain queues and returns no error; an error with
// no deltas queues nothing, does not count as a queued-with-error batch, and
// still propagates.
func TestDrainStatusErrorControls15217(t *testing.T) {
	t.Run("clean drain", func(t *testing.T) {
		d, _, cfg := drainFixture15217(t)
		drainer := &fakeUserspaceDeltaDrainer{
			batches: [][]dpuserspace.SessionDeltaInfo{{transitOpen9767()}},
		}
		queued, err := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 8)
		if err != nil {
			t.Fatalf("clean drain error = %v, want nil", err)
		}
		if queued != 1 {
			t.Fatalf("clean drain queued = %d, want 1", queued)
		}
		if got := d.UserspaceDeltaDrainStatusErrorCount(); got != 0 {
			t.Fatalf("clean drain status-error count = %d, want 0", got)
		}
	})

	t.Run("error without deltas", func(t *testing.T) {
		d, _, cfg := drainFixture15217(t)
		wantErr := errors.New("drain transport failed 15217")
		drainer := &statusErrDrainer15217{err: wantErr}
		queued, err := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 8)
		if !errors.Is(err, wantErr) {
			t.Fatalf("drain error = %v, want propagated error", err)
		}
		if queued != 0 {
			t.Fatalf("error-without-deltas queued = %d, want 0", queued)
		}
		if got := d.UserspaceDeltaDrainStatusErrorCount(); got != 0 {
			t.Fatalf("error-without-deltas status-error count = %d, want 0 (nothing was queued despite an error)", got)
		}
	})
}
