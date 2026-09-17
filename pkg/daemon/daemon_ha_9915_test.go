package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// capacityProbeDP9915 publishes a fixed helper session capacity through the
// cached-status probe. It embeds the counting drainer so it satisfies the
// same backend shape the fallback-loop binders use.
type capacityProbeDP9915 struct {
	countingDeltaDrainerDP
	maxSessions uint64
}

func (c *capacityProbeDP9915) CachedStatus() (dpuserspace.ProcessStatus, bool) {
	return dpuserspace.ProcessStatus{MaxSessions: c.maxSessions}, true
}

// TestEventStreamFallbackLoopWiresHelperCapacityIntoSyncGuards_9915 binds the
// F-044 daemon wiring: the fallback tick publishes helper MaxSessions into
// SessionSync's guard sizing. Fails if the tick stops calling the setter (or
// passes zero/unknown through).
func TestEventStreamFallbackLoopWiresHelperCapacityIntoSyncGuards_9915(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Daemon{cluster: clusterManagerPrimaryForRGs(0)}
	ss := cluster.NewSessionSync(":0", ":0", nil)
	d.sessionSync = ss
	d.setDataplane(&capacityProbeDP9915{maxSessions: 786432})
	if got := ss.Stats().GenGuardSessionCap; got != 0 {
		t.Fatalf("FIXTURE: wired capacity = %d, want 0 before any tick", got)
	}
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		d.eventStreamFallbackLoop(ctx, nil)
	}()
	dl := time.Now().Add(5 * time.Second)
	for ss.Stats().GenGuardSessionCap != 786432 {
		if time.Now().After(dl) {
			t.Fatalf("helper capacity was not wired after 5s (got %d, want 786432)", ss.Stats().GenGuardSessionCap)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-loopDone
}

// kernelLikeRT9915 is a runtime backend with no cached-status probe,
// standing in for the kernel/legacy dataplane (nil-embedded: only the
// type assertion runs against it, never a method call).
type kernelLikeRT9915 struct {
	dataplane.RuntimeDataPlane
}

// TestGenGuardCapacityForRuntime_9915 pins F-044 backend capacity
// resolution: helper reports provisioned sessions, kernel falls back to the
// addressed max, nil/unknown stays unknown (callers retain previous).
func TestGenGuardCapacityForRuntime_9915(t *testing.T) {
	if got, ok := genGuardCapacityForRuntime(nil); ok || got != 0 {
		t.Fatalf("nil runtime = (%d, %v), want (0, false)", got, ok)
	}
	if got, ok := genGuardCapacityForRuntime(&capacityProbeDP9915{maxSessions: 786432}); !ok || got != 786432 {
		t.Fatalf("helper runtime = (%d, %v), want (786432, true)", got, ok)
	}
	if got, ok := genGuardCapacityForRuntime(&capacityProbeDP9915{maxSessions: 0}); ok || got != 0 {
		t.Fatalf("unknown helper = (%d, %v), want (0, false)", got, ok)
	}
	if got, ok := genGuardCapacityForRuntime(&kernelLikeRT9915{}); !ok || got != conntrack.MaxSessions/2 {
		t.Fatalf("kernel runtime = (%d, %v), want (%d, true)", got, ok, conntrack.MaxSessions/2)
	}
}
