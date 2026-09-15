package snmp

import (
	"testing"
)

// TestTrapPerTargetCapAdmitsHealthy9917 is the F-140 cell: a dead receiver's
// backlog must not evict healthy-target traps from the shared queue. With no
// worker draining, 256 sick-target jobs plus one healthy job are enqueued; the
// per-target admission cap must hold the sick share to maxPerTargetTrapQueue so
// the healthy trap is admitted. RED on base (shared FIFO: sick fills all 256,
// healthy dropped queue-full).
func TestTrapPerTargetCapAdmitsHealthy9917(t *testing.T) {
	agent := &Agent{}
	agent.trapQueue = make(chan trapJob, trapQueueDepth)
	agent.trapWorkerOnce.Do(func() {}) // consume the Once so no worker starts

	const sick = "192.0.2.9:162"
	for i := 0; i < trapQueueDepth; i++ {
		agent.enqueueTrap(trapJob{target: sick, pkt: []byte{1}})
	}
	agent.enqueueTrap(trapJob{target: "198.51.100.7:162", pkt: []byte{2}})

	var sickN, healthyN int
	for drained := false; !drained; {
		select {
		case job := <-agent.trapQueue:
			if job.target == sick {
				sickN++
			} else {
				healthyN++
			}
		default:
			drained = true
		}
	}
	if healthyN != 1 {
		t.Fatalf("F-140: healthy-target trap admitted = %d, want 1 (sick backlog of %d filled the shared queue and evicted it)", healthyN, sickN)
	}
	if sickN > maxPerTargetTrapQueue {
		t.Fatalf("F-140: sick-target backlog = %d, want <= %d (per-target admission cap not enforced)", sickN, maxPerTargetTrapQueue)
	}
	if got := agent.trapsDropped.Load(); got != trapQueueDepth-maxPerTargetTrapQueue {
		t.Fatalf("trapsDropped = %d, want %d (shed sick backlog beyond the cap, exactly once each)", got, trapQueueDepth-maxPerTargetTrapQueue)
	}
}

// TestTrapPerTargetCapNormalizesPortSpelling9917 pins that the cap counts the
// RECEIVER, not the spelling: "host" and "host:162" name the same :162 dial
// target (sendTrap applies the default port), so jobs under both spellings
// share one cap. RED on base (no cap at all: all admitted).
func TestTrapPerTargetCapNormalizesPortSpelling9917(t *testing.T) {
	agent := &Agent{}
	agent.trapQueue = make(chan trapJob, trapQueueDepth)
	agent.trapWorkerOnce.Do(func() {})

	for i := 0; i < maxPerTargetTrapQueue; i++ {
		agent.enqueueTrap(trapJob{target: "192.0.2.9", pkt: []byte{1}})
	}
	for i := 0; i < maxPerTargetTrapQueue; i++ {
		agent.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}
	admitted := len(agent.trapQueue)
	if admitted != maxPerTargetTrapQueue {
		t.Fatalf("F-140: admitted %d across equivalent spellings, want exactly %d (one receiver, one cap)", admitted, maxPerTargetTrapQueue)
	}
}
