package snmp

import (
	"testing"
)

// pressureAgent9917 returns an agent with no worker draining and the standard
// production-depth queue.
func pressureAgent9917() *Agent {
	agent := &Agent{}
	agent.trapQueue = make(chan trapJob, trapQueueDepth)
	agent.trapWorkerOnce.Do(func() {}) // consume the Once so no worker starts
	return agent
}

// TestTrapPerTargetCapAdmitsHealthy9917 is the F-140 cell: a dead receiver's
// backlog must not evict healthy-target traps from the shared queue. With no
// worker draining, 256 sick-target jobs plus one healthy job are enqueued; the
// sick share stops at the pressure threshold (free burst absorption below
// half-full, capped above it) and the healthy trap is admitted. RED on base
// (shared FIFO: sick fills all 256, healthy dropped queue-full).
func TestTrapPerTargetCapAdmitsHealthy9917(t *testing.T) {
	agent := pressureAgent9917()

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
		t.Fatalf("F-140: healthy-target trap admitted = %d, want 1 (sick backlog of %d evicted it)", healthyN, sickN)
	}
	if sickN != trapCapPressureThreshold {
		t.Fatalf("F-140: sick-target backlog = %d, want exactly %d (free absorption to half-full, then capped)", sickN, trapCapPressureThreshold)
	}
	if got, want := agent.trapsDropped.Load(), uint64(trapQueueDepth-trapCapPressureThreshold); got != want {
		t.Fatalf("trapsDropped = %d, want %d (shed sick backlog past pressure, exactly once each)", got, want)
	}
}

// TestTrapFanOutBelowPressureLosesNothing9917 is the fan-out regression cell: a
// healthy burst that fits the shared queue must be admitted whole even while
// the worker is stalled -- the per-target cap binds only under pressure, so it
// cannot drop traffic the un-capped queue would have held. (An always-on cap
// admits 64 here and drops 16 despite 192 free slots.)
func TestTrapFanOutBelowPressureLosesNothing9917(t *testing.T) {
	agent := pressureAgent9917()

	const events = 40
	for i := 0; i < events; i++ {
		agent.enqueueTrap(trapJob{target: "198.51.100.7:162", pkt: []byte{1}})
		agent.enqueueTrap(trapJob{target: "203.0.113.8:162", pkt: []byte{1}})
	}
	if got := len(agent.trapQueue); got != 2*events {
		t.Fatalf("F-140: admitted %d of %d healthy fan-out jobs, want all (cap bound without queue pressure)", got, 2*events)
	}
	if got := agent.trapsDropped.Load(); got != 0 {
		t.Fatalf("trapsDropped = %d, want 0 (free shared capacity must not shed)", got)
	}
}

// TestTrapPerTargetCapNormalizesPortSpelling9917 pins that the cap counts the
// RECEIVER, not the spelling: "host" and "host:162" name the same :162 dial
// target (sendTrap applies the default port), so jobs under both spellings
// share one cap once pressure binds. RED on base (no cap at all).
func TestTrapPerTargetCapNormalizesPortSpelling9917(t *testing.T) {
	agent := pressureAgent9917()

	// Pre-pressure filler from one unrelated receiver: the queue reaches the
	// threshold with no cap binding, so the spellings below are judged purely
	// on receiver identity.
	for i := 0; i < trapCapPressureThreshold; i++ {
		agent.enqueueTrap(trapJob{target: "198.51.100.99:162", pkt: []byte{9}})
	}
	for i := 0; i < maxPerTargetTrapQueue; i++ {
		agent.enqueueTrap(trapJob{target: "192.0.2.9", pkt: []byte{1}})
	}
	for i := 0; i < maxPerTargetTrapQueue; i++ {
		agent.enqueueTrap(trapJob{target: "192.0.2.9:162", pkt: []byte{1}})
	}
	if got, want := len(agent.trapQueue), trapCapPressureThreshold+maxPerTargetTrapQueue; got != want {
		t.Fatalf("F-140: queued %d, want %d (one receiver, one cap of %d past pressure)", got, want, maxPerTargetTrapQueue)
	}
	if got := agent.trapsDropped.Load(); got != maxPerTargetTrapQueue {
		t.Fatalf("trapsDropped = %d, want %d (second spelling shed as the same receiver)", got, maxPerTargetTrapQueue)
	}
}

// TestTrapPerTargetCapCanonicalizesNumericIP9917 pins that numeric-IP spellings
// key together: 2001:db8::9, 2001:0db8::9 and 2001:DB8::9 dial identically, so
// spelling games cannot multiply one receiver's capped share. RED on base (no
// cap) and on keying without canonicalization (96 admitted).
func TestTrapPerTargetCapCanonicalizesNumericIP9917(t *testing.T) {
	agent := pressureAgent9917()

	for i := 0; i < trapCapPressureThreshold; i++ {
		agent.enqueueTrap(trapJob{target: "198.51.100.99:162", pkt: []byte{9}})
	}
	spellings := []string{"2001:db8::9", "2001:0db8::9", "2001:DB8::9"}
	for _, s := range spellings {
		for i := 0; i < maxPerTargetTrapQueue; i++ {
			agent.enqueueTrap(trapJob{target: s, pkt: []byte{1}})
		}
	}
	if got, want := len(agent.trapQueue), trapCapPressureThreshold+maxPerTargetTrapQueue; got != want {
		t.Fatalf("F-140: queued %d, want %d (three spellings, one receiver, one cap)", got, want)
	}
	if got, want := agent.trapsDropped.Load(), uint64(2*maxPerTargetTrapQueue); got != want {
		t.Fatalf("trapsDropped = %d, want %d (alias spellings shed as the same receiver)", got, want)
	}
}
