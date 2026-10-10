package userspace

import "testing"

func TestHelperSupervisorStateUsesArmedCrashLoopDebt12159(t *testing.T) {
	m := New()
	m.mu.Lock()
	m.procGen = 7
	m.helperCrash = HelperCrashRecord{
		LastExitWasCrash: true,
		Restarts:         1,
		restartGen:       m.procGen,
	}
	m.mu.Unlock()
	if running, looping := m.HelperSupervisorState(); running || looping {
		t.Fatalf("one fast restart state = (running=%v, looping=%v), want (false,false)", running, looping)
	}

	attempt := 1
	for helperRestartDelay(attempt) < helperRestartBackoffMax {
		attempt++
	}
	m.mu.Lock()
	m.helperCrash.Restarts = attempt
	m.mu.Unlock()
	if running, looping := m.HelperSupervisorState(); running || !looping {
		t.Fatalf("armed capped retry state = (running=%v, looping=%v), want (false,true)", running, looping)
	}

	// CrashLooping alone deliberately survives an intentional stop, but an
	// orphaned retry is not a persistent supervisor loop and cannot retain HA
	// election debt.
	m.mu.Lock()
	m.procGen++
	m.mu.Unlock()
	if running, looping := m.HelperSupervisorState(); running || looping {
		t.Fatalf("cancelled retry state = (running=%v, looping=%v), want (false,false)", running, looping)
	}
}
