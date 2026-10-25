package daemon

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

// #17014 (R4-Q31-01) — restoreStep0TunablesOnShutdown was a THIRD
// shutdown-path applySem acquire and the only unbounded one: it acquired
// with context.Background(), so its "proceeding without it" warning branch
// was dead. #8597 bounded the scheduler acquire, but its documentation
// omitted this already-existing restore acquire in three places.
//
// Before this fix, a wedged holder let the shutdown drain and
// stopPolicySchedulerLoop time out, then blocked forever in the restore
// until systemd SIGKILLed the process. That lost the #801 B2 host-tunable
// restore and the #16083 final syslog drain (both after the restore).
//
// TestRestoreStep0TunablesIsBoundedByAWedgedApply_17014 is the RED-on-revert
// core, mirroring the reporter's probe: applySem held by an in-flight apply,
// restoreStep0TunablesOnShutdown must return within the common shutdown bound
// instead of blocking until SIGKILL. A populated snapshot and concurrent map
// writer prove timeout does not hand off the snapshot and race that apply.
func TestRestoreStep0TunablesIsBoundedByAWedgedApply_17014(t *testing.T) {
	const path = "/dev/null"
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		priorTunables: &priorHostTunables{
			neighRetrans: map[string]string{path: "250"},
		},
	}
	prior := d.priorTunables

	// The in-flight apply: it owns applySem and continues to mutate a
	// populated snapshot while shutdown attempts the bounded restore.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}
	stopWriter := make(chan struct{})
	writerDone := make(chan string, 1)
	writerStarted := make(chan struct{})
	go func() {
		value := "250"
		close(writerStarted)
		for {
			prior.neighRetrans[path] = value
			select {
			case <-stopWriter:
				writerDone <- value
				return
			default:
			}
			if value == "250" {
				value = "251"
			} else {
				value = "250"
			}
			time.Sleep(time.Millisecond)
		}
	}()
	<-writerStarted

	start := time.Now()

	done := make(chan struct{})
	go func() {
		d.restoreStep0TunablesOnShutdown()
		close(done)
	}()

	earlyReturn := false
	select {
	case <-done:
		earlyReturn = true
	case <-time.After(150 * time.Millisecond):
		// Prove the test exercises a real holder before entering the bound wait.
	}

	var timedOut bool
	if !earlyReturn {
		select {
		case <-done:
			// The shutdown acquire gave up after its bounded wait.
		case <-time.After(applyCloseoutDrainTimeout + time.Second):
			timedOut = true
		}
	}
	close(stopWriter)
	lastValue := <-writerDone

	if earlyReturn {
		d.applySem.Release(1)
		t.Fatal("restoreStep0TunablesOnShutdown completed before the shutdown " +
			"acquire bound while applySem was held")
	}

	if timedOut {
		// Release the fixture permit so a reverted, unbounded implementation
		// drains its goroutine before the test reports RED.
		d.applySem.Release(1)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("restoreStep0TunablesOnShutdown remained stuck after applySem was released")
		}
		t.Fatal("restoreStep0TunablesOnShutdown did not return within " +
			"applyCloseoutDrainTimeout + 1s while a wedged apply held applySem; " +
			"its shutdown-path acquire is unbounded (#17014)")
	}
	if elapsed := time.Since(start); elapsed < applyCloseoutDrainTimeout {
		t.Errorf("returned after %v, before the %v budget: it cannot have waited for "+
			"the semaphore at all", elapsed, applyCloseoutDrainTimeout)
	}
	if d.priorTunables != prior {
		t.Fatal("restoreStep0TunablesOnShutdown handed off or cleared the snapshot " +
			"after its bounded acquire timed out; the in-flight apply still owns it (#17014)")
	}
	if got := prior.neighRetrans[path]; got != lastValue {
		t.Errorf("restore changed the apply-owned snapshot on timeout: got %q, "+
			"want the concurrent writer's final value %q", got, lastValue)
	}

	// The failed acquire must not release a permit it never took. Otherwise
	// a second apply can enter while the wedged holder is still active.
	if d.applySem.TryAcquire(1) {
		d.applySem.Release(1)
		t.Fatal("restoreStep0TunablesOnShutdown released a permit it never took; " +
			"another apply can run concurrently with the wedged holder (#17014/#8597)")
	}
	d.applySem.Release(1)
	select {
	case <-done:
		// Restore returned on timeout and retained the snapshot.
	case <-time.After(2 * time.Second):
		t.Fatal("restoreStep0TunablesOnShutdown did not return")
	}
}

// TestShutdownApplySemAcquiresSerializeConcurrentWork_17014 drives several
// concurrent shutdown callers through the shared acquire protocol. Each
// simulates work in the protected critical section; the active count must
// never exceed one, and the permit must be available afterwards.
func TestShutdownApplySemAcquiresSerializeConcurrentWork_17014(t *testing.T) {
	const callers = 3
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	start := make(chan struct{})
	ready := make(chan struct{}, callers)
	results := make(chan bool, callers)
	var finished sync.WaitGroup
	finished.Add(callers)
	var mu sync.Mutex
	active, maximum := 0, 0

	for range callers {
		go func() {
			defer finished.Done()
			ready <- struct{}{}
			<-start
			if acquired, _ := d.acquireApplySemForShutdown(); !acquired {
				results <- false
				return
			}
			mu.Lock()
			active++
			if active > maximum {
				maximum = active
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			active--
			mu.Unlock()
			d.applySem.Release(1)
			results <- true
		}()
	}
	for range callers {
		<-ready
	}
	close(start)
	finished.Wait()
	close(results)

	for acquired := range results {
		if !acquired {
			t.Error("a concurrent shutdown acquire failed with a freeable semaphore")
		}
	}
	if maximum != 1 {
		t.Errorf("concurrent shutdown critical sections overlapped: max active=%d, want 1 "+
			"(double-apply / semaphore serialization regression)", maximum)
	}
	if !d.applySem.TryAcquire(1) {
		t.Fatal("applySem remained held after concurrent shutdown callers completed")
	}
	d.applySem.Release(1)
}

func shutdownFunctionSource(t *testing.T, file, signature string) string {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	start := strings.Index(string(src), signature)
	if start < 0 {
		t.Fatalf("%s does not define %q", file, signature)
	}
	body := string(src)[start:]
	if next := strings.Index(body[len(signature):], "\nfunc "); next >= 0 {
		body = body[:len(signature)+next]
	}
	return body
}

// TestShutdownApplySemAcquiresUseOneBoundedHelper_17014 pins all three
// shutdown acquire sites. A context.Background() acquire or a hand-written
// fourth site must fail this scan, not silently reopen the incomplete census
// that prompted #17014.
func TestShutdownApplySemAcquiresUseOneBoundedHelper_17014(t *testing.T) {
	helper := shutdownFunctionSource(t, "daemon_run_shutdown.go",
		"func (d *Daemon) acquireApplySemForShutdown(")
	if got := strings.Count(helper, "d.applySem.Acquire("); got != 1 {
		t.Errorf("shared helper has %d direct applySem.Acquire calls, want 1", got)
	}
	if !strings.Contains(helper, "context.WithTimeout(context.Background(), applyCloseoutDrainTimeout)") {
		t.Error("shared shutdown acquire is not bounded by applyCloseoutDrainTimeout")
	}

	for _, site := range []struct {
		file, signature string
	}{
		{"daemon_run_shutdown.go", "func (d *Daemon) runShutdownSequence("},
		{"daemon_scheduler.go", "func (d *Daemon) stopPolicySchedulerLoop("},
		{"host_tunables_daemon.go", "func (d *Daemon) restoreStep0TunablesOnShutdown("},
	} {
		body := shutdownFunctionSource(t, site.file, site.signature)
		if !strings.Contains(body, "d.acquireApplySemForShutdown()") {
			t.Errorf("%s does not use the shared bounded shutdown acquire", site.signature)
		}
		if strings.Contains(body, "d.applySem.Acquire(") {
			t.Errorf("%s has a hand-written applySem acquire outside the helper", site.signature)
		}
	}

	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	start := strings.Index(string(readme), "- **Every shutdown-path `applySem` acquire")
	if start < 0 {
		t.Fatal("README.md does not document the shutdown acquire bound")
	}
	section := string(readme)[start:]
	if end := strings.Index(section[1:], "\n- **"); end >= 0 {
		section = section[:end+1]
	}
	for _, stale := range []string{"exactly two", "exactly three"} {
		if strings.Contains(section, stale) {
			t.Errorf("README shutdown section has a stale acquire census: %q", stale)
		}
	}
	for _, name := range []string{
		"stopPolicySchedulerLoop",
		"restoreStep0TunablesOnShutdown",
	} {
		if !strings.Contains(section, name) {
			t.Errorf("README shutdown section omits %s", name)
		}
	}

	schedulerTestDoc, err := os.ReadFile("scheduler_stop_bounded_8597_test.go")
	if err != nil {
		t.Fatalf("read scheduler_stop_bounded_8597_test.go: %v", err)
	}
	if strings.Contains(string(schedulerTestDoc), "exactly two") {
		t.Error("scheduler test doc retains the incomplete shutdown acquire census")
	}
}
