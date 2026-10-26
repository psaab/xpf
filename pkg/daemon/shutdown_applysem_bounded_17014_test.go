package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
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
// A wedged holder previously received a fresh five-second wait at the drain,
// scheduler stop, restore, and Run's deferred scheduler stop. The sequence
// now shares one deadline across those paths, and the scheduler's stopped
// latch makes the deferred call an immediate no-op after ordered shutdown.
// Restore still skips unsafe map access and preserves its snapshot when the
// semaphore remains held at expiry.
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

func TestShutdownApplySemAcquisitionsShareWaitDeadline_17014(t *testing.T) {
	const (
		totalWaitBudget = 400 * time.Millisecond
		initialHold     = 150 * time.Millisecond
	)
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	ctx, cancel := context.WithTimeout(context.Background(), totalWaitBudget)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}
	released := make(chan struct{})
	time.AfterFunc(initialHold, func() {
		d.applySem.Release(1)
		close(released)
	})

	acquired, err := d.acquireApplySemForShutdownContext(ctx)
	if err != nil || !acquired {
		t.Fatalf("first acquire = (%v, %v), want success", acquired, err)
	}
	<-released
	d.applySem.Release(1)

	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("second precondition acquire: %v", err)
	}
	remainingAtStart := time.Until(deadline)
	started := time.Now()
	acquired, err = d.acquireApplySemForShutdownContext(ctx)
	secondWait := time.Since(started)
	if acquired {
		d.applySem.Release(1)
		t.Fatal("second acquire unexpectedly took a held permit")
	}
	if err == nil {
		t.Fatal("second acquire should exhaust the shared deadline")
	}
	if secondWait > remainingAtStart+100*time.Millisecond {
		t.Errorf("second acquire waited %v with only %v left; acquisitions did not "+
			"share one deadline", secondWait, remainingAtStart)
	}
	if d.applySem.TryAcquire(1) {
		t.Fatal("timed-out acquire released a permit it never took")
	}
	d.applySem.Release(1)

	// An expired shared deadline still permits immediate progress when the
	// permit is already free.
	acquired, err = d.acquireApplySemForShutdownContext(ctx)
	if err != nil || !acquired {
		t.Fatalf("nonblocking acquire after deadline = (%v, %v), want success", acquired, err)
	}
	d.applySem.Release(1)
}

func TestStopPolicySchedulerLoopDoesNotWaitAgainAfterShutdown_17014(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		d.stopPolicySchedulerLoopWithContext(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("first scheduler stop did not return after its deadline")
	}
	if !d.schedulerStopped.Load() {
		t.Fatal("scheduler stop latch was not set")
	}

	started := time.Now()
	d.stopPolicySchedulerLoopWithContext(ctx)
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Errorf("deferred scheduler stop waited again after the ordered stop: %v", elapsed)
	}
	if d.applySem.TryAcquire(1) {
		t.Fatal("timed-out scheduler stop released a permit it never took")
	}
	d.applySem.Release(1)
}

func TestRunShutdownChainAndDeferredSchedulerStopShareDeadline_17014(t *testing.T) {
	d, _ := fenceTestDaemon(t)
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	var wg sync.WaitGroup
	done := make(chan error, 1)
	go func() {
		err := d.runShutdownSequence(ctx, &wg, func() {}, nil)
		// Run's deferred scheduler stop receives the same lazily-created
		// shutdown context used by the sequence above.
		d.stopPolicySchedulerLoopWithContext(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runShutdownSequence returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		d.applySem.Release(1)
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("shutdown sequence plus Run's deferred scheduler stop exceeded 2s " +
			"with a wedged apply holder; shutdown acquires must share one deadline")
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Errorf("shutdown sequence plus deferred scheduler stop took %v; want well "+
			"under TimeoutStopSec", elapsed)
	}
	if !d.schedulerStopped.Load() {
		t.Error("shutdown sequence did not latch the scheduler as stopped")
	}
	if d.applySem.TryAcquire(1) {
		d.applySem.Release(1)
		t.Error("shutdown released a permit still owned by the wedged apply")
	} else {
		d.applySem.Release(1)
	}
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

func shutdownApplySemAcquireCounts(t *testing.T, files ...string) map[string]int {
	t.Helper()
	counts := make(map[string]int)
	for _, file := range files {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				method, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || method.Sel.Name != "Acquire" {
					return true
				}
				sem, ok := method.X.(*ast.SelectorExpr)
				if ok && sem.Sel.Name == "applySem" {
					counts[fn.Name.Name]++
				}
				return true
			})
		}
	}
	return counts
}

// TestShutdownApplySemAcquisitionsUseSharedContext_17014 scans the shutdown
// call graph's entry points so a new raw applySem.Acquire cannot hide outside
// the bounded context helper.
func TestShutdownApplySemAcquisitionsUseSharedContext_17014(t *testing.T) {
	helperSignature := "func (d *Daemon) acquireApplySemForShutdownContext("
	helper := shutdownFunctionSource(t, "daemon_run_shutdown.go", helperSignature)
	if got := strings.Count(helper, "d.applySem.Acquire("); got != 1 {
		t.Errorf("shared context helper has %d direct applySem.Acquire calls, want 1", got)
	}
	if !strings.Contains(helper, "ctx.Err()") ||
		!strings.Contains(helper, "d.applySem.TryAcquire(1)") ||
		!strings.Contains(helper, "d.applySem.Acquire(ctx, 1)") {
		t.Error("shared helper must use the context deadline and nonblocking fallback")
	}
	deadline := shutdownFunctionSource(t, "daemon_run_shutdown.go",
		"func newShutdownApplyContext(")
	if !strings.Contains(deadline,
		"context.WithTimeout(context.Background(), applyCloseoutDrainTimeout)") {
		t.Error("shutdown context does not establish the shared closeout deadline")
	}

	sequence := shutdownFunctionSource(t, "daemon_run_shutdown.go",
		"func (d *Daemon) runShutdownSequence(")
	for _, call := range []string{
		"d.acquireApplySemForShutdownContext(shutdownApplyCtx)",
		"d.stopPolicySchedulerLoopWithContext(shutdownApplyCtx)",
		"d.restoreStep0TunablesOnShutdownWithContext(shutdownApplyCtx)",
	} {
		if !strings.Contains(sequence, call) {
			t.Errorf("runShutdownSequence does not share its shutdown context with %s", call)
		}
	}

	run := shutdownFunctionSource(t, "daemon_run.go", "func (d *Daemon) Run(")
	if strings.Count(run, "shutdownApplyContext()") < 3 ||
		!strings.Contains(run, "d.stopPolicySchedulerLoopWithContext(shutdownApplyCtx)") {
		t.Error("Run does not pass one lazily-created context to both shutdown paths and its deferred scheduler stop")
	}

	stop := shutdownFunctionSource(t, "daemon_scheduler.go",
		"func (d *Daemon) stopPolicySchedulerLoopWithContext(")
	latch := strings.Index(stop, "d.schedulerStopped.Load()")
	acquire := strings.Index(stop, "d.acquireApplySemForShutdownContext(ctx)")
	if latch < 0 || acquire < 0 || latch > acquire {
		t.Error("scheduler stop must fast-path its stopped latch before acquiring applySem")
	}

	// Include Run and every shutdown wrapper/implementation, rather than only
	// the three sites present when the earlier census was written.
	for _, site := range []struct {
		file, signature string
		wantAcquire     int
	}{
		{"daemon_run_shutdown.go", helperSignature, 1},
		{"daemon_run_shutdown.go", "func (d *Daemon) acquireApplySemForShutdown(", 0},
		{"daemon_run_shutdown.go", "func (d *Daemon) runShutdownSequence(", 0},
		{"daemon_scheduler.go", "func (d *Daemon) stopPolicySchedulerLoop(", 0},
		{"daemon_scheduler.go", "func (d *Daemon) stopPolicySchedulerLoopWithContext(", 0},
		{"host_tunables_daemon.go", "func (d *Daemon) restoreStep0TunablesOnShutdown(", 0},
		{"host_tunables_daemon.go", "func (d *Daemon) restoreStep0TunablesOnShutdownWithContext(", 0},
		{"daemon_run.go", "func (d *Daemon) Run(", 0},
	} {
		body := shutdownFunctionSource(t, site.file, site.signature)
		if got := strings.Count(body, "d.applySem.Acquire("); got != site.wantAcquire {
			t.Errorf("%s has %d direct applySem.Acquire calls, want %d (only the bounded helper may acquire)",
				site.signature, got, site.wantAcquire)
		}
	}

	// Scan every relevant source file, not only the currently known three
	// shutdown methods. The two direct acquisitions in scheduler tick callbacks
	// are live-runtime operations, not shutdown acquisitions; every other direct
	// applySem.Acquire in these files must be the bounded shutdown helper.
	acquireCounts := shutdownApplySemAcquireCounts(t,
		"daemon_run_shutdown.go", "daemon_scheduler.go", "host_tunables_daemon.go", "daemon_run.go")
	allowedAcquires := map[string]int{
		"acquireApplySemForShutdownContext":   1,
		"publishPolicyScheduleStateWithLatch": 1,
		"heartbeatPolicySchedule":             1,
	}
	for name, count := range acquireCounts {
		if want := allowedAcquires[name]; count != want {
			t.Errorf("%s has %d direct applySem.Acquire calls in the shutdown source files, want %d",
				name, count, want)
		}
	}
	for name, want := range allowedAcquires {
		if got := acquireCounts[name]; got != want {
			t.Errorf("%s has %d direct applySem.Acquire calls, want %d", name, got, want)
		}
	}

	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	start := strings.Index(string(readme), "- **Shutdown `applySem` acquisitions share one BOUNDED deadline")
	if start < 0 {
		t.Fatal("README.md does not document the shared shutdown acquire deadline")
	}
	section := string(readme)[start:]
	if end := strings.Index(section[1:], "\n- **"); end >= 0 {
		section = section[:end+1]
	}
	for _, stale := range []string{"exactly two", "exactly three", "for retry"} {
		if strings.Contains(section, stale) {
			t.Errorf("README shutdown section has stale wording: %q", stale)
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
