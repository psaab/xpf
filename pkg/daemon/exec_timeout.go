// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// externalCommandTimeout bounds external commands run on the config-apply
// path. 15s mirrors the established FRR precedent (pkg/frr/vtysh.go
// FrrReloadPy / VtyshLoad callers and the chrony reload in
// daemon_system.go): apply-path exec sites run while applySem is held,
// so a single hung systemctl/useradd/chown would otherwise wedge every
// CLI/gRPC/HTTP commit and HA config sync indefinitely (#1794).
const externalCommandTimeout = 15 * time.Second

// runCommandTimeout runs an external command under a 15s context timeout
// and returns its combined output. On timeout the process is killed and
// the error reflects the context deadline; callers log the failure and
// continue — apply success/failure semantics are unchanged, failures
// just become visible and bounded.
//
// It is a package var (not a bare func) so tests can capture the argv a
// caller passes to root-privileged tools without spawning real processes —
// the seam the #5005 applySystemLogin option-injection test uses to assert
// the `--` end-of-options separator reaches id/useradd/chown. Production
// code never reassigns it.
var runCommandTimeout = func(name string, args ...string) ([]byte, error) {
	return runCommandStdinTimeout(nil, name, args...)
}

// errHostAuthExecCompletedSuperseded16830 marks a child that RAN TO
// COMPLETION (its mutation may have landed) before the calling goroutine
// was superseded. It deliberately does NOT wrap
// errHostAuthStaleOwner14969: callers that roll back ownership claims on
// a plain failure must not withdraw provenance for a mutation that may
// have succeeded — the newer authority may rely on that marker to revoke
// the credential (#16830, the chpasswd arm of R3-F11-01). A child killed
// by the supersession watcher (context cancelled) never completed, so it
// keeps reporting the plain stale error and rollback remains correct.
var errHostAuthExecCompletedSuperseded16830 = errors.New("host-auth command completed before this closeout owner was superseded; its result is not rolled back (#16830)")

// runWithHostAuthExec15539 runs body (one external-command spawn) with
// the #15539 exec-seam fence applied on BOTH sides of the spawn, closing
// the check-then-exec TOCTOU the entry-only #14969 check left open:
//
//   - BEFORE the spawn it re-checks the calling goroutine's generation;
//     a superseded owner never spawns the command at all.
//   - The spawn runs under a context that a 1ms watcher cancels the
//     moment a newer host-auth authority advances past the caller's
//     captured generation, so an in-flight command (chpasswd, useradd,
//     usermod, systemctl, ...) is KILLED rather than landing its
//     mutation after the newer authority began. A command killed this
//     way reports the stale-owner error, not a plain signal kill.
//   - AFTER the spawn it re-checks again; output from a command that
//     raced supersession is never reported as success.
//
// #16830 refines the after-spawn arm: if the child completed on its own
// (ctx not cancelled by the watcher) but the epoch advanced while it
// ran, its mutation may have landed BEFORE the newer authority's final
// seam — discarding the result and letting the caller roll back its
// provenance claims would withdraw the newer authority's marker. The
// seam therefore returns the child's REAL output/error wrapped with
// errHostAuthExecCompletedSuperseded16830 (never the stale sentinel), so
// claim-rollback callers abstain while the supersession stays visible.
// Only a watcher-killed child (ctx.Err() != nil) reports the plain
// stale error, because then no mutation completed.
//
// Callers on goroutines with no captured generation (the normal tail,
// every non-host-auth exec user) run body directly under a plain
// never-cancelled context — byte-identical to the pre-#15539 seam.
func runWithHostAuthExec15539(body func(context.Context) ([]byte, error)) ([]byte, error) {
	id := currentGoroutineID14969()
	var gen uint64
	captured := false
	if id != 0 {
		if v, ok := hostAuthGoroutineGen14969.Load(id); ok {
			gen, _ = v.(uint64)
			captured = gen != 0
		}
	}
	if !captured {
		return body(context.Background())
	}
	if err := checkHostAuthSeam14969(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if hostAuthGeneration14969.Load() != gen {
					cancel()
					return
				}
			}
		}
	}()
	out, err := body(ctx)
	if staleErr := checkHostAuthSeam14969(); staleErr != nil {
		if ctx.Err() != nil {
			// Watcher killed the in-flight child: nothing completed.
			return nil, staleErr
		}
		// Child completed before supersession was observed: surface its
		// real result, marked completed-but-superseded, so callers do
		// not roll back provenance for a mutation that may have landed.
		if err != nil {
			return out, fmt.Errorf("%w: %w", errHostAuthExecCompletedSuperseded16830, err)
		}
		return out, errHostAuthExecCompletedSuperseded16830
	}
	return out, err
}

// runCommandStdinTimeout is runCommandTimeout with an optional stdin
// (used by `chpasswd -e`, which reads the user:hash pair from stdin).
func runCommandStdinTimeout(stdin io.Reader, name string, args ...string) ([]byte, error) {
	// #14969/#15539: a superseded closeout owner must not spawn — or
	// leave in flight — a credential mutation (chpasswd/useradd/
	// usermod/id/chown/visudo/systemctl) after a newer host-auth
	// authority has begun. runWithHostAuthExec15539 re-validates the
	// generation BEFORE the spawn, kills the child if supersession
	// lands mid-exec, and re-validates after it returns. Callers on
	// goroutines with no captured generation are never refused.
	return runWithHostAuthExec15539(func(execCtx context.Context) ([]byte, error) {
		ctx, cancel := context.WithTimeout(execCtx, externalCommandTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		if stdin != nil {
			cmd.Stdin = stdin
		}
		// WaitDelay caps the post-SIGKILL pipe-drain window. Without it,
		// CombinedOutput blocks until all write-end holders (e.g. PAM
		// exec helpers spawned by useradd) close their copies of the
		// pipe — which may be long after the main process is killed. 5s
		// is generous for simple admin commands; the hard ceiling
		// becomes 15s+5s=20s per site.
		cmd.WaitDelay = 5 * time.Second
		return cmd.CombinedOutput()
	})
}
