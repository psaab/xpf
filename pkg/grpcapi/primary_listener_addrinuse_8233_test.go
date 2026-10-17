package grpcapi

import (
	"context"
	"errors"

	"github.com/psaab/xpf/pkg/authz"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// #8233: a second xpfd used to come up with a permanently dead management
// listener. supervisePrimaryListener treated every bind failure as transient
// and Run returned nil, so the daemon started and everything else came up.

func addrInUseErr() error {
	return &net.OpError{
		Op:  "listen",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "bind", Err: syscall.EADDRINUSE},
	}
}

// THE BINDING BETWEEN THE CONSTANT AND THE UNIT.
//
// The grace is not a number that happens to work — it must exceed the unit's
// TimeoutStopSec, or a restart overlap (the predecessor still holding the port,
// legitimately, for up to that long) is treated as a duplicate and
// Restart=on-failure turns the fatal exit into a restart LOOP.
//
// Documenting that in a comment would leave it true only until someone raises
// TimeoutStopSec. Parsing the unit makes the relationship checked.
func TestPrimaryAddrInUseGraceExceedsUnitStopTimeout_8233(t *testing.T) {
	const unit = "../../test/incus/xpfd.service"
	b, err := os.ReadFile(unit)
	if err != nil {
		t.Fatalf("read %s: %v", unit, err)
	}
	m := regexp.MustCompile(`(?m)^TimeoutStopSec=(\d+)`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("no TimeoutStopSec in %s — this cell can no longer see the value it exists to "+
			"compare against, and would pass vacuously", unit)
	}
	stop, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse TimeoutStopSec %q: %v", m[1], err)
	}
	stopDur := time.Duration(stop) * time.Second
	if primaryAddrInUseGrace <= stopDur {
		t.Errorf("primaryAddrInUseGrace (%s) does not exceed the unit's TimeoutStopSec (%s). "+
			"A restarting predecessor may hold the management port for the whole stop timeout, so "+
			"a grace at or below it makes a legitimate restart look like a duplicate — and "+
			"Restart=on-failure turns that fatal exit into a restart loop. Raise the grace, do "+
			"not lower the timeout.", primaryAddrInUseGrace, stopDur)
	}
}

// A persistent EADDRINUSE must END the daemon rather than be retried forever.
//
// #14581: the holder attribution is INJECTED as uid 0 here — the fatal
// is sound only for a privileged (duplicate-xpfd) holder. The same
// synthetic EADDRINUSE with a non-root or unattributed holder must NOT
// be fatal; those arms are TestNonRootHolderIsNotFatal_14581 and
// TestUnattributedHolderIsNotFatal_14581.
func TestPersistentAddrInUseIsFatal_8233(t *testing.T) {
	s := &Server{addr: "127.0.0.1:0"}
	// BOUNDED DELIBERATELY. The defect this test guards is "retries forever",
	// so the failure mode of the code under test is a HANG, and an unbounded
	// context makes the test inherit it: disabling the fatal branch made this
	// case run until the CI timeout killed the whole package, which reports a
	// void rather than a diagnosis. 10s is ~400x the 20ms grace plus a 2ms
	// backoff cap, so a correct supervisor returns in ~25ms and never comes
	// near it. The deadline is not the pass condition -- expiry returns
	// something that is not ErrManagementPortHeld, so the assertion below
	// still fails, and it fails with a message instead of a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     2 * time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 20 * time.Millisecond,
		holderCheck:    holderFunc(authz.ListenerOwner{Found: true, UID: 0}, nil),
		listen:         func(context.Context) (net.Listener, error) { return nil, addrInUseErr() },
		serve:          func(context.Context, net.Listener) error { return nil },
	})
	if !errors.Is(err, ErrManagementPortHeld) {
		t.Fatalf("supervisor returned %v, want ErrManagementPortHeld. Retrying forever is how a "+
			"second xpfd ran with a dead management listener and no external signal", err)
	}
	// The message must name what it found, not merely that something failed.
	if !strings.Contains(err.Error(), "held for") {
		t.Errorf("fatal error does not say how long it waited: %v", err)
	}
}

// THE RESTART-OVERLAP CASE, and the reason this is a window rather than
// first-bind-fatal. RestartSec=1 against TimeoutStopSec=20 means the successor
// routinely starts while the predecessor still holds the port. If that were
// fatal on sight, Restart=on-failure would make the fatal exit re-trigger the
// start — a restart loop for the whole shutdown window, and no convergence at
// all if the predecessor is wedged.
func TestAddrInUseThatClearsInsideTheWindowStartsNormally_8233(t *testing.T) {
	var attempts int
	served := make(chan struct{})
	s := &Server{addr: "127.0.0.1:0"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     2 * time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 10 * time.Second, // far longer than the collision lasts
		listen: func(context.Context) (net.Listener, error) {
			attempts++
			if attempts < 4 {
				return nil, addrInUseErr() // the predecessor is still exiting
			}
			return net.Listen("tcp", "127.0.0.1:0")
		},
		serve: func(ctx context.Context, lis net.Listener) error {
			close(served)
			_ = lis.Close()
			return nil // clean stop -> supervisor returns nil
		},
	})
	if err != nil {
		t.Fatalf("a collision that CLEARED inside the window must not be fatal; got %v", err)
	}
	select {
	case <-served:
	default:
		t.Error("the listener never served, so this cell did not exercise the recovery path")
	}
}

// ONLY EADDRINUSE. A permissions failure or a missing VRF is a different
// condition and must stay supervised — turning every bind error fatal would
// take a node down for a fault the supervisor exists to ride out.
func TestNonAddrInUseBindErrorIsNeverFatal_8233(t *testing.T) {
	s := &Server{addr: "127.0.0.1:0"}
	// Bounded, so a supervisor that (correctly) retries forever ends the cell
	// by ctx cancellation rather than hanging the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	err := s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     2 * time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 10 * time.Millisecond, // would have expired many times over
		listen: func(context.Context) (net.Listener, error) {
			return nil, &net.OpError{Op: "listen", Net: "tcp",
				Err: &os.SyscallError{Syscall: "bind", Err: syscall.EACCES}}
		},
		serve: func(context.Context, net.Listener) error { return nil },
	})
	if err != nil {
		t.Fatalf("a non-EADDRINUSE bind failure became fatal (%v). EACCES is a different "+
			"condition — a permissions problem or a missing VRF — and must stay supervised", err)
	}
}

// An intermittent collision that resolves between attempts must not accumulate
// toward the deadline: the window measures a CONTINUOUS run of EADDRINUSE, and
// a supervisor that never reset the start time would eventually kill a daemon
// whose collisions were all transient.
func TestAddrInUseRunResetsOnAnInterveningError_8233(t *testing.T) {
	var attempts int
	s := &Server{addr: "127.0.0.1:0"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 40 * time.Millisecond,
		listen: func(context.Context) (net.Listener, error) {
			attempts++
			if attempts%2 == 0 {
				return nil, &net.OpError{Op: "listen", Net: "tcp",
					Err: &os.SyscallError{Syscall: "bind", Err: syscall.EACCES}}
			}
			return nil, addrInUseErr()
		},
		serve: func(context.Context, net.Listener) error { return nil },
	})
	if err != nil {
		t.Fatalf("alternating EADDRINUSE/EACCES became fatal (%v); no CONTINUOUS run of "+
			"EADDRINUSE ever reached the grace, so the daemon must stay up", err)
	}
}
