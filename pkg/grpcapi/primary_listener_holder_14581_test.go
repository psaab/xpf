package grpcapi

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
)

// #14581: the #8233 fatal must fire only for a PRIVILEGED holder.
//
// Before this, supervisePrimaryListener returned ErrManagementPortHeld
// for ANY persistent EADDRINUSE — the holder's uid was never inspected —
// so a non-root squatter on 127.0.0.1:50051 (an SSH remote forward, a
// compromised service uid) exited xpfd into a Restart=on-failure loop
// while impersonating the management server. These cells drive the
// supervisor with a synthetic EADDRINUSE (the existing #8233 fixture)
// plus an injected holder attribution: the ONLY thing that differs
// between "second xpfd" and "squatter" is the attributed uid, which is
// precisely what the production code now consults.

func holderFunc(owner authz.ListenerOwner, err error) func(string) (authz.ListenerOwner, error) {
	return func(string) (authz.ListenerOwner, error) { return owner, err }
}

// A persistent squat by a NON-ROOT holder must NOT be fatal: the
// supervisor keeps retrying (and alarming) until ctx ends, exactly as
// it does for any other supervised fault.
func TestNonRootHolderIsNotFatal_14581(t *testing.T) {
	s := &Server{addr: "127.0.0.1:50051"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     2 * time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 20 * time.Millisecond,
		holderCheck:    holderFunc(authz.ListenerOwner{Found: true, UID: 1001}, nil),
		selfUID:        0, // the daemon's arm: uid 0 is privileged regardless
		listen:         func(context.Context) (net.Listener, error) { return nil, addrInUseErr() },
		serve:          func(context.Context, net.Listener) error { return nil },
	})
	if err != nil {
		t.Fatalf("a non-root holder (uid 1001) was fatal (%v). Going fatal hands any "+
			"unprivileged port squatter a persistent kill switch via Restart=on-failure", err)
	}
	if errors.Is(err, ErrManagementPortHeld) {
		t.Fatal("ErrManagementPortHeld returned for a non-root holder")
	}
}

// The same squat by a ROOT holder IS the #8233 duplicate-xpfd case and
// stays fatal.
func TestRootHolderRemainsFatal_14581(t *testing.T) {
	s := &Server{addr: "127.0.0.1:50051"}
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
		t.Fatalf("supervisor returned %v, want ErrManagementPortHeld for a root holder "+
			"(the #8233 duplicate-xpfd case must stay fatal)", err)
	}
}

// A holder running as OUR OWN uid is a second xpfd started by the same
// account and stays fatal — driven with an explicit selfUID so the arm
// is reachable without running the suite as that uid pair.
func TestOwnUIDHolderRemainsFatal_14581(t *testing.T) {
	s := &Server{addr: "127.0.0.1:50051"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     2 * time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 20 * time.Millisecond,
		holderCheck:    holderFunc(authz.ListenerOwner{Found: true, UID: 4242}, nil),
		selfUID:        4242,
		listen:         func(context.Context) (net.Listener, error) { return nil, addrInUseErr() },
		serve:          func(context.Context, net.Listener) error { return nil },
	})
	if !errors.Is(err, ErrManagementPortHeld) {
		t.Fatalf("supervisor returned %v, want ErrManagementPortHeld for an own-uid holder", err)
	}
}

// An UNATTRIBUTED holder (no LISTEN row — vanished, other netns) is not
// evidence of another xpfd and must not be fatal.
func TestUnattributedHolderIsNotFatal_14581(t *testing.T) {
	s := &Server{addr: "127.0.0.1:50051"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     2 * time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 20 * time.Millisecond,
		holderCheck:    holderFunc(authz.ListenerOwner{Found: false, Detail: "no listening socket found"}, nil),
		listen:         func(context.Context) (net.Listener, error) { return nil, addrInUseErr() },
		serve:          func(context.Context, net.Listener) error { return nil },
	})
	if err != nil {
		t.Fatalf("an unattributed holder was fatal (%v); unattributed is not evidence of another xpfd", err)
	}
}

// A FAILED holder lookup (unreadable /proc) must never read as
// privileged: a broken observation cannot reinstate fatal-on-anyone.
func TestHolderLookupFailureIsNotFatal_14581(t *testing.T) {
	s := &Server{addr: "127.0.0.1:50051"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     2 * time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 20 * time.Millisecond,
		holderCheck:    holderFunc(authz.ListenerOwner{}, errors.New("socket table unreadable")),
		listen:         func(context.Context) (net.Listener, error) { return nil, addrInUseErr() },
		serve:          func(context.Context, net.Listener) error { return nil },
	})
	if err != nil {
		t.Fatalf("a failed holder lookup was fatal (%v)", err)
	}
}

// The decisive acceptance check with the REAL kernel lookup: hold the
// port with a listener owned by THIS test process and run the
// supervisor against that very address. As a non-root test process
// (the CI/dev case) the holder is non-privileged and the supervisor
// must stay up; as root the holder is uid 0 and it must go fatal. The
// expectation is derived from os.Getuid() so the cell is sound under
// either runner, and it exercises the production /proc attribution —
// not an injected double — end to end.
func TestRealNonRootHolderDoesNotExit_14581(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	addr := holder.Addr().String()

	s := &Server{addr: addr}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	err = s.supervisePrimaryListener(ctx, primarySupervisorConfig{
		backoffBase:    time.Millisecond,
		backoffMax:     2 * time.Millisecond,
		healthyServe:   time.Hour,
		addrInUseGrace: 20 * time.Millisecond,
		// REAL kernel lookup, with the production daemon's self uid:
		// xpfd runs as uid 0 (the unit has no User=), so a holder owned
		// by this test process's uid is a NON-root squatter relative to
		// the daemon. (In-process the holder and supervisor necessarily
		// share a uid, so the own-uid arm cannot be simulated here; it
		// is covered by TestOwnUIDHolderRemainsFatal_14581.)
		holderCheck: authz.LookupListenerOwner,
		selfUID:     0,
		listen:      func(context.Context) (net.Listener, error) { return net.Listen("tcp", addr) },
		serve:       func(context.Context, net.Listener) error { return nil },
	})
	if os.Getuid() == 0 {
		// Root runner: the in-process holder cannot be distinguished
		// from the daemon (both uid 0), so the real-lookup arm cannot
		// discriminate here. The discriminating arms are the injected
		// cells above (non-root / own-uid / unattributed) and the
		// non-root run of this cell in CI.
		t.Skip("running as root: holder, lookup self and daemon are all uid 0, " +
			"so the real-holder cell cannot discriminate; see injected 14581 cells")
	}
	if err != nil {
		t.Fatalf("a real non-root holder (uid %d) was fatal: %v — xpfd would exit in a "+
			"Restart=on-failure loop while the holder impersonates it", os.Getuid(), err)
	}
}

// When the squatter LEAVES, the supervisor must bind and serve: staying
// up is only worth anything if recovery still works.
func TestSupervisorRecoversWhenNonRootHolderLeaves_14581(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := holder.Addr().String()

	s := &Server{addr: addr}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if os.Getuid() == 0 {
		t.Skip("running as root: an in-process holder is uid 0 (privileged), so a " +
			"distinct-uid squatter cannot be simulated; the non-root arm is " +
			"TestRealNonRootHolderDoesNotExit_14581's non-root run")
	}
	served := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- s.supervisePrimaryListener(ctx, primarySupervisorConfig{
			backoffBase:    time.Millisecond,
			backoffMax:     2 * time.Millisecond,
			healthyServe:   time.Hour,
			addrInUseGrace: 20 * time.Millisecond,
			holderCheck:    authz.LookupListenerOwner,
			selfUID:        0, // production daemon uid; see the real-holder cell above
			listen:         func(context.Context) (net.Listener, error) { return net.Listen("tcp", addr) },
			serve: func(ctx context.Context, lis net.Listener) error {
				served <- struct{}{}
				<-ctx.Done()
				return nil
			},
		})
	}()

	// Let the supervisor collide with the squatter past its grace.
	time.Sleep(100 * time.Millisecond)
	_ = holder.Close()

	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor never served after the non-root holder left")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("supervisor returned %v after recovery + clean cancel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not stop on cancel")
	}
}
