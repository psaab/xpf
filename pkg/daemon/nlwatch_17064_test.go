package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// captureSlog17064 swaps the default slog logger for a buffer-backed one.
func captureSlog17064(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// TestNLWatchTable17064 is the #17064 acceptance table: one fake
// subscriber per cell drives fail / close / error-callback sequences
// and asserts OnGap, the Name-carrying log line, and resubscription.
func TestNLWatchTable17064(t *testing.T) {
	errSub := errors.New("subscribe boom")
	cases := []struct {
		name       string
		subscribe  func(call int, ch chan<- netlink.LinkUpdate, onErr func(error)) error
		wantGap    int32
		wantSub    int32
		wantLogSub string
	}{
		{
			name: "subscribe-failure-logs-and-gaps-on-failure",
			subscribe: func(call int, ch chan<- netlink.LinkUpdate, onErr func(error)) error {
				if call == 1 {
					return errSub
				}
				go func() { <-time.After(50 * time.Millisecond) }()
				return nil
			},
			wantGap:    1, // only via second success OnGap; failure has no OnGap unless OnGapOnFailure
			wantSub:    2,
			wantLogSub: "watcher=cell-fail",
		},
		{
			name: "close-resubscribes-and-recatches-up",
			subscribe: func(call int, ch chan<- netlink.LinkUpdate, onErr func(error)) error {
				go func() {
					if call == 1 {
						close(ch)
					}
				}()
				return nil
			},
			wantGap: 2,
			wantSub: 2,
		},
		{
			name: "error-callback-logs-name-and-gaps",
			subscribe: func(call int, ch chan<- netlink.LinkUpdate, onErr func(error)) error {
				go func() {
					if call == 1 {
						onErr(unix.ENOBUFS)
						close(ch)
					}
				}()
				return nil
			},
			wantGap:    2,
			wantSub:    2,
			wantLogSub: "watcher=cell-err",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureSlog17064(t)
			var gap, subs, recvErr atomic.Int32
			var call atomic.Int32
			w := nlWatch[netlink.LinkUpdate]{
				Name:    "cell-" + map[string]string{"subscribe-failure-logs-and-gaps-on-failure": "fail", "close-resubscribes-and-recatches-up": "close", "error-callback-logs-name-and-gaps": "err"}[tc.name],
				Backoff: time.Millisecond,
				Buf:     4,
				Subscribe: func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
					n := int(call.Add(1))
					subs.Add(1)
					return tc.subscribe(n, ch, onErr)
				},
				OnGap: func() { gap.Add(1) },
				OnReceiveError: func(err error) {
					recvErr.Add(1)
				},
				OnEvent: func(netlink.LinkUpdate) {},
			}
			// For the failure cell, OnGapOnFailure is off: gap comes
			// only from the successful second subscribe.
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { w.Run(ctx); close(done) }()
			if !waitUntil(t, 2*time.Second, func() bool { return subs.Load() >= tc.wantSub && gap.Load() >= tc.wantGap }) {
				cancel()
				t.Fatalf("subs=%d gap=%d want subs>=%d gap>=%d log=%s", subs.Load(), gap.Load(), tc.wantSub, tc.wantGap, buf.String())
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Run did not exit on cancel")
			}
			if tc.wantLogSub != "" && !strings.Contains(buf.String(), tc.wantLogSub) {
				t.Fatalf("log missing %q: %s", tc.wantLogSub, buf.String())
			}
			if tc.name == "error-callback-logs-name-and-gaps" {
				if recvErr.Load() < 1 {
					t.Fatalf("OnReceiveError not called, log=%s", buf.String())
				}
				if !strings.Contains(buf.String(), "watcher=cell-err") {
					t.Fatalf("receive-error log missing watcher name: %s", buf.String())
				}
			}
		})
	}
}

// TestNLWatchOnGapOnFailure17064 asserts the failure-gap arm used by
// transit-gate / rxvlan: a failing subscribe still runs OnGap.
func TestNLWatchOnGapOnFailure17064(t *testing.T) {
	captureSlog17064(t)
	var gap atomic.Int32
	w := nlWatch[netlink.LinkUpdate]{
		Name:           "cell-gapfail",
		Backoff:        time.Millisecond,
		OnGapOnFailure: true,
		Subscribe: func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
			return errors.New("nope")
		},
		OnGap: func() { gap.Add(1) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	if !waitUntil(t, 2*time.Second, func() bool { return gap.Load() >= 2 }) {
		cancel()
		t.Fatalf("OnGapOnFailure did not run OnGap on subscribe failure, gap=%d", gap.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit")
	}
}

// TestNLWatchBackoffStoppable17064 asserts ctx cancels promptly even
// mid-backoff (stoppable timer, not time.Sleep).
func TestNLWatchBackoffStoppable17064(t *testing.T) {
	w := nlWatch[netlink.LinkUpdate]{
		Name:    "cell-backoff",
		Backoff: time.Hour,
		Subscribe: func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
			go close(ch)
			return nil
		},
		OnGap: func() {},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run stuck in backoff after cancel")
	}
}

// TestNLWatchAcceptanceGrep17064 documents the acceptance invariant:
// this file is the table test; the grep itself is verified in the PR
// (only nlwatch.go matches netlink.*Subscribe outside tests).
func TestNLWatchDefaultSubscriber17064(t *testing.T) {
	// Control: the default subscriber table returns a non-nil func for
	// each daemon update type and the no-default error otherwise.
	for _, f := range []any{
		defaultNLSubscribe[netlink.LinkUpdate](),
		defaultNLSubscribe[netlink.NeighUpdate](),
		defaultNLSubscribe[netlink.RouteUpdate](),
		defaultNLSubscribe[netlink.AddrUpdate](),
	} {
		if f == nil {
			t.Fatal("default subscriber nil")
		}
	}
	if err := defaultNLSubscribe[int]()(make(chan int), make(chan struct{}), func(error) {}); err == nil {
		t.Fatal("expected no-default error for int")
	}
}
