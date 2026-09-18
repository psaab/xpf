package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #7174 C12a: StopAll must JOIN, not merely cancel.
//
// pkg/dhcp's StopAll does `dc.cancel(); <-dc.done`; pkg/rpm's does
// `m.cancel(); m.wg.Wait()`. feeds cancelled and returned, so StopAll could
// return with its refresh goroutines still running — a third spelling of
// shutdown in one daemon, and the only one where "stopped" meant "asked to
// stop".
//
// WHY THIS TEST IS FRAMED ON REPLACEMENT AND NOT SHUTDOWN. On daemon exit an
// unjoined fetcher races process teardown and is mostly harmless, and a
// shutdown-shaped test passes whether or not the join is there because teardown
// hides the window. The reachable defect is CONFIG REPLACEMENT: StopAll clears
// `m.feeds` and returned while a removed feed's fetch was still in flight, so
// that fetch could complete afterwards and install a snapshot for a feed the
// operator had just removed.
//
// HOW IT IS MADE DETERMINISTIC. The fixture holds the refresh goroutine inside
// an HTTP handler that never responds, so at the moment StopAll is called the
// goroutine is provably still running — there is no window to race. The
// assertion is then a non-blocking read of `done` immediately after StopAll
// returns:
//
//   - with the join, StopAll cannot return until `done` is closed;
//   - without it, StopAll returns while the goroutine is still parked in the
//     handler, and the same read finds `done` open.
//
// The request is aborted by context cancellation rather than by the server
// replying (`http.NewRequestWithContext`), which is also why joining is cheap
// here and does not wait out the client timeout.
func TestStopAllJoinsRefreshGoroutines7174C12a(t *testing.T) {
	blocked := make(chan struct{})
	entered := make(chan struct{})
	var closeEntered = func() func() {
		var once bool
		return func() {
			if !once {
				once = true
				close(entered)
			}
		}
	}()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		closeEntered()
		// Never respond. The only way out is the client's context being
		// cancelled, which is exactly what StopAll does.
		select {
		case <-blocked:
		case <-r.Context().Done():
		}
	}))
	defer ts.Close()
	defer close(blocked)

	m := newLabManager10177(func() error { return nil })
	m.Apply(context.Background(), &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"held": {
				Name:           "held",
				URL:            ts.URL,
				FeedName:       "held",
				UpdateInterval: 3600,
			},
		},
	})

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the fetch never reached the server, so the refresh goroutine was " +
			"not in flight when StopAll ran — this cell would then pass whether or " +
			"not StopAll joins, which is the failure mode it exists to avoid")
	}

	m.mu.Lock()
	fs := m.feeds["held"]
	m.mu.Unlock()
	if fs == nil {
		t.Fatal("precondition: the feed must be registered before StopAll")
	}
	// Control: the goroutine is genuinely still running right now. If `done`
	// were already closed here, the assertion after StopAll would prove nothing.
	select {
	case <-fs.done:
		t.Fatal("the refresh goroutine already exited before StopAll was called; " +
			"the fixture failed to hold it, so the join assertion below is vacuous")
	default:
	}

	m.StopAll()

	select {
	case <-fs.done:
		// StopAll waited for the goroutine. This is the property.
	default:
		t.Error("StopAll returned while the refresh goroutine was still running " +
			"(#7174 C12a). On a config replacement that removes a feed, its fetch " +
			"can then complete after StopAll cleared the registry and install a " +
			"snapshot for a feed the operator just removed.")
	}
}
