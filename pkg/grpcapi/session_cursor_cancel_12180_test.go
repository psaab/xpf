package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const cursorCancelTestRows12180 = 20 * sessionWalkCancelInterval9060

type cursorCancelDP12180 struct {
	*dataplane.Manager
	nV4, nV6                         int
	countV4Rows, countV6Rows         int
	cursorV4Visited                  int
	cursorV6Visited                  int
	countV4Visited, countV6Visited   int
	cursorV6Calls, countV6Calls      int
	cancel                           context.CancelFunc
	cancelAtV4, cancelAtV6           int
	cancelAtCountV4, cancelAtCountV6 int
}

func (d *cursorCancelDP12180) IsLoaded() bool { return true }

func (d *cursorCancelDP12180) IterateSessionsFrom(_ *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for range d.nV4 {
		d.cursorV4Visited++
		if d.cancel != nil && d.cursorV4Visited == d.cancelAtV4 {
			d.cancel()
		}
		key := dataplane.SessionKey{Protocol: 6}
		if !fn(key, dataplane.SessionValue{}) {
			return nil
		}
	}
	return nil
}

func (d *cursorCancelDP12180) IterateSessionsV6From(_ *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.cursorV6Calls++
	for range d.nV6 {
		d.cursorV6Visited++
		if d.cancel != nil && d.cursorV6Visited == d.cancelAtV6 {
			d.cancel()
		}
		key := dataplane.SessionKeyV6{Protocol: 6}
		if !fn(key, dataplane.SessionValueV6{}) {
			return nil
		}
	}
	return nil
}

func (d *cursorCancelDP12180) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for range d.countV4Rows {
		d.countV4Visited++
		if d.cancel != nil && d.countV4Visited == d.cancelAtCountV4 {
			d.cancel()
		}
		if !fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{}) {
			return nil
		}
	}
	return nil
}

func (d *cursorCancelDP12180) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.countV6Calls++
	for range d.countV6Rows {
		d.countV6Visited++
		if d.cancel != nil && d.countV6Visited == d.cancelAtCountV6 {
			d.cancel()
		}
		if !fn(dataplane.SessionKeyV6{Protocol: 6}, dataplane.SessionValueV6{}) {
			return nil
		}
	}
	return nil
}

func withSingleSessionWalkSlot12180(t *testing.T) {
	t.Helper()
	original := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { sessionWalkLimiter = original })
}

func assertCancelledAndReleased12180(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.Canceled {
		t.Fatalf("GetSessions error = %v (code %v), want Canceled", err, status.Code(err))
	}
	if got := sessionWalkLimiter.InFlight(); got != 0 {
		t.Fatalf("cancelled GetSessions left %d walk slots in flight, want 0", got)
	}
	release, acquireErr := sessionWalkLimiter.Acquire()
	if acquireErr != nil {
		t.Fatalf("walk slot unavailable after cancellation: %v", acquireErr)
	}
	release()
}

func TestGetSessionsCursorCancelsDuringV4Walk12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV4: cursorCancelTestRows12180, nV6: 1,
		cancel: cancel, cancelAtV4: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "udp", PageSize: 1})

	if dp.cursorV4Visited >= dp.nV4 {
		t.Errorf("selective cursor visited %d of %d v4 rows after cancellation; want sampled early stop", dp.cursorV4Visited, dp.nV4)
	}
	if dp.cursorV6Calls != 0 {
		t.Errorf("v6 cursor started %d times after v4 cancellation, want 0", dp.cursorV6Calls)
	}
	if dp.countV4Visited != 0 || dp.countV6Calls != 0 {
		t.Errorf("filtered total ran after page-walk cancellation: v4 visits=%d, v6 walks=%d", dp.countV4Visited, dp.countV6Calls)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsCursorCancelsDuringV6Walk12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV6: cursorCancelTestRows12180,
		cancel: cancel, cancelAtV6: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{
		Protocol: "udp", PageSize: 1, PageToken: encodePageTokenV6Start(),
	})

	if dp.cursorV6Visited >= dp.nV6 {
		t.Errorf("selective cursor visited %d of %d v6 rows after cancellation; want sampled early stop", dp.cursorV6Visited, dp.nV6)
	}
	if dp.countV4Visited != 0 || dp.countV6Calls != 0 {
		t.Errorf("filtered total ran after page-walk cancellation: v4 visits=%d, v6 walks=%d", dp.countV4Visited, dp.countV6Calls)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsFilteredTotalCancelsBeforeV6Count12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV4: 1, nV6: 1,
		countV4Rows: cursorCancelTestRows12180,
		cancel:      cancel, cancelAtCountV4: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "udp", PageSize: 1})

	if dp.countV4Visited >= dp.countV4Rows {
		t.Errorf("filtered total visited %d of %d v4 rows after cancellation; want sampled early stop", dp.countV4Visited, dp.countV4Rows)
	}
	if dp.countV6Calls != 0 {
		t.Errorf("v6 total walk started %d times after v4 total cancellation, want 0", dp.countV6Calls)
	}
	assertCancelledAndReleased12180(t, err)
}

func TestGetSessionsFilteredTotalCancelsDuringV6Count12180(t *testing.T) {
	withSingleSessionWalkSlot12180(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dp := &cursorCancelDP12180{
		Manager: dataplane.New(), nV4: 1, nV6: 1,
		countV4Rows: 1, countV6Rows: cursorCancelTestRows12180,
		cancel: cancel, cancelAtCountV6: sessionWalkCancelInterval9060 / 2,
	}
	s := newViewServer(t, dp)

	_, err := s.GetSessions(ctx, &pb.GetSessionsRequest{Protocol: "udp", PageSize: 1})

	if dp.countV6Visited >= dp.countV6Rows {
		t.Errorf("filtered total visited %d of %d v6 rows after cancellation; want sampled early stop", dp.countV6Visited, dp.countV6Rows)
	}
	assertCancelledAndReleased12180(t, err)
}
