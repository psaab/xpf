package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

const sessionSummaryTopRows12181 = 8 * sessionWalkCancelInterval9060

type sessionSummaryTopCancelDP12181 struct {
	*dataplane.Manager
	rows      int
	cancel    context.CancelFunc
	cancelOn  string
	cancelAt  int
	v4Visited int
	v6Visited int
}

func (*sessionSummaryTopCancelDP12181) IsLoaded() bool { return true }

func (d *sessionSummaryTopCancelDP12181) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < d.rows; i++ {
		d.v4Visited++
		if d.cancelOn == "v4" && d.v4Visited == d.cancelAt {
			d.cancel()
		}
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{}) {
			return nil
		}
	}
	return nil
}

func (d *sessionSummaryTopCancelDP12181) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i := 0; i < d.rows; i++ {
		d.v6Visited++
		if d.cancelOn == "v6" && d.v6Visited == d.cancelAt {
			d.cancel()
		}
		if !fn(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}) {
			return nil
		}
	}
	return nil
}

func TestSessionSummaryAndTopWalkCancellation12181(t *testing.T) {
	for _, surface := range []string{"summary", "zone-pair", "sessions-top"} {
		for _, family := range []string{"v4", "v6"} {
			t.Run(surface+"/"+family, func(t *testing.T) {
				originalLimiter := sessionWalkLimiter
				t.Cleanup(func() { sessionWalkLimiter = originalLimiter })
				sessionWalkLimiter = diagcmd.NewLimiter(1)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				dp := &sessionSummaryTopCancelDP12181{
					Manager:  dataplane.New(),
					rows:     sessionSummaryTopRows12181,
					cancel:   cancel,
					cancelOn: family,
					cancelAt: 2*sessionWalkCancelInterval9060 + 1,
				}
				s := newViewServer(t, dp)

				var err error
				switch surface {
				case "summary":
					_, err = s.GetSessionSummary(ctx, &pb.GetSessionSummaryRequest{})
				case "zone-pair":
					_, err = s.GetZonePairSummary(ctx, &pb.GetZonePairSummaryRequest{})
				case "sessions-top":
					_, err = s.ShowText(ctx, &pb.ShowTextRequest{Topic: "sessions-top:bytes"})
				}

				if got := status.Code(err); got != codes.Canceled {
					t.Errorf("%s canceled during %s walk: error = %v (code %v), want Canceled", surface, family, err, got)
				}
				if dp.v4Visited > dp.rows || dp.v6Visited > dp.rows {
					t.Fatalf("visited more than the fixture size: v4=%d v6=%d rows=%d", dp.v4Visited, dp.v6Visited, dp.rows)
				}
				maxCanceledVisits := dp.cancelAt + sessionWalkCancelInterval9060
				if family == "v4" {
					if dp.v4Visited < dp.cancelAt || dp.v4Visited > maxCanceledVisits {
						t.Errorf("canceled v4 walk visited %d rows after cancellation at %d; want stop within %d more rows", dp.v4Visited, dp.cancelAt, sessionWalkCancelInterval9060)
					}
					if dp.v6Visited != 0 {
						t.Errorf("v6 walk started after canceled v4 walk: visited %d rows", dp.v6Visited)
					}
				} else {
					if dp.v4Visited != dp.rows {
						t.Errorf("v4 walk visited %d rows before v6 cancellation, want %d", dp.v4Visited, dp.rows)
					}
					if dp.v6Visited < dp.cancelAt || dp.v6Visited > maxCanceledVisits {
						t.Errorf("canceled v6 walk visited %d rows after cancellation at %d; want stop within %d more rows", dp.v6Visited, dp.cancelAt, sessionWalkCancelInterval9060)
					}
				}

				// Cancellation must release the shared scan admission slot on every
				// public surface, so another RPC can start immediately.
				release, acquireErr := sessionWalkLimiter.Acquire()
				if acquireErr != nil {
					t.Fatalf("session-walk slot remained held after cancellation: %v", acquireErr)
				}
				release()
			})
		}
	}
}
