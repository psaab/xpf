package userspace

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionDeltaLossProbeFreshConfirmationBypassesHeldStatus18635(t *testing.T) {
	socketDir, err := os.MkdirTemp(os.TempDir(), "xpf18635-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	listener, err := net.Listen("unix", filepath.Join(socketDir, "h"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	startedAt := time.Date(2026, 5, 20, 10, 11, 12, 0, time.UTC)
	var lost atomic.Uint64
	confirmationRequest := make(chan ControlRequest, 1)
	releaseConfirmation := make(chan struct{})
	helperErr := make(chan error, 1)
	go func() {
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				helperErr <- acceptErr
				return
			}
			var request ControlRequest
			decodeErr := json.NewDecoder(conn).Decode(&request)
			if decodeErr != nil {
				_ = conn.Close()
				helperErr <- decodeErr
				return
			}
			if request.Type != "status" || !request.SuppressStatus || request.SessionDeltaLossProbe == nil {
				_ = conn.Close()
				helperErr <- &probeTestError{message: "request did not use the fresh suppressed status probe"}
				return
			}
			sequence := uint64(40)
			open := uint64(0)
			lostSince := uint64(0)
			if requestIndex == 0 {
				if request.SessionDeltaLossProbe.Baseline != nil {
					_ = conn.Close()
					helperErr <- &probeTestError{message: "wait-start query unexpectedly supplied a baseline"}
					return
				}
			} else {
				baseline := request.SessionDeltaLossProbe.Baseline
				if baseline == nil {
					_ = conn.Close()
					helperErr <- &probeTestError{message: "confirmation omitted its wait-start baseline"}
					return
				}
				confirmationRequest <- request
				<-releaseConfirmation
				sequence = 43
				open = lost.Load()
				lostSince = open - baseline.EventStreamSessionDeltaLostOpen
			}
			response := ControlResponse{
				OK: true,
				SessionDeltaLossProbe: &SessionDeltaLossProbeResponse{
					Valid:                           true,
					PID:                             4242,
					StartedAt:                       startedAt,
					HelperStatusMeasurementSequence: sequence,
					EventStreamSessionDeltaLostOpen: open,
					LostSince:                       &lostSince,
				},
			}
			encodeErr := json.NewEncoder(conn).Encode(response)
			_ = conn.Close()
			if encodeErr != nil {
				helperErr <- encodeErr
				return
			}
		}
		helperErr <- nil
	}()

	manager := New()
	manager.cfg.ControlSocket = listener.Addr().String()
	baselineResponse, err := manager.SessionDeltaLossProbe(nil)
	if err != nil {
		t.Fatalf("wait-start helper query: %v", err)
	}
	if !baselineResponse.Valid || baselineResponse.LostSince == nil || *baselineResponse.LostSince != 0 {
		t.Fatalf("wait-start response = %+v, want valid zero-loss baseline", baselineResponse)
	}
	baseline := &SessionDeltaLossBaseline{
		PID:                               baselineResponse.PID,
		StartedAt:                         baselineResponse.StartedAt,
		HelperStatusMeasurementSequence:   baselineResponse.HelperStatusMeasurementSequence,
		EventStreamSessionDeltaLostOpen:   baselineResponse.EventStreamSessionDeltaLostOpen,
		EventStreamSessionDeltaLostClose:  baselineResponse.EventStreamSessionDeltaLostClose,
		EventStreamSessionDeltaLostUpdate: baselineResponse.EventStreamSessionDeltaLostUpdate,
	}

	// Ordinary helper projections 41 and 42 were both projected with zero loss;
	// the newer one is deliberately retained in the manager cache, then the
	// loss lands while the confirmation round trip is in flight. Neither held
	// projection is allowed to answer the since-baseline query.
	for sequence := uint64(41); sequence <= 42; sequence++ {
		zero := uint64(0)
		cached := *readyHelperStatus()
		cached.PID = baseline.PID
		cached.StartedAt = baseline.StartedAt
		cached.HelperStatusMeasurementSequence = &sequence
		cached.EventStreamSessionDeltaLostOpen = &zero
		cached.EventStreamSessionDeltaLostClose = &zero
		cached.EventStreamSessionDeltaLostUpdate = &zero
		manager.mu.Lock()
		manager.recordHelperStatusLocked(&cached)
		manager.mu.Unlock()
	}
	stale, err := manager.Status()
	if err != nil || stale.HelperStatusMeasurementSequence == nil || *stale.HelperStatusMeasurementSequence != 42 {
		t.Fatalf("manager cache before confirmation = %+v, err=%v; want held epoch 42", stale, err)
	}

	confirmed := make(chan struct {
		response *SessionDeltaLossProbeResponse
		err      error
	}, 1)
	go func() {
		response, probeErr := manager.SessionDeltaLossProbe(baseline)
		confirmed <- struct {
			response *SessionDeltaLossProbeResponse
			err      error
		}{response, probeErr}
	}()
	select {
	case request := <-confirmationRequest:
		if request.SessionDeltaLossProbe.Baseline.HelperStatusMeasurementSequence != 40 {
			t.Fatalf("confirmation baseline stamp = %d, want wait-start stamp 40",
				request.SessionDeltaLossProbe.Baseline.HelperStatusMeasurementSequence)
		}
		lost.Store(1)
		close(releaseConfirmation)
	case <-time.After(2 * time.Second):
		t.Fatal("confirmation query did not reach helper")
	}
	select {
	case result := <-confirmed:
		if result.err != nil {
			t.Fatalf("confirmation helper query: %v", result.err)
		}
		if result.response.LostSince == nil || *result.response.LostSince != 1 {
			t.Fatalf("fresh since-baseline response = %+v, want lost_since=1", result.response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("confirmation query did not complete")
	}
	stillCached, err := manager.Status()
	if err != nil || stillCached.EventStreamSessionDeltaLostOpen == nil || *stillCached.EventStreamSessionDeltaLostOpen != 0 {
		t.Fatalf("fresh probe should not republish into the ordinary cache: status=%+v err=%v", stillCached, err)
	}
	if err := <-helperErr; err != nil {
		t.Fatalf("fake helper: %v", err)
	}
}

type probeTestError struct{ message string }

func (e *probeTestError) Error() string { return e.message }
