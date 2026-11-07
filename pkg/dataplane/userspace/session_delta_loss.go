package userspace

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SessionDeltaLossBaseline binds a wait window to one helper lifetime and the
// exact loss counters observed by its initial probe.
type SessionDeltaLossBaseline struct {
	PID                               int       `json:"pid"`
	StartedAt                         time.Time `json:"started_at"`
	HelperStatusMeasurementSequence   uint64    `json:"helper_status_measurement_sequence"`
	EventStreamSessionDeltaLostOpen   uint64    `json:"event_stream_session_delta_lost_open"`
	EventStreamSessionDeltaLostClose  uint64    `json:"event_stream_session_delta_lost_close"`
	EventStreamSessionDeltaLostUpdate uint64    `json:"event_stream_session_delta_lost_update"`
}

type SessionDeltaLossProbeRequest struct {
	Baseline *SessionDeltaLossBaseline `json:"baseline,omitempty"`
}

type SessionDeltaLossProbeResponse struct {
	Valid                             bool       `json:"valid"`
	PID                               *int       `json:"pid"`
	StartedAt                         *time.Time `json:"started_at"`
	HelperStatusMeasurementSequence   *uint64    `json:"helper_status_measurement_sequence"`
	EventStreamSessionDeltaLostOpen   *uint64    `json:"event_stream_session_delta_lost_open"`
	EventStreamSessionDeltaLostClose  *uint64    `json:"event_stream_session_delta_lost_close"`
	EventStreamSessionDeltaLostUpdate *uint64    `json:"event_stream_session_delta_lost_update"`
	LostSince                         *uint64    `json:"lost_since,omitempty"`
}

// SessionDeltaLossProbe bypasses helperStatusView and asks the helper to
// evaluate the wait-start baseline against counters read while answering this
// fresh control-socket request. It intentionally does not publish its response
// to the manager cache: a later cache publisher must not turn an old answer
// into fresh proof.
func (m *Manager) SessionDeltaLossProbe(baseline *SessionDeltaLossBaseline) (*SessionDeltaLossProbeResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:           "status",
		SuppressStatus: true,
		SessionDeltaLossProbe: &SessionDeltaLossProbeRequest{
			Baseline: baseline,
		},
	})
	if err != nil {
		return nil, err
	}
	if resp.SessionDeltaLossProbe == nil {
		return nil, errors.New("userspace helper omitted session-delta loss probe response")
	}
	return resp.SessionDeltaLossProbe, nil
}

const (
	SessionDeltaLossBaselineFilter = "loss-baseline"
	SessionDeltaLossSinceFilter    = "loss-since"
)

// ParseSessionDeltaLossProbeFilter parses the private statistics-view filter
// used by HA wait loops. The opaque URL-safe token carries the helper identity,
// projection stamp and all three per-kind counters captured at wait start.
func ParseSessionDeltaLossProbeFilter(filter string) (baseline *SessionDeltaLossBaseline, isBaseline bool, err error) {
	parts := strings.Fields(filter)
	switch {
	case len(parts) == 1 && parts[0] == SessionDeltaLossBaselineFilter:
		return nil, true, nil
	case len(parts) == 2 && parts[0] == SessionDeltaLossSinceFilter:
		payload, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
		if decodeErr != nil {
			return nil, false, fmt.Errorf("invalid session-delta loss baseline token: %w", decodeErr)
		}
		var parsed SessionDeltaLossBaseline
		if decodeErr = json.Unmarshal(payload, &parsed); decodeErr != nil {
			return nil, false, fmt.Errorf("invalid session-delta loss baseline token: %w", decodeErr)
		}
		if parsed.PID <= 0 || parsed.StartedAt.IsZero() || parsed.HelperStatusMeasurementSequence == 0 {
			return nil, false, errors.New("session-delta loss baseline token has no helper identity or stamp")
		}
		return &parsed, false, nil
	default:
		return nil, false, fmt.Errorf("unsupported data-plane statistics filter %q", filter)
	}
}

// FormatSessionDeltaLossProbe renders a machine-readable token at wait start,
// or the helper's authoritative since-baseline total at confirmation.
func FormatSessionDeltaLossProbe(response *SessionDeltaLossProbeResponse, baseline bool) (string, error) {
	if response == nil || !response.Valid {
		return "", errors.New("session-delta loss baseline identity or counters changed; wait evidence is void")
	}
	if response.PID == nil || *response.PID <= 0 ||
		response.StartedAt == nil || response.StartedAt.IsZero() ||
		response.HelperStatusMeasurementSequence == nil || *response.HelperStatusMeasurementSequence == 0 ||
		response.EventStreamSessionDeltaLostOpen == nil ||
		response.EventStreamSessionDeltaLostClose == nil ||
		response.EventStreamSessionDeltaLostUpdate == nil {
		return "", errors.New("session-delta loss probe omitted required identity, stamp, or counter field")
	}
	if baseline {
		value := SessionDeltaLossBaseline{
			PID:                               *response.PID,
			StartedAt:                         *response.StartedAt,
			HelperStatusMeasurementSequence:   *response.HelperStatusMeasurementSequence,
			EventStreamSessionDeltaLostOpen:   *response.EventStreamSessionDeltaLostOpen,
			EventStreamSessionDeltaLostClose:  *response.EventStreamSessionDeltaLostClose,
			EventStreamSessionDeltaLostUpdate: *response.EventStreamSessionDeltaLostUpdate,
		}
		payload, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("encode session-delta loss baseline: %w", err)
		}
		if value.EventStreamSessionDeltaLostOpen > ^uint64(0)-value.EventStreamSessionDeltaLostClose {
			return "", errors.New("session-delta loss baseline total overflows u64")
		}
		total := value.EventStreamSessionDeltaLostOpen + value.EventStreamSessionDeltaLostClose
		if total > ^uint64(0)-value.EventStreamSessionDeltaLostUpdate {
			return "", errors.New("session-delta loss baseline total overflows u64")
		}
		total += value.EventStreamSessionDeltaLostUpdate
		return fmt.Sprintf("Event stream HA session delta loss baseline token: %s\nEvent stream HA session delta lost total: %d\n",
			base64.RawURLEncoding.EncodeToString(payload), total), nil
	}
	if response.LostSince == nil {
		return "", errors.New("session-delta loss probe omitted its since-baseline total")
	}
	return fmt.Sprintf("Event stream HA session delta lost since baseline: %d\n", *response.LostSince), nil
}
