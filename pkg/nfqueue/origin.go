package nfqueue

import (
	"errors"
	"fmt"
	"sync"
)

// CaptureFamily is the normalized netfilter family recorded for a queue.
// AF_INET and AF_INET6 both normalize to inet; AF_BRIDGE remains bridge.
type CaptureFamily string

const (
	CaptureFamilyInet   CaptureFamily = "inet"
	CaptureFamilyBridge CaptureFamily = "bridge"
)

// CaptureHook is the normalized netfilter hook recorded for a queue.
type CaptureHook string

const (
	CaptureHookForward CaptureHook = "forward"
	CaptureHookInput   CaptureHook = "input"
)

// CaptureOrigin is the immutable ownership identity of one NFQUEUE number.
// Queue numbers are never sufficient identity on their own: rotation can
// recycle a number only with a new queue epoch and a new registry instance.
type CaptureOrigin struct {
	Family       CaptureFamily
	Hook         CaptureHook
	Owner        string
	STN          string
	OwnedIfindex uint32
}

// OriginRegistry maps queue numbers to immutable capture origins. A queue may
// be registered once only; replacement is refused so an old packet cannot be
// reinterpreted as belonging to a newly reused queue identity.
type OriginRegistry struct {
	mu      sync.RWMutex
	origins map[uint16]CaptureOrigin
}

var (
	errOriginInvalid = errors.New("nfqueue: invalid capture origin")
	errOriginQueue   = errors.New("nfqueue: queue origin already registered")
)

// Register installs origin for queue exactly once. Queue 0, empty owner/STN,
// unknown family/hook, and a zero ifindex are invalid and fail closed.
func (r *OriginRegistry) Register(queue uint16, origin CaptureOrigin) error {
	if r == nil {
		return fmt.Errorf("%w: nil registry", errOriginInvalid)
	}
	if queue == 0 || !validCaptureOrigin(origin) {
		return fmt.Errorf("%w: queue=%d origin=%+v", errOriginInvalid, queue, origin)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.origins == nil {
		r.origins = make(map[uint16]CaptureOrigin)
	}
	if _, exists := r.origins[queue]; exists {
		return fmt.Errorf("%w: queue=%d", errOriginQueue, queue)
	}
	r.origins[queue] = origin
	return nil
}

// Lookup returns a copy of the immutable origin for queue.
func (r *OriginRegistry) Lookup(queue uint16) (CaptureOrigin, bool) {
	if r == nil {
		return CaptureOrigin{}, false
	}
	r.mu.RLock()
	origin, ok := r.origins[queue]
	r.mu.RUnlock()
	return origin, ok
}

func validCaptureOrigin(origin CaptureOrigin) bool {
	return (origin.Family == CaptureFamilyInet || origin.Family == CaptureFamilyBridge) &&
		(origin.Hook == CaptureHookForward || origin.Hook == CaptureHookInput) &&
		origin.Owner != "" && origin.STN != "" && origin.OwnedIfindex != 0
}

const (
	captureAFInet   = 2
	captureAFInet6  = 10
	captureAFBridge = 7

	captureHookPreRouting = 0
	captureHookLocalIn    = 1
	captureHookForward    = 2
	captureHookLocalOut   = 3
	captureHookPostRoute  = 4
)

// ProvenanceError is a typed fail-closed mismatch. Callers must DROP and
// count it; no mismatch may proceed to a q0 reinject path.
type ProvenanceError struct {
	Queue    uint16
	Expected CaptureOrigin
	Got      CaptureOrigin
	Field    string
	Reason   string
}

func (e *ProvenanceError) Error() string {
	if e == nil {
		return "nfqueue: provenance mismatch"
	}
	if e.Reason != "" {
		return fmt.Sprintf("nfqueue: provenance queue=%d %s: expected=%+v got=%+v", e.Queue, e.Reason, e.Expected, e.Got)
	}
	return fmt.Sprintf("nfqueue: provenance queue=%d field=%s expected=%+v got=%+v", e.Queue, e.Field, e.Expected, e.Got)
}

// normalizeCaptureFamily maps the wire nfgenmsg family to the capture family.
func normalizeCaptureFamily(family uint8) (CaptureFamily, bool) {
	switch int(family) {
	case captureAFInet, captureAFInet6:
		return CaptureFamilyInet, true
	case captureAFBridge:
		return CaptureFamilyBridge, true
	default:
		return "", false
	}
}

func normalizeCaptureHook(hook uint8) (CaptureHook, bool) {
	switch int(hook) {
	case captureHookForward:
		return CaptureHookForward, true
	case captureHookLocalIn:
		return CaptureHookInput, true
	default:
		return "", false
	}
}

// ValidateProvenance compares the packet's kernel provenance with the
// immutable queue-origin registry. Any absent/unknown field is a typed refusal.
func ValidateProvenance(packet *Packet, registry *OriginRegistry) error {
	if packet == nil {
		return &ProvenanceError{Reason: "nil packet"}
	}
	if registry == nil {
		return &ProvenanceError{Queue: packet.queueID, Reason: "nil origin registry"}
	}
	expected, ok := registry.Lookup(packet.queueID)
	if !ok {
		return &ProvenanceError{Queue: packet.queueID, Reason: "queue is not registered"}
	}
	family, ok := normalizeCaptureFamily(packet.nfgenFamily)
	if !ok {
		return &ProvenanceError{Queue: packet.queueID, Expected: expected, Field: "family", Reason: "unknown nfgen family"}
	}
	hook, ok := normalizeCaptureHook(packet.hook)
	if !ok {
		return &ProvenanceError{Queue: packet.queueID, Expected: expected, Field: "hook", Reason: "unsupported hook"}
	}
	got := CaptureOrigin{Family: family, Hook: hook, Owner: expected.Owner, STN: expected.STN, OwnedIfindex: packet.indevIfindex}
	if got.Family != expected.Family {
		return &ProvenanceError{Queue: packet.queueID, Expected: expected, Got: got, Field: "family"}
	}
	if got.Hook != expected.Hook {
		return &ProvenanceError{Queue: packet.queueID, Expected: expected, Got: got, Field: "hook"}
	}
	if got.OwnedIfindex == 0 || got.OwnedIfindex != expected.OwnedIfindex {
		return &ProvenanceError{Queue: packet.queueID, Expected: expected, Got: got, Field: "ifindex"}
	}
	return nil
}
