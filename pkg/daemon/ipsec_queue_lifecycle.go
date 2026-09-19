package daemon

import (
	"errors"
	"fmt"
	"sync"
)

// ipsecQueueFamily/hook mirror the four provenance-specific queue classes in
// r6 §2.2. The values are deliberately strings at the API boundary so logs and
// evidence rows remain self-describing.
type ipsecQueueFamily uint8

const (
	ipsecFamilyInet ipsecQueueFamily = iota
	ipsecFamilyBridge
)

type ipsecQueueHook uint8

const (
	ipsecHookForward ipsecQueueHook = iota
	ipsecHookInput
)

type ipsecQueueKey struct {
	Generation uint64
	Family     ipsecQueueFamily
	Hook       ipsecQueueHook
	Owner      string
	STN        string
	Ifindex    int
}

type ipsecQueueHandle struct {
	Number uint16
	Epoch  uint64
	Key    ipsecQueueKey
}

type ipsecQueueEntry struct {
	handle           ipsecQueueHandle
	retired          bool
	listenerExited   bool
	destroyConfirmed bool
	retiredAtTick    uint64
}

var (
	errIpsecQueueExhausted   = errors.New("ipsec: queue allocator exhausted")
	errIpsecQueueQuarantined = errors.New("ipsec: queue number is quarantined")
	errIpsecQueueStale       = errors.New("ipsec: stale queue epoch or provenance")
)

// ipsecQueueAllocator allocates queue numbers with epoch-tagged identity. A
// retired number is not reusable until the listener has exited, destruction is
// confirmed, and one complete supervisor tick has elapsed. The allocator is
// bounded and fail-closed; it never aliases family/hook/device provenance.
type ipsecQueueAllocator struct {
	mu        sync.Mutex
	next      uint16
	max       uint16
	capacity  int
	tickNo    uint64
	entries   map[uint16]*ipsecQueueEntry
	free      []uint16
	lastEpoch map[uint16]uint64
}

func newIpsecQueueAllocator() *ipsecQueueAllocator {
	return &ipsecQueueAllocator{
		next:      1000,
		max:       65534,
		capacity:  128, // 32 tunnels × 4 provenance classes (r6 §3.5/T12).
		entries:   make(map[uint16]*ipsecQueueEntry),
		lastEpoch: make(map[uint16]uint64),
	}
}

func (a *ipsecQueueAllocator) allocate(key ipsecQueueKey) (ipsecQueueHandle, error) {
	if a == nil || key.Owner == "" || key.STN == "" || key.Ifindex <= 0 {
		return ipsecQueueHandle{}, fmt.Errorf("%w: invalid provenance key", errIpsecQueueExhausted)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.free) == 0 && a.capacity > 0 && len(a.entries) >= a.capacity {
		return ipsecQueueHandle{}, fmt.Errorf("%w: active/quarantined handles=%d cap=%d", errIpsecQueueExhausted, len(a.entries), a.capacity)
	}
	var number uint16
	if len(a.free) > 0 {
		n := len(a.free) - 1
		number = a.free[n]
		a.free = a.free[:n]
	} else {
		for a.next <= a.max {
			n := a.next
			a.next++
			if _, used := a.entries[n]; !used {
				number = n
				break
			}
		}
		if number == 0 {
			return ipsecQueueHandle{}, errIpsecQueueExhausted
		}
	}
	epoch := a.lastEpoch[number] + 1
	if epoch == 0 { // overflow is a hard refusal, never identity reuse.
		return ipsecQueueHandle{}, errIpsecQueueExhausted
	}
	h := ipsecQueueHandle{Number: number, Epoch: epoch, Key: key}
	a.lastEpoch[number] = epoch
	a.entries[number] = &ipsecQueueEntry{handle: h}
	return h, nil
}

func (a *ipsecQueueAllocator) retire(handle ipsecQueueHandle, listenerExited, destroyConfirmed bool) error {
	if a == nil {
		return errIpsecQueueStale
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.entries[handle.Number]
	if e == nil || e.handle.Epoch != handle.Epoch || e.handle.Key != handle.Key {
		return errIpsecQueueStale
	}
	e.listenerExited = e.listenerExited || listenerExited
	e.destroyConfirmed = e.destroyConfirmed || destroyConfirmed
	e.retired = true
	if e.retiredAtTick == 0 && a.tickNo != 0 {
		e.retiredAtTick = a.tickNo
	}
	return nil
}

func (a *ipsecQueueAllocator) tick() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tickNo++
	for n, e := range a.entries {
		if !e.retired || !e.listenerExited || !e.destroyConfirmed || a.tickNo <= e.retiredAtTick {
			continue
		}
		delete(a.entries, n)
		a.free = append(a.free, n)
	}
}

func (a *ipsecQueueAllocator) validate(handle ipsecQueueHandle, key ipsecQueueKey) error {
	if a == nil {
		return errIpsecQueueStale
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.entries[handle.Number]
	if e == nil || e.handle.Epoch != handle.Epoch || e.handle.Key != key || e.handle.Key != handle.Key {
		return errIpsecQueueStale
	}
	if e.retired {
		return errIpsecQueueQuarantined
	}
	return nil
}

func (a *ipsecQueueAllocator) released(handle ipsecQueueHandle) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.entries[handle.Number]
	return e == nil || e.handle.Epoch != handle.Epoch
}

// ---- atomic generation rotation ------------------------------------------

type ipsecRotationState uint8

const (
	ipsecRotationClosed ipsecRotationState = iota
	ipsecRotationQuarantine
	ipsecRotationOpen
)

func (s ipsecRotationState) String() string {
	switch s {
	case ipsecRotationClosed:
		return "CLOSED"
	case ipsecRotationQuarantine:
		return "QUARANTINE"
	case ipsecRotationOpen:
		return "OPEN"
	default:
		return fmt.Sprintf("rotation(%d)", s)
	}
}

type ipsecRotation struct {
	mu         sync.Mutex
	stateValue ipsecRotationState
	old        []ipsecQueueHandle
	staged     []ipsecQueueHandle
	generation uint64
	active     []ipsecQueueHandle
	failSecond bool
}

func newIpsecRotation() *ipsecRotation {
	return &ipsecRotation{stateValue: ipsecRotationClosed}
}

func handlesEqual(a, b []ipsecQueueHandle) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (r *ipsecRotation) stage(old, staged []ipsecQueueHandle) error {
	if r == nil || len(staged) == 0 {
		return errors.New("ipsec: empty rotation generation")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.active) > 0 && !handlesEqual(old, r.active) {
		return errors.New("ipsec: stale old generation supplied for rotation")
	}
	if r.stateValue == ipsecRotationOpen {
		// Rotation retains the old OPEN generation as the rollback target but
		// immediately moves publication to closed/quarantine-only.
		r.stateValue = ipsecRotationQuarantine
	}
	r.failSecond = false
	snapshotGeneration := staged[0].Key.Generation
	if snapshotGeneration == 0 {
		return errors.New("ipsec: staged generation is zero")
	}
	if r.generation != 0 && snapshotGeneration <= r.generation {
		return errors.New("ipsec: staged snapshot generation did not advance active generation")
	}
	for i, h := range staged {
		if h.Key.Generation != snapshotGeneration || h.Number == 0 || h.Epoch == 0 {
			return errors.New("ipsec: mixed or invalid staged snapshot generation")
		}
		if i < len(old) && old[i].Key.Generation != 0 && h.Key.Generation <= old[i].Key.Generation {
			return errors.New("ipsec: staged snapshot generation did not advance")
		}
		if i < len(old) && h.Number == old[i].Number && h.Epoch <= old[i].Epoch {
			return errors.New("ipsec: queue epoch did not advance")
		}
	}
	if len(staged) != len(old) {
		return errors.New("ipsec: incomplete provenance generation")
	}
	r.old = append([]ipsecQueueHandle(nil), old...)
	r.staged = append([]ipsecQueueHandle(nil), staged...)
	r.stateValue = ipsecRotationQuarantine
	return nil
}

func (r *ipsecRotation) failSecondFamily() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.failSecond = true
	r.mu.Unlock()
}

func (r *ipsecRotation) activate() error {
	if r == nil {
		return errors.New("ipsec: nil rotation")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stateValue != ipsecRotationQuarantine {
		return errors.New("ipsec: rotation is not staged")
	}
	if r.failSecond {
		// Leave the staged generation quarantined; caller rolls back or forces
		// tunnel-DOWN. Never expose an inet-new/bridge-old OPEN state.
		return errors.New("ipsec: family staging failed; rotation remains closed")
	}
	for _, h := range r.staged {
		if h.Epoch == 0 || h.Number == 0 || h.Key.Generation != r.staged[0].Key.Generation {
			return errors.New("ipsec: invalid staged generation")
		}
	}
	if len(r.staged) != len(r.old) {
		return errors.New("ipsec: incomplete provenance generation")
	}
	r.generation = r.staged[0].Key.Generation
	r.active = append([]ipsecQueueHandle(nil), r.staged...)
	r.stateValue = ipsecRotationOpen
	return nil
}

func (r *ipsecRotation) state() ipsecRotationState {
	if r == nil {
		return ipsecRotationClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stateValue
}

func (r *ipsecRotation) openGeneration() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.generation
}
