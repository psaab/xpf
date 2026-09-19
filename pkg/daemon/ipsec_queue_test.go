package daemon

// RED batch B — 9506 S4 T12 queue allocator/quarantine/epoch/provenance cells
// (r6 §2.2 queue lifecycle, §3.5 item 4a, T12[P] cells 2–3).

import (
	"testing"
	"time"
)

func TestIpsecQueueAllocatorQuarantinesUntilListenerExitDestroyAndTick9506(t *testing.T) {
	a := newIpsecQueueAllocator()
	key := ipsecQueueKey{Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 11}
	first, err := a.allocate(key)
	if err != nil {
		t.Fatalf("allocate first: %v", err)
	}
	if first.Number == 0 || first.Epoch == 0 {
		t.Fatalf("first handle = %+v, want non-zero number/epoch", first)
	}
	if err := a.retire(first, false, false); err != nil {
		t.Fatalf("retire first: %v", err)
	}
	second, err := a.allocate(key)
	if err != nil {
		t.Fatalf("allocate second: %v", err)
	}
	if second.Number == first.Number {
		t.Fatalf("queue %d reused before listener exit/destruction/tick", second.Number)
	}
	if err := a.retire(first, true, false); err != nil {
		t.Fatalf("mark listener exit: %v", err)
	}
	a.tick()
	third, err := a.allocate(key)
	if err != nil {
		t.Fatalf("allocate third: %v", err)
	}
	if third.Number == first.Number {
		t.Fatalf("queue %d reused before destruction confirmation", third.Number)
	}
	if err := a.retire(first, true, true); err != nil {
		t.Fatalf("confirm destruction: %v", err)
	}
	// One full supervisor tick after both conditions is required.
	a.tick()
	fourth, err := a.allocate(key)
	if err != nil {
		t.Fatalf("allocate fourth: %v", err)
	}
	if fourth.Number != first.Number {
		t.Fatalf("queue number = %d after quarantine, want recycled %d", fourth.Number, first.Number)
	}
	if fourth.Epoch <= first.Epoch {
		t.Fatalf("recycled queue epoch = %d, want > old epoch %d", fourth.Epoch, first.Epoch)
	}
}

func TestIpsecQueueAllocatorRefusesStaleEpoch9506(t *testing.T) {
	a := newIpsecQueueAllocator()
	key := ipsecQueueKey{Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 11}
	old, err := a.allocate(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.retire(old, true, true); err != nil {
		t.Fatal(err)
	}
	a.tick()
	fresh, err := a.allocate(key)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Number != old.Number || fresh.Epoch == old.Epoch {
		t.Fatalf("fresh handle = %+v, want same number/new epoch after retirement", fresh)
	}
	if a.validate(ipsecQueueHandle{Number: fresh.Number, Epoch: old.Epoch}, key) == nil {
		t.Fatal("stale epoch validated against recycled queue")
	}
	if err := a.validate(fresh, key); err != nil {
		t.Fatalf("fresh epoch rejected: %v", err)
	}
}

func TestIpsecQueueAllocatorKeyIncludesFamilyHookOwnerDeviceIdentity9506(t *testing.T) {
	a := newIpsecQueueAllocator()
	base := ipsecQueueKey{Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 11}
	variants := []ipsecQueueKey{
		{Family: ipsecFamilyInet, Hook: ipsecHookInput, Owner: "owner-a", STN: "st0", Ifindex: 11},
		{Family: ipsecFamilyBridge, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 11},
		{Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-b", STN: "st0", Ifindex: 11},
		{Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 12},
	}
	first, err := a.allocate(base)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint16]bool{first.Number: true}
	for _, key := range variants {
		h, err := a.allocate(key)
		if err != nil {
			t.Fatalf("allocate %+v: %v", key, err)
		}
		if seen[h.Number] {
			t.Fatalf("queue number %d aliased distinct provenance key %+v", h.Number, key)
		}
		seen[h.Number] = true
	}
}

func TestIpsecQueueAllocatorIdentityCannotCrossConsumeReplacement9506(t *testing.T) {
	a := newIpsecQueueAllocator()
	oldKey := ipsecQueueKey{Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 11}
	newKey := oldKey
	newKey.Ifindex = 12
	old, err := a.allocate(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.retire(old, true, true); err != nil {
		t.Fatal(err)
	}
	a.tick()
	fresh, err := a.allocate(newKey)
	if err != nil {
		t.Fatal(err)
	}
	if a.validate(old, newKey) == nil {
		t.Fatal("old owner handle validated against replacement device identity")
	}
	if err := a.validate(fresh, newKey); err != nil {
		t.Fatal(err)
	}
}

func TestIpsecQueueRotationTransactionNeverOpensMixedGeneration9506(t *testing.T) {
	r := newIpsecRotation()
	old := []ipsecQueueHandle{
		{Number: 1001, Epoch: 1, Key: ipsecQueueKey{Generation: 1, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "a", STN: "st0", Ifindex: 11}},
		{Number: 1002, Epoch: 1, Key: ipsecQueueKey{Generation: 1, Family: ipsecFamilyInet, Hook: ipsecHookInput, Owner: "a", STN: "st0", Ifindex: 11}},
	}
	newKey0 := old[0].Key
	newKey0.Generation = 2
	newKey1 := old[1].Key
	newKey1.Generation = 2
	newGen := []ipsecQueueHandle{
		{Number: 2001, Epoch: 2, Key: newKey0},
		{Number: 2002, Epoch: 2, Key: newKey1},
	}
	if err := r.stage(old, newGen); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if r.state() != ipsecRotationQuarantine {
		t.Fatalf("staged rotation state = %v, want quarantine", r.state())
	}
	if err := r.activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if r.state() != ipsecRotationOpen {
		t.Fatalf("activated rotation state = %v, want open", r.state())
	}
	if got := r.openGeneration(); got != 2 {
		t.Fatalf("open generation = %d, want 2", got)
	}
	// A family staging failure must leave no mixed OPEN generation.
	r2 := newIpsecRotation()
	if err := r2.stage(old, newGen); err != nil {
		t.Fatal(err)
	}
	r2.failSecondFamily()
	if err := r2.activate(); err == nil {
		t.Fatal("second-family staging failure activated mixed generation")
	}
	if r2.state() == ipsecRotationOpen {
		t.Fatalf("failed staging left rotation OPEN (generation %d)", r2.openGeneration())
	}
	if err := r2.stage(old, newGen); err != nil {
		t.Fatalf("restage after family failure: %v", err)
	}
	if err := r2.activate(); err != nil {
		t.Fatalf("restaged generation did not converge: %v", err)
	}
}

func TestIpsecQueueRotationRejectsMixedSnapshotGeneration9506(t *testing.T) {
	r := newIpsecRotation()
	a := ipsecQueueHandle{Number: 1001, Epoch: 1, Key: ipsecQueueKey{Generation: 1, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "a", STN: "st0", Ifindex: 11}}
	b := a
	b.Number, b.Epoch, b.Key.Generation = 1002, 2, 2
	c := b
	c.Number, c.Epoch, c.Key.Generation = 1003, 2, 3
	if err := r.stage([]ipsecQueueHandle{a}, []ipsecQueueHandle{b, c}); err == nil {
		t.Fatal("mixed snapshot generations staged for OPEN")
	}
	if r.state() == ipsecRotationOpen {
		t.Fatal("mixed snapshot generation became OPEN")
	}
}
func TestIpsecQueueAllocatorRejectsOldSnapshotGeneration9506(t *testing.T) {
	a := newIpsecQueueAllocator()
	oldKey := ipsecQueueKey{Generation: 41, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 11}
	newKey := oldKey
	newKey.Generation = 42
	h, err := a.allocate(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if a.validate(h, newKey) == nil {
		t.Fatal("old snapshot generation validated against a current-generation key")
	}
}

func TestIpsecQueueRotationSuccessiveGenerationAndStaleOldRefusal9506(t *testing.T) {
	r := newIpsecRotation()
	old := ipsecQueueHandle{Number: 1001, Epoch: 1, Key: ipsecQueueKey{Generation: 1, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "a", STN: "st0", Ifindex: 11}}
	next := old
	next.Number, next.Epoch, next.Key.Generation = 2001, 2, 2
	if err := r.stage([]ipsecQueueHandle{old}, []ipsecQueueHandle{next}); err != nil {
		t.Fatal(err)
	}
	if err := r.activate(); err != nil {
		t.Fatal(err)
	}
	staleOld := old
	gen3 := next
	gen3.Number, gen3.Epoch, gen3.Key.Generation = 3001, 3, 3
	if err := r.stage([]ipsecQueueHandle{staleOld}, []ipsecQueueHandle{gen3}); err == nil {
		t.Fatal("stale old generation was accepted for successive rotation")
	}
	if r.state() != ipsecRotationOpen || r.openGeneration() != 2 {
		t.Fatalf("stale rotation changed active state to %v generation %d", r.state(), r.openGeneration())
	}
	if err := r.stage([]ipsecQueueHandle{next}, []ipsecQueueHandle{gen3}); err != nil {
		t.Fatalf("successive rotation with active old handles refused: %v", err)
	}
	if err := r.activate(); err != nil {
		t.Fatal(err)
	}
	if r.openGeneration() != 3 {
		t.Fatalf("successive rotation generation = %d, want 3", r.openGeneration())
	}
}

func TestIpsecQueueRetireBound9506(t *testing.T) {
	a := newIpsecQueueAllocator()
	key := ipsecQueueKey{Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 11}
	h, err := a.allocate(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.retire(h, true, true); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	a.tick()
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("allocator tick exceeded bounded maintenance budget")
	}
}
func TestIpsecQueueAllocatorRefusesBeyond128Handles9506(t *testing.T) {
	a := newIpsecQueueAllocator()
	for i := 0; i < 128; i++ {
		key := ipsecQueueKey{Generation: uint64(i + 1), Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: i + 1}
		if _, err := a.allocate(key); err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
	}
	if _, err := a.allocate(ipsecQueueKey{Generation: 129, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 999}); err == nil {
		t.Fatal("allocator admitted 129th active/quarantined handle; cap is 128")
	}
}
func TestIpsecQueueRetireImmediatelyInvalidatesDescriptor9506(t *testing.T) {
	a := newIpsecQueueAllocator()
	key := ipsecQueueKey{Generation: 1, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 11}
	h, err := a.allocate(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.retire(h, false, false); err != nil {
		t.Fatal(err)
	}
	if err := a.validate(h, key); err != errIpsecQueueQuarantined {
		t.Fatalf("retired handle validate = %v, want quarantine refusal before first tick", err)
	}
}
