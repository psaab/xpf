package dataplane

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #19110: an XDP attach that fails because the device is OCCUPIED is not an
// interface that lacks native XDP.
//
// After an unclean exit the dead process's bpf_links stay attached, held by their
// pins. The restarted daemon's first sweep deletes those pins, but deleting a
// pin only schedules the link's release in the kernel. A native attach that
// overtakes the release gets EBUSY ("Can't replace active BPF XDP link") on the
// mlx5 VFs, or EEXIST ("Native and generic XDP can't be active at the same
// time") on an interface whose stale link is generic. attachUserspaceShimXDP
// read both as "native XDP unavailable" and fell back to generic:
//   - generic EEXIST while the stale native link was still there, so the arm
//     failed;
//   - or generic success once it was gone: a native-capable VF in skb mode with
//     AF_XDP in copy mode, which forwarded nothing on loss.
//
// These cells drive the real attach loop through the #18740 transition seam,
// with no kernel and no privilege. The seam answers with the errno shapes the
// kernel and cilium produce (`attach XDP to ifindex N: failed to attach link:
// create link: <errno>`).

type xdpAttachScript19110 struct {
	mu sync.Mutex
	// native and generic hold each ifindex's queued results. When a queue
	// runs out, its last entry repeats.
	native  map[int][]error
	generic map[int][]error
	ops     []string
}

func occupiedErr19110(ifindex int, errno error) error {
	return fmt.Errorf("attach XDP to ifindex %d: %w", ifindex,
		fmt.Errorf("failed to attach link: %w", fmt.Errorf("create link: %w", errno)))
}

func (s *xdpAttachScript19110) next(q map[int][]error, ifindex int) error {
	errs := q[ifindex]
	if len(errs) == 0 {
		return nil
	}
	e := errs[0]
	if len(errs) > 1 {
		q[ifindex] = errs[1:]
	}
	return e
}

func (s *xdpAttachScript19110) seam(op string, ifindex int, generic bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mode := "native"
	if generic {
		mode = "generic"
	}
	s.ops = append(s.ops, fmt.Sprintf("%s/%d/%s", op, ifindex, mode))
	if op != "attach" {
		return true, nil
	}
	if generic {
		return true, s.next(s.generic, ifindex)
	}
	return true, s.next(s.native, ifindex)
}

func (s *xdpAttachScript19110) count(op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, o := range s.ops {
		if o == op {
			n++
		}
	}
	return n
}

func (s *xdpAttachScript19110) trace() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ops...)
}

func runAttach19110(t *testing.T, s *xdpAttachScript19110, pending ...int) error {
	t.Helper()
	return runAttachWithSeam19110(t, s.seam, pending...)
}

// runAttachWithSeam19110 runs one attach pass against a fresh Manager behind the
// given #18740 seam, and fails the cell instead of hanging if the pass never
// returns (an unbounded refusal wait).
func runAttachWithSeam19110(t *testing.T, seam func(string, int, bool) (bool, error), pending ...int) error {
	t.Helper()
	restore := SetXDPTransitionSeamForTest(seam)
	t.Cleanup(restore)
	m := New()
	done := make(chan error, 1)
	go func() { done <- m.attachUserspaceShimXDP(&CompileResult{pendingXDP: pending}) }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("attachUserspaceShimXDP did not return within 30 s: the refusal wait is unbounded")
		return nil
	}
}

// C2, the loss shape. Ifindex 4 is the virtio fabric parent, which has no
// native XDP (EINVAL) and goes generic. Ifindexes 5 and 6 are the mlx5 VFs,
// still occupied by the dead process's links for the first two attempts.
// The VFs must end NATIVE, with no generic attempt on either.
//
// RED at master: the first EBUSY sends the VF to generic.
func TestOccupiedNativeAttachWaitsInsteadOfFallingBackToGeneric19110(t *testing.T) {
	s := &xdpAttachScript19110{
		native: map[int][]error{
			4: {occupiedErr19110(4, unix.EINVAL)},
			5: {occupiedErr19110(5, unix.EBUSY), occupiedErr19110(5, unix.EBUSY), nil},
			6: {occupiedErr19110(6, unix.EBUSY), nil},
		},
		// What the kernel answers while a native link is still attached.
		generic: map[int][]error{
			5: {occupiedErr19110(5, unix.EEXIST), nil},
			6: {occupiedErr19110(6, unix.EEXIST), nil},
		},
	}
	if err := runAttach19110(t, s, 4, 5, 6); err != nil {
		t.Errorf("attach failed: %v (trace %v)", err, s.trace())
	}
	for _, vf := range []int{5, 6} {
		if n := s.count(fmt.Sprintf("attach/%d/generic", vf)); n != 0 {
			t.Errorf("ifindex %d: %d generic attach attempt(s) on an OCCUPIED native-capable "+
				"interface; occupancy is not \"native unavailable\" (#19110). trace %v", vf, n, s.trace())
		}
	}
	if n := s.count("attach/5/native"); n != 3 {
		t.Errorf("ifindex 5: %d native attempts, want 3 (EBUSY, EBUSY, success). trace %v", n, s.trace())
	}
	if n := s.count("attach/4/generic"); n != 1 {
		t.Errorf("ifindex 4 (no native XDP, EINVAL): %d generic attempts, want 1: the real "+
			"unsupported fallback must survive. trace %v", n, s.trace())
	}
}

// C3: the occupant never leaves. The attach must give up within a bound and
// return an error that still carries the occupancy errno. It must not try
// generic, which the kernel refuses while a native program is attached, and
// which would land a native-capable VF in skb mode if the occupant left in the
// meantime.
//
// RED at master: master tries generic and returns the generic attempt's error.
func TestPersistentOccupancyFailsWithoutGenericFallback19110(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EBUSY, unix.EEXIST} {
		t.Run(errno.Error(), func(t *testing.T) {
			s := &xdpAttachScript19110{
				native:  map[int][]error{5: {occupiedErr19110(5, errno)}},
				generic: map[int][]error{5: {occupiedErr19110(5, unix.EEXIST)}},
			}
			start := time.Now()
			err := runAttach19110(t, s, 5)
			if err == nil {
				t.Fatalf("a permanently occupied interface reported a successful attach (trace %v)", s.trace())
			}
			if n := s.count("attach/5/generic"); n != 0 {
				t.Errorf("%d generic attempt(s) on a permanently occupied interface (trace %v)", n, s.trace())
			}
			if !errors.Is(err, errno) {
				t.Errorf("the error does not carry the occupancy errno %v, so an operator cannot tell "+
					"\"something is attached\" from \"driver lacks native XDP\": %v", errno, err)
			}
			if n := s.count("attach/5/native"); n < 2 {
				t.Errorf("%d native attempt(s): an occupied interface must be retried within the bound "+
					"before giving up (trace %v)", n, s.trace())
			}
			t.Logf("gave up after %s and %d native attempts", time.Since(start).Round(time.Millisecond),
				s.count("attach/5/native"))
		})
	}
}

// C4 (control): a genuine "this device has no native XDP" still falls back to
// generic, on the first attempt and without waiting. The cell guards against a
// classifier so broad that it parks a virtio or iavf interface for the whole
// occupancy bound. GREEN at master and at the fix.
func TestUnsupportedNativeXDPStillFallsBackToGeneric19110(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EINVAL, unix.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			s := &xdpAttachScript19110{native: map[int][]error{4: {occupiedErr19110(4, errno)}}}
			start := time.Now()
			if err := runAttach19110(t, s, 4); err != nil {
				t.Fatalf("attach failed: %v (trace %v)", err, s.trace())
			}
			if n := s.count("attach/4/native"); n != 1 {
				t.Errorf("%d native attempts on an unsupported device, want exactly 1 (trace %v)", n, s.trace())
			}
			if n := s.count("attach/4/generic"); n != 1 {
				t.Errorf("%d generic attempts, want 1 (trace %v)", n, s.trace())
			}
			if el := time.Since(start); el > time.Second {
				t.Errorf("an unsupported device took %s to fall back; it must not wait out an occupancy bound", el)
			}
		})
	}
}

// C5: a virtio interface whose stale link is GENERIC. The native attempt first
// sees EEXIST (the other mode is still attached). Once the stale link is gone,
// native reports the real answer, EINVAL, and the interface goes generic.
// Every retry result is RECLASSIFIED: an EEXIST that turns into EINVAL is an
// unsupported device, not a persistent occupant.
//
// The final state (generic, no error) is the same at master, but the attempt
// SEQUENCE is not: master never retries native. RED at master on the sequence
// assertion.
func TestOccupiedThenUnsupportedEndsGeneric19110(t *testing.T) {
	s := &xdpAttachScript19110{
		native: map[int][]error{4: {
			occupiedErr19110(4, unix.EEXIST),
			occupiedErr19110(4, unix.EINVAL),
		}},
	}
	if err := runAttach19110(t, s, 4); err != nil {
		t.Fatalf("attach failed: %v (trace %v)", err, s.trace())
	}
	if n := s.count("attach/4/generic"); n != 1 {
		t.Errorf("%d generic attempts, want 1 (trace %v)", n, s.trace())
	}
	if n := s.count("attach/4/native"); n != 2 {
		t.Errorf("%d native attempts, want 2: EEXIST must be retried, and the retry's EINVAL must be "+
			"reclassified as unsupported (trace %v)", n, s.trace())
	}
}

// C2b: the refusal changes errno between retries (EBUSY while the stale native
// link is attached, then EEXIST, then success). Every retry result is
// reclassified within the one deadline; none of them is "unsupported".
//
// RED at master: the first EBUSY sends the interface to generic.
func TestRefusalThatChangesErrnoIsStillRetried19110(t *testing.T) {
	s := &xdpAttachScript19110{
		native: map[int][]error{5: {
			occupiedErr19110(5, unix.EBUSY),
			occupiedErr19110(5, unix.EEXIST),
			nil,
		}},
		generic: map[int][]error{5: {occupiedErr19110(5, unix.EEXIST)}},
	}
	if err := runAttach19110(t, s, 5); err != nil {
		t.Errorf("attach failed: %v (trace %v)", err, s.trace())
	}
	if n := s.count("attach/5/generic"); n != 0 {
		t.Errorf("%d generic attempt(s) (trace %v)", n, s.trace())
	}
	if n := s.count("attach/5/native"); n != 3 {
		t.Errorf("%d native attempts, want 3 (EBUSY, EEXIST, success) (trace %v)", n, s.trace())
	}
}

// C3b: the occupancy budget is ONE deadline for the whole attach pass, not one
// per interface. Three interfaces are each refused for the first 2 s after
// their own first attempt, and then attach. With one 5 s budget per pass,
// ifindexes 5 and 6 use about 4.4 s, so ifindex 7 runs out before its 2 s are
// up and the pass fails. A per-interface budget would give 7 a fresh 5 s, and
// the pass would SUCCEED. The cell judges that OUTCOME, not a timing.
//
// RED at master through the no-generic assertion. Master sends the first
// refused interface to generic, which the seam refuses with EEXIST.
func TestOccupancyBudgetIsSharedAcrossThePass19110(t *testing.T) {
	var mu sync.Mutex
	firstTry := map[int]time.Time{}
	var ops []string
	seam := func(op string, ifindex int, generic bool) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		ops = append(ops, fmt.Sprintf("%s/%d/%v", op, ifindex, generic))
		if op != "attach" {
			return true, nil
		}
		if generic {
			return true, occupiedErr19110(ifindex, unix.EEXIST)
		}
		if _, ok := firstTry[ifindex]; !ok {
			firstTry[ifindex] = time.Now()
		}
		if time.Since(firstTry[ifindex]) >= 2*time.Second {
			return true, nil
		}
		return true, occupiedErr19110(ifindex, unix.EBUSY)
	}
	start := time.Now()
	err := runAttachWithSeam19110(t, seam, 5, 6, 7)
	mu.Lock()
	trace := append([]string(nil), ops...)
	mu.Unlock()
	for _, o := range trace {
		if strings.HasSuffix(o, "/true") {
			t.Errorf("a generic attempt on a refused interface: %s", o)
		}
	}
	if err == nil {
		t.Errorf("all three interfaces attached after %s: each one got a fresh budget, so the budget is "+
			"per interface, not one per pass (trace %v)", time.Since(start).Round(time.Millisecond), trace)
	} else if !errors.Is(err, unix.EBUSY) {
		t.Errorf("the pass failed, but not on the refusal: %v", err)
	}
	t.Logf("pass ended after %s: %v", time.Since(start).Round(time.Millisecond), err)
}
