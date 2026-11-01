package nftables

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// #18721 (review round 2): the overlay readback makes several separate reads.
// A commit landing between them (AD: a same-handle NLM_F_REPLACE between
// GetRules and the expression-name dump) would let the two views describe
// different rules. readAtStableNftGeneration brackets the whole readback with
// NFT_MSG_GETGEN and retries, then fails closed.

func genSeq18721(ids ...uint32) (func() (uint32, error), *int) {
	calls := 0
	return func() (uint32, error) {
		id := ids[len(ids)-1]
		if calls < len(ids) {
			id = ids[calls]
		}
		calls++
		return id, nil
	}, &calls
}

// testBackoff18721 is a 3-step backoff (4 attempts) for the pure cells. Its
// sleeps are recorded, not slept.
var testBackoff18721 = []time.Duration{2 * time.Millisecond, 10 * time.Millisecond, 50 * time.Millisecond}

func TestReadAtStableNftGeneration18721(t *testing.T) {
	errVerdict := errors.New("the readback's own verdict")
	var slept []time.Duration
	clock := time.Unix(0, 0)
	now := func() time.Time { return clock }
	sleep := func(d time.Duration) { slept = append(slept, d); clock = clock.Add(d) }
	const noDeadline = time.Hour

	// A stable generation hands back the read's verdict, pass or fail, with
	// no pause.
	for _, want := range []error{nil, errVerdict} {
		slept = nil
		gen, _ := genSeq18721(5, 5)
		reads := 0
		got := readAtStableNftGeneration(testBackoff18721, noDeadline, now, sleep, gen, func() error { reads++; return want })
		if got != want || reads != 1 || len(slept) != 0 {
			t.Errorf("stable generation, read returns %v: got %v after %d reads and sleeps %v, want %v after 1 read, no sleep", want, got, reads, slept, want)
		}
	}

	// One commit mid-read: the first verdict is discarded, the retry's is used.
	{
		slept = nil
		gen, _ := genSeq18721(5, 6, 6, 6)
		reads := 0
		got := readAtStableNftGeneration(testBackoff18721, noDeadline, now, sleep, gen, func() error {
			reads++
			if reads == 1 {
				return nil // a PASS read across a commit must not be returned
			}
			return errVerdict
		})
		if got != errVerdict || reads != 2 {
			t.Errorf("one mid-read commit: got %v after %d reads, want the retry's verdict after 2", got, reads)
		}
		if len(slept) != 1 || slept[0] != testBackoff18721[0] {
			t.Errorf("one mid-read commit: slept %v, want [%v]", slept, testBackoff18721[0])
		}
	}

	// AD fold 4: a burst that moves the generation on attempts 1 and 2 and then
	// holds is waited out with growing pauses, and the readback succeeds.
	{
		slept = nil
		gen, calls := genSeq18721(1, 2, 3, 4, 4, 4)
		reads := 0
		got := readAtStableNftGeneration(testBackoff18721, noDeadline, now, sleep, gen, func() error { reads++; return nil })
		if got != nil || reads != 3 || *calls != 6 {
			t.Errorf("two-commit burst: got %v after %d reads / %d generation reads, want nil after 3 / 6", got, reads, *calls)
		}
		if len(slept) != 2 || slept[0] != testBackoff18721[0] || slept[1] != testBackoff18721[1] {
			t.Errorf("two-commit burst: slept %v, want %v", slept, testBackoff18721[:2])
		}
	}

	// A ruleset that never holds still fails closed after len(backoff)+1
	// attempts, even though every read passed, having paused every step.
	{
		slept = nil
		gen, calls := genSeq18721(1, 2, 3, 4, 5, 6, 7, 8, 9)
		reads := 0
		got := readAtStableNftGeneration(testBackoff18721, noDeadline, now, sleep, gen, func() error { reads++; return nil })
		// Generations 1..8 were read: 7 commits landed between the first read
		// and the last, including those during the pauses.
		if got == nil || !strings.Contains(got.Error(), "changed during each of 4 attempts") || !strings.Contains(got.Error(), "7 commits observed, generation 1 -> 8") || !strings.Contains(got.Error(), "attempts exhausted") {
			t.Errorf("moving ruleset: got %v, want a fail-closed \"changed during each of 4 attempts (7 commits observed, generation 1 -> 8, ..., attempts exhausted)\"", got)
		}
		if reads != 4 || *calls != 8 {
			t.Errorf("moving ruleset: %d reads / %d generation reads, want 4 / 8", reads, *calls)
		}
		if len(slept) != 3 || slept[0] != testBackoff18721[0] || slept[1] != testBackoff18721[1] || slept[2] != testBackoff18721[2] {
			t.Errorf("moving ruleset: slept %v, want %v", slept, testBackoff18721)
		}
	}

	// A generation read error is the verdict, before or after the read.
	genErr := errors.New("getgen failed")
	if got := readAtStableNftGeneration(testBackoff18721, noDeadline, now, sleep, func() (uint32, error) { return 0, genErr }, func() error { return nil }); !errors.Is(got, genErr) {
		t.Errorf("failing first generation read: got %v", got)
	}
	n := 0
	afterFails := func() (uint32, error) {
		n++
		if n == 2 {
			return 0, genErr
		}
		return 1, nil
	}
	if got := readAtStableNftGeneration(testBackoff18721, noDeadline, now, sleep, afterFails, func() error { return nil }); !errors.Is(got, genErr) {
		t.Errorf("failing second generation read: got %v", got)
	}
}

// The production backoff is positive and growing, and allows at least the 3
// attempts the first version had (AD fold 4).
func TestHostOverlayReadbackBackoffIsGrowing18721(t *testing.T) {
	for i, d := range hostOverlayReadbackBackoff {
		if d <= 0 || (i > 0 && d <= hostOverlayReadbackBackoff[i-1]) {
			t.Errorf("backoff step %d = %v is not positive and growing: %v", i, d, hostOverlayReadbackBackoff)
		}
	}
	if len(hostOverlayReadbackBackoff)+1 < 3 {
		t.Errorf("backoff %v gives %d attempts, want >= 3", hostOverlayReadbackBackoff, len(hostOverlayReadbackBackoff)+1)
	}
}

// AD fold 6: the wall-clock deadline bounds the readback whatever one pass
// costs. With the production backoff and deadline and a pass that takes 80 ms
// (a slow table under load), a ruleset that never holds must stop on the
// deadline: well before 5 attempts, within deadline + one pass, failing
// closed. The clock is injected and advanced by the fake pass and the sleeps,
// so the pass count is exact rather than load-dependent.
func TestReadAtStableNftGenerationStopsAtTheDeadline18721(t *testing.T) {
	const pass = 80 * time.Millisecond
	clock := time.Unix(0, 0)
	now := func() time.Time { return clock }
	sleep := func(d time.Duration) { clock = clock.Add(d) }
	gen, _ := genSeq18721(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
	reads := 0
	got := readAtStableNftGeneration(hostOverlayReadbackBackoff, hostOverlayReadbackDeadline, now, sleep, gen,
		func() error { reads++; clock = clock.Add(pass); return nil })
	elapsed := clock.Sub(time.Unix(0, 0))
	if got == nil || !strings.Contains(got.Error(), "deadline") {
		t.Fatalf("slow, moving readback = %v, want a fail-closed stop at the deadline", got)
	}
	// 80 ms passes against a 190 ms deadline:
	//   - pass 1 ends at 80 ms; 80+2+80 = 162 fits, so pass 2 runs;
	//   - pass 2 ends at 162 ms; 162+10+80 = 252 does not fit, so it stops.
	// Without the previous-pass estimate it would start a third pass (162+10
	// fits) and end at 252 ms, past the deadline.
	if reads != 2 {
		t.Errorf("readback made %d passes; with 80 ms passes the deadline must stop it after exactly 2", reads)
	}
	if elapsed > hostOverlayReadbackDeadline {
		t.Errorf("readback took %v of injected time, more than the %v deadline", elapsed, hostOverlayReadbackDeadline)
	}
	// A fast pass gets every attempt: on a quick table, the deadline is not
	// what limits a burst.
	gen2, _ := genSeq18721(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
	reads = 0
	clock = time.Unix(0, 0)
	got = readAtStableNftGeneration(hostOverlayReadbackBackoff, hostOverlayReadbackDeadline, now, sleep, gen2,
		func() error { reads++; return nil })
	if got == nil || !strings.Contains(got.Error(), "attempts exhausted") || reads != len(hostOverlayReadbackBackoff)+1 {
		t.Errorf("fast, moving readback = %v after %d passes, want all %d attempts then exhaustion", got, reads, len(hostOverlayReadbackBackoff)+1)
	}
}

func genReply18721(t *testing.T, typ uint16, attrs ...netlink.Attribute) netlink.Message {
	t.Helper()
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | typ)},
		Data:   append([]byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, 0, 0}, b...),
	}
}

func TestDecodeNftGeneration18721(t *testing.T) {
	id := netlink.Attribute{Type: unix.NFTA_GEN_ID, Data: []byte{0, 0, 0x12, 0x34}}
	pid := netlink.Attribute{Type: unix.NFTA_GEN_PROC_PID, Data: []byte{0, 0, 0, 1}}
	got, err := decodeNftGeneration([]netlink.Message{genReply18721(t, unix.NFT_MSG_NEWGEN, id, pid)})
	if err != nil || got != 0x1234 {
		t.Fatalf("decode = %#x, %v; want 0x1234", got, err)
	}
	for name, msgs := range map[string][]netlink.Message{
		"no reply":     nil,
		"two replies":  {genReply18721(t, unix.NFT_MSG_NEWGEN, id), genReply18721(t, unix.NFT_MSG_NEWGEN, id)},
		"wrong type":   {genReply18721(t, unix.NFT_MSG_NEWRULE, id)},
		"no gen id":    {genReply18721(t, unix.NFT_MSG_NEWGEN, pid)},
		"short header": {{Header: netlink.Header{Type: netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWGEN)}, Data: []byte{0}}},
	} {
		if _, err := decodeNftGeneration(msgs); err == nil {
			t.Errorf("%s: decoded a generation", name)
		}
	}
}

// The production call site is bracketed: against a fake whose generation
// moves on every read, VerifyHostInboundOverlay must return the fail-closed
// "changed" verdict after 2 x attempts generation reads. It must never return
// any one pass's verdict; here every pass errors on its first object read.
func TestVerifyHostInboundOverlayIsGenerationBracketed18721(t *testing.T) {
	gens := 0
	getGen := netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETGEN)
	fake := func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 1 && req[0].Header.Type == getGen {
			gens++
			reply := genReply18721(t, unix.NFT_MSG_NEWGEN,
				netlink.Attribute{Type: unix.NFTA_GEN_ID, Data: []byte{0, 0, 0, byte(gens)}})
			reply.Header.Sequence, reply.Header.PID = req[0].Header.Sequence, req[0].Header.PID
			return []netlink.Message{reply}, nil
		}
		return nltest.Error(int(unix.ENOENT), req)
	}
	in := newNetlinkInstallerConn(func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithTestDial(fake))
	})
	start := time.Now()
	err := in.VerifyHostInboundOverlay(overlay18721())
	elapsed := time.Since(start)
	// AD fold 5: production must actually PAUSE between attempts. The pure
	// cells inject a recorder, and these call-site and live cells advance per
	// pass, so only wall time can show the call site sleeps. A lower bound
	// cannot flake: the exhaustion path sleeps every step.
	var pause time.Duration
	for _, d := range hostOverlayReadbackBackoff {
		pause += d
	}
	if elapsed < pause {
		t.Errorf("VerifyHostInboundOverlay exhausted its attempts in %v, less than the %v backoff; the call site is not pausing", elapsed, pause)
	}
	if err == nil || !strings.Contains(err.Error(), "changed during each of") {
		t.Fatalf("VerifyHostInboundOverlay over a moving generation = %v, want the fail-closed \"changed during each of\"", err)
	}
	if want := 2 * (len(hostOverlayReadbackBackoff) + 1); gens != want {
		t.Errorf("VerifyHostInboundOverlay read the generation %d times, want %d", gens, want)
	}
}

// The production call site is bounded by the deadline (AD fold 6). The
// fake's GETGEN is slow (40 ms), so every pass costs at least 80 ms. With a
// generation that moves on every read, the call site must stop on the
// deadline: before all 5 attempts, within deadline + one pass.
func TestVerifyHostInboundOverlayStopsAtTheDeadline18721(t *testing.T) {
	gens := 0
	getGen := netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETGEN)
	fake := func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 1 && req[0].Header.Type == getGen {
			gens++
			time.Sleep(40 * time.Millisecond)
			reply := genReply18721(t, unix.NFT_MSG_NEWGEN,
				netlink.Attribute{Type: unix.NFTA_GEN_ID, Data: []byte{0, 0, 0, byte(gens)}})
			reply.Header.Sequence, reply.Header.PID = req[0].Header.Sequence, req[0].Header.PID
			return []netlink.Message{reply}, nil
		}
		return nltest.Error(int(unix.ENOENT), req)
	}
	in := newNetlinkInstallerConn(func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithTestDial(fake))
	})
	start := time.Now()
	err := in.VerifyHostInboundOverlay(overlay18721())
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("slow, moving call site = %v, want a fail-closed stop at the deadline", err)
	}
	if gens >= 2*(len(hostOverlayReadbackBackoff)+1) {
		t.Errorf("call site read the generation %d times; the deadline should have stopped it before all attempts", gens)
	}
	if limit := hostOverlayReadbackDeadline + 80*time.Millisecond; elapsed > limit {
		t.Errorf("call site took %v, more than the deadline + one pass (%v)", elapsed, limit)
	}
}

// The production call site waits out a short burst (AD fold 4): the fake's
// generation moves on attempts 1 and 2 and then holds, so the call site must
// return the third, stable pass's own verdict. Here that verdict is the fake's
// object-read error, not the fail-closed "changed" verdict.
func TestVerifyHostInboundOverlayWaitsOutABurst18721(t *testing.T) {
	gens := 0
	getGen := netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETGEN)
	fake := func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 1 && req[0].Header.Type == getGen {
			gens++
			id := gens // reads 1..4 move (attempts 1 and 2); from read 5 it holds
			if id > 5 {
				id = 5
			}
			reply := genReply18721(t, unix.NFT_MSG_NEWGEN,
				netlink.Attribute{Type: unix.NFTA_GEN_ID, Data: []byte{0, 0, 0, byte(id)}})
			reply.Header.Sequence, reply.Header.PID = req[0].Header.Sequence, req[0].Header.PID
			return []netlink.Message{reply}, nil
		}
		return nltest.Error(int(unix.ENOENT), req)
	}
	in := newNetlinkInstallerConn(func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithTestDial(fake))
	})
	err := in.VerifyHostInboundOverlay(overlay18721())
	if err == nil || strings.Contains(err.Error(), "changed during each of") || !strings.Contains(err.Error(), "read host overlay objects") {
		t.Fatalf("VerifyHostInboundOverlay after a two-commit burst = %v, want the stable third pass's own verdict", err)
	}
	if gens != 6 {
		t.Errorf("VerifyHostInboundOverlay read the generation %d times, want 6 (3 attempts)", gens)
	}
}

// requirePrivateNetns18721 enters a fresh netns on a locked thread. It skips
// without CAP_NET_ADMIN, unless XPF_REQUIRE_NETNS is set, where it fails.
func requirePrivateNetns18721(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err == nil {
		var ns netns.NsHandle
		if ns, err = netns.New(); err == nil {
			t.Cleanup(func() {
				_ = netns.Set(orig)
				ns.Close()
				orig.Close()
				runtime.UnlockOSThread()
			})
			return
		}
		orig.Close()
	}
	runtime.UnlockOSThread()
	if os.Getenv("XPF_REQUIRE_NETNS") != "" {
		t.Fatalf("cannot create a private netns (run under `unshare -rn`): %v (XPF_REQUIRE_NETNS is set)", err)
	}
	t.Skipf("cannot create a private netns (run under `unshare -rn`): %v", err)
}

// The live race cell. Between GetRules and the expression-name dump, a writer
// REPLACES the zero-hop DROP in place (NLM_F_REPLACE keeps the handle). The
// replacement has the same number of allowlisted expressions but ACCEPTs. An
// unbracketed readback judges the old typed DROP against the new rule's names,
// sees agreement, and passes with an ACCEPT ahead of the fence. The bracket
// sees the generation move, rereads, and refuses the ACCEPT.
func TestOverlayReadbackRetriesPastAMidReadbackCommit18721(t *testing.T) {
	requirePrivateNetns18721(t)
	in := NewNetlinkInstaller().(*netlinkInstaller)
	o := overlay18721()
	t.Cleanup(func() { _ = in.DeleteTable(HostInboundTableName) })
	install := func() {
		t.Helper()
		in.overlayReadbackBetweenReadsFn = nil
		if err := in.InstallHostInbound(HostInboundSpec{Overlay: &o}); err != nil {
			t.Fatalf("install fenced host-inbound table: %v", err)
		}
		if err := in.VerifyHostInboundOverlay(o); err != nil {
			t.Fatalf("control: readback of the untouched fenced table: %v", err)
		}
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: HostInboundTableName}
	chain := &nftables.Chain{Name: "input", Table: tbl}
	flush := func(what string, c *nftables.Conn) {
		t.Helper()
		if err := c.Flush(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	t.Run("same-handle replace with an ACCEPT twin", func(t *testing.T) {
		install()
		calls := 0
		in.overlayReadbackBetweenReadsFn = func() {
			calls++
			if calls != 1 {
				return
			}
			c, err := nftables.New()
			if err != nil {
				t.Fatalf("conn: %v", err)
			}
			rules, err := c.GetRules(tbl, chain)
			if err != nil || len(rules) == 0 {
				t.Fatalf("read the live chain: %d rules, %v", len(rules), err)
			}
			head := rules[0]
			if !hasType18721[*expr.Fib](head.Exprs) {
				t.Fatalf("fixture: rule 0 is not the zero-hop DROP: %#v", head.Exprs)
			}
			// Same expression count as the head's typed decode, all
			// allowlisted kinds, ending in ACCEPT.
			twin := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
			}
			for len(twin) < len(head.Exprs)-2 {
				twin = append(twin,
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}})
			}
			if len(twin) < len(head.Exprs)-1 {
				twin = append(twin, &expr.Counter{})
			}
			twin = append(twin, &expr.Verdict{Kind: expr.VerdictAccept})
			if len(twin) != len(head.Exprs) {
				t.Fatalf("fixture: twin has %d expressions, head decodes to %d", len(twin), len(head.Exprs))
			}
			c.ReplaceRule(&nftables.Rule{Table: tbl, Chain: chain, Handle: head.Handle, Exprs: twin})
			flush("replace the head rule in place", c)
			after, err := c.GetRules(tbl, chain)
			if err != nil || len(after) == 0 || after[0].Handle != head.Handle {
				t.Fatalf("fixture: the replace did not keep handle %d at the head (%v)", head.Handle, err)
			}
		}
		err := in.VerifyHostInboundOverlay(o)
		if err == nil {
			t.Error("readback passed with an ACCEPT replaced in ahead of the fence mid-readback")
		} else if !strings.Contains(err.Error(), "leading rule absent") {
			t.Errorf("readback = %v, want the reread to refuse the ACCEPT head (\"leading rule absent\")", err)
		}
		if calls != 2 {
			t.Errorf("readback ran %d passes, want 2 (the first one spanned a commit)", calls)
		}
	})

	t.Run("a harmless mid-readback commit is retried and passes", func(t *testing.T) {
		install()
		calls := 0
		in.overlayReadbackBetweenReadsFn = func() {
			calls++
			if calls != 1 {
				return
			}
			c, err := nftables.New()
			if err != nil {
				t.Fatalf("conn: %v", err)
			}
			c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "zz18721"})
			flush("add an unrelated table", c)
		}
		if err := in.VerifyHostInboundOverlay(o); err != nil {
			t.Errorf("readback after one unrelated commit: %v", err)
		}
		if calls != 2 {
			t.Errorf("readback ran %d passes, want 2", calls)
		}
	})

	t.Run("a two-commit burst is waited out and passes", func(t *testing.T) {
		install()
		calls := 0
		in.overlayReadbackBetweenReadsFn = func() {
			calls++
			if calls > 2 {
				return
			}
			c, err := nftables.New()
			if err != nil {
				t.Fatalf("conn: %v", err)
			}
			name := "zz18721c"
			if calls == 1 {
				c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
			} else {
				c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
			}
			flush("burst commit", c)
		}
		if err := in.VerifyHostInboundOverlay(o); err != nil {
			t.Errorf("readback after a two-commit burst: %v", err)
		}
		if calls != 3 {
			t.Errorf("readback ran %d passes, want 3", calls)
		}
	})

	t.Run("a ruleset that never holds still fails closed", func(t *testing.T) {
		install()
		calls := 0
		in.overlayReadbackBetweenReadsFn = func() {
			calls++
			c, err := nftables.New()
			if err != nil {
				t.Fatalf("conn: %v", err)
			}
			if calls%2 == 1 {
				c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "zz18721b"})
			} else {
				c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "zz18721b"})
			}
			flush("churn an unrelated table", c)
		}
		start := time.Now()
		err := in.VerifyHostInboundOverlay(o)
		elapsed := time.Since(start)
		if err == nil || !strings.Contains(err.Error(), "changed during each of") {
			t.Errorf("readback under constant churn = %v, want fail-closed \"changed during each of\"", err)
		}
		// It stops on attempts or on the deadline, whichever comes first.
		// Either way, it retried, and it stayed within the deadline plus the
		// overrun of one pass (a commit plus a readback here).
		if max := len(hostOverlayReadbackBackoff) + 1; calls < 2 || calls > max {
			t.Errorf("readback ran %d passes, want 2..%d", calls, max)
		}
		if limit := hostOverlayReadbackDeadline + 100*time.Millisecond; elapsed > limit {
			t.Errorf("readback under churn took %v, more than %v", elapsed, limit)
		}
	})

	t.Run("a multi-master overlay reads only the sets its rules reference", func(t *testing.T) {
		in.overlayReadbackBetweenReadsFn = nil
		multi := CanonicalHostInputFenceOverlay(HostInputFenceOverlay{
			MasterSet: []string{"st0", "st1", "st2"}, Generation: 9, PermitEpoch: 3, CloseRequestSeq: 4,
			CloseRequestKey: "9/[xfrmi:st0,st1,st2]", WatchGeneration: 9, State: "CLOSING",
		})
		// Many unrelated ifname sets beside it: the screen-flood views below
		// declare named sets, and the ingress scoping adds more.
		spec := largeHostInboundSpec12128(24)
		spec.Overlay = &multi
		if err := in.InstallHostInbound(spec); err != nil {
			t.Fatalf("install multi-master fenced table: %v", err)
		}
		c, err := nftables.New()
		if err != nil {
			t.Fatalf("conn: %v", err)
		}
		live, err := c.GetRules(tbl, chain)
		if err != nil {
			t.Fatalf("read live chain: %v", err)
		}
		if refs := hostOverlayReferencedSets(live, HostInputFenceOverlayCounterName(multi)); len(refs) == 0 {
			t.Fatal("fixture: the multi-master overlay rule references no set, so the referenced-set read is not exercised")
		}
		if err := in.VerifyHostInboundOverlay(multi); err != nil {
			t.Errorf("multi-master overlay readback: %v", err)
		}
		other := multi
		other.MasterSet = []string{"st0", "st1"}
		if err := in.VerifyHostInboundOverlay(CanonicalHostInputFenceOverlay(other)); err == nil {
			t.Error("readback accepted a different master set for the multi-master overlay")
		}
	})
	in.overlayReadbackBetweenReadsFn = nil
}
