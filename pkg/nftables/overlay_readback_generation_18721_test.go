package nftables

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

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

// #18721 fold 8: one readback is exactly ONE pass bracketed by two
// generation reads, with no retry. A stable generation hands back the pass's
// own verdict, however long the pass took. A moved generation fails closed at
// once, whatever the pass decided.
func TestReadAtStableNftGeneration18721(t *testing.T) {
	errVerdict := errors.New("the readback's own verdict")
	for _, want := range []error{nil, errVerdict} {
		gen, calls := genSeq18721(5, 5)
		reads := 0
		got := readAtStableNftGeneration(gen, func() error { reads++; return want })
		if got != want || reads != 1 || *calls != 2 {
			t.Errorf("stable generation, read returns %v: got %v after %d reads / %d generation reads, want %v after 1 / 2", want, got, reads, *calls, want)
		}
	}
	// A moved generation: no retry, fail closed, even though the pass passed,
	// and the Warn/error carry the number of commits that landed.
	gen, calls := genSeq18721(5, 8)
	reads := 0
	got := readAtStableNftGeneration(gen, func() error { reads++; return nil })
	if got == nil || !strings.Contains(got.Error(), "generation changed during readback") || !strings.Contains(got.Error(), "3 commits observed, generation 5 -> 8") {
		t.Errorf("moved generation: got %v, want a fail-closed \"generation changed during readback (3 commits observed, generation 5 -> 8)\"", got)
	}
	if reads != 1 || *calls != 2 {
		t.Errorf("moved generation: %d reads / %d generation reads, want exactly 1 / 2 (no retry)", reads, *calls)
	}
	// A refusal across a moved generation still fails closed.
	gen2, _ := genSeq18721(1, 2)
	if got := readAtStableNftGeneration(gen2, func() error { return errVerdict }); got == nil || got == errVerdict || !strings.Contains(got.Error(), "generation changed") {
		t.Errorf("moved generation with a refusing pass: got %v, want the fail-closed generation error", got)
	}

	// A generation read error is the verdict, before or after the read.
	genErr := errors.New("getgen failed")
	if got := readAtStableNftGeneration(func() (uint32, error) { return 0, genErr }, func() error { return nil }); !errors.Is(got, genErr) {
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
	if got := readAtStableNftGeneration(afterFails, func() error { return nil }); !errors.Is(got, genErr) {
		t.Errorf("failing second generation read: got %v", got)
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

// The production call site is bracketed and makes exactly ONE pass: against
// a fake whose generation moves on every read, VerifyHostInboundOverlay must
// return the fail-closed generation verdict after exactly 2 GETGEN reads. It
// must never return the pass's own verdict; here the pass errors on its first
// object read.
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
	err := in.VerifyHostInboundOverlay(overlay18721())
	if err == nil || !strings.Contains(err.Error(), "generation changed during readback") {
		t.Fatalf("VerifyHostInboundOverlay over a moving generation = %v, want the fail-closed generation verdict", err)
	}
	if gens != 2 {
		t.Errorf("VerifyHostInboundOverlay read the generation %d times, want exactly 2 (one pass, no retry)", gens)
	}
}

// And a stable generation hands back the pass's own verdict: here the fake's
// object-read error, not a generation failure.
func TestVerifyHostInboundOverlayReturnsTheStablePassVerdict18721(t *testing.T) {
	getGen := netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETGEN)
	fake := func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 1 && req[0].Header.Type == getGen {
			reply := genReply18721(t, unix.NFT_MSG_NEWGEN,
				netlink.Attribute{Type: unix.NFTA_GEN_ID, Data: []byte{0, 0, 0, 7}})
			reply.Header.Sequence, reply.Header.PID = req[0].Header.Sequence, req[0].Header.PID
			return []netlink.Message{reply}, nil
		}
		return nltest.Error(int(unix.ENOENT), req)
	}
	in := newNetlinkInstallerConn(func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithTestDial(fake))
	})
	err := in.VerifyHostInboundOverlay(overlay18721())
	if err == nil || strings.Contains(err.Error(), "generation changed") || !strings.Contains(err.Error(), "read host overlay objects") {
		t.Fatalf("VerifyHostInboundOverlay over a stable generation = %v, want the pass's own verdict", err)
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
// sees agreement, and passes with an ACCEPT ahead of the fence. Fold 8: the
// bracket sees the generation move and FAILS CLOSED, with no retry; a stable
// read of the untouched table passes (the control in install).
func TestOverlayReadbackFailsClosedOnAMidReadbackCommit18721(t *testing.T) {
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
			t.Fatal("readback passed with an ACCEPT replaced in ahead of the fence mid-readback")
		}
		if !strings.Contains(err.Error(), "generation changed during readback") {
			t.Errorf("readback = %v, want the fail-closed generation verdict", err)
		}
		if calls != 1 {
			t.Errorf("readback ran %d passes, want exactly 1 (no retry)", calls)
		}
	})

	t.Run("a harmless mid-readback commit fails closed", func(t *testing.T) {
		install()
		calls := 0
		in.overlayReadbackBetweenReadsFn = func() {
			calls++
			c, err := nftables.New()
			if err != nil {
				t.Fatalf("conn: %v", err)
			}
			c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "zz18721"})
			flush("add an unrelated table", c)
		}
		err := in.VerifyHostInboundOverlay(o)
		if err == nil || !strings.Contains(err.Error(), "generation changed during readback") {
			t.Errorf("readback across an unrelated commit = %v, want the fail-closed generation verdict", err)
		}
		if calls != 1 {
			t.Errorf("readback ran %d passes, want exactly 1 (no retry)", calls)
		}
		// With the writer gone, the next readback is stable and passes.
		in.overlayReadbackBetweenReadsFn = nil
		if err := in.VerifyHostInboundOverlay(o); err != nil {
			t.Errorf("stable readback after the commit: %v", err)
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
