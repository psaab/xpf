package nftables

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// #18746, AG on #18759: readAtStableNftGeneration returns a typed error and
// does not log. Its Warn used to say "host overlay readback" for every caller,
// including the zero-hop predicates the kernel-truth loop runs every 30 s.

func captureSlog18746(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(orig) })
	return &buf
}

func TestGenerationChangedErrorIsTypedAndSilent18746(t *testing.T) {
	buf := captureSlog18746(t)
	gen, _ := genSeq18721(5, 8)
	err := readAtStableNftGeneration(gen, func() error { return nil })
	var moved *GenerationChangedError
	if !errors.As(err, &moved) || *moved != (GenerationChangedError{CommitsObserved: 3, Before: 5, After: 8}) {
		t.Fatalf("moved generation = %#v, want *GenerationChangedError{3, 5, 8}", err)
	}
	if !errors.Is(fmt.Errorf("nftables read %s input rules: %w", "t", err), ErrGenerationChanged) {
		t.Error("ErrGenerationChanged does not match through %w wrapping")
	}
	if errors.Is(errors.New("generation changed during readback"), ErrGenerationChanged) {
		t.Error("an untyped error with the same text matched ErrGenerationChanged")
	}
	if buf.Len() != 0 {
		t.Errorf("readAtStableNftGeneration logged; each caller must label its own failure:\n%s", buf.String())
	}
}

func TestRereadOnGenerationChange18746(t *testing.T) {
	moved := &GenerationChangedError{CommitsObserved: 1, Before: 1, After: 2}
	scripted := func(errs ...error) (func() (int, error), *int) {
		n := 0
		return func() (int, error) {
			e := errs[min(n, len(errs)-1)]
			n++
			return n, e
		}, &n
	}
	// Moved once, then stable: the re-read's verdict comes back.
	read, n := scripted(moved, nil)
	if v, err := RereadOnGenerationChange(3, read); err != nil || v != 2 || *n != 2 {
		t.Errorf("moved then stable = %d, %v after %d reads; want 2, nil after 2", v, err, *n)
	}
	// Always moving: bounded at 1+rereads, and the generation error survives.
	read, n = scripted(moved)
	if _, err := RereadOnGenerationChange(3, read); !errors.Is(err, ErrGenerationChanged) || *n != 4 {
		t.Errorf("constant churn = %v after %d reads; want the generation error after 4", err, *n)
	}
	// A real error is returned at once.
	real := errors.New("permission denied")
	read, n = scripted(real, nil)
	if _, err := RereadOnGenerationChange(3, read); err != real || *n != 1 {
		t.Errorf("real error = %v after %d reads; want it unchanged after 1", err, *n)
	}
	// The pausing variant pauses before each re-read only.
	pauses := 0
	read, n = scripted(moved, moved, nil)
	if _, err := RereadOnGenerationChangeAfter(3, func() { pauses++ }, read); err != nil || *n != 3 || pauses != 2 {
		t.Errorf("pausing re-read = %v after %d reads and %d pauses; want nil after 3 reads, 2 pauses", err, *n, pauses)
	}
	pauses = 0
	read, n = scripted(nil)
	if _, _ = RereadOnGenerationChangeAfter(3, func() { pauses++ }, read); pauses != 0 {
		t.Errorf("a first read that answers paused %d times, want 0", pauses)
	}
	// Zero re-reads is one read.
	read, n = scripted(moved, nil)
	if _, err := RereadOnGenerationChange(0, read); !errors.Is(err, ErrGenerationChanged) || *n != 1 {
		t.Errorf("rereads=0 = %v after %d reads; want one read", err, *n)
	}
}

// The overlay readback keeps its Warn and its error text, and the error is
// still typed for a caller that wants to test it.
func TestOverlayReadbackLabelsItsOwnGenerationFailure18746(t *testing.T) {
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
	buf := captureSlog18746(t)
	err := in.VerifyHostInboundOverlay(overlay18721())
	const want = "host overlay readback: generation changed during readback (1 commits observed, generation 1 -> 2); failing closed"
	if err == nil || err.Error() != want {
		t.Fatalf("overlay readback = %v, want %q", err, want)
	}
	if !errors.Is(err, ErrGenerationChanged) {
		t.Error("the overlay's generation failure is not errors.Is ErrGenerationChanged")
	}
	out := buf.String()
	if strings.Count(out, "level=WARN") != 1 || !strings.Contains(out, "host overlay readback: generation changed during readback; failing closed") || !strings.Contains(out, "commits_observed=1") {
		t.Errorf("overlay readback must Warn exactly once with its own label and the commit count:\n%s", out)
	}
	if gens != 2 {
		t.Errorf("overlay readback read the generation %d times, want 2 (no re-read)", gens)
	}
}
