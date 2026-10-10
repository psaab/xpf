package ra

// Regression tests for #3895: an over-large PREF64/router/prefix lifetime made
// the ndp marshal of a single option fail, which — since the whole Router
// Advertisement is built and sent in ONE conn.WriteTo — aborted the ENTIRE RA.
// The segment then silently stopped receiving RAs and hosts lost their default
// route / SLAAC config once the current advertisements expired (IPv6
// blackhole). The commit-time schema bound (pkg/config) is the primary guard;
// buildRA now also prunes any un-marshalable option so a bad option degrades to
// "missing that one option" instead of a total RA blackout (defense-in-depth
// for a config that predates the bound, e.g. a loaded active.json).

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// overlargePREF64Life is a PREF64 lifetime whose RFC 8781 §4 13-bit
// scaled-by-8 wire field overflows: round(100000/8) = 12500 > 8191, so
// ndp.PREF64.marshal returns "scaled lifetime is too large". Only the direct
// helper test below hands it to the probe: an explicit lifetime this large
// that reaches buildRA is dropped before the probe by the #12536 sink check.
const overlargePREF64Life = 100000

// unmarshalablePREF64Prefix keeps the buildRA-level probe test honest. Paired
// with a valid lifetime no sink check drops it, but /33 is outside the RFC 8781
// §4 length set {32,40,48,56,64,96}, so ndp.PREF64.marshal fails with
// "invalid pref64 prefix size". The commit-time gate rejects the length
// (#2497 ValidatePREF64CIDR); tolerant Load / peer-sync ingress can still
// deliver it to buildRA, where the probe is the only guard.
const unmarshalablePREF64Prefix = "64:ff9b::/33"

func newTestSender3895(cfg *config.RAInterfaceConfig) *sender {
	return &sender{
		cfg: cfg,
		iface: &net.Interface{
			Name:         cfg.Interface,
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}
}

// An un-marshalable PREF64 that reaches the sender must NOT abort the whole
// RA. buildRA prunes it so the rest of the RA (SLLA + on-link prefix) still
// marshals and goes out on the wire.
//
// RED-on-revert: remove the buildRA prune call and the bad PREF64 stays in
// ra.Options; ndp.MarshalMessage — the same encoder conn.WriteTo runs — then
// fails, so the segment stops getting RAs (the #3895 blackhole). The option
// must stay un-marshalable for a reason no earlier buildRA check catches: an
// over-large explicit lifetime is now dropped before the probe (#12536), so
// that shape would pass here even with the prune call removed.
func TestBuildRA_3895_PruneUnmarshalablePREF64(t *testing.T) {
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface:       "trust0",
		NAT64Prefix:     unmarshalablePREF64Prefix,
		NAT64PrefixLife: 1800,
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
	})

	ra := s.buildRA()

	// The whole RA must marshal — this is exactly what conn.WriteTo does.
	if _, err := ndp.MarshalMessage(ra); err != nil {
		t.Fatalf("RA must still marshal after pruning the bad PREF64; got %v", err)
	}

	// The bad PREF64 must be gone...
	for _, opt := range ra.Options {
		if _, ok := opt.(*ndp.PREF64); ok {
			t.Fatal("un-marshalable PREF64 option should have been pruned")
		}
	}

	// ...while the rest of the RA survives (only the bad option is dropped).
	var foundSLLA, foundPrefix bool
	for _, opt := range ra.Options {
		switch opt.(type) {
		case *ndp.LinkLayerAddress:
			foundSLLA = true
		case *ndp.PrefixInformation:
			foundPrefix = true
		}
	}
	if !foundSLLA {
		t.Error("source link-layer address dropped; only the bad option should be")
	}
	if !foundPrefix {
		t.Error("prefix information dropped; only the bad option should be")
	}
}

// A valid PREF64 lifetime must be kept and the RA must marshal with it (guards
// against the prune over-reaching and dropping legitimate options).
func TestBuildRA_3895_ValidPREF64Kept(t *testing.T) {
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface:       "trust0",
		NAT64Prefix:     "64:ff9b::/96",
		NAT64PrefixLife: 1800,
	})

	ra := s.buildRA()
	if _, err := ndp.MarshalMessage(ra); err != nil {
		t.Fatalf("RA with a valid PREF64 must marshal; got %v", err)
	}
	var found bool
	for _, opt := range ra.Options {
		if _, ok := opt.(*ndp.PREF64); ok {
			found = true
		}
	}
	if !found {
		t.Error("valid PREF64 option was dropped")
	}
}

// Boundary: exactly the RFC 8781 §4 maximum (65528s) still marshals and is kept.
func TestBuildRA_3895_MaxPREF64Kept(t *testing.T) {
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface:       "trust0",
		NAT64Prefix:     "64:ff9b::/96",
		NAT64PrefixLife: 65528,
	})

	ra := s.buildRA()
	if _, err := ndp.MarshalMessage(ra); err != nil {
		t.Fatalf("RA with the max PREF64 lifetime (65528s) must marshal; got %v", err)
	}
	var found bool
	for _, opt := range ra.Options {
		if _, ok := opt.(*ndp.PREF64); ok {
			found = true
		}
	}
	if !found {
		t.Error("max-lifetime PREF64 option was dropped")
	}
}

// Direct unit test of the per-option robustness helper: a mix of good options
// plus one hand-crafted un-marshalable PREF64 -> only the bad one is dropped
// and every survivor marshals cleanly.
func TestPruneUnmarshalableOptions_3895(t *testing.T) {
	good1 := &ndp.LinkLayerAddress{
		Direction: ndp.Source,
		Addr:      net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}
	bad := &ndp.PREF64{
		Lifetime: time.Duration(overlargePREF64Life) * time.Second,
		Prefix:   netip.MustParsePrefix("64:ff9b::/96"),
	}
	good2 := ndp.NewMTU(1500)

	// Sanity: the crafted bad option really does fail to marshal.
	if _, err := ndp.MarshalMessage(&ndp.RouterAdvertisement{Options: []ndp.Option{bad}}); err == nil {
		t.Fatal("test precondition: crafted PREF64 should fail to marshal")
	}

	kept := pruneUnmarshalableOptions("trust0", []ndp.Option{good1, bad, good2})

	if len(kept) != 2 {
		t.Fatalf("kept %d options, want 2 (bad PREF64 dropped)", len(kept))
	}
	for _, opt := range kept {
		if _, ok := opt.(*ndp.PREF64); ok {
			t.Fatal("bad PREF64 should not survive pruning")
		}
		probe := &ndp.RouterAdvertisement{Options: []ndp.Option{opt}}
		if _, err := ndp.MarshalMessage(probe); err != nil {
			t.Fatalf("surviving option %T must marshal; got %v", opt, err)
		}
	}
}
