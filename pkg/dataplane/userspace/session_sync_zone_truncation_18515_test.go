package userspace

// #18515: the session value carries only the low 16 bits of the u32
// StableZoneID (#16557). The sync request must recover the full ID and the
// zone name from the zones published to the helper; a zero-extended u16 is
// an ID no zone has, which made every peer-synced session FOREIGN on the
// node that imported it and killed every established flow on failover.

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestResolveTruncatedZone18515(t *testing.T) {
	lan, wan := config.StableZoneID("lan"), config.StableZoneID("wan")
	// The fixture is only meaningful if the full IDs do not fit in 16 bits:
	// that is the population the zero-extension corrupted.
	if lan <= 0xFFFF || wan <= 0xFFFF {
		t.Fatalf("FIXTURE: zone ids lan=%d wan=%d must exceed 16 bits", lan, wan)
	}
	if uint16(lan) == uint16(wan) {
		t.Fatalf("FIXTURE: lan and wan must not share low 16 bits")
	}
	zones := []ZoneSnapshot{{Name: "lan", ID: lan}, {Name: "wan", ID: wan}}

	cases := []struct {
		name          string
		zones         []ZoneSnapshot
		in            uint16
		wantID        uint32
		wantName      string
		wantAmbiguous bool
	}{
		{"zero is no zone", zones, 0, 0, "", false},
		{"recovers lan", zones, uint16(lan), lan, "lan", false},
		{"recovers wan", zones, uint16(wan), wan, "wan", false},
		// Distinct full IDs sharing low 16 bits cannot be told apart:
		// import an ID no zone carries (same low 16 bits) rather than guess
		// one, and say so. Not 0: an unzoned arrival is zone 0 and would be
		// judged the session's owner.
		{"distinct ids sharing low 16 bits are ambiguous", []ZoneSnapshot{{Name: "a", ID: 0x0001_0007}, {Name: "b", ID: 0x0002_0007}}, 7, 0x0000_0007, "", true},
		// The bare low-16 value is itself a zone's ID: skip to the next
		// free ID with the same low bits.
		{"ambiguous skips an id a zone carries", []ZoneSnapshot{{Name: "a", ID: 0x0000_0007}, {Name: "b", ID: 0x0001_0007}}, 7, 0x0002_0007, "", true},
		// A zone whose ID has low 16 bits 0 is indistinguishable from the
		// session value's "no zone": it cannot be carried at all.
		{"zone with low 16 bits zero is unrecoverable", []ZoneSnapshot{{Name: "z", ID: 0x0003_0000}}, 0, 0, "", false},
		{"no matching zone passes through", zones, uint16(lan) ^ 1, uint32(uint16(lan) ^ 1), "", false},
		{"no published zones passes through", nil, uint16(lan), uint32(uint16(lan)), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotID, gotName, gotAmbiguous := resolveTruncatedZone(tc.zones, tc.in)
			if gotID != tc.wantID || gotName != tc.wantName || gotAmbiguous != tc.wantAmbiguous {
				t.Fatalf("resolveTruncatedZone(%d) = (%d, %q, %t), want (%d, %q, %t)",
					tc.in, gotID, gotName, gotAmbiguous, tc.wantID, tc.wantName, tc.wantAmbiguous)
			}
		})
	}
}

// The request the importing helper receives must carry the FULL zone IDs and
// names for both families — resolved from m.lastSnapshot.Zones, the set the
// production path reads — and the egress owner RG that the zone-name
// fallback derives when the FIB egress is unresolved.
func TestSessionSyncRequestCarriesFullZoneIDs18515(t *testing.T) {
	lan, wan := config.StableZoneID("lan"), config.StableZoneID("wan")
	m := goldenManager16172()
	m.lastSnapshot.Zones = []ZoneSnapshot{{Name: "lan", ID: lan}, {Name: "wan", ID: wan}}
	check := func(t *testing.T, req SessionSyncRequest) {
		t.Helper()
		if req.IngressZoneID != lan || req.IngressZone != "lan" {
			t.Fatalf("ingress zone = (%d, %q), want (%d, \"lan\")", req.IngressZoneID, req.IngressZone, lan)
		}
		if req.EgressZoneID != wan || req.EgressZone != "wan" {
			t.Fatalf("egress zone = (%d, %q), want (%d, \"wan\")", req.EgressZoneID, req.EgressZone, wan)
		}
		// FibIfindex is 0, so the owner RG comes from the egress zone name:
		// reth0.80 (zone wan) is RG 1 in the golden snapshot.
		if req.OwnerRGID != 1 {
			t.Fatalf("owner RG = %d, want 1 (from egress zone wan)", req.OwnerRGID)
		}
	}
	t.Run("v4", func(t *testing.T) {
		check(t, m.buildSessionSyncRequestV4("upsert",
			dataplane.SessionKey{SrcIP: [4]byte{10, 0, 62, 102}, DstIP: [4]byte{172, 16, 80, 210}, SrcPort: hostToNetwork16(48742), DstPort: hostToNetwork16(5211), Protocol: 6},
			&dataplane.SessionValue{IngressZone: uint16(lan), EgressZone: uint16(wan)}))
	})
	t.Run("v6", func(t *testing.T) {
		check(t, m.buildSessionSyncRequestV6("upsert",
			dataplane.SessionKeyV6{SrcIP: ip16("2001:559:8585:aa00::102"), DstIP: ip16("2001:559:8585:80::210"), SrcPort: hostToNetwork16(48742), DstPort: hostToNetwork16(5211), Protocol: 6},
			&dataplane.SessionValueV6{IngressZone: uint16(lan), EgressZone: uint16(wan)}))
	})
}

// warnCapture18515 records every slog record, so the warn-once cell asserts
// the LOG (level and count), not only the dedup bookkeeping.
type warnCapture18515 struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *warnCapture18515) Enabled(context.Context, slog.Level) bool { return true }
func (c *warnCapture18515) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r.Clone())
	return nil
}
func (c *warnCapture18515) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *warnCapture18515) WithGroup(string) slog.Handler      { return c }

// An ambiguous value is reported ONCE at WARN, not per synced session: a
// per-call warning would flood the log during a bulk sync.
func TestAmbiguousSyncZoneWarnsOnce18515(t *testing.T) {
	capture := &warnCapture18515{}
	prev := slog.Default()
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(prev) })

	m := goldenManager16172()
	m.lastSnapshot.Zones = []ZoneSnapshot{{Name: "a", ID: 0x0001_0007}, {Name: "b", ID: 0x0002_0007}, {Name: "c", ID: 0x0003_0009}}
	for i := 0; i < 3; i++ {
		if id, name := m.resolveSessionZoneLocked(7); id != 0x0000_0007 || name != "" {
			t.Fatalf("ambiguous zone resolved to (%#x, %q), want (0x7, \"\")", id, name)
		}
	}
	// A value that resolves to a unique zone never warns.
	if id, name := m.resolveSessionZoneLocked(9); id != 0x0003_0009 || name != "c" {
		t.Fatalf("unique zone resolved to (%#x, %q), want (0x30009, \"c\")", id, name)
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()
	warns := 0
	for _, r := range capture.records {
		if strings.Contains(r.Message, "session-sync zone id is ambiguous") {
			if r.Level != slog.LevelWarn {
				t.Fatalf("ambiguity record level = %v, want WARN", r.Level)
			}
			warns++
		}
	}
	if warns != 1 {
		t.Fatalf("ambiguity warnings = %d over 3 calls, want exactly 1", warns)
	}
}

var zoneSink18515 uint32

// The 16172 allocation pin publishes no zones, so the resolver loop never
// runs under it. With zones published, resolving a unique, an ambiguous
// (already warned) and an unmatched value allocates nothing: this runs once
// per synced session, twice per request, during a bulk.
func TestSyncZoneResolutionAllocatesNothing18515(t *testing.T) {
	lan, wan := config.StableZoneID("lan"), config.StableZoneID("wan")
	m := goldenManager16172()
	m.lastSnapshot.Zones = []ZoneSnapshot{{Name: "lan", ID: lan}, {Name: "wan", ID: wan}, {Name: "a", ID: 0x0001_0007}, {Name: "b", ID: 0x0002_0007}}
	// The once-per-value warning is a one-time cost, not a per-call one.
	m.ambiguousSyncZoneWarned = map[uint16]struct{}{7: {}}
	for _, v := range []uint16{uint16(lan), 7, uint16(lan) ^ 1} {
		allocs := testing.AllocsPerRun(200, func() { zoneSink18515, _ = m.resolveSessionZoneLocked(v) })
		if allocs != 0 {
			t.Fatalf("resolveSessionZoneLocked(%#x) allocates %.1f/op with zones published, want 0", v, allocs)
		}
	}
}
