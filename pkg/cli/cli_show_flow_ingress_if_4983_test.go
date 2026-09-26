package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #4983 F5: the detailed `show security flow session` output resolves the
// "In: ... If:" column from the session's RECORDED ingress identity, the same
// datum sessionFilter.resolveIngressIfaces selects on.
//
// Before this the column was derived from the ingress zone's FIRST configured
// interface (zoneIfaces[val.IngressZone]). Once the FILTER became exact, the
// two disagreed on exactly the sessions the feature exists for: `show security
// flow session interface lo.50` would select the sessions that arrived on
// lo.50 and then print `If: ge-0/0/8.0` for every one of them. A filter and a
// column that answer the same question differently read as a bug in the
// filter.
//
// "the sessions that arrived on lo.50" is the INGRESS ARM only (#6928 review):
// matchesV4/matchesV6 OR the ingress and egress arms, so an `interface` filter
// also selects sessions that merely EGRESS there. The #4983 tests below are
// about the ingress column agreeing with the ingress arm and leave FibIfindex
// zero; the two #6928 tests at the end of this file exercise the egress arm
// deliberately, because the OR is what makes "the filter and the column cannot
// disagree" false even for a perfectly stamped identity.
//
// Harness note: buildSessionEgressIfaces resolves names through the real
// net.InterfaceByName, so the fixture's ingress interface has to be a netdev
// that exists on the test host. `lo` is the one name that is always present
// (the #5813 display tests use it for the same reason). THREE UNITS of it —
// unit 0, unit 50 and unit 80 — give the fixture its distinguishing properties
// without needing a second real NIC: every unit shares one parent ifindex, so
// only the {ifindex, VLAN} pair separates them, which is precisely the identity
// under test. Unit 80 is the egress name the #6928 tests filter on.

const (
	ingressIfColumnTrustZoneID   uint16 = 1
	ingressIfColumnUntrustZoneID uint16 = 2
	// A zone that binds NO interfaces — declared in the config and compiled
	// into ZoneIDs, but with an empty interface list, so zoneIfaces has no
	// entry for it. That is the last-resort arm of the column resolver.
	ingressIfColumnEmptyZoneID uint16 = 3
)

// ingressIfColumnCLIDP is a "loaded" dataplane serving exactly one v4 and one
// v6 forward session, both recorded with the ingress identity and zone the
// fixture was built with.
type ingressIfColumnCLIDP struct {
	*dataplane.Manager
	apply       *dataplane.ApplyResult
	ifindex     uint32
	vlanID      uint16
	ingressZone uint16
	v4State     uint8
	v6State     uint8
	// The FIB egress identity, zero for every caller that only exercises the
	// ingress column (#6928). A non-zero value gives the session a NAMEABLE
	// egress interface, which is what the egress arm of the interface filter
	// resolves — see TestInterfaceFilterReachesRowViaEgressArm6928.
	fibIfindex uint32
	fibVlanID  uint16
}

func (d *ingressIfColumnCLIDP) IsLoaded() bool { return true }

func (d *ingressIfColumnCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func (d *ingressIfColumnCLIDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	key := dataplane.SessionKey{Protocol: 6}
	copy(key.SrcIP[:], net.IPv4(10, 0, 62, 102).To4())
	copy(key.DstIP[:], net.IPv4(8, 8, 8, 8).To4())
	val := dataplane.SessionValue{
		State:       d.v4State,
		IngressZone: d.ingressZone,
		EgressZone:  ingressIfColumnUntrustZoneID,
		// FibIfindex is 0 for every caller that asserts on the ingress column,
		// so the EGRESS column falls back to the untrust zone's own interface
		// and cannot supply the name the ingress assertion is looking for. The
		// #6928 egress-arm tests set it deliberately.
		FibIfindex:     d.fibIfindex,
		FibVlanID:      d.fibVlanID,
		IngressIfindex: d.ifindex,
		IngressVlanID:  d.vlanID,
	}
	fn(key, val)
	return nil
}

func (d *ingressIfColumnCLIDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	key := dataplane.SessionKeyV6{Protocol: 6}
	copy(key.SrcIP[:], net.ParseIP("2001:559:8585:bf01::102").To16())
	copy(key.DstIP[:], net.ParseIP("2001:4860:4860::8888").To16())
	val := dataplane.SessionValueV6{
		State:          d.v6State,
		IngressZone:    d.ingressZone,
		EgressZone:     ingressIfColumnUntrustZoneID,
		FibIfindex:     d.fibIfindex,
		FibVlanID:      d.fibVlanID,
		IngressIfindex: d.ifindex,
		IngressVlanID:  d.vlanID,
	}
	fn(key, val)
	return nil
}

// ingressIfColumnCLI builds the CLI + config for the column test: a `trust`
// zone whose FIRST interface (ge-0/0/8.0, the zone-derived answer) is NOT the
// interface the session arrived on (lo.50, the recorded answer), and an
// `untrust` zone supplying a third distinct name for the egress column.
func ingressIfColumnCLI(t *testing.T) *CLI {
	t.Helper()
	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	return ingressIfColumnCLIWith(t, uint32(loIface.Index), 50, ingressIfColumnTrustZoneID)
}

// ingressIfColumnCLIWith is the same fixture with the session's recorded
// ingress identity and ingress zone supplied by the caller, so one config can
// drive both the precise arm of the column resolver and each of its fallback
// arms. It does NOT need `lo` to resolve — only ingressIfColumnCLI does, for
// the precise case.
func ingressIfColumnCLIWith(t *testing.T, ifindex uint32, vlanID, ingressZone uint16) *CLI {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/8 {
        unit 0 { family inet { address 10.20.31.40/24; } }
    }
    ge-0/0/9 {
        unit 0 { family inet { address 10.20.30.40/24; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { ge-0/0/8.0; }
        }
        security-zone untrust {
            interfaces { ge-0/0/9.0; }
        }
        security-zone quarantine {
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		t.Fatalf("fixture missing active config")
	}
	// Add the ingress unit on a netdev that really resolves. Injected rather
	// than parsed because `lo` is not a Junos interface name; the shape
	// (parent + two units, one tagged) is what the code under test reads.
	//
	// Unit 80 exists for the #6928 egress-arm tests. It has to be a THIRD unit
	// rather than reusing unit 0: buildSessionEgressIfaces names unit 0 plainly
	// `lo` (session_display.go:57-60 only appends `.N` for a non-zero unit or
	// VLAN), and `ifaceMatches` treats a bare parent name as matching every unit
	// of it — so a `lo` filter would hit the INGRESS arm too and the tests could
	// not tell the two arms apart.
	cfg.Interfaces.Interfaces["lo"] = &config.InterfaceConfig{
		Name: "lo",
		Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			50: {Number: 50, VlanID: 50},
			80: {Number: 80, VlanID: 80},
		},
	}
	trust := cfg.Security.Zones["trust"]
	if trust == nil {
		t.Fatalf("fixture missing trust zone")
	}
	// ge-0/0/8.0 stays FIRST: it is the name the retired zone-derived column
	// would print, so it must be a live candidate for the assertion to bind.
	trust.Interfaces = append(trust.Interfaces, "lo.50")

	if q := cfg.Security.Zones["quarantine"]; q == nil {
		t.Fatalf("fixture missing quarantine zone: a zone with no interfaces must be "+
			"expressible, otherwise the zoneName last-resort arm is unreachable; zones=%v",
			cfg.Security.Zones)
	} else if len(q.Interfaces) != 0 {
		t.Fatalf("quarantine zone must bind NO interfaces, got %v", q.Interfaces)
	}

	return &CLI{
		store: store,
		dp: &ingressIfColumnCLIDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
				"trust":      ingressIfColumnTrustZoneID,
				"untrust":    ingressIfColumnUntrustZoneID,
				"quarantine": ingressIfColumnEmptyZoneID,
			}},
			ifindex:     ifindex,
			vlanID:      vlanID,
			ingressZone: ingressZone,
		},
	}
}

// ingressIfColumnValues returns the `If:` value from every "In:" line of the
// captured output. Reading the In lines specifically keeps the Out line's own
// If: column from satisfying the assertion by accident.
func ingressIfColumnValues(t *testing.T, out string) []string {
	t.Helper()
	var got []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "In: ") {
			continue
		}
		idx := strings.Index(trimmed, "If: ")
		if idx < 0 {
			t.Fatalf("In line has no If: column: %q", trimmed)
		}
		rest := trimmed[idx+len("If: "):]
		if end := strings.Index(rest, ","); end >= 0 {
			rest = rest[:end]
		}
		got = append(got, rest)
	}
	return got
}

// TestShowFlowSessionIngressIfColumnUsesRecordedIdentity4983 is the
// fail-on-revert binding for the display column. Restoring
// `inIf := zoneIfaces[val.IngressZone]` at either print site makes the
// corresponding arm print the trust zone's FIRST interface and go RED.
func TestShowFlowSessionIngressIfColumnUsesRecordedIdentity4983(t *testing.T) {
	c := ingressIfColumnCLI(t)
	out := captureStdout(t, func() {
		if err := c.showFlowSession(nil); err != nil {
			t.Fatalf("showFlowSession: %v", err)
		}
	})

	got := ingressIfColumnValues(t, out)
	if len(got) != 2 {
		t.Fatalf("want one In line for each of the v4 and v6 sessions, got %d: %q\n%s",
			len(got), got, out)
	}
	for i, name := range got {
		if name != "lo.50" {
			t.Errorf("In-line If: column %d = %q, want %q: the column is still derived "+
				"from the ingress ZONE's first interface instead of the session's "+
				"recorded ingress identity, so it disagrees with the interface filter "+
				"that now selects on that identity (#4983)", i, name, "lo.50")
		}
	}
}

// TestShowFlowSessionEgressIfColumnUnchanged4983 is the over-reach guard. The
// EGRESS column's rule is untouched by this change: with no FIB result it
// still falls back to the egress zone's interface. It must stay GREEN under
// the revert that turns the ingress test RED — otherwise the "ingress" test is
// just observing that some interface name appears somewhere.
func TestShowFlowSessionEgressIfColumnUnchanged4983(t *testing.T) {
	c := ingressIfColumnCLI(t)
	out := captureStdout(t, func() {
		if err := c.showFlowSession(nil); err != nil {
			t.Fatalf("showFlowSession: %v", err)
		}
	})

	var outLines int
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Out: ") {
			continue
		}
		outLines++
		if !strings.Contains(trimmed, "If: ge-0/0/9.0,") {
			t.Errorf("Out-line If: column changed: %q — the egress resolver is "+
				"unchanged by #4983 and must still fall back to the egress zone's "+
				"interface when the session carries no FIB result", trimmed)
		}
	}
	if outLines != 2 {
		t.Fatalf("want one Out line for each of the v4 and v6 sessions, got %d\n%s", outLines, out)
	}
}

// TestShowFlowSessionIngressIfColumnFallsBackWhenIdentityUnusable4983 binds the
// FALLBACK arms of the ingress column resolver (`sessionIngressIf` in
// cli_show_flow.go), which the precise-arm test above cannot reach.
//
// Why it is needed: the two tests above both feed a session whose ingress
// identity is present AND nameable, so the resolver returns from its first
// arm every time. Replacing everything after that arm with `return ""` leaves
// the whole pkg/cli suite green — measured, not assumed. The fallback is not
// dead code being tidied around: it is the compat path for the three
// populations that legitimately carry no ingress identity (the reverse
// companion, a peer-synced session whose originating ifindex is node-local
// and deliberately not carried across the cluster wire, and the host-outbound
// GRE path, which has no ingress binding to record), plus the case of an
// identity the running config can no longer name. #6928: a "pre-#4983 helper"
// is NOT one of them — the shim ABI pre-flight hard-refuses a ValueSize
// mismatch against the live pin. If the column blanks for
// those, `show security flow session` prints rows with an empty If: field for
// every HA-synced flow.
//
// The three cases are the three distinct ways the resolver can be asked, and
// each has its own arm:
//
//	identity absent          -> zone's first interface
//	identity present, unnameable -> zone's first interface
//	zone binds no interfaces -> the zone NAME
//
// Note the deliberate contrast with the precise-arm test: these expect
// ge-0/0/8.0, the zone-derived answer, which is exactly the value the precise
// test asserts must NOT appear. One fixture cannot satisfy both, which is why
// the arms need separate tests rather than more assertions in one.
func TestShowFlowSessionIngressIfColumnFallsBackWhenIdentityUnusable4983(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ifindex uint32
		vlanID  uint16
		zone    uint16
		want    string
	}{
		{
			// The reverse companion / peer-synced / host-outbound-GRE
			// population, in a zone binding MORE THAN ONE interface
			// (ge-0/0/8.0 and lo.50). #6987: the column used to print the
			// FIRST of them as though it were the session's own interface.
			// With nothing to distinguish the members it names the zone.
			name: "absent identity in a multi-interface zone names the zone",
			zone: ingressIfColumnTrustZoneID,
			want: "trust",
		},
		{
			// A real binding the config cannot name any more: an interface
			// deleted since install, or a tunnel/fabric ingress with no unit.
			name:    "unnameable identity in a multi-interface zone names the zone",
			ifindex: 4242,
			zone:    ingressIfColumnTrustZoneID,
			want:    "trust",
		},
		{
			// The over-reach control for the two rows above: with a SINGLE
			// bound interface the zone approximation has exactly one answer,
			// so it is not an approximation and the column still prints it.
			// Without this row, blanking the column unconditionally would
			// pass — and that is the failure the #4983 message below names.
			name: "absent identity in a single-interface zone still names it",
			zone: ingressIfColumnUntrustZoneID,
			want: "ge-0/0/9.0",
		},
		{
			// Last resort: the zone exists but binds nothing, so there is no
			// interface name to fall back to and the column names the zone.
			name: "zone with no interfaces falls back to the zone name",
			zone: ingressIfColumnEmptyZoneID,
			want: "quarantine",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ingressIfColumnCLIWith(t, tc.ifindex, tc.vlanID, tc.zone)
			out := captureStdout(t, func() {
				if err := c.showFlowSession(nil); err != nil {
					t.Fatalf("showFlowSession: %v", err)
				}
			})

			got := ingressIfColumnValues(t, out)
			if len(got) != 2 {
				t.Fatalf("want one In line for each of the v4 and v6 sessions, got %d: %q\n%s",
					len(got), got, out)
			}
			for i, name := range got {
				if name != tc.want {
					t.Errorf("In-line If: column %d = %q, want %q — a session whose ingress "+
						"identity cannot be resolved must still print SOMETHING: the zone's "+
						"interface where the zone binds exactly one, otherwise the zone "+
						"itself. Blanking it hides the ingress column for every peer-synced "+
						"and reverse-direction flow (#4983); naming one member of a "+
						"multi-interface zone claims an interface the row cannot support "+
						"(#6987)", i, name, tc.want)
				}
			}
		})
	}
}

// ingressIfColumnCLIWithEgress is ingressIfColumnCLIWith plus a NAMEABLE FIB
// egress identity on the session, so the EGRESS arm of the interface filter
// has something precise to resolve. The two #6928 tests below need `lo` to
// exist for the same reason the precise ingress test does.
func ingressIfColumnCLIWithEgress(t *testing.T, ifindex uint32, vlanID, ingressZone uint16,
	fibIfindex uint32, fibVlanID uint16) *CLI {
	t.Helper()
	c := ingressIfColumnCLIWith(t, ifindex, vlanID, ingressZone)
	dp, ok := c.dp.(*ingressIfColumnCLIDP)
	if !ok {
		t.Fatalf("fixture dataplane is %T, want *ingressIfColumnCLIDP", c.dp)
	}
	dp.fibIfindex = fibIfindex
	dp.fibVlanID = fibVlanID
	return c
}

// loIfindex is the kernel ifindex of `lo`, the one netdev always present.
func loIfindex(t *testing.T) uint32 {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	return uint32(iface.Index)
}

// TestInterfaceFilterReachesRowViaEgressArm6928 falsifies, by construction, the
// claim that a session whose ingress zone binds NO interface cannot be selected
// by any interface filter.
//
// `matchesV4`/`matchesV6` reject only when BOTH arms miss —
// `!ifaceMatchesAny(inIfs) && !ifaceMatchesAny(outIfs)` (session_filter.go). So
// the ingress arm going empty removes one of two ways in, not the row. Here the
// session's ingress zone is `quarantine`, which binds nothing, AND its ingress
// identity is 0, so `resolveIngressIfaces` returns an empty slice — the exact
// state the retired sentence described as unreachable. It is selected anyway,
// through its nameable egress interface.
//
// RED-on-revert: change either arm of that condition to a conjunction over the
// ingress side alone (drop `&& !f.ifaceMatchesAny(outIfs)`) and this test loses
// both its In lines.
func TestInterfaceFilterReachesRowViaEgressArm6928(t *testing.T) {
	lo := loIfindex(t)
	// Ingress: zone `quarantine` (binds no interface) with NO identity stamped.
	// Egress: lo unit 80, which the config CAN name, so the egress arm is precise.
	c := ingressIfColumnCLIWithEgress(t, 0, 0, ingressIfColumnEmptyZoneID, lo, 80)

	out := captureStdout(t, func() {
		if err := c.showFlowSession([]string{"interface", "lo.80"}); err != nil {
			t.Fatalf("showFlowSession: %v", err)
		}
	})

	got := ingressIfColumnValues(t, out)
	if len(got) != 2 {
		t.Fatalf("`interface lo.80` selected %d of the 2 sessions (%q). A row whose ingress "+
			"zone binds NO interface and carries no ingress identity is still selectable "+
			"through the EGRESS arm of the filter; it is not unreachable (#6928)\n%s",
			len(got), got, out)
	}
	// And the control: an interface neither arm can name selects nothing, so the
	// assertion above is not merely observing that the filter is inert.
	outNone := captureStdout(t, func() {
		if err := c.showFlowSession([]string{"interface", "ge-0/0/8.0"}); err != nil {
			t.Fatalf("showFlowSession: %v", err)
		}
	})
	if none := ingressIfColumnValues(t, outNone); len(none) != 0 {
		t.Fatalf("`interface ge-0/0/8.0` must select neither session (its ingress zone binds "+
			"nothing and its egress is lo.80), got %d: %q\n%s", len(none), none, outNone)
	}
}

// TestInterfaceFilterEgressArmMakesColumnNameAnotherInterface6928 falsifies the
// claim that, for a NON-ZERO NAMEABLE ingress identity, the filter and the
// displayed interface name cannot disagree.
//
// The session arrives on `lo.50` and egresses on `lo.80` — two units of one NIC,
// separated only by the {ifindex, VLAN} pair, both nameable, neither a fallback.
// `interface lo.80` selects it through the EGRESS arm, and the In line prints
// `If: lo.50`, the interface it actually arrived on. Filter term and column
// differ, with no zero identity and no fallback anywhere in the derivation.
//
// This is not a defect: an operator naming an interface wants the flows crossing
// it in EITHER direction (cli_show_flow.go:307-315 derives exactly this), and the
// ingress column answers a different question from the filter's disjunction. What
// is bounded is narrower than "cannot disagree": when a row is selected BY ITS
// INGRESS ARM, the column names the interface that was typed, because both read
// the same stamped identity through the same {ifindex, VLAN} map. The second
// sub-test pins that narrower property so the pair distinguishes the two cases.
//
// RED-on-revert: restore `inIf := zoneIfaces[val.IngressZone]` at the print site
// and the ingress-selected sub-test goes red (the column prints ge-0/0/8.0, the
// zone's first interface, instead of the lo.50 that was filtered on).
func TestInterfaceFilterEgressArmMakesColumnNameAnotherInterface6928(t *testing.T) {
	lo := loIfindex(t)

	t.Run("selected via EGRESS: column names the ingress interface, not the filter term", func(t *testing.T) {
		c := ingressIfColumnCLIWithEgress(t, lo, 50, ingressIfColumnTrustZoneID, lo, 80)
		out := captureStdout(t, func() {
			if err := c.showFlowSession([]string{"interface", "lo.80"}); err != nil {
				t.Fatalf("showFlowSession: %v", err)
			}
		})
		got := ingressIfColumnValues(t, out)
		if len(got) != 2 {
			t.Fatalf("`interface lo.80` must select both sessions through the egress arm, "+
				"got %d: %q\n%s", len(got), got, out)
		}
		for i, name := range got {
			if name != "lo.50" {
				t.Errorf("In-line If: column %d = %q, want %q — the column reports the "+
					"interface the session ARRIVED on, which for an egress-arm match is "+
					"not the interface that was filtered on (#6928)", i, name, "lo.50")
			}
			if name == "lo.80" {
				t.Errorf("In-line If: column %d = %q: the ingress column must not be "+
					"rewritten to echo the filter term", i, name)
			}
		}
	})

	t.Run("selected via INGRESS: column names the filter term", func(t *testing.T) {
		c := ingressIfColumnCLIWithEgress(t, lo, 50, ingressIfColumnTrustZoneID, lo, 80)
		out := captureStdout(t, func() {
			if err := c.showFlowSession([]string{"interface", "lo.50"}); err != nil {
				t.Fatalf("showFlowSession: %v", err)
			}
		})
		got := ingressIfColumnValues(t, out)
		if len(got) != 2 {
			t.Fatalf("`interface lo.50` must select both sessions through the ingress arm, "+
				"got %d: %q\n%s", len(got), got, out)
		}
		for i, name := range got {
			if name != "lo.50" {
				t.Errorf("In-line If: column %d = %q, want %q — a row selected by its "+
					"INGRESS arm must print the interface that was filtered on: both read "+
					"the same stamped identity through the same map (#4983)", i, name, "lo.50")
			}
		}
	})
}

func TestShowFlowSessionReportsValidityUnknown10835(t *testing.T) {
	c := ingressIfColumnCLI(t)
	dp := c.dp.(*ingressIfColumnCLIDP)
	dp.v4State = dataplane.SessStateFINWait
	dp.v6State = dataplane.SessStateEstablished

	out := captureStdout(t, func() {
		if err := c.showFlowSession(nil); err != nil {
			t.Fatalf("showFlowSession: %v", err)
		}
	})

	const unknown = "Session State: Unknown (validity not tracked)"
	if got := strings.Count(out, unknown); got != 2 {
		t.Fatalf("v4/v6 session rows report validity %d times, want twice:\n%s", got, out)
	}
	if strings.Contains(out, "Session State: Valid") ||
		strings.Contains(out, "Session State: Established") ||
		strings.Contains(out, "Session State: FIN_WAIT") {
		t.Fatalf("session validity must be explicit and must not substitute TCP FSM state:\n%s", out)
	}
}
