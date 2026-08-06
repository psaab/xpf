package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #6829 A2: the CLI commit mirror must report an unmappable facility, exactly
// as the daemon does.
//
// buildSyslogClients is documented as "Mirror the daemon exactly" (#5738) and
// runs live via reloadSyslog on an in-process commit. It was left on the
// unchecked logging.ParseFacility on the argument that the schema enum gates
// the name. That holds on the STRICT path only: configstore.Store downgrades
// the gate to a warning on Load (boot) and SyncApply (HA peer sync), which is
// the same reachability class the severity belt exists for. Untold, every
// record on the stream leaves under local0 while `show system syslog` still
// reports the authored name.
//
// The warning is the only observable difference for the checked-vs-unchecked
// CONVERSION itself — both forms return the same code, so no assertion on
// client.Facility can distinguish ParseFacility from ParseFacilityChecked.
//
// The test does BOTH, and the reason is a different property. Since #6829 the
// site has a compute/assign split (classify above the client construction,
// assign below it), and dropping the ASSIGN half is invisible to a log
// assertion — the warning still fires while nothing is installed. So the log
// capture binds the conversion and the client inspection binds the assignment.
// An earlier revision of this comment said the test captures the log RATHER
// THAN inspecting the client; that stopped being true when the inspection was
// added below.
//
// The warn uses slog.Warn rather than the fmt.Fprintf(os.Stderr) form its two
// sibling warnings in buildSyslogClients use. That is deliberate: this function
// is documented to mirror the daemon, the daemon site uses slog.Warn, and
// slog.Warn is already the established form elsewhere in pkg/cli (peer.go,
// session_filter.go). Matching the daemon was judged more important than
// matching the two lines above it.
//
// RED-on-revert: put the site back on logging.ParseFacility (or drop the
// !known warn) and the unmapped subtest goes silent.
func TestBuildSyslogClientsWarnsOnUnmappedFacility_6829(t *testing.T) {
	build := func(t *testing.T, facility string) (string, []*logging.SyslogClient) {
		t.Helper()
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		t.Cleanup(func() { slog.SetDefault(prev) })

		cfg := &config.Config{}
		cfg.Security.Log.Streams = map[string]*config.SyslogStream{
			"audit": {
				Name: "audit", Host: "192.0.2.10", Port: 514,
				Facility: facility, Severity: "info",
			},
		}
		// Call FIRST, then read the buffer: `return buf.String(), build(...)`
		// evaluates the buffer before the call and always captures "".
		clients := buildSyslogClients(cfg)
		return buf.String(), clients
	}

	t.Run("unmapped facility warns", func(t *testing.T) {
		got, clients := build(t, "authorization")
		// #6829 round 8: count asserted with Fatalf rather than folded into the
		// value check — `len(clients) == 1 && ...` evaporates when nothing is
		// installed, so a regression to ZERO passed silently.
		//
		// The VALUE is deliberately not treated as discriminating here:
		// FacilityLocal0 is the constructor default, so on an unmapped facility
		// "the substitution ran" and "nothing ran" are the same number. The
		// discriminating coverage is the mapped subtest and the two-stream
		// subtest below.
		if len(clients) != 1 {
			t.Fatalf("want exactly one installed client, got %d — forwarding is deliberately "+
				"NOT withheld for an unmappable facility, so a regression to zero clients is "+
				"a behaviour change this subtest must catch", len(clients))
		}
		if clients[0].Facility != logging.FacilityLocal0 {
			t.Errorf("installed client Facility = %d, want FacilityLocal0 (%d) — the warning "+
				"promises records leave under local0, so that must be what is installed",
				clients[0].Facility, logging.FacilityLocal0)
		}
		if !strings.Contains(got, "unmapped facility name") {
			t.Errorf("the CLI commit mirror silently mapped an unmappable facility to local0 "+
				"with no warning, while the daemon warns for the same config — the two "+
				"paths are documented to mirror each other (#5738/#6829). captured:\n%s", got)
		}
		if !strings.Contains(got, "authorization") {
			t.Errorf("the warning must name the unmapped facility. captured:\n%s", got)
		}
	})

	// #6829 round 8: the ordering property, mirroring the daemon site. Before
	// the compute/assign split the classify block sat BELOW the `client == nil`
	// continue, so a stream whose host does not resolve was skipped and the
	// operator never learned the facility was also unmappable. RED-on-revert:
	// move the classify block back below the continue and this goes silent.
	t.Run("warns even when client construction fails", func(t *testing.T) {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		t.Cleanup(func() { slog.SetDefault(prev) })

		cfg := &config.Config{}
		cfg.Security.Log.Streams = map[string]*config.SyslogStream{
			"audit": {
				Name: "audit", Host: "no-such-host.invalid.", Port: 514,
				Facility: "authorization", Severity: "info",
			},
		}
		clients := buildSyslogClients(cfg)

		if len(clients) != 0 {
			t.Fatalf("premise broken: this fixture must FAIL construction so the ordering "+
				"is what is under test; got %d clients", len(clients))
		}
		if got := buf.String(); !strings.Contains(got, "unmapped facility name") {
			t.Errorf("construction failed and the stream was skipped, so the operator was "+
				"never told the facility is ALSO unmappable (#6829). captured:\n%s", got)
		}
	})

	// The value assertion that CAN fail: two streams, one unmappable and one
	// mapped to a non-default facility. Dropping the assign half leaves BOTH on
	// the constructor default, which the single-stream unmapped cell cannot see.
	t.Run("unmapped and mapped streams get different facilities", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.Log.Streams = map[string]*config.SyslogStream{
			"unmappable": {Name: "unmappable", Host: "192.0.2.10", Port: 514,
				Facility: "authorization", Severity: "info"},
			"mapped": {Name: "mapped", Host: "192.0.2.11", Port: 514,
				Facility: "auth", Severity: "info"},
		}
		clients := buildSyslogClients(cfg)
		if len(clients) != 2 {
			t.Fatalf("want two installed clients, got %d", len(clients))
		}
		seen := map[int]bool{}
		for _, c := range clients {
			seen[c.Facility] = true
		}
		if !seen[logging.FacilityLocal0] || !seen[logging.FacilityAuth] {
			t.Errorf("installed facilities = %v, want both FacilityLocal0 (%d) and "+
				"FacilityAuth (%d). Both on local0 means the assign half was dropped",
				seen, logging.FacilityLocal0, logging.FacilityAuth)
		}
	})

	t.Run("mapped facility stays quiet", func(t *testing.T) {
		got, clients := build(t, "auth")
		if strings.Contains(got, "unmapped facility name") {
			t.Errorf("`auth` is mapped; a correct config must not warn. captured:\n%s", got)
		}
		// #6829 F2: bind the VALUE, not just the warning. This site has the same
		// compute-then-assign shape as the daemon's, so dropping either half is
		// invisible to a log assertion.
		if len(clients) != 1 {
			t.Fatalf("want one installed client, got %d", len(clients))
		}
		if clients[0].Facility != logging.FacilityAuth {
			t.Errorf("installed client Facility = %d, want FacilityAuth (%d) — the authored "+
				"facility must survive the compute/assign split",
				clients[0].Facility, logging.FacilityAuth)
		}
	})

	t.Run("wildcard any stays quiet", func(t *testing.T) {
		if got, _ := build(t, "any"); strings.Contains(got, "unmapped facility name") {
			t.Errorf("`any` names no facility on purpose, so warning about it is false — and "+
				"`host <ip> any <sev>` is the canonical Junos form. captured:\n%s", got)
		}
	})
}
