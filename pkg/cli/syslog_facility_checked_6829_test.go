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
// The warning is the ONLY observable difference: both forms return the same
// code, so an assertion on client.Facility cannot bind this conversion. That is
// why this test captures the log rather than inspecting the client.
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
		if len(clients) == 1 && clients[0].Facility != logging.FacilityLocal0 {
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
