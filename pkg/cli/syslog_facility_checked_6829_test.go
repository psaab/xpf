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
		got, _ := build(t, "authorization")
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
		if got, _ := build(t, "auth"); strings.Contains(got, "unmapped facility name") {
			t.Errorf("`auth` is mapped; a correct config must not warn. captured:\n%s", got)
		}
	})

	t.Run("wildcard any stays quiet", func(t *testing.T) {
		if got, _ := build(t, "any"); strings.Contains(got, "unmapped facility name") {
			t.Errorf("`any` names no facility on purpose, so warning about it is false — and "+
				"`host <ip> any <sev>` is the canonical Junos form. captured:\n%s", got)
		}
	})
}
