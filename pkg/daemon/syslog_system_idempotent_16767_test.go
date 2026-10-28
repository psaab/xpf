package daemon

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #16767: system syslog idempotence.
//
// applySystemSyslog rebuilt every system syslog host client on every
// apply and every retry tick: no fingerprint, no per-host reuse, and
// SetClients closed every old client — including a healthy one whose
// collector hostname stopped resolving under a DNS outage. These cells
// drive the REAL applySystemSyslog with the client constructor
// redirected through newSystemSyslogClientFn (the syslogWarmFn
// pattern), counting dials and failing hosts on cue.
//
// RED-on-revert (measured): pointing applySystemSyslog's constructor
// back at logging.NewSyslogClientWithSource leaves every dial count
// and failure injection dead, so cells 1-3 fail. Stubbing only the
// gate (hash never set) leaves cell 1 failing (apply #2 dials).
// Removing per-host reuse leaves cells 2-3 failing.

// systemSyslogFake16767 counts constructor calls and fails a
// configurable subset of hosts, so a test can inject DNS loss per host
// mid-sequence.
type systemSyslogFake16767 struct {
	dials atomic.Int32
	fail  atomic.Value // map[string]bool
}

func (f *systemSyslogFake16767) setFail(m map[string]bool) { f.fail.Store(m) }

func (f *systemSyslogFake16767) construct(host string, port int, sourceAddr string) (*logging.SyslogClient, error) {
	f.dials.Add(1)
	if m, ok := f.fail.Load().(map[string]bool); ok && m[host] {
		return nil, errors.New("dial udp: lookup " + host + ": no such host (injected #16767)")
	}
	// Build a real loopback client so handler install/close semantics
	// are genuine, on the stanza's port when loopback-bindable. The
	// stanza host is a hostname or TEST-NET literal on purpose: the
	// daemon's dial target is what varies, never this fixture's socket.
	return logging.NewSyslogClientTransport("127.0.0.1", port, sourceAddr, "udp", nil)
}

func withSystemSyslogFake16767(t *testing.T) *systemSyslogFake16767 {
	t.Helper()
	f := &systemSyslogFake16767{}
	f.setFail(nil)
	prev := newSystemSyslogClientFn
	newSystemSyslogClientFn = f.construct
	t.Cleanup(func() { newSystemSyslogClientFn = prev })
	return f
}

func newSystemSyslogDaemon16767(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))}
	t.Cleanup(func() { d.slogHandler.SetClients(nil) })
	return d
}

func systemSyslogCfg16767(hosts ...*config.SyslogHostConfig) *config.Config {
	cfg := &config.Config{}
	cfg.System.Syslog = &config.SystemSyslogConfig{Hosts: hosts}
	return cfg
}

func udpSink16767(t *testing.T) (int, *net.UDPConn) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve sink: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen sink: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port, conn
}

func TestSystemSyslogUnchangedApplyZeroDials16767(t *testing.T) {
	fake := withSystemSyslogFake16767(t)
	d := newSystemSyslogDaemon16767(t)
	cfg := systemSyslogCfg16767(
		&config.SyslogHostConfig{Address: "collector-a.example", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
		&config.SyslogHostConfig{Address: "192.0.2.20", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
	)

	d.applySystemSyslog(cfg)
	if got := fake.dials.Load(); got != 2 {
		t.Fatalf("NON-VACUITY: first apply must dial both hosts, got %d", got)
	}
	first := d.slogHandler.Clients()
	if len(first) != 2 {
		t.Fatalf("first apply installed %d clients, want 2", len(first))
	}

	d.applySystemSyslog(cfg)
	if got := fake.dials.Load(); got != 2 {
		t.Fatalf("#16767: unchanged second apply dialed (dials=%d, want still 2) — "+
			"zero dials for an unchanged stanza is acceptance 1 (#9326 AC1 twin)", got)
	}
	second := d.slogHandler.Clients()
	if len(second) != 2 || second[0] != first[0] || second[1] != first[1] {
		t.Fatalf("#16767: unchanged apply replaced clients: %v -> %v", first, second)
	}

	// Control: a changed stanza must dial — a gate that never rebuilds
	// would pass the cell above and pin the daemon to its first config.
	changed := systemSyslogCfg16767(
		&config.SyslogHostConfig{Address: "collector-a.example", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
		&config.SyslogHostConfig{Address: "192.0.2.21", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
	)
	d.applySystemSyslog(changed)
	if got := fake.dials.Load(); got != 3 {
		t.Fatalf("CONTROL: changed stanza must dial the changed host (dials=%d, want 3)", got)
	}
}

func TestSystemSyslogPartialFailurePreservesHealthy16767(t *testing.T) {
	fake := withSystemSyslogFake16767(t)
	d := newSystemSyslogDaemon16767(t)
	good := &config.SyslogHostConfig{Address: "good.example", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}}
	bad := &config.SyslogHostConfig{Address: "bad.example", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}}
	cfg := systemSyslogCfg16767(good, bad)

	// Both fail-open at first? No: only bad fails — healthy installs.
	fake.setFail(map[string]bool{"bad.example": true})
	d.applySystemSyslog(cfg)
	first := d.slogHandler.Clients()
	if len(first) != 1 {
		t.Fatalf("premise: partial build must install the healthy host only, got %d", len(first))
	}
	if !d.systemSyslogRetryOwed() {
		t.Fatal("premise: partial build must arm system retry debt")
	}
	healthy := first[0]

	// Retry tick (same cfg): healthy pointer must survive, bad retried.
	before := fake.dials.Load()
	d.applySystemSyslog(cfg)
	second := d.slogHandler.Clients()
	if len(second) != 1 || second[0] != healthy {
		t.Fatalf("#16767: retry replaced the healthy client: %v -> %v (want same pointer)", first, second)
	}
	if got := fake.dials.Load(); got != before+1 {
		t.Fatalf("#16767: retry must dial only the unbuilt host (dials %d -> %d, want +1)", before, got)
	}
	if !d.systemSyslogRetryOwed() {
		t.Fatal("retry with bad still failing must remain owed")
	}
	if err := healthy.Send(6, "still-alive-after-retry"); err != nil {
		t.Fatalf("#16767: healthy client must still send after the retry tick (closed by the swap?): %v", err)
	}

	// Bad recovers: installs beside the preserved healthy client.
	fake.setFail(nil)
	d.applySystemSyslog(cfg)
	third := d.slogHandler.Clients()
	if len(third) != 2 {
		t.Fatalf("recovery apply installed %d, want 2", len(third))
	}
	found := false
	for _, c := range third {
		if c == healthy {
			found = true
		}
	}
	if !found {
		t.Fatal("#16767: healthy client must survive the recovery apply too")
	}
	if d.systemSyslogRetryOwed() {
		t.Fatal("full build must discharge system retry debt")
	}
	if !d.systemSyslogHashSet {
		t.Fatal("full build must latch the system fingerprint")
	}

	// Fourth apply after latch: zero new dials.
	before = fake.dials.Load()
	d.applySystemSyslog(cfg)
	if got := fake.dials.Load(); got != before {
		t.Fatalf("#16767: latched identical apply dialed (dials %d -> %d)", before, got)
	}
}

func TestSystemSyslogDNSLossKeepsWorkingClient16767(t *testing.T) {
	fake := withSystemSyslogFake16767(t)
	d := newSystemSyslogDaemon16767(t)
	port, sink := udpSink16767(t)

	cfg := systemSyslogCfg16767(&config.SyslogHostConfig{
		Address: "collector.example", Port: port,
		Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}},
	})
	d.applySystemSyslog(cfg)
	first := d.slogHandler.Clients()
	if len(first) != 1 {
		t.Fatalf("premise: first apply must install 1 client, got %d", len(first))
	}
	if err := first[0].Send(6, "before-dns-loss"); err != nil {
		t.Fatalf("premise: send before DNS loss: %v", err)
	}
	buf := make([]byte, 2048)
	_ = sink.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := sink.ReadFromUDP(buf); err != nil {
		t.Fatalf("premise: record before DNS loss must arrive: %v", err)
	}

	// DNS loss: construct now fails for this host. An unrelated commit
	// (same stanza) must keep the working client installed.
	fake.setFail(map[string]bool{"collector.example": true})
	d.applySystemSyslog(cfg)
	second := d.slogHandler.Clients()
	if len(second) != 1 || second[0] != first[0] {
		t.Fatalf("#16767 same-client: DNS-loss apply closed or replaced the working client: %v -> %v", first, second)
	}
	if d.systemSyslogRetryOwed() {
		t.Fatal("unchanged stanza under DNS loss must not arm retry debt — nothing was rebuilt")
	}
	if err := second[0].Send(6, "during-dns-loss"); err != nil {
		t.Fatalf("#16767: working client must still send during DNS loss: %v", err)
	}
	_ = sink.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := sink.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("#16767 received-during: no record arrived during DNS loss: %v", err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "during-dns-loss") {
		t.Fatalf("received record %q does not carry the during-loss message", got)
	}
}

func TestSystemSyslogPerHostFingerprintRebuildsOnlyChanged16767(t *testing.T) {
	fake := withSystemSyslogFake16767(t)
	d := newSystemSyslogDaemon16767(t)
	a := func(sev string) *config.SyslogHostConfig {
		return &config.SyslogHostConfig{Address: "a.example", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: sev}}}
	}
	b := func() *config.SyslogHostConfig {
		return &config.SyslogHostConfig{Address: "b.example", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}}
	}

	d.applySystemSyslog(systemSyslogCfg16767(a("info"), b()))
	if got := fake.dials.Load(); got != 2 {
		t.Fatalf("premise: first apply dials=%d want 2", got)
	}
	first := d.slogHandler.Clients()

	// Change ONLY host A's severity: B must not re-dial, A must.
	d.applySystemSyslog(systemSyslogCfg16767(a("warning"), b()))
	if got := fake.dials.Load(); got != 3 {
		t.Fatalf("#16767 per-host: severity change on A dialed total=%d, want 3 (only A)", got)
	}
	second := d.slogHandler.Clients()
	if len(second) != 2 {
		t.Fatalf("installed %d, want 2", len(second))
	}
	// B pointer preserved; A necessarily new (different threshold).
	if second[1] != first[1] {
		t.Fatal("#16767 per-host: unchanged host B was rebuilt on A's severity change")
	}
	if second[0] == first[0] {
		t.Fatal("per-host control: changed host A must be a fresh client")
	}
	if err := second[1].Send(6, "b-still-alive"); err != nil {
		t.Fatalf("#16767: unchanged host B must still send after A's rebuild: %v", err)
	}
	if err := second[0].Send(3, "a-warning-threshold"); err != nil {
		t.Fatalf("#16767: changed host A (warning) must forward warning+ records: %v", err)
	}

	// Edge: duplicate identical hosts collapse to one installed client.
	d.applySystemSyslog(systemSyslogCfg16767(b(), b()))
	if got := len(d.slogHandler.Clients()); got != 1 {
		t.Fatalf("duplicate hosts installed %d clients, want 1", got)
	}
	d.applySystemSyslog(systemSyslogCfg16767(b()))
	if got := len(d.slogHandler.Clients()); got != 1 {
		t.Fatalf("deduped config installed %d clients, want 1", got)
	}
	if d.systemSyslogRetryOwed() {
		t.Fatal("deduped config must not arm debt")
	}
}

// #17828: successful A -> failed B at the same endpoint -> revert A must
// not resurrect the closed A client. The failed-B apply retires A via the
// preserving install; the cache must evict that retired entry before any
// revert reuses it. Control: unchanged A apply after the revert is
// zero-dial again.
func TestApplySystemSyslogFailedChangeThenRevertDoesNotReuseClosedClient(t *testing.T) {
	fake := withSystemSyslogFake16767(t)
	d := newSystemSyslogDaemon16767(t)
	host := func(sev string) *config.SyslogHostConfig {
		return &config.SyslogHostConfig{Address: "collector.example", Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: sev}}}
	}
	cfgA := systemSyslogCfg16767(host("info"))
	cfgB := systemSyslogCfg16767(host("warning"))

	// A succeeds: one dial, one installed client, latched, no debt.
	d.applySystemSyslog(cfgA)
	if got := fake.dials.Load(); got != 1 {
		t.Fatalf("premise: first apply dials=%d want 1", got)
	}
	first := d.slogHandler.Clients()
	if len(first) != 1 {
		t.Fatalf("premise: first apply installed %d, want 1", len(first))
	}
	if d.systemSyslogRetryOwed() {
		t.Fatal("premise: successful A apply must not arm retry debt")
	}

	// B (same endpoint, severity change) fails to construct. The install
	// retires/closes A and the apply arms retry debt.
	fake.setFail(map[string]bool{"collector.example": true})
	d.applySystemSyslog(cfgB)
	if got := fake.dials.Load(); got != 2 {
		t.Fatalf("premise: failed B apply dials=%d want 2", got)
	}
	if got := len(d.slogHandler.Clients()); got != 0 {
		t.Fatalf("premise: failed B apply installed %d, want 0 (A retired)", got)
	}
	if !d.systemSyslogRetryOwed() {
		t.Fatal("premise: failed B apply must arm retry debt")
	}
	if err := first[0].Send(6, "after-failed-change"); err == nil {
		t.Fatal("premise: retired A client must be closed by the failed-B install")
	}

	// Revert to A with the constructor healthy again: the closed A
	// pointer must not be served from the cache.
	fake.setFail(nil)
	d.applySystemSyslog(cfgA)
	if got := fake.dials.Load(); got != 3 {
		t.Fatalf("#17828: revert to A must re-dial the retired endpoint (dials=%d, want 3); a cache hit here resurrects a closed client", got)
	}
	reverted := d.slogHandler.Clients()
	if len(reverted) != 1 {
		t.Fatalf("revert installed %d, want 1", len(reverted))
	}
	if reverted[0] == first[0] {
		t.Fatal("#17828: revert reused the closed A client pointer")
	}
	if d.systemSyslogRetryOwed() {
		t.Fatal("successful revert must discharge retry debt")
	}
	if err := reverted[0].Send(6, "after-revert"); err != nil {
		t.Fatalf("#17828: reverted client must send: %v", err)
	}

	// Control: unchanged A apply after the revert is zero-dial.
	d.applySystemSyslog(cfgA)
	if got := fake.dials.Load(); got != 3 {
		t.Fatalf("control: unchanged apply after revert dialed (dials=%d, want still 3)", got)
	}
}

// If an external SetClients call retires a cached system client, the next
// apply must not recover that closed pointer from the daemon's per-host
// cache. This is the cache-identity drift control for #17828.
func TestApplySystemSyslogDoesNotReuseExternallyRetiredClient(t *testing.T) {
	fake := withSystemSyslogFake16767(t)
	d := newSystemSyslogDaemon16767(t)
	cfg := systemSyslogCfg16767(&config.SyslogHostConfig{
		Address:    "collector.example",
		Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}},
	})

	d.applySystemSyslog(cfg)
	if got := fake.dials.Load(); got != 1 {
		t.Fatalf("premise: first apply dials=%d want 1", got)
	}
	first := d.slogHandler.Clients()
	if len(first) != 1 {
		t.Fatalf("premise: first apply installed %d, want 1", len(first))
	}

	// A foreign handler swap retires and closes the client's identity while
	// leaving the daemon's per-host cache untouched.
	d.slogHandler.SetClients(nil)
	if err := first[0].Send(6, "after-external-retirement"); err == nil {
		t.Fatal("premise: foreign SetClients(nil) must close the old client")
	}

	d.applySystemSyslog(cfg)
	if got := fake.dials.Load(); got != 2 {
		t.Fatalf("#17828: apply after external retirement must redial (dials=%d, want 2)", got)
	}
	reinstalled := d.slogHandler.Clients()
	if len(reinstalled) != 1 {
		t.Fatalf("apply after external retirement installed %d, want 1", len(reinstalled))
	}
	if reinstalled[0] == first[0] {
		t.Fatal("#17828: apply reused the externally retired client")
	}
	if err := reinstalled[0].Send(6, "after-rebuild"); err != nil {
		t.Fatalf("#17828: rebuilt client must send: %v", err)
	}

	// Control: the rebuilt identical configuration is again zero-dial.
	d.applySystemSyslog(cfg)
	if got := fake.dials.Load(); got != 2 {
		t.Fatalf("control: unchanged apply after rebuild dialed (dials=%d, want still 2)", got)
	}
}

// #17828: SetClients closes every former client, including pointers included
// in the replacement slice. The closed cache entry must defeat the
// single-host fingerprint gate and be redialed on the unchanged apply.
func TestApplySystemSyslogSameIdentitySetClientsRedialsClosedClient17828(t *testing.T) {
	fake := withSystemSyslogFake16767(t)
	d := newSystemSyslogDaemon16767(t)
	port, sink := udpSink16767(t)
	cfg := systemSyslogCfg16767(&config.SyslogHostConfig{
		Address: "collector.example", Port: port,
		Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}},
	})

	d.applySystemSyslog(cfg)
	first := d.slogHandler.Clients()
	if len(first) != 1 || fake.dials.Load() != 1 {
		t.Fatalf("premise: installed %d clients after %d dials, want 1", len(first), fake.dials.Load())
	}

	d.slogHandler.SetClients(d.slogHandler.Clients())
	if !first[0].Closed() {
		t.Fatal("premise: SetClients(Clients()) must close the reinstalled client")
	}

	d.applySystemSyslog(cfg)
	current := d.slogHandler.Clients()
	if got := fake.dials.Load(); got != 2 {
		t.Fatalf("#17828: unchanged apply after same-identity SetClients must redial (dials=%d, want 2)", got)
	}
	if len(current) != 1 || current[0] == first[0] || current[0].Closed() {
		t.Fatalf("#17828: unchanged apply did not install a fresh live client: %v", current)
	}
	if err := current[0].Send(6, "after-same-identity-setclients"); err != nil {
		t.Fatalf("#17828: rebuilt client send failed: %v", err)
	}
	buf := make([]byte, 2048)
	_ = sink.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := sink.ReadFromUDP(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "after-same-identity-setclients") {
		t.Fatalf("#17828: rebuilt client did not deliver a record: n=%d err=%v data=%q", n, err, buf[:n])
	}
}

// #17828: reordered same-identity clients are still terminally closed by
// SetClients. The reordered handler list must not make the unchanged
// configuration reuse those closed per-host cache pointers.
func TestApplySystemSyslogReorderedSetClientsRedialsClosedClients17828(t *testing.T) {
	fake := withSystemSyslogFake16767(t)
	d := newSystemSyslogDaemon16767(t)
	portA, sinkA := udpSink16767(t)
	portB, sinkB := udpSink16767(t)
	cfg := systemSyslogCfg16767(
		&config.SyslogHostConfig{Address: "a.example", Port: portA, Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
		&config.SyslogHostConfig{Address: "b.example", Port: portB, Facilities: []config.SyslogFacility{{Facility: "daemon", Severity: "info"}}},
	)

	d.applySystemSyslog(cfg)
	first := d.slogHandler.Clients()
	if len(first) != 2 || fake.dials.Load() != 2 {
		t.Fatalf("premise: installed %d clients after %d dials, want 2", len(first), fake.dials.Load())
	}

	d.slogHandler.SetClients([]*logging.SyslogClient{first[1], first[0]})
	if !first[0].Closed() || !first[1].Closed() {
		t.Fatal("premise: reordered SetClients must close both former clients")
	}

	d.applySystemSyslog(cfg)
	current := d.slogHandler.Clients()
	if got := fake.dials.Load(); got != 4 {
		t.Fatalf("#17828: unchanged apply after reordered SetClients must redial both clients (dials=%d, want 4)", got)
	}
	if len(current) != 2 || current[0] == first[0] || current[1] == first[1] ||
		current[0].Closed() || current[1].Closed() {
		t.Fatalf("#17828: unchanged apply did not install fresh live clients: %v", current)
	}
	for i, client := range current {
		message := []string{"after-reordered-setclients-a", "after-reordered-setclients-b"}[i]
		if err := client.Send(6, message); err != nil {
			t.Fatalf("#17828: rebuilt client %d send failed: %v", i, err)
		}
	}
	for _, tc := range []struct {
		name string
		sink *net.UDPConn
		want string
	}{
		{name: "a", sink: sinkA, want: "after-reordered-setclients-a"},
		{name: "b", sink: sinkB, want: "after-reordered-setclients-b"},
	} {
		buf := make([]byte, 2048)
		_ = tc.sink.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := tc.sink.ReadFromUDP(buf)
		if err != nil || !strings.Contains(string(buf[:n]), tc.want) {
			t.Fatalf("#17828: rebuilt client %s did not deliver a record: n=%d err=%v data=%q", tc.name, n, err, buf[:n])
		}
	}
}
