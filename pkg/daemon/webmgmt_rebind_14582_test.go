package daemon

// webmgmt_rebind_14582_test.go — #14582.
//
// The web-management interface bind was resolved once, early in
// applyConfigLocked (deliberately, for credential revocation), before
// networkd applied the interface addresses later in the same apply — and
// never re-resolved. A commit that created the interface address and the
// `web-management https interface` stanza together, or a lifeline DHCP
// lease change to a new address, left HTTPS bound to the loopback fallback
// (or the stale lease address) while `show system services` reported it
// Listening: off-box REST/J-Web silently down on a box reported healthy.
//
// Three pieces, each with its own cell:
//
//  1. Same-commit convergence: the post-networkd re-reconcile in
//     applyConfigLocked re-resolves once the address exists.
//  2. Lease-change convergence: the DHCP management-only fast path
//     re-resolves the bound interface (gated, serialized — the #2884 shape).
//  3. Honest state: a leg on the loopback fallback reports Stale (not
//     Listening), which is the same state the 30s re-assert owner keys on,
//     so it re-drives until the address lands — and a healthy leg is never
//     bounced by a tick.
//
// FAIL-ON-REVERT: reverting any piece reds its cell — drop the degraded
// reporting and (1)/(2) stay bound to loopback while reporting Listening;
// drop the re-assert gate on degraded and nothing re-drives; drop the
import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/sysservices"
)

// webMgmtKernelAddrs is the mutable kernel-address seam for #14582 cells:
// the test rewrites the address set to model networkd applying (or a DHCP
// lease replacing) the interface address after the early reconcile ran.
type webMgmtKernelAddrs struct {
	addrs atomic.Value // []net.Addr
}

func newWebMgmtKernelAddrs() *webMgmtKernelAddrs {
	k := &webMgmtKernelAddrs{}
	k.addrs.Store([]net.Addr{})
	return k
}

func (k *webMgmtKernelAddrs) set(addrs ...net.Addr) {
	if addrs == nil {
		addrs = []net.Addr{}
	}
	k.addrs.Store(addrs)
}

func (k *webMgmtKernelAddrs) install(t *testing.T) {
	t.Helper()
	prev := interfaceAddrsByName
	t.Cleanup(func() { interfaceAddrsByName = prev })
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		if kernelName == "ge-0-0-0" || kernelName == "fxp0" {
			return k.addrs.Load().([]net.Addr), nil
		}
		return nil, fmt.Errorf("no such kernel interface: %s", kernelName)
	}
}

func ip4Addr(s string) *net.IPNet {
	return &net.IPNet{IP: net.ParseIP(s), Mask: net.CIDRMask(24, 32)}
}

// httpsBoundAddr14582 returns the HTTPS leg's bound address as the
// effective-listener snapshot reports it. The fake listener's Addr() is
// a fixed loopback (fakeLn), so the socket's real bind address is read
// from the reconciler's converged fingerprint instead — the address the
// leg was actually bound to — while State still comes from the snapshot.
func httpsBoundAddr14582(m *managementReconciler) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur.httpsAddr
}

// bootWebMgmt14582 commits cfgText through a real store and boots a live
// management reconciler over the fake listener registry, with the kernel
// seam installed. The reconciler's TLS cert dir is redirected so generated
// certs never touch /etc/xpf.
func bootWebMgmt14582(t *testing.T, k *webMgmtKernelAddrs, cfgText string) (*Daemon, *managementReconciler, *configstore.Store, *fakeReg) {
	t.Helper()
	k.install(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	mgmtAuthCommit(t, store, cfgText)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: store}
	reg := newFakeReg()
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.mgmt.Store(m)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.start(ctx); err != nil {
		t.Fatalf("mgmt start: %v", err)
	}
	m.mu.Lock()
	srv := m.srv
	m.mu.Unlock()
	if srv == nil {
		t.Fatal("management server was not constructed; every assertion would be vacuous")
	}
	srv.SetTLSCertDirForTest(t.TempDir())
	return d, m, store, reg
}

const webMgmt14582Secret = "rebind-secret-14582"

// TestWebMgmtRebindsWhenInterfaceAddressAppears14582 is the decisive
// acceptance cell (z4): the interface address appears only AFTER the early
// reconcile resolved the bind (networkd timing). The leg must report a
// non-Listening state, the re-assert owner must see it down, and a tick
// must rebind it onto the interface address — with no further commit.
//
// Controls: before the address appears the leg is Stale/down; a further
// tick on the now-healthy leg must not bounce it.
func TestWebMgmtRebindsWhenInterfaceAddressAppears14582(t *testing.T) {
	k := newWebMgmtKernelAddrs() // kernel: no address yet
	d, m, store, reg := bootWebMgmt14582(t, k, mgmtAuthConfigFor("ge-0/0/0", webMgmt14582Secret))

	// The early (pre-networkd) reconcile: credential revocation placement.
	// The address does not exist yet, so this lands on the loopback fallback.
	if err := d.reconcileWebManagement(store.ActiveConfig()); err != nil {
		t.Fatalf("early reconcile: %v", err)
	}
	if got := m.effectiveHTTPSListener(); got.State == sysservices.StateListening {
		t.Fatalf("a loopback-fallback leg reported Listening (%+v); the operator "+
			"sees a healthy management plane that is unreachable off-box (#14582)", got)
	}
	if got := d.effectiveListeners().HTTPS; got.State != sysservices.StateStale {
		t.Fatalf("loopback-fallback leg state = %v, want Stale (non-Listening): %+v", got.State, got)
	}
	if !d.mgmtListenerDown() {
		t.Fatal("the re-assert gate did not see the degraded leg down; nothing " +
			"would ever re-drive it, so the fallback bind is permanent (#14582)")
	}

	// networkd applies the address (same commit, later; or the address
	// simply arrives). No commit follows — the 30s owner must converge it.
	k.set(ip4Addr("10.0.0.1"))
	d.reassertMgmtListenersOnce(context.Background())

	if got := m.effectiveHTTPSListener(); got.State != sysservices.StateListening || httpsBoundAddr14582(m) != "10.0.0.1:443" {
		t.Fatalf("after the address appeared and one re-assert tick: %+v, "+
			"want Listening at 10.0.0.1:443 — HTTPS stayed on the stale "+
			"loopback fallback (#14582)", got)
	}
	if ln := reg.get("10.0.0.1:443"); ln == nil || !ln.isOpen() {
		t.Fatal("no live listener at the interface address after the rebind")
	}
	if d.mgmtListenerDown() {
		t.Fatal("a converged leg still reported down; the owner would rebind it every tick")
	}

	// Paired control: a tick on the healthy leg must not bounce it.
	before := reg.get("10.0.0.1:443")
	d.reassertMgmtListenersOnce(context.Background())
	if after := reg.get("10.0.0.1:443"); after != before || !after.isOpen() {
		t.Fatal("a re-assert tick bounced a healthy, converged management leg")
	}
}

// TestWebMgmtRebindsOnAddressReplacement14582 covers the vanished-address
// direction: a converged leg whose interface address is replaced (lease
// renew to a new address) must rebind to the NEW address, not keep serving
// (and reporting) the old one.
func TestWebMgmtRebindsOnAddressReplacement14582(t *testing.T) {
	k := newWebMgmtKernelAddrs()
	k.set(ip4Addr("10.0.0.1"))
	d, m, store, reg := bootWebMgmt14582(t, k, mgmtAuthConfigFor("ge-0/0/0", webMgmt14582Secret))

	if err := d.reconcileWebManagement(store.ActiveConfig()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := m.effectiveHTTPSListener(); got.State != sysservices.StateListening || httpsBoundAddr14582(m) != "10.0.0.1:443" {
		t.Fatalf("setup: want Listening at 10.0.0.1:443, got %+v", got)
	}

	// The lease moves to a new address; the old one vanishes. The leg is
	// still bound to (and still serving) the old address — which the kernel
	// no longer has — so it must report a NON-Listening (stale) state, and
	// that same state is what the re-assert owner keys on.
	k.set(ip4Addr("10.0.0.9"))
	if got := d.effectiveListeners().HTTPS; got.State != sysservices.StateStale {
		t.Fatalf("a leg bound to a vanished interface address reported %v, "+
			"want Stale — off-box callers get RST while the box claims "+
			"Listening (#14582): %+v", got.State, got)
	}
	if !d.mgmtListenerDown() {
		t.Fatal("the re-assert gate did not see the stale leg down; nothing " +
			"would re-drive it onto the new address (#14582)")
	}
	stale := reg.get("10.0.0.1:443")
	if stale == nil || !stale.isOpen() {
		t.Fatal("setup: the stale-address listener is not open before the rebind")
	}
	d.reassertMgmtListenersOnce(context.Background())

	if got := m.effectiveHTTPSListener(); got.State != sysservices.StateListening || httpsBoundAddr14582(m) != "10.0.0.9:443" {
		t.Fatalf("after the address replacement and one tick: %+v, want "+
			"Listening at 10.0.0.9:443 — the leg kept the stale address (#14582)", got)
	}
	// Retirement is asynchronous (#14824): stopLegLocked only wakes the
	// serve goroutine, which closes the socket after its background
	// drain. Poll for the close instead of asserting it synchronously.
	waitClosed(t, stale)
}

// TestWebMgmtDHCPLeaseChangeRebindsBoundInterface14582 is the DHCP sibling
// (the more common trigger, per z4): a lifeline lease change on the
// management-only fast path re-resolves the web-management bind. Gated: a
// config whose bound interface is not DHCP-managed must not be re-driven.
func TestWebMgmtDHCPLeaseChangeRebindsBoundInterface14582(t *testing.T) {
	dhcpCfg := &config.Config{}
	dhcpCfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
	}
	dhcpCfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{HTTPS: true, HTTPSInterface: "fxp0.0"},
	}
	if !webMgmtBindsToDHCPInterface(dhcpCfg) {
		t.Fatal("gate: an HTTPS leg bound to a DHCP unit must be lease-dependent")
	}

	staticCfg := &config.Config{}
	staticCfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
	}
	staticCfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{HTTPS: true, HTTPSInterface: "fxp0.0"},
	}
	if webMgmtBindsToDHCPInterface(staticCfg) {
		t.Fatal("gate: a statically-addressed bound interface is not lease-dependent; " +
			"re-driving it on every renew would churn the listener")
	}

	k := newWebMgmtKernelAddrs()
	k.set(ip4Addr("10.0.0.1"))
	d, m, _, _ := bootWebMgmt14582(t, k, dhcpWebMgmtConfig14582())
	if err := d.reconcileWebManagement(d.store.ActiveConfig()); err != nil {
		t.Fatalf("setup reconcile: %v", err)
	}
	if got := httpsBoundAddr14582(m); got != "10.0.0.1:443" {
		t.Fatalf("setup: want HTTPS at 10.0.0.1:443, got %+v", got)
	}

	var calls atomic.Int64
	prevApply := webMgmtRebindApply
	t.Cleanup(func() { webMgmtRebindApply = prevApply })
	webMgmtRebindApply = func(dd *Daemon, cfg *config.Config) error {
		calls.Add(1)
		return prevApply(dd, cfg)
	}

	// Lease renews to a new address; the fast path fires.
	k.set(ip4Addr("10.0.0.9"))
	d.rebindWebMgmtForLeaseChange(d.store.ActiveConfig())

	if calls.Load() != 1 {
		t.Fatalf("lease-change rebind driven %d times, want 1 — the DHCP "+
			"management-only fast path never re-resolved the bind (#14582)", calls.Load())
	}
	if got := m.effectiveHTTPSListener(); got.State != sysservices.StateListening || httpsBoundAddr14582(m) != "10.0.0.9:443" {
		t.Fatalf("after the lease change: %+v, want Listening at 10.0.0.9:443", got)
	}

	// Control: the static config is not re-driven.
	calls.Store(0)
	d.rebindWebMgmtForLeaseChange(staticCfg)
	if calls.Load() != 0 {
		t.Fatal("a lease change re-drove a web-management bind that no DHCP interface feeds")
	}
}

// dhcpWebMgmtConfig14582 is the committed form of the DHCP cell's config:
// fxp0.0 DHCP-managed, HTTPS bound to it, authenticated (so the off-loopback
// bind survives the #4047/#5127 clamp).
func dhcpWebMgmtConfig14582() string {
	secret := mgmtAuthTestSecret(webMgmt14582Secret)
	return "set interfaces fxp0 unit 0 family inet dhcp\n" +
		"set system services web-management https system-generated-certificate\n" +
		"set system services web-management https interface fxp0.0\n" +
		"set system services web-management api-auth expires 2099-01-01\n" +
		`set system services web-management api-auth user webadmin password "` + secret + `"` + "\n"
}

// TestWebMgmtPostNetworkdReconcileResolvesInSameApply14582 pins the
// same-commit wiring at the source: applyConfigLocked must reconcile the
// web-management bind again AFTER applyDataplaneAndHACore (networkd), not
// only before it. A test that only drove reconcileWebManagement directly
// would pass with the second call deleted, which is exactly the defect.
func TestWebMgmtPostNetworkdReconcileResolvesInSameApply14582(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_apply.go"))
	const call = "d.reconcileWebManagement(cfg)"
	early := strings.Index(src, call)
	if early < 0 {
		t.Fatal("the early web-management reconcile is gone from applyConfigLocked")
	}
	dataplane := strings.Index(src, "d.applyDataplaneAndHACore(")
	if dataplane < 0 {
		t.Fatal("applyDataplaneAndHACore call not found in daemon_apply.go")
	}
	late := strings.Index(src[early+len(call):], call)
	if late < 0 {
		t.Fatal("applyConfigLocked reconciles web-management only BEFORE the " +
			"dataplane/networkd apply; a same-commit interface address still " +
			"resolves against an empty kernel and stays on loopback (#14582)")
	}
	late += early + len(call)
	if late < dataplane {
		t.Fatalf("the second web-management reconcile (offset %d) does not follow "+
			"applyDataplaneAndHACore (offset %d) (#14582)", late, dataplane)
	}
	// The DHCP fast path must also carry the rebind.
	dhcpSrc := stripLineComments6791(readDaemonSource(t, "daemon_dhcp.go"))
	if !strings.Contains(dhcpSrc, "d.rebindWebMgmtForLeaseChange(activeCfg)") {
		t.Fatal("onDHCPAddressChange's management-only branch does not re-resolve " +
			"the web-management bind (#14582 DHCP sibling)")
	}
}
