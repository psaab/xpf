package daemon

// apply_phase_errors_production_16170_test.go — #16170 production-path cells.
//
// Unlike apply_phase_errors_16170_test.go, these tests do not assign the
// expected applyPhaseErrors fields themselves. They fail real production
// producers (dataplane, networkd, routing, fabric, FRR, IPsec, DHCP, VRRP and
// the credential/NFT owners), drive applyDataplaneAndHACore,
// applyTailReconciles, or applyConfigLocked, and observe where the resulting
// errors land. Transposing two values at applyConfigLocked's construction
// site changes the ordered leaf sequence and therefore fails these cells.
// Moving a tail phase operand across a non-nil tail-local operand likewise
// changes the exact joined string asserted below.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/networkd"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
)

func topLevelErrors16170(t *testing.T, err error) []error {
	t.Helper()
	if err == nil {
		t.Fatal("expected a joined error, got nil")
	}
	u, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("error %T does not expose a flat Unwrap() []error: %v", err, err)
	}
	return u.Unwrap()
}

func assertFlatJoin16170(t *testing.T, err error, want []error) {
	t.Helper()
	got := topLevelErrors16170(t, err)
	if len(got) != len(want) {
		t.Fatalf("flat join has %d children, want %d: %v", len(got), len(want), err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("flat join child %d = %v, want exact sentinel %v (full error: %v)", i, got[i], want[i], err)
		}
	}
}

// TestApplyPhaseErrorsJoinIsFlat16170 pins the allocation/tree-shape fix from
// the #16232 review: join must be the single flat errors.Join, not nested
// lead/follow subgroup joins (errors.Join does not flatten nested joins).
func TestApplyPhaseErrorsJoinIsFlat16170(t *testing.T) {
	sentinels, phase := phaseSentinels16170()
	assertFlatJoin16170(t, phase.join(), sentinels)
}

type productionPhaseDP16170 struct {
	*runtimeOnlyApplyTestDP
	publishErr  error
	bumpErr     error
	lastOverlay []config.RouteOverlayEntry
	publishSeen bool
}

func (d *productionPhaseDP16170) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	d.applyCalls++
	if d.applyErr != nil {
		if d.applyResult != nil {
			return d.applyResult.Clone(), d.applyErr
		}
		return nil, d.applyErr
	}
	return d.runtimeOnlyApplyTestDP.ApplyConfig(ctx, cfg)
}

func (d *productionPhaseDP16170) PublishRouteOverlaySnapshotWithLatch(_ *config.Config, overlay []config.RouteOverlayEntry, _ map[string]bool, _ bool) (bool, error) {
	d.publishSeen = true
	d.lastOverlay = append([]config.RouteOverlayEntry(nil), overlay...)
	if d.publishErr != nil {
		return false, d.publishErr
	}
	return true, nil
}

func (d *productionPhaseDP16170) BumpFIBGeneration() (uint32, error) {
	return 1, d.bumpErr
}

// TestApplyCoreProductionAttribution16170 drives the real core with three
// distinct producer failures. The ordinary dataplane failure must be the
// deferred Phase.Dataplane value, the networkd write failure produced from
// that same partial apply result must be Phase.Networkd, and the post-networkd
// VRF terminator failure must remain Phase.VRF rather than being relabelled
// as networkd. Terminal must stay nil for this deferred class.
func TestApplyCoreProductionAttribution16170(t *testing.T) {
	networkDir := t.TempDir()
	blocked := filepath.Join(networkDir, "10-xpf-ge-0-0-0.network")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}

	dataplaneSentinel := errors.New("sentinel-16170-production-dataplane")
	dp := &productionPhaseDP16170{runtimeOnlyApplyTestDP: &runtimeOnlyApplyTestDP{
		applyErr: dataplaneSentinel,
		applyResult: &dataplane.ApplyResult{ManagedInterfaces: []networkd.InterfaceConfig{{
			Name: "ge-0-0-0", Addresses: []string{"192.0.2.1/24"},
		}}},
	}}

	termSentinel := errors.New("sentinel-16170-production-core-vrf")
	linkOps := newReconcileFakeLinkOps()
	linkOps.links["vrf-tenant"] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-tenant", Index: 44}, Table: 100}
	term := &startupTerminator10421{addErr: termSentinel, failAfter: 2}
	routingMgr := routing.NewManagerWithLinkTermAndRuleOpsForTest(linkOps, term, startupRuleOps10421{})
	if err := routingMgr.ReconcileVRFs([]routing.VRFSpec{{Name: "tenant", TableID: 100}}); err != nil {
		t.Fatalf("prime VRF terminator state: %v", err)
	}

	prevMgmt := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return nil }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = prevMgmt })

	d := &Daemon{
		networkd: networkd.NewInDir(networkDir),
		routing:  routingMgr,
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(dp)

	cfg := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{{Name: "tenant", TableID: 100}}}
	res := d.applyDataplaneAndHACore(context.Background(), cfg)

	if res.Terminal != nil {
		t.Fatalf("deferred core failures leaked into Terminal: %v", res.Terminal)
	}
	if res.Phase.Dataplane != dataplaneSentinel {
		t.Fatalf("Phase.Dataplane = %v, want the exact ordinary dataplane sentinel", res.Phase.Dataplane)
	}
	if res.Phase.Networkd == nil || !strings.Contains(res.Phase.Networkd.Error(), "apply networkd config:") {
		t.Fatalf("Phase.Networkd = %v, want the production networkd write failure", res.Phase.Networkd)
	}
	if errors.Is(res.Phase.Networkd, termSentinel) {
		t.Fatalf("VRF terminator sentinel was mislabelled as Networkd: %v", res.Phase.Networkd)
	}
	if !errors.Is(res.Phase.VRF, termSentinel) {
		t.Fatalf("Phase.VRF = %v, want the VRF terminator sentinel", res.Phase.VRF)
	}
	if errors.Is(res.Phase.VRF, dataplaneSentinel) {
		t.Fatalf("dataplane sentinel was mislabelled as VRF: %v", res.Phase.VRF)
	}

	// The abort class is the opposite assignment: a required protocol-gate
	// dataplane error belongs only in Terminal and must not also masquerade
	// as the deferred dataplane phase.
	abort := &Daemon{opts: Options{NoDataplane: true}}
	abortDP := &runtimeOnlyApplyTestDP{applyErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible}
	abort.setDataplane(abortDP)
	res = abort.applyDataplaneAndHACore(context.Background(), &config.Config{})
	if !errors.Is(res.Terminal, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("Terminal = %v, want the required-protocol-gate sentinel", res.Terminal)
	}
	if res.Phase.Dataplane != nil || res.Phase.Networkd != nil || res.Phase.VRF != nil {
		t.Fatalf("abort leaked into deferred phase fields: %+v", res.Phase)
	}
}

type failingDHCPApplier16170 struct {
	*recordingDHCPApplier9349
	err error
}

func (f *failingDHCPApplier16170) ApplyWithLeaseAuthority(cfg *config.DHCPServerConfig, authority dhcpserver.LeaseApplyAuthority) error {
	return f.err
}

// TestApplyConfigLockedProductionAttribution16170 is the construction-site
// cell. Every named phase producer fails at once with a distinguishable
// error. applyConfigLocked must place them in the tail's flat leaf order;
// swapping any two construction values moves a marker to another position.
// It also observes the routing retry debt and the production log labels.
func TestApplyConfigLockedProductionAttribution16170(t *testing.T) {
	d, cfg, dp, sentinels := productionApplyFixture16170(t)

	logs, restore := captureSlog(t)
	err := d.applyConfigLocked(context.Background(), cfg)
	restore()
	if err == nil {
		t.Fatal("applyConfigLocked returned nil with every production phase failing")
	}
	if applyErrSkipsPeerSync(err) {
		t.Fatalf("deferred production failures were classified as peer-sync skipping: %v", err)
	}

	children := topLevelErrors16170(t, err)
	if len(children) != 11 {
		t.Fatalf("full apply tail has %d top-level children, want 11 phase children: %v", len(children), err)
	}
	type expectation struct {
		name   string
		marker string
		target error
	}
	want := []expectation{
		{"Networkd", "apply networkd config:", nil},
		{"Dataplane", "", sentinels.dataplane},
		{"DHCPServer", "", sentinels.dhcp},
		{"IPsec", "apply IPsec config:", syscall.ENOTDIR},
		{"Iface", "", sentinels.iface},
		{"RouteLeak", "route-leak snapshot republish:", sentinels.routeLeak},
		{"RoutingRule", "", sentinels.routingRule},
		{"MgmtRoute", "", sentinels.mgmtRoute},
		{"VRF", "", sentinels.vrfSetup},
		{"Fabric", "", sentinels.fabric},
		{"FRR", "", sentinels.frr},
	}
	for i, w := range want {
		child := children[i]
		if w.target != nil && !errors.Is(child, w.target) {
			t.Fatalf("tail child %d (%s) = %v, want it to wrap %v; full order: %v", i, w.name, child, w.target, err)
		}
		if w.marker != "" && !strings.Contains(child.Error(), w.marker) {
			t.Fatalf("tail child %d (%s) = %v, want marker %q; full order: %v", i, w.name, child, w.marker, err)
		}
	}
	if !errors.Is(children[8], sentinels.coreVRF) {
		t.Fatalf("VRF child does not also carry the core terminator sentinel: %v", children[8])
	}
	setupAt := strings.Index(children[8].Error(), sentinels.vrfSetup.Error())
	coreAt := strings.Index(children[8].Error(), sentinels.coreVRF.Error())
	if setupAt < 0 || coreAt < 0 || setupAt > coreAt {
		t.Fatalf("VRF setup/core order inside VRF child is wrong: %v", children[8])
	}

	wantOverlay := failedIPMonEngine(t).ActiveOverlay()
	if !dp.publishSeen {
		t.Fatal("route-leak producer was never driven")
	}
	if fmt.Sprint(dp.lastOverlay) != fmt.Sprint(wantOverlay) {
		t.Fatalf("core Overlay reaching route-leak/FRR = %v, want production ipmon overlay %v", dp.lastOverlay, wantOverlay)
	}

	owed, failures, last := d.RoutingReconcileDebt()
	if !owed || failures == 0 {
		t.Fatalf("routing retry debt not latched: owed=%v failures=%d last=%q", owed, failures, last)
	}
	if !strings.Contains(last, sentinels.routingRule.Error()) || !strings.Contains(last, sentinels.routeLeak.Error()) || !strings.Contains(last, sentinels.coreVRF.Error()) {
		t.Fatalf("routing debt last error does not carry routing/route-leak/core-VRF producers: %q", last)
	}
	if strings.Contains(last, sentinels.frr.Error()) {
		t.Fatalf("FRR failure was incorrectly latched as routing debt: %q", last)
	}
	// MgmtRoute has its own debt bucket (#11450): it must carry the
	// sentinel, must not be discharged by the generic routing latch that
	// overwrote lastErr afterwards, and its log label must have fired.
	d.routingDebt.mu.Lock()
	mgmtOwed, mgmtLast := d.routingDebt.mgmtRoutesOwed, d.routingDebt.mgmtRoutesLastErr
	d.routingDebt.mu.Unlock()
	if !mgmtOwed || !strings.Contains(mgmtLast, sentinels.mgmtRoute.Error()) {
		t.Fatalf("mgmt-route debt bucket = owed:%v last:%q, want owed carrying %q", mgmtOwed, mgmtLast, sentinels.mgmtRoute)
	}
	if !strings.Contains(logs.String(), "management-VRF route reconcile failed") {
		t.Fatalf("mgmt-route debt log label missing; logs:\n%s", logs.String())
	}
	for _, label := range []string{
		"failed to apply networkd config",
		"failed to apply IPsec config",
		"failed to apply DHCP server config",
		"routing reconcile failed; the retry owner will re-run it until it succeeds",
	} {
		if !strings.Contains(logs.String(), label) {
			t.Fatalf("production log label %q missing; logs:\n%s", label, logs.String())
		}
	}
}

type productionSentinels16170 struct {
	dataplane   error
	dhcp        error
	iface       error
	routeLeak   error
	routingRule error
	mgmtRoute   error
	vrfSetup    error
	coreVRF     error
	fabric      error
	frr         error
}

func productionApplyFixture16170(t *testing.T) (*Daemon, *config.Config, *productionPhaseDP16170, productionSentinels16170) {
	t.Helper()
	s := productionSentinels16170{
		dataplane:   errors.New("sentinel-16170-production-dataplane"),
		dhcp:        errors.New("sentinel-16170-production-dhcp-server"),
		iface:       errors.New("sentinel-16170-production-iface"),
		routeLeak:   errors.New("sentinel-16170-production-route-leak"),
		routingRule: errors.New("sentinel-16170-production-routing-rule"),
		mgmtRoute:   errors.New("sentinel-16170-production-mgmt-route"),
		vrfSetup:    errors.New("sentinel-16170-production-vrf-setup"),
		coreVRF:     errors.New("sentinel-16170-production-core-vrf"),
		fabric:      errors.New("sentinel-16170-production-fabric"),
		frr:         errors.New("sentinel-16170-production-frr"),
	}

	networkDir := t.TempDir()
	d, _ := minimalNetworkdDaemon(t, networkDir, &dataplane.ApplyResult{})
	d.earlyInputHandoffDone.Store(true)
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }

	if _, err := d.store.SyncApply("system {\n    backup-router 192.0.2.254;\n}\ninterfaces {\n    fxp0 {\n        unit 0;\n    }\n}\n", nil); err != nil {
		t.Fatalf("seed active config: %v", err)
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("seed active config is nil")
	}
	if cfg.Interfaces.Interfaces == nil {
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	}
	cfg.Interfaces.Interfaces["gr-0/0/0"] = &config.InterfaceConfig{
		Name:   "gr-0/0/0",
		Tunnel: &config.TunnelConfig{Name: "gr-0-0-0", Source: "192.0.2.1", Destination: "198.51.100.1"},
	}
	cfg.Interfaces.Interfaces["fab0"] = &config.InterfaceConfig{
		Name: "fab0", LocalFabricMember: "ge-0/0/0",
		Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.99.0.1/24"}}},
	}
	cfg.RoutingInstances = append(cfg.RoutingInstances, &config.RoutingInstanceConfig{Name: "tenant", TableID: 100})
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{"vpn1": {Gateway: "gw1"}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {Name: "wan-failover", MatchRPMProbe: "WAN", PreferredRoutes: []*config.PreferredRoute{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1"}}},
	}}

	// Networkd: block the generated file for the interface in the partial
	// dataplane result, exactly as the existing production networkd cell does.
	if err := os.Mkdir(filepath.Join(networkDir, "10-xpf-ge-0-0-0.network"), 0o755); err != nil {
		t.Fatal(err)
	}
	dp := &productionPhaseDP16170{
		runtimeOnlyApplyTestDP: &runtimeOnlyApplyTestDP{
			applyErr: s.dataplane,
			applyResult: &dataplane.ApplyResult{ManagedInterfaces: []networkd.InterfaceConfig{{
				Name: "ge-0-0-0", Addresses: []string{"192.0.2.1/24"},
			}}},
		},
		publishErr: s.routeLeak,
	}
	d.setDataplane(dp)
	d.ipmon = failedIPMonEngine(t)

	linkOps := newReconcileFakeLinkOps()
	linkOps.links["fxp0"] = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 2}}
	linkOps.addFail["vrf-tenant"] = s.vrfSetup
	linkOps.addFail["gr-0-0-0"] = s.iface
	term := &startupTerminator10421{addErr: s.coreVRF, failAfter: 2}
	ruleOps := &fakeRuleOps5844{listErr: s.routingRule}
	d.routing = routing.NewManagerWithLinkTermAndRuleOpsForTest(linkOps, term, ruleOps)

	prevEnsure, prevDelay := fabricEnsureFn, fabricIPVLANRetryDelay
	fabricEnsureFn = func(string, string, []string, int) error { return s.fabric }
	fabricIPVLANRetryDelay = 0
	t.Cleanup(func() { fabricEnsureFn, fabricIPVLANRetryDelay = prevEnsure, prevDelay })

	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.frr = frr.NewForTest(conf, &frr.RecordingExecutor{ReloadErr: s.frr})

	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.ipsec = ipsec.NewWithConfigDir(filepath.Join(blocker, "conf.d"))

	dhcpMgr := dhcp.NewManagerForTesting(nil)
	dhcpMgr.SeedLeaseForTesting("fxp0", dhcp.AFInet, gwLease("fxp0", "192.0.2.1"))
	d.dhcp = dhcpMgr
	d.dhcpServer = &failingDHCPApplier16170{recordingDHCPApplier9349: &recordingDHCPApplier9349{}, err: s.dhcp}

	// MgmtRoute: drive the real applyMgmtVRFRoutesTo through a fake
	// mgmtRouteProgrammer whose RouteReplace fails with the sentinel.
	// applyConfigLocked calls applyMgmtVRFRoutes directly (not via
	// mgmtVRFRouteReconcileFn), so the programmable core is swapped to
	// reach the same production reconcile with the fake programmer.
	// The seeded backup-router above makes mgmtStaticRoutesDesired emit
	// a default route, and fxp0 is in the published mgmt set once
	// applyVRFReconcile runs, so RouteReplace is reached.
	prevRoutes, prevDNS := mgmtVRFRoutesApplyFn, mgmtDNSRulesApplyFn
	mgmtFake := &fakeMgmtProgrammer{linkIdx: 2, replaceErr: s.mgmtRoute}
	mgmtVRFRoutesApplyFn = func(d *Daemon, _ mgmtRouteProgrammer, leases []*dhcp.Lease) error {
		return d.applyMgmtVRFRoutesTo(mgmtFake, leases, d.mgmtVRFIfaceSet())
	}
	mgmtDNSRulesApplyFn = func(*Daemon, []*dhcp.Lease, *config.Config) error { return nil }
	t.Cleanup(func() { mgmtVRFRoutesApplyFn, mgmtDNSRulesApplyFn = prevRoutes, prevDNS })

	return d, cfg, dp, s
}

// TestApplyTailProductionInterleaveOrder16170 drives the real tail with every
// phase field and every tail-local producer failing simultaneously. The exact
// string and the flat top-level child sequence pin hostInbound/lo0/DNS, all
// five credential owners, and VRRP between their neighbouring phase fields.
func TestApplyTailProductionInterleaveOrder16170(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	_, phase := phaseSentinels16170()

	hostSentinel := errors.New("sentinel-16170-tail-host-inbound")
	lo0Sentinel := errors.New("sentinel-16170-tail-lo0")
	dnsSentinel := errors.New("sentinel-16170-tail-dns")
	loginSentinel := errors.New("sentinel-16170-tail-login")
	sudoersSentinel := errors.New("sentinel-16170-tail-sudoers")
	sshSentinel := errors.New("sentinel-16170-tail-ssh")

	origInstaller := nftInstaller
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return hostSentinel },
		lo0:         func(xnft.Lo0FilterSpec) error { return lo0Sentinel },
	}
	t.Cleanup(func() { nftInstaller = origInstaller })

	f.d.reconcileDNSFn = func(*config.Config, bool) error { return dnsSentinel }
	f.d.vrrpMgr = nil

	f.cfg.Interfaces.Interfaces["reth0"].Units[0].Addresses = []string{"10.7.7.1/24"}
	f.cfg.Security.Zones["trust"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"ssh"}}
	f.cfg.System.Lo0FilterInputV4 = "mgmt-lockdown"
	f.cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"mgmt-lockdown": {Name: "mgmt-lockdown", Terms: []*config.FirewallFilterTerm{{Name: "deny-all", Action: config.FilterActionDiscard}}},
	}
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{{Name: "admin", Class: "super-user"}}}
	f.cfg.System.Services = &config.SystemServicesConfig{SSH: &config.SSHServiceConfig{RootLogin: "deny"}}
	f.cfg.System.RootAuthentication = &config.RootAuthConfig{SSHKeys: []string{"not a single-line key\nsecond line"}}

	runCommandTimeout = func(string, ...string) ([]byte, error) { return []byte("refused"), loginSentinel }
	validateSudoersFile = func(string) error { return sudoersSentinel }
	sshdValidateCmd = func() ([]byte, error) { return []byte("bad"), sshSentinel }

	if err := os.MkdirAll(provisionedUsersDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(provisionedUsersDir, "ghost"), []byte("4242"), 0o600); err != nil {
		t.Fatal(err)
	}
	absentPasswd := filepath.Join(f.root, "passwd-as-dir")
	if err := os.MkdirAll(absentPasswd, 0o755); err != nil {
		t.Fatal(err)
	}
	passwdPath = absentPasswd

	err := f.d.applyTailReconciles(f.cfg, phase)
	if err == nil {
		t.Fatal("applyTailReconciles returned nil with every phase and local producer failing")
	}

	want := []string{
		"sentinel-16170-networkd",
		"sentinel-16170-dataplane",
		"sentinel-16170-dhcp-server",
		"apply host-inbound nftables filter: sentinel-16170-tail-host-inbound",
		"apply lo0 nftables filter: sentinel-16170-tail-lo0",
		"sentinel-16170-tail-dns",
		"create user admin: sentinel-16170-tail-login",
		"write sudoers grant for admin: generated sudoers grant rejected: sentinel-16170-tail-sudoers",
		fmt.Sprintf("read passwd for removed user ghost: read %s: is a directory", absentPasswd),
		"validate sshd config: sentinel-16170-tail-ssh",
		"SSH key 1 for root must be a single-line OpenSSH public key",
		"sentinel-16170-ipsec",
		"sentinel-16170-iface",
		"sentinel-16170-route-leak",
		"sentinel-16170-routing-rule",
		"sentinel-16170-mgmt-route",
		"sentinel-16170-vrf",
		"sentinel-16170-fabric",
		"update VRRP instances: VRRP manager not initialized (apply reached the VRRP reconcile before daemon startup constructed it)",
		"sentinel-16170-frr",
	}
	if got := err.Error(); got != strings.Join(want, "\n") {
		t.Fatalf("exact local/phase join order changed:\n got: %q\nwant: %q", got, strings.Join(want, "\n"))
	}
	children := topLevelErrors16170(t, err)
	if len(children) != len(want) {
		t.Fatalf("tail top-level join has %d children, want %d (nested subgroup?): %v", len(children), len(want), err)
	}
	for i := range want {
		if children[i].Error() != want[i] {
			t.Fatalf("tail child %d = %q, want %q", i, children[i].Error(), want[i])
		}
	}
	for _, target := range []error{hostSentinel, lo0Sentinel, dnsSentinel, loginSentinel, sudoersSentinel, sshSentinel} {
		if !errors.Is(err, target) {
			t.Fatalf("joined tail error lost local sentinel %v", target)
		}
	}
	_ = vrrp.NewManager
}
