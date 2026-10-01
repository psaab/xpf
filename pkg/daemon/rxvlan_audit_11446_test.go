package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
)

func storeWithPlainVLANParents11446(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"interfaces ge-0/0/0 unit 100 vlan-id 100",
		"interfaces ge-0/0/0 unit 100 family inet address 192.0.2.1/24",
		"interfaces ge-0/0/1 unit 200 vlan-id 200",
		"interfaces ge-0/0/1 unit 200 family inet address 198.51.100.1/24",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit VLAN parents: %v", err)
	}
	return store
}

// TestRxVlanAuditReassertsOutOfBandToggleOnEveryPlainVLANParent11446 is the
// user-visible out-of-band-toggle cell: a driver reports rx-vlan-offload ON
// after reset and a complete audit must disable it on every configured trunk.
func TestRxVlanAuditReassertsOutOfBandToggleOnEveryPlainVLANParent11446(t *testing.T) {
	store := storeWithPlainVLANParents11446(t)
	links := map[string]netlink.Link{
		"ge-0-0-0": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 40, Name: "ge-0-0-0", Flags: net.FlagUp}},
		"ge-0-0-1": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 41, Name: "ge-0-0-1", Flags: net.FlagUp}},
	}
	oldByName := rxVlanAuditLinkByName
	rxVlanAuditLinkByName = func(name string) (netlink.Link, error) {
		link, ok := links[name]
		if !ok {
			t.Fatalf("audit resolved unexpected parent %q", name)
		}
		return link, nil
	}
	t.Cleanup(func() { rxVlanAuditLinkByName = oldByName })

	oldRun := runCommandTimeout
	var disabled []string
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name != "ethtool" || len(args) < 2 {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			if len(args) != 4 || args[2] != "rxvlan" || args[3] != "off" {
				t.Fatalf("unexpected offload repair command: %v", args)
			}
			disabled = append(disabled, args[1])
			return nil, nil
		default:
			t.Fatalf("unexpected ethtool operation: %v", args)
			return nil, nil
		}
	}
	t.Cleanup(func() { runCommandTimeout = oldRun })

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	if err := d.rxVlanAuditOnce(context.Background(), "", newRxVlanAuditState()); err != nil {
		t.Fatalf("rxvlan audit: %v", err)
	}
	if len(disabled) != 2 || disabled[0] == disabled[1] {
		t.Fatalf("disabled parents = %v, want both plain VLAN parents ge-0-0-0 and ge-0-0-1", disabled)
	}
}

type rxVlanAuditRuntime11446 struct {
	dataplane.RuntimeDataPlane
	mu       sync.Mutex
	attached map[int]bool
	events   *[]string
}

func (r *rxVlanAuditRuntime11446) AttachedXDPIfindexes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int, 0, len(r.attached))
	for index := range r.attached {
		out = append(out, index)
	}
	return out
}

func (r *rxVlanAuditRuntime11446) AttachedXDPLinkCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attached)
}

func (r *rxVlanAuditRuntime11446) DetachXDP(index int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.events != nil {
		*r.events = append(*r.events, "detach")
	}
	delete(r.attached, index)
	return nil
}

func TestRxVlanAuditQuarantinesFailedDisableBehindClosedFence11446(t *testing.T) {
	store := storeWithPlainVLANParents11446(t)
	dir := t.TempDir()
	v4, v6 := filepath.Join(dir, "ip_forward"), filepath.Join(dir, "forwarding")
	for _, path := range []string{v4, v6} {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
	oldV4, oldV6 := ipv4ForwardSysctlPath, ipv6ForwardSysctlPath
	ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = v4, v6
	t.Cleanup(func() { ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = oldV4, oldV6 })

	var events []string
	runtime := &rxVlanAuditRuntime11446{
		attached: map[int]bool{40: true},
		events:   &events,
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	d.dpCell.Store(&dpSlot{v: runtime})
	d.transitGateOwned.Store(true)
	d.dataplaneArmed.Store(true)

	links := map[string]netlink.Link{
		"ge-0-0-0": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 40, Name: "ge-0-0-0", Flags: net.FlagUp}},
		"ge-0-0-1": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 41, Name: "ge-0-0-1", Flags: net.FlagUp}},
	}
	oldByName := rxVlanAuditLinkByName
	rxVlanAuditLinkByName = func(name string) (netlink.Link, error) {
		link, ok := links[name]
		if !ok {
			t.Fatalf("audit resolved unexpected parent %q", name)
		}
		return link, nil
	}
	t.Cleanup(func() { rxVlanAuditLinkByName = oldByName })

	oldInstaller := nftInstaller
	installer := &fakeNftInstaller{barrierInstall: func() error {
		events = append(events, "barrier")
		return nil
	}}
	nftInstaller = installer
	t.Cleanup(func() { nftInstaller = oldInstaller })

	disableErr := errors.New("ethtool refused rxvlan off")
	oldRun := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name != "ethtool" || len(args) < 2 {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		switch args[0] {
		case "-k":
			if args[1] == "ge-0-0-0" {
				return []byte("rx-vlan-offload: on\n"), nil
			}
			return []byte("rx-vlan-offload: off\n"), nil
		case "-K":
			return nil, disableErr
		default:
			t.Fatalf("unexpected ethtool operation: %v", args)
			return nil, nil
		}
	}
	t.Cleanup(func() { runCommandTimeout = oldRun })

	err := d.rxVlanAuditOnce(context.Background(), "", newRxVlanAuditState())
	if !errors.Is(err, disableErr) {
		t.Fatalf("audit error = %v, want the failed offload command", err)
	}
	if indexes := runtime.AttachedXDPIfindexes(); len(indexes) != 0 {
		t.Fatalf("quarantined parent's XDP bindings remain: %v", indexes)
	}
	if len(events) < 2 || events[0] != "barrier" || events[1] != "detach" {
		t.Fatalf("transit fence/detach order = %v, want barrier before detach", events)
	}
	for _, path := range []string{v4, v6} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != "0" {
			t.Errorf("%s = %q after XDP quarantine, want forwarding closed", path, got)
		}
	}
}

func TestRxVlanAuditRecoveryDoesNotArmFailedDataplaneStart11446(t *testing.T) {
	store := storeWithPlainVLANParents11446(t)
	dir := t.TempDir()
	v4, v6 := filepath.Join(dir, "ip_forward"), filepath.Join(dir, "forwarding")
	for _, path := range []string{v4, v6} {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
	oldV4, oldV6 := ipv4ForwardSysctlPath, ipv6ForwardSysctlPath
	ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = v4, v6
	t.Cleanup(func() { ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = oldV4, oldV6 })

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	d.dpCell.Store(&dpSlot{v: &rxVlanAuditRuntime11446{attached: make(map[int]bool)}})
	d.transitGateOwned.Store(true)
	state := newRxVlanAuditState()

	linkUp := true
	oldByName := rxVlanAuditLinkByName
	rxVlanAuditLinkByName = func(name string) (netlink.Link, error) {
		if name != "ge-0-0-0" && name != "ge-0-0-1" {
			t.Fatalf("audit resolved unexpected parent %q", name)
		}
		flags := net.Flags(0)
		if linkUp {
			flags = net.FlagUp
		}
		index := 40
		if name == "ge-0-0-1" {
			index = 41
		}
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: index, Name: name, Flags: flags}}, nil
	}
	t.Cleanup(func() { rxVlanAuditLinkByName = oldByName })
	oldSetDown := rxVlanAuditLinkSetDown
	rxVlanAuditLinkSetDown = func(netlink.Link) error {
		linkUp = false
		return nil
	}
	t.Cleanup(func() { rxVlanAuditLinkSetDown = oldSetDown })

	oldInstaller := nftInstaller
	nftInstaller = &fakeNftInstaller{barrierInstall: func() error {
		return errors.New("injected transit barrier failure")
	}}
	t.Cleanup(func() { nftInstaller = oldInstaller })

	disableErr := errors.New("ethtool refused rxvlan off")
	targetQueries := 0
	oldRun := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name != "ethtool" || len(args) < 2 {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		switch args[0] {
		case "-k":
			if args[1] != "ge-0-0-0" {
				return []byte("rx-vlan-offload: off\n"), nil
			}
			targetQueries++
			if targetQueries == 1 {
				return []byte("rx-vlan-offload: on\n"), nil
			}
			return []byte("rx-vlan-offload: off\n"), nil
		case "-K":
			return nil, disableErr
		default:
			t.Fatalf("unexpected ethtool operation: %v", args)
			return nil, nil
		}
	}
	t.Cleanup(func() { runCommandTimeout = oldRun })

	if err := d.rxVlanAuditOnce(context.Background(), "", state); !errors.Is(err, disableErr) {
		t.Fatalf("initial audit error = %v, want failed offload disable", err)
	}
	if !state.transitSuppressed || state.restoreDataplaneArmed {
		t.Fatalf("quarantine state = %+v, want suppressed without an armed dataplane restore", state)
	}
	if d.DataplaneArmed() {
		t.Fatal("failed dataplane start became armed during RX VLAN quarantine")
	}

	linkUp = true
	if err := d.rxVlanAuditOnce(context.Background(), "", state); err != nil {
		t.Fatalf("recovery audit: %v", err)
	}
	if state.transitSuppressed {
		t.Fatal("full audit did not clear the recovered transit suppression")
	}
	if d.DataplaneArmed() {
		t.Fatal("RX VLAN audit armed a dataplane whose Start had failed")
	}
}

func TestRxVlanAuditRetainsOldParentsAcrossFailedReplacement11446(t *testing.T) {
	store := storeWithPlainVLANParents11446(t)
	runtime := &rxVlanAuditRuntime11446{attached: make(map[int]bool)}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	d.dpCell.Store(&dpSlot{v: runtime})

	oldConfig := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/9": {Units: map[int]*config.InterfaceUnit{100: {VlanID: 100}}},
		}},
	}
	d.retainRxVlanAppliedParents(oldConfig, true)
	d.retainRxVlanAppliedParents(store.ActiveConfig(), false)

	links := map[string]netlink.Link{
		"ge-0-0-0": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 40, Name: "ge-0-0-0", Flags: net.FlagUp}},
		"ge-0-0-1": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 41, Name: "ge-0-0-1", Flags: net.FlagUp}},
		"ge-0-0-9": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 49, Name: "ge-0-0-9", Flags: net.FlagUp}},
	}
	oldByName := rxVlanAuditLinkByName
	rxVlanAuditLinkByName = func(name string) (netlink.Link, error) {
		link, ok := links[name]
		if !ok {
			t.Fatalf("audit resolved unexpected parent %q", name)
		}
		return link, nil
	}
	t.Cleanup(func() { rxVlanAuditLinkByName = oldByName })

	oldRun := runCommandTimeout
	queried := make(map[string]bool)
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name != "ethtool" || len(args) != 2 || args[0] != "-k" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		queried[args[1]] = true
		return []byte("rx-vlan-offload: off\n"), nil
	}
	t.Cleanup(func() { runCommandTimeout = oldRun })

	if err := d.rxVlanAuditOnce(context.Background(), "", newRxVlanAuditState()); err != nil {
		t.Fatalf("rxvlan audit: %v", err)
	}
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1", "ge-0-0-9"} {
		if !queried[name] {
			t.Errorf("audit missed VLAN parent %s during failed replacement; queried %v", name, queried)
		}
	}
}

func TestRxVlanAuditRechecksParentOnLinkUp11446(t *testing.T) {
	store := storeWithPlainVLANParents11446(t)
	oldInterval := rxVlanAuditInterval
	rxVlanAuditInterval = time.Hour
	t.Cleanup(func() { rxVlanAuditInterval = oldInterval })

	links := map[string]netlink.Link{
		"ge-0-0-0": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 40, Name: "ge-0-0-0", Flags: net.FlagUp}},
		"ge-0-0-1": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 41, Name: "ge-0-0-1", Flags: net.FlagUp}},
	}
	oldByName := rxVlanAuditLinkByName
	rxVlanAuditLinkByName = func(name string) (netlink.Link, error) { return links[name], nil }
	t.Cleanup(func() { rxVlanAuditLinkByName = oldByName })

	subscribed := make(chan chan<- netlink.LinkUpdate, 1)
	oldSubscribe := rxVlanAuditLinkSubscribe
	rxVlanAuditLinkSubscribe = func(ch chan<- netlink.LinkUpdate, _ <-chan struct{}, _ func(error)) error {
		subscribed <- ch
		return nil
	}
	t.Cleanup(func() { rxVlanAuditLinkSubscribe = oldSubscribe })

	initialAudit := make(chan struct{})
	disabled := make(chan string, 1)
	oldRun := runCommandTimeout
	queries := 0
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name != "ethtool" || len(args) < 2 {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		switch args[0] {
		case "-k":
			queries++
			if queries == 2 {
				close(initialAudit)
			}
			if queries <= 2 {
				return []byte("rx-vlan-offload: off\n"), nil
			}
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			disabled <- args[1]
			return nil, nil
		default:
			t.Fatalf("unexpected ethtool operation: %v", args)
			return nil, nil
		}
	}
	t.Cleanup(func() { runCommandTimeout = oldRun })

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var retry bool
	go func() {
		retry = d.runRxVlanAuditLinkSubscription(ctx, newRxVlanAuditState())
		close(finished)
	}()
	defer func() {
		cancel()
		<-finished
	}()
	var updates chan<- netlink.LinkUpdate
	select {
	case updates = <-subscribed:
	case <-time.After(time.Second):
		t.Fatal("rxvlan audit did not subscribe to RTNL link updates")
	}
	select {
	case <-initialAudit:
	case <-time.After(time.Second):
		t.Fatal("initial parent audit did not finish")
	}
	updates <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   links["ge-0-0-0"],
	}
	select {
	case got := <-disabled:
		if got != "ge-0-0-0" {
			t.Fatalf("link-up reasserted %s, want ge-0-0-0", got)
		}
	case <-time.After(time.Second):
		t.Fatal("link-up event did not re-disable the re-enabled rxvlan offload")
	}
	cancel()
	<-finished
	if retry {
		t.Fatal("link subscription reported a retry after context cancellation")
	}
}

func TestRxVlanAuditPeriodicRechecksOutOfBandToggle11446(t *testing.T) {
	store := storeWithPlainVLANParents11446(t)
	oldInterval := rxVlanAuditInterval
	rxVlanAuditInterval = time.Millisecond
	t.Cleanup(func() { rxVlanAuditInterval = oldInterval })

	links := map[string]netlink.Link{
		"ge-0-0-0": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 40, Name: "ge-0-0-0", Flags: net.FlagUp}},
		"ge-0-0-1": &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 41, Name: "ge-0-0-1", Flags: net.FlagUp}},
	}
	oldByName := rxVlanAuditLinkByName
	rxVlanAuditLinkByName = func(name string) (netlink.Link, error) { return links[name], nil }
	t.Cleanup(func() { rxVlanAuditLinkByName = oldByName })

	oldSubscribe := rxVlanAuditLinkSubscribe
	rxVlanAuditLinkSubscribe = func(chan<- netlink.LinkUpdate, <-chan struct{}, func(error)) error { return nil }
	t.Cleanup(func() { rxVlanAuditLinkSubscribe = oldSubscribe })

	disabled := make(chan string, 1)
	oldRun := runCommandTimeout
	queries := 0
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name != "ethtool" || len(args) < 2 {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		switch args[0] {
		case "-k":
			queries++
			if queries <= 2 || args[1] != "ge-0-0-0" {
				return []byte("rx-vlan-offload: off\n"), nil
			}
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			disabled <- args[1]
			return nil, nil
		default:
			t.Fatalf("unexpected ethtool operation: %v", args)
			return nil, nil
		}
	}
	t.Cleanup(func() { runCommandTimeout = oldRun })

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var retry bool
	go func() {
		retry = d.runRxVlanAuditLinkSubscription(ctx, newRxVlanAuditState())
		close(finished)
	}()
	defer func() {
		cancel()
		<-finished
	}()
	select {
	case got := <-disabled:
		if got != "ge-0-0-0" {
			t.Fatalf("periodic audit reasserted %s, want ge-0-0-0", got)
		}
	case <-time.After(time.Second):
		t.Fatal("periodic audit did not re-disable the out-of-band rxvlan toggle")
	}
	cancel()
	<-finished
	if retry {
		t.Fatal("link subscription reported a retry after context cancellation")
	}
}

func TestRxVlanParentNamesSelectsLocalRethMember11446(t *testing.T) {
	cfg := &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{NodeID: 0}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
				80: {Number: 80, VlanID: 180},
			}},
			"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
			"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
		}},
	}
	got := rxVlanParentNames(cfg)
	if len(got) != 1 || got[0] != "ge-0-0-2" {
		t.Fatalf("VLAN RETH parents = %v, want only this node's ge-0-0-2 member", got)
	}
}
