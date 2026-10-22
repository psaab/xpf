package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/grpcapi"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
)

const vrfRetry12168ChildEnv = "XPF_VRF_RETRY_12168_CHILD"

// isolatedVRFRetryChild12168 gives each real-kernel test its own user, network,
// and mount namespaces. The child test name is explicit so the outer process
// can invoke one acceptance case without rerunning the whole package.
func isolatedVRFRetryChild12168(t *testing.T) bool {
	t.Helper()
	if os.Getenv(vrfRetry12168ChildEnv) == t.Name() {
		return true
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatalf("unshare unavailable for isolated VRF test: %v", err)
	}
	// Namespace EPERM is a legitimate environment skip only when this
	// dedicated capability probe fails. The acceptance child itself is always
	// fail-closed, even if its error text also contains "operation not permitted".
	probe := exec.Command(unshare, "-Urnm", "--propagation", "private", "--", "/bin/true")
	probeOutput, probeErr := probe.CombinedOutput()
	if probeErr != nil {
		if strings.Contains(strings.ToLower(string(probeOutput)), "operation not permitted") {
			t.Skipf("isolated VRF namespace probe unavailable: %s", probeOutput)
		}
		t.Fatalf("isolated VRF namespace probe failed: %v\n%s", probeErr, probeOutput)
	}
	cmd := exec.Command(unshare, "-Urnm", "--propagation", "private", "--", os.Args[0],
		"-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), vrfRetry12168ChildEnv+"="+t.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated VRF acceptance process failed: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "--- SKIP:") {
		t.Fatalf("isolated kernel VRF acceptance test skipped after the capability probe succeeded:\n%s", output)
	}
	t.Logf("isolated kernel VRF acceptance output:\n%s", output)
	return false
}

func newKernelVRFRetryFixture12168(t *testing.T) (*Daemon, *config.Config, netlink.Link, netlink.Link) {
	t.Helper()
	installFakeNetworkctl(t)
	useTemporaryDNSReconciler12168(t)
	stateDir := t.TempDir()
	if err := unix.Mount(stateDir, "/var/lib/xpf", "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("cannot isolate keyed heartbeat epoch state: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount("/var/lib/xpf", 0); err != nil {
			t.Errorf("unmount isolated HA state directory: %v", err)
		}
	})

	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName}, Table: config.ManagementVRFTableID}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Fatalf("cannot create management VRF in isolated namespace: %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("bring up management VRF: %v", err)
	}
	control := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "em0"}}
	if err := netlink.LinkAdd(control); err != nil {
		t.Fatalf("create control interface: %v", err)
	}
	if err := netlink.LinkSetUp(control); err != nil {
		t.Fatalf("bring up control interface: %v", err)
	}
	for _, cidr := range []string{"198.51.100.1/24", "198.51.100.2/24"} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("parse control address %s: %v", cidr, err)
		}
		if err := netlink.AddrAdd(control, addr); err != nil {
			t.Fatalf("assign control address %s: %v", cidr, err)
		}
	}

	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-test-key-12168",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 198.51.100.2",
		"set interfaces em0 unit 0 family inet address 198.51.100.1/24",
	})
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("fixture did not compile cluster config")
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		store:     store,
		networkd:  networkd.NewInDir(t.TempDir()),
		vrrpMgr:   vrrp.NewManager(),
		cluster:   cluster.NewManager(0, 1),
		daemonCtx: ctx,
		opts:      Options{NoDataplane: true},
	}
	d.grpcSrv = grpcapi.NewServer("", grpcapi.Config{Store: store, Cluster: d.cluster})
	t.Cleanup(func() {
		d.stopClusterComms()
		d.cluster.Stop() // join keyed-epoch persistence before the state mount is removed
		cancel()
	})
	return d, cfg, control, vrf
}

// TestFailedBootConvergenceBindsHeartbeatToManagementVRF12168 drives the real
// apply-tail restart path and verifies the replacement heartbeat records a
// successful SO_BINDTODEVICE bind to vrf-mgmt.
func TestFailedBootConvergenceBindsHeartbeatToManagementVRF12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, cfg, control, vrf := newKernelVRFRetryFixture12168(t)

	// Failed boot apply: comms starts while the published management-VRF set is
	// still nil, so the first heartbeat is successfully installed unbound.
	d.publishMgmtVRFIfaces(nil)
	d.startClusterComms(d.daemonCtx)
	waitForHeartbeatVRF12168(t, d.cluster, "")
	if got := d.activeTransport().VRFDevice; got != "" {
		t.Fatalf("failed-boot transport unexpectedly selected VRF %q", got)
	}

	// Converging apply: install the VRF master and publish the membership before
	// step 20 compares the active and candidate transport keys.
	if err := netlink.LinkSetMaster(control, vrf); err != nil {
		t.Fatalf("enslave control interface to management VRF: %v", err)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	_ = d.applyTailReconciles(cfg, applyPhaseErrors{})

	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
	if got := d.activeTransport().VRFDevice; got != config.ManagementVRFDeviceName {
		t.Fatalf("converged transport VRF = %q, want %q", got, config.ManagementVRFDeviceName)
	}
}

// TestWarmHeartbeatRetryResolvesNewVRFMembership12168 exercises the warm
// retry transition with a real kernel VRF and assigned control address. The
// resolver must run inside each attempt: after em0 is enslaved but before its
// membership is published, an unbound bind fails; publishing membership lets
// the next attempt bind its real sockets to vrf-mgmt.
func TestWarmHeartbeatRetryResolvesNewVRFMembership12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, _, control, vrf := newKernelVRFRetryFixture12168(t)
	if err := netlink.LinkSetMaster(control, vrf); err != nil {
		t.Fatalf("enslave control interface to management VRF: %v", err)
	}
	d.publishMgmtVRFIfaces(nil)
	ctx, cancel := context.WithTimeout(d.daemonCtx, 7*time.Second)
	defer cancel()
	commsCtx, gen, cancelComms := d.beginClusterCommsEpoch(ctx)
	defer cancelComms()
	done := make(chan struct{})
	go func() {
		d.startHeartbeatWithRetryForEpoch(commsCtx, "em0", "198.51.100.2", gen)
		close(done)
	}()
	time.Sleep(150 * time.Millisecond)
	if d.cluster.HeartbeatRunning() {
		t.Fatal("premise failed: heartbeat started before VRF membership was published")
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat retry did not finish after publishing VRF membership")
	}
	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
}

func waitForHeartbeatVRF12168(t *testing.T, manager *cluster.Manager, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if manager.HeartbeatRunning() && manager.HeartbeatVRFDevice() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("heartbeat did not become running with VRF device %q (running=%v device=%q)",
		want, manager.HeartbeatRunning(), manager.HeartbeatVRFDevice())
}

func warmVRFCommsGeneration12168(d *Daemon) uint64 {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	return d.clusterCommsGen
}

type warmVRFSocket12168 struct {
	FD, Port, Kind, Ifindex int
	Device, Identity        string
}

func warmVRFSockets12168(t *testing.T) []warmVRFSocket12168 {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var result []warmVRFSocket12168
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		sa, err := unix.Getsockname(fd)
		if err != nil {
			continue
		}
		ip, ok := sa.(*unix.SockaddrInet4)
		if !ok || ip.Addr != [4]byte{198, 51, 100, 1} {
			continue
		}
		kind, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if kind == unix.SOCK_STREAM {
			accepting, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
			if accepting != 1 {
				continue
			}
		}
		device, deviceErr := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if deviceErr != nil {
			device = "ERROR:" + deviceErr.Error()
		}
		ifindex, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, 62)
		identity, _ := os.Readlink("/proc/self/fd/" + entry.Name())
		result = append(result, warmVRFSocket12168{
			FD: fd, Port: ip.Port, Kind: kind, Ifindex: ifindex, Device: device, Identity: identity,
		})
	}
	return result
}

func waitWarmVRFSockets12168(t *testing.T, want string) []warmVRFSocket12168 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sockets := warmVRFSockets12168(t)
		ports := map[int]bool{}
		clean := true
		for _, socket := range sockets {
			if socket.Port == 4784 || socket.Port == 4785 || socket.Port == 50051 {
				ports[socket.Port] = true
				if socket.Device != want {
					clean = false
				}
			}
		}
		if clean && ports[4784] && ports[4785] && ports[50051] {
			return sockets
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("all comms listeners did not converge to %q: %+v", want, warmVRFSockets12168(t))
	return nil
}

func warmVRFSocketControl12168(device string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			if device != "" {
				socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
			}
		}); err != nil {
			return err
		}
		return socketErr
	}
}

func warmVRFTraffic12168(t *testing.T, device string) {
	t.Helper()
	listenConfig := net.ListenConfig{Control: warmVRFSocketControl12168(device)}
	pc, err := listenConfig.ListenPacket(context.Background(), "udp4", "198.51.100.2:4784")
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, from, err := pc.ReadFrom(buf)
	_ = pc.Close()
	if err != nil {
		t.Fatalf("heartbeat wire receive device=%q: %v", device, err)
	}
	if n < 4 || string(buf[:4]) != "BPFX" {
		t.Fatalf("unexpected heartbeat frame: %x", buf[:n])
	}
	for _, port := range []int{4785, 50051} {
		dialer := net.Dialer{
			Timeout:   time.Second,
			Control:   warmVRFSocketControl12168(device),
			LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.2")},
		}
		conn, err := dialer.Dial("tcp4", fmt.Sprintf("198.51.100.1:%d", port))
		if err != nil {
			t.Fatalf("listener %d device=%q: %v", port, device, err)
		}
		_ = conn.Close()
	}
	t.Logf("wire heartbeat bytes=%d source=%s device=%q; TCP accepts on 4785/50051", n, from, device)
}

type failManagementBind12168 struct {
	*netlink.Handle
	fail bool
}

func (ops *failManagementBind12168) LinkSetMaster(link, master netlink.Link) error {
	if ops.fail && link.Attrs().Name == "em0" {
		return unix.EBUSY
	}
	return ops.Handle.LinkSetMaster(link, master)
}

func TestWarmFailedBootPublishInRetryWindow12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, cfg, control, vrf := newKernelVRFRetryFixture12168(t)
	if err := netlink.LinkSetMaster(control, vrf); err != nil {
		t.Fatal(err)
	}
	d.publishMgmtVRFIfaces(nil)
	d.startClusterComms(d.daemonCtx)
	time.Sleep(1500 * time.Millisecond)
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	_ = d.applyTailReconciles(cfg, applyPhaseErrors{})
	sockets := waitWarmVRFSockets12168(t, config.ManagementVRFDeviceName)
	if got := d.activeTransport().VRFDevice; got != config.ManagementVRFDeviceName {
		t.Fatalf("warm publish in retry window transport = %q, want vrf-mgmt", got)
	}
	t.Logf("warm publish in retry window: gen=%d key=%+v sockets=%+v",
		warmVRFCommsGeneration12168(d), d.activeTransport(), sockets)
	warmVRFTraffic12168(t, config.ManagementVRFDeviceName)
}

func TestWarmFailedBootPublishAfterRetryWindow12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, cfg, control, vrf := newKernelVRFRetryFixture12168(t)
	if err := netlink.LinkSetMaster(control, vrf); err != nil {
		t.Fatal(err)
	}
	d.publishMgmtVRFIfaces(nil)
	d.startClusterComms(d.daemonCtx)
	time.Sleep(63 * time.Second)
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	_ = d.applyTailReconciles(cfg, applyPhaseErrors{})
	sockets := waitWarmVRFSockets12168(t, config.ManagementVRFDeviceName)
	if got := d.activeTransport().VRFDevice; got != config.ManagementVRFDeviceName {
		t.Fatalf("warm publish after retry window transport = %q, want vrf-mgmt", got)
	}
	t.Logf("warm publish after retry window: gen=%d key=%+v sockets=%+v",
		warmVRFCommsGeneration12168(d), d.activeTransport(), sockets)
	warmVRFTraffic12168(t, config.ManagementVRFDeviceName)
}

func TestReassertConvergenceRestartsCommsWithoutCommit12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, cfg, _, _ := newKernelVRFRetryFixture12168(t)
	d.startClusterComms(d.daemonCtx)
	waitWarmVRFSockets12168(t, "")
	waitForHeartbeatVRF12168(t, d.cluster, "")
	handle, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	ops := &failManagementBind12168{Handle: handle, fail: true}
	d.routing = routing.NewManagerWithLinkOpsForTest(ops)
	d.applySem = semaphore.NewWeighted(1)
	if ctxErr, vrfErr := d.applyVRFReconcile(context.Background(), cfg); ctxErr != nil || vrfErr != nil {
		t.Fatalf("device reconcile: %v %v", ctxErr, vrfErr)
	}
	if err := d.rebindManagementVRFIfaces(cfg); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("expected injected EBUSY, got %v", err)
	}
	if err := restartHeartbeatAfterRebind(d.cluster); err != nil {
		t.Fatalf("still-main heartbeat restart: %v", err)
	}
	_ = d.applyTailReconciles(cfg, applyPhaseErrors{Networkd: unix.EBUSY})
	before := warmVRFCommsGeneration12168(d)
	ops.fail = false
	d.reassertMgmtVRFOnce(context.Background())
	if after := warmVRFCommsGeneration12168(d); after == before {
		t.Fatalf("reassert-only convergence did not restart comms: generation=%d", before)
	}
	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
	waitWarmVRFSockets12168(t, config.ManagementVRFDeviceName)
	warmVRFTraffic12168(t, config.ManagementVRFDeviceName)
}

func TestReassertConvergencePersistsWithoutCommit12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, cfg, _, _ := newKernelVRFRetryFixture12168(t)
	d.startClusterComms(d.daemonCtx)
	waitWarmVRFSockets12168(t, "")
	waitForHeartbeatVRF12168(t, d.cluster, "")
	handle, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	ops := &failManagementBind12168{Handle: handle, fail: true}
	d.routing = routing.NewManagerWithLinkOpsForTest(ops)
	d.applySem = semaphore.NewWeighted(1)
	_, _ = d.applyVRFReconcile(context.Background(), cfg)
	bindErr := d.rebindManagementVRFIfaces(cfg)
	if !errors.Is(bindErr, unix.EBUSY) {
		t.Fatalf("expected injected EBUSY, got %v", bindErr)
	}
	_ = restartHeartbeatAfterRebind(d.cluster)
	_ = d.applyTailReconciles(cfg, applyPhaseErrors{Networkd: bindErr})
	ops.fail = false
	before := warmVRFCommsGeneration12168(d)
	d.reassertMgmtVRFOnce(context.Background())
	if after := warmVRFCommsGeneration12168(d); after == before {
		t.Fatalf("reassert-only convergence did not restart comms: generation=%d", before)
	}
	gen := warmVRFCommsGeneration12168(d)
	active := d.activeTransport()
	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
	waitWarmVRFSockets12168(t, config.ManagementVRFDeviceName)
	warmVRFTraffic12168(t, config.ManagementVRFDeviceName)
	time.Sleep(10 * time.Second)
	d.reassertMgmtVRFOnce(context.Background())
	if after := warmVRFCommsGeneration12168(d); after != gen || d.activeTransport() != active {
		t.Fatalf("idle reassert changed transport epoch without drift: gen=%d->%d key=%+v->%+v",
			gen, after, active, d.activeTransport())
	}
	warmVRFTraffic12168(t, config.ManagementVRFDeviceName)
}

func TestConvergingCommitRestartsHeartbeatWithoutStaleRetries12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, cfg, _, _ := newKernelVRFRetryFixture12168(t)
	d.startClusterComms(d.daemonCtx)
	waitWarmVRFSockets12168(t, "")
	waitForHeartbeatVRF12168(t, d.cluster, "")
	handle, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	d.routing = routing.NewManagerWithLinkOpsForTest(&failManagementBind12168{Handle: handle})
	if ctxErr, vrfErr := d.applyVRFReconcile(context.Background(), cfg); ctxErr != nil || vrfErr != nil {
		t.Fatalf("device reconcile: %v %v", ctxErr, vrfErr)
	}
	var networkdErr error
	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		networkdErr = errors.Join(networkdErr, err)
	}
	started := time.Now()
	if err := restartHeartbeatAfterRebind(d.cluster); err != nil {
		networkdErr = errors.Join(networkdErr, err)
	}
	restartDuration := time.Since(started)
	commitErr := d.applyTailReconciles(cfg, applyPhaseErrors{Networkd: networkdErr})
	if commitErr != nil {
		t.Fatalf("converging commit returned error: %v", commitErr)
	}
	if restartDuration >= 2*time.Second {
		t.Fatalf("2.7 heartbeat restart took %v, want one fresh-device attempt, not stale-device retries", restartDuration)
	}
	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
	if !d.cluster.HeartbeatRunning() || d.cluster.HeartbeatVRFDevice() != config.ManagementVRFDeviceName {
		t.Fatalf("heartbeat did not restart on vrf-mgmt: running=%v device=%q",
			d.cluster.HeartbeatRunning(), d.cluster.HeartbeatVRFDevice())
	}
	waitWarmVRFSockets12168(t, config.ManagementVRFDeviceName)
	warmVRFTraffic12168(t, config.ManagementVRFDeviceName)
}

func prepareStripRetryFixture12168(t *testing.T) (*Daemon, *config.Config) {
	t.Helper()
	d, cfg, control, vrf := newKernelVRFRetryFixture12168(t)
	addrs, err := netlink.AddrList(control, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("list startup control addresses: %v", err)
	}
	for i := range addrs {
		if err := netlink.AddrDel(control, &addrs[i]); err != nil {
			t.Fatalf("remove startup control address %s: %v", addrs[i], err)
		}
	}
	if err := netlink.LinkSetMaster(control, vrf); err != nil {
		t.Fatalf("prepare converged control interface: %v", err)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	d.startClusterComms(d.daemonCtx)
	if got := d.activeTransport().VRFDevice; got != config.ManagementVRFDeviceName {
		t.Fatalf("epoch start key VRF = %q, want %q", got, config.ManagementVRFDeviceName)
	}
	time.Sleep(500 * time.Millisecond)

	if err := netlink.LinkSetNoMaster(control); err != nil {
		t.Fatalf("simulate networkd stripping the control interface: %v", err)
	}
	for _, cidr := range []string{"198.51.100.1/24", "198.51.100.2/24"} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("parse control address %s: %v", cidr, err)
		}
		if err := netlink.AddrAdd(control, addr); err != nil {
			t.Fatalf("assign control address %s: %v", cidr, err)
		}
	}
	waitWarmVRFSockets12168(t, "")
	if !d.activeTransport().BindingChanged {
		t.Fatal("off-key startup bind did not mark the epoch transport changed")
	}
	return d, cfg
}

func installMgmtVRFReassertFixture12168(t *testing.T, d *Daemon) {
	t.Helper()
	handle, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	d.routing = routing.NewManagerWithLinkOpsForTest(handle)
	d.applySem = semaphore.NewWeighted(1)
	prev := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return nil }
	t.Cleanup(func() {
		mgmtVRFRouteReconcileFn = prev
		handle.Close()
	})
}

func assertWarmVRFIfindex12168(t *testing.T) {
	t.Helper()
	sockets := waitWarmVRFSockets12168(t, config.ManagementVRFDeviceName)
	vrf, err := netlink.LinkByName(config.ManagementVRFDeviceName)
	if err != nil || vrf == nil || vrf.Attrs() == nil {
		t.Fatalf("lookup management VRF for socket ifindex: link=%v err=%v", vrf, err)
	}
	for _, socket := range sockets {
		if socket.Port != 4784 && socket.Port != 4785 && socket.Port != 50051 {
			continue
		}
		if socket.Ifindex != vrf.Attrs().Index {
			t.Errorf("socket %d SO_BINDTOIFINDEX=%d, want vrf-mgmt ifindex %d",
				socket.Port, socket.Ifindex, vrf.Attrs().Index)
		}
	}
}

// X1: sockets bind while networkd has stripped the interface even though the
// epoch key was computed while it was still a management-VRF member. A
// successful #11448 reassert must replace all three sockets, not trust the
// unchanged epoch-start key.
func TestStripRetryReassertRestartsEveryCommsSocket12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, _ := prepareStripRetryFixture12168(t)
	installMgmtVRFReassertFixture12168(t, d)
	before := warmVRFCommsGeneration12168(d)
	d.reassertMgmtVRFOnce(context.Background())
	if after := warmVRFCommsGeneration12168(d); after == before {
		t.Fatalf("reassert did not replace off-key comms epoch: generation=%d", before)
	}
	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
	assertWarmVRFIfindex12168(t)
	warmVRFTraffic12168(t, config.ManagementVRFDeviceName)
}

// X2: a later commit's step 2.7 restarts only the heartbeat. The sticky
// off-key mark must make step 20 replace session sync and fabric gRPC too.
func TestStripRetryStep27RestartsEveryCommsSocket12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d, cfg := prepareStripRetryFixture12168(t)
	installMgmtVRFReassertFixture12168(t, d)
	before := warmVRFCommsGeneration12168(d)
	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		t.Fatalf("step 2.7 rebind: %v", err)
	}
	if err := restartHeartbeatAfterRebind(d.cluster); err != nil {
		t.Fatalf("step 2.7 heartbeat restart: %v", err)
	}
	if got := d.cluster.HeartbeatVRFDevice(); got != config.ManagementVRFDeviceName {
		t.Fatalf("step 2.7 heartbeat VRF = %q, want %q", got, config.ManagementVRFDeviceName)
	}
	devices := make(map[int]string)
	for _, socket := range warmVRFSockets12168(t) {
		devices[socket.Port] = socket.Device
	}
	if devices[4784] != config.ManagementVRFDeviceName ||
		devices[4785] != "" || devices[50051] != "" {
		t.Fatalf("step 2.7 must refresh only heartbeat before step 20, got %v", devices)
	}
	if err := d.applyTailReconciles(cfg, applyPhaseErrors{}); err != nil {
		t.Fatalf("commit step 20: %v", err)
	}
	if after := warmVRFCommsGeneration12168(d); after == before {
		t.Fatalf("step 20 did not replace off-key comms epoch: generation=%d", before)
	}
	waitForHeartbeatVRF12168(t, d.cluster, config.ManagementVRFDeviceName)
	assertWarmVRFIfindex12168(t)
	warmVRFTraffic12168(t, config.ManagementVRFDeviceName)
}

var dualFabricVRFLines12168 = []string{
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster authentication-key dual-fabric-vrf-test-12168",
	"set chassis cluster fabric-interface fab0",
	"set chassis cluster fabric-peer-address 198.51.110.2",
	"set chassis cluster fabric1-interface fab1",
	"set chassis cluster fabric1-peer-address 198.51.111.2",
}

func newDualFabricVRFFixture12168(t *testing.T, includeFab1 bool) *Daemon {
	t.Helper()
	installFakeNetworkctl(t)
	stateDir := t.TempDir()
	if err := unix.Mount(stateDir, "/var/lib/xpf", "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("cannot isolate keyed heartbeat epoch state: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount("/var/lib/xpf", 0); err != nil {
			t.Errorf("unmount isolated HA state directory: %v", err)
		}
	})

	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName}, Table: config.ManagementVRFTableID}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Fatalf("cannot create management VRF in isolated namespace: %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("bring up management VRF: %v", err)
	}
	fab0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fab0"}}
	if err := netlink.LinkAdd(fab0); err != nil {
		t.Fatalf("create primary fabric: %v", err)
	}
	if err := netlink.LinkSetUp(fab0); err != nil {
		t.Fatalf("bring up primary fabric: %v", err)
	}
	if err := netlink.LinkSetMaster(fab0, vrf); err != nil {
		t.Fatalf("enslave primary fabric to management VRF: %v", err)
	}
	for _, cidr := range []string{"198.51.110.1/24", "198.51.110.2/24"} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("parse primary fabric address %s: %v", cidr, err)
		}
		if err := netlink.AddrAdd(fab0, addr); err != nil {
			t.Fatalf("assign primary fabric address %s: %v", cidr, err)
		}
	}
	if includeFab1 {
		fab1 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fab1"}}
		if err := netlink.LinkAdd(fab1); err != nil {
			t.Fatalf("create secondary fabric: %v", err)
		}
		if err := netlink.LinkSetUp(fab1); err != nil {
			t.Fatalf("bring up secondary fabric: %v", err)
		}
		for _, cidr := range []string{"198.51.111.1/24", "198.51.111.2/24"} {
			addr, err := netlink.ParseAddr(cidr)
			if err != nil {
				t.Fatalf("parse secondary fabric address %s: %v", cidr, err)
			}
			if err := netlink.AddrAdd(fab1, addr); err != nil {
				t.Fatalf("assign secondary fabric address %s: %v", cidr, err)
			}
		}
	}

	store := testStoreWithSetConfig(t, dualFabricVRFLines12168)
	ctx, cancel := context.WithCancel(context.Background())
	handle, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		store:     store,
		networkd:  networkd.NewInDir(t.TempDir()),
		vrrpMgr:   vrrp.NewManager(),
		cluster:   cluster.NewManager(0, 1),
		daemonCtx: ctx,
		opts:      Options{NoDataplane: true},
		routing:   routing.NewManagerWithLinkOpsForTest(handle),
	}
	d.grpcSrv = grpcapi.NewServer("", grpcapi.Config{Store: store, Cluster: d.cluster})
	members := map[string]bool{"fab0": true, "fab1": true}
	d.publishMgmtVRFIfaces(members)
	t.Cleanup(func() {
		d.stopClusterComms()
		d.cluster.Stop()
		cancel()
		handle.Close()
	})
	return d
}

func fabricVRFSockets12168(t *testing.T, ip string) map[int]string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	wantIP := net.ParseIP(ip).To4()
	var want [4]byte
	copy(want[:], wantIP)
	ports := make(map[int]string)
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		sa, err := unix.Getsockname(fd)
		if err != nil {
			continue
		}
		addr, ok := sa.(*unix.SockaddrInet4)
		if !ok || addr.Addr != want || (addr.Port != 4785 && addr.Port != 50051) {
			continue
		}
		if addr.Port == 50051 {
			accepting, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
			if accepting != 1 {
				continue
			}
		}
		device, err := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if err != nil {
			device = "ERROR:" + err.Error()
		}
		ports[addr.Port] = device
	}
	return ports
}

func waitFabricVRFSockets12168(t *testing.T, ip, device string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ports := fabricVRFSockets12168(t, ip)
		if ports[4785] == device && ports[50051] == device {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("primary fabric listeners did not bind to %q: %v", device, fabricVRFSockets12168(t, ip))
}

func fabricVRFTraffic12168(t *testing.T, localIP, peerIP, device string) {
	t.Helper()
	for _, port := range []int{4785, 50051} {
		dialer := net.Dialer{
			Timeout:   time.Second,
			Control:   warmVRFSocketControl12168(device),
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(peerIP)},
		}
		conn, err := dialer.Dial("tcp4", net.JoinHostPort(localIP, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("primary fabric listener %d device=%q: %v", port, device, err)
		}
		_ = conn.Close()
	}
	t.Logf("primary fabric accepted TCP on 4785/50051 through %s", device)
}

// F1b: an addressed but not-yet-enslaved fab1 must not veto the healthy
// primary-fabric session-sync and gRPC listeners.
func TestDualFabricSecondaryOutsideVRFKeepsPrimary12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d := newDualFabricVRFFixture12168(t, true)
	d.startClusterComms(d.daemonCtx)
	waitFabricVRFSockets12168(t, "198.51.110.1", config.ManagementVRFDeviceName, 10*time.Second)
	fabricVRFTraffic12168(t, "198.51.110.1", "198.51.110.2", config.ManagementVRFDeviceName)
}

// F1a: an absent fab1 takes its address-resolution timeout, then the healthy
// primary-only transport must still bind in vrf-mgmt.
func TestDualFabricSecondaryMissingKeepsPrimary12168(t *testing.T) {
	if !isolatedVRFRetryChild12168(t) {
		return
	}
	d := newDualFabricVRFFixture12168(t, false)
	d.startClusterComms(d.daemonCtx)
	waitFabricVRFSockets12168(t, "198.51.110.1", config.ManagementVRFDeviceName, 42*time.Second)
	fabricVRFTraffic12168(t, "198.51.110.1", "198.51.110.2", config.ManagementVRFDeviceName)
}
