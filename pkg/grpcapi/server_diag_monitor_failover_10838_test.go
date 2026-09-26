package grpcapi

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/monitoriface"
)

var monitorKernelNamePattern10838 = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

type failoverMonitorDP10838 struct {
	dataplane.DataPlane
	counters map[int]uint64
}

func (failoverMonitorDP10838) IsLoaded() bool { return true }
func (d failoverMonitorDP10838) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{RxPackets: d.counters[ifindex] / 100, RxBytes: d.counters[ifindex]}, nil
}
func (failoverMonitorDP10838) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{Enabled: true}, nil
}

// TestMonitorInterfaceSingleDeviceChangeResetsBaseline10838 drives the real
// handler across a committed RETH-member change. It proves the second frame
// reads the new member, marks the old->new device transition, and restarts its
// delta from zero rather than comparing counters from different devices.
func TestMonitorInterfaceSingleDeviceChangeResetsBaseline10838(t *testing.T) {
	oldIface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	var newKernel string
	for _, candidate := range mustInterfaces10838(t) {
		if candidate.Name == "lo" || !monitorKernelNamePattern10838.MatchString(candidate.Name) {
			continue
		}
		resolved := monitoriface.ResolvePhysicalParent(candidate.Name)
		if resolved != "" && resolved != "lo" {
			if _, err := net.InterfaceByName(resolved); err == nil {
				newKernel = resolved
				break
			}
		}
	}
	if newKernel == "" {
		t.Skip("no second live kernel interface available for RETH member failover")
	}
	newIface, err := net.InterfaceByName(newKernel)
	if err != nil {
		t.Fatalf("new member %q disappeared: %v", newKernel, err)
	}

	store := monitorStore9144(t, monitorCfgRethA9144)
	memberConfig := strings.Replace(monitorCfgRethA9144, "    lo {", "    "+newKernel+" {", 1)
	if memberConfig == monitorCfgRethA9144 {
		t.Fatal("fixture could not replace the original RETH member")
	}
	s := &Server{
		store: store,
		dp: failoverMonitorDP10838{counters: map[int]uint64{
			oldIface.Index: 1000,
			newIface.Index: 9000,
		}},
	}
	stream := newTwoTickMonitorStream9144(func(n int) {
		if n == 1 {
			commitMonitorCfg9144(t, store, memberConfig)
		}
	})
	done := make(chan error, 1)
	go func() {
		done <- s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "reth0"}, stream)
	}()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("MonitorInterface: %v", err)
		}
	case <-time.After(20 * time.Second):
		stream.cancel()
		t.Fatal("MonitorInterface did not emit two frames")
	}
	if len(stream.frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(stream.frames))
	}
	if !strings.Contains(stream.frames[0], "Input  bytes:") {
		t.Fatalf("first frame lacks input counters:\n%s", stream.frames[0])
	}
	for _, want := range []string{
		"Interface: reth0",
		"reth0 device changed lo -> " + newKernel,
		"possible RG failover",
		"baseline reset",
	} {
		if !strings.Contains(stream.frames[1], want) {
			t.Errorf("second frame missing %q:\n%s", want, stream.frames[1])
		}
	}
	var inputLine string
	for _, line := range strings.Split(stream.frames[1], "\n") {
		if strings.Contains(line, "Input  bytes:") {
			inputLine = line
			break
		}
	}
	if inputLine == "" || !strings.Contains(inputLine, "[0]") {
		t.Fatalf("new member's first delta was not reset to zero; input line %q\n%s", inputLine, stream.frames[1])
	}
}

func mustInterfaces10838(t *testing.T) []net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	return interfaces
}
