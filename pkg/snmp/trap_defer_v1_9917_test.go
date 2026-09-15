package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// drainTrapQueue9917 removes every buffered job without blocking.
func drainTrapQueue9917(agent *Agent) []trapJob {
	var jobs []trapJob
	for {
		select {
		case job := <-agent.trapQueue:
			jobs = append(jobs, job)
		default:
			return jobs
		}
	}
}

func v1TrapAgent9917(version string) *Agent {
	agent := &Agent{
		cfg: &config.SNMPConfig{
			TrapGroups: map[string]*config.SNMPTrapGroup{
				"g1": {Name: "g1", Targets: []string{"127.0.0.1"}, Version: version},
			},
		},
		startTime: time.Now(),
	}
	agent.trapQueue = make(chan trapJob, 16)
	agent.trapWorkerOnce.Do(func() {}) // consume the Once so no worker starts
	return agent
}

// TestSendLinkTrapsDefersV1Build9917 is the F-134 RED cell: for a `version v1`
// group the per-target packet build (which pays a DNS lookup plus an up-to-2s
// dial inside agentAddrForTarget) must NOT run on the caller's (link-monitor)
// goroutine. The queued job must therefore carry no prebuilt packet — the trap
// worker builds it. RED on base (every job carries a caller-built pkt).
func TestSendLinkTrapsDefersV1Build9917(t *testing.T) {
	agent := v1TrapAgent9917("v1")
	agent.NotifyLinkDown(7, "ge-0/0/0")

	jobs := drainTrapQueue9917(agent)
	if len(jobs) != 1 {
		t.Fatalf("v1 linkDown enqueued %d jobs, want 1", len(jobs))
	}
	if jobs[0].pkt != nil {
		t.Fatalf("F-134: v1 trap packet (%d bytes) was built on the caller's goroutine; want a deferred job (nil pkt) built on the trap worker", len(jobs[0].pkt))
	}
	if !jobs[0].deferredV1 {
		t.Fatal("F-134: deferred v1 job does not carry deferredV1 (worker would send an empty packet)")
	}
}

// TestSendLinkTrapsAllVersionDefersOnlyV19917 pins the `version all` split: the
// v1 leg (agent-addr dial) is deferred while the v2c leg (pure BER, no I/O)
// stays prebuilt on the caller. RED on base (both legs prebuilt).
func TestSendLinkTrapsAllVersionDefersOnlyV19917(t *testing.T) {
	agent := v1TrapAgent9917("all")
	agent.NotifyLinkDown(7, "ge-0/0/0")

	jobs := drainTrapQueue9917(agent)
	if len(jobs) != 2 {
		t.Fatalf("all-version linkDown enqueued %d jobs, want 2 (v1 + v2c)", len(jobs))
	}
	var deferred, prebuilt int
	for _, job := range jobs {
		if job.pkt == nil {
			deferred++
		} else {
			prebuilt++
		}
	}
	if deferred != 1 || prebuilt != 1 {
		t.Fatalf("F-134: all-version jobs = %d deferred + %d prebuilt, want 1 + 1 (v1 deferred, v2c prebuilt)", deferred, prebuilt)
	}
}

// TestTrapWorkerDeliversDeferredV19917 proves the deferred half of F-134: the
// worker builds the v1 Trap-PDU from the job parameters and delivers a valid v1
// trap whose agent-addr is the source toward the target. Revert-sensitive both
// ways: dropping the worker build delivers an empty packet (decode fails), and
// reverting the deferral keeps this green while the shape cells above go red.
func TestTrapWorkerDeliversDeferredV19917(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp loopback available: %v", err)
	}
	defer pc.Close()

	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{"public": {Name: "public"}},
			TrapGroups: map[string]*config.SNMPTrapGroup{
				"live": {Name: "live", Targets: []string{pc.LocalAddr().String()}, Version: "v1"},
			},
		},
		startTime: time.Now(),
	}
	defer agent.Stop() // abandon backlog, join the lazily started worker

	agent.NotifyLinkDown(7, "ge-0/0/0")

	buf := make([]byte, 4096)
	if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read deferred v1 trap: %v", err)
	}
	pkt := buf[:n]
	version, pduTag := decodeTrapVersionAndPDU(t, pkt)
	if version != snmpVersion1 || pduTag != pduSNMPv1Trap {
		t.Fatalf("deferred trap version/pdu = %d/0x%02x, want 0/0xa4 (v1 Trap-PDU)", version, pduTag)
	}
	if got := decodeAgentAddr9123(t, pkt); !got.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("deferred v1 agent-addr = %v, want 127.0.0.1 (source toward the target)", got)
	}
}

// TestTrapWorkerAllVersionOrder9917 pins the `version all` delivery contract:
// the v1 leg then the v2c leg, matching buildLinkTrapsForVersion's packet order.
// Single worker plus FIFO queue makes the order deterministic.
func TestTrapWorkerAllVersionOrder9917(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp loopback available: %v", err)
	}
	defer pc.Close()

	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{"public": {Name: "public"}},
			TrapGroups: map[string]*config.SNMPTrapGroup{
				"live": {Name: "live", Targets: []string{pc.LocalAddr().String()}, Version: "all"},
			},
		},
		startTime: time.Now(),
	}
	defer agent.Stop()

	agent.NotifyLinkDown(7, "ge-0/0/0")

	buf := make([]byte, 4096)
	if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	var got [2][2]int // (version, pduTag) per datagram, in arrival order
	for i := range got {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read all-version trap %d: %v", i, err)
		}
		version, pduTag := decodeTrapVersionAndPDU(t, buf[:n])
		got[i] = [2]int{version, int(pduTag)}
	}
	if got[0] != [2]int{snmpVersion1, pduSNMPv1Trap} {
		t.Errorf("first all-version trap = %d/0x%02x, want v1 0/0xa4", got[0][0], got[0][1])
	}
	if got[1] != [2]int{snmpVersion2c, pduSNMPv2Trap} {
		t.Errorf("second all-version trap = %d/0x%02x, want v2c 1/0xa7", got[1][0], got[1][1])
	}
}
