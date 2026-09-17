package nfqueue

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type memorySnapshot struct {
	rssBytes    uint64
	cgroupBytes uint64
	slabBytes   uint64
	goAlloc     uint64
}

// TestMeasureMemory9506 is M2 from the Phase-0 plan. It accounts for
// userspace payload/descriptors plus available cgroup and global slab deltas;
// the latter are explicitly diagnostic because this environment does not
// expose a per-NFQUEUE slab/socket attribution API. The real-box gate must
// retain that residual rather than treating RSS alone as kernel accounting.
func TestMeasureMemory9506(t *testing.T) {
	requireNetNS(t)
	q, err := Open(65)
	if err != nil {
		t.Fatalf("M2 Open: %v", err)
	}
	defer q.Close()
	release, err := divertTestTraffic(t, q.ID())
	if err != nil {
		t.Fatalf("M2 divert: %v", err)
	}
	defer closeTestReceiver()
	defer release()
	sender, err := openTestSender()
	if err != nil {
		t.Fatalf("M2 sender: %v", err)
	}
	defer sender.Close()

	before := memoryNow()
	postDrain := make([]memorySnapshot, 0, 3)
	for cycle := 0; cycle < 3; cycle++ {
		held := make([]*Packet, phase0MemoryDatagrams)
		deadline := time.Now().Add(30 * time.Second)
		cycleStart := memoryNow()
		for i := range held {
			if err := sendTestDatagramConn(sender, phase0PayloadSize(i), i, deadline); err != nil {
				t.Fatalf("M2 cycle=%d send=%d: %v", cycle+1, i, err)
			}
			pkt, err := q.Recv(deadline)
			if err != nil {
				t.Fatalf("M2 cycle=%d recv=%d: %v", cycle+1, i, err)
			}
			held[i] = pkt
		}
		afterHold := memoryNow()
		if cycle == 0 {
			measureTunPayloads(t, held)
		}
		t.Logf("M2 cycle=%d hold rss_delta=%d cgroup_delta=%d slab_delta=%d go_alloc_delta=%d per_packet_rss=%d", cycle+1,
			delta(afterHold.rssBytes, cycleStart.rssBytes),
			delta(afterHold.cgroupBytes, cycleStart.cgroupBytes),
			delta(afterHold.slabBytes, cycleStart.slabBytes),
			delta(afterHold.goAlloc, cycleStart.goAlloc),
			delta(afterHold.rssBytes, cycleStart.rssBytes)/phase0MemoryDatagrams)
		if d := delta(afterHold.rssBytes, cycleStart.rssBytes) / phase0MemoryDatagrams; d > 64*1024 {
			t.Fatalf("M2 RSS bound: %d bytes/held packet > 65536", d)
		}
		for i := 0; i < len(held); {
			end := i + 8
			if end > len(held) {
				end = len(held)
			}
			if err := q.VerdictBatch(VerdictAccept, held[i:end]); err != nil {
				t.Fatalf("M2 cycle=%d drain=%d..%d: %v", cycle+1, i, end, err)
			}
			i = end
		}
		runtime.GC()
		afterDrain := memoryNow()
		postDrain = append(postDrain, afterDrain)
		t.Logf("M2 cycle=%d drain rss=%d cgroup=%d slab=%d go_alloc=%d", cycle+1,
			afterDrain.rssBytes, afterDrain.cgroupBytes, afterDrain.slabBytes, afterDrain.goAlloc)
	}
	if len(postDrain) == 3 {
		first := postDrain[0].rssBytes
		third := postDrain[2].rssBytes
		if first == 0 {
			first = before.rssBytes
		}
		if third > first+64*1024 && third > first*3/2 {
			t.Fatalf("M2 RSS growth gate: cycle3=%d cycle1=%d", third, first)
		}
	}
	stats := q.Stats()
	if stats.Held != phase0MemoryDatagrams*3 || stats.Accepted != phase0MemoryDatagrams*3 || stats.VerdictErrors != 0 {
		t.Fatalf("M2 queue stats=%+v, want held=accepted=%d errors=0", stats, phase0MemoryDatagrams*3)
	}

	measureM2OverCap(t, q, sender)
}
func measureTunPayloads(t *testing.T, held []*Packet) {
	t.Helper()
	sink, err := OpenTunSink("xpf9506m")
	if err != nil {
		t.Fatalf("M2 TUN leg unavailable: %v", err)
	}
	defer sink.Close()
	link, err := netlink.LinkByName(sink.Name())
	if err != nil {
		t.Fatalf("M2 find TUN link %q: %v", sink.Name(), err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("M2 bring TUN link %q up: %v", sink.Name(), err)
	}
	before := memoryNow()
	eagain := 0
	successFrames := 0
	successBytes := uint64(0)
	minBytes, maxBytes := 0, 0
	for i, pkt := range held {
		frame := pkt.Payload()
		n, err := sink.WriteFrame(frame)
		if errors.Is(err, unix.EAGAIN) {
			eagain++
			continue
		}
		if err != nil {
			t.Fatalf("M2 TUN write %d: %v", i, err)
		}
		successFrames++
		successBytes += uint64(n)
		if minBytes == 0 || n < minBytes {
			minBytes = n
		}
		if n > maxBytes {
			maxBytes = n
		}
	}
	after := memoryNow()
	if sink.FramesWritten() != uint64(successFrames) || sink.BytesWritten() != successBytes {
		t.Fatalf("M2 TUN accounting frames=%d/%d bytes=%d/%d", sink.FramesWritten(), successFrames, sink.BytesWritten(), successBytes)
	}
	t.Logf("M2 TUN attempts=%d complete_frames=%d bytes=%d eagain=%d per_frame_bytes=%d..%d rss_delta=%d cgroup_delta=%d slab_delta=%d go_alloc_delta=%d",
		sink.Attempts(), sink.FramesWritten(), sink.BytesWritten(), eagain, minBytes, maxBytes,
		delta(after.rssBytes, before.rssBytes), delta(after.cgroupBytes, before.cgroupBytes),
		delta(after.slabBytes, before.slabBytes), delta(after.goAlloc, before.goAlloc))
}

func measureM2OverCap(t *testing.T, q *Queue, sender net.Conn) {
	t.Helper()
	pool, err := NewFragPool(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	key := testFragmentKey(4, 9506)
	for i := 0; i < 2; i++ {
		if _, err := pool.Insert(key, Fragment{Offset: uint32(i), More: true, Data: []byte{byte(i)}}); err != nil {
			t.Fatalf("M2 over-cap setup %d: %v", i, err)
		}
	}
	if _, err := pool.Insert(key, Fragment{Offset: 2, More: true, Data: []byte{2}}); !errors.Is(err, ErrFragmentCapacity) {
		t.Fatalf("M2 over-cap error=%v, want ErrFragmentCapacity", err)
	}
	if stats := pool.Stats(); stats.Flows != 0 || stats.CapacityDrops != 1 {
		t.Fatalf("M2 over-cap stats=%+v", stats)
	}
	if complete, err := pool.Insert(testFragmentKey(4, 9507), Fragment{More: false, Data: []byte("recovered")}); !complete || err != nil {
		t.Fatalf("M2 pool recovery complete=%t err=%v", complete, err)
	}

	const overCapSends = nfqueueQueueMaxLen + 256
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; i < overCapSends; i++ {
		if err := sendTestDatagramConn(sender, 64, i, deadline); err != nil {
			t.Fatalf("M2 NFQUEUE over-cap send=%d: %v", i, err)
		}
	}
	held := make([]*Packet, 0, nfqueueQueueMaxLen)
	for {
		pkt, err := q.Recv(time.Now().Add(200 * time.Millisecond))
		if errors.Is(err, ErrTimeout) {
			break
		}
		if err != nil {
			t.Fatalf("M2 NFQUEUE over-cap receive: %v", err)
		}
		held = append(held, pkt)
	}
	if len(held) == 0 || len(held) >= overCapSends {
		t.Fatalf("M2 NFQUEUE over-cap held=%d sends=%d, want bounded loss", len(held), overCapSends)
	}
	for i := 0; i < len(held); i += 8 {
		end := i + 8
		if end > len(held) {
			end = len(held)
		}
		if err := q.VerdictBatch(VerdictDrop, held[i:end]); err != nil {
			t.Fatalf("M2 NFQUEUE over-cap drain %d..%d: %v", i, end, err)
		}
	}
	recoveryPayload := []byte("m2-recovery-9506")
	if err := sendTestPayloadConn(sender, recoveryPayload, time.Now().Add(5*time.Second)); err != nil {
		t.Fatalf("M2 NFQUEUE recovery send: %v", err)
	}
	recovered, err := q.Recv(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatalf("M2 NFQUEUE recovery receive: %v", err)
	}
	if len(recovered.Payload()) < 28 || recovered.Payload()[0]>>4 != 4 {
		t.Fatalf("M2 NFQUEUE recovery payload malformed")
	}
	ihl := int(recovered.Payload()[0]&0x0f) * 4
	if ihl < 20 || len(recovered.Payload()) < ihl+8 || !bytes.Contains(recovered.Payload()[ihl+8:], recoveryPayload) {
		t.Fatalf("M2 NFQUEUE recovery packet did not carry unique payload")
	}
	if err := recovered.Verdict(VerdictAccept); err != nil {
		t.Fatalf("M2 NFQUEUE recovery verdict: %v", err)
	}
	t.Logf("M2 NFQUEUE over-cap sends=%d held=%d dropped_before_receive=%d recovery=accepted", overCapSends, len(held), overCapSends-len(held))
}

const phase0MemoryDatagrams = 4096

func delta(after, before uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}

func memoryNow() memorySnapshot {
	return memorySnapshot{
		rssBytes:    procRSSBytes(),
		cgroupBytes: readUintFile("/sys/fs/cgroup/memory.current"),
		slabBytes:   meminfoValue("Slab:"),
		goAlloc:     goAllocBytes(),
	}
}

func procRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

func goAllocBytes() uint64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.Alloc
}

func readUintFile(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func meminfoValue(name string) uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == name {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				if len(fields) >= 3 && fields[2] == "kB" {
					return value * 1024
				}
				return value
			}
		}
	}
	return 0
}
