package nfqueue

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type stageMeasurement struct {
	shape string
	ns    int64
}

type stageShape struct {
	batch    int
	affinity bool
}

// TestMeasureStages9506 is M1 from the Phase-0 plan. It measures the actual
// pipelined NFQUEUE receive/verdict transport in an isolated netns for inline,
// B=3, B=8 and owner-affinity grouping. The nine-round result is baseline data,
// not a performance kill gate. The UDP OUTPUT->INPUT harness is synthetic; the
// FORWARD/iif==stN XFRM path remains a loss-cluster gate.
func TestMeasureStages9506(t *testing.T) {
	requireNetNS(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cpus := measurementCPUs()
	if len(cpus) > 0 {
		if err := pinMeasurementThread(cpus[0]); err != nil {
			t.Logf("M1 main-thread pin unavailable: %v", err)
		} else {
			t.Logf("M1 main-thread cpu=%d", cpus[0])
		}
	}
	base := []stageShape{{batch: 1}, {batch: 3}, {batch: 8}, {batch: 8, affinity: true}}
	byShape := make(map[string][]stageMeasurement)
	for round := 0; round < phase0Rounds; round++ {
		// Counterbalance warm-up and scheduler state: every shape occupies
		// each order position before the predeclared five-round gate.
		for n := range base {
			shape := base[(n+round)%len(base)]
			name := phase0ShapeName(shape.batch, shape.affinity)
			ns, packets := runStageShape(t, shape.batch, shape.affinity, cpus)
			if packets != phase0Datagrams {
				t.Fatalf("M1 %s round %d processed %d packets, want %d", name, round+1, packets, phase0Datagrams)
			}
			byShape[name] = append(byShape[name], stageMeasurement{shape: name, ns: ns})
			t.Logf("M1 round=%d shape=%s packets=%d ns_per_packet=%d", round+1, name, packets, ns)
		}
	}
	for _, name := range []string{"inline", "batch-3", "batch-8", "batch-8-affinity"} {
		samples := byShape[name]
		if len(samples) != phase0Rounds {
			t.Fatalf("M1 %s has %d rounds, want %d", name, len(samples), phase0Rounds)
		}
		median, mean, variance, min, max := stageSummary(samples)
		t.Logf("M1 baseline pin shape=%s rounds=%d median_ns=%d mean_ns=%d variance_ns2=%d min_ns=%d max_ns=%d",
			name, len(samples), median, mean, variance, min, max)
	}
	inline := byShape["inline"]
	b8 := byShape["batch-8"]
	for i := range inline {
		t.Logf("M1 baseline round-table round=%d inline_ns=%d batch8_ns=%d delta_ns=%d",
			i+1, inline[i].ns, b8[i].ns, inline[i].ns-b8[i].ns)
	}
	t.Logf("M1 kill-gate disposition: baseline pins only; B=8 consistency remains open for the mechanism phase")
}

func stageMedian(samples []stageMeasurement) int64 {
	values := append([]stageMeasurement(nil), samples...)
	sort.Slice(values, func(i, j int) bool { return values[i].ns < values[j].ns })
	return values[len(values)/2].ns
}

func stageSummary(samples []stageMeasurement) (median, mean, variance, min, max int64) {
	if len(samples) == 0 {
		return 0, 0, 0, 0, 0
	}
	min, max = samples[0].ns, samples[0].ns
	var total int64
	for _, sample := range samples {
		if sample.ns < min {
			min = sample.ns
		}
		if sample.ns > max {
			max = sample.ns
		}
		total += sample.ns
	}
	mean = total / int64(len(samples))
	for _, sample := range samples {
		delta := sample.ns - mean
		variance += delta * delta
	}
	variance /= int64(len(samples))
	return stageMedian(samples), mean, variance, min, max
}

func runStageShape(t *testing.T, batch int, affinity bool, cpus []int) (nsPerPacket int64, packets int) {
	t.Helper()
	q, err := Open(61)
	if err != nil {
		t.Fatalf("M1 Open: %v", err)
	}
	defer q.Close()
	release, err := divertTestTraffic(t, q.ID())
	if err != nil {
		t.Fatalf("M1 divert: %v", err)
	}
	defer closeTestReceiver()
	defer release()
	senders, err := openTestFlowSenders(4)
	if err != nil {
		t.Fatalf("M1 senders: %v", err)
	}
	defer func() {
		for _, sender := range senders {
			_ = sender.Close()
		}
	}()

	deadline := time.Now().Add(30 * time.Second)
	sendErr := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if len(cpus) > 1 {
			_ = pinMeasurementThread(cpus[1])
		}
		for i := 0; i < phase0Datagrams; i++ {
			// Four stable source sockets provide four actual UDP 5-tuples.
			// Runs of four packets make the B=8 affinity row produce two
			// owner-homogeneous sub-batches instead of one artificial flow.
			flow := (i / 4) % len(senders)
			if err := sendTestDatagramFlowConn(senders[flow], phase0PayloadSize(i), flow, i, deadline); err != nil {
				sendErr <- fmt.Errorf("send packet %d flow %d: %w", i, flow, err)
				return
			}
		}
		sendErr <- nil
	}()

	start := time.Now()
	sent := 0
	for sent < phase0Datagrams {
		count := batch
		if remaining := phase0Datagrams - sent; count > remaining {
			count = remaining
		}
		pkts := make([]*Packet, count)
		for i := range pkts {
			pkt, err := q.Recv(deadline)
			if err != nil {
				t.Fatalf("M1 recv shape=%s packet=%d: %v", phase0ShapeName(batch, affinity), sent+i, err)
			}
			if len(pkt.Payload()) == 0 {
				t.Fatalf("M1 recv shape=%s packet=%d has empty payload", phase0ShapeName(batch, affinity), sent+i)
			}
			pkts[i] = pkt
		}
		if affinity && len(pkts) > 1 {
			// Sort by the actual IPv4 5-tuple extracted from each captured
			// packet, then submit one batch per owner. A large upstream batch
			// may therefore produce small owner sub-batches; this is the
			// cost the Codex r4 objection requires us to price.
			sort.SliceStable(pkts, func(i, j int) bool {
				return payloadOwner(pkts[i].Payload()) < payloadOwner(pkts[j].Payload())
			})
			for i := 0; i < len(pkts); {
				owner := payloadOwner(pkts[i].Payload())
				j := i + 1
				for j < len(pkts) && payloadOwner(pkts[j].Payload()) == owner {
					j++
				}
				if err := q.VerdictBatch(VerdictAccept, pkts[i:j]); err != nil {
					t.Fatalf("M1 affinity batch shape=%s packet=%d: %v", phase0ShapeName(batch, affinity), sent+i, err)
				}
				i = j
			}
		} else if batch == 1 {
			if err := pkts[0].Verdict(VerdictAccept); err != nil {
				t.Fatalf("M1 verdict shape=inline packet=%d: %v", sent, err)
			}
		} else if err := q.VerdictBatch(VerdictAccept, pkts); err != nil {
			t.Fatalf("M1 batch verdict shape=%s packet=%d: %v", phase0ShapeName(batch, affinity), sent, err)
		}
		sent += count
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("M1 producer shape=%s: %v", phase0ShapeName(batch, affinity), err)
	}
	elapsed := time.Since(start)
	stats := q.Stats()
	if stats.Held != phase0Datagrams || stats.Accepted != phase0Datagrams || stats.VerdictErrors != 0 {
		t.Fatalf("M1 shape=%s stats=%+v, want held=accepted=%d errors=0", phase0ShapeName(batch, affinity), stats, phase0Datagrams)
	}
	return elapsed.Nanoseconds() / phase0Datagrams, phase0Datagrams
}

func measurementCPUs() []int {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return nil
	}
	cpus := make([]int, 0, 2)
	for cpu := 0; cpu < runtime.NumCPU() && len(cpus) < 2; cpu++ {
		if set.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	return cpus
}

func pinMeasurementThread(cpu int) error {
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	return unix.SchedSetaffinity(0, &set)
}

func payloadOwner(payload []byte) uint32 {
	if len(payload) >= 20 && payload[0]>>4 == 4 {
		ihl := int(payload[0]&0x0f) * 4
		if ihl >= 20 && payload[9] == 17 && len(payload) >= ihl+8 {
			// The owner key is derived from the actual IPv4 5-tuple
			// (source/destination addresses, protocol and ports), not
			// from application bytes.
			h := uint32(2166136261)
			for _, b := range payload[12:20] {
				h ^= uint32(b)
				h *= 16777619
			}
			for _, b := range payload[ihl : ihl+4] {
				h ^= uint32(b)
				h *= 16777619
			}
			return h
		}
	}
	var h uint32 = 2166136261
	for _, b := range payload {
		h ^= uint32(b)
		h *= 16777619
	}
	return h
}

func TestPayloadOwnerUsesIPv4Tuple9506(t *testing.T) {
	frame := make([]byte, 28)
	frame[0] = 0x45
	frame[9] = 17
	frame[12], frame[13], frame[14], frame[15] = 192, 0, 2, 1
	frame[16], frame[17], frame[18], frame[19] = 198, 51, 100, 1
	binary.BigEndian.PutUint16(frame[20:22], 10001)
	binary.BigEndian.PutUint16(frame[22:24], harnessUDPPort)
	first := payloadOwner(frame)
	binary.BigEndian.PutUint16(frame[20:22], 10002)
	if second := payloadOwner(frame); first == second {
		t.Fatalf("owner key did not change with source port: %08x", first)
	}
}
