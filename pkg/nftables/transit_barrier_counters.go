package nftables

import (
	"errors"
	"fmt"

	gnft "github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// TransitFenceCounter is one read of the inet forward-fence q0 witness.
// Packets counts marked q0 frames that reached the post-TUN inet FORWARD
// pinhole. A userspace write() to the TUN injects into the kernel RX path;
// TX is the kernel-to-userspace direction and was the wrong bg_7 scrape.
// Because q0 is also used by transit MissingNeighbor adjudication, callers
// must use the delta only under a quiesced S5 window.
type TransitFenceCounter struct {
	Packets uint64
	Bytes   uint64
}

// ReadTransitFenceCounter reads the named q0 mark-conjunction counter from the
// live inet forward fence through netlink. available=false means the fence is
// absent, disarmed/counterless, or otherwise does not expose the product-owned
// witness; it is never an authoritative zero. A netlink failure is returned so
// the caller can latch the witness unavailable rather than publishing 0.
func ReadTransitFenceCounter() (TransitFenceCounter, bool, error) {
	conn, err := gnft.New()
	if err != nil {
		return TransitFenceCounter{}, false, fmt.Errorf("nftables conn: %w", err)
	}
	tables, err := conn.ListTablesOfFamily(gnft.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return TransitFenceCounter{}, false, nil
		}
		return TransitFenceCounter{}, false, fmt.Errorf("nftables list tables: %w", err)
	}
	var table *gnft.Table
	for _, candidate := range tables {
		if candidate != nil && candidate.Name == TransitBarrierTableName {
			table = candidate
			break
		}
	}
	if table == nil {
		return TransitFenceCounter{}, false, nil
	}
	chain, err := conn.ListChain(table, "forward")
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return TransitFenceCounter{}, false, nil
		}
		return TransitFenceCounter{}, false, fmt.Errorf("nftables list chain %s: %w", TransitBarrierTableName, err)
	}
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return TransitFenceCounter{}, false, nil
		}
		return TransitFenceCounter{}, false, fmt.Errorf("nftables list rules %s: %w", TransitBarrierTableName, err)
	}
	objects, err := conn.GetObjects(table)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return TransitFenceCounter{}, false, nil
		}
		return TransitFenceCounter{}, false, fmt.Errorf("nftables list objects %s: %w", TransitBarrierTableName, err)
	}
	counter, ok := classifyTransitFenceCounterObjects(objects)
	if !ok || !transitFenceRulesContainWitnessCounter(rules) {
		return TransitFenceCounter{}, false, nil
	}
	return counter, true, nil
}

func transitFenceRulesContainWitnessCounter(rules []*gnft.Rule) bool {
	for _, rule := range rules {
		shape, _, ok := decodeTransitFenceRule(rule, nil)
		if ok && shape.mark != nil && isTransitFenceWitnessMark(*shape.mark) &&
			shape.counter == TransitFenceDeliveredCounterName {
			return true
		}
	}
	return false
}

// classifyTransitFenceCounterObjects is split from the netlink walk so absent
// and counterless (disarmed) fences remain unit-testable without CAP_NET_ADMIN.
func classifyTransitFenceCounterObjects(objects []gnft.Obj) (TransitFenceCounter, bool) {
	for _, object := range objects {
		counter, ok := object.(*gnft.CounterObj)
		if !ok || counter.Name != TransitFenceDeliveredCounterName {
			continue
		}
		return TransitFenceCounter{Packets: counter.Packets, Bytes: counter.Bytes}, true
	}
	return TransitFenceCounter{}, false
}
