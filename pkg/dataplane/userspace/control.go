package userspace

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/dataplane"
)

const (
	ForwardingUsage = "request chassis cluster data-plane userspace forwarding <arm|disarm>"
	QueueUsage      = "request chassis cluster data-plane userspace queue <N> <register|unregister|arm|disarm>"
	BindingUsage    = "request chassis cluster data-plane userspace binding slot <N> <register|unregister|arm|disarm>"
)

// parseBindingSlot parses a CLI/gRPC binding-slot argument and rejects
// negatives and values >= dataplane.BindingSlotMapMaxEntries. A valid slot
// lives in [0, BindingSlotMapMaxEntries): the planner's dense slot dimension
// (4096), which bounds the helper maps keyed by slot (userspace_heartbeat,
// userspace_xsk_map) — NOT BindingArrayMaxEntries (1048576), which bounds the
// COMPOSED index into userspace_bindings and is 256x wider (#7497, #9915
// F-124). Slots the helper cannot address are refused here, truthfully and
// early, instead of failing later as "unknown binding slot".
// Without the bounds check a "-1" slot passes strconv.Atoi and wraps to
// 4294967295 on the uint32 cast (#5449). The bound is compared in int space
// so a value larger than uint32 max cannot alias a valid slot via truncation.
func parseBindingSlot(arg string) (uint32, error) {
	n, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("invalid slot: %s", arg)
	}
	if n < 0 || n >= int(dataplane.BindingSlotMapMaxEntries) {
		return 0, fmt.Errorf("slot %d out of range [0, %d)", n, dataplane.BindingSlotMapMaxEntries)
	}
	return uint32(n), nil
}

// parseQueueID parses a CLI/gRPC queue-id argument and rejects negatives
// and values >= dataplane.BindingQueuesPerIface. A valid queue id lives in
// [0, BindingQueuesPerIface), the queue dimension of the flat binding index
// formula `idx = ifindex * BindingQueuesPerIface + queue`. This mirrors the
// #5449-hardened parseBindingSlot and the #4894 queue-dimension guard in
// maps_sync.go: without the bounds check a "-1" queue passes strconv.Atoi
// and wraps to 4294967295 on the uint32 cast, and any queue-id >= the stride
// (16) aliases the adjacent ifindex's queue-0 slot — steering a queue
// register/arm op to a wrong worker binding. The bound is compared in int
// space so a value larger than uint32 max cannot alias a valid queue id via
// truncation.
func parseQueueID(arg string) (uint32, error) {
	n, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("invalid queue: %s", arg)
	}
	if n < 0 || n >= int(dataplane.BindingQueuesPerIface) {
		return 0, fmt.Errorf("queue %d out of range [0, %d)", n, dataplane.BindingQueuesPerIface)
	}
	return uint32(n), nil
}

func ParseForwardingCommand(args []string) (bool, error) {
	if len(args) != 2 || args[0] != "forwarding" {
		return false, fmt.Errorf("usage: %s", ForwardingUsage)
	}
	switch strings.ToLower(args[1]) {
	case "arm":
		return true, nil
	case "disarm":
		return false, nil
	default:
		return false, fmt.Errorf("usage: %s", ForwardingUsage)
	}
}

func ParseQueueCommand(args []string) (queueID uint32, registered, armed bool, err error) {
	if len(args) != 3 || args[0] != "queue" {
		return 0, false, false, fmt.Errorf("usage: %s", QueueUsage)
	}
	queueID, err = parseQueueID(args[1])
	if err != nil {
		return 0, false, false, err
	}
	registered, armed, err = ParseRegistrationOperation(args[2])
	if err != nil {
		return 0, false, false, fmt.Errorf("usage: %s", QueueUsage)
	}
	return queueID, registered, armed, nil
}

func ParseBindingCommand(args []string) (slot uint32, registered, armed bool, err error) {
	if len(args) != 4 || args[0] != "binding" || args[1] != "slot" {
		return 0, false, false, fmt.Errorf("usage: %s", BindingUsage)
	}
	slot, err = parseBindingSlot(args[2])
	if err != nil {
		return 0, false, false, err
	}
	registered, armed, err = ParseRegistrationOperation(args[3])
	if err != nil {
		return 0, false, false, fmt.Errorf("usage: %s", BindingUsage)
	}
	return slot, registered, armed, nil
}

func ParseRegistrationOperation(op string) (registered, armed bool, err error) {
	switch strings.ToLower(op) {
	case "register":
		return true, false, nil
	case "unregister":
		return false, false, nil
	case "arm":
		return true, true, nil
	case "disarm":
		return true, false, nil
	default:
		return false, false, fmt.Errorf("unknown operation %q", op)
	}
}
