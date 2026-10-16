package dataplane

// Constants in this file are Go-visible mirrors of BPF-side limits.
// THEY MUST STAY IN SYNC WITH:
//
//   - MAX_INTERFACES in bpf/headers/xpf_common.h
//   - BINDING_QUEUES_PER_IFACE in userspace-xdp/src/binding_index.rs
//     (from which userspace-xdp/src/lib.rs derives
//     BINDING_ARRAY_MAX_ENTRIES = MAX_INTERFACES *
//     BINDING_QUEUES_PER_IFACE via env!("MAX_INTERFACES"))
//
// Drift between these and the BPF objects is the exact recurrence #814
// was filed for (fab0 at ifindex 2561 overflowing tx_ports sized at 2048
// and USERSPACE_BINDINGS sized at 1024*16=16384). The load-time
// MaxEntries assertion in loader_userspace_shim.go (validateUserspaceShimSpec)
// catches drift by comparing the embedded userspace_xdp_bpfel.o maps'
// max_entries against these Go constants before
// ebpf.NewCollectionWithOptions runs.
const (
	// MaxInterfaces mirrors MAX_INTERFACES in bpf/headers/xpf_common.h.
	// This is the dense max_entries of the tx_ports DEVMAP and the
	// userspace-side ingress-iface HashMap. Raising it requires bumping
	// both the C constant and the Rust env!() wiring's input.
	MaxInterfaces uint32 = 65536

	// BindingQueuesPerIface mirrors BINDING_QUEUES_PER_IFACE in
	// userspace-xdp/src/binding_index.rs. Used as the stride in the flat
	// index formula `idx = ifindex * BindingQueuesPerIface + queue`.
	BindingQueuesPerIface uint32 = 16

	// BindingArrayMaxEntries mirrors BINDING_ARRAY_MAX_ENTRIES in
	// userspace-xdp/src/lib.rs. This is the max_entries of the aya
	// Array<UserspaceBindingValue> named "userspace_bindings".
	BindingArrayMaxEntries uint32 = MaxInterfaces * BindingQueuesPerIface

	// BindingSlotMapMaxEntries mirrors BINDING_SLOT_MAP_MAX_ENTRIES in
	// userspace-xdp/src/binding_index.rs: the max_entries of the two shim
	// maps keyed by the binding VALUE's slot field — "userspace_heartbeat"
	// and "userspace_xsk_map".
	//
	// Deliberately NOT derived from MaxInterfaces, and NOT interchangeable
	// with BindingArrayMaxEntries even though both are "the binding bound"
	// in casual speech (#7497). BindingArrayMaxEntries bounds the COMPOSED
	// index `ifindex*BindingQueuesPerIface + queue` into userspace_bindings,
	// so it scales with the ifindex axis. This one bounds `slot`, which the
	// helper's planner assigns DENSELY over the bindings it planned, so it
	// is a ceiling on the TOTAL NUMBER OF BINDINGS. It is 256x smaller, and
	// a check against the larger value admits slots these maps cannot
	// address — which is why the write-side composed-index guards do not
	// stand in for it.
	// UserspaceSessionsMaxEntries sizes the shim's no-prealloc steering map
	// for the 16-worker binding-planner ceiling, 131072 sessions per worker,
	// and up to four distinct rows per live session (NAT wire aliases).
	// It mirrors USERSPACE_SESSIONS_MAX_ENTRIES in userspace-xdp/src/lib.rs.
	UserspaceSessionsMaxEntries uint32 = 16 * 131072 * 4
	BindingSlotMapMaxEntries    uint32 = 4096
)
