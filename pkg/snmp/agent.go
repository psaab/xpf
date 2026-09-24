package snmp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// SNMP v2c PDU types.
const (
	tagInteger          = 0x02
	tagOctetString      = 0x04
	tagNull             = 0x05
	tagObjectIdentifier = 0x06
	tagSequence         = 0x30

	pduGetRequest     = 0xa0
	pduGetNextRequest = 0xa1
	pduGetResponse    = 0xa2
	pduSetRequest     = 0xa3
	pduGetBulkRequest = 0xa5

	// SNMP error codes (RFC 3416 error-status values).
	errNoError     = 0
	errTooBig      = 1
	errNoSuchName  = 2
	errGenErr      = 5
	errNoAccess    = 6
	errNotWritable = 17

	// Implicit tags for exception values (context-specific, primitive).
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82

	snmpVersion2c = 1 // version field: 0 = v1, 1 = v2c

	maxPacketSize = 4096

	// minMsgMaxSize is the RFC 3412 / RFC 3416 floor for a request's
	// advertised msgMaxSize (the smallest maximum message size any SNMP
	// engine must accept). A request that advertises less than this — or a
	// v3 request whose msgMaxSize decoded to a tiny/garbage value — is
	// clamped up to this floor before we size a GETBULK response against it,
	// so a misbehaving manager cannot force us to truncate every response to
	// nothing. The effective bound is then min(clamped msgMaxSize,
	// maxPacketSize).
	minMsgMaxSize = 484

	// usmTimeWindow is the RFC 3414 §3.2 timeliness window in seconds: an
	// authenticated request whose msgAuthoritativeEngineTime differs from
	// the authoritative engine's own time by more than this is rejected as
	// outside the time window (and is therefore not replayable beyond it).
	usmTimeWindow = 150

	// engineBootsMax is the RFC 3414 ceiling for msgAuthoritativeEngineBoots
	// (2^31 - 1). When our boots counter reaches it, the engine ID must be
	// reconfigured; until then every authenticated request is rejected as
	// not-in-time-window per §3.2.
	engineBootsMax = 2147483647
)

// defaultEngineBootsPath is the on-disk location of the persisted SNMPv3
// engineBoots counter. It is loaded and incremented once at agent
// construction so (engineBoots, engineTime) is monotonic across daemon
// restarts per RFC 3414 — a manager that caches our authoritative boots/time
// keeps working over a restart, and a request captured before a restart no
// longer validates (the boots value advanced). /var/lib/xpf is the persistent
// runtime-state root shared with the other xpf subsystems.
const defaultEngineBootsPath = "/var/lib/xpf/snmp-engineboots"

// defaultEngineIDPath is the on-disk location of the persisted per-device random
// EngineID component (#5283). A 16-byte crypto/rand value is generated ONCE on
// first agent init and reused on every subsequent boot, so the derived SNMPv3
// EngineID is stable across reboots of THE SAME appliance yet unique per
// appliance. This closes the cross-clone USM auth bypass: without a per-device
// component, two same-hostname clones (HA pair, factory-default, lab, restore)
// derived byte-identical EngineIDs, hence byte-identical localized USM keys,
// hence firewall B accepted an authenticated SNMPv3 request captured from A.
//
// IMPORTANT (clone/bake): this file MUST NOT be copied identically into cloned
// appliances or a golden image — that would re-establish the collision it
// exists to prevent. It is treated like /etc/machine-id: the image bake
// (scripts/image/bake.py) removes it during virt-sysprep so each appliance
// regenerates a fresh one on first boot, and /etc/machine-id is additionally
// folded into the component (see deviceComponent) as defense in depth so even a
// mistakenly-copied file still yields distinct EngineIDs across clones.
const defaultEngineIDPath = "/var/lib/xpf/snmp-engine-id"

// machineIDPath is the systemd per-device identity. virt-sysprep resets it
// per-appliance at image bake, so it differs on every cloned appliance. It is
// folded into the EngineID device component as defense in depth against a
// mistakenly-cloned defaultEngineIDPath file.
const machineIDPath = "/etc/machine-id"

// deviceComponentLen is the size (octets) of the persisted per-device random
// EngineID component. 128 bits is far beyond birthday-collision range for any
// realistic appliance fleet.
const deviceComponentLen = 16

// tagCounter32 is the ASN.1 application tag for Counter32.
const tagCounter32 = 0x41

// tagGauge32 is the ASN.1 application tag for Gauge32.
const tagGauge32 = 0x42

// tagCounter64 is the ASN.1 application tag for Counter64.
const tagCounter64 = 0x46

// OID constants for the system MIB group (1.3.6.1.2.1.1).
var (
	oidSysDescr    = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = []int{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysUpTime   = []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSysContact  = []int{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysName     = []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation = []int{1, 3, 6, 1, 2, 1, 1, 6, 0}

	// ifNumber: 1.3.6.1.2.1.2.1.0
	oidIfNumber = []int{1, 3, 6, 1, 2, 1, 2, 1, 0}

	// ifTable column OIDs: 1.3.6.1.2.1.2.2.1.<col>.<ifIndex>
	// Columns: 1=ifIndex, 2=ifDescr, 3=ifType, 4=ifMtu, 5=ifSpeed,
	//          7=ifAdminStatus, 8=ifOperStatus, 10=ifInOctets, 16=ifOutOctets
	oidIfTablePrefix = []int{1, 3, 6, 1, 2, 1, 2, 2, 1}

	// ifXTable column OIDs: 1.3.6.1.2.1.31.1.1.1.<col>.<ifIndex>
	oidIfXTablePrefix = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1}

	// Ordered list of static OIDs we serve, for GETNEXT walking.
	staticOIDs = [][]int{
		oidSysDescr,
		oidSysObjectID,
		oidSysUpTime,
		oidSysContact,
		oidSysName,
		oidSysLocation,
		oidIfNumber,
	}

	// ifTable columns we serve (sorted for GETNEXT).
	ifTableColumns = []int{1, 2, 3, 4, 5, 7, 8, 10, 16}

	// ifXTable columns we serve (sorted for GETNEXT).
	// 1=ifName, 2=ifInMulticastPkts, 3=ifInBroadcastPkts, 4=ifOutMulticastPkts,
	// 5=ifOutBroadcastPkts, 6=ifHCInOctets, 7=ifHCInUcastPkts,
	// 10=ifHCOutOctets, 11=ifHCOutUcastPkts, 15=ifHighSpeed, 18=ifAlias
	ifXTableColumns = []int{1, 2, 3, 4, 5, 6, 7, 10, 11, 15, 18}
)

// IfData represents a single network interface for the SNMP ifTable/ifXTable.
type IfData struct {
	IfIndex     int
	IfDescr     string
	IfType      int // 6=ethernetCsmacd, 1=other, 131=tunnel, 53=propVirtual
	IfMtu       int
	IfSpeed     uint32 // bits per second
	AdminStatus int    // 1=up, 2=down
	OperStatus  int    // 1=up, 2=down
	InOctets    uint32 // Counter32 (wraps at 2^32)
	OutOctets   uint32 // Counter32 (wraps at 2^32)

	// ifXTable fields (64-bit high-capacity counters).
	IfName           string // interface name (ifXTable.1)
	InMulticastPkts  uint32 // Counter32 (ifXTable.2)
	InBroadcastPkts  uint32 // Counter32 (ifXTable.3)
	OutMulticastPkts uint32 // Counter32 (ifXTable.4)
	OutBroadcastPkts uint32 // Counter32 (ifXTable.5)
	HCInOctets       uint64 // Counter64 (ifXTable.6)
	HCInUcastPkts    uint64 // Counter64 (ifXTable.7)
	HCOutOctets      uint64 // Counter64 (ifXTable.10)
	HCOutUcastPkts   uint64 // Counter64 (ifXTable.11)
	IfHighSpeed      uint32 // Gauge32 Mbps (ifXTable.15)
	IfAlias          string // description (ifXTable.18)
}

// Agent is an SNMP v2c/v3 agent that serves the system MIB and ifTable.
type Agent struct {
	conn        *net.UDPConn
	startTime   time.Time
	ifDataFn    func() []IfData // callback for live interface data
	mu          sync.Mutex
	stopped     bool
	engineID    []byte // SNMPv3 engine ID (immutable after initEngine)
	engineBoots int    // SNMPv3 engine boots counter (immutable after initEngine)
	lastPacket  []byte // raw packet for v3 auth verification

	// engineBootsPath is the persistence seam for the engineBoots counter
	// (RFC 3414 monotonicity across restarts). Empty means the default
	// path; tests inject a temp file to assert the load/increment/persist
	// cycle. Set before initEngine runs (NewAgent / NewAgentWithBootsPath).
	engineBootsPath string

	// engineIDPath is the persistence seam for the per-device random EngineID
	// component (#5283). Empty means defaultEngineIDPath; tests inject a temp
	// file to drive the generate/persist/reuse cycle and to prove two agents
	// with DIFFERENT persisted components derive DIFFERENT EngineIDs (the
	// anti-clone property). Set before initEngine runs.
	engineIDPath string

	// cfgMu guards the live authorization/identity configuration (cfg) and
	// the derived USM user table (v3Users). The request-serving goroutine
	// reads both under RLock; UpdateConfig swaps both under Lock so a commit
	// that changes community authorization or v3 users takes effect on the
	// running agent without dropping the UDP listener. Keeping this separate
	// from mu (which guards conn/stopped/ifDataFn) avoids holding the
	// listener lock across config reads on every request.
	cfgMu   sync.RWMutex
	cfg     *config.SNMPConfig  // authorization + sysContact/Location/Description
	v3Users map[string]*usmUser // SNMPv3 USM users (keyed by name)

	// privSalt is the SNMPv3 privacy salt source (RFC 3826 §3.3 for AES,
	// RFC 3414 §8.1.1.1 for DES). The msgPrivacyParameters carried with every
	// encrypted scopedPDU MUST be UNIQUE per (engineBoots, privKey) so the
	// derived cipher IV never repeats within an engine boot: an IV repeat under
	// AES-128-CFB leaks the XOR of two plaintexts, and under DES-CBC (IV =
	// key-derived preIV XOR salt) repeats the first-block structure
	// (RFC 3414 §8.2.1). Drawing an INDEPENDENT random salt per message (the
	// pre-#5032 behavior) gives only birthday-bound uniqueness. Instead the salt
	// is a MONOTONIC 64-bit counter: seeded ONCE from crypto/rand at first use
	// (an arbitrary boot-time starting point, RFC 3826 §3.3) and incremented
	// atomically for each encryption, so successive salts within an engine boot
	// are guaranteed distinct — not merely probably distinct. engineBoots
	// (immutable per boot, monotonic across restarts) scopes it to the boot, so a
	// restart re-randomizes the start and advances the AES IV's boots field.
	// See Agent.nextPrivSalt.
	privSalt       atomic.Uint64
	privSaltSeeded atomic.Bool
	privSaltMu     sync.Mutex // serializes the one-time seed draw

	// Asynchronous trap delivery (#2991). Link-state traps are emitted from
	// the daemon's netlink link-monitor goroutine; sendTrap does a blocking
	// net.DialTimeout (and DNS resolution for an FQDN target) that, done
	// inline, would stall link processing for up to dialTimeout × target
	// count when a target is dead or slow. Instead sendLinkTraps enqueues a
	// pre-built packet onto a small bounded channel drained by a single
	// worker goroutine. The queue is started lazily (works for both NewAgent
	// and bare-struct test agents) and is capacity-bounded: when full, the
	// trap is dropped and trapsDropped is incremented rather than blocking
	// the caller. A single worker bounds goroutine growth (no per-trap
	// goroutine storm) while still serializing the slow dials off the hot
	// link-monitor path.
	trapQueue      chan trapJob
	trapWorkerOnce sync.Once
	trapsDropped   atomic.Uint64
	// trapPerTarget counts admitted-but-not-yet-dequeued trap jobs per
	// normalized receiver (#9917 F-140). Guarded by mu; lazily created in
	// enqueueTrap next to the queue itself so bare-struct test agents work.
	// Every increment (admit) pairs with exactly one decTrapPerTarget
	// (worker dequeue, whether sent, abandoned, or drained), so the map
	// tracks live backlog only. Keys are config-authored targets, hence
	// bounded — no network-driven growth.
	trapPerTarget map[string]int

	// trapSender delivers a single pre-built trap to a target. It is a
	// per-Agent field (not a package global) so tests can inject a
	// deliberately slow/blocking or mock sender on their OWN Agent without a
	// cross-goroutine write to a shared global that races the running trap
	// worker's read (#5023). Defaults to sendTrap (set by the constructors); a
	// bare-struct test Agent may leave it nil, in which case the worker falls
	// back to sendTrap. Production never reassigns it after construction, and
	// the worker snapshots it once at start, so there is no shared mutable
	// state between the worker and any injector.
	trapSender func(target string, pkt []byte) error

	// Lifecycle shutdown (#4916). Stop must cancel the context-watcher
	// goroutine AND stop the trap worker so a day-2 SNMP disable (Stop called
	// while the daemon context is still live) does not leak a goroutine pair
	// nor deliver a queued trap to a removed/rotated receiver after the config
	// that authorized it was revoked. All three are guarded by mu:
	//   - lifeCancel cancels the derived lifecycle context the ctx-watcher
	//     waits on, so Stop unblocks the watcher even when the parent context
	//     stays live.
	//   - trapStop is closed by Stop to tell the worker to ABANDON its queue
	//     (no post-Stop delivery); the worker also re-checks it before each
	//     send so a Stop that races a dequeued job never delivers it.
	//   - trapWG lets Stop wait for the worker to exit. It counts only a
	//     worker that actually started (lazy, via trapWorkerOnce), so Stop
	//     returns immediately when none ran.
	lifeCancel context.CancelFunc
	trapStop   chan struct{}
	trapWG     sync.WaitGroup
	// serveBudget is the Serve loop's per-source request budget (#9917 F-139),
	// set by the constructors. A nil budget (bare-struct test agents) allows
	// everything -- only constructor-built agents enforce.
	serveBudget *snmpServeBudget
}

// trapJob is one queued trap-delivery unit: a destination target (host or
// host:port) plus either a pre-built SNMP packet or, for the v1 leg, the
// parameters the worker builds it from. Prebuilt packets are assembled on the
// caller's goroutine (cheap, allocation only) and the blocking dial/write
// happens on the worker. A v1 packet is NOT prebuilt: its agent-addr costs a
// DNS lookup plus an up-to-2s dial, which must not run on the link monitor, so
// sendLinkTraps enqueues a deferred job (pkt nil, deferredV1 set) and the
// worker builds it just before sending (#9917 F-134). Precedence: a deferred
// job's build wins over any carried pkt (senders never set both; explicit
// beats ambiguous).
type trapJob struct {
	target  string
	pkt     []byte
	group   string
	event   string
	iface   string
	ifindex int
	// Deferred v1 build parameters (used only when deferredV1 is set). uptime
	// is captured at event time so the v1 time-stamp keeps event-time
	// semantics instead of skewing to delivery time under backlog.
	deferredV1 bool
	community  string
	linkUp     bool
	uptime     int
}

// trapQueueDepth bounds the number of pending trap deliveries. A handful of
// targets times a short burst of link flaps fits comfortably; past this the
// targets are clearly not draining and dropping is preferable to unbounded
// memory growth or blocking the link monitor.
const trapQueueDepth = 256

// maxPerTargetTrapQueue caps how many jobs one receiver may hold in the
// shared trap queue once the queue is under pressure (#9917 F-140). Past the
// cap that receiver's new traps are shed (counted in trapsDropped) so a dead
// receiver cannot fill the queue and evict healthy-target traps behind it. A
// lone sick receiver holds at most ~half the queue (admitted pre-pressure),
// versus all of it before; healthy targets always have room. The cap counts
// queued PACKETS, not events -- a `version all` group consumes two slots per
// event per target. This is DROP isolation only: the worker still drains one
// shared FIFO, so a healthy trap admitted behind a sick backlog waits out the
// serial sends ahead of it before delivery.
const maxPerTargetTrapQueue = 32

// trapCapPressureThreshold is the shared-queue occupancy at which the
// per-target cap starts binding (#9917 F-140). Below half-full the queue
// absorbs bursts freely -- including healthy fan-out while the worker is
// transiently stalled -- so the cap cannot drop traffic the un-capped queue
// would have held. Above half-full each receiver is capped, which is exactly
// when one receiver's backlog threatens the others' room.
const trapCapPressureThreshold = trapQueueDepth / 2

// NewAgent creates a new SNMP agent with the given configuration. The
// SNMPv3 engineBoots counter is loaded from defaultEngineBootsPath,
// incremented, and persisted so (engineBoots, engineTime) advances
// monotonically across daemon restarts (RFC 3414). The per-device EngineID
// component is loaded/generated at defaultEngineIDPath (#5283).
func NewAgent(cfg *config.SNMPConfig) *Agent {
	return NewAgentWithPaths(cfg, defaultEngineBootsPath, defaultEngineIDPath)
}

// NewAgentWithBootsPath is NewAgent with an explicit engineBoots persistence
// path and the default per-device EngineID component path. Retained for
// existing callers/tests that only need to redirect the boots counter.
func NewAgentWithBootsPath(cfg *config.SNMPConfig, bootsPath string) *Agent {
	return NewAgentWithPaths(cfg, bootsPath, defaultEngineIDPath)
}

// NewAgentWithPaths is NewAgent with explicit persistence paths for the
// engineBoots counter and the per-device EngineID component. It is the seam
// tests use to drive both the boots load/increment/persist cycle and the
// EngineID component generate/persist/reuse cycle against temp files without
// touching /var/lib/xpf. An empty path falls back to the respective default.
func NewAgentWithPaths(cfg *config.SNMPConfig, bootsPath, engineIDPath string) *Agent {
	if bootsPath == "" {
		bootsPath = defaultEngineBootsPath
	}
	if engineIDPath == "" {
		engineIDPath = defaultEngineIDPath
	}
	a := &Agent{
		cfg:             cfg,
		startTime:       time.Now(),
		engineBootsPath: bootsPath,
		engineIDPath:    engineIDPath,
		trapSender:      sendTrap,
		serveBudget:     newSNMPServeBudget(),
	}
	a.initEngine()
	a.initV3Users()
	return a
}

// UpdateConfig atomically swaps the agent's live authorization/identity
// configuration and rederives the USM v3 user table to match. It is the
// commit-time reconcile entry point (called from the daemon's
// applyConfigLocked) so that a config change to community authorization
// (read-write -> read-only, or a deleted community) or to the v3 user set
// reaches the running agent without a restart.
//
// In-place reconfigure is preferred over restart: restarting the agent would
// tear down the UDP/161 listener and interrupt in-flight polls. The swap is
// done under cfgMu.Lock so the request-serving goroutine (which reads cfg and
// v3Users under cfgMu.RLock) always observes a consistent pair: it never sees
// the new community map with the stale v3 users, or vice versa.
//
// engineID/engineBoots/startTime are intentionally NOT touched — they are the
// agent's stable identity. The v3 user keys are re-localized against the
// existing engineID, matching how initV3Users derived them at startup.
func (a *Agent) UpdateConfig(cfg *config.SNMPConfig) {
	v3 := a.deriveV3Users(cfg)
	a.cfgMu.Lock()
	a.cfg = cfg
	a.v3Users = v3
	a.cfgMu.Unlock()
}

// snapshotCfg returns the live config pointer under cfgMu.RLock.
func (a *Agent) snapshotCfg() *config.SNMPConfig {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg
}

// snapshotV3User looks up a USM user by name under cfgMu.RLock.
func (a *Agent) snapshotV3User(name string) *usmUser {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.v3Users[name]
}

// hasV3Users reports whether any USM user is configured, under cfgMu.RLock.
func (a *Agent) hasV3Users() bool {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return len(a.v3Users) > 0
}

// SNMPv3 authoritative EngineID construction (RFC 3411 §5).
//
// RFC 3411 constrains SnmpEngineID to 5..32 octets AND requires it to be UNIQUE
// per authoritative engine (unique, not secret). An EngineID outside the length
// range is rejected by standards-compliant managers; a NON-unique EngineID is a
// security hole, because USM localizes each user's auth/priv keys against it —
// two engines with the same EngineID derive byte-identical localized keys, so an
// authenticated SNMPv3 request captured from one is accepted by the other
// (cross-device telemetry disclosure / auth bypass, #5283).
//
// The historical construction derived the ENTIRE EngineID from a fixed prefix +
// os.Hostname() (short: prefix||hostname; long: sha256(hostname)[:26]). It had
// no per-device component, so two same-hostname CLONES (HA pair, factory
// default, lab image, config restore) derived IDENTICAL EngineIDs and hence
// identical USM keys (#4917/#5264 only capped the length, they did not add
// uniqueness). The construction now folds a per-device unique component (a
// persisted crypto/rand value + /etc/machine-id, see deviceComponent) into the
// hash so clones diverge, while staying inside the 5..32-octet cap.
const (
	// snmpEngineIDMaxLen is the RFC 3411 SnmpEngineID upper bound (octets).
	snmpEngineIDMaxLen = 32

	// engineIDFormatOctets (RFC 3411 §5, format 4 "administratively assigned
	// octets") labels the payload as OCTETS — a binary (non-text) SHA-256
	// digest. 0x04 (text) would mislabel the hash as text.
	engineIDFormatOctets = 0x05
)

// engineIDPrefix is the 5-octet enterprise header: the RFC 3411 variable-length
// format flag (high bit 0x80 set on the first octet) over private enterprise
// number 0x000186a3. The sixth octet — the format selector — is appended by
// buildEngineID. Read-only after init; buildEngineID copies it (append from a
// fresh backing array) and never mutates it.
var engineIDPrefix = []byte{0x80, 0x00, 0x01, 0x86, 0xa3}

// buildEngineID derives the authoritative SNMPv3 EngineID from the OS hostname
// AND a per-device unique component (#5283). The EngineID must be:
//
//   - RFC 3411-valid (5..32 octets): the result is ALWAYS exactly 32 octets —
//     engineIDPrefix(5) || 0x05 (octets) || sha256(deviceID || 0x00 || hostname)[:26]
//     — so the #4917/#5264 length cap holds for every input, empty or
//     multi-kilobyte hostname alike.
//   - stable across restarts of the SAME device: SHA-256 over a fixed
//     (deviceID, hostname) pair is deterministic (no randomness/timestamp at
//     build time — the randomness lives in the PERSISTED deviceID), so a manager
//     that cached our (engineBoots, engineTime) and localized its keys keeps
//     working over a restart.
//   - UNIQUE per device: deviceID is a per-appliance value (persisted random +
//     machine-id). Two clones with the same hostname derive DIFFERENT deviceIDs,
//     hence different EngineIDs, hence different localized USM keys — A's
//     authenticated packet no longer validates against B (the #5283 bypass is
//     closed). A 0x00 separator between deviceID and hostname prevents any
//     boundary-shift aliasing.
//
// A nil/empty deviceID (only the catastrophic all-sources-failed path) degrades
// to the pre-#5283 hostname-only identity — deterministic but NOT clone-unique;
// initEngine logs that case.
func buildEngineID(hostname string, deviceID []byte) []byte {
	h := sha256.New()
	h.Write(deviceID)
	h.Write([]byte{0x00}) // domain separator: deviceID | hostname
	h.Write([]byte(hostname))
	sum := h.Sum(nil)
	headerLen := len(engineIDPrefix) + 1      // enterprise prefix + one format octet
	hashLen := snmpEngineIDMaxLen - headerLen // 26 -> total exactly 32 octets
	id := make([]byte, 0, snmpEngineIDMaxLen)
	id = append(id, engineIDPrefix...)
	id = append(id, engineIDFormatOctets)
	id = append(id, sum[:hashLen]...)
	return id
}

// initEngine derives the RFC 3411-bounded, per-device-unique engine ID from the
// hostname and the per-device component (see buildEngineID / deviceComponent),
// then loads/increments the engineBoots counter.
func (a *Agent) initEngine() {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	deviceID := a.deviceComponent()
	if len(deviceID) == 0 {
		// One-time state event (not in a loop): every per-device identity source
		// failed, so the EngineID falls back to hostname-only and is NOT unique
		// across same-hostname clones. Surface it so the operator can provision
		// persistent state / a machine-id.
		slog.Warn("SNMP: no per-device EngineID component available; EngineID is derived from hostname only and is NOT unique across clones",
			"engineid_path", a.engineIDPath)
	}
	a.engineID = buildEngineID(hostname, deviceID)
	a.engineBoots = a.loadAndIncrementEngineBoots()
}

// deviceComponent returns the per-device unique EngineID component (#5283).
//
// It combines two independent per-device sources so a clone must defeat BOTH to
// collide:
//
//  1. a 16-byte crypto/rand value persisted at a.engineIDPath, generated ONCE
//     and reused on every boot (primary — stable per device, unique per
//     appliance);
//  2. /etc/machine-id, which virt-sysprep resets per-appliance at image bake
//     (defense in depth — even a mistakenly-cloned persisted file yields a
//     distinct component because machine-id differs).
//
// The returned slice is empty ONLY when the persisted random cannot be created
// AND no machine-id exists — the catastrophic path initEngine logs.
func (a *Agent) deviceComponent() []byte {
	var comp []byte
	if rnd := a.loadOrCreatePersistedComponent(); len(rnd) > 0 {
		comp = append(comp, rnd...)
	}
	if mid := readMachineID(); len(mid) > 0 {
		comp = append(comp, mid...)
	}
	return comp
}

// loadOrCreatePersistedComponent returns the persisted per-device random
// component, generating and durably persisting it (0600) on first use. It
// returns the component only when it is durably on disk (stable across
// reboots); on any read-corruption, RNG, or persist failure it returns nil so
// deviceComponent falls back to /etc/machine-id rather than serving an
// un-persisted value that would change every boot (churning manager caches).
func (a *Agent) loadOrCreatePersistedComponent() []byte {
	path := a.engineIDPath
	if path == "" {
		path = defaultEngineIDPath
	}
	// Reuse an existing component -> stable EngineID across reboots.
	if data, err := os.ReadFile(path); err == nil {
		if b, derr := hex.DecodeString(strings.TrimSpace(string(data))); derr == nil && len(b) == deviceComponentLen {
			return b
		}
		slog.Warn("SNMP: persisted EngineID component malformed, regenerating", "path", path)
	} else if !os.IsNotExist(err) {
		slog.Warn("SNMP: EngineID component read error, regenerating", "path", path, "err", err)
	}
	// Generate once, persist atomically with 0600 (need not be secret, but keep
	// it consistent and not world-readable).
	buf := make([]byte, deviceComponentLen)
	if _, err := rand.Read(buf); err != nil {
		slog.Warn("SNMP: EngineID component RNG failed, falling back to machine-id", "err", err)
		return nil
	}
	encoded := []byte(hex.EncodeToString(buf) + "\n")
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("SNMP: EngineID component dir create failed, falling back to machine-id", "path", path, "err", err)
		return nil
	}
	if err := fsatomic.WriteFileDurable(path, encoded, 0o600); err != nil {
		slog.Warn("SNMP: EngineID component persist failed, falling back to machine-id", "path", path, "err", err)
		return nil
	}
	return buf
}

// readMachineID reads /etc/machine-id and decodes it to raw bytes. An empty
// (uninitialized first-boot) or unparseable value is treated as absent (nil).
func readMachineID() []byte {
	data, err := os.ReadFile(machineIDPath)
	if err != nil {
		return nil
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(b) == 0 {
		return nil
	}
	return b
}

// loadAndIncrementEngineBoots reads the persisted engineBoots counter, returns
// it incremented by one, and writes the new value back so the next start
// advances again. On first boot (file missing) it starts at 1. engineTime then
// counts from THIS boot (a.startTime), so (engineBoots, engineTime) is the
// monotonically-advancing authoritative pair RFC 3414 requires for replay
// protection across restarts.
//
// RFC 3414 §2.2 requires engineBoots to be MONOTONIC for the authoritative
// engine; it must never silently decrease while the engineID stays the same.
// A reset back to a low value re-opens the replay window: a captured
// authenticated request from a prior low-boots epoch can become timely again
// (#2649). So a read/parse failure, a value already at/over the RFC ceiling,
// an increment that would reach the ceiling, OR a failed durable write all
// FAIL CLOSED by pinning engineBoots to the ceiling (engineBootsMax) rather
// than restarting at 1. At the ceiling checkTimeliness rejects every
// authenticated request (§3.2 step 7), which forces managers to re-discover —
// the engineID must be reconfigured to recover. The agent still starts and
// answers discovery/report (no SNMP DoS — the owner's #2649 concern), but no
// replayed low-boots packet can pass while the counter is corrupt or maxed.
func (a *Agent) loadAndIncrementEngineBoots() int {
	prev := 0
	corrupt := false
	if data, err := os.ReadFile(a.engineBootsPath); err == nil {
		if n, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil && n > 0 && n < engineBootsMax {
			prev = n
		} else {
			slog.Warn("SNMP: engineBoots state unreadable, pinning to ceiling (fail-closed, re-discovery required)", "path", a.engineBootsPath)
			corrupt = true
		}
	} else if os.IsNotExist(err) {
		// First boot: no prior epoch exists, so boots=1 is genuinely new and
		// not a reuse of a persisted low value. This is not a fail-open reset.
	} else {
		slog.Warn("SNMP: engineBoots state read error, pinning to ceiling (fail-closed, re-discovery required)", "path", a.engineBootsPath, "err", err)
		corrupt = true
	}

	boots := prev + 1
	if corrupt || boots < 1 || boots >= engineBootsMax {
		// Fail closed: a lost/corrupt counter or an exhausted counter pins to
		// the ceiling so no low-boots replay is timely. Never restart at 1.
		boots = engineBootsMax
	}

	if err := fsatomic.MkdirAllDurable(filepath.Dir(a.engineBootsPath), 0o755); err != nil {
		slog.Warn("SNMP: engineBoots state dir create failed, pinning to ceiling (fail-closed)", "path", a.engineBootsPath, "err", err)
		boots = engineBootsMax
	}
	if err := fsatomic.WriteFileDurable(a.engineBootsPath, []byte(strconv.Itoa(boots)+"\n"), 0o644); err != nil {
		// A boots value we cannot durably persist would be reused next start
		// (the next read sees the stale lower value) → replay window. Fail
		// closed for THIS run so the unpersisted epoch is never serveable.
		slog.Warn("SNMP: engineBoots state persist failed, pinning to ceiling (fail-closed, re-discovery required)", "path", a.engineBootsPath, "err", err)
		boots = engineBootsMax
	}
	return boots
}

// engineTime returns the number of seconds since agent start.
func (a *Agent) engineTime() int {
	return int(time.Since(a.startTime).Seconds())
}

// checkTimeliness applies the RFC 3414 §3.2 timeliness window for the agent
// acting as the authoritative engine. It compares an incoming authenticated
// request's msgAuthoritativeEngineBoots/Time against the agent's own clock and
// returns true when the request is within the window (and may be accepted).
//
// Per §3.2 step 7, the request is NOT in the time window if our boots counter
// has reached the ceiling, if the request's boots differs from ours, or if the
// request's time differs from ours by more than usmTimeWindow seconds. A
// replayed request fails the time test once usmTimeWindow has elapsed (or fails
// the boots test immediately after a restart bumped our boots), which is the
// replay protection the bare HMAC check lacked.
func (a *Agent) checkTimeliness(reqBoots, reqTime int) bool {
	if a.engineBoots >= engineBootsMax {
		return false
	}
	if reqBoots != a.engineBoots {
		return false
	}
	diff := a.engineTime() - reqTime
	if diff < 0 {
		diff = -diff
	}
	return diff <= usmTimeWindow
}

// SetIfDataFn sets the callback for retrieving interface data.
func (a *Agent) SetIfDataFn(fn func() []IfData) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ifDataFn = fn
}

// getIfData returns sorted interface data from the callback, or nil.
//
// The callback (buildSNMPIfData in the daemon) performs a full netlink
// LinkList (RTM_GETLINK dump) on every invocation, so getIfData is EXPENSIVE.
// A request handler must not call it per-varbind: it snapshots ONCE per PDU via
// ifSnapshot and threads the result through the walk (#4013).
func (a *Agent) getIfData() []IfData {
	if a.ifDataFn == nil {
		return nil
	}
	return a.ifDataFn()
}

// ifSnapshot memoizes a single interface-table read for the lifetime of ONE
// PDU. getOIDValue / findNextOID / getIfTableValue / getIfXTableValue read the
// interface list through it, so a GETBULK or GETNEXT walk over N interfaces
// performs at most one netlink LinkList per PDU instead of the pre-#4013 two
// dumps per returned varbind — an O(N)/O(N²) RTM_GETLINK storm that floods the
// kernel netlink path and contends with the interface reconcile and VRRP on a
// box with many interfaces. This mirrors the >1/s control-socket snapshot
// discipline in CLAUDE.md, applied to netlink.
//
// The snapshot is LAZY: a PDU that never touches the ifTable/ifXTable (e.g. a
// system-group GET of sysUpTime, the common monitoring poll) triggers no
// LinkList at all, so the fix adds no netlink cost to those requests. It is not
// safe for concurrent use — each request builds its own via newIfSnapshot.
type ifSnapshot struct {
	a      *Agent
	loaded bool
	data   []IfData

	// oids is the full MIB view for this PDU in lexicographic order —
	// staticOIDs, then every ifTable cell, then every ifXTable cell — built
	// once on first use and binary-searched by findNextOIDSnap (#6597).
	// oidsBuilt distinguishes "not yet built" from "built and legitimately
	// empty" (an agent with no interfaces still has staticOIDs, so empty is in
	// practice unreachable, but the flag keeps the lazy contract honest).
	oids      [][]int
	oidsBuilt bool
}

// newIfSnapshot returns a fresh per-PDU interface-data snapshot bound to the
// agent. Call once at the start of handling a request and thread the result
// through getOIDValueSnap / findNextOIDSnap for the whole PDU.
func (a *Agent) newIfSnapshot() *ifSnapshot {
	return &ifSnapshot{a: a}
}

// get returns the interface table for this PDU, invoking the agent's ifDataFn
// (one netlink LinkList) on the first call and returning the cached slice on
// every subsequent call within the same PDU.
func (s *ifSnapshot) get() []IfData {
	if !s.loaded {
		s.data = s.a.getIfData()
		s.loaded = true
	}
	return s.data
}

// mibOIDs returns this PDU's whole MIB view in lexicographic order, built once
// per snapshot (#6597).
//
// The successor lookup used to LINEAR-SCAN this view for every varbind —
// O(static + interfaces x columns) per lookup, multiplied by every varbind an
// operation emits. Because the agent runs on a single serial goroutine, that
// per-lookup cost is the floor on requests/second for every operation at once,
// and it grows with interface count: a max-size plain GETNEXT of 239 deep
// ifXTable OIDs measured ~33 ms, i.e. ~30 req/s for that shape (#6551 fold).
// Building the ordered view once per PDU and binary-searching it moves the walk
// from O(varbinds x entries) to O(entries + varbinds x log entries).
//
// The interface list is SORTED BY IfIndex here, which the linear scan did not
// do. Its lexicographic correctness silently depended on `ifDataFn` returning
// IfIndex-ascending data, and nothing enforces that: the production provider
// (`buildSNMPIfData`, pkg/daemon) appends in netlink LinkList order with no
// sort. For the usual ascending case the emitted order is identical to the
// linear scan's; for a provider that returns them out of order the walk is now
// correctly lexicographic where it previously could revisit or skip OIDs, which
// is a fix rather than a behaviour change worth preserving.
//
// Column-major with ascending IfIndex IS the lexicographic order of
// `<prefix>.<col>.<ifIndex>`, so the concatenation below is sorted by
// construction; `TestMIBOIDViewIsSorted` pins that rather than trusting it.
func (s *ifSnapshot) mibOIDs() [][]int {
	if s.oidsBuilt {
		return s.oids
	}
	s.oidsBuilt = true

	ifaces := s.get()
	sorted := make([]IfData, len(ifaces))
	copy(sorted, ifaces)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].IfIndex < sorted[j].IfIndex })

	out := make([][]int, 0, len(staticOIDs)+
		len(sorted)*(len(ifTableColumns)+len(ifXTableColumns)))
	out = append(out, staticOIDs...)
	for _, tbl := range []struct {
		prefix []int
		cols   []int
	}{
		{oidIfTablePrefix, ifTableColumns},
		{oidIfXTablePrefix, ifXTableColumns},
	} {
		for _, col := range tbl.cols {
			for _, iface := range sorted {
				candidate := make([]int, len(tbl.prefix)+2)
				copy(candidate, tbl.prefix)
				candidate[len(tbl.prefix)] = col
				candidate[len(tbl.prefix)+1] = iface.IfIndex
				out = append(out, candidate)
			}
		}
	}
	s.oids = out
	return s.oids
}

// Start binds the UDP/161 listener and then serves requests until the context
// is cancelled. It is a convenience wrapper over Bind + Serve for callers that
// do not need to observe the bind result separately from the serve loop; it
// returns the bind error synchronously and blocks in Serve only on a
// successful bind.
func (a *Agent) Start(ctx context.Context) error {
	if err := a.Bind(ctx); err != nil {
		return err
	}
	a.Serve()
	return nil
}

// Bind resolves and opens the UDP/161 listener and arms the lifecycle watcher
// that turns ctx cancellation (or a day-2 Stop) into a socket close. It returns
// the bind error SYNCHRONOUSLY so a caller can learn whether the listener
// actually came up before publishing "SNMP is running" state (#5110): a
// discarded bind failure (e.g. a transient UDP/161 conflict) otherwise leaves
// SNMP silently down while the apply records success, and every identical later
// apply no-ops. On success the caller MUST call Serve (directly or in a
// goroutine) to process requests and Stop to release the socket. On failure no
// socket or goroutine is left behind (the watcher is armed only after a
// successful ListenUDP), so the caller can retry a clean Bind.
func (a *Agent) Bind(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", ":161")
	if err != nil {
		return fmt.Errorf("snmp: resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("snmp: listen: %w", err)
	}

	// Derive a lifecycle context so BOTH parent-context cancellation and an
	// explicit day-2 Stop() unblock the watcher below (#4916). Stop calls
	// lifeCancel; the parent ctx cancelling also propagates here.
	lifeCtx, cancel := context.WithCancel(ctx)

	a.mu.Lock()
	a.conn = conn
	a.lifeCancel = cancel
	a.mu.Unlock()

	slog.Info("SNMP agent listening", "addr", ":161")

	go func() {
		<-lifeCtx.Done()
		a.Stop()
	}()
	return nil
}

// Serve runs the request loop on the listener opened by a prior successful
// Bind, blocking until the socket is closed (by Stop / ctx cancellation). It is
// a no-op if no socket is open (Bind failed or was never called, or Stop
// already ran), so it is safe to call unconditionally after Bind.
func (a *Agent) Serve() {
	a.mu.Lock()
	conn := a.conn
	a.mu.Unlock()
	if conn == nil {
		return
	}

	buf := make([]byte, maxPacketSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			a.mu.Lock()
			stopped := a.stopped
			a.mu.Unlock()
			if stopped {
				return
			}
			slog.Error("SNMP read error", "err", err)
			continue
		}

		srcIP := sourceIPForUDP(remoteAddr)
		// #9917 F-139: per-source request budget plus a global aggregate
		// backstop. The loop stays strictly serial -- which is what keeps the
		// lastPacket auth pattern safe -- so fairness comes from shedding an
		// over-budget source BEFORE any MIB work (no per-PDU LinkList snapshot
		// for shed requests) and debiting loop time consumed, rather than from
		// concurrency. Shed is silent (no response), as with unknown-community
		// and source-denied drops: a tooBig reply would cost a BER decode plus,
		// for v3, near-full USM framing, defeating the shed, and an over-budget
		// source is abusive or pathological by construction at this rate. No
		// queue is introduced, so there is nothing to shed via tooBig instead.
		if !a.serveBudget.allow(srcIP) {
			slog.Debug("SNMP: request shed: source over budget", "src", srcIP)
			continue
		}
		start := a.serveBudget.clock()
		resp := a.handlePacketFrom(buf[:n], srcIP)
		// Debit the loop time consumed: without the service charge the refill
		// during handling would replenish the admission token of any request
		// slower than 1/rate, letting back-to-back expensive PDUs hold the
		// serial loop forever without depleting.
		a.serveBudget.account(srcIP, a.serveBudget.clock().Sub(start))
		if resp != nil {
			if _, err := conn.WriteToUDP(resp, remoteAddr); err != nil {
				slog.Error("SNMP write error", "err", err, "remote", remoteAddr)
			}
		}
	}
}

// sourceIPForUDP preserves the source family used by the listener. A dual-stack
// socket represents an IPv4 peer as a 16-byte IPv4-mapped address; that is a
// kernel transport representation of an IPv4 datagram, so pass its 4-byte
// form to the family-strict SNMP clients matcher. An explicit mapped IPv6
// identity outside this socket path remains 16 bytes and cannot match IPv4
// client prefixes.
func sourceIPForUDP(remoteAddr *net.UDPAddr) net.IP {
	if remoteAddr == nil {
		return nil
	}
	if ip4 := remoteAddr.IP.To4(); ip4 != nil {
		return ip4
	}
	return remoteAddr.IP
}

// Stop shuts down the SNMP agent. It is idempotent and safe to call
// concurrently: the ctx-watcher goroutine and a day-2 reconcile both call it.
//
// #4916: besides closing the UDP socket, Stop must (a) cancel the lifecycle
// context so the ctx-watcher goroutine unblocks even when the parent daemon
// context is still live, and (b) signal the trap worker to abandon its queue
// and wait for it to exit — so no goroutine pair leaks per disable/re-enable
// cycle and no queued trap is delivered to a removed/rotated receiver after the
// authorizing config was revoked.
func (a *Agent) Stop() {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return // already stopped: idempotent, no double-close / double-wait
	}
	a.stopped = true
	if a.lifeCancel != nil {
		a.lifeCancel() // unblock the ctx-watcher goroutine
	}
	if a.trapStop != nil {
		close(a.trapStop) // tell the trap worker to abandon its queue
	}
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}
	a.mu.Unlock()

	// Wait for the trap worker to exit OUTSIDE the lock: it may be mid-send,
	// and enqueueTrap briefly takes a.mu. trapWG counts only a worker that
	// actually started, so this returns immediately when none ran.
	a.trapWG.Wait()
	slog.Info("SNMP agent stopped")
}

// handlePacket decodes an SNMP v2c or v3 request and produces a response. It is
// the source-agnostic entry point (tests / non-IP transports); the real serving
// path in Start() calls handlePacketFrom with the UDP source so the #4289
// community `clients` source-IP restriction is enforced.
func (a *Agent) handlePacket(data []byte) []byte {
	return a.handlePacketFrom(data, nil)
}

// handlePacketFrom decodes an SNMP v2c or v3 request and produces a response,
// carrying the request source IP so the v2c community `clients` allowlist
// (#4289) can be enforced. A nil srcIP disables the source check (see
// SNMPCommunity.AllowsSource).
func (a *Agent) handlePacketFrom(data []byte, srcIP net.IP) []byte {
	// Save raw packet for v3 auth verification.
	a.lastPacket = make([]byte, len(data))
	copy(a.lastPacket, data)

	// Decode the outer SEQUENCE.
	tag, msgBody, err := berDecodeHeader(data)
	if err != nil || tag != tagSequence {
		slog.Debug("SNMP: invalid packet, not a SEQUENCE")
		return nil
	}

	// Decode version.
	version, rest, err := berDecodeInteger(msgBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode version")
		return nil
	}

	switch version {
	case snmpVersion1:
		return a.handleV1Packet(rest, srcIP)
	case snmpVersion2c:
		return a.handleV2cPacket(rest, srcIP)
	case snmpVersion3:
		if !a.hasV3Users() {
			slog.Debug("SNMP: v3 not configured")
			return nil
		}
		return a.handleV3Packet(rest)
	default:
		slog.Debug("SNMP: unsupported version", "version", version)
		return nil
	}
}

// handleV2cPacket processes an SNMP v2c message (version already decoded).
// srcIP is the request source (nil disables the source check); it enforces the
// community `clients` source-IP allowlist (#4289).
func (a *Agent) handleV2cPacket(rest []byte, srcIP net.IP) []byte {
	// Decode community string.
	community, rest, err := berDecodeOctetString(rest)
	if err != nil {
		slog.Debug("SNMP: failed to decode community")
		return nil
	}

	// Verify community string and resolve its authorization level.
	comm := a.getCommunity(string(community))
	if comm == nil {
		// SECURITY (#4302): do NOT log the community string — it is the v2c
		// shared secret (SNMPCommunity.Name, redacted everywhere else). Log
		// only the source; known_community=false marks the unknown-community
		// drop, symmetric with the source-denied known_community=true log
		// below (#4289).
		slog.Debug("SNMP: invalid community", "src", srcIP, "known_community", false)
		return nil
	}

	// #4289: enforce the community `clients` source-IP restriction. A community
	// scoped to specific prefixes must be answered ONLY from those sources; a
	// query from a non-permitted source is silently dropped (no response, as
	// with an unknown community). A community without `clients` is allow-all.
	if !comm.AllowsSource(srcIP) {
		// SECURITY: do NOT log the community string — it is the v2c shared
		// secret (SNMPCommunity.Name, redacted everywhere else). Log only the
		// source; known_community=true distinguishes this source-denied KNOWN
		// community from the unknown-community drop above (which also logs no
		// secret value here) so a source-restriction denial can be correlated
		// without exposing the secret (#4289).
		slog.Debug("SNMP: source not permitted for community",
			"src", srcIP, "known_community", true)
		return nil
	}

	// Decode PDU.
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		slog.Debug("SNMP: failed to decode PDU header")
		return nil
	}

	switch pduTag {
	case pduGetRequest:
		return a.handleGet(community, pduBody)
	case pduGetNextRequest:
		return a.handleGetNext(community, pduBody)
	case pduGetBulkRequest:
		return a.handleGetBulk(community, pduBody)
	case pduSetRequest:
		return a.handleSet(community, comm, srcIP, pduBody)
	default:
		slog.Debug("SNMP: unsupported PDU type", "type", pduTag)
		return nil
	}
}

// handleV1Packet processes an SNMPv1 message (RFC 1157; version already decoded
// as 0). It shares the community frame, the source allowlist (#4289), and the
// bounded MIB lookup with the v2c path — the ONLY differences are the response
// rules a v1 manager expects (#5049): a missing/unresolvable OID yields a whole-
// PDU error-status=noSuchName(2) with a 1-based error-index and the request
// varbinds echoed back UNCHANGED (v1 has no per-varbind exception values), and
// no v2-only type (Counter64) ever reaches the wire.
//
// Before #5049 the version-0 case fell through to the default "unsupported
// version" drop, so the agent emitted v1 traps but silently dropped every v1
// GET/GETNEXT poll — a legacy v1 manager saw the device as down.
func (a *Agent) handleV1Packet(rest []byte, srcIP net.IP) []byte {
	// Decode community string (same frame as v2c).
	community, rest, err := berDecodeOctetString(rest)
	if err != nil {
		slog.Debug("SNMP: failed to decode community")
		return nil
	}

	// Verify community string and resolve its authorization level.
	comm := a.getCommunity(string(community))
	if comm == nil {
		// SECURITY (#4302): never log the community string (the v1 shared
		// secret); log only the source, symmetric with the v2c path (#4289).
		slog.Debug("SNMP: invalid community", "src", srcIP, "known_community", false)
		return nil
	}

	// #4289: enforce the community `clients` source-IP restriction, identical to
	// the v2c path — a scoped community answers ONLY permitted sources.
	if !comm.AllowsSource(srcIP) {
		slog.Debug("SNMP: source not permitted for community",
			"src", srcIP, "known_community", true)
		return nil
	}

	// Decode PDU.
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		slog.Debug("SNMP: failed to decode PDU header")
		return nil
	}

	switch pduTag {
	case pduGetRequest:
		return a.handleV1Get(community, pduBody)
	case pduGetNextRequest:
		return a.handleV1GetNext(community, pduBody)
	case pduSetRequest:
		return a.handleV1Set(community, comm, srcIP, pduBody)
	default:
		// v1 has no GETBULK (a v2c/v3 addition); any other PDU type is dropped,
		// matching the v2c default.
		slog.Debug("SNMP: unsupported v1 PDU type", "type", pduTag)
		return nil
	}
}

// echoVarbinds builds the request-echo varbind list an SNMPv1 error response
// carries: each requested OID with a NULL value. RFC 1157 §4.1.x specifies that
// on an error the GetResponse-PDU's variable-bindings field is that of the
// received request — v1 never rewrites individual varbind values with exception
// markers the way v2c does.
func echoVarbinds(oids [][]int) []varbind {
	vbs := make([]varbind, 0, len(oids))
	for _, oid := range oids {
		vbs = append(vbs, varbind{oid: oid, tag: tagNull, value: nil})
	}
	return vbs
}

// handleV1Get processes an SNMPv1 GET (RFC 1157 §4.1.2). All requested OIDs must
// resolve; the first that does not fails the WHOLE PDU with noSuchName and the
// 1-based index of the offending varbind, echoing the request varbinds. A
// Counter64-typed object is not representable in v1 (RFC 2089), so a direct GET
// of one is treated as a missing name → noSuchName, and no Counter64 is emitted.
func (a *Agent) handleV1Get(community []byte, pduBody []byte) []byte {
	requestID, _, _, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode v1 GET PDU", "err", err)
		return nil
	}

	// One interface snapshot for the whole PDU (#4013).
	snap := a.newIfSnapshot()
	varbinds := make([]varbind, 0, len(oids))
	for i, oid := range oids {
		val, valTag := a.getOIDValueSnap(oid, snap)
		if val == nil || valTag == tagCounter64 {
			// Missing name, or a v2-only Counter64 that v1 cannot carry: fail
			// the whole PDU with noSuchName + the 1-based offending index, and
			// echo the request varbinds unchanged.
			return a.buildResponseVersion(snmpVersion1, community, requestID,
				errNoSuchName, i+1, echoVarbinds(oids))
		}
		varbinds = append(varbinds, varbind{oid: oid, tag: valTag, value: val})
	}

	return a.boundGetResponseVersion(snmpVersion1, community, requestID, varbinds)
}

// handleV1GetNext processes an SNMPv1 GETNEXT (RFC 1157 §4.1.3). Each requested
// OID advances lexicographically to the next served object, STEPPING OVER any
// Counter64-typed node (RFC 2089 — a v1 walk must not surface a type it cannot
// encode). Running off the end of the MIB view fails the PDU with noSuchName and
// the 1-based index, echoing the request varbinds (v1 has no endOfMibView).
func (a *Agent) handleV1GetNext(community []byte, pduBody []byte) []byte {
	requestID, _, _, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode v1 GETNEXT PDU", "err", err)
		return nil
	}

	// One interface snapshot for the whole PDU (#4013).
	snap := a.newIfSnapshot()
	varbinds := make([]varbind, 0, len(oids))
	for i, oid := range oids {
		nextOID, val, valTag := a.findNextV1OIDSnap(oid, snap)
		if nextOID == nil {
			// End of MIB view: v1 signals this as noSuchName on the whole PDU
			// (there is no per-varbind endOfMibView exception).
			return a.buildResponseVersion(snmpVersion1, community, requestID,
				errNoSuchName, i+1, echoVarbinds(oids))
		}
		varbinds = append(varbinds, varbind{oid: nextOID, tag: valTag, value: val})
	}

	return a.boundGetResponseVersion(snmpVersion1, community, requestID, varbinds)
}

// findNextV1OIDSnap is findNextOIDSnap for the SNMPv1 MIB view: it returns the
// next served OID after `oid` that is representable in v1 (RFC 2089), skipping
// any Counter64-typed node so a v1 GETNEXT/GET-walk steps over the 64-bit
// high-capacity counters instead of stalling or emitting a type v1 cannot carry.
// Returns (nil, nil, 0) at the end of the MIB view.
// #7433: the loop below is the ONE unbounded walk over the successor lookup,
// and it used to terminate only because `findNextOIDSnap` returns a successor
// that STRICTLY advances past the cursor. Nothing asserted that, and the
// property lives in a DIFFERENT function — so someone optimising the successor
// lookup could not see what depended on it.
//
// Worse, the failure mode was a HANG, not a wrong answer. It was found by
// mutation: changing the successor's search predicate from `> 0` to `>= 0`
// makes an OID its own successor and this loop spins forever. The cell did not
// fail, it hung — which produces no `--- FAIL` line, so a harness gating on
// named failures scores it as a void or an escape rather than a defect.
//
// It is not reachable from the wire today: GETNEXT performs one lookup per
// request OID with no loop, and GETBULK is bounded by max-repetitions plus the
// #6551 byte budget. But both of those bounds are INCIDENTAL — they are
// properties of the callers, not of this loop — so this now carries its own.
//
// The bound is the view length, which is the most steps a strictly-advancing
// walk can possibly take: every iteration must consume at least one OID from an
// ordered view, so exceeding it proves the invariant is broken. Exceeding it
// returns end-of-view, which is fail-CLOSED (a v1 walk ends early rather than
// spinning a CPU serving no one), and logs loudly enough to attribute.
func (a *Agent) findNextV1OIDSnap(oid []int, snap *ifSnapshot) ([]int, []byte, byte) {
	return a.findNextV1OIDSnapWith(oid, snap, a.findNextOIDSnap)
}

// findNextV1OIDSnapWith is findNextV1OIDSnap with the successor lookup passed
// in (#7433).
//
// PARAMETERIZED SO THE BOUND CAN BE EXERCISED, not for production flexibility —
// there is one production caller and it passes `a.findNextOIDSnap`. The step
// bound below can only fire when the successor fails to advance, and the
// successor is correct, so with the real lookup the guard is unreachable and a
// mutation deleting it escapes every test. A guard whose failure mode is a HANG
// is the one most worth binding, so the loop takes the successor as an argument
// and a test supplies a non-advancing one.
//
// This is the same shape as extracting a body from its snapshot handoff: the
// production path is unchanged and the thing that was untestable becomes
// reachable, without a behaviour hook on the production struct.
func (a *Agent) findNextV1OIDSnapWith(
	oid []int,
	snap *ifSnapshot,
	nextOID func([]int, *ifSnapshot) []int,
) ([]int, []byte, byte) {
	cur := oid
	// +1 so the bound can never be tighter than a legitimate walk: the first
	// call may start below the view, and a walk that skips every OID in it is
	// still correct.
	maxSteps := len(snap.mibOIDs()) + 1
	for steps := 0; ; steps++ {
		if steps > maxSteps {
			slog.Warn("SNMP: v1 successor walk exceeded the MIB view length; the "+
				"successor lookup is not strictly advancing (#7433)",
				"start_oid", oid, "cursor", cur, "steps", steps, "view_len", maxSteps-1)
			return nil, nil, 0
		}
		next := nextOID(cur, snap)
		if next == nil {
			return nil, nil, 0
		}
		val, valTag := a.getOIDValueSnap(next, snap)
		if val == nil || valTag == tagCounter64 {
			// Not representable in v1 (Counter64) or unexpectedly empty: advance
			// past it and keep walking.
			cur = next
			continue
		}
		return next, val, valTag
	}
}

// handleV1Set processes an SNMPv1 SET (RFC 1157 §4.1.5). The agent serves only
// read-only objects, and v1 has neither the noAccess nor notWritable
// error-status the v2c handler uses; per the RFC 2089 §2.1 SNMPv2→SNMPv1 error
// mapping BOTH map to noSuchName(2). So a SET — whether denied for a read-only
// community or refused because no served object is writable — returns
// noSuchName with error-index 1 and the request varbinds echoed.
func (a *Agent) handleV1Set(community []byte, comm *config.SNMPCommunity, srcIP net.IP, pduBody []byte) []byte {
	requestID, _, _, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode v1 SET PDU", "err", err)
		return nil
	}

	if !communityCanWrite(comm) {
		// SECURITY (#4302): log the source and (non-secret) authorization level,
		// never the community string, matching the v2c #4289 pattern.
		slog.Debug("SNMP: v1 SET denied, community not authorized read-write",
			"src", srcIP, "authorization", comm.Authorization)
	}

	// Read-only community OR read-write community with no writable object: both
	// collapse to noSuchName in v1. error-index is the 1-based position of the
	// offending varbind (the first one when any OID is present).
	errIdx := 0
	if len(oids) > 0 {
		errIdx = 1
	}
	return a.buildResponseVersion(snmpVersion1, community, requestID,
		errNoSuchName, errIdx, echoVarbinds(oids))
}

// communityCanWrite reports whether the community is authorized for SET
// (write) operations. Only "read-write" grants write access; the compiler
// defaults an unspecified authorization to "read-only".
func communityCanWrite(c *config.SNMPCommunity) bool {
	return c != nil && c.Authorization == "read-write"
}

// SETAuthorized reports whether the named community would pass the SET
// access-control gate against the agent's CURRENTLY LIVE config — i.e. it
// resolves the community from the same snapshotCfg() the request-serving path
// uses (getCommunity) and applies the same communityCanWrite predicate
// handleSet enforces. An unknown community returns false (handleSet drops it).
//
// This is a read-only observation of the live authorization gate, exported so
// the daemon-package reconcile wiring test can assert that a committed
// read-write -> read-only downgrade actually reached the running agent via
// applyConfigLocked -> UpdateConfig. It takes no listener lock (getCommunity
// reads cfg under cfgMu.RLock), so it is safe to call while the agent serves.
func (a *Agent) SETAuthorized(community string) bool {
	return communityCanWrite(a.getCommunity(community))
}

// handleSet processes a SET request (RFC 3416 pduSetRequest, 0xa3).
//
// Access control comes first: a community without "read-write" authorization
// is denied with noAccess before any write is attempted. This is the
// security boundary the operator configures with
// `set snmp community <name> authorization read-write` — without this gate
// the agent would honor SET from any valid community regardless of the
// configured authorization (a Junos divergence).
//
// A read-write community passes the authorization gate, but the agent serves
// only read-only MIB objects (system group, ifTable, ifXTable), so the write
// itself is refused per-varbind with notWritable. No served object is
// mutable, so a successful SET is never produced here — but the read-only vs
// read-write distinction is enforced and observable in the error-status.
func (a *Agent) handleSet(community []byte, comm *config.SNMPCommunity, srcIP net.IP, pduBody []byte) []byte {
	requestID, _, _, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode SET PDU", "err", err)
		return nil
	}

	// Echo the requested OIDs back in the response varbind list (with null
	// values) so the response is well-formed regardless of outcome.
	var varbinds []varbind
	for _, oid := range oids {
		varbinds = append(varbinds, varbind{oid: oid, tag: tagNull, value: nil})
	}

	if !communityCanWrite(comm) {
		// Read-only (or unspecified) community: deny write access.
		// SECURITY (#4302): do NOT log the community string — it is the v2c
		// shared secret. Log the source and the (non-secret) authorization
		// level so the denial is correlatable without exposing the secret,
		// matching the #4289 pattern.
		slog.Debug("SNMP: SET denied, community not authorized read-write",
			"src", srcIP, "authorization", comm.Authorization)
		errIdx := 0
		if len(oids) > 0 {
			errIdx = 1
		}
		return a.buildResponse(community, requestID, errNoAccess, errIdx, varbinds)
	}

	// Authorized for write, but the agent exposes no writable objects. Refuse
	// the first varbind with notWritable per RFC 3416.
	errIdx := 0
	if len(oids) > 0 {
		errIdx = 1
	}
	return a.buildResponse(community, requestID, errNotWritable, errIdx, varbinds)
}

// handleGet processes a GET request.
func (a *Agent) handleGet(community []byte, pduBody []byte) []byte {
	requestID, _, _, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode GET PDU", "err", err)
		return nil
	}

	// One interface snapshot for the whole PDU (#4013): the ifTable read
	// happens at most once regardless of how many OIDs the GET requests.
	snap := a.newIfSnapshot()
	var varbinds []varbind
	for _, oid := range oids {
		val, valTag := a.getOIDValueSnap(oid, snap)
		if val == nil {
			// getOIDValueSnap classifies the missing object/instance so v2c
			// can emit the RFC 3416 exception appropriate to this OID.
			varbinds = append(varbinds, varbind{oid: oid, tag: valTag, value: nil})
		} else {
			varbinds = append(varbinds, varbind{oid: oid, tag: valTag, value: val})
		}
	}

	return a.boundGetResponse(community, requestID, varbinds)
}

// handleGetNext processes a GETNEXT request.
func (a *Agent) handleGetNext(community []byte, pduBody []byte) []byte {
	requestID, _, _, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode GETNEXT PDU", "err", err)
		return nil
	}

	// One interface snapshot for the whole PDU (#4013).
	snap := a.newIfSnapshot()
	var varbinds []varbind
	for _, oid := range oids {
		nextOID := a.findNextOIDSnap(oid, snap)
		if nextOID == nil {
			// End of MIB view.
			varbinds = append(varbinds, varbind{oid: oid, tag: tagEndOfMibView, value: nil})
		} else {
			val, valTag := a.getOIDValueSnap(nextOID, snap)
			varbinds = append(varbinds, varbind{oid: nextOID, tag: valTag, value: val})
		}
	}

	return a.boundGetResponse(community, requestID, varbinds)
}

// boundGetResponse builds a v2c GET/GETNEXT GetResponse and enforces the local
// message-size ceiling (#4918, residual of #2612 which bounded only GETBULK).
// A GET/GETNEXT carries a fixed 1:1 varbind-per-request-OID contract, so —
// unlike GETBULK, whose oversized walk the manager continues with a follow-up
// request — an oversized GET/GETNEXT response cannot be trimmed. Per RFC 3416
// §4.2.1/§4.2.2 it is replaced with tooBig + an empty varbind list rather than
// emitting a datagram larger than maxPacketSize.
func (a *Agent) boundGetResponse(community []byte, requestID int, varbinds []varbind) []byte {
	return a.boundGetResponseVersion(snmpVersion2c, community, requestID, varbinds)
}

// boundGetResponseVersion is boundGetResponse parameterized on the message
// version field, so the SNMPv1 GET/GETNEXT handlers (#5049) share the identical
// size ceiling and tooBig fallback as v2c while emitting a version-0 envelope.
func (a *Agent) boundGetResponseVersion(version int, community []byte, requestID int, varbinds []varbind) []byte {
	resp := a.buildResponseVersion(version, community, requestID, errNoError, 0, varbinds)
	if len(resp) > effectiveMaxSize(maxPacketSize) {
		return a.buildResponseVersion(version, community, requestID, errTooBig, 0, nil)
	}
	return resp
}

// handleGetBulk processes a GETBULK request (RFC 3416).
func (a *Agent) handleGetBulk(community []byte, pduBody []byte) []byte {
	requestID, nonRepeaters, maxRepetitions, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode GETBULK PDU", "err", err)
		return nil
	}

	if nonRepeaters < 0 {
		nonRepeaters = 0
	}
	if maxRepetitions < 0 {
		maxRepetitions = 0
	}
	if maxRepetitions > 100 {
		maxRepetitions = 100 // safety cap
	}

	// One interface snapshot for the whole PDU (#4013): a GETBULK walk over N
	// interfaces returns O(N) varbinds; without this the pre-#4013 code did two
	// netlink LinkList dumps (findNextOID + getOIDValue) per varbind — an
	// O(N)/O(N²) RTM_GETLINK storm. The snapshot bounds it to one dump per PDU.
	snap := a.newIfSnapshot()

	// Bound the response to maxPacketSize (RFC 3416 §4.2.3). v2c carries no
	// per-request msgMaxSize, so the local maximum is the only ceiling. The
	// SAME ceiling is handed to buildBulkVarbinds so the grid stops expanding
	// once it has produced more bytes than the response can carry (#6551) —
	// the work is bounded before it is done, not trimmed after.
	maxSize := effectiveMaxSize(maxPacketSize)
	varbinds := a.buildBulkVarbinds(oids, nonRepeaters, maxRepetitions, snap, maxSize)

	// Trim trailing varbinds until the encoded message fits; the manager
	// continues the walk from the last returned OID. Only if nothing fits do we
	// fall back to tooBig with an empty varbind list.
	resp, ok := trimToFit(varbinds, maxSize, func(vbs []varbind) []byte {
		return a.buildResponse(community, requestID, errNoError, 0, vbs)
	})
	if !ok {
		return a.buildResponse(community, requestID, errTooBig, 0, nil)
	}
	return resp
}

// buildBulkVarbinds produces the varbind list for a GETBULK request in RFC 3416
// §4.2.3 order. The first nonRepeaters OIDs are treated like GETNEXT (one
// varbind each). The remaining OIDs are "repeaters", each walked up to
// maxRepetitions times. It is shared verbatim by the v2c handler and the v3
// dispatcher so both encode identical wire order.
//
// The repeater varbinds are emitted repetition-major, NOT column-major (#5065).
// For R repeater columns and M repetitions the order is
//
//	rep0-col0, rep0-col1, ..., rep0-col(R-1), rep1-col0, ...
//
// i.e. varbind index nonRepeaters + rep*R + col. RFC 3416 §4.2.3 mandates this
// interleaving so a table-oriented manager reconstructs rows by the known
// repeater width R; the pre-#5065 code nested the repetition loop inside the
// per-column loop and emitted col0-rep0..col0-rep(M-1) then col1-... (column-
// major), which mis-associates columns for R >= 2.
//
// Each repeater column advances its OWN GETNEXT cursor across repetitions. When
// a column runs past the end of its MIB view it emits endOfMibView (named with
// that column's terminal OID) in its own cell for that repetition and every
// later repetition, so the row*R+col index stays aligned to the originating
// column instead of collapsing the grid.
//
// maxBytes is the response ceiling the caller will bound the encoded message to
// (effectiveMaxSize of the local maximum for v2c, of the advertised msgMaxSize
// for v3). Expansion STOPS as soon as the varbinds produced so far already
// encode to more than that (#6551): the grid is repeaters*maxRepetitions cells
// and every cell costs a findNextOIDSnap MIB walk plus a getOIDValueSnap, while
// repeaterCount = len(oids)-nonRepeaters is bounded only by how many varbinds
// the manager can pack into one request datagram. A 4094-byte v2c GETBULK with
// 580 minimal repeater OIDs and max-repetitions >= 100 built 58,000 varbinds to
// return 116 — ~0.67 s of MIB walking on the single serial SNMP goroutine per
// datagram, against a ~2.5 us baseline poll, so a handful of requests per second
// saturates SNMP permanently (monitoring blindness).
//
// The stop is output-neutral. bulkBudget accumulates the EXACT encoded size of
// each emitted varbind, which is a strict lower bound on the size of the
// response message carrying it: the message only ADDS bytes on top — the
// varbind-list SEQUENCE header, the PDU fields, the version/community or
// USM/scopedPDU envelope, and for authPriv the CBC block padding around the
// encrypted scopedPDU. So once the accumulated varbind bytes exceed maxBytes,
// every message built
// from that prefix — and from any longer one — is already over the ceiling and
// would be discarded by the caller's trimToFit. Dropping those cells therefore
// yields a byte-identical response while never performing the walk. RFC 3416
// §4.2.3 explicitly sanctions returning fewer varbinds than requested: "If the
// size of the message encapsulating the Response-PDU containing the requested
// number of variable bindings would be greater than either a local constraint
// or the maximum message size of the originator, then the response is generated
// with a lesser number of variable bindings. [...] Note that the number of
// variable bindings removed has no relationship to the values of N, M, or R."
// The removal is from the END of the ordered set, which is exactly the prefix
// this stop preserves, so the repetition-major order and the per-column
// endOfMibView placement of #5065 are untouched.
func (a *Agent) buildBulkVarbinds(oids [][]int, nonRepeaters, maxRepetitions int, snap *ifSnapshot, maxBytes int) []varbind {
	var varbinds []varbind
	budget := bulkBudget{max: maxBytes}

	// Non-repeaters: a single GETNEXT for each of the first nonRepeaters OIDs.
	for i := 0; i < nonRepeaters && i < len(oids); i++ {
		var vb varbind
		nextOID := a.findNextOIDSnap(oids[i], snap)
		if nextOID == nil {
			vb = varbind{oid: oids[i], tag: tagEndOfMibView, value: nil}
		} else {
			val, valTag := a.getOIDValueSnap(nextOID, snap)
			vb = varbind{oid: nextOID, tag: valTag, value: val}
		}
		varbinds = append(varbinds, vb)
		if budget.add(vb) {
			return varbinds
		}
	}

	// Repeaters: one persistent GETNEXT cursor per repeater column, advanced
	// across repetitions and emitted repetition-major.
	repeaterCount := len(oids) - nonRepeaters
	if repeaterCount <= 0 || maxRepetitions <= 0 {
		return varbinds
	}
	cursors := make([][]int, repeaterCount)
	exhausted := make([]bool, repeaterCount)
	for c := 0; c < repeaterCount; c++ {
		cursors[c] = oids[nonRepeaters+c]
	}
	for rep := 0; rep < maxRepetitions; rep++ {
		for c := 0; c < repeaterCount; c++ {
			var vb varbind
			nextOID := []int(nil)
			if !exhausted[c] {
				nextOID = a.findNextOIDSnap(cursors[c], snap)
			}
			switch {
			case exhausted[c]:
				// Column already ran off the end of the MIB view; keep its cell
				// filled with endOfMibView so the row*R+col mapping holds.
				vb = varbind{oid: cursors[c], tag: tagEndOfMibView, value: nil}
			case nextOID == nil:
				vb = varbind{oid: cursors[c], tag: tagEndOfMibView, value: nil}
				exhausted[c] = true
			default:
				val, valTag := a.getOIDValueSnap(nextOID, snap)
				vb = varbind{oid: nextOID, tag: valTag, value: val}
				cursors[c] = nextOID
			}
			varbinds = append(varbinds, vb)
			if budget.add(vb) {
				return varbinds
			}
		}
	}
	return varbinds
}

// bulkBudget tracks how many encoded bytes the varbinds of an in-progress
// GETBULK grid already occupy, so expansion can stop at the response ceiling
// instead of materializing the whole repeaters*maxRepetitions grid and trimming
// afterwards (#6551).
type bulkBudget struct {
	used int // exact encoded size of the varbinds accounted so far
	max  int // response ceiling in bytes (effectiveMaxSize of the caller's max)
}

// add accounts vb against the budget and reports whether the ceiling has been
// passed — i.e. whether the caller must stop expanding the grid. It returns
// true only once the accumulated varbind bytes STRICTLY exceed max, so the
// varbind that trips it is still emitted and the caller never stops one cell
// short of a prefix that would have fit.
func (b *bulkBudget) add(vb varbind) bool {
	b.used += varbindEncodedLen(vb)
	return b.used > b.max
}

// varbindEncodedLen returns the exact number of bytes vb contributes to the
// varbind list of an encoded response. It MUST stay in step with the per-varbind
// encoding in buildResponseVersion / buildV3Response — an overestimate would
// stop a GETBULK grid short of varbinds that would have fit and shrink the
// response. TestVarbindEncodedLenMatchesEncoder_6551 pins the two together.
func varbindEncodedLen(vb varbind) int {
	oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(vb.oid))
	var valBytes []byte
	if vb.tag == tagNoSuchObject || vb.tag == tagNoSuchInstance || vb.tag == tagEndOfMibView {
		valBytes = berEncodeTLV(vb.tag, nil)
	} else {
		valBytes = berEncodeValue(vb.tag, vb.value)
	}
	body := len(oidBytes) + len(valBytes)
	return 1 + len(berEncodeLength(body)) + body
}

// getCommunity returns the configured community matching the given string, or
// nil if none matches. The returned struct carries the authorization level
// (read-only / read-write) used to gate SET requests.
func (a *Agent) getCommunity(community string) *config.SNMPCommunity {
	cfg := a.snapshotCfg()
	if cfg == nil || cfg.Communities == nil {
		return nil
	}
	// Communities is keyed by community name, so look it up directly.
	return cfg.Communities[community]
}

// isValidCommunity checks if the given community string is configured.
func (a *Agent) isValidCommunity(community string) bool {
	return a.getCommunity(community) != nil
}

// getOIDValue returns the encoded value and BER tag for a given OID. It is the
// one-shot convenience form: it builds a fresh per-call interface snapshot.
// Request handlers that walk multiple OIDs in one PDU MUST use getOIDValueSnap
// with a single shared snapshot instead, so the ifTable read happens once per
// PDU (#4013).
func (a *Agent) getOIDValue(oid []int) ([]byte, byte) {
	return a.getOIDValueSnap(oid, a.newIfSnapshot())
}

// oidAbsenceTag classifies an OID that has no value in this MIB view. A
// requested scalar object is identified by its OID without the required .0
// instance; table objects are identified by their column under the table
// prefix. A known object with a missing/malformed instance is noSuchInstance,
// while an OID naming no served object is noSuchObject (RFC 3416 §4.2.1).
func oidAbsenceTag(oid []int) byte {
	for _, objectOID := range staticOIDs {
		if len(objectOID) > 0 && oidHasPrefix(oid, objectOID[:len(objectOID)-1]) {
			return tagNoSuchInstance
		}
	}

	for _, table := range []struct {
		prefix []int
		cols   []int
	}{
		{oidIfTablePrefix, ifTableColumns},
		{oidIfXTablePrefix, ifXTableColumns},
	} {
		if !oidHasPrefix(oid, table.prefix) {
			continue
		}
		rest := oid[len(table.prefix):]
		if len(rest) == 0 {
			return tagNoSuchObject
		}
		for _, col := range table.cols {
			if rest[0] == col {
				return tagNoSuchInstance
			}
		}
		return tagNoSuchObject
	}

	return tagNoSuchObject
}

// getOIDValueSnap is getOIDValue served from a caller-provided per-PDU
// interface snapshot. All ifTable/ifXTable/ifNumber reads go through snap so a
// multi-varbind walk triggers at most one netlink LinkList.
func (a *Agent) getOIDValueSnap(oid []int, snap *ifSnapshot) ([]byte, byte) {
	cfg := a.snapshotCfg()
	// System MIB group
	if oidEqual(oid, oidSysDescr) {
		desc := "xpf stateful firewall"
		if cfg != nil && cfg.Description != "" {
			desc = cfg.Description
		}
		return []byte(desc), tagOctetString
	}
	if oidEqual(oid, oidSysObjectID) {
		return berEncodeOID([]int{1, 3, 6, 1, 4, 1, 99999, 1}), tagObjectIdentifier
	}
	if oidEqual(oid, oidSysUpTime) {
		uptime := time.Since(a.startTime)
		hundredths := int(uptime.Milliseconds() / 10)
		return berEncodeTimeTicks(hundredths), tagTimeTicks
	}
	if oidEqual(oid, oidSysContact) {
		contact := ""
		if cfg != nil {
			contact = cfg.Contact
		}
		return []byte(contact), tagOctetString
	}
	if oidEqual(oid, oidSysName) {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}
		return []byte(hostname), tagOctetString
	}
	if oidEqual(oid, oidSysLocation) {
		location := ""
		if cfg != nil {
			location = cfg.Location
		}
		return []byte(location), tagOctetString
	}

	// interfaces.ifNumber
	if oidEqual(oid, oidIfNumber) {
		ifaces := snap.get()
		return berEncodeIntegerValue(len(ifaces)), tagInteger
	}

	// ifTable: 1.3.6.1.2.1.2.2.1.<col>.<ifIndex>
	if len(oid) == len(oidIfTablePrefix)+2 && oidHasPrefix(oid, oidIfTablePrefix) {
		col := oid[len(oidIfTablePrefix)]
		ifIdx := oid[len(oidIfTablePrefix)+1]
		val, tag := getIfTableValue(col, ifIdx, snap.get())
		if val == nil {
			return nil, oidAbsenceTag(oid)
		}
		return val, tag
	}

	// ifXTable: 1.3.6.1.2.1.31.1.1.1.<col>.<ifIndex>
	if len(oid) == len(oidIfXTablePrefix)+2 && oidHasPrefix(oid, oidIfXTablePrefix) {
		col := oid[len(oidIfXTablePrefix)]
		ifIdx := oid[len(oidIfXTablePrefix)+1]
		val, tag := getIfXTableValue(col, ifIdx, snap.get())
		if val == nil {
			return nil, oidAbsenceTag(oid)
		}
		return val, tag
	}

	return nil, oidAbsenceTag(oid)
}

// getIfTableValue returns the value for a specific ifTable column and ifIndex,
// served from the caller's per-PDU interface snapshot (#4013) rather than a
// fresh netlink dump.
func getIfTableValue(col, ifIdx int, ifaces []IfData) ([]byte, byte) {
	var iface *IfData
	for i := range ifaces {
		if ifaces[i].IfIndex == ifIdx {
			iface = &ifaces[i]
			break
		}
	}
	if iface == nil {
		return nil, 0
	}

	switch col {
	case 1: // ifIndex
		return berEncodeIntegerValue(iface.IfIndex), tagInteger
	case 2: // ifDescr
		return []byte(iface.IfDescr), tagOctetString
	case 3: // ifType
		return berEncodeIntegerValue(iface.IfType), tagInteger
	case 4: // ifMtu
		return berEncodeIntegerValue(iface.IfMtu), tagInteger
	case 5: // ifSpeed
		return berEncodeGauge32(iface.IfSpeed), tagGauge32
	case 7: // ifAdminStatus
		return berEncodeIntegerValue(iface.AdminStatus), tagInteger
	case 8: // ifOperStatus
		return berEncodeIntegerValue(iface.OperStatus), tagInteger
	case 10: // ifInOctets
		return berEncodeCounter32(iface.InOctets), tagCounter32
	case 16: // ifOutOctets
		return berEncodeCounter32(iface.OutOctets), tagCounter32
	}
	return nil, 0
}

// getIfXTableValue returns the value for a specific ifXTable column and
// ifIndex, served from the caller's per-PDU interface snapshot (#4013) rather
// than a fresh netlink dump.
func getIfXTableValue(col, ifIdx int, ifaces []IfData) ([]byte, byte) {
	var iface *IfData
	for i := range ifaces {
		if ifaces[i].IfIndex == ifIdx {
			iface = &ifaces[i]
			break
		}
	}
	if iface == nil {
		return nil, 0
	}

	switch col {
	case 1: // ifName
		name := iface.IfName
		if name == "" {
			name = iface.IfDescr
		}
		return []byte(name), tagOctetString
	case 2: // ifInMulticastPkts
		return berEncodeCounter32(iface.InMulticastPkts), tagCounter32
	case 3: // ifInBroadcastPkts
		return berEncodeCounter32(iface.InBroadcastPkts), tagCounter32
	case 4: // ifOutMulticastPkts
		return berEncodeCounter32(iface.OutMulticastPkts), tagCounter32
	case 5: // ifOutBroadcastPkts
		return berEncodeCounter32(iface.OutBroadcastPkts), tagCounter32
	case 6: // ifHCInOctets
		return berEncodeCounter64(iface.HCInOctets), tagCounter64
	case 7: // ifHCInUcastPkts
		return berEncodeCounter64(iface.HCInUcastPkts), tagCounter64
	case 10: // ifHCOutOctets
		return berEncodeCounter64(iface.HCOutOctets), tagCounter64
	case 11: // ifHCOutUcastPkts
		return berEncodeCounter64(iface.HCOutUcastPkts), tagCounter64
	case 15: // ifHighSpeed
		return berEncodeGauge32(iface.IfHighSpeed), tagGauge32
	case 18: // ifAlias
		return []byte(iface.IfAlias), tagOctetString
	}
	return nil, 0
}

// findNextOID returns the next OID in the tree after the given OID, or nil. It
// is the one-shot convenience form: it builds a fresh per-call interface
// snapshot. Request handlers that walk in one PDU MUST use findNextOIDSnap with
// a single shared snapshot instead (#4013).
func (a *Agent) findNextOID(oid []int) []int {
	return a.findNextOIDSnap(oid, a.newIfSnapshot())
}

// findNextOIDSnap is findNextOID served from a caller-provided per-PDU
// interface snapshot, so a GETNEXT/GETBULK walk reads the interface list once
// per PDU rather than once per next-OID lookup.
func (a *Agent) findNextOIDSnap(oid []int, snap *ifSnapshot) []int {
	// #6597: binary search the per-PDU ordered MIB view instead of scanning it.
	// sort.Search returns the first index whose OID sorts strictly after `oid`,
	// which is exactly the GETNEXT successor.
	view := snap.mibOIDs()
	i := sort.Search(len(view), func(i int) bool {
		return oidCompare(view[i], oid) > 0
	})
	if i == len(view) {
		return nil
	}
	return view[i]
}

// varbind holds a single OID-value binding.
type varbind struct {
	oid   []int
	tag   byte
	value []byte
}

// effectiveMaxSize returns the byte budget a GETBULK response must fit
// within: the smaller of the manager's advertised msgMaxSize and our own
// maxPacketSize. The advertised value is first clamped up to minMsgMaxSize so
// a manager that advertises a tiny (or, for v3, mis-decoded) msgMaxSize cannot
// force every response down to nothing — RFC 3412 guarantees every engine
// accepts at least minMsgMaxSize bytes. v2c carries no msgMaxSize on the wire,
// so callers pass maxPacketSize there and this returns maxPacketSize.
func effectiveMaxSize(advertised int) int {
	if advertised < minMsgMaxSize {
		advertised = minMsgMaxSize
	}
	if advertised > maxPacketSize {
		return maxPacketSize
	}
	return advertised
}

// trimToFit bounds a GETBULK response to maxSize bytes (RFC 3416 §4.2.3). It
// builds the response from vbs via build; if the full encoded message exceeds
// maxSize it binary-searches the largest leading prefix of varbinds whose
// encoded message still fits and returns that truncated-but-well-formed
// response (#4918: O(log n) rebuilds, not the old O(n) decrement-and-rebuild).
// A manager that receives a trimmed response continues the walk with a
// follow-up GETBULK from the last returned OID, so trimming (not tooBig) is the
// normal, preferred outcome.
//
// build must construct a complete SNMP response message from the supplied
// varbind list (it captures the version-specific envelope: v2c community frame
// or v3 USM/scopedPDU/auth/priv frame, request-id, error fields). It is called
// repeatedly with successively shorter prefixes of vbs.
//
// If even the zero-varbind response cannot fit maxSize, trimFit reports ok
// false; the caller then returns errTooBig with an empty varbind list. With a
// minMsgMaxSize (>= 484) floor and our small fixed MIB this only happens for a
// pathological maxSize, but it is handled rather than emitting an oversized
// datagram.
func trimToFit(vbs []varbind, maxSize int, build func([]varbind) []byte) (resp []byte, ok bool) {
	// Fast path: the full varbind set almost always fits, so try it first —
	// one build, no trimming (the common case, unchanged cost).
	full := build(vbs)
	if len(full) <= maxSize {
		return full, true
	}

	// Oversized. The encoded message length is monotonic non-decreasing in the
	// number of leading varbinds (each varbind adds bytes), so binary-search
	// the largest prefix that still fits instead of dropping one varbind at a
	// time and rebuilding. This turns the trim from O(n) rebuilds (each O(n),
	// and for v3 each re-running USM framing/HMAC/encryption on the single
	// serial SNMP goroutine) into O(log n) rebuilds — #4918, the O(n^2)
	// residual of #2612. The result is identical to the decrement-and-rebuild:
	// the longest leading prefix of vbs whose encoded response is <= maxSize.
	empty := build(vbs[:0])
	if len(empty) > maxSize {
		return nil, false // even a zero-varbind response cannot fit
	}
	// Invariant: build(vbs[:lo]) fits, build(vbs[:hi]) does not (len(vbs) was
	// just shown oversized). Narrow until lo+1 == hi; lo is then the answer.
	lo, hi := 0, len(vbs)
	best := empty
	for lo+1 < hi {
		mid := (lo + hi) / 2
		r := build(vbs[:mid])
		if len(r) <= maxSize {
			lo, best = mid, r
		} else {
			hi = mid
		}
	}
	return best, true
}

// buildResponse constructs a complete SNMP v2c response packet.
func (a *Agent) buildResponse(community []byte, requestID int, errorStatus int, errorIndex int, varbinds []varbind) []byte {
	return a.buildResponseVersion(snmpVersion2c, community, requestID, errorStatus, errorIndex, varbinds)
}

// buildResponseVersion constructs a complete SNMP GetResponse packet with an
// explicit message version field. v2c callers pass snmpVersion2c (via
// buildResponse); the SNMPv1 handlers (#5049) pass snmpVersion1 so the response
// carries a version-0 envelope. The PDU shape (GetResponse tag, request-id /
// error-status / error-index / varbind-list body) is identical for v1 and v2c —
// only the version field and the caller-chosen error-status/varbind semantics
// differ. v1 callers never pass an exception-tag varbind (noSuchObject /
// noSuchInstance / endOfMibView), so those v2-only markers never reach the wire
// on a v1 response.
func (a *Agent) buildResponseVersion(version int, community []byte, requestID int, errorStatus int, errorIndex int, varbinds []varbind) []byte {
	// Encode varbind list.
	var vbListBytes []byte
	for _, vb := range varbinds {
		oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(vb.oid))
		var valBytes []byte
		if vb.tag == tagNoSuchObject || vb.tag == tagNoSuchInstance || vb.tag == tagEndOfMibView {
			valBytes = berEncodeTLV(vb.tag, nil)
		} else {
			valBytes = berEncodeValue(vb.tag, vb.value)
		}
		pair := append(oidBytes, valBytes...)
		vbListBytes = append(vbListBytes, berEncodeTLV(tagSequence, pair)...)
	}
	vbListEncoded := berEncodeTLV(tagSequence, vbListBytes)

	// Encode PDU body: request-id, error-status, error-index, varbind-list.
	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(errorStatus)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(errorIndex)...)
	pduBody = append(pduBody, vbListEncoded...)

	pduEncoded := berEncodeTLV(pduGetResponse, pduBody)

	// Encode message: version, community, PDU.
	msgBody := berEncodeIntegerTLV(version)
	msgBody = append(msgBody, berEncodeTLV(tagOctetString, community)...)
	msgBody = append(msgBody, pduEncoded...)

	return berEncodeTLV(tagSequence, msgBody)
}
