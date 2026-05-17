package runtime

import "time"

type SessionFamily string

const (
	SessionFamilyInet  SessionFamily = "inet"
	SessionFamilyInet6 SessionFamily = "inet6"
)

type SessionDeltaReason string

const (
	SessionDeltaReasonOpen   SessionDeltaReason = "open"
	SessionDeltaReasonClose  SessionDeltaReason = "close"
	SessionDeltaReasonUpdate SessionDeltaReason = "update"
)

type SessionIdentity struct {
	Protocol      uint8
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	IngressZone   string
	EgressZone    string
	IngressZoneID uint16
	EgressZoneID  uint16
}

type SessionState struct {
	Disposition      string
	Origin           string
	EgressIfindex    int
	TXIfindex        int
	TunnelEndpointID uint16
	TXVLANID         uint16
	NextHop          string
	NeighborMAC      string
	SrcMAC           string
	NATSrcIP         string
	NATDstIP         string
	NATSrcPort       uint16
	NATDstPort       uint16
	FabricRedirect   bool
	FabricIngress    bool
}

type RuntimeStatus struct {
	Enabled                bool
	ForwardingArmed        bool
	ForwardingSupported    bool
	UnsupportedReasons     []string
	LastSnapshotGeneration uint64
	LastFIBGeneration      uint32
}

type SessionDelta struct {
	Timestamp  time.Time
	Slot       uint32
	QueueID    uint32
	WorkerID   uint32
	Interface  string
	Ifindex    int
	Family     SessionFamily
	Key        SessionIdentity
	Value      SessionState
	OwnerRGID  int
	Reason     SessionDeltaReason
	Generation uint64
}

type SessionDeltaSnapshot struct {
	Deltas       []SessionDelta
	Status       RuntimeStatus
	BackendEpoch uint64
	Truncated    bool
}

type SessionDeltaSource interface {
	DrainSessionDeltas(max uint32) (SessionDeltaSnapshot, error)
	ExportOwnerRGSessions(rgIDs []int, max uint32) (SessionDeltaSnapshot, error)
	SessionSyncSweepProfile() (enabled bool, activeInterval, idleInterval time.Duration)
}
