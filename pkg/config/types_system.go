package config

import (
	"encoding/json"
	"fmt"
	"sort"
)

// System and platform-services configuration: system stanza, userspace
// dataplane, syslog, SNMP, login, REST API auth, RPM, flow-monitoring,
// forwarding-options, firewall filters/policers, and DHCP server/relay.

// SystemConfig holds system-level configuration.
type SystemConfig struct {
	HostName     string
	DomainName   string   // system domain-name (e.g. "example.com")
	DomainSearch []string // system domain-search (search domains)
	TimeZone     string
	NameServers  []string // DNS server addresses
	NTPServers   []string // NTP server addresses
	// NTPServerOptions carries the Junos per-server MODIFIERS, keyed by the
	// server address they follow (#7132). Empty for a server authored without
	// modifiers, which is the common case.
	//
	// Kept BESIDE NTPServers rather than replacing it with a struct slice: every
	// existing consumer reads the address list and none of them needed changing,
	// so widening the shared field would have been churn in three packages to
	// serve one of them.
	NTPServerOptions   map[string]NTPServerOption
	NTPThreshold       int    // NTP threshold in seconds (0 = default)
	NTPThresholdAction string // "accept" or "reject"
	NoRedirects        bool   // disable ICMP redirects
	BackupRouter       string // backup default gateway IP
	BackupRouterDst    string // backup router destination prefix
	Lo0FilterInputV4   string // lo0 unit 0 family inet filter input (host-bound filtering)
	Lo0FilterInputV6   string // lo0 unit 0 family inet6 filter input (host-bound filtering)
	DataplaneType      string // empty defaults to "userspace"; explicit "ebpf" is legacy; "dpdk" is retired (#1525) and tolerated via rewriteRetiredDataplaneType (pkg/configstore/dataplane_retire.go) at both Store.Load and Store.SyncApply for stored-config rolling upgrade
	UserspaceDataplane *UserspaceConfig
	InternetOptions    *InternetOptionsConfig
	Services           *SystemServicesConfig
	Syslog             *SystemSyslogConfig
	DHCPServer         DHCPServerConfig
	SNMP               *SNMPConfig
	Login              *LoginConfig
	// LoginDroppedByPacking records that the candidate DID author a `system
	// login` path but wrote it packed onto an ancestor statement line, so the
	// compiler dropped the stanza (#6662/#6706). It is NOT a finding count and
	// NOT a commit verdict — the packed gate owns those. It is the one bit
	// pkg/daemon needs to tell two states apart that otherwise both arrive as
	// `Login == nil`:
	//
	//   - nothing configured RBAC at all -> pkg/cli's legacy unset-class mode,
	//     which permits every command and renders secrets in cleartext. That
	//     contract is deliberate (permissions.go) and must not change.
	//   - RBAC WAS configured and compiled away -> the same nil, reached from a
	//     config that reads as restrictive. Landing there opens the box.
	//
	// The flag is set for EVERY packed `system login` ancestor path, including
	// the short prefixes the gate deliberately does not report (`system login;`,
	// `system login user;`). Those commit clean by design — rejecting them
	// would be a new rejection of config that master accepts — but they are not
	// inert: the NESTED spelling of the same text compiles a non-nil empty
	// LoginConfig and denies every non-root caller, while the packed spelling
	// compiles nil and permits everyone. Reporting is the gate's job; making
	// the two spellings agree at RUNTIME is this flag's.
	//
	// It matters most on the TOLERANT ingress (Store.Load at boot,
	// Store.SyncApply from a peer), where the #1960 no-brick doctrine downgrades
	// the packed finding to a warning and KEEPS the config.
	//
	// It is NOT only the tolerant path (corrected, #6706 review r11). An
	// earlier revision said "strict commit rejects, so on that path the flag
	// is never read". Strict rejects the prefixes that NAME something, but it
	// ACCEPTS the content-free ones — `system login;`, `system login user;` —
	// because the reporting gate deliberately does not report a prefix naming
	// nobody. Those commit strictly AND set this flag, so a strict commit is a
	// live path for it, not one where it is dead.
	LoginDroppedByPacking bool
	RootAuthentication    *RootAuthConfig
	Archival              *ArchivalConfig
	// MasterPassword is a misnomer kept for the Junos token: it holds the
	// `system master-password pseudorandom-function <fn>` value, i.e. the PRF
	// ALGORITHM-SELECTOR NAME (e.g. hmac-sha256), NOT key material. The actual
	// master key is node-local + HKDF-derived and never stored in config (see
	// compiler_system.go / configstore/crypto.go), so this field is not a
	// secret and is intentionally a plain string, not config.Secret (#2053).
	MasterPassword           string   // PRF algorithm-selector name (not a secret)
	LicenseAutoUpdate        string   // license autoupdate URL
	DisabledProcesses        []string // processes marked "disable"
	PersistGroupsInheritance bool     // system commit persist-groups-inheritance (syntax accepted, runtime no-op)

	// ManagementInterface is the #1922 Item 3B/Item 4 explicit management
	// interface override ("" = unset, defaults to fxp0). When set, it joins
	// the protected set (never brought down by the unmanaged strip); an
	// explicit non-fxp0 value also NARROWS fxp0 out of the auto-protection
	// (OQ-D escape valve, so fxp0 can be repurposed as a revenue port).
	// The typed field is wired through the protected-set resolver; the
	// config-mode `set system management-interface <name>` parser grammar is
	// deferred (the no-config bootstrap default-route signal is the primary
	// lifeline path; this leaf is the operator override once a config
	// exists). See docs/research/1922-safe-bootstrap-daemon/plan.md Item 3B.
	ManagementInterface string
}

// UserspaceConfig holds separate-process userspace dataplane configuration.
type UserspaceConfig struct {
	Binary        string            `json:"binary"`                 // helper process path
	ControlSocket string            `json:"control_socket"`         // unix control socket path
	EventSocket   string            `json:"event_socket,omitempty"` // event stream socket path (auto-derived if empty)
	StateFile     string            `json:"state_file"`             // helper state file path
	Workers       int               `json:"workers"`                // worker thread count
	RingEntries   int               `json:"ring_entries"`           // planned AF_XDP ring entries
	PollMode      string            `json:"poll_mode"`              // "busy-poll" (default) or "interrupt"
	SharedUMEM    *SharedUMEMConfig `json:"shared_umem,omitempty"`

	// RSSIndirectionDisabled, when true, disables D3 RSS indirection
	// reshaping (#785 / #797). Default is enabled — operators opt out
	// explicitly via `set system dataplane rss-indirection disable`.
	// Serialized as an inverted bool so omission implies the safe
	// default (enabled) and only disabled deploys carry the field.
	RSSIndirectionDisabled bool `json:"rss_indirection_disabled,omitempty"`

	// ClaimHostTunables is the #801 opt-in gate for host-scope knobs
	// that are NOT interface-scoped (CPU governor + netdev_budget + the
	// mlx5 adaptive-coalescence flip). D3's rss-indirection stays bound
	// to a specific NIC so it is safe to apply by default; the Step-0
	// knobs reach outside xpfd's interface allowlist and the operator
	// must explicitly opt in via
	// `set system dataplane claim-host-tunables true`. When false (the
	// default), xpfd never writes to cpufreq scaling_governor,
	// /proc/sys/net/core/netdev_budget, or mlx5 adaptive-rx/tx, even if
	// the derived default values are non-zero. Per-iface rx-usecs/tx-usecs
	// are still applied when coalescence is otherwise configured —
	// those are bound to the same mlx5 interface as D3.
	ClaimHostTunables bool `json:"claim_host_tunables,omitempty"`

	// Phase B Step-0 tunables (#801). Each is a first-class knob with
	// a documented default so operators can override without editing
	// systemd units or sysctl.conf. Omission leaves the zero value and
	// daemon resolves the default at apply-time (empty string / 0).

	// CPUGovernor requests a cpufreq governor on every writable
	// /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor node on the
	// host. Accepted values:
	//   "performance"          — explicit (default)
	//   "schedutil"            — explicit override
	//   "default" / ""         — skip (leave whatever the host has set)
	// Running inside a VM without a writable cpufreq sysfs is a no-op
	// (detected at apply-time); the daemon logs a single informational
	// line noting the skip. On bare metal the setting is applied on
	// daemon start and re-applied on every commit.
	CPUGovernor string `json:"cpu_governor,omitempty"`

	// NetdevBudget is the value written to /proc/sys/net/core/netdev_budget.
	// 0 means "leave the kernel default" (no write); the daemon
	// resolves a non-zero default at apply-time (600, per #801).
	NetdevBudget int `json:"netdev_budget,omitempty"`

	// CoalescenceAdaptiveDisabled, when true, disables mlx5 adaptive
	// coalescing on every userspace-dp-bound mlx5 interface
	// (`ethtool -C <iface> adaptive-rx off adaptive-tx off`). Default
	// is true (disable) at apply-time; the config knob is
	// `set system dataplane coalescence adaptive disable|enable`.
	// Serialized as an inverted bool so the most-common "disable"
	// deploy case is the zero value.
	//
	// CoalescenceAdaptiveExplicit distinguishes "operator explicitly
	// set enable" from "omitted, use default". Default is
	// "disabled" so an omitted knob leaves the field at
	// CoalescenceAdaptiveDisabled=false but the daemon still applies
	// "adaptive off". An explicit "enable" sets Explicit=true and
	// Disabled=false so the daemon skips the ethtool write (operator
	// override).
	CoalescenceAdaptiveDisabled bool `json:"coalescence_adaptive_disabled,omitempty"`
	CoalescenceAdaptiveExplicit bool `json:"coalescence_adaptive_explicit,omitempty"`

	// CoalescenceRXUsecs / CoalescenceTXUsecs set the rx-usecs and
	// tx-usecs coalescing ceiling on mlx5 interfaces. 0 means "use
	// daemon default" (8 µs per #801). Only written when adaptive
	// coalescing is disabled — with adaptive on, the kernel controls
	// these values dynamically and writes are a waste.
	CoalescenceRXUsecs int `json:"coalescence_rx_usecs,omitempty"`
	CoalescenceTXUsecs int `json:"coalescence_tx_usecs,omitempty"`

	// RetiredKnobsSeen records which retired DPDK-era `system dataplane`
	// knobs (cores, memory, socket-mem, rx-mode, ports — consumer deleted
	// in #1525) were present in the compiled tree. They are accepted for
	// stored-config compatibility but have no effect; the compiler turns
	// each into a commit warning (userspaceRetiredKnobWarnings, #1892).
	// Compile-time bookkeeping only — never serialized.
	RetiredKnobsSeen []string `json:"-"`
}

// SharedUMEMConfig is an optional AF_XDP shared-UMEM policy override passed
// through to the userspace helper. Omission lets the helper attempt
// opportunistic cross-NIC shared UMEM and fall back per binding when the live
// device/kernel path cannot support it. Phase 0 artifacts are audit evidence:
// the helper logs mismatches but does not gate runtime selection on them.
//
// Phase0ArtifactFile is the operator-DECLARED path to the machine-readable
// Phase 0 audit artifact (#5300). It intentionally carries only the declared
// path, NEVER the node-local file's parsed contents: the artifact is audit
// evidence only (docs/shared-umem-plan.md "Phase 0"), does not gate runtime
// shared-UMEM selection, and MUST NOT make the compiled typed config depend on
// a node-local file — otherwise the identical committed tree would compile to a
// DIFFERENT typed config on a peer / after restart when the file is absent or
// differs, breaking same-tree->same-config determinism and HA replay. The audit
// read itself is performed non-fatally by sharedUMEMAuditWarnings: a missing /
// unreadable / non-regular / oversized / malformed artifact becomes a commit
// WARNING, never a compile error, and never changes this typed config.
type SharedUMEMConfig struct {
	Mode               string   `json:"mode,omitempty"`
	Interfaces         []string `json:"interfaces,omitempty"`
	Phase0ArtifactFile string   `json:"phase0_artifact_file,omitempty"`
}

// RootAuthConfig holds root-authentication settings.
type RootAuthConfig struct {
	EncryptedPassword Secret // crypt(3) hash; redacted on JSON/YAML marshal (#2053)
	SSHKeys           []string
}

// ArchivalConfig holds configuration archival settings.
type ArchivalConfig struct {
	TransferOnCommit bool
	TransferInterval int // minutes between auto-archives (0 = on commit only)
	ArchiveSites     []string
	ArchiveDir       string // local directory for archives (default /var/lib/xpf/archive)
	MaxArchives      int    // max number of archives to keep (default 10)

	// #651: archive site URLs for which an inline `password "$9$..."`
	// credential was configured. bpfrx's archival shells out to `scp`
	// with `-o BatchMode=yes` and cannot use inline passwords, so a
	// password here is ignored silently unless we warn. We keep the
	// URLs (not the passwords) so the warning can name the site.
	ArchiveSitesWithPassword []string
}

// MarshalJSON redacts a credential embedded in an RPM test TARGET (#6733).
//
// An `http-get` probe's target is a URL, and a monitored endpoint routinely
// carries an auth token in it. For the icmp-ping / tcp-ping probe types the
// target is a bare IP or hostname, which RedactURL returns unchanged
// (measured, including v6 literals), so this is a no-op for them rather than a
// probe-type conditional that could drift from the type list.
//
// The receiver is a VALUE for robustness rather than necessity: RPMProbe holds
// `Tests map[string]*RPMTest`, so a pointer receiver would be reached today. A
// value receiver is reached through BOTH a *RPMTest and an RPMTest, so it keeps
// working if the container is ever changed to hold values — a redaction that
// silently stops applying when a field's container changes shape is the failure
// this whole change is about.
//
// The alias type sheds this method to avoid recursion while preserving every
// field, so a field added to RPMTest later is still marshalled.
func (t RPMTest) MarshalJSON() ([]byte, error) {
	type alias RPMTest
	v := alias(t)
	v.Target = RedactURL(v.Target)
	return json.Marshal(v)
}

// MarshalJSON redacts the license auto-update URL (#6733).
//
// `system license autoupdate url <url>` is a fetch endpoint, and a licence
// server URL routinely carries the entitlement token inline or as a query
// parameter. The field is named for what it is, so the name-keyed redaction
// pass never reached it and the authenticated REST GET returned it verbatim.
//
// The receiver is a VALUE, not a pointer, deliberately: Config holds
// `System SystemConfig` by value, and encoding/json only promotes to a
// pointer method when the value is addressable. A pointer receiver here would
// work when a *Config is marshalled and silently do NOTHING when a Config is
// marshalled by value — a redaction that depends on the caller's syntax is
// worse than none, because it tests green on whichever form the test happens
// to use.
//
// The alias type sheds this method to avoid recursion while preserving every
// field, so a field added to SystemConfig later is still marshalled.
func (s SystemConfig) MarshalJSON() ([]byte, error) {
	type alias SystemConfig
	v := alias(s)
	v.LicenseAutoUpdate = RedactURL(v.LicenseAutoUpdate)
	return json.Marshal(v)
}

// MarshalJSON redacts the credential-bearing URL slots on an ArchivalConfig
// (#6733).
//
// `system archival configuration archive-sites <url>` takes a transfer URL, and
// the Junos idiom puts the credential inline — `scp://user:pw@host:/dir` or an
// ftp URL with a password. Both lists hold that URL verbatim:
// ArchiveSitesWithPassword exists precisely BECAUSE a site carried an inline
// `password`, so it is the highest-value list on this struct and was returned
// in full by the authenticated REST GET.
//
// The redaction pass is keyed on field NAMES that look secret; these are named
// for what they are (sites), so no name-keyed rule reaches them. RedactURL
// leaves a credential-free URL untouched, so an ordinary config renders
// identically.
//
// The alias type sheds this method to avoid recursion while preserving every
// field, so a field added to ArchivalConfig later is still marshalled.
func (a *ArchivalConfig) MarshalJSON() ([]byte, error) {
	if a == nil {
		return []byte("null"), nil
	}
	type alias ArchivalConfig
	v := alias(*a)
	v.ArchiveSites = redactURLSlice(v.ArchiveSites)
	v.ArchiveSitesWithPassword = redactURLSlice(v.ArchiveSitesWithPassword)
	return json.Marshal(v)
}

// redactURLSlice returns a redacted COPY of a URL list, leaving the caller's
// slice untouched. Copying matters: these marshallers run on an alias of a
// live *Config, and the backing array is shared with it — redacting in place
// would mutate the running configuration as a side effect of serving a GET.
func redactURLSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = RedactURL(s)
	}
	return out
}

// InternetOptionsConfig holds internet-options settings.
type InternetOptionsConfig struct {
	NoIPv6RejectZeroHopLimit bool
}

// SystemServicesConfig holds system services (SSH, web-management).
type SystemServicesConfig struct {
	SSH                *SSHServiceConfig
	WebManagement      *WebManagementConfig
	DNSEnabled         bool // system services dns
	DNSProxyConfigured bool // system services dns dns-proxy (syntax accepted, runtime no-op)
	// DynamicDNS is the `system services dynamic-dns` provider catalog + engine
	// tunables (#2691 P2, plan §5.9). It is the OPERATOR-FACING shared catalog
	// the per-interface Surface A `dynamic-dns` bindings reference by name
	// (credentials configured once, referenced by scope). nil == no Surface A
	// DDNS configured.
	DynamicDNS *DDNSServicesConfig
}

// DDNSServicesConfig is the `system services dynamic-dns` block (#2691 P2,
// plan §5.9): a named provider catalog (referenced by per-interface Surface A
// bindings) plus the global engine tunables (the inadyn period/forced-update
// analogues). nil == no Surface A DDNS configured (Surface B's DHCP-lease DDNS
// is unaffected — it keeps its inline stanza under dhcp-local-server).
type DDNSServicesConfig struct {
	// Providers is the named provider catalog, keyed by provider name. A
	// per-interface `dynamic-dns provider <name>` binding references one of
	// these entries (credentials + transport binding configured once here).
	Providers map[string]*DDNSProvider
	// ForcedRefreshSeconds is the wire-update FLOOR for an unchanged address
	// (inadyn idea #7, plan §5.5): the engine re-asserts desired state every
	// reconcile but sends a wire UPDATE for an unchanged address at most once
	// per this interval. 0 == the engine default (24h).
	ForcedRefreshSeconds int
	// ErrorBackoffMaxSeconds caps the per-scope flat error backoff (inadyn idea
	// #8, plan §5.5): a failing provider is not hammered at the poll cadence
	// (ban-avoidance). 0 == the engine default (1h).
	ErrorBackoffMaxSeconds int
}

// DDNSProvider is one named entry in the `system services dynamic-dns provider`
// catalog (#2691 P2, plan §5.2/§5.9). It carries the backend selection, the
// credentials (config.Secret-redacted), and the per-provider transport binding
// (source/interface/VRF). P2 implements the rfc2136 backend; the HTTP backends
// (dyndns2/cloudflare/route53/generic) are reserved enum values that P3
// implements (an unimplemented backend publishes nothing and warns at commit).
type DDNSProvider struct {
	// Name is the provider identity (the `provider <name>` token), used by
	// per-interface bindings to reference this catalog entry.
	Name string
	// Backend selects the DNS-update mechanism. "rfc2136" (default, live in P2)
	// publishes over RFC 2136 UPDATE. "dyndns2" / "cloudflare" / "route53" /
	// "generic" are reserved for P3 (the HTTP providers).
	Backend string
	// UpdateServer is the RFC 2136 target authoritative DNS, host or host:port.
	UpdateServer string
	// TSIGKeyName / TSIGAlgorithm / TSIGSecret are the TSIG credentials for
	// authenticated RFC 2136 updates. TSIGSecret is the sensitive HMAC key,
	// redacted by the Secret type on every marshal and by String() below.
	TSIGKeyName   string
	TSIGAlgorithm string
	TSIGSecret    Secret
	// SourceAddress / DestinationInterface / RoutingInstance scope the UPDATE
	// TRANSPORT for this provider (the same source-binding model as the Surface B
	// per-family leaves, #2665). All optional. As of #2846 the HTTP backends
	// (dyndns2/cloudflare/route53/generic) AND the external checkip probe bind to
	// these too (via the shared HTTP client's DialContext) — not only RFC 2136.
	SourceAddress        string
	DestinationInterface string
	RoutingInstance      string

	// --- HTTP-provider fields (#2691 P3; plan §5.2/§5.9). Only meaningful for
	// the dyndns2 / cloudflare / route53 / generic backends; ignored by rfc2136.

	// Server overrides the dyndns2 update endpoint host (or full base URL). When
	// empty the dyndns2 backend uses the built-in endpoint for the named provider
	// (Backend == a known dyndns2 provider name) or the canonical dyn.com path.
	Server string
	// Username / Password are the HTTP Basic-auth credentials (dyndns2 + generic).
	// Password is sensitive (config.Secret-redacted on every marshal + String()).
	Username string
	Password Secret
	// URLTemplate is the generic-templated backend's update URL with %h
	// (hostname), %i (IP), %u (username), %p (password), %% literal-percent
	// specifiers (inadyn "custom"; plan §3.7 idea #3). config-only — no Go code
	// per provider.
	URLTemplate string
	// OKResponse is the generic backend's success-substring matcher; an HTTP 2xx
	// body containing this substring is a success. Empty ⇒ the default matcher
	// set ("good", "nochg", "ok", "true", "updated").
	OKResponse string
	// APIToken is the Cloudflare API token (config.Secret-redacted). Emitted as
	// `Authorization: Bearer <token>`.
	APIToken Secret
	// Zone is the Cloudflare DNS zone name (e.g. example.net) the record lives in;
	// the backend resolves the zone id at update time (the inadyn `setup` step).
	Zone string
	// AWSAccessKeyID / AWSSecretAccessKey / AWSRegion / HostedZoneID are the
	// Route 53 SigV4 credentials + target. AWSSecretAccessKey is sensitive.
	AWSAccessKeyID     string
	AWSSecretAccessKey Secret
	AWSRegion          string
	HostedZoneID       string
	// CheckIPURL is the optional external checkip endpoint (opt-in; plan §5.3) a
	// scope referencing this provider may use as the address source when the
	// firewall is behind NAT. Subject to the bogus-IP allowlist. Empty ⇒ no
	// checkip (interface/DHCP observation only).
	CheckIPURL string
	// CheckIPAllowlist is a comma/space-separated list of bogus addresses to
	// ignore in a checkip response (the inadyn except[] case — e.g. a checkip
	// page that embeds the resolver/anycast IP like 1.1.1.1). Empty ⇒ none.
	CheckIPAllowlist string
}

// String redacts every credential-bearing field so a %v/%s/slog format of a
// DDNSProvider never leaks an operator secret (logging hygiene, mirrors
// DHCPDynamicDNSConfig). The Secret-typed fields (TSIGSecret, Password,
// APIToken, AWSSecretAccessKey) redact to the secret sentinel. The URL fields
// (Server, URLTemplate, CheckIPURL) are NOT Secret-typed — they are plain
// strings — but the generic backend explicitly supports credentials embedded
// in the URL template (userinfo, or a token in the query string, see
// pkg/ddns/backend_generic.go) and a checkip-url can carry an API key, so each
// is run through RedactURL which strips userinfo and the query string while
// keeping the scheme/host/path for diagnostics (#2781).
func (p *DDNSProvider) String() string {
	if p == nil {
		return "<nil>"
	}
	red := func(s Secret) string {
		if s != "" {
			return SecretRedacted
		}
		return ""
	}
	return fmt.Sprintf("DDNSProvider{name=%q backend=%q update-server=%q "+
		"tsig-key=%q tsig-alg=%q tsig-secret=%q source-address=%q "+
		"destination-interface=%q routing-instance=%q server=%q username=%q "+
		"password=%q url-template=%q ok-response=%q api-token=%q zone=%q "+
		"aws-access-key=%q aws-secret-key=%q aws-region=%q hosted-zone-id=%q "+
		"checkip-url=%q checkip-allowlist=%q}",
		p.Name, p.Backend, RedactURL(p.UpdateServer), p.TSIGKeyName, p.TSIGAlgorithm,
		red(p.TSIGSecret), p.SourceAddress, p.DestinationInterface, p.RoutingInstance,
		RedactURL(p.Server), p.Username, red(p.Password), RedactURL(p.URLTemplate), p.OKResponse,
		red(p.APIToken), p.Zone, p.AWSAccessKeyID, red(p.AWSSecretAccessKey),
		p.AWSRegion, p.HostedZoneID, RedactURL(p.CheckIPURL), p.CheckIPAllowlist)
}

// MarshalJSON redacts the URL-bearing leaves on every JSON render of a
// provider (#6703). The Secret-typed credentials (TSIGSecret, Password,
// APIToken, AWSSecretAccessKey) are already handled by Secret.MarshalJSON, and
// String() has redacted these same URL fields since #2781 — but the REST
// config-read surface does neither: GET /api/v1/config json-encodes the
// compiled *Config directly, so a plain string field marshalled VERBATIM. That
// route leaked even a userinfo credential, which RedactURL has always stripped,
// because nothing on the path ever called it.
//
// The alias type sheds this method (so json.Marshal does not recurse) while
// keeping every field and tag identical, and the copy is redacted in place —
// so a field added to DDNSProvider later is still marshalled, and only these
// four are rewritten. A hand-built object literal would silently drop new
// fields, which is the failure mode that makes hand-maintained render lists
// unsafe.
func (p *DDNSProvider) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("null"), nil
	}
	type alias DDNSProvider
	v := alias(*p)
	v.UpdateServer = RedactURL(v.UpdateServer)
	v.Server = RedactURL(v.Server)
	v.URLTemplate = RedactURL(v.URLTemplate)
	v.CheckIPURL = RedactURL(v.CheckIPURL)
	return json.Marshal(v)
}

// SSHServiceConfig holds SSH service settings.
type SSHServiceConfig struct {
	RootLogin   string   // "allow", "deny", "deny-password"
	KeyExchange []string // sshd KexAlgorithms (key-exchange methods)
	// #4305 S-4: sshd hardening knobs rendered into the xpf sshd drop-in.
	Ciphers         []string // sshd Ciphers
	MACs            []string // sshd MACs
	ConnectionLimit int      // sshd MaxStartups (0 = unset)
	// ClientAlive* use presence flags because 0 is a meaningful sshd value
	// (interval 0 disables keepalives; count-max 0 drops on the first miss).
	ClientAliveInterval    int
	ClientAliveIntervalSet bool
	ClientAliveCountMax    int
	ClientAliveCountMaxSet bool
	// ProtocolVersion is recognized but accept-with-advisory: sshd is
	// SSH-2-only, so v2 is a no-op and any other value gets a compile
	// advisory (no `Protocol` line is emitted — the directive is gone from
	// modern sshd).
	ProtocolVersion string
}

// WebManagementConfig holds web management settings.
type WebManagementConfig struct {
	HTTP                bool
	HTTPS               bool
	HTTPInterface       string         // interface binding for HTTP
	HTTPSInterface      string         // interface binding for HTTPS
	SystemGeneratedCert bool           // auto-generated TLS certificate
	APIAuth             *APIAuthConfig // REST API authentication
}

// APIAuthConfig holds REST API authentication settings.
type APIAuthConfig struct {
	Users   []*APIAuthUser // basic auth users
	APIKeys []Secret       // bearer/X-API-Key tokens; redacted on marshal (#2053)
}

// APIAuthUser defines a basic auth user for the REST API.
type APIAuthUser struct {
	Username string
	Password Secret // redacted on JSON/YAML marshal (#2053)
}

// SystemSyslogConfig holds traditional Junos system syslog config.
type SystemSyslogConfig struct {
	Hosts []*SyslogHostConfig
	Files []*SyslogFileConfig
	Users []*SyslogUserConfig // user destinations (e.g. "user * { any emergency; }")
}

// SyslogUserConfig defines a syslog user destination.
type SyslogUserConfig struct {
	User string // "*" = all users
	// Selectors holds EVERY facility/severity pair authored under this user
	// destination, in config order.
	//
	// #7187: these were a scalar Facility/Severity pair, and the compiler
	// ASSIGNED rather than appended, so `user * { daemon info; auth warning; }`
	// kept only `auth warning` — the last pair parsed. Every earlier selector
	// was discarded at compile time, before any render or validation could see
	// it, so the operator got no warning and no record under the facility they
	// authored first. The host sink already carried a slice
	// (SyslogHostConfig.Facilities); this brings the user sink to the same
	// shape. A destination with no authored pair has an empty slice and
	// renders `*.*`, which is what an empty scalar pair rendered before.
	Selectors []SyslogFacility
}

// SyslogHostConfig defines a syslog host destination.
type SyslogHostConfig struct {
	Address    string
	Facilities []SyslogFacility // multiple facility/severity pairs
	// SourceAddress binds the outgoing syslog socket to a specific local
	// source IP (`host <h> source-address <ip>`). Empty = OS-selected
	// source. Wired into logging.SyslogClient's source-bind (#4303 S-1).
	SourceAddress string
	// Port overrides the destination UDP port (`host <h> port <n>`).
	// 0 = the RFC 3164 default 514 (#4303 S-1).
	Port            int
	AllowDuplicates bool
}

// SyslogFacility represents a facility/severity pair in syslog config.
type SyslogFacility struct {
	Facility string // "daemon", "change-log", "any", etc.
	Severity string // "info", "warning", "error", "emergency", "any"
}

// SyslogFileConfig defines a syslog file destination.
type SyslogFileConfig struct {
	Name string
	// Selectors holds EVERY facility/severity pair authored under this file
	// destination, in config order. See SyslogUserConfig.Selectors — the same
	// #7187 assign-instead-of-append defect applied here, so
	// `file messages { daemon info; auth warning; }` logged only auth records.
	Selectors []SyslogFacility
	// ArchiveConfigured records that an `archive` container was present
	// under this syslog file (#7146). In Junos a bare `archive;` enables
	// archiving with defaults, so PRESENCE alone — not just a populated
	// sub-statement — is what the operator asked for and what the commit
	// advisory reports.
	//
	// xpf implements NONE of it: applySyslogFiles writes an rsyslog drop-in
	// that directs matching messages to /var/log/<name> and nothing more.
	// There is no rotation, size cap, retention count, start-time schedule,
	// or off-box transfer anywhere in the daemon for a syslog FILE (the
	// `archive`/`archiveTransfer` machinery in pkg/daemon belongs to the
	// unrelated `system archival configuration` feature, which archives the
	// CONFIG, not logs). These two fields exist only so ValidateConfig can
	// name the inert block at commit — the #4316 accept-with-advisory
	// pattern — and are read by nothing else.
	ArchiveConfigured bool
	// ArchiveKnobs holds the sorted, deduplicated `archive` sub-statement
	// KEYWORDS found under this file (files, size, start-time,
	// transfer-interval, archive-sites, world-readable, no-world-readable).
	// Keywords ONLY, never their values: an `archive-sites` URL can embed
	// credentials (scp://user:pass@host/), and the advisory echoes this
	// slice — the same "name the keyword, never the leaf value" rule
	// systemInertKnobWarnings applies to the NTP authentication-key.
	ArchiveKnobs []string
}

// SNMPConfig holds SNMP agent configuration.
type SNMPConfig struct {
	Location    string
	Contact     string
	Description string
	Communities map[string]*SNMPCommunity
	TrapGroups  map[string]*SNMPTrapGroup
	V3Users     map[string]*SNMPv3User
	// ClientLists holds the `snmp client-list <name> { <prefix> [restrict]; }`
	// definitions, keyed by list name (#9416). It is the DEFINITION surface;
	// enforcement happens through each referencing community's resolved
	// Clients, so nothing reads this at serve time. Retained so
	// `show configuration` and the API render what the operator wrote, and so a
	// list that no community references is still visible rather than dropped.
	ClientLists map[string][]SNMPClient
}

// MarshalJSON redacts the SNMPv1/v2c community strings on the JSON surface
// (#2053). The community string is the secret AND the Communities map key,
// so a plain map marshal would leak it as a JSON object key regardless of
// SNMPCommunity.MarshalJSON (which only redacts the value's Name field). To
// avoid emitting secret keys, the Communities map is rendered as a sorted
// slice of (already-redacting) SNMPCommunity values — dropping the
// secret-equals-the-key. V3Users/TrapGroups keys are usernames/group names
// (not secrets) and pass through unchanged. The in-memory map (and its
// lookup-by-community-string in pkg/snmp) is untouched.
func (s SNMPConfig) MarshalJSON() ([]byte, error) {
	// NOTE: the snmpAlias projection below is intentionally duplicated in
	// MarshalYAML; the two MUST stay in sync. If you add/rename a field here,
	// mirror it in MarshalYAML or the JSON and YAML redaction surfaces diverge.
	type snmpAlias struct {
		Location    string
		Contact     string
		Description string
		Communities []*SNMPCommunity
		TrapGroups  map[string]*SNMPTrapGroup
		V3Users     map[string]*SNMPv3User
		// #9416: the alias enumerates fields EXPLICITLY, so a field added to
		// SNMPConfig and not added here silently vanishes from the API surface.
		// A client-list name and its prefixes are not secrets (the community
		// string is), and an operator inspecting why a community is restricted
		// needs to see the list it names.
		ClientLists map[string][]SNMPClient `json:",omitempty"`
	}
	a := snmpAlias{
		Location:    s.Location,
		Contact:     s.Contact,
		Description: s.Description,
		TrapGroups:  s.TrapGroups,
		V3Users:     s.V3Users,
		ClientLists: s.ClientLists,
	}
	if len(s.Communities) > 0 {
		names := make([]string, 0, len(s.Communities))
		for name := range s.Communities {
			names = append(names, name)
		}
		sort.Strings(names)
		a.Communities = make([]*SNMPCommunity, 0, len(names))
		for _, name := range names {
			a.Communities = append(a.Communities, s.Communities[name])
		}
	}
	return json.Marshal(a)
}

// MarshalYAML mirrors MarshalJSON for the gopkg.in/yaml.v3 marshaller,
// redacting the community-string map keys by rendering Communities as a
// sorted slice (future-proofing; no config YAML marshaller exists today —
// #2053).
func (s SNMPConfig) MarshalYAML() (any, error) {
	// Keep this projection in sync with MarshalJSON above (same snmpAlias +
	// Communities map->sorted-slice redaction).
	type snmpAlias struct {
		Location    string
		Contact     string
		Description string
		Communities []*SNMPCommunity
		TrapGroups  map[string]*SNMPTrapGroup
		V3Users     map[string]*SNMPv3User
		// #9416: the alias enumerates fields EXPLICITLY, so a field added to
		// SNMPConfig and not added here silently vanishes from the API surface.
		// A client-list name and its prefixes are not secrets (the community
		// string is), and an operator inspecting why a community is restricted
		// needs to see the list it names.
		ClientLists map[string][]SNMPClient `json:",omitempty"`
	}
	a := snmpAlias{
		Location:    s.Location,
		Contact:     s.Contact,
		Description: s.Description,
		TrapGroups:  s.TrapGroups,
		V3Users:     s.V3Users,
		ClientLists: s.ClientLists,
	}
	if len(s.Communities) > 0 {
		names := make([]string, 0, len(s.Communities))
		for name := range s.Communities {
			names = append(names, name)
		}
		sort.Strings(names)
		a.Communities = make([]*SNMPCommunity, 0, len(names))
		for _, name := range names {
			a.Communities = append(a.Communities, s.Communities[name])
		}
	}
	return a, nil
}

// SNMPCommunity defines an SNMP community string.
//
// Name is the SNMPv1/v2c community string, which IS the shared secret (it
// authorizes the request on the wire). It is also the key of the
// SNMPConfig.Communities map, so it stays a plain string (the map lookup in
// pkg/snmp/agent.go is by the on-wire community string). Redaction on the
// JSON/YAML surface is applied via the targeted MarshalJSON / MarshalYAML
// below; keeping Name a string leaves the map key and the compiler assignment
// unchanged.
//
// The cost of that choice is that Name is the ONE operator secret in the
// config tree not covered by the Secret newtype's String() redaction (#2053) —
// every other secret masks itself under %s/%v, this one does not. So each
// manual TEXT renderer that prints the map key must mask it explicitly, via
// the shared SNMPCommunityDisplayName helper below. Three surfaces do:
// pkg/cli `show snmp` / `show system services` (#4111), the pkg/api show-text
// handler (#5315) and the pkg/grpcapi ShowText snmp topic (#6532). The raw-AST
// `show configuration` render paths are masked separately by RedactedClone
// (ast_redact.go, #4051), which matches the community on the AST key path.
type SNMPCommunity struct {
	Name          string
	Authorization string // "read-only" or "read-write"
	// Clients is the Junos `clients` source-IP allowlist (#4289). When
	// non-empty, only a query whose source IP matches the allowlist (by
	// longest-prefix match, honoring the per-entry `restrict` deny modifier)
	// is served — a query from any other source is dropped. An empty Clients
	// is allow-all (the Junos default). Enforced by the SNMP agent via
	// AllowsSource (snmp_clients.go).
	Clients []SNMPClient

	// ClientListNames holds the `client-list-name` references this community
	// authored, in document order and de-duplicated (#9416).
	//
	// It is NOT the enforcement input -- a referenced list's prefixes are
	// RESOLVED into Clients at compile time, so AllowsSource, compileClientNets
	// and the API surface all keep working on one field. This exists for two
	// reasons that Clients cannot serve:
	//
	//  1. the reconcile HASH (daemon_snmp_reconcile.go). A community with an
	//     UNRESOLVABLE reference has an empty Clients and is quarantined to
	//     deny-all via clientNets, which the hash does not see -- so adding
	//     such a reference to a previously-unrestricted community would hash
	//     EQUAL, the reconcile would take the no-op path, and the running
	//     agent would keep serving every source. That is the #5105 class
	//     reached through a new door;
	//  2. `show configuration` / the API must render what the operator wrote,
	//     not only what it resolved to.
	ClientListNames []string

	// clientNets is Clients pre-parsed into an allocation-free match set
	// (#4711). The compiler populates it via compileClientNets after Clients
	// is finalized, before the config reaches the SNMP agent, so AllowsSource
	// matches without re-parsing every prefix on every incoming v2c packet.
	// Unexported: derived state, not part of the config surface (not marshaled,
	// not persisted); a config path that skips compilation leaves it nil and
	// AllowsSource parses on the fly. See snmp_clients.go.
	clientNets []compiledSNMPClient
}

// SNMPClient is one entry of an SNMP community `clients` source-IP allowlist:
// an address prefix and an optional Junos `restrict` (deny) modifier. See
// SNMPCommunity.AllowsSource (snmp_clients.go).
type SNMPClient struct {
	Prefix   string // CIDR (10.0.0.0/24) or bare address (192.168.1.5 == /32 or /128)
	Restrict bool   // true = deny this prefix (Junos `restrict`)
}

// MarshalJSON redacts the community string (the secret) on the JSON
// surface, e.g. GET /api/v1/config, while leaving Authorization and the
// (non-secret) clients allowlist in the clear. See the type doc for why
// Name stays a plain string (#2053).
func (c SNMPCommunity) MarshalJSON() ([]byte, error) {
	type alias struct {
		Name          Secret
		Authorization string
		Clients       []SNMPClient `json:",omitempty"`
		// #9416: a client-list NAME is not a secret (the community string is),
		// and hiding it would make an unresolvable reference invisible on the
		// API surface -- which is the one case where the community is
		// quarantined to deny-all and the operator needs to see why.
		ClientListNames []string `json:",omitempty"`
	}
	return json.Marshal(alias{Name: Secret(c.Name), Authorization: c.Authorization, Clients: c.Clients, ClientListNames: c.ClientListNames})
}

// MarshalYAML mirrors MarshalJSON for the gopkg.in/yaml.v3 marshaller
// (future-proofing; no config YAML marshaller exists today — #2053).
func (c SNMPCommunity) MarshalYAML() (any, error) {
	return struct {
		Name          Secret
		Authorization string
		Clients       []SNMPClient `yaml:",omitempty"`
		// #9416: kept in sync with MarshalJSON above, per this type's own rule.
		ClientListNames []string `yaml:",omitempty"`
	}{Name: Secret(c.Name), Authorization: c.Authorization, Clients: c.Clients, ClientListNames: c.ClientListNames}, nil
}

// SNMPCommunityDisplayName returns the token an operator-facing TEXT renderer
// must print in place of an SNMPv1/v2c community name. It is the single
// implementation of the community-masking rule, shared by every render surface
// that formats the Communities map key itself:
//
//   - pkg/cli `show snmp` + `show system services` (#4111) pass
//     redact=showConfigRedacted(), so a VIEW-only login class sees the
//     placeholder and super-user keeps cleartext (the #4057/#4106
//     console-operator allowance).
//   - pkg/api show-text (#5315) and pkg/grpcapi ShowText (#6532) pass
//     redact=true unconditionally: neither surface carries a login class to
//     gate on, so there is no privileged caller to exempt. The gRPC one is not
//     merely loopback — ShowText is on the cluster-fabric allowlist (#4122),
//     reachable from the peer chassis.
//
// The authorization mode is NOT a secret and is never masked by this helper —
// callers keep rendering it in the clear.
//
// Why a helper and not an inline `if` per site: the community is the one
// operator secret that the Secret newtype does not protect (see SNMPCommunity
// above), so every renderer must remember to mask it by hand. Three
// independent copies of that one-line rule is precisely how the gRPC surface
// silently stayed in the clear for two hardening passes (#6532). One
// implementation, one place to audit.
func SNMPCommunityDisplayName(name string, redact bool) string {
	if redact {
		return SecretDataPlaceholder
	}
	return name
}

// SNMPTrapGroup defines an SNMP trap destination group.
type SNMPTrapGroup struct {
	Name    string
	Targets []string // IP addresses
	// Version selects the SNMP protocol version used to emit this group's
	// traps: "v1" emits an SNMPv1 Trap-PDU, "v2" an SNMPv2c trap (the
	// default), and "all" emits both a v1 and a v2c trap. An empty string
	// (unspecified) defaults to v2c. The schema enum is v1|v2|all (Junos
	// semantics); the emitter honors it in pkg/snmp/traps.go so a
	// `version v1` group is not silently sent as v2c (#3948).
	Version string
	// Categories scopes which trap categories this group receives (Junos
	// `snmp trap-group <g> categories <cat>`). A group lists the categories it
	// WANTS; a notification is dispatched to the group only if the trap's
	// category is in this list. An empty/nil slice means the group receives
	// EVERY category — the Junos default for a trap-group with no `categories`
	// stanza. Enforced in pkg/snmp/traps.go via groupWantsCategory (#5522);
	// without this the configured category filter was parsed but discarded, so
	// a group scoped to exclude a category (e.g. `link`) still received every
	// linkUp/linkDown notification (a silent filter bypass).
	Categories []string
}

// SNMPv3User defines an SNMPv3 USM user with authentication and privacy.
type SNMPv3User struct {
	Name         string
	AuthProtocol string // "md5", "sha", "sha256"
	AuthPassword Secret // redacted on JSON/YAML marshal (#2053)
	PrivProtocol string // "des", "aes128"
	PrivPassword Secret // redacted on JSON/YAML marshal (#2053)
}

// ServicesConfig holds service configuration (flow-monitoring, RPM, etc.).
type ServicesConfig struct {
	FlowMonitoring            *FlowMonitoringConfig
	RPM                       *RPMConfig
	IPMonitoring              *IPMonitoringConfig // services ip-monitoring (#1827 PR-1b)
	ApplicationIdentification bool                // DPI-based application detection
}

// IPMonitoringConfig holds `services ip-monitoring` policies (#1827
// PR-1b): probe-driven preferred-route injection, Junos parity.
type IPMonitoringConfig struct {
	Policies map[string]*IPMonitoringPolicy
}

// IPMonitoringPolicy matches one RPM probe and injects its preferred
// routes (at route preference 1, Static/1 on SRX) while ANY test of the
// matched probe is FAILED; on recovery they are withdrawn.
type IPMonitoringPolicy struct {
	Name            string
	MatchRPMProbe   string
	PreferredRoutes []*PreferredRoute
	// HoldDownSecs damps recovery flaps (extension beyond Junos;
	// 0 = Junos parity: withdraw immediately on recovery).
	HoldDownSecs int
}

// PreferredRoute is one injected route of an ip-monitoring policy.
type PreferredRoute struct {
	RoutingInstance string // "" = master; may target instance-type forwarding (FBF, #1827 PR-2)
	Destination     string // CIDR
	// NextHop is the literal next-hop IP; "" when the configured
	// next-hop is interface-typed (#1844). Mutually exclusive with
	// NextHopInterface.
	NextHop string
	// NextHopInterface is the resolved Linux DHCP lease key
	// (DHCPLeaseIfName: LinuxIfName + optional ".<vlan-id>") when the
	// configured next-hop names a DHCP-enabled interface unit
	// (`next-hop ge-0/0/3.0`, #1844). The route then tracks that
	// unit's DHCP-learned gateway at actuation time. Compile-time
	// derived; config identity only, never lease state. Mutually
	// exclusive with NextHop.
	NextHopInterface string
	// PreferredMetric is a metric AMONG injected routes for the same
	// prefix (the tie-break when two policies in FAIL both inject the
	// same destination — lowest wins, then lexicographic policy name).
	// It is NOT the route preference: the injected route always has
	// preference 1.
	PreferredMetric int
}

// RouteOverlayEntry is one winner-resolved effective route of the
// ip-monitoring overlay (#1827 PR-1b §4.3): the single decision point
// consumed by BOTH the FRR managed-section render (distance-1 static)
// and the userspace dataplane snapshot builder (whole-entry replacement
// of the (table, family, prefix) route set). Runtime state, never
// config: it does not participate in config sync.
type RouteOverlayEntry struct {
	RoutingInstance string // "" = master table
	Destination     string // CIDR
	NextHop         string
	// NextHopInterface records the DHCP lease key the NextHop was
	// resolved from when the owning PreferredRoute is interface-typed
	// (#1844); "" for literal next-hops. FRR/snapshot consumers read
	// NextHop only — this field exists so FilterOverlayForConfig can
	// match an interface-typed entry against the incoming config (the
	// resolved gateway is runtime state and never equals the config
	// spec).
	NextHopInterface string
	Metric           int    // winning preferred-metric (informational downstream)
	Policy           string // owning policy name (logging/show)
}

// RPMConfig holds RPM (Real-time Performance Monitoring) configuration.
type RPMConfig struct {
	Probes map[string]*RPMProbe
}

// RPMProbe defines a single RPM probe for health monitoring.
type RPMProbe struct {
	Name  string
	Tests map[string]*RPMTest
}

const (
	DefaultRPMProbeType            = "icmp-ping"
	DefaultRPMProbeIntervalSeconds = 5
	DefaultRPMProbeCount           = 1
	DefaultRPMTestIntervalSeconds  = 60
	DefaultRPMSuccessiveLosses     = 3
	DefaultRPMTCPDestinationPort   = 80
)

// Probe pin plumbing constants (#1827 PR-1a). Each RPM test with a
// `next-hop` pin gets a deterministic per-test fwmark + kernel routing
// table + ip-rule priority, assigned in sorted probe/test order. The
// reserved probe table range 7000-7049 is clear of the Linux reserved
// tables (0/253/254/255), the daemon's management VRF table (999), and
// the routing-instance auto-assignment that grows upward from 100
// (compileRoutingInstances). The ip-rule priority band 50-99 sits below
// the next-table (100-199), PBR (31000+), and rib-group (33000+) clear
// windows in pkg/routing/rules.go. pkg/routing's probe-pin reconciler
// and pkg/rpm's SO_MARK assignment both consume these constants so the
// rule/table/mark assignment cannot drift between the two sides.
const (
	// ProbeTableBase is the first kernel routing table reserved for
	// RPM probe next-hop pins.
	ProbeTableBase = 7000
	// ProbeTableCount caps the number of next-hop-pinned RPM tests
	// (commit error past the cap).
	ProbeTableCount = 50
	// ProbeFwmarkBase is the first fwmark value used for probe pins
	// (mark = ProbeFwmarkBase + index).
	ProbeFwmarkBase = 0x1000
	// ProbeRulePriorityBase is the first ip-rule priority of the
	// probe-pin band (50-99).
	ProbeRulePriorityBase = 50
	// PBRRulePriorityBase is the first ip-rule priority of the
	// policy-based-routing / filter-based-forwarding (FBF) band
	// (31000-31999): firewall-filter `then routing-instance` actions
	// installed by pkg/routing's pbrManager. These rules carry match
	// SELECTORS (source/dest address, DSCP, protocol, source/dest port)
	// in addition to a Dst, so — unlike the pure per-prefix next-table /
	// rib-group leak bands — they MUST NOT be mirrored into the userspace
	// next-table FIB snapshot as a bare dst-only leak (that drops the
	// selectors and re-opens the #3730 over-steer; see #4479 and
	// pkg/dataplane/userspace/routes.go buildRouteSnapshots). Both
	// pkg/routing (install side) and pkg/dataplane/userspace (snapshot
	// ingest side) consume these, so they live here as the single source
	// of truth alongside ProbeRulePriorityBase.
	PBRRulePriorityBase = 31000
	// PBRRuleWindow is the size of the PBR band; the band is
	// [PBRRulePriorityBase, PBRRulePriorityBase+PBRRuleWindow) = 31000-31999.
	// It also bounds the number of PBR ip rules the applier installs
	// (pkg/routing maxPBRRules) and the priority window clear() scans.
	PBRRuleWindow = 1000
	// NextTableRulePriorityBase is the first ip-rule priority of the
	// next-table inter-VRF route-leak band (100-199): global
	// `routing-options static route <p> next-table <instance>` leaks installed
	// by pkg/routing's nextTableManager. Unlike the PBR band these rules carry
	// a pure per-prefix Dst with NO selectors, so the userspace FIB snapshot
	// (pkg/dataplane/userspace/routes.go) DOES mirror them as bare NextTable
	// leaks. Both pkg/routing (install side) and pkg/dataplane/userspace
	// (config-static mirror side) consume the band, so it lives here as the
	// single source of truth alongside PBRRulePriorityBase.
	NextTableRulePriorityBase = 100
	// NextTableRuleWindow is the size of the next-table band; the band is
	// [NextTableRulePriorityBase, NextTableRulePriorityBase+NextTableRuleWindow)
	// = 100-199. It bounds THREE things that MUST agree or the control plane
	// and dataplane diverge past the cap (#6467): the number of next-table ip
	// rules the applier installs and the priority window clear() scans
	// (pkg/routing maxNextTableRules), the commit-time over-subscription gate
	// (pkg/config maxNextTableRules, #5854), and the number of config-static
	// next-table leaks the userspace FIB mirror publishes
	// (pkg/dataplane/userspace/routes.go). Capping all three at this single
	// value keeps the kernel ip-rule table and the userspace dataplane FIB from
	// disagreeing on which leaks survive truncation.
	NextTableRuleWindow = 100
)

// RPMTest defines a test within an RPM probe.
type RPMTest struct {
	Name                 string
	ProbeType            string // "http-get", "icmp-ping", "tcp-ping"
	Target               string // target IP or hostname
	SourceAddress        string
	RoutingInstance      string
	DestinationInterface string // egress interface pin (SO_BINDTODEVICE), Junos unit name
	NextHop              string // next-hop IP pin via reserved fwmark probe table (#1827)
	ProbeInterval        int    // seconds (0 = default 5)
	ProbeCount           int    // number of probes per test (0 = default 1)
	TestInterval         int    // seconds (0 = default 60)
	ThresholdSuccessive  int    // successive failures before probe-fail (0 = default 3)
	ProbeLimit           int    // max consecutive failed probes before stopping the current test cycle (0 = unlimited)
	DestPort             int    // for tcp-ping
}

// IsScoped reports whether the test's probe DATA socket is bound to a
// specific VRF / egress device / next-hop path — i.e. probeOpts would set
// SO_BINDTODEVICE (from destination-interface, or the routing-instance VRF
// device) or SO_MARK (from a next-hop pin). A scoped test measures a
// SPECIFIC path, so a hostname target must resolve in that path's context.
// Since #2614 the runtime resolver does exactly that — it binds the DNS
// socket to the same SO_BINDTODEVICE / SO_MARK as the probe socket
// (rpm.resolveProbeTarget / probeDialer.Resolver) — so a scoped hostname
// resolves in-context (the #2493 commit gate that previously refused this
// combination was removed). This predicate is retained as the shared
// definition of "scoped".
func (t *RPMTest) IsScoped() bool {
	if t == nil {
		return false
	}
	return t.DestinationInterface != "" || t.RoutingInstance != "" || t.NextHop != ""
}

func (t *RPMTest) EffectiveProbeType() string {
	if t == nil || t.ProbeType == "" {
		return DefaultRPMProbeType
	}
	return t.ProbeType
}

func (t *RPMTest) EffectiveProbeInterval() int {
	if t == nil || t.ProbeInterval <= 0 {
		return DefaultRPMProbeIntervalSeconds
	}
	return t.ProbeInterval
}

func (t *RPMTest) EffectiveProbeCount() int {
	if t == nil || t.ProbeCount <= 0 {
		return DefaultRPMProbeCount
	}
	return t.ProbeCount
}

func (t *RPMTest) EffectiveTestInterval() int {
	if t == nil || t.TestInterval <= 0 {
		return DefaultRPMTestIntervalSeconds
	}
	return t.TestInterval
}

func (t *RPMTest) EffectiveSuccessiveLossThreshold() int {
	if t == nil || t.ThresholdSuccessive <= 0 {
		return DefaultRPMSuccessiveLosses
	}
	return t.ThresholdSuccessive
}

func (t *RPMTest) EffectiveDestinationPort() int {
	if t == nil || t.DestPort <= 0 {
		return DefaultRPMTCPDestinationPort
	}
	return t.DestPort
}

// FlowMonitoringConfig holds flow monitoring configuration.
type FlowMonitoringConfig struct {
	Version9     *NetFlowV9Config
	VersionIPFIX *NetFlowIPFIXConfig
}

// NetFlowIPFIXConfig holds IPFIX (NetFlow v10) template definitions.
type NetFlowIPFIXConfig struct {
	Templates map[string]*NetFlowIPFIXTemplate
}

// NetFlowIPFIXTemplate defines an IPFIX export template.
type NetFlowIPFIXTemplate struct {
	Name                string
	FlowActiveTimeout   int      // seconds
	FlowInactiveTimeout int      // seconds
	TemplateRefreshRate int      // seconds
	ExportExtensions    []string // e.g. "app-id", "flow-dir"
}

// NetFlowV9Config holds NetFlow v9 template definitions.
type NetFlowV9Config struct {
	Templates map[string]*NetFlowV9Template
}

// NetFlowV9Template defines a NetFlow v9 export template.
type NetFlowV9Template struct {
	Name                string
	FlowActiveTimeout   int      // seconds (0 = default 60)
	FlowInactiveTimeout int      // seconds (0 = default 15)
	TemplateRefreshRate int      // seconds (0 = default 60)
	ExportExtensions    []string // e.g. "app-id", "flow-dir"
}

// ForwardingOptionsConfig holds forwarding/sampling configuration.
type ForwardingOptionsConfig struct {
	Sampling        *SamplingConfig
	DHCPRelay       *DHCPRelayConfig
	FamilyInet6Mode string // "flow-based" or "packet-based" (default "flow-based")
	PortMirroring   *PortMirroringConfig
	// AllowDataplaneSleep mirrors `forwarding-options allow-dataplane-sleep`
	// (#2008 H13 Stage 1). Syntax accepted + typed; the idle-yield runtime
	// (workers currently busy-poll) is Stage 2 / lab-gated, so this is an
	// accepted-but-unenforced flag that emits a commit warning.
	AllowDataplaneSleep bool
}

// PortMirroringConfig holds port mirroring (SPAN) configuration.
type PortMirroringConfig struct {
	Instances map[string]*PortMirrorInstance
}

// PortMirrorInstance defines a named port mirroring instance.
type PortMirrorInstance struct {
	Name      string
	InputRate int      // 1-in-N sampling rate (0 = mirror all)
	Input     []string // ingress interfaces to mirror
	Output    string   // egress mirror destination interface
}

// DHCPRelayConfig holds DHCP relay agent configuration.
type DHCPRelayConfig struct {
	ServerGroups map[string]*DHCPRelayServerGroup
	Groups       map[string]*DHCPRelayGroup
}

// DHCPRelayServerGroup defines a group of DHCP servers.
type DHCPRelayServerGroup struct {
	Name    string
	Servers []string // server IPs
}

// DHCPRelayGroup defines a DHCP relay group bound to interfaces.
type DHCPRelayGroup struct {
	Name              string
	Interfaces        []string
	ActiveServerGroup string // reference to server group name
	// AlwaysBroadcast forces every server reply (OFFER/ACK) to be
	// broadcast to 255.255.255.255:68 even when the client cleared the
	// broadcast flag, mirroring Junos `dhcp-relay ... overrides
	// always-broadcast`. When false (the default) the relay honors the
	// client's broadcast flag and raw-L2-unicasts flag-clear replies to
	// chaddr+yiaddr (#2076).
	AlwaysBroadcast bool
	// #4309 (fable-review-167 I-4): additional relay overrides.
	//
	// MaximumHopCount is the RFC 1542 §4.1.1 loop-protection hop limit —
	// the relay drops a client request whose hops field has reached this
	// value. 0 = unset = the pre-#4309 hardcoded default (16). ENFORCED.
	MaximumHopCount int
	// ForwardOnly / RelayAgentOption are ACCEPTED-ONLY (a commit-time
	// advisory notes each matches the relay's existing default behavior):
	// the xpf relay already forwards statelessly (no persistent per-client
	// binding), and it always inserts Option 82 (circuit-id).
	ForwardOnly      bool
	RelayAgentOption bool
	// TrustOption82 marks this group's interfaces as TRUSTED relay uplinks
	// (Junos `overrides trust-option-82`) — the RFC 3046 §2.1 anti-spoofing
	// trust knob (#5414). ENFORCED. When false (the default) an interface is
	// an UNTRUSTED client-facing segment: a nonzero inbound giaddr (and any
	// Option 82) is treated as client-forged and NOT trusted — the relay
	// overwrites giaddr with its own address and re-stamps Option 82 per RFC
	// 951/1542 first-hop rules. When true the interface faces a downstream
	// relay, so an inbound nonzero giaddr + Option 82 is preserved untouched
	// (the RFC 1542 §4.1 intermediate-relay behavior, #5071).
	TrustOption82 bool
	// MaximumPacketRate is the per-interface DHCP relay ingress rate limit in
	// packets per second (#5670, Junos `overrides maximum-packet-rate`).
	// ENFORCED. The relay admits at most this many client-facing datagrams per
	// second per interface (a token bucket with a short burst allowance),
	// dropping the excess before the DHCP parse + Option-82 fan-out so an
	// untrusted client segment cannot CPU-exhaust the relay or amplify a flood
	// into the upstream servers (1 client packet → N server packets). 0 = unset
	// = the default (defaultMaxPacketRate, 100 pps). Set a high value to
	// effectively disable the bound. Compiled into `relaySpec.maxPacketRate`
	// (a change restarts the per-interface relay).
	MaximumPacketRate int
}

// SamplingConfig holds sampling instance definitions.
type SamplingConfig struct {
	Instances map[string]*SamplingInstance
}

// SamplingInstance defines a traffic sampling instance.
type SamplingInstance struct {
	Name        string
	InputRate   int // 1-in-N sampling rate (0 = sample all)
	FamilyInet  *SamplingFamily
	FamilyInet6 *SamplingFamily
}

// SamplingFamily holds per-AF sampling output configuration.
//
// SourceAddress is the OUTPUT-LEVEL default source-address (the
// `source-address` sibling of `flow-server` under `output { ... }`) —
// the per-output default every flow-server inherits when it declares no
// nested source of its own. It is NOT the resolved per-collector bind:
// a flow-server-nested `source-address` (FlowServer.SourceAddress) is a
// per-collector override that wins over this default, and the effective
// bind is computed PER COLLECTOR in the flowexport resolver
// (collectInstanceVersionCollectors), not collapsed to one family-wide
// value. Before #3745 the nested source was collapsed into this single
// field (last-writer-wins across servers of the same family), so two
// collectors with distinct nested sources both bound the last one.
type SamplingFamily struct {
	FlowServers              []*FlowServer
	SourceAddress            string
	InlineJflow              bool
	InlineJflowSourceAddress string // inline-jflow { source-address; }
}

// FlowServer defines a flow export collector destination.
//
// Version selects the export protocol for THIS collector (Junos binds
// each flow-server to exactly one export version). It is set by the
// compiler from whichever per-server selector nests under the
// flow-server: "version9" (the `version9 { template }` /
// `version9-template` selector) or "version-ipfix" (the
// `version-ipfix { template }` selector). It is "" when the operator
// configured no per-server selector — in that case the live exporter
// resolves a deterministic version per the documented precedence (see
// pkg/flowexport BuildExportConfig / BuildIPFIXExportConfig and #2136).
//
// Before #2136 the live Go exporter ignored the per-server selector
// entirely and flattened all flow-servers into BOTH the v9 and the
// IPFIX collector set, so a flow-server reachable under both global
// version stanzas received every flow twice (one v9 + one IPFIX
// datagram to the same socket).
type FlowServer struct {
	Address              string
	Port                 int
	Version              string // "version9" | "version-ipfix" | "" (unbound)
	Version9Template     string
	VersionIPFIXTemplate string
	// SourceAddress is the per-collector local bind address configured as
	// `flow-server <addr> { source-address <src>; }` (#3745). It is the
	// per-collector OVERRIDE of the output-level default
	// (SamplingFamily.SourceAddress): the flowexport resolver binds THIS
	// collector's socket to this source when set, else falls back to the
	// family default. Empty ("") means inherit the family/output default.
	// Before #3745 this value was collapsed into the one family-wide
	// SamplingFamily.SourceAddress (last-writer-wins), so a second
	// collector could not bind its own configured source.
	SourceAddress string
}

// Flow-server per-collector export version selectors (FlowServer.Version).
const (
	FlowServerVersion9     = "version9"
	FlowServerVersionIPFIX = "version-ipfix"
)

// FirewallConfig holds firewall filter definitions.
type FirewallConfig struct {
	FiltersInet        map[string]*FirewallFilter          // family inet filters
	FiltersInet6       map[string]*FirewallFilter          // family inet6 filters
	Policers           map[string]*PolicerConfig           // named policer definitions
	ThreeColorPolicers map[string]*ThreeColorPolicerConfig // named three-color policers
}

// PolicerConfig defines a single-rate two-color policer (token bucket).
type PolicerConfig struct {
	Name                    string
	BandwidthLimit          uint64 // bytes per second (converted from Junos bits/sec)
	BurstSizeLimit          uint64 // burst bucket size in bytes
	ThenAction              string // "discard" or "loss-priority high/medium-high/medium-low/low"
	LogicalInterfacePolicer bool   // shared across protocol families on the interface
	// ThenActions records EVERY action keyword authored in the policer's
	// `then` block, in source order (#8445).
	//
	// ThenAction above is single-valued and last-write-wins, so it is the
	// SURVIVOR, not the intent. A gate that reads it cannot see that two
	// actions were written: `then { discard; loss-priority high; }` compiles to
	// exactly what was authored — for one of the two statements — which is why
	// a cell asserting "ThenAction is what was authored" passes today.
	// validateFirewallPolicerThenConflictStrict reads this instead.
	ThenActions []string
}

// ThreeColorPolicerConfig defines a three-color policer (RFC 2697/2698).
type ThreeColorPolicerConfig struct {
	Name       string
	TwoRate    bool // true=two-rate (RFC 2698), false=single-rate (RFC 2697)
	ColorBlind bool // color-blind mode (Junos default when no color statement; #4535)
	// Explicit mode/color markers are retained for commit-time ambiguity
	// checks. The dataplane snapshot still carries only the canonical mode.
	SingleRateConfigured bool
	TwoRateConfigured    bool
	ColorAwareConfigured bool
	ColorBlindConfigured bool
	CIR                  uint64 // committed information rate (bytes/sec)
	CBS                  uint64 // committed burst size (bytes)
	PIR                  uint64 // peak information rate (bytes/sec, two-rate only)
	PBS                  uint64 // peak/excess burst size (bytes)
	ThenAction           string // action on exceed/violate: "discard" or "loss-priority"
	// ThenActions: the authored set, for the same reason as PolicerConfig's
	// (#8445). The three-color `then` loop is the identical last-wins switch.
	ThenActions []string
}

// FirewallFilter defines a named firewall filter with ordered terms.
type FirewallFilter struct {
	Name  string
	Terms []*FirewallFilterTerm
	// InterfaceSpecific records the Junos `interface-specific` flag
	// (fable-167 F-3a, #4316). In Junos it instantiates a distinct
	// counter/policer instance per interface the filter is attached to; xpf
	// keeps a single shared counter, so the flag is accepted but inert. It
	// is recorded here only to drive the commit advisory
	// (validateFirewallInterfaceSpecificWarnings); the dataplane never reads
	// it.
	InterfaceSpecific bool
}

// FirewallFilterTerm is a single match/action term within a filter.
type FirewallFilterTerm struct {
	Name              string
	SourceAddresses   []string        // CIDRs
	DestAddresses     []string        // CIDRs
	SourcePrefixLists []PrefixListRef // source-prefix-list references
	DestPrefixLists   []PrefixListRef // destination-prefix-list references
	// DSCPs / Protocols / ICMPTypes / ICMPCodes are SCHEMA-DECLARED multi-value
	// (schema_cos.go marks them `multi: true`) and Junos accepts the match
	// criterion repeated within one `from` block. They are stored as SLICES
	// (#2545) so repeated children accumulate into a match-ANY set instead of
	// the prior scalar last-write-wins (`from protocol tcp; from protocol udp`
	// silently dropped tcp). An EMPTY slice means the criterion is unconstrained
	// (matches any), exactly like the prior empty-string / -1 sentinels. The
	// dataplane (filters.go) emits every value into the corresponding wire
	// vector and the Rust matcher evaluates set membership (match-ANY within a
	// field, AND across fields).
	DSCPs            []string // DSCP/traffic-class names (ef, af43, ...) or numbers
	Protocols        []string // tcp, udp, icmp, icmpv6, esp, ...
	DestinationPorts []string // port numbers or names
	SourcePorts      []string // source port numbers or ranges
	// SourcePortsExcept / DestinationPortsExcept are the NEGATED port match
	// sets (#2622, Junos `from source-port-except` / `destination-port-except`):
	// match any port EXCEPT the listed ones. They are mutually exclusive with the
	// positive SourcePorts / DestinationPorts in Junos; if both are somehow set,
	// the dataplane evaluates whichever direction carries entries (the compiler
	// keeps them as independent slices, the wire carries an `except` flag per
	// direction). An empty slice means the except criterion is unconstrained
	// (matches any), exactly like the positive port slices.
	SourcePortsExcept []string // source ports to EXCLUDE (match all others)
	DestPortsExcept   []string // destination ports to EXCLUDE (match all others)
	ICMPTypes         []int    // ICMP/ICMPv6 type bytes (0..255); empty = not set
	ICMPCodes         []int    // ICMP/ICMPv6 code bytes (0..255); empty = not set
	// UnknownICMPTypes / UnknownICMPCodes / UnknownPorts record symbolic match
	// values that could not be resolved to a number at compile time (#3205,
	// agy-070 #07/#08). Previously such a value was silently dropped: an
	// unresolved icmp-type left the type set empty (matches ALL ICMP — a policy
	// bypass) and an unresolved named port left the port set constrained-but-
	// empty (the `*-port-except` term matched ALL ports — fail open). These are
	// the deferred-reject channel (mirroring UnknownActions): the compile path
	// records the offending token and validateFilterMatchValuesStrict
	// hard-rejects the commit; the tolerant load / peer-sync path downgrades to
	// a warning, and the kept-verbatim token makes the dataplane fail CLOSED.
	UnknownICMPTypes []string
	UnknownICMPCodes []string
	UnknownPorts     []string
	// UnknownAddresses records literal `from source-address` /
	// `destination-address` tokens that are not parseable IP/CIDR literals at
	// compile time (#6463) — classifyFilterAddrFamily rejects them. The token
	// is kept VERBATIM in SourceAddresses / DestAddresses (the pre-#6463
	// behavior) so the term still compiles for the strict-gate diagnostic;
	// validateFilterAddressLiteralsStrict (#3433) hard-rejects the commit, and
	// on the tolerant load / peer-sync path the snapshot builder sets the
	// AddressUnrepresentable wire marker so the Rust filter compiler fails the
	// whole snapshot CLOSED. Without the marker the Rust parse_address dropped
	// the malformed token PER-TOKEN, so a PARTIALLY-malformed list silently
	// narrowed a discard/reject term to only the surviving prefixes (fail-OPEN
	// via fall-through to the implicit accept). Mirrors UnknownPorts.
	UnknownAddresses []string
	TCPFlags         []string // TCP flags: "syn", "ack", "fin", "rst", "psh", "urg"
	IsFragment       bool     // match IP fragments
	Action           string   // "accept", "reject", "discard", ""
	// TerminalActions records EVERY terminating action keyword
	// (accept/reject/discard) compileFilterThen encountered across all of the
	// term's `then` blocks, in order and including duplicates. Action itself is
	// single-valued and last-write-wins, so a term with `then accept` AND `then
	// reject` would silently resolve to whichever came last — the operator's
	// intent was ambiguous and the compiled behavior did not necessarily match
	// what they wrote (#4375, avo-review-007 H3). This slice is the
	// mutual-exclusion channel: validateFilterTerminalConflictStrict hard-rejects
	// any term whose distinct-terminal count exceeds one; the tolerant load /
	// peer-sync path downgrades to a warning (#1960 no-brick) and the last-wins
	// Action still drives the dataplane. Junos treats accept/reject/discard as
	// mutually exclusive (a term has exactly one terminating action); the
	// non-terminating modifiers (count/log/forwarding-class/loss-priority/dscp/
	// traffic-class/policer/routing-instance) coexist with a terminal and are NOT
	// recorded here.
	TerminalActions []string
	// UnknownActions records `then` tokens that are neither a recognized
	// terminating action nor a recognized modifier (#2399 finding 032-16).
	// An unknown or misspelled action would otherwise be silently dropped
	// during compile and default to ACCEPT in BOTH the dataplane compiler and
	// the Rust filter (a fail-open permit). validateFilterActionsStrict
	// hard-rejects any term carrying an entry here at commit; the tolerant
	// load path downgrades it to a warning (#1960 no-brick). Populated by
	// compileFilterThen.
	UnknownActions []string
	// RejectMessageType is the optional message-type after `then reject`
	// (e.g. tcp-reset, administratively-prohibited, port-unreachable). Junos
	// accepts `then reject <message-type>` and the term acts as a plain reject;
	// this captures the type for config fidelity. The dataplane does not act on
	// it today (FilterAction::Reject only). An unknown token after `reject` is
	// a typo and is NOT stored here — it is flagged via UnknownActions.
	RejectMessageType string
	// NextTerm records `then next term` / `then next-term` — an explicit
	// fall-through to the next term (a no-op terminating-wise; Action stays "").
	// It is a recognized, valid construct, not an unknown action.
	NextTerm        bool
	RoutingInstance string // routing-instance name (policy-based routing)
	Log             bool
	// Syslog records `then syslog` as DISTINCT from `then log` (#6853).
	//
	// In Junos the two name different sinks: `then log` writes the firewall
	// filter log buffer (`show firewall log`), `then syslog` sends to the
	// system log. Both spellings previously compiled to `Log` alone, so the
	// two were indistinguishable in the model and could never be routed
	// apart.
	//
	// `then syslog` sets BOTH this and Log, which keeps today's behaviour
	// bit-identical: Log is what makes the dataplane emit a filter-log event
	// at all, and clearing it would stop `then syslog` emitting anything.
	// Recording the distinction is the whole change; #6859 owns the routing
	// decision that consumes it (specifically whether `then log` should stop
	// reaching syslog, which is a behaviour change with a migration cost and
	// is deliberately NOT made here).
	Syslog          bool
	Count           string           // counter name
	ForwardingClass string           // forwarding-class name
	LossPriority    string           // loss-priority (low, medium-low, medium-high, high)
	DSCPRewrite     string           // then dscp <value> — rewrite DSCP/traffic-class
	Policer         string           // then policer <name> — reference to policer definition
	FlexMatch       *FlexMatchConfig // flexible-match-range configuration
	// UnknownFlexMatch records `flexible-match-range` numeric tokens that could
	// not be parsed (byte-offset / bit-length / match-value / match-mask) OR
	// that fell outside the representable range (#3203, agy-070 #02/#03/#04).
	// Previously compileFilterFrom IGNORED the strconv error and left the field
	// at its zero default — a malformed or >32-bit match-value silently became
	// 0x0 and the term then matched the WRONG (zero) pattern with a clean
	// commit. Mirroring UnknownActions/UnknownICMPTypes, the compile path
	// records the offending token and validateFilterFlexMatchStrict hard-rejects
	// the commit; the tolerant load / peer-sync path downgrades to a warning
	// (#1960 no-brick). Populated by compileFilterFrom.
	UnknownFlexMatch []string
	// FlexMatchRangeNames records EVERY named `flexible-match-range` range seen
	// for this term, aggregated across ALL repeated flexible-match-range blocks
	// and BOTH AST shapes (hierarchical + flat-set), including duplicate names
	// and `from` group-expanded copies (#5823). The wire matcher supports at
	// most ONE range per term; the pre-#5823 compiler silently kept only the
	// FIRST and dropped the rest — an accept term then over-permitted and a
	// discard/reject term over-dropped the traffic the missing ranges covered.
	// len > 1 is a CARDINALITY violation: validateFilterFlexMatchStrict
	// hard-rejects it at commit (naming every range), and the tolerant load /
	// peer-sync path fails CLOSED — the userspace snapshot builder poisons the
	// term to match NOTHING (an unrepresentable flex-match) rather than silently
	// enforcing only the first range. A single range (len == 1) compiles exactly
	// as before via FlexMatch. Populated by compileFilterFrom.
	FlexMatchRangeNames []string
	// UnknownFrom records `from` match leaves the dataplane does NOT enforce
	// (#3307). The schema gate is opt-in (schema_walk.go), so an unknown `from`
	// leaf (e.g. ttl / source-mac-address / ip-options / fragment-offset /
	// hop-limit) resolves to a nil schema child and passes commit; the
	// compileFilterFrom switch had no default arm, so the leaf was silently
	// dropped and the term enforced a BROADER match than authored — an `accept`
	// term over-permits, a `discard`/`reject` term over-drops, with no commit or
	// apply error. Mirroring UnknownActions/UnknownFlexMatch, compileFilterFrom's
	// default arm records the offending leaf name here and
	// validateFilterFromMatchStrict hard-rejects the commit; the tolerant load /
	// peer-sync path downgrades to a warning (#1960 no-brick). The enforced set
	// is exactly the compileFilterFrom switch cases (every one maps to a wire
	// field the snapshot builder emits and the Rust matcher evaluates).
	UnknownFrom []string

	// CrossFamilyMatchSpellings records `from` match leaves written with the
	// OTHER address family's spelling of a field that both families carry:
	//
	//	dscp <-> traffic-class     the same six bits (IPv4 DSCP / IPv6 Traffic Class)
	//	protocol <-> next-header   the same L4 protocol selector
	//
	// Junos spells each per family; xpf compiles either into the same typed
	// field rather than refusing a configuration that commits today.
	//
	// It is recorded because accepting it silently is the half of #8773/#8781 a
	// spelling-alignment fix would otherwise leave in place: the BRACED spelling
	// accepted these while the PACKED spelling dropped them without a word, and
	// making the two agree on `accept` without saying so would trade one silent
	// behaviour for another. Read by validateFilterCrossFamilyDSCPWarnings.
	//
	// #8781 widened this from DSCP-only. The name lost its `DSCP` because a
	// second field joined it; a DSCP-specific name on a list holding protocol
	// spellings is the kind of stale label that later gets reasoned from.
	CrossFamilyMatchSpellings []string
}

// FlexMatchConfig defines a flexible byte-offset match condition.
type FlexMatchConfig struct {
	MatchStart string // "layer-3" (only supported start point)
	ByteOffset uint8  // byte offset from match start
	BitLength  uint8  // match length in bits (8, 16, 32)
	Value      uint32 // expected value (after mask)
	Mask       uint32 // mask to apply before comparison
}

// PrefixListRef references a named prefix-list with optional "except" modifier.
type PrefixListRef struct {
	Name   string
	Except bool
}

// DHCPServerConfig holds DHCP server configuration.
type DHCPServerConfig struct {
	DHCPLocalServer   *DHCPLocalServerConfig
	DHCPv6LocalServer *DHCPLocalServerConfig
	// DynamicDNS is the opt-in DHCP DDNS policy (#1387 increment 1). It is the
	// IPv4-family (dhcp-local-server) policy. nil == disabled == today's
	// behaviour byte-for-byte; the dataplane (Kea render, daemon wiring)
	// ignores a nil block entirely.
	//
	// #2691 P1b / #2663: this is now the v4 policy ONLY. The v6 policy lives in
	// DynamicDNSv6 and is INDEPENDENT (separate domain / server / TSIG / TTL /
	// conflict-policy / source-binding). The two families are no longer
	// field-merged into one struct — a v4-family block and a v6-family block
	// keep their own settings. Backward compatibility: a config that sets the
	// stanza under only ONE family compiles to that family's field with the
	// other nil (so the single-family case is byte-for-byte unchanged), and a
	// config that set BOTH under the pre-P1b field-merge model now keeps them
	// distinct (the documented behaviour change in §5.8).
	DynamicDNS *DHCPDynamicDNSConfig
	// DynamicDNSv6 is the opt-in IPv6-family (dhcpv6-local-server) DDNS policy
	// (#2691 P1b / #2663), independent of the v4 DynamicDNS policy above. nil
	// == no v6 DDNS policy. When a config sets the stanza under only
	// dhcpv6-local-server, DynamicDNS is nil and this carries the v6 policy.
	DynamicDNSv6 *DHCPDynamicDNSConfig
}

// DHCPDynamicDNSConfig is the opt-in dynamic-DNS policy for the DHCP
// server (#1387). When DHCP clients take a lease, the firewall can
// publish forward (A/AAAA) and reverse (PTR) records into an external
// authoritative DNS server, and remove them again when the lease ends
// (expire / release / decline / reclaim / reassign).
//
// This is the FIRST increment per docs/research/1387-dhcp-ddns/plan.md
// (recommended Path C — pluggable backend, RFC 2136 first). Increment 1
// ships the config model, the state-aware lease parser, the DNSUpdater
// interface + reconciler core (fake-updater unit-tested), and the
// never-delete-non-owned state store. The LIVE rfc2136 backend, the HA
// ownership coupling, and the Kea D2 backend are deferred to later
// lab-gated / test-failover-gated increments. An absent block (nil) is
// the default and changes nothing.
type DHCPDynamicDNSConfig struct {
	// Enabled turns the reconciler on. A block that parses but never
	// sets enable is still disabled — the operator opts in explicitly.
	Enabled bool
	// Domain is the default DNS suffix appended to a client name that is
	// not already a FQDN (e.g. "corp.example.com").
	Domain string
	// TTLSeconds is the TTL applied to published records (default 300
	// when zero, applied at render time, not here).
	TTLSeconds int
	// HostnameSource selects how the published label is derived from the
	// lease: client-hostname (DHCP host-name option, default), fqdn (the
	// client-supplied FQDN option), or mac-fallback (synthesize
	// dhcp-<sanitized-id> when no name is offered).
	HostnameSource string
	// ConflictPolicy governs an existing record collision: replace-owned
	// (default — only replace records this firewall owns per the state
	// store), skip-existing, or strict-fail.
	ConflictPolicy string
	// Backend selects the DNS-update mechanism. "rfc2136" is the default and
	// is LIVE (#1387 inc-2): records are published to and withdrawn from the
	// authoritative server over real RFC 2136 UPDATE by the always-on
	// reconcile loop. "kea-d2" is a reserved enum value that is NOT
	// implemented (Kea D2 is not in the image — bake.py); selecting it warns
	// at commit and publishes nothing.
	Backend string
	// UpdateServer is the RFC 2136 target authoritative DNS, host or
	// host:port (rfc2136 backend). It IS consumed by the live path: an
	// enabled rfc2136 backend with no update-server publishes nothing and
	// warns at commit (validateDDNSBackendWarnings).
	UpdateServer string
	// TSIGKeyName / TSIGAlgorithm / TSIGSecret are the TSIG credentials
	// for authenticated RFC 2136 updates. TSIGSecret is the sensitive HMAC
	// key. It is redacted by String() (so a %v/%s/slog of this struct never
	// leaks the key — see String below) AND, since #2053, by its Secret
	// type on every JSON/YAML marshal (so the compiled-config dump on
	// GET /api/v1/config never leaks it either). The reconciler/render paths
	// read the cleartext via Reveal().
	TSIGKeyName   string
	TSIGAlgorithm string
	TSIGSecret    Secret
	// SourceAddress / DestinationInterface / RoutingInstance scope the RFC
	// 2136 UPDATE TRANSPORT (#2691 P1b / #2665). In a multi-WAN / VRF
	// deployment a DNS UPDATE must egress from the right source IP, the right
	// interface, and/or the right routing-instance (VRF) or it is dropped by
	// source-IP-keyed ACLs or sent to the wrong upstream. The live rfc2136
	// backend builds its transport with a custom net.Dialer:
	//   - SourceAddress       → Dialer.LocalAddr (bind the UDP/TCP socket's
	//     source IP). Must be a bare IP literal (v4 or v6); the port is chosen
	//     by the kernel.
	//   - DestinationInterface → Dialer.Control → SO_BINDTODEVICE (pin egress
	//     to a specific interface; covers the no-source-route / policy-route
	//     case).
	//   - RoutingInstance     → Dialer.Control → SO_BINDTODEVICE on the VRF
	//     master device (Linux binds a socket into a VRF by binding to the vrf
	//     device). xpf names a routing-instance and the VRF device shares that
	//     name (pkg/routing), so the bind target is the routing-instance name.
	// All three are optional; empty means "default table / kernel source
	// selection" (today's behaviour). They are per-family (v4 vs v6 may bind
	// different sources), which is why they live on this per-family struct.
	SourceAddress        string
	DestinationInterface string
	RoutingInstance      string
}

// String redacts TSIGSecret so a %v/%s/slog format of a
// DHCPDynamicDNSConfig never leaks the shared HMAC key (logging hygiene,
// mirrors WireguardPeer in types_routing.go). The reconciler and render
// paths read the field directly; only formatted/logged copies are
// redacted.
func (d *DHCPDynamicDNSConfig) String() string {
	if d == nil {
		return "<nil>"
	}
	secret := ""
	if d.TSIGSecret != "" {
		secret = "<redacted>"
	}
	return fmt.Sprintf("DHCPDynamicDNS{enabled=%t domain=%q ttl=%d "+
		"hostname-source=%q conflict-policy=%q backend=%q update-server=%q "+
		"tsig-key=%q tsig-alg=%q tsig-secret=%q}",
		d.Enabled, d.Domain, d.TTLSeconds, d.HostnameSource,
		d.ConflictPolicy, d.Backend, RedactURL(d.UpdateServer), // #9497: same redaction as MarshalJSON
		d.TSIGKeyName, d.TSIGAlgorithm, secret)
}

// DHCPLocalServerConfig holds per-group DHCP server settings.
type DHCPLocalServerConfig struct {
	Groups map[string]*DHCPServerGroup
	// ExpiredLeases is the opt-in Kea expired-lease reclamation policy
	// (#1387 stale-lease-cleanup slice / Path S). nil == today's
	// behaviour byte-for-byte: no `expired-leases-processing` block is
	// rendered and Kea uses its built-in reclamation defaults. The block
	// is GLOBAL to the family — Kea has no per-subnet reclamation — so it
	// sits here on DHCPLocalServerConfig (one per family: dhcp-local-server
	// for v4, dhcpv6-local-server for v6), not on DHCPPool. v4 and v6 are
	// tuned independently because Kea renders the block per Dhcp4 / Dhcp6.
	ExpiredLeases *DHCPExpiredLeasesConfig

	// SocketType maps to Kea's `interfaces-config.dhcp-socket-type` and is
	// IPv4-ONLY (#7318). "" == today's behaviour byte-for-byte: the key is not
	// rendered, so Kea applies its documented default `raw`. The measurement
	// that motivates the leaf, and the trade that makes it opt-in rather than a
	// default flip, are on DHCPSocketTypeRaw/UDP in types_dhcp_socket_type.go.
	SocketType string
}

// DHCPExpiredLeasesConfig maps to Kea's per-family
// `expired-leases-processing` block (#1387 stale-lease-cleanup slice).
// It controls how aggressively Kea REMOVES leases that have ALREADY
// expired/been released/declined from the memfile — it is ORTHOGONAL to
// lease-time (DHCPPool.LeaseTime / the hardcoded valid-lifetime), which
// sets how long a lease stays VALID (invariant H4). Field
// units/semantics are Kea-native (the operator types Kea numbers); see
// https://kea.readthedocs.io for the authoritative meaning.
//
// Rendering is opt-in: a nil block OR Enabled==false renders NOTHING, so
// the generated Kea config is byte-identical to today (invariant H1).
// Each numeric field is emitted only when set, so an operator can flip
// `enable` on and tune one knob without pinning the rest to a value we
// invented.
type DHCPExpiredLeasesConfig struct {
	// Enabled gates rendering of the whole block. A block that parses but
	// never sets `enable` still renders nothing (explicit opt-in, mirrors
	// DHCPDynamicDNSConfig.Enabled).
	Enabled bool
	// ReclaimTimerWait is seconds between reclamation cycles
	// (reclaim-timer-wait-time). 0 == unset -> the key is omitted and Kea
	// uses its default.
	ReclaimTimerWait int
	// FlushReclaimedTimerWait is seconds between flush passes that remove
	// reclaimed leases past hold-time (flush-reclaimed-timer-wait-time).
	// 0 == unset -> omitted.
	FlushReclaimedTimerWait int
	// HoldReclaimedTime is seconds a reclaimed lease is retained before
	// physical removal (hold-reclaimed-time). 0 == unset -> omitted. (Kea
	// keeps a reclaimed lease this long so a renewing client reclaims its
	// own address.)
	HoldReclaimedTime int
	// MaxReclaimLeases caps leases reclaimed per cycle (max-reclaim-leases).
	// In Kea, 0 means UNLIMITED — a DIFFERENT desired state from "omit the
	// key and inherit Kea's default" — so the model MUST distinguish a
	// value of 0 from unset (invariant H2). MaxReclaimLeasesSet is true
	// exactly when the operator configured `max-leases`; a bare `if x > 0`
	// render would make `max-leases 0` (unlimited) un-expressible.
	MaxReclaimLeases    int
	MaxReclaimLeasesSet bool
	// MaxReclaimTime caps milliseconds spent reclaiming per cycle
	// (max-reclaim-time). 0 means UNLIMITED in Kea, so it uses the same
	// set/unset discipline as MaxReclaimLeases (invariant H2).
	MaxReclaimTime    int
	MaxReclaimTimeSet bool
	// UnwarnedReclaimCycles is consecutive cycles hitting the cap before
	// Kea warns (unwarned-reclaim-cycles). 0 == unset -> omitted.
	UnwarnedReclaimCycles int
}

// DHCPServerGroup defines a DHCP server group.
type DHCPServerGroup struct {
	Name       string
	Interfaces []string
	Pools      []*DHCPPool
	// MembersFiltered marks a group whose Interfaces list is a RUNTIME-narrowed
	// subset of what the operator authored — today only the chassis-cluster
	// master-RG filter (daemon.filterDHCPConfigForMasterRGs) sets it. It is
	// never set by the config compiler and never appears in a committed config.
	//
	// It exists because Interfaces and Pools are independent arrays with NO
	// semantic edge: nothing records which pool belongs to which member. So once
	// members are removed, "this group has exactly one interface" no longer
	// implies "every pool in this group is served on that interface" — the
	// inference dhcpserver.subnetInterface makes when it emits Kea's per-subnet
	// interface selector. A mixed `[fxp0.0, reth0.80]` group narrowed to the
	// surviving RETH member would otherwise bind the fxp0 pool's subnet to the
	// RETH member (#6520). With this set the renderer omits the selector and
	// Kea falls back to address-based subnet selection, which is correct for
	// every group — just less robust than an explicit binding, which is why the
	// selector is emitted at all.
	//
	// It is excluded from every marshal (`json:"-"`, `yaml:"-"`): it describes
	// this PROCESS's current mastership view, not the operator's configuration,
	// so it must not appear in the compiled-config dump (GET /api/v1/config),
	// in the golden compile baseline, or in anything the cluster config-sync
	// carries to the peer — where it would be read as a committed value the
	// peer's own filter should not inherit.
	MembersFiltered bool `json:"-" yaml:"-"`
}

// DHCPPool defines an address pool for DHCP leases.
type DHCPPool struct {
	Name       string
	RangeLow   string
	RangeHigh  string
	Subnet     string // pool network (e.g. "10.0.1.0/24")
	Router     string
	DNSServers []string
	LeaseTime  int // seconds (0 = default 86400)
	Domain     string
	// StaticBindings are fixed (reserved) address assignments scoped to
	// this pool's subnet (#2243). Each binds a client identity
	// (hardware-address / MAC) to a fixed-address that the matching client
	// always receives. They render to Kea per-subnet `reservations`
	// (hw-address -> ip-address [+ hostname]). Reservations derive entirely
	// from the committed config, so an HA pair serving identical subnets is
	// reservation-consistent by construction via the existing cluster
	// config-sync — no per-lease replication is needed for the static case
	// (the dynamic-lease HA gap is the separate companion #2239).
	StaticBindings []*DHCPStaticBinding
}

// DHCPStaticBinding is a single fixed/reserved DHCP-server host binding
// (#2243). Junos `dhcp-local-server group <g> pool <p> static-binding <mac>
// { fixed-address <ip>; host-name <name>; }`. It maps a client hardware
// address to a fixed address within the enclosing pool's subnet; the
// optional host-name becomes the Kea reservation hostname.
type DHCPStaticBinding struct {
	// MACAddress is the client hardware address (the binding identity key),
	// e.g. "00:11:22:33:44:55". Rendered as Kea `hw-address`.
	MACAddress string
	// FixedAddress is the reserved IP the matching client always receives.
	// Must fall inside the enclosing pool's Subnet. Rendered as Kea
	// `ip-address`.
	FixedAddress string
	// HostName is the optional reservation hostname (Kea `hostname`). Empty
	// when not configured.
	HostName string
}

// NTPServerOption is the set of Junos `system ntp server <addr>` per-server
// modifiers (#7132). Before #7132 these were absorbed into the server address
// list as if they were additional servers — `prefer` is a syntactically valid
// hostname, so validation accepted it — and a hand-written keyword table in the
// compiler existed solely to skip them. They are now modeled in setSchema as
// modifier children of the `server` leaf, so the compiler reads them from the
// AST instead of pattern-matching keywords.
type NTPServerOption struct {
	// Prefer marks this source preferred to chrony.
	Prefer bool
	// Key is the authentication key id (0 = unset).
	Key int
	// Version is the NTP protocol version to use (0 = chrony default).
	Version int
	// RoutingInstance is the VRF the server is reached in ("" = default).
	// Recorded but not yet honoured by the chrony renderer — chrony has no
	// per-source VRF directive, so acting on it needs a routing change rather
	// than a config one.
	RoutingInstance string
}
