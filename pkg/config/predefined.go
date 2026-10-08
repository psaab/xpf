package config

import "fmt"

// u8p returns a pointer to a uint8 literal, used for optional ICMP type/code
// constraints on predefined applications (for example, junos-icmp-ping).
func u8p(v uint8) *uint8 { return &v }

// PredefinedApplications contains built-in Junos application definitions.
// Based on the official Junos OS predefined application list.
var PredefinedApplications = map[string]*Application{
	// --- Basic services ---
	"junos-ftp":    {Name: "junos-ftp", Protocol: "tcp", DestinationPort: "21", ALG: "ftp"},
	"junos-ssh":    {Name: "junos-ssh", Protocol: "tcp", DestinationPort: "22"},
	"junos-telnet": {Name: "junos-telnet", Protocol: "tcp", DestinationPort: "23"},
	"junos-smtp":   {Name: "junos-smtp", Protocol: "tcp", DestinationPort: "25"},
	"junos-smtps":  {Name: "junos-smtps", Protocol: "tcp", DestinationPort: "465"},
	"junos-http":   {Name: "junos-http", Protocol: "tcp", DestinationPort: "80"},
	"junos-https":  {Name: "junos-https", Protocol: "tcp", DestinationPort: "443"},
	"junos-rtsp":   {Name: "junos-rtsp", Protocol: "tcp", DestinationPort: "554"},

	// --- DNS ---
	"junos-dns-udp": {Name: "junos-dns-udp", Protocol: "udp", DestinationPort: "53"},
	"junos-dns-tcp": {Name: "junos-dns-tcp", Protocol: "tcp", DestinationPort: "53"},

	// --- Mail ---
	"junos-pop3":  {Name: "junos-pop3", Protocol: "tcp", DestinationPort: "110"},
	"junos-imap":  {Name: "junos-imap", Protocol: "tcp", DestinationPort: "143"},
	"junos-imaps": {Name: "junos-imaps", Protocol: "tcp", DestinationPort: "993"},
	"junos-nntp":  {Name: "junos-nntp", Protocol: "tcp", DestinationPort: "119"},

	// --- DHCP & Boot ---
	"junos-dhcp-client": {Name: "junos-dhcp-client", Protocol: "udp", DestinationPort: "68"},
	"junos-dhcp-server": {Name: "junos-dhcp-server", Protocol: "udp", DestinationPort: "67"},
	"junos-bootpc":      {Name: "junos-bootpc", Protocol: "udp", DestinationPort: "68"},
	"junos-bootps":      {Name: "junos-bootps", Protocol: "udp", DestinationPort: "67"},

	// --- File transfer ---
	"junos-tftp": {Name: "junos-tftp", Protocol: "udp", DestinationPort: "69"},

	// --- Network management ---
	"junos-ntp":            {Name: "junos-ntp", Protocol: "udp", DestinationPort: "123"},
	"junos-snmp":           {Name: "junos-snmp", Protocol: "udp", DestinationPort: "161"},
	"junos-snmp-agentx":    {Name: "junos-snmp-agentx", Protocol: "tcp", DestinationPort: "705"},
	"junos-syslog":         {Name: "junos-syslog", Protocol: "udp", DestinationPort: "514"},
	"junos-xnm-ssl":        {Name: "junos-xnm-ssl", Protocol: "tcp", DestinationPort: "3220"},
	"junos-xnm-clear-text": {Name: "junos-xnm-clear-text", Protocol: "tcp", DestinationPort: "3221"},

	// --- Routing ---
	"junos-bgp":     {Name: "junos-bgp", Protocol: "tcp", DestinationPort: "179"},
	"junos-rip":     {Name: "junos-rip", Protocol: "udp", DestinationPort: "520"},
	"junos-ldp-tcp": {Name: "junos-ldp-tcp", Protocol: "tcp", DestinationPort: "646"},
	"junos-ldp-udp": {Name: "junos-ldp-udp", Protocol: "udp", DestinationPort: "646"},
	"junos-ospf":    {Name: "junos-ospf", Protocol: "89"},

	// --- Directory & authentication ---
	"junos-ldap":      {Name: "junos-ldap", Protocol: "tcp", DestinationPort: "389"},
	"junos-tacacs":    {Name: "junos-tacacs", Protocol: "tcp", DestinationPort: "49"},
	"junos-tacacs-ds": {Name: "junos-tacacs-ds", Protocol: "tcp", DestinationPort: "65"},
	"junos-radius":    {Name: "junos-radius", Protocol: "udp", DestinationPort: "1812"},
	"junos-radacct":   {Name: "junos-radacct", Protocol: "udp", DestinationPort: "1813"},

	// --- VPN & tunneling ---
	"junos-ike":      {Name: "junos-ike", Protocol: "udp", DestinationPort: "500"},
	"junos-ike-nat":  {Name: "junos-ike-nat", Protocol: "udp", DestinationPort: "4500"},
	"junos-l2tp":     {Name: "junos-l2tp", Protocol: "udp", DestinationPort: "1701"},
	"junos-gre":      {Name: "junos-gre", Protocol: "gre"},
	"junos-ip-in-ip": {Name: "junos-ip-in-ip", Protocol: "4"},
	"junos-ipip":     {Name: "junos-ipip", Protocol: "4"},

	// --- Windows/SMB ---
	"junos-smb-session":     {Name: "junos-smb-session", Protocol: "tcp", DestinationPort: "445"},
	"junos-netbios-session": {Name: "junos-netbios-session", Protocol: "tcp", DestinationPort: "139"},
	"junos-nbname":          {Name: "junos-nbname", Protocol: "udp", DestinationPort: "137"},
	"junos-nbds":            {Name: "junos-nbds", Protocol: "udp", DestinationPort: "138"},
	"junos-ms-sql":          {Name: "junos-ms-sql", Protocol: "tcp", DestinationPort: "1433"},
	"junos-ms-rpc-tcp":      {Name: "junos-ms-rpc-tcp", Protocol: "tcp", DestinationPort: "135"},
	"junos-ms-rpc-udp":      {Name: "junos-ms-rpc-udp", Protocol: "udp", DestinationPort: "135"},

	// --- RPC / NFS ---
	"junos-sun-rpc-tcp": {Name: "junos-sun-rpc-tcp", Protocol: "tcp", DestinationPort: "111"},
	"junos-sun-rpc-udp": {Name: "junos-sun-rpc-udp", Protocol: "udp", DestinationPort: "111"},
	"junos-nfsd-tcp":    {Name: "junos-nfsd-tcp", Protocol: "tcp", DestinationPort: "2049"},
	"junos-nfsd-udp":    {Name: "junos-nfsd-udp", Protocol: "udp", DestinationPort: "2049"},

	// --- Printing ---
	"junos-printer": {Name: "junos-printer", Protocol: "tcp", DestinationPort: "515"},

	// --- Database ---
	"junos-sqlnet-v1":  {Name: "junos-sqlnet-v1", Protocol: "tcp", DestinationPort: "1525"},
	"junos-sqlnet-v2":  {Name: "junos-sqlnet-v2", Protocol: "tcp", DestinationPort: "1521"},
	"junos-cvspserver": {Name: "junos-cvspserver", Protocol: "tcp", DestinationPort: "2401"},

	// --- VoIP / signaling ---
	// SIP signals over BOTH transports on port 5060 (UDP by default, TCP added
	// in Junos 12.3X48-D25 / 17.3R1). Real Junos `junos-sip` matches UDP/5060 AND
	// TCP/5060, so it is modeled as the PredefinedApplicationSet "junos-sip" below
	// over these two single-protocol members — mirroring the junos-ms-rpc /
	// junos-sun-rpc TCP+UDP split. The prior UDP-only predefined application
	// silently dropped TCP/5060 SIP from any policy referencing junos-sip (#5634).
	"junos-sip-udp": {Name: "junos-sip-udp", Protocol: "udp", DestinationPort: "5060"},
	"junos-sip-tcp": {Name: "junos-sip-tcp", Protocol: "tcp", DestinationPort: "5060"},
	"junos-mgcp-ua": {Name: "junos-mgcp-ua", Protocol: "udp", DestinationPort: "2427"},
	"junos-mgcp-ca": {Name: "junos-mgcp-ca", Protocol: "udp", DestinationPort: "2727"},
	// The #11341 Junos-defaults captures define H.323 as six terms. Represent
	// them as individual predefined members for the junos-h323 set below.
	"junos-h323-q931":     {Name: "junos-h323-q931", Protocol: "tcp", DestinationPort: "1720", ALG: "q931"},
	"junos-h323-ras":      {Name: "junos-h323-ras", Protocol: "udp", DestinationPort: "1719", ALG: "ras"},
	"junos-h323-tcp-1503": {Name: "junos-h323-tcp-1503", Protocol: "tcp", DestinationPort: "1503"},
	"junos-h323-tcp-389":  {Name: "junos-h323-tcp-389", Protocol: "tcp", DestinationPort: "389"},
	"junos-h323-tcp-522":  {Name: "junos-h323-tcp-522", Protocol: "tcp", DestinationPort: "522"},
	"junos-h323-tcp-1731": {Name: "junos-h323-tcp-1731", Protocol: "tcp", DestinationPort: "1731"},
	"junos-sccp":          {Name: "junos-sccp", Protocol: "tcp", DestinationPort: "2000"},

	// --- Messaging ---
	"junos-msn": {Name: "junos-msn", Protocol: "tcp", DestinationPort: "1863"},
	"junos-aol": {Name: "junos-aol", Protocol: "tcp", DestinationPort: "5190-5193"},
	"junos-irc": {Name: "junos-irc", Protocol: "tcp", DestinationPort: "6660-6669"},

	// --- Remote desktop ---
	"junos-vnc":         {Name: "junos-vnc", Protocol: "tcp", DestinationPort: "5800"},
	"junos-x-windows":   {Name: "junos-x-windows", Protocol: "tcp", DestinationPort: "6000-6063"},
	"junos-winframe":    {Name: "junos-winframe", Protocol: "tcp", DestinationPort: "1494"},
	"junos-pc-anywhere": {Name: "junos-pc-anywhere", Protocol: "udp", DestinationPort: "5632"},
	"junos-rdp":         {Name: "junos-rdp", Protocol: "tcp", DestinationPort: "3389"},

	// --- Streaming / misc ---
	"junos-vdo-live": {Name: "junos-vdo-live", Protocol: "udp", DestinationPort: "7000-7010"},
	"junos-gnutella": {Name: "junos-gnutella", Protocol: "udp", DestinationPort: "6346-6347"},
	"junos-http-ext": {Name: "junos-http-ext", Protocol: "tcp", DestinationPort: "7001"},
	"junos-gtp":      {Name: "junos-gtp", Protocol: "udp", DestinationPort: "2123"},

	// --- Lookup / info ---
	"junos-finger": {Name: "junos-finger", Protocol: "tcp", DestinationPort: "79"},
	"junos-ident":  {Name: "junos-ident", Protocol: "tcp", DestinationPort: "113"},
	"junos-whois":  {Name: "junos-whois", Protocol: "tcp", DestinationPort: "43"},
	"junos-gopher": {Name: "junos-gopher", Protocol: "tcp", DestinationPort: "70"},
	"junos-wais":   {Name: "junos-wais", Protocol: "tcp", DestinationPort: "210"},

	// --- Juniper management ---
	"junos-ns-global":     {Name: "junos-ns-global", Protocol: "tcp", DestinationPort: "15397"},
	"junos-ns-global-pro": {Name: "junos-ns-global-pro", Protocol: "tcp", DestinationPort: "15397"},

	// --- ICMP / ICMPv6 ---
	// #11340: three version-bounded Junos defaults dumps define junos-ping and
	// junos-pingv6 as protocol-only ICMP/ICMPv6 applications. The echo-only
	// application is junos-icmp-ping (ICMP type 8, no code constraint).
	"junos-ping":      {Name: "junos-ping", Protocol: "icmp"},
	"junos-pingv6":    {Name: "junos-pingv6", Protocol: "icmpv6"},
	"junos-icmp-ping": {Name: "junos-icmp-ping", Protocol: "icmp", ICMPType: u8p(8)},
	"junos-icmp-all":  {Name: "junos-icmp-all", Protocol: "icmp"},
	"junos-icmp6-all": {Name: "junos-icmp6-all", Protocol: "icmpv6"},

	// --- Traceroute ---
	"junos-traceroute": {Name: "junos-traceroute", Protocol: "udp", DestinationPort: "33434-33523"},

	// --- Wildcard protocol ---
	"junos-tcp-any": {Name: "junos-tcp-any", Protocol: "tcp"},
	"junos-udp-any": {Name: "junos-udp-any", Protocol: "udp"},
}

// PredefinedApplicationSets contains Junos application-set definitions from
// version-bounded `junos-defaults` captures; it does not claim current-release
// SRX/vSRX inventory. A canonical vSRX policy may reference these names — e.g.
// `set security policies ... match application junos-ms-rpc` — so the table
// makes captured Junos defaults available without operator redefinition. Before
// #4102 ResolveApplicationSet consulted ONLY user-defined sets, so such
// references failed at commit and runtime.
//
// Members for the original bundles were verified against an SRX 15.1X49
// `show configuration groups junos-defaults` dump. #11341 adds the multi-term
// junos-smb and junos-h323 defaults from the issue's version-bounded captures;
// those captures do not establish current-release vSRX parity. Every member
// resolves through PredefinedApplications, so each set expands to >= 1 member
// and clears the empty-set fail-open gate (#3146). ResolveApplicationSet and
// ExpandApplicationSet fall back to this table AFTER user-defined sets, so an
// operator can still shadow or extend a bundle name (user-then-predefined
// precedence, mirroring ResolveApplication).
var PredefinedApplicationSets = map[string]*ApplicationSet{
	// Microsoft RPC endpoint mapper (TCP + UDP 135).
	"junos-ms-rpc": {
		Name:         "junos-ms-rpc",
		Applications: []string{"junos-ms-rpc-tcp", "junos-ms-rpc-udp"},
	},
	// ONC / Sun RPC portmapper (TCP + UDP 111).
	"junos-sun-rpc": {
		Name:         "junos-sun-rpc",
		Applications: []string{"junos-sun-rpc-tcp", "junos-sun-rpc-udp"},
	},
	// CIFS / Windows file sharing over NetBIOS session (139) + SMB (445).
	"junos-cifs": {
		Name:         "junos-cifs",
		Applications: []string{"junos-netbios-session", "junos-smb-session"},
	},
	// Inbound routing protocols: BGP (179/tcp), RIP (520/udp), LDP (646/tcp+udp).
	"junos-routing-inbound": {
		Name:         "junos-routing-inbound",
		Applications: []string{"junos-bgp", "junos-rip", "junos-ldp-tcp", "junos-ldp-udp"},
	},
	// SIP signaling over both transports: UDP/5060 (default) + TCP/5060 (SIP over
	// TCP, Junos 12.3X48-D25 / 17.3R1). Junos `junos-sip` matches both; modeling
	// it as a bundle (rather than the old UDP-only application) closes the
	// TCP/5060 under-match (#5634). Member order is UDP-first to mirror the Junos
	// default transport. resolveUserspaceApplicationNames resolves an application
	// FIRST, so junos-sip MUST NOT remain in PredefinedApplications (an app hit
	// would shadow this set and re-drop TCP/5060).
	"junos-sip": {
		Name:         "junos-sip",
		Applications: []string{"junos-sip-udp", "junos-sip-tcp"},
	},
	// The #11341 issue-cited, version-bounded Junos defaults define these as
	// multi-term applications. They are sets because Application stores one
	// protocol/port tuple; current-release vSRX readback remains outstanding.
	// Keep both names out of PredefinedApplications: app-first resolution would
	// shadow each multi-term set with the previous single-term entry.
	"junos-smb": {
		Name:         "junos-smb",
		Applications: []string{"junos-netbios-session", "junos-smb-session"},
	},
	"junos-h323": {
		Name: "junos-h323",
		Applications: []string{
			"junos-h323-q931", "junos-h323-ras", "junos-h323-tcp-1503",
			"junos-h323-tcp-389", "junos-h323-tcp-522", "junos-h323-tcp-1731",
		},
	},
}

// ResolveApplication looks up an application by name, checking user-defined
// applications first, then predefined.
func ResolveApplication(name string, userApps map[string]*Application) (*Application, bool) {
	if userApps != nil {
		if app, ok := userApps[name]; ok {
			return app, true
		}
	}
	if app, ok := PredefinedApplications[name]; ok {
		return app, true
	}
	return nil, false
}

// ResolveApplicationSet looks up an application-set by name, checking
// user-defined sets first, then the built-in PredefinedApplicationSets table
// (#4102, #11341). Mirrors ResolveApplication's user-then-predefined precedence
// so the commit gate and runtime resolver recognize the Junos bundles, including
// the version-bounded junos-smb and junos-h323 definitions.
func ResolveApplicationSet(name string, appSets map[string]*ApplicationSet) (*ApplicationSet, bool) {
	return lookupApplicationSet(name, appSets)
}

// lookupApplicationSet returns the application-set definition for name,
// checking user-defined sets first (so an operator can shadow or extend a
// predefined bundle name) then the built-in predefined Junos set table.
func lookupApplicationSet(name string, appSets map[string]*ApplicationSet) (*ApplicationSet, bool) {
	if appSets != nil {
		// #5179: a present-but-nil map value (ApplicationSets[name] == nil)
		// must NOT be reported as a found set. The tolerant-load / peer-sync
		// path (#1960) can admit a null slot; returning (nil, true) here made
		// expandAppSet range over as.Applications on a nil *ApplicationSet — a
		// nil-deref panic that took down the whole control-plane catalog build
		// (appid.CatalogNames) on commit/load. Skip the nil slot so the lookup
		// falls through to the predefined table (an operator nulling out a
		// predefined bundle name keeps the built-in definition) or, failing
		// that, returns (nil, false) → a deterministic "not found" expansion
		// error instead of a panic. Fail-closed, not fatal.
		if as, ok := appSets[name]; ok && as != nil {
			return as, true
		}
	}
	if as, ok := PredefinedApplicationSets[name]; ok {
		return as, true
	}
	return nil, false
}

// ExpandApplicationSet recursively expands an application-set to individual
// application names. Returns an error if a member is not found. Max depth 3.
func ExpandApplicationSet(name string, apps *ApplicationsConfig) ([]string, error) {
	return expandAppSet(name, apps, 0)
}

// appSetMemo collapses the repeated expansion of the SAME application-set
// within one compile (issue 8889).
//
// Without it, a nest of sets each referencing B others re-expands every shared
// subtree on every path that reaches it, and the depth cap of 3 fixes the
// exponent at four: doubling B costs about 23x, and ~193 sets extrapolates to
// roughly a minute. That runs under the store's READ lock in CommitCheck, so
// Commit, Load and the HA SyncApply path queue behind it.
//
// KEYED ON (name, depth), NOT NAME. A set that expands cleanly at depth 0 may
// exceed the cap when reached at depth 3, so a name-keyed memo would serve a
// shallow success into a deep context and silently satisfy the depth check that
// makes the cost bounded in the first place. Keying on the pair reuses a result
// only in the identical depth context, so cap behaviour is unchanged
// bit-for-bit, and the memo is still at most 4 entries per set -- O(total)
// rather than O(B^4).
//
// calls counts expansion BODIES executed. It exists so the guard can assert the
// CURVE (a count that does not grow with B) instead of a wall-clock threshold,
// which is flaky and tells the next reader nothing about why.
type appSetMemo struct {
	done  map[appSetMemoKey]appSetMemoEntry
	calls int
}

type appSetMemoKey struct {
	name  string
	depth int
}

type appSetMemoEntry struct {
	result []string
	err    error
}

func newAppSetMemo() *appSetMemo {
	return &appSetMemo{done: make(map[appSetMemoKey]appSetMemoEntry)}
}

func expandAppSet(name string, apps *ApplicationsConfig, depth int) ([]string, error) {
	return expandAppSetMemo(name, apps, depth, newAppSetMemo())
}

func expandAppSetMemo(name string, apps *ApplicationsConfig, depth int, memo *appSetMemo) ([]string, error) {
	if memo == nil {
		memo = newAppSetMemo()
	}
	key := appSetMemoKey{name: name, depth: depth}
	if hit, ok := memo.done[key]; ok {
		// Copy: callers append to and dedupe into their own result slice, and a
		// shared backing array would let one caller's append corrupt another's.
		if hit.result == nil {
			return nil, hit.err
		}
		out := make([]string, len(hit.result))
		copy(out, hit.result)
		return out, hit.err
	}
	memo.calls++
	result, err := expandAppSetUncached(name, apps, depth, memo)
	memo.done[key] = appSetMemoEntry{result: result, err: err}
	if result == nil {
		return nil, err
	}
	out := make([]string, len(result))
	copy(out, result)
	return out, err
}

func expandAppSetUncached(name string, apps *ApplicationsConfig, depth int, memo *appSetMemo) ([]string, error) {
	if depth > 3 {
		return nil, fmt.Errorf("application-set nesting too deep (max 3): %s", name)
	}

	as, ok := lookupApplicationSet(name, apps.ApplicationSets)
	if !ok {
		return nil, fmt.Errorf("application-set %q not found", name)
	}

	var result []string
	seen := make(map[string]bool)

	for _, memberName := range as.Applications {
		// Check if it's another application-set (recurse). A member may name a
		// user-defined OR a predefined set (#4102); memberIsNestedSet preserves
		// the historical classification (user-set → application → error) and
		// only recurses a predefined set when the member is not an application.
		if memberIsNestedSet(memberName, apps) {
			expanded, err := expandAppSetMemo(memberName, apps, depth+1, memo)
			if err != nil {
				return nil, err
			}
			for _, a := range expanded {
				if !seen[a] {
					seen[a] = true
					result = append(result, a)
				}
			}
			continue
		}

		// Must be an individual application
		if _, found := ResolveApplication(memberName, apps.Applications); !found {
			return nil, fmt.Errorf("application-set %q: member %q not found", name, memberName)
		}
		if !seen[memberName] {
			seen[memberName] = true
			result = append(result, memberName)
		}
	}

	return result, nil
}

// memberIsNestedSet reports whether an application-set member should be expanded
// as a nested set rather than resolved as a leaf application. A user-defined set
// always wins first (an operator may shadow a predefined bundle name); a
// predefined set is consulted only when the member does not resolve as an
// application, so a user application that shadows a predefined-set name keeps
// application semantics — preserving the pre-#4102 member classification for
// every existing config while enabling nested references to predefined bundles.
func memberIsNestedSet(memberName string, apps *ApplicationsConfig) bool {
	if apps.ApplicationSets != nil {
		// #5671: mirror lookupApplicationSet's `&& as != nil` guard. The
		// tolerant-load / peer-sync path (#1960) can admit a present-but-nil
		// slot (ApplicationSets[memberName] == nil). Treating that slot as a
		// nested set routed the member to expandAppSet → lookupApplicationSet,
		// which skips the nil and errors "application-set not found" — instead
		// of falling through to resolve the member as a leaf application (which
		// may well exist and shadow the nulled name). Skip the nil slot so the
		// leaf-application / predefined-set classification below runs.
		if as, ok := apps.ApplicationSets[memberName]; ok && as != nil {
			return true
		}
	}
	if _, isApp := ResolveApplication(memberName, apps.Applications); isApp {
		return false
	}
	_, isPredefSet := PredefinedApplicationSets[memberName]
	return isPredefSet
}

const maxAddressSetDepth = 5

// ExpandAddressSet recursively expands an address-set to individual
// address names. Handles nested address-sets with cycle detection. A set carrying
// an unknown member statement is rejected rather than expanded to its surviving
// subset (#11822). Max depth is five nested edges.
func ExpandAddressSet(name string, ab *AddressBook) ([]string, error) {
	return expandAddrSet(name, ab, make(map[string]bool), 0)
}

func addressSetForExpansion(
	name string,
	ab *AddressBook,
	visited map[string]bool,
	depth int,
) (*AddressSet, error) {
	if depth > maxAddressSetDepth {
		return nil, fmt.Errorf(
			"address-set nesting too deep (max %d): %s",
			maxAddressSetDepth, name)
	}
	if visited[name] {
		return nil, fmt.Errorf("cycle detected in address-set %q", name)
	}

	as, ok := ab.AddressSets[name]
	if !ok {
		return nil, fmt.Errorf("address-set %q not found", name)
	}
	if as == nil {
		return nil, fmt.Errorf("address-set %q is nil", name)
	}
	if len(as.UnknownMembers) > 0 {
		return nil, fmt.Errorf("address-set %q has unknown member statement %q; "+
			"the member was silently dropped and the set is under-populated",
			name, as.UnknownMembers[0])
	}
	return as, nil
}

// validateAddressSetDepthAndCycles checks the same path-local depth and cycle
// bounds as ExpandAddressSet without allocating its flattened member result.
func validateAddressSetDepthAndCycles(name string, ab *AddressBook) error {
	return validateAddrSetDepthAndCycles(name, ab, make(map[string]bool), 0)
}

func validateAddrSetDepthAndCycles(
	name string,
	ab *AddressBook,
	visited map[string]bool,
	depth int,
) error {
	as, err := addressSetForExpansion(name, ab, visited, depth)
	if err != nil {
		return err
	}
	visited[name] = true
	defer delete(visited, name)
	for _, nested := range as.AddressSets {
		if err := validateAddrSetDepthAndCycles(nested, ab, visited, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func expandAddrSet(name string, ab *AddressBook, visited map[string]bool, depth int) ([]string, error) {
	as, err := addressSetForExpansion(name, ab, visited, depth)
	if err != nil {
		return nil, err
	}

	visited[name] = true
	defer delete(visited, name)

	var result []string
	seen := make(map[string]bool)

	// Direct address members
	for _, addrName := range as.Addresses {
		if !seen[addrName] {
			seen[addrName] = true
			result = append(result, addrName)
		}
	}

	// Nested address-set members
	for _, setName := range as.AddressSets {
		expanded, err := expandAddrSet(setName, ab, visited, depth+1)
		if err != nil {
			return nil, err
		}
		for _, a := range expanded {
			if !seen[a] {
				seen[a] = true
				result = append(result, a)
			}
		}
	}

	return result, nil
}
