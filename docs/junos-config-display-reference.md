# Junos `show configuration` Display Reference

Reference captured from a live Juniper vSRX cluster (JUNOS 24.4R1-S2.9) on 2026-02-15.

> **Secret redaction (#4099).** For every login class except `super-user`, all
> `show configuration` output — hierarchical, `| display set/json/xml/
> inheritance`, path-scoped, and the `show system rollback` / `rescue` /
> `root-authentication` variants — masks secret leaves with `##SECRET-DATA##`,
> matching Junos and the REST/gRPC `ShowConfig` path (#4051). A VIEW-only
> `read-only` / `config-viewer` / `operator` class never sees a cleartext IKE
> PSK, SNMP community or auth-key. See `docs/system-login.md`.

---

## 1. `show configuration` Sub-Path Completions

The `show configuration` command accepts a hierarchical path to narrow output to a
specific configuration section. Tab/`?` shows:

```
claude@vsrx-bert> show configuration ?
Possible completions:
  <[Enter]>            Execute this command
> access               Network access configuration
> access-profile       Access profile for this instance
> accounting-options   Accounting data configuration
> applications         Define applications by protocol characteristics
+ apply-groups         Groups from which to inherit configuration data
> chassis              Chassis configuration
> class-of-service     Class-of-service configuration
> diameter             Diameter protocol layer
> firewall             Define a firewall configuration
> forwarding-options   Configure options to control packet forwarding
> groups               Configuration groups
> interfaces           Interface configuration
> logical-systems      Logical systems
> policy-options       Policy option configuration
> protocols            Routing protocol configuration
> routing-instances    Routing instance configuration
> routing-options      Protocol-independent routing option configuration
> schedulers           Security scheduler
> security             Security configuration
> services             System services
> smtp                 Simple Mail Transfer Protocol service configuration
> snmp                 Simple Network Management Protocol configuration
> switch-options       Options for default routing-instance of type virtual-switch
> system               System parameters
> tenants              Tenants defined in this system
> vlans                VLAN configuration
  |                    Pipe through a command
```

**Legend:**
- `>` prefix = container node (has sub-completions when you drill deeper)
- `+` prefix = leaf-list (e.g. `apply-groups` accepts multiple values)
- no prefix = leaf or command

Each sub-path can be drilled into further. For example `show configuration interfaces ?`
shows all configured interfaces by name, `show configuration security ?` shows all
security sub-sections, etc.

### 1.1 `show configuration security ?`

```
Possible completions:
  <[Enter]>            Execute this command
> address-book         Security address book
> advance-policy-based-routing  Configure Network Security APBR Policies
  advanced-connection-tracking-timeout  System wide timeout value in seconds
> alarms               Configure security alarms
> alg                  Configure ALG security options
> analysis             Configure security analysis
> application-services  Configure application services
> application-tracking  Application tracking configuration
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
> authentication-key-chains  Authentication key chain configuration
> casb                 Cloud access security broker configuration
> certificates         X.509 certificate configuration
> cloud                Configure Cloud security options
> distribution-profile  IPSec Tunnels distribution profile
> dynamic-address      Configure security dynamic address
> dynamic-application  Configure dynamic-application
> firewall-authentication  Firewall authentication parameters
> flow                 FLOW configuration
> forwarding-options   Security-forwarding-options configuration
> forwarding-process   Configure security forwarding-process options
> group-vpn            Group VPN configuration
> gtp                  GPRS tunneling protocol configuration
> idp                  Configure IDP
> ike                  IKE configuration
> ipsec                IPSec configuration
> ipsec-policy         IPSec policy configuration
> key-manager          Define JKM managed configurations
> l3vpn
> log                  Configure security log
> nat                  Configure Network Address Translation
> ngfw                 Next generation unified L4/L7 firewall
> pki                  PKI service configuration
> policies             Configure Network Security Policies
> remote-access        Configure remote access
> resource-manager     Configure resource manager security options
> screen               Configure screen feature
> sctp                 GPRS stream control transmission protocol configuration
> secure-web-gateway   Secure web gateway configuration for security modules
> softwires            Configure softwire feature
> ssh-known-hosts      SSH known host list
> tcp-encap            Configure TCP Encapsulation
> traceoptions         Network security daemon tracing options
> tunnel-inspection    Security tunnel-inspection
> user-identification  Configure user-identification
> utm                  Content security service configuration
> zones                Zone configuration
  |                    Pipe through a command
```

### 1.2 `show configuration interfaces ?`

Shows all configured interfaces plus meta-options:

```
Possible completions:
  <[Enter]>            Execute this command
  <interface-name>     Interface name
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
  fab0                 Interface name
  fab1                 Interface name
  fxp0                 Interface name
  ge-0/0/0             Interface name
  ge-0/0/2             Interface name
  ...
> interface-range      Interface ranges configuration
> interface-set        Logical interface set configuration
  lo0                  Interface name
  reth0                Comcast Gigabit Pro       <-- description shown!
  reth1                vSRX to US-16-XG
  reth2                ATT
  reth3                Comcast-BCI
  reth4                Atherton-Fiber
  st0                  Interface name
> stacked-interface-set  Stacked interface set configuration
> traceoptions         Interface trace options
  |                    Pipe through a command
```

**Key observation:** Interface descriptions appear in the completion list.

### 1.3 `show configuration system ?`

```
Possible completions:
  <[Enter]>            Execute this command
> accounting           System accounting configuration
  allow-6pe-traceroute  Allow IPv4-mapped v6 address in tag icmp6 TTL expired
  allow-v4mapped-packets  Allow processing for packets with V4 mapped address
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
> archival             System archival management
> arp                  ARP settings
  arp-system-cache-limit  Set max system cache size for ARP nexthops
+ authentication-order  Order in which authentication methods are invoked
> autoinstallation     Autoinstallation configuration
> backup-router        IPv4 router to use while booting
> commit               Configuration commit management
  compress-configuration-files  Compress the router configuration files
> configuration        Set the configuration processing related parameters
> configuration-database  Configuration database parameters
  default-address-selection  Use system address for locally originated traffic
  domain-name          Domain name for this router
+ domain-search        List of domain names to search
  encrypt-configuration-files  Encrypt the router configuration files
> extensions           Configuration for extensions to JUNOS
> fips                 FIPS configuration
> health-monitor       Kernel health monitoring system
  host-name            Hostname for this router
> inet6-backup-router  IPv6 router to use while booting
> internet-options     Tunable options for Internet operation
> license              License information for the router
> location             Location of the system, in various forms
> login                Names, login classes, and passwords for users
  management-instance  Enable Management VRF Instance
> master-password      Master password for $8$ password-encryption
  max-cli-sessions     Maximum number of cli sessions
  max-configurations-on-flash  Number of configuration files stored on flash
> name-server          DNS name servers
  no-hidden-commands   Deny hidden commands for all users except root
  no-multicast-echo    Disable ICMP echo on multicast addresses
  no-redirects         Disable ICMP redirects
  no-redirects-ipv6    Disable IPV6 ICMP redirects
> ntp                  Network Time Protocol services
> password-options     Local password options
> processes            Process control
> radius-server        RADIUS server configuration
> root-authentication  Authentication information for the root login
> services             System services
> syslog               System logging facility
> tacplus-server       TACACS+ server configuration
  time-zone            Time zone name or POSIX-compliant time zone string
  |                    Pipe through a command
```

### 1.4 `show configuration firewall ?`

```
Possible completions:
  <[Enter]>            Execute this command
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
  disable-arp-policers  Disables ARP policers
> family               Protocol family
> filter               Define an IPv4 firewall filter
> flexible-match       Flexible packet match template definition
> policer              Policer template definition
> tunnel-end-point     Tunnel end-point template definition
  |                    Pipe through a command
```

### 1.5 `show configuration routing-instances ?`

Shows all configured routing instance names with tab completion:

```
Possible completions:
  <[Enter]>            Execute this command
  <instance_name>      Routing instance name
  ATT                  Routing instance name
  Atherton-Fiber       Routing instance name
  Comcast-BCI          Routing instance name
  Comcast-GigabitPro   Routing instance name
  Other-GigabitPro     Routing instance name
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
  bv-firehouse-vpn     Routing instance name
  sfmix                Routing instance name
  |                    Pipe through a command
```

### 1.6 `show configuration groups ?`

Shows all configuration group names:

```
Possible completions:
  <[Enter]>            Execute this command
  <group_name>         Group name
  allow-all-between-zones  Group name
  allow-all-between-zones-logged  Group name
  allow-friends-in     Group name
  allow-icmp           Group name
  allow-internet-in-muorg  Group name
  allow-iperf-in       Group name
  allow-my-networks-in  Group name
  allow-plex-in        Group name
  default-deny-template  Group name
  default-internet-out  Group name
  default-internet-to-lan  Group name
  default-long-ssh-allow  Group name
  node0                Group name
  node1                Group name
  |                    Pipe through a command
```

### 1.7 Other Notable Sub-Paths

**`show configuration applications ?`:**
```
> application          Define an application
> application-set      Define an application set
+ apply-groups         Groups from which to inherit configuration data
```

**`show configuration chassis ?`:**
```
> aggregated-devices   Aggregated devices configuration
> alarm                Global alarm settings
  auto-image-upgrade   Auto image upgrade using DHCP
> cluster              Chassis cluster configuration
> config-button        Config button behavior settings
> fpc                  Flexible PIC Concentrator parameters
> high-availability    Enable High Availability mode
> routing-engine       Routing Engine settings
```

**`show configuration policy-options ?`:**
```
> application-maps     Define application maps
> as-list              BGP as range list information
> as-path              BGP autonomous system path regular expression
> as-path-group        Group a set of AS paths
> community            BGP community information
> condition            Define a route advertisement condition
> damping              BGP route flap damping properties
> defaults             Policy default behaviour
> fast-lookup-tuple-list  Define a named set of address prefixes
> mac-list             Define a named set of mac addresses
> policy-statement     Routing policy
> prefix-list          Define a named set of address prefixes
> resolution-map       Define a set of PNH resolution modes
> rib-list             Define a named set of RIB names or wildcards
> route-distinguisher  Route-distinguisher information
> route-filter-list    Define a named set of route-filter address prefixes
  skip-then-actions    Skip 'then' actions and allow route actions in 'from'
> tunnel-attribute     BGP tunnel attributes definition
```

**`show configuration class-of-service ?`:**
```
> adaptive-shapers     Define the list of trigger types and associated rates
> application-traffic-control  Application classifier configuration
> classifiers          Classify incoming packets based on code point value
> code-point-aliases   Mapping of code point aliases to bit strings
> drop-profiles        Random Early Drop (RED) data point map
> forwarding-classes   One or more mappings of forwarding class to queue number
> forwarding-policy    Class-of-service forwarding policy
> host-outbound-traffic  Classify and mark host traffic to forwarding engine
> interfaces           Apply class-of-service options to interfaces
> loss-priority-maps   Map loss priority of incoming packets based on code point value
> rewrite-rules        Write code point value of outgoing packets
> scheduler-maps       Mapping of forwarding classes to packet schedulers
> schedulers           Packet schedulers
  tri-color            Enable tricolor marking
```

**`show configuration forwarding-options ?`:**
```
> access-security      Access security configuration
> accounting           Configure accounting of traffic
> dhcp-relay           Dynamic Host Configuration Protocol relay configuration
> evpn-vxlan           EVPN VXLAN configurations
> family               Protocol family
> hash-key             Select data used in the hash key
> helpers              Port forwarding configuration
> load-balance         Configure load-balancing attributes on the forwarding path
> multicast            Multicast resolve and mismatch rate
> packet-capture       Packet capture options
> port-mirroring       Configure port mirroring of traffic
> sampling             Statistical traffic sampling options
> sflow                Sflow related
> storm-control-profiles  Storm control profile for this instance
```

**`show configuration services ?`:**
```
> advanced-anti-malware
> analytics            Traffic analytics configuration options
> anti-virus
> application-identification  Application identification configuration
> dns-filtering
> flow-monitoring      Configure flow monitoring
> icap-redirect        Configure ICAP redirection service
> ip-monitoring        IP monitoring for route action
> rpm                  Real-time performance monitoring
> rtlog                Secure log daemon options
> screen               Configure screen feature
> security-intelligence
> ssl                  Configuration for Secure Socket Layer support service
> unified-access-control  Configure Unified Access Control
> user-identification  Configure user-identification
> web-filter           Web Filtering service configuration
> web-proxy            Configuration for Web Proxy service
```

**`show configuration snmp ?`:**
```
> arp                  JVision ARP settings
> client-list          Client list
> community            Configure a community string
  contact              Contact information for administrator
  description          System description
> engine-id            SNMPv3 engine ID
  filter-duplicates    Filter requests with duplicate source address/port and request ID
> filter-interfaces    List of interfaces that needs to be filtered
> health-monitor       Health monitoring configuration
+ interface            Restrict SNMP requests to interfaces
  location             Physical location of system
  name                 System name override
> nonvolatile          Configure the handling of nonvolatile SNMP Set requests
> proxy                SNMP proxy configuration
> rmon                 Remote Monitoring configuration
> routing-instance-access  SNMP routing-instance options
> trap-group           Configure traps and notifications
> trap-options         SNMP trap options
> v3                   SNMPv3 configuration information
> view                 Define MIB views
```

---

## 2. Pipe Filters (`|`)

After any `show configuration` command (with or without a sub-path), you can
pipe through one or more filters:

```
claude@vsrx-bert> show configuration | ?
Possible completions:
  append               Append output text to file
  compare              Compare configuration changes with prior version
  count                Count occurrences
  display              Show additional kinds of information
  except               Show only text that does not match a pattern
  find                 Search for first occurrence of pattern
  hold                 Hold text without exiting the --More-- prompt
  last                 Display end of output only
  match                Show only text that matches a pattern
  no-more              Don't paginate output
  save                 Save output text to file
  suppress-zeros       Suppresses lines with zero values
  tee                  Write to standard output and file
  trim                 Trim specified number of columns from start of line
```

### 2.1 `| match <pattern>`

Shows only lines matching a regex pattern. Case-sensitive by default.

```
claude@vsrx-bert> show configuration | match address | count
Count: 1135 lines
```

Argument:
```
Possible completions:
  <pattern>            Pattern to match against
```

### 2.2 `| except <pattern>`

Inverse of `match` -- shows lines that do NOT match the pattern.

```
claude@vsrx-bert> show configuration | except address | count
Count: 4635 lines
```

Argument:
```
Possible completions:
  <pattern>            Pattern to avoid
```

### 2.3 `| find <pattern>`

Scrolls output to the first occurrence of the pattern, then shows everything
from that point forward.

```
claude@vsrx-bert> show configuration | find "routing-options" | last 30
    ...
    static {
        route 0.0.0.0/0 next-table Comcast-GigabitPro.inet.0;
        ...
    }
    rib-groups { ... }
    forwarding-table { ... }
}
```

If the pattern is not found:
```
Count: 0 lines

Pattern not found
```

Argument:
```
Possible completions:
  <pattern>            Pattern to search for
```

### 2.4 `| count`

Counts the number of output lines. No arguments.

```
claude@vsrx-bert> show configuration | count
Count: 5770 lines

claude@vsrx-bert> show configuration | display set | match reth0 | count
(chains with other filters)
```

Completions after `count`:
```
Possible completions:
  <[Enter]>            Execute this command
  |                    Pipe through a command
```

### 2.5 `| last [<lines>]`

Shows the last N lines (default: all if no number given -- effectively shows
the tail of output).

```
claude@vsrx-bert> show configuration | last 20
```

Completions:
```
Possible completions:
  <[Enter]>            Execute this command
  <lines>              Number of lines from end of output to display
  |                    Pipe through a command
```

### 2.6 `| trim <columns>`

Removes the first N columns from each line. Useful for stripping indentation.

```
claude@vsrx-bert> show configuration | trim 4 | match interface | count
Count: 80 lines
```

Argument:
```
Possible completions:
  <columns>            Number of columns to trim
```

### 2.7 `| no-more`

Disables pagination (equivalent to `set cli screen-length 0` for one command).
No arguments.

```
claude@vsrx-bert> show configuration | no-more
```

Completions after `no-more`:
```
Possible completions:
  <[Enter]>            Execute this command
  |                    Pipe through a command
```

### 2.8 `| hold`

Holds output at the `--More--` prompt without auto-exiting. No arguments.

### 2.9 `| suppress-zeros`

Suppresses lines with zero values. Primarily useful for `show` commands with
counters/statistics. For configuration, it has no visible effect.

```
claude@vsrx-bert> show configuration | suppress-zeros | count
Count: 5770 lines    (same as without suppress-zeros)
```

### 2.10 `| save <filename>`

Saves output to a file or URL instead of displaying it.

```
Possible completions:
  <filename>           Output file name (or URL)
  routing-instance     Name of the routing_instance
  source-address       Local address to be used in originating the connection
```

Example: `show configuration | save /var/tmp/config.txt`

### 2.11 `| append <filename>`

Like `save`, but appends to an existing file.

```
Possible completions:
  <filename>           Output file name (or URL)
  routing-instance     Name of the routing instance
  source-address       Local address to be used in originating the connection
```

### 2.12 `| tee <filename>`

Writes to both standard output AND a file (like Unix `tee`).

```
Possible completions:
  <filename>           Output file name (or URL)
```

### 2.13 `| compare`

Compares the current configuration against a prior version.

```
Possible completions:
  <[Enter]>            Execute this command
  <filename>           Filename or URL of configuration file
  revision             Configuration revision to compare with
  rollback             Index of rollback configuration file (0..49)
  routing-instance     Name of the routing_instance
  source-address       Local address to be used in originating the connection
  |                    Pipe through a command
```

#### `| compare rollback <N>`

Compares against a specific rollback slot. The `?` completion shows timestamps:

```
claude@vsrx-bert> show configuration | compare rollback ?
Possible completions:
  0                    2026-02-15 03:20:57 PST by ps via cli
  1                    2026-02-14 19:49:02 PST by ps via cli
  2                    2026-02-12 10:56:49 PST by ps via cli
  ...
  49                   2025-11-08 18:07:58 PST by ps via synchronize
```

Output uses unified diff format with `[edit ...]` context headers:

```
claude@vsrx-bert> show configuration | compare rollback 1
[edit system login]
+    class config-viewer {
+        permissions [ view view-configuration ];
+        allow-commands "(show configuration.*)|(show version)|(show system information)";
+    }
[edit system login user claude]
-    class read-only;
+    class config-viewer;
```

`| compare` with no argument compares candidate vs. active (useful in
configuration mode).

> **Note (#6701).** The `config-viewer` class in the excerpt above is a
> **custom** definition captured from a real vSRX. `config-viewer` is a
> system-defined class in xpf (`super-user`, `operator`, `read-only`,
> `config-viewer`, `unauthorized`), and a custom definition that shadows a
> built-in is now **rejected** at strict import / commit — on xpf it was always
> inert, because `resolveClassPerms` consults the built-in table first, and the
> old silence reported a narrowing that never applied. Upgrade boot stays
> lenient and does not brick; the rejection surfaces on the next commit. This
> transcript is preserved verbatim as a record of vSRX output — do not copy the
> class definition into an xpf config. See `docs/system-login.md` ("Compatibility
> break").

---

## 3. `| display` Sub-Options

The `display` pipe filter changes the output format or adds metadata:

```
claude@vsrx-bert> show configuration | display ?
Possible completions:
  changed              Tag changes with junos:changed attribute (XML only)
  detail               Show configuration data detail
  inheritance          Show inherited configuration data and source group
  json                 Show output in JSON format
  mark-changed         Tag changes with junos:mark-changed attribute (XML only)
  max-depth            Maximum depth of configuration data
  max-version          Maximum version of configuration data
  omit                 Emit configuration statements with the 'omit' option
  rfc5952              Display IPv6 addresses as per RFC 5952 specifications
  set                  Show 'set' commands that create configuration
  xml                  Show output as XML tags
```

### 3.1 `| display set`

Converts hierarchical config into flat `set` commands. This is one of the most
commonly used display options.

```
claude@vsrx-bert> show configuration system ntp | display set
set system ntp server 2001:559:8585:ffff::4
set system ntp server 192.168.99.4
set system ntp threshold 400
set system ntp threshold action accept
```

Sub-options:
```
Possible completions:
  <[Enter]>            Execute this command
  explicit             Show 'set' commands explicitly for presence containers
  relative             Show 'set' commands relative to the current edit path
  |                    Pipe through a command
```

#### `| display set relative`

Omits the parent path prefix -- shows set commands relative to the current
section being viewed:

```
claude@vsrx-bert> show configuration system ntp | display set relative
set server 2001:559:8585:ffff::4
set server 192.168.99.4
set threshold 400
set threshold action accept
```

Compare to non-relative which includes the full path:
```
set system ntp server 2001:559:8585:ffff::4
```

#### `| display set explicit`

Same as `display set` but also includes set commands for "presence containers"
(configuration knobs that exist just by being present, with no child values).

```
claude@vsrx-bert> show configuration system ntp | display set explicit
set system ntp server 2001:559:8585:ffff::4
set system ntp server 192.168.99.4
set system ntp threshold 400
set system ntp threshold action accept
```

(Difference is more visible for sections with presence containers like
`services { application-identification; }`)

### 3.2 `| display xml`

Outputs configuration in NETCONF-style XML format:

```
claude@vsrx-bert> show configuration system ntp | display xml
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/24.4R1-S2.9/junos">
    <configuration junos:commit-seconds="1771154457"
                   junos:commit-localtime="2026-02-15 03:20:57 PST"
                   junos:commit-user="ps">
            <system>
                <ntp>
                    <server>
                        <name>2001:559:8585:ffff::4</name>
                    </server>
                    <server>
                        <name>192.168.99.4</name>
                    </server>
                    <threshold>
                        <value>400</value>
                        <action>accept</action>
                    </threshold>
                </ntp>
            </system>
    </configuration>
    <cli>
        <banner>{primary:node1}</banner>
    </cli>
</rpc-reply>
```

Sub-options:
```
Possible completions:
  <[Enter]>            Execute this command
  groups               Tag inherited data with the source group name
  interface-ranges     Tag inherited data with the source interface-range name
  no-export-path       Don't export parent path in the data
  |                    Pipe through a command
```

### 3.3 `| display json`

Outputs configuration in JSON format:

```
claude@vsrx-bert> show configuration system ntp | display json
{
    "configuration" : {
        "@" : {
            "junos:commit-seconds" : "1771154457",
            "junos:commit-localtime" : "2026-02-15 03:20:57 PST",
            "junos:commit-user" : "ps"
        },
        "system" : {
            "ntp" : {
                "server" : [
                {
                    "name" : "2001:559:8585:ffff::4"
                },
                {
                    "name" : "192.168.99.4"
                }
                ],
                "threshold" : {
                    "value" : 400,
                    "action" : "accept"
                }
            }
        }
    }
}
```

Sub-options (same as XML):
```
Possible completions:
  <[Enter]>            Execute this command
  groups               Tag inherited data with the source group name
  interface-ranges     Tag inherited data with the source interface-range name
  no-export-path       Don't export parent path in the data
  |                    Pipe through a command
```

### 3.4 `| display inheritance`

Expands configuration groups (apply-groups) inline, showing inherited data and
its source group.

**It normalizes the same way a commit does (#9743).** `FormatInheritance` and
`FormatPathInheritance` run the #8662 compact normalizer on their expansion
clone before expanding groups, because both compile cores normalize first
(`compiler.go`, and `schema_walk.go` via `normalizeCompactForValidation`).
Skipping it made the display disagree with the commit: since #9620 the
normalizer rewrites a brace-elided routing instance into its braced shape, and
group expansion binds against that shape, so

```
groups { G { routing-instances { blue instance-type forwarding description inherited; } } }
```

committed `blue` with both properties while the display showed neither — the
same group body written braced showed both. `instance-type forwarding` decides
whether the daemon creates a VRF at all, so the display was wrong exactly where
an operator checks what a group contributes.

The clone is normalized, never the caller's tree: these are read-only
operations on a candidate configuration, and normalizing is a rewrite.

Line counts show the impact of inheritance expansion:
- Base config: 5,770 lines
- With inheritance: 10,574 lines (no-comments)
- With inheritance+comments: 15,123 lines (brief)
- With inheritance+defaults: 38,324 lines

Sub-options:
```
Possible completions:
  <[Enter]>            Execute this command
  brief                Display brief output
  defaults             Show default configuration values
  no-comments          Display inherited data without comments
  terse                Display inline comments
  when                 Specify additional conditions
  |                    Pipe through a command
```

#### `| display inheritance` (default)

Shows inherited config with `##` comment annotations showing the source group:

```
claude@vsrx-bert> show configuration | display inheritance
system {
    ##
    ## 'vsrx-bert' was inherited from group 'node1'
    ##
    host-name vsrx-bert;
    ...
}
```

#### `| display inheritance no-comments`

Same expansion but without the `##` source-group comments (10,574 lines).

#### `| display inheritance brief`

Shows inline comments instead of block comments (15,123 lines).

#### `| display inheritance terse`

Also displays inline comments, same line count as no-comments (10,574 lines).

#### `| display inheritance defaults`

Additionally shows default values that are not explicitly configured (38,324
lines -- massive expansion).

### 3.5 `| display detail`

Adds YANG module metadata, package info, daemon notify lists, and range
constraints as comments:

```
claude@vsrx-bert> show configuration system ntp | display detail
##
## ntp: Network Time Protocol services
## YANG module: junos-es-conf-system@2024-01-01.yang
## alias: network-time
## Daemon notify list: : none xntpd
## package: jkernel_usp
##
##
## Name or address of server
## Daemon notify list: : hostname-cached
##
server 2001:559:8585:ffff::4;
##
## Name or address of server
## Daemon notify list: : hostname-cached
##
server 192.168.99.4;
##
## threshold: Set the maximum threshold(sec) allowed for NTP adjustment
## YANG module: junos-es-conf-system@2024-01-01.yang
## Daemon notify list: : xntpd
## The maximum value(sec) allowed for NTP adjustment
## range: 1 .. 600
## action: Select actions for NTP abnormal adjustment
## YANG module: junos-es-conf-system@2024-01-01.yang
##
threshold 400 action accept;
```

Full config with `display detail` produces 33,814 lines.

### 3.6 `| display changed`

Tags configuration elements that have changed since the last commit with
`junos:changed` XML attributes. In text mode, the output looks similar to
normal config but with change markers in XML mode.

```
claude@vsrx-bert> show configuration | display changed | count
Count: 5,801 lines
```

(Slightly more than base 5,770 due to change annotation overhead.)

### 3.7 `| display mark-changed`

Similar to `display changed` but uses the `junos:mark-changed` attribute
instead. Primarily useful in XML output mode to distinguish between changed
and unchanged nodes.

### 3.8 `| display max-depth <N>`

Truncates the config hierarchy to a maximum depth. Children beyond the
specified depth are collapsed to `{ ... }`.

#### `| display max-depth 1`

```
claude@vsrx-bert> show configuration | display max-depth 1
version 24.4R1-S2.9;
groups {
    node0 { ... }
    node1 { ... }
    default-deny-template { ... }
    ...
}
system {
    root-authentication { ... }
    commit persist-groups-inheritance;
    login { ... }
    services { ... }
    time-zone America/Los_Angeles;
    no-redirects;
    ...
}
security {
    log { ... }
    ike { ... }
    ipsec { ... }
    nat { ... }
    policies { ... }
    zones { ... }
}
interfaces {
    ge-0/0/0 { ... }
    reth0 { ... }
    reth1 { ... }
    ...
}
```

#### `| display max-depth 2`

```
claude@vsrx-bert> show configuration | display max-depth 2
groups {
    node0 {
        system { ... }
        interfaces { ... }
    }
    ...
}
system {
    login {
        class config-viewer { ... }
        user claude { ... }
        ...
    }
    services {
        ssh { ... }
        dns { ... }
        web-management { ... }
    }
    ...
}
interfaces {
    reth0 {
        description "Comcast Gigabit Pro";
        redundant-ether-options { ... }
        unit 0 { ... }
    }
    reth1 {
        description "vSRX to US-16-XG";
        vlan-tagging;
        redundant-ether-options { ... }
        unit 1 { ... }
        unit 50 { ... }
        ...
    }
    ...
}
```

This is extremely useful for getting a high-level overview of a large
configuration.

### 3.9 `| display max-version <N>`

Filters configuration to show only statements at or below a certain schema
version. Rarely used.

```
Possible completions:
  <version>            Version value
```

### 3.10 `| display omit`

Emits configuration statements that have the `omit` option set. In practice,
output looks identical to normal config for most configurations.

### 3.11 `| display rfc5952`

Formats IPv6 addresses according to RFC 5952 (canonical representation with
zero suppression). Example output:

```
claude@vsrx-bert> show configuration interfaces reth1 unit 1 | display rfc5952
family inet6 {
    address fe80::351/6;
    address fd35:1940:27:1::1/6;
    address 2001:559:8585:fff1::1/6;
    address 2602:fd41:70:fff1::1/6;
    ...
}
```

**Note:** On this version (24.4R1-S2.9), the prefix lengths appear truncated
(showing `/6` instead of `/64`). This may be a display bug in the
terminal-width handling of the CLI.

---

## 4. Pipe Chaining

Multiple pipe filters can be chained together. Each filter processes the output
of the previous one, left to right:

```
show configuration | display set | match reth0 | no-more
show configuration | display set | match reth0 | count
show configuration | trim 4 | match interface | count
show configuration | find "routing-options" | last 30
show configuration interfaces | display set | except reth1 | count
show configuration security zones | display set | match interface | count
show configuration | display set | match "security nat" | count
```

**Common chaining patterns:**

| Pattern | Purpose |
|---------|---------|
| `\| display set \| match <pat>` | Find specific set commands |
| `\| display set \| match <pat> \| count` | Count matching set commands |
| `\| display set \| except <pat> \| count` | Count non-matching set commands |
| `\| match <pat> \| count` | Count matching lines in hierarchical output |
| `\| find <pat> \| last <N>` | Show last N lines starting from pattern |
| `\| display xml \| no-more` | Full XML output without pagination |
| `\| display set \| save /var/tmp/f.txt` | Save flat config to file |
| `\| display inheritance no-comments \| display set` | Flat set with groups expanded |

---

## 5. Sub-Path + Display Combinations

You can combine sub-path narrowing with display formats:

```
# Just the interfaces section, as set commands, relative paths
show configuration interfaces | display set relative

# Security section, one level deep
show configuration security | display max-depth 1

# NTP section in JSON
show configuration system ntp | display json

# NTP section in XML
show configuration system ntp | display xml

# Specific interface, with YANG detail
show configuration interfaces reth0 | display detail
```

---

## 6. Output Line Counts by Format

For the same configuration (5,770 lines in hierarchical format):

| Format | Line Count |
|--------|-----------|
| `show configuration` (hierarchical) | 5,770 |
| `\| display set` | ~5,800+ |
| `\| display changed` | 5,801 |
| `\| display xml` | 9,901 |
| `\| display json` | 10,655 |
| `\| display inheritance no-comments` | 10,574 |
| `\| display inheritance terse` | 10,574 |
| `\| display inheritance brief` | 15,123 |
| `\| display detail` | 33,814 |
| `\| display inheritance defaults` | 38,324 |

---

## 7. Interesting Behaviors and Notes

### 7.1 Comment Annotations

Junos adds `##` comments in the output for various conditions:

- `## SECRET-DATA` -- passwords and keys are redacted
- `## 'X' is not defined` -- forward references to undefined objects
- `## Last commit: <timestamp> by <user>` -- commit header
- `inactive:` prefix -- deactivated config stanzas
- `## Warning: 'ssh-dsa' is deprecated` -- deprecation notices

**xpf secret redaction (#4051/#4060):** xpf masks secret leaf values with the
placeholder `##SECRET-DATA##` on every raw-AST DISPLAY surface — the REST
`show` / `export` / `search` endpoints and the gRPC `ShowConfig` /
`ShowCompare` / `ShowRollback` RPCs. This mirrors Junos `## SECRET-DATA` and the
typed-struct redaction on `GET /api/v1/config`. Consequently a REST `export`
(or any `show configuration` render) is **secret-redacted, not a full-fidelity
restorable backup**: re-applying it would commit `##SECRET-DATA##` as the
literal secret for every secret leaf, so xpf **rejects the placeholder on
commit-ingest** (`## SECRET-DATA` cannot round-trip). For a restorable backup use
the cleartext DR/compliance archive or `request system configuration rescue
save`; to restore, load from that archive/rescue or re-enter the secret in
cleartext. (The cleartext SSOT still backs HA config sync, the DR archive and
on-disk persistence — only the display surfaces redact.)

**xpf URL redaction (#6703):** a URL is secret-*bearing* without being a
secret — the credential lives in the userinfo, query or fragment, while the
scheme, host and path are the diagnostic payload an operator needs. So
URL-bearing leaves are **transformed**, not masked: `config.RedactURL` strips
userinfo, query and fragment (and an authority that cannot be a `host:port`,
#6609) and leaves everything else intact. A URL with no credential-bearing
component renders **unchanged**.

This applies on the typed-struct render (`GET /api/v1/config`, via
`MarshalJSON` on `DDNSProvider` and `FeedServer`) and on the raw-AST display
surfaces (`show` / `export`, via `urlLeafIndices` in `ast_redact.go`). Before
#6703 neither surface reached any redactor at all, so these leaves rendered
verbatim — including a `user:pass@` credential that `RedactURL` has stripped
since #2781.

The AST rule is keyed on the **leaf name**, so a `url` leaf inherits redaction
in every context and a future one needs no extra step. `url-template` and
`checkip-url` are distinctive enough to match unqualified; `server` and
`update-server` are gated on a `dynamic-dns` ancestor because `server` is also
an NTP leaf.

A redacted URL still looks like a valid URL, so re-applying a redacted export
would silently install a broken endpoint rather than failing loudly. xpf
therefore **rejects a URL leaf containing `<redacted>` on commit-ingest**, the
same way it rejects `##SECRET-DATA##`.

**Not covered:** a credential embedded in the URL's *hostname* or *path*
(`https://SECRET.dyn.example.com/upd`) is indistinguishable from an ordinary
hostname, so no string rule can redact it without redacting every host. Put
credentials in the userinfo or the query, where they are redacted. Tracked in
#7406.

### 7.2 `{ ... }` Collapse in max-depth

When `display max-depth` truncates children, it uses `{ ... }` notation.
Leaf values at the visible depth are shown normally:

```
reth0 {
    description "Comcast Gigabit Pro";    <-- leaf shown
    redundant-ether-options { ... }        <-- container collapsed
    unit 0 { ... }                         <-- container collapsed
}
```

### 7.3 `deactivate` in Set Output

Deactivated configuration shows as `deactivate` instead of `set`:

```
set groups node0 interfaces fxp0 unit 0 family inet address 192.168.50.210/24
deactivate groups node0 interfaces fxp0 unit 0 family inet address 192.168.50.210/24
```

### 7.4 Wildcard Groups

Configuration groups can use `<*>` wildcards that match any value:

```
groups {
    default-deny-template {
        security {
            policies {
                from-zone <*> to-zone <*> {
                    policy default-deny { ... }
                }
            }
        }
    }
}
```

**xpf implementation (#9423).** A group key of the form `<pattern>` is matched
as a glob against the instance name, so a PARTIAL wildcard selects a subset:

```
groups { uplinks { interfaces { <ge-*> { description UPLINK; } } } }
```

`*` matches any run of characters **including `/`**, which is required because
every interface name here contains one (`ge-0/0/0`). `?` is not supported and
cannot be authored — the lexer rejects it (`unexpected character: ?`). A `[...]`
character class survives lexing as part of the token and is matched literally,
so it selects nothing rather than mis-selecting.

**A pattern that matches nothing applies nothing.** Before #9423 only the exact
token `<*>` was recognised as a wildcard, so `<ge-*>` took the ordinary
container path, found no destination with that literal name, and was **adopted
as a new instance**: the compiled config gained an interface literally named
`<ge-*>` carrying the group's content, while the real interface got none of it.
That mattered beyond the template not applying — xpfd owns every interface on
the box and reconciles the configured set against the kernel, and a zone or
policy can reference the phantom by name.

The channels disagreed about it by SLOT, not by pattern: `configstore.CheckText`
refused the interfaces case only because the typed interface-name validator
rejects `<` as a name character, while a `security-zone <tr*>` phantom reached
the operator commit path with zero warnings. Recognising every `<...>`-shaped
key as a wildcard removes the phantom by construction — that branch merges into
each matching destination and never appends.

### 7.5 Rollback History

The `compare rollback` completion shows full commit history with timestamps,
user, and commit method (cli, junoscript, synchronize):

```
  0    2026-02-15 03:20:57 PST by ps via cli
  1    2026-02-14 19:49:02 PST by ps via cli
  ...
  49   2025-11-08 18:07:58 PST by ps via synchronize
```

Up to 50 rollback slots (0-49) are available.

### 7.6 Inactive Prefix

Inactive configuration elements are prefixed with `inactive:` in hierarchical
format and shown as `deactivate` commands in set format:

```
# Hierarchical:
inactive: stream promtail-syslog { ... }

# Set format:
deactivate security log stream promtail-syslog
```

### 7.7 `display set relative` vs. `display set`

`relative` removes the parent path from set commands. Particularly useful when
you are deep in a sub-path:

```
# Full path:
show configuration interfaces | display set
set interfaces reth0 description "Comcast Gigabit Pro"
set interfaces reth0 unit 0 family inet address 50.220.171.30/30 primary

# Relative:
show configuration interfaces | display set relative
set reth0 description "Comcast Gigabit Pro"
set reth0 unit 0 family inet address 50.220.171.30/30 primary
```

### 7.8 JSON Format Details

The JSON output wraps everything under `"configuration"` with commit metadata
in the `"@"` key:

```json
{
    "configuration" : {
        "@" : {
            "junos:commit-seconds" : "1771154457",
            "junos:commit-localtime" : "2026-02-15 03:20:57 PST",
            "junos:commit-user" : "ps"
        },
        ...
    }
}
```

Lists are represented as JSON arrays. For example, NTP servers become:
```json
"server" : [
    { "name" : "2001:559:8585:ffff::4" },
    { "name" : "192.168.99.4" }
]
```

### 7.9 Completion Symbol Meanings

In the `?` help output:
- `>` = container/branch node (drill deeper)
- `+` = leaf-list (accepts multiple values, e.g. `apply-groups`)
- `<[Enter]>` = command can be executed as-is
- `<pattern>`, `<filename>`, `<depth>` = required argument placeholder
- `|` = pipe to another filter

---

## 8. Summary Table: All Pipe Filters

| Filter | Arguments | Description |
|--------|-----------|-------------|
| `match` | `<pattern>` (required) | Show only lines matching regex |
| `except` | `<pattern>` (required) | Show only lines NOT matching regex |
| `find` | `<pattern>` (required) | Start output from first match |
| `count` | (none) | Count output lines |
| `last` | `[<lines>]` (optional) | Show last N lines of output |
| `trim` | `<columns>` (required) | Remove first N columns |
| `no-more` | (none) | Disable pagination |
| `hold` | (none) | Hold at --More-- prompt |
| `suppress-zeros` | (none) | Hide lines with zero values |
| `save` | `<filename>` (required) | Save output to file/URL |
| `append` | `<filename>` (required) | Append output to file/URL |
| `tee` | `<filename>` (required) | Output to screen AND file |
| `compare` | `[rollback N]`, `[filename]` | Diff against prior config |
| `display` | (sub-command required) | Change output format |

## 9. Summary Table: All Display Sub-Options

| Display Option | Arguments | Description |
|----------------|-----------|-------------|
| `set` | `[explicit]`, `[relative]` | Flat `set` command format |
| `xml` | `[groups]`, `[interface-ranges]`, `[no-export-path]` | NETCONF XML format |
| `json` | `[groups]`, `[interface-ranges]`, `[no-export-path]` | JSON format |
| `inheritance` | `[brief]`, `[defaults]`, `[no-comments]`, `[terse]`, `[when]` | Expand groups inline |
| `detail` | (none) | YANG metadata, ranges, daemon notify |
| `changed` | (none) | Tag changed elements |
| `mark-changed` | (none) | Tag with mark-changed attribute |
| `max-depth` | `<depth>` (required) | Truncate hierarchy depth |
| `max-version` | `<version>` (required) | Filter by schema version |
| `omit` | (none) | Emit statements with omit option |
| `rfc5952` | (none) | Canonical IPv6 formatting |
