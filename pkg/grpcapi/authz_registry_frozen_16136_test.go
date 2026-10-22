package grpcapi

import "github.com/psaab/xpf/pkg/config"

// #16136 FROZEN migration contract — the independent expectation the
// registry census grades against. This file is test data, captured
// from the PRE-REGISTRY literal tables at the PR merge base
// ba55ef764aaed0b552bae09d1f18286a3a49013e:
//
//   - ShowText commands: pkg/cmdtree/showtext_topic.go
//     (var showTextTopicCommand, 135 keys at that commit);
//   - ShowText prices: pkg/grpcapi/authz_methods.go
//     (showTextViewTopics / showTextElevatedTopics at that commit);
//   - SystemAction prices: pkg/grpcapi/authz_methods.go
//     (systemActionPermissions, 23 verbs);
//   - SystemAction commands: pkg/authz/system_action_commands_9952.go
//     (SystemActionVerbCommand, 23 verbs).
//
// It is a literal in this file on purpose: it MUST NOT be generated
// from pkg/optopic at test runtime, or the census becomes the
// registry grading itself. Changing a row here is a reviewed
// migration-contract change, not a sync step: if a future topic or
// verb is added, its row is added here by hand with its emitting
// command as the justification, exactly as the sole delta below.
//
// SOLE DELTA from the captured tables: "applications:" (PermView,
// `show security applications`). At the merge base the dispatcher
// already served `applications:<name>` (server_show.go prefix arm,
// #15207 filtered render) but no pre-registry table priced or
// commanded it — that absence is the census hole #16136 exists to
// close. Its price/command are pinned from the emitting surface,
// not from the registry: the console `show security applications`
// family (pkg/cli/cli_show_security_dispatch.go) is a `show`
// command, which pkg/cli/permissions.go charges at PermView, and
// the bare `applications` row captured above already maps that
// family to `show security applications`.

type frozenOpExpectation16136 struct {
	permission config.LoginClassPermission
	command    string
}

var frozenShowText16136 = map[string]frozenOpExpectation16136{
	"address-book":                      {permission: config.PermView, command: "show security address-book"},
	"alarms":                            {permission: config.PermView, command: "show system alarms"},
	"alg":                               {permission: config.PermView, command: "show security alg"},
	"application-identification-status": {permission: config.PermView, command: "show services application-identification status"},
	"applications":                      {permission: config.PermView, command: "show security applications"},
	"backup-router":                     {permission: config.PermView, command: "show system backup-router"},
	"bfd-peers":                         {permission: config.PermView, command: "show protocols bfd peers"},
	"bootstrap-import":                  {permission: config.PermView, command: "show system bootstrap-import"},
	"buffers":                           {permission: config.PermView, command: "show system buffers"},
	"buffers-detail":                    {permission: config.PermView, command: "show system buffers detail"},
	"chassis":                           {permission: config.PermView, command: "show chassis"},
	"chassis-cluster":                   {permission: config.PermView, command: "show chassis cluster"},
	"chassis-cluster-control-plane-statistics": {permission: config.PermView, command: "show chassis cluster control-plane statistics"},
	"chassis-cluster-data-plane-fairness":      {permission: config.PermView, command: "show chassis cluster data-plane fairness"},
	"chassis-cluster-data-plane-flows":         {permission: config.PermView, command: "show chassis cluster data-plane flows"},
	"chassis-cluster-data-plane-interfaces":    {permission: config.PermView, command: "show chassis cluster data-plane interfaces"},
	"chassis-cluster-data-plane-statistics":    {permission: config.PermView, command: "show chassis cluster data-plane statistics"},
	"chassis-cluster-fabric-statistics":        {permission: config.PermView, command: "show chassis cluster fabric statistics"},
	"chassis-cluster-fence-status":             {permission: config.PermView, command: "show chassis cluster fence-status"},
	"chassis-cluster-information":              {permission: config.PermView, command: "show chassis cluster information"},
	"chassis-cluster-interfaces":               {permission: config.PermView, command: "show chassis cluster interfaces"},
	"chassis-cluster-ip-monitoring-status":     {permission: config.PermView, command: "show chassis cluster ip-monitoring status"},
	"chassis-cluster-statistics":               {permission: config.PermView, command: "show chassis cluster statistics"},
	"chassis-cluster-status":                   {permission: config.PermView, command: "show chassis cluster status"},
	"chassis-device-map":                       {permission: config.PermView, command: "show chassis device-map"},
	"chassis-device-map-candidates":            {permission: config.PermView, command: "show chassis device-map candidates"},
	"chassis-environment":                      {permission: config.PermView, command: "show chassis environment"},
	"chassis-forwarding":                       {permission: config.PermView, command: "show chassis forwarding"},
	"chassis-hardware":                         {permission: config.PermView, command: "show chassis hardware"},
	"class-of-service":                         {permission: config.PermView, command: "show class-of-service interface"},
	"class-of-service:":                        {permission: config.PermView, command: "show class-of-service interface"},
	"commit-history":                           {permission: config.PermView, command: "show system commit history"},
	"core-dumps":                               {permission: config.PermView, command: "show system core-dumps"},
	"cos-classifier":                           {permission: config.PermView, command: "show class-of-service classifier"},
	"cos-classifier:":                          {permission: config.PermView, command: "show class-of-service classifier"},
	"cos-forwarding-class":                     {permission: config.PermView, command: "show class-of-service forwarding-class"},
	"cos-rewrite-rule":                         {permission: config.PermView, command: "show class-of-service rewrite-rule"},
	"cos-rewrite-rule:":                        {permission: config.PermView, command: "show class-of-service rewrite-rule"},
	"cos-scheduler-map":                        {permission: config.PermView, command: "show class-of-service scheduler-map"},
	"cos-scheduler-map:":                       {permission: config.PermView, command: "show class-of-service scheduler-map"},
	"dhcp-relay":                               {permission: config.PermView, command: "show dhcp-relay"},
	"dhcp-server":                              {permission: config.PermView, command: "show dhcp-server"},
	"dhcp-server-detail":                       {permission: config.PermView, command: "show dhcp-server detail"},
	"dhcp-server-dynamic-dns":                  {permission: config.PermView, command: "show dhcp-server dynamic-dns"},
	"dhcp-server-dynamic-dns-detail":           {permission: config.PermView, command: "show dhcp-server dynamic-dns detail"},
	"dynamic-address":                          {permission: config.PermView, command: "show security dynamic-address"},
	"event-options":                            {permission: config.PermView, command: "show event-options"},
	"firewall":                                 {permission: config.PermView, command: "show firewall"},
	"firewall-effective":                       {permission: config.PermView, command: "show firewall effective"},
	"firewall-effective-filter:":               {permission: config.PermView, command: "show firewall filter"},
	"firewall-effective:":                      {permission: config.PermView, command: "show firewall effective"},
	"firewall-filter:":                         {permission: config.PermView, command: "show firewall filter"},
	"flow-monitoring":                          {permission: config.PermView, command: "show flow-monitoring"},
	"flow-monitoring-statistics":               {permission: config.PermView, command: "show flow-monitoring statistics"},
	"flow-statistics":                          {permission: config.PermView, command: "show security flow statistics"},
	"flow-timeouts":                            {permission: config.PermView, command: "show security flow"},
	"flow-traceoptions":                        {permission: config.PermView, command: "show security flow traceoptions"},
	"forwarding-options":                       {permission: config.PermView, command: "show forwarding-options"},
	"forwarding-options-port-mirroring":        {permission: config.PermView, command: "show forwarding-options port-mirroring"},
	"ike":                                      {permission: config.PermView, command: "show security ike"},
	"interfaces-detail":                        {permission: config.PermView, command: "show interfaces detail"},
	"interfaces-extensive":                     {permission: config.PermView, command: "show interfaces extensive"},
	"interfaces-queue":                         {permission: config.PermView, command: "show interfaces queue"},
	"interfaces-queue:":                        {permission: config.PermView, command: "show interfaces queue"},
	"interfaces-statistics":                    {permission: config.PermView, command: "show interfaces statistics"},
	"internet-options":                         {permission: config.PermView, command: "show system internet-options"},
	"ipsec-statistics":                         {permission: config.PermView, command: "show security ipsec statistics"},
	"ipv6-router-advertisement":                {permission: config.PermView, command: "show ipv6 router-advertisement"},
	"kernel-upgrade":                           {permission: config.PermView, command: "show system kernel-upgrade"},
	"license":                                  {permission: config.PermView, command: "show system license"},
	"lldp":                                     {permission: config.PermView, command: "show lldp"},
	"lldp-neighbors":                           {permission: config.PermView, command: "show lldp neighbors"},
	"log":                                      {permission: config.PermView, command: "show log"},
	"log:":                                     {permission: config.PermView, command: "show log"},
	"login":                                    {permission: config.PermView, command: "show system login"},
	"monitor-security-flow":                    {permission: config.PermView, command: "show monitor security flow"},
	"nat-dest-rule-detail":                     {permission: config.PermView, command: "show security nat destination rule detail"},
	"nat-nptv6":                                {permission: config.PermView, command: "show security nat nptv6"},
	"nat-source-rule-detail":                   {permission: config.PermView, command: "show security nat source rule detail"},
	"nat-static":                               {permission: config.PermView, command: "show security nat static"},
	"nat-static-rule":                          {permission: config.PermView, command: "show security nat static rule"},
	"nat-static-rule-detail":                   {permission: config.PermView, command: "show security nat static rule detail"},
	"nat64":                                    {permission: config.PermView, command: "show security nat nat64"},
	"ntp":                                      {permission: config.PermView, command: "show system ntp"},
	"persistent-nat":                           {permission: config.PermView, command: "show security nat source persistent-nat-table"},
	"persistent-nat-detail":                    {permission: config.PermView, command: "show security nat source persistent-nat-table detail"},
	"policies-check":                           {permission: config.PermControl, command: "request security policies check"},
	"policies-detail":                          {permission: config.PermView, command: "show security policies detail"},
	"policies-hit-count":                       {permission: config.PermView, command: "show security policies hit-count"},
	"policy-options":                           {permission: config.PermView, command: "show policy-options"},
	"root-authentication":                      {permission: config.PermView, command: "show system root-authentication"},
	"route-all":                                {permission: config.PermView, command: "show route"},
	"route-detail":                             {permission: config.PermView, command: "show route detail"},
	"route-fib":                                {permission: config.PermView, command: "show route fib"},
	"route-instance":                           {permission: config.PermView, command: "show route instance"},
	"route-map":                                {permission: config.PermView, command: "show route-map"},
	"route-prefix:":                            {permission: config.PermView, command: "show route"},
	"route-protocol:":                          {permission: config.PermView, command: "show route protocol"},
	"route-summary":                            {permission: config.PermView, command: "show route summary"},
	"route-table:":                             {permission: config.PermView, command: "show route table"},
	"route-terse":                              {permission: config.PermView, command: "show route terse"},
	"routing-instances":                        {permission: config.PermView, command: "show routing-instances"},
	"routing-instances-detail":                 {permission: config.PermView, command: "show routing-instances detail"},
	"routing-options":                          {permission: config.PermView, command: "show routing-options"},
	"rpm":                                      {permission: config.PermView, command: "show services rpm"},
	"schedulers":                               {permission: config.PermView, command: "show schedulers"},
	"screen":                                   {permission: config.PermView, command: "show security screen"},
	"screen-ids-option-detail:":                {permission: config.PermView, command: "show security screen ids-option"},
	"screen-ids-option:":                       {permission: config.PermView, command: "show security screen ids-option"},
	"screen-statistics-all":                    {permission: config.PermView, command: "show security screen statistics"},
	"screen-statistics:":                       {permission: config.PermView, command: "show security screen statistics zone"},
	"security-alarms":                          {permission: config.PermView, command: "show security alarms"},
	"security-alarms-detail":                   {permission: config.PermView, command: "show security alarms detail"},
	"security-log":                             {permission: config.PermView, command: "show security log"},
	"services-dynamic-dns":                     {permission: config.PermView, command: "show services dynamic-dns"},
	"services-dynamic-dns-detail":              {permission: config.PermView, command: "show services dynamic-dns detail"},
	"services-ip-monitoring-status":            {permission: config.PermView, command: "show services ip-monitoring status"},
	"sessions-top:bytes":                       {permission: config.PermView, command: "show security flow session sort-by bytes"},
	"sessions-top:packets":                     {permission: config.PermView, command: "show security flow session sort-by packets"},
	"snmp":                                     {permission: config.PermView, command: "show snmp"},
	"snmp-v3":                                  {permission: config.PermView, command: "show snmp v3"},
	"storage":                                  {permission: config.PermView, command: "show system storage"},
	"system-services":                          {permission: config.PermView, command: "show system services"},
	"system-syslog":                            {permission: config.PermView, command: "show system syslog"},
	"task":                                     {permission: config.PermView, command: "show task"},
	"test-policy:":                             {permission: config.PermControl, command: "test policy"},
	"test-routing:":                            {permission: config.PermControl, command: "test routing"},
	"test-zone:":                               {permission: config.PermControl, command: "test security-zone"},
	"tunnels":                                  {permission: config.PermView, command: "show interfaces tunnel"},
	"version":                                  {permission: config.PermView, command: "show version"},
	"vlans":                                    {permission: config.PermView, command: "show vlans"},
	"wireguard":                                {permission: config.PermView, command: "show security wireguard"},
	"wireguard-detail":                         {permission: config.PermView, command: "show security wireguard detail"},
	"wireguard-public-key":                     {permission: config.PermView, command: "show security wireguard public-key"},
	"zones-detail":                             {permission: config.PermView, command: "show security zones detail"},
	"applications:":                            {permission: config.PermView, command: "show security applications"}, // sole delta; see header
}

var frozenSystemAction16136 = map[string]frozenOpExpectation16136{
	"bgp-clear":                   {permission: config.PermControl, command: "request protocols bgp clear"},
	"clear-arp":                   {permission: config.PermClear, command: "clear arp"},
	"clear-config-lock":           {permission: config.PermClear, command: "clear system config-lock"},
	"clear-firewall-counters":     {permission: config.PermClear, command: "clear firewall all"},
	"clear-interfaces-statistics": {permission: config.PermClear, command: "clear interfaces statistics"},
	"clear-ipv6-neighbors":        {permission: config.PermClear, command: "clear ipv6 neighbors"},
	"clear-nat-counters":          {permission: config.PermClear, command: "clear security nat statistics"},
	"clear-persistent-nat":        {permission: config.PermClear, command: "clear security nat source persistent-nat-table"},
	"clear-policy-counters":       {permission: config.PermClear, command: "clear security policies hit-count"},
	"cluster-rejoin":              {permission: config.PermMaint, command: "request chassis cluster failover"},
	"dhcp-renew":                  {permission: config.PermControl, command: "request dhcp renew"},
	"dynamic-address-shrink-ack":  {permission: config.PermConfig, command: "request security dynamic-address acknowledge-shrink"},
	"dynamic-dns-check":           {permission: config.PermControl, command: "request system dynamic-dns check"},
	"dynamic-dns-update":          {permission: config.PermControl, command: "request system dynamic-dns update"},
	"halt":                        {permission: config.PermMaint, command: "request system halt"},
	"in-service-upgrade":          {permission: config.PermMaint, command: "request system software in-service-upgrade"},
	"ipsec-sa-clear":              {permission: config.PermControl, command: "request security ipsec sa clear"},
	"ospf-clear":                  {permission: config.PermControl, command: "request protocols ospf clear"},
	"power-off":                   {permission: config.PermMaint, command: "request system power-off"},
	"reboot":                      {permission: config.PermMaint, command: "request system reboot"},
	"rescue-delete":               {permission: config.PermControl, command: "request system configuration rescue delete"},
	"rescue-save":                 {permission: config.PermControl, command: "request system configuration rescue save"},
	"zeroize":                     {permission: config.PermMaint, command: "request system zeroize"},
}
