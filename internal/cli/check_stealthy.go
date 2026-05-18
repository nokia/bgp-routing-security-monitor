package cli

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Verdicts for the stealthy-hijack check.
const (
	verdictClean        = "CLEAN"
	verdictStealthy     = "STEALTHY_HIJACK"
	verdictDivergence   = "DIVERGENCE"
	verdictInconclusive = "INCONCLUSIVE"
)

// protocolICMP is the IANA protocol number for ICMPv4.
const protocolICMP = 1

// stealthyRoute mirrors api.RouteResponse for CLI decoding.
type stealthyRoute struct {
	Prefix    string   `json:"prefix"`
	PeerAddr  string   `json:"peer"`
	PeerASN   uint32   `json:"peer_asn"`
	OriginASN uint32   `json:"origin_asn"`
	ASPath    []uint32 `json:"as_path"`
	NextHop   string   `json:"next_hop"`
	ROV       string   `json:"rov"`
	ROVReason string   `json:"rov_reason,omitempty"`
	ASPA      string   `json:"aspa"`
	Posture   string   `json:"posture"`
}

// stealthyPeer mirrors api.PeerResponse for CLI decoding.
type stealthyPeer struct {
	Addr       string `json:"addr"`
	ASN        uint32 `json:"asn"`
	State      string `json:"state"`
	RouteCount uint64 `json:"route_count"`
}

// probeResult is one ICMP TTL=1 probe outcome.
type probeResult struct {
	Index        int    `json:"index"`
	TimedOut     bool   `json:"timed_out"`
	RespondedIP  string `json:"responded_ip,omitempty"`
	RespondedASN uint32 `json:"responded_asn,omitempty"`
	Label        string `json:"label,omitempty"`
}

// stealthyReport is the structured output of `raven check stealthy`.
type stealthyReport struct {
	Prefix            string        `json:"prefix"`
	ProbeIP           string        `json:"probe_ip"`
	ExpectedOriginASN uint32        `json:"expected_origin_asn"`
	ExpectedPeer      string        `json:"expected_peer"`
	ExpectedPeerASN   uint32        `json:"expected_peer_asn"`
	RIBPosture        string        `json:"rib_posture"`
	RIBState          string        `json:"rib_state"`
	RIBReason         string        `json:"rib_reason"`
	Probes            []probeResult `json:"probes"`
	Verdict           string        `json:"verdict"`
	Explanation       string        `json:"explanation"`
	TrafficASN        uint32        `json:"traffic_asn,omitempty"`
	UsedTCPFallback   bool          `json:"used_tcp_fallback,omitempty"`
}

// checkCmd is the parent `raven check` command.
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "On-demand security checks (stealthy hijacks, etc.)",
}

// checkStealthyCmd is `raven check stealthy`.
var checkStealthyCmd = &cobra.Command{
	Use:   "stealthy",
	Short: "Detect stealthy BGP hijacks via control/data-plane divergence",
	Long: `Compare RAVEN's BMP RIB view against actual data-plane forwarding
using ICMP TTL=1 probes. Diverging first-hop ASN indicates a stealthy
hijack that the control-plane RIB alone cannot reveal.`,
	RunE: runCheckStealthy,
}

func init() {
	checkStealthyCmd.Flags().String("prefix", "", "Prefix to probe (required, CIDR)")
	checkStealthyCmd.Flags().Int("probe-count", 3, "Number of probes to send")
	checkStealthyCmd.Flags().Duration("timeout", 3*time.Second, "Probe timeout")
	checkStealthyCmd.Flags().String("format", "table", "Output format: table|json")
	checkStealthyCmd.Flags().String("probe-via", "", "Run probes from inside this Docker container (uses traceroute) instead of local ICMP")

	checkCmd.AddCommand(checkStealthyCmd)
}

func runCheckStealthy(cmd *cobra.Command, args []string) error {
	daemonAddr, _ := cmd.Flags().GetString("address")
	prefix, _ := cmd.Flags().GetString("prefix")
	count, _ := cmd.Flags().GetInt("probe-count")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	format, _ := cmd.Flags().GetString("format")
	probeVia, _ := cmd.Flags().GetString("probe-via")

	if prefix == "" {
		return fmt.Errorf("--prefix is required")
	}
	if count < 1 {
		count = 1
	}

	pfx, err := netip.ParsePrefix(prefix)
	if err != nil {
		return fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	if !pfx.Addr().Is4() {
		return fmt.Errorf("only IPv4 prefixes supported")
	}

	routes, err := fetchStealthyRoutes(daemonAddr, prefix)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		return fmt.Errorf("no routes found for prefix %s in BMP RIB", prefix)
	}
	best := pickBestRoute(routes)

	probeIP, err := firstHostIPv4(pfx)
	if err != nil {
		return fmt.Errorf("probe target: %w", err)
	}

	peers, err := fetchStealthyPeers(daemonAddr)
	if err != nil {
		return err
	}

	if format != "json" {
		fmt.Printf("Checking control/data-plane divergence for %s...\n\n", prefix)
		fmt.Println("Control plane (BMP/RIB):")
		fmt.Printf("  Route   : %s via AS%d (%s)\n", best.Prefix, best.OriginASN, best.Posture)
		ribState, ribReason := classifyRIB(best)
		fmt.Printf("  RIB state: %s — %s\n\n", ribState, ribReason)
		if probeVia != "" {
			fmt.Printf("Data plane probe (traceroute from %s to %s):\n", probeVia, probeIP)
		} else {
			fmt.Printf("Data plane probe (ICMP TTL=1 to %s):\n", probeIP)
		}
	}

	var (
		results  []probeResult
		usedTCP  bool
		probeErr error
	)
	if probeVia != "" {
		results, probeErr = runProbesViaContainer(probeVia, probeIP, count, timeout)
	} else {
		results, usedTCP, probeErr = runProbes(probeIP, count, timeout)
	}
	if probeErr != nil {
		return probeErr
	}
	annotateProbes(results, peers, best)

	if format != "json" {
		for _, r := range results {
			if r.TimedOut {
				fmt.Printf("  Probe %d : timeout (no TTL-exceeded received in %s)\n", r.Index, timeout)
				continue
			}
			asLabel := "unknown AS"
			if r.RespondedASN != 0 {
				asLabel = fmt.Sprintf("AS%d", r.RespondedASN)
			}
			fmt.Printf("  Probe %d : TTL-exceeded at %s (%s — %s)\n", r.Index, r.RespondedIP, asLabel, r.Label)
		}
	}

	report := stealthyReport{
		Prefix:            prefix,
		ProbeIP:           probeIP.String(),
		ExpectedOriginASN: best.OriginASN,
		ExpectedPeer:      best.PeerAddr,
		ExpectedPeerASN:   best.PeerASN,
		RIBPosture:        best.Posture,
		Probes:            results,
		UsedTCPFallback:   usedTCP,
	}
	report.RIBState, report.RIBReason = classifyRIB(best)
	report.Verdict, report.TrafficASN, report.Explanation = computeVerdict(results, best, peers)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	fmt.Println()
	printVerdictBox(report)
	return nil
}

// ─── HTTP/JSON helpers (use the existing REST API exposed by the daemon) ─────

func fetchStealthyRoutes(daemonAddr, prefix string) ([]stealthyRoute, error) {
	params := url.Values{"prefix": {prefix}}
	resp, err := apiGet(daemonAddr, "/api/v1/routes", params)
	if err != nil {
		return nil, fmt.Errorf("query routes: %w", err)
	}
	defer resp.Body.Close()

	var routes []stealthyRoute
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return nil, fmt.Errorf("decode routes: %w", err)
	}
	return routes, nil
}

func fetchStealthyPeers(daemonAddr string) ([]stealthyPeer, error) {
	resp, err := apiGet(daemonAddr, "/api/v1/peers", nil)
	if err != nil {
		return nil, fmt.Errorf("query peers: %w", err)
	}
	defer resp.Body.Close()

	var peers []stealthyPeer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, fmt.Errorf("decode peers: %w", err)
	}
	return peers, nil
}

// pickBestRoute prefers ROV=Valid; if none are Valid, returns the first entry.
func pickBestRoute(routes []stealthyRoute) stealthyRoute {
	for _, r := range routes {
		if strings.EqualFold(r.ROV, "Valid") {
			return r
		}
	}
	return routes[0]
}

func classifyRIB(r stealthyRoute) (state, reason string) {
	switch strings.ToLower(r.Posture) {
	case "origin-only", "origin-valid", "valid", "unverified", "":
		return "CLEAN", "ROV " + r.ROV + ", no path violations"
	case "origin-invalid":
		return "SUSPICIOUS", "ROV Invalid — origin AS does not match ROA"
	case "path-suspect":
		return "SUSPICIOUS", "ASPA Invalid — unauthorized provider in AS_PATH"
	default:
		return "SUSPICIOUS", "posture=" + r.Posture
	}
}

// firstHostIPv4 returns network-address + 1 for IPv4 prefixes.
func firstHostIPv4(p netip.Prefix) (netip.Addr, error) {
	if !p.Addr().Is4() {
		return netip.Addr{}, errors.New("only IPv4 supported")
	}
	masked := p.Masked()
	n := masked.Addr().As4()
	v := binary.BigEndian.Uint32(n[:])
	v++
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out), nil
}

// ─── Probing ─────────────────────────────────────────────────────────────────

func runProbes(target netip.Addr, count int, timeout time.Duration) ([]probeResult, bool, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if isPermissionErr(err) {
			results, terr := runTCPProbes(target, count, timeout)
			if terr != nil {
				return nil, true, fmt.Errorf(
					"probe failed: insufficient permissions. Run with sudo or grant CAP_NET_RAW to the raven binary.\n  (ICMP: %v) (TCP: %v)", err, terr)
			}
			return results, true, nil
		}
		return nil, false, fmt.Errorf("ICMP listen failed: %w", err)
	}
	defer conn.Close()

	pc4 := conn.IPv4PacketConn()
	if err := pc4.SetTTL(1); err != nil {
		return nil, false, fmt.Errorf("set TTL=1: %w", err)
	}

	dst := &net.IPAddr{IP: target.AsSlice()}
	results := make([]probeResult, 0, count)
	for i := 1; i <= count; i++ {
		results = append(results, sendOneICMP(conn, dst, i, timeout))
	}
	return results, false, nil
}

func sendOneICMP(conn *icmp.PacketConn, dst *net.IPAddr, seq int, timeout time.Duration) probeResult {
	id := os.Getpid() & 0xffff
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("raven-stealthy")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return probeResult{Index: seq, TimedOut: true}
	}
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return probeResult{Index: seq, TimedOut: true}
	}

	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return probeResult{Index: seq, TimedOut: true}
		}
		rm, perr := icmp.ParseMessage(protocolICMP, rb[:n])
		if perr != nil {
			if time.Now().After(deadline) {
				return probeResult{Index: seq, TimedOut: true}
			}
			continue
		}
		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded, ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeDestinationUnreachable:
			return probeResult{Index: seq, RespondedIP: peer.String()}
		}
		if time.Now().After(deadline) {
			return probeResult{Index: seq, TimedOut: true}
		}
	}
}

// runTCPProbes is a best-effort fallback when ICMP raw sockets are unavailable.
// It sets IP_TTL=1 on a TCP socket so the SYN expires at the first hop. The
// responder IP is not recoverable through standard socket APIs without
// IP_RECVERR, so probes here can only detect blackholes, not identify hops.
func runTCPProbes(target netip.Addr, count int, timeout time.Duration) ([]probeResult, error) {
	results := make([]probeResult, 0, count)
	for i := 1; i <= count; i++ {
		results = append(results, sendOneTCP(target, i, timeout))
	}
	return results, nil
}

func sendOneTCP(target netip.Addr, seq int, timeout time.Duration) probeResult {
	dialer := net.Dialer{
		Timeout: timeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	conn, err := dialer.Dial("tcp4", net.JoinHostPort(target.String(), "80"))
	if err != nil {
		return probeResult{Index: seq, TimedOut: true, Label: "tcp ttl=1 fallback — no source IP available"}
	}
	_ = conn.Close()
	return probeResult{Index: seq, TimedOut: true, Label: "tcp connected unexpectedly"}
}

// runProbesViaContainer shells out to `docker exec <container> traceroute -I -n
// -m 1 -q <count> -w <timeout>` and parses the first-hop line. Running inside
// a Containerlab node ensures probes traverse the lab's BGP topology rather
// than the WSL2 virtual gateway. BusyBox traceroute (present in FRR images)
// is the target format.
func runProbesViaContainer(container string, target netip.Addr, count int, timeout time.Duration) ([]probeResult, error) {
	timeoutSec := max(int(timeout.Seconds()), 1)
	// Bound the whole docker-exec invocation generously: BusyBox traceroute
	// can sit on `-w` per probe at the single hop we care about.
	ctxTimeout := timeout*time.Duration(count) + 5*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", container,
		"traceroute", "-I", "-n",
		"-m", "1",
		"-q", strconv.Itoa(count),
		"-w", strconv.Itoa(timeoutSec),
		target.String(),
	)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("traceroute via %s failed: %w\n%s", container, err, string(out))
	}
	return parseFirstHop(string(out), count), nil
}

// parseFirstHop extracts the responder IP and per-probe state from a BusyBox
// traceroute line of the form: " 1  10.0.3.2  0.234 ms  0.123 ms  0.156 ms".
// A "*" token marks a probe timeout. The IP carries forward across probes
// when the same hop responds; if a "*" intervenes we reset so we don't
// misattribute the next IP to an earlier probe slot.
func parseFirstHop(output string, count int) []probeResult {
	var line string
	for raw := range strings.SplitSeq(output, "\n") {
		trimmed := strings.TrimLeft(raw, " \t")
		if strings.HasPrefix(trimmed, "1 ") || strings.HasPrefix(trimmed, "1\t") {
			line = trimmed
			break
		}
	}
	results := make([]probeResult, 0, count)
	if line == "" {
		for i := 1; i <= count; i++ {
			results = append(results, probeResult{Index: i, TimedOut: true})
		}
		return results
	}

	ipRe := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	fields := strings.Fields(line)
	if len(fields) > 0 && fields[0] == "1" {
		fields = fields[1:]
	}

	probeIdx := 0
	var lastIP string
	for _, tok := range fields {
		if probeIdx >= count {
			break
		}
		switch {
		case tok == "*":
			probeIdx++
			results = append(results, probeResult{Index: probeIdx, TimedOut: true})
			lastIP = ""
		case ipRe.MatchString(tok):
			lastIP = tok
		case tok == "ms":
			probeIdx++
			if lastIP == "" {
				results = append(results, probeResult{Index: probeIdx, TimedOut: true})
			} else {
				results = append(results, probeResult{Index: probeIdx, RespondedIP: lastIP})
			}
		}
	}
	for probeIdx < count {
		probeIdx++
		results = append(results, probeResult{Index: probeIdx, TimedOut: true})
	}
	return results
}

func isPermissionErr(err error) bool {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "permission denied") || strings.Contains(m, "operation not permitted")
}

// ─── Reverse lookup + verdict ────────────────────────────────────────────────

func annotateProbes(probes []probeResult, peers []stealthyPeer, best stealthyRoute) {
	for i := range probes {
		p := &probes[i]
		if p.TimedOut || p.RespondedIP == "" {
			continue
		}
		if peer := lookupPeer(peers, p.RespondedIP); peer != nil {
			p.RespondedASN = peer.ASN
			p.Label = labelFor(peer.ASN, best)
		} else {
			p.Label = "unknown peer (not in BMP table)"
		}
	}
}

func lookupPeer(peers []stealthyPeer, ip string) *stealthyPeer {
	for i, p := range peers {
		if p.Addr == ip {
			return &peers[i]
		}
	}
	return nil
}

func labelFor(asn uint32, best stealthyRoute) string {
	switch asn {
	case best.OriginASN:
		return "expected origin"
	case best.PeerASN:
		return "expected peer"
	default:
		return "ATTACKER"
	}
}

// computeVerdict returns (verdict, trafficASN, explanation).
func computeVerdict(probes []probeResult, best stealthyRoute, peers []stealthyPeer) (string, uint32, string) {
	allTimedOut := true
	var firstResponderASN uint32
	var firstResponderIP string
	for _, p := range probes {
		if !p.TimedOut {
			allTimedOut = false
			if firstResponderIP == "" {
				firstResponderASN = p.RespondedASN
				firstResponderIP = p.RespondedIP
			}
		}
	}
	if allTimedOut {
		return verdictInconclusive, 0, "All probes timed out — cannot determine data-plane path"
	}

	// CLEAN: any probe responded with the expected ASN.
	for _, p := range probes {
		if p.TimedOut {
			continue
		}
		if p.RespondedASN != 0 && (p.RespondedASN == best.OriginASN || p.RespondedASN == best.PeerASN) {
			return verdictClean, p.RespondedASN, "Data-plane first hop matches BMP RIB"
		}
	}

	// STEALTHY HIJACK DETECTED: responder is a known BMP peer but mismatched.
	if firstResponderASN != 0 && lookupPeer(peers, firstResponderIP) != nil {
		return verdictStealthy, firstResponderASN, "control/data-plane divergence"
	}

	// DIVERGENCE: responder not in BMP, so we can't be sure who they are.
	return verdictDivergence, firstResponderASN,
		"Data-plane first hop is not a known BMP peer — divergence unconfirmed"
}

// ─── Rendering ───────────────────────────────────────────────────────────────

func printVerdictBox(r stealthyReport) {
	color := ansiReset
	switch r.Verdict {
	case verdictStealthy:
		color = ansiRed + ansiBold
	case verdictClean:
		color = "\033[0;32m" // green
	case verdictDivergence:
		color = ansiAmber
	case verdictInconclusive:
		color = "\033[0;90m" // grey
	}

	// Display label diverges from the JSON verdict value: the latter is a
	// stable machine-readable token, the former is a human banner.
	displayVerdict := r.Verdict
	if r.Verdict == verdictStealthy {
		displayVerdict = "STEALTHY HIJACK DETECTED"
	}
	line1 := fmt.Sprintf("%s: %s", displayVerdict, r.Explanation)

	rib := fmt.Sprintf("AS%d", r.ExpectedOriginASN)
	traffic := "?"
	if r.TrafficASN != 0 {
		traffic = fmt.Sprintf("AS%d", r.TrafficASN)
	}
	line2 := fmt.Sprintf("RIB says: %s │ Traffic goes to: %s", rib, traffic)

	width := max(len(line1), len(line2), 46)
	bar := strings.Repeat("═", width+2)
	fmt.Printf("%s╔%s╗%s\n", color, bar, ansiReset)
	fmt.Printf("%s║ %-*s ║%s\n", color, width, line1, ansiReset)
	fmt.Printf("%s║ %-*s ║%s\n", color, width, line2, ansiReset)
	fmt.Printf("%s╚%s╝%s\n", color, bar, ansiReset)
}
