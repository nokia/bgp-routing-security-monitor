package bmp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Listener accepts BMP connections from routers and processes messages.
type Listener struct {
	addr       string
	tlsCfg     *tls.Config // nil = plain TCP
	log        *slog.Logger
	routeCh    chan<- types.Route
	withdrawCh chan<- types.Withdrawal
	peerMu     sync.RWMutex
	peers      map[PeerKey]*Peer
	routerMu   sync.RWMutex
	routers    map[netip.Addr]string
	listener   net.Listener
}

// NewListener creates a BMP listener that sends parsed routes to routeCh.
// If tlsCfg is non-nil, the listener accepts TLS connections; otherwise plain TCP.
func NewListener(addr string, tlsCfg *tls.Config, routeCh chan<- types.Route, withdrawCh chan<- types.Withdrawal, log *slog.Logger) *Listener {
	return &Listener{
		addr:       addr,
		tlsCfg:     tlsCfg,
		log:        log.With("subsystem", "bmp"),
		routeCh:    routeCh,
		withdrawCh: withdrawCh,
		peers:      make(map[PeerKey]*Peer),
		routers:    make(map[netip.Addr]string),
	}
}

// BuildTLSConfig assembles a server-side *tls.Config from the operator-supplied
// paths. Cert and Key are required (BMP TLS is server auth). If CA is present,
// mutual TLS is enabled and client certs are required.
func BuildTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("BMP TLS config is nil")
	}
	if cfg.Cert == "" || cfg.Key == "" {
		return nil, fmt.Errorf("BMP TLS requires both cert and key paths")
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load BMP TLS keypair: %w", err)
	}

	out := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   cfg.TLSMinVersion(),
	}

	if cfg.CA != "" {
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("read BMP TLS CA %q: %w", cfg.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse BMP TLS CA %q: no PEM certificates found", cfg.CA)
		}
		out.ClientCAs = pool
		out.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return out, nil
}

// Start begins listening for BMP connections. Blocks until ctx is cancelled.
func (l *Listener) Start(ctx context.Context) error {
	var err error
	transport := "tcp"
	if l.tlsCfg != nil {
		l.listener, err = tls.Listen("tcp", l.addr, l.tlsCfg)
		transport = "tls"
	} else {
		l.listener, err = net.Listen("tcp", l.addr)
	}
	if err != nil {
		return fmt.Errorf("BMP listen on %s: %w", l.addr, err)
	}
	l.log.Info("BMP listener started", "addr", l.addr, "transport", transport)

	go func() {
		<-ctx.Done()
		l.listener.Close()
	}()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutting down
			}
			l.log.Error("BMP accept error", "error", err)
			continue
		}

		remoteAddr := conn.RemoteAddr().String()
		l.log.Info("BMP session accepted", "remote", remoteAddr)

		// One goroutine per BMP session (per the architecture doc)
		go l.handleSession(ctx, conn)
	}
}

// GetPeers returns a snapshot of all known peers.
func (l *Listener) GetPeers() []Peer {
	l.peerMu.RLock()
	defer l.peerMu.RUnlock()

	result := make([]Peer, 0, len(l.peers))
	for _, p := range l.peers {
		result = append(result, *p)
	}
	return result
}

// GetRouterStates returns the current BMP session state for every router
// that has sent an Initiation message. Only up sessions appear (1=up);
// sessions that disconnected are removed from the map by handleSession.
func (l *Listener) GetRouterStates() map[string]int64 {
	l.routerMu.RLock()
	defer l.routerMu.RUnlock()

	result := make(map[string]int64, len(l.routers))
	for _, sysName := range l.routers {
		result[sysName] = 1
	}
	return result
}

// handleSession processes a single BMP session (one TCP connection = one router).
func (l *Listener) handleSession(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	routerAddr, _ := netip.ParseAddrPort(remoteAddr)
	sessionLog := l.log.With("router", remoteAddr)
	sessionLog.Info("BMP session started")

	defer func() {
		sessionLog.Info("BMP session ended")
		// Withdraw all routes from all peers of this router
		l.peerMu.RLock()
		var peerAddrs []netip.Addr
		for key := range l.peers {
			if key.RouterAddr == routerAddr.Addr() {
				peerAddrs = append(peerAddrs, key.PeerAddr)
			}
		}
		l.peerMu.RUnlock()

		for _, peerAddr := range peerAddrs {
			select {
			case l.withdrawCh <- types.Withdrawal{
				PeerAddr:    peerAddr,
				WithdrawAll: true,
			}:
			default:
			}
		}

		// Clean up peers for this router
		l.peerMu.Lock()
		for key := range l.peers {
			if key.RouterAddr == routerAddr.Addr() {
				delete(l.peers, key)
			}
		}
		l.peerMu.Unlock()

		// Clean up router state
		l.routerMu.Lock()
		sysName := l.routers[routerAddr.Addr()]
		delete(l.routers, routerAddr.Addr())
		l.routerMu.Unlock()
		if sysName == "" {
			sysName = remoteAddr
		}
		metrics.BMPSessionState.WithLabelValues(sysName).Set(0)
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		hdrBuf := make([]byte, CommonHeaderLen)
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			sessionLog.Error("failed to read BMP header", "error", err)
			return
		}
		hdr, err := ParseCommonHeader(hdrBuf)
		if err != nil {
			sessionLog.Error("invalid BMP header", "error", err)
			return
		}
		bodyLen := int(hdr.Length) - CommonHeaderLen
		if bodyLen < 0 {
			sessionLog.Error("invalid BMP message length", "length", hdr.Length)
			return
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(conn, body); err != nil {
				sessionLog.Error("failed to read BMP body", "error", err)
				return
			}
		}
		l.processMessage(ctx, sessionLog, routerAddr.Addr(), hdr, body)
	}
}

// processMessage dispatches a parsed BMP message by type.
func (l *Listener) processMessage(
	ctx context.Context,
	log *slog.Logger,
	routerAddr netip.Addr,
	hdr BMPCommonHeader,
	body []byte,
) {
	switch hdr.MsgType {
	case MsgTypeInitiation:
		init, err := ParseInitiation(body)
		if err != nil {
			log.Error("failed to parse initiation", "error", err)
			return
		}
		// Store sysName for use as Prometheus label
		sysName := init.SysName
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.routerMu.Lock()
		l.routers[routerAddr] = sysName
		l.routerMu.Unlock()
		metrics.BMPSessionState.WithLabelValues(sysName).Set(1)
		log.Info("BMP initiation", "sysName", sysName, "sysDescr", init.SysDescr)

	case MsgTypePeerUp:
		pu, err := ParsePeerUp(body)
		if err != nil {
			log.Error("failed to parse peer up", "error", err)
			return
		}
		key := PeerKey{RouterAddr: routerAddr, PeerAddr: pu.PerPeer.PeerAddr}
		l.routerMu.RLock()
		sysName := l.routers[routerAddr]
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.peerMu.Lock()
		l.peers[key] = &Peer{
			Addr:     pu.PerPeer.PeerAddr,
			ASN:      pu.PerPeer.PeerASN,
			LocalASN: pu.LocalASN,
			RouterID: pu.PerPeer.PeerBGPID,
			SysName:  sysName,
			State:    "up",
			UpSince:  time.Now(),
			LastMsg:  time.Now(),
		}
		l.peerMu.Unlock()
		metrics.BMPPeerState.WithLabelValues(sysName, pu.PerPeer.PeerAddr.String()).Set(1)
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "peer_up").Inc()
		log.Info("BMP peer up",
			"peer", pu.PerPeer.PeerAddr,
			"asn", pu.PerPeer.PeerASN,
			"local_asn", pu.LocalASN,
			"router_id", pu.PerPeer.PeerBGPID,
		)

	case MsgTypePeerDown:
		pd, err := ParsePeerDown(body)
		if err != nil {
			log.Error("failed to parse peer down", "error", err)
			return
		}
		key := PeerKey{RouterAddr: routerAddr, PeerAddr: pd.PerPeer.PeerAddr}
		l.routerMu.RLock()
		sysName := l.routers[routerAddr]
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.peerMu.Lock()
		if p, ok := l.peers[key]; ok {
			p.State = "down"
			p.LastMsg = time.Now()
		}
		l.peerMu.Unlock()
		metrics.BMPPeerState.WithLabelValues(sysName, pd.PerPeer.PeerAddr.String()).Set(0)
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "peer_down").Inc()
		log.Info("BMP peer down", "peer", pd.PerPeer.PeerAddr, "reason", pd.Reason)
		// Signal withdrawal of all routes from this peer
		select {
		case l.withdrawCh <- types.Withdrawal{
			PeerAddr:    pd.PerPeer.PeerAddr,
			WithdrawAll: true,
		}:
		default:
		}

	case MsgTypeRouteMonitoring:
		l.routerMu.RLock()
		sysName := l.routers[routerAddr]
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "route_monitoring").Inc()

		rm, err := ParseRouteMonitoring(body)
		if err != nil {
			log.Debug("failed to parse route monitoring", "error", err)
			return
		}
		routes, withdrawals, err := l.parseRoutes(rm, routerAddr)
		if err != nil {
			log.Debug("failed to parse BGP UPDATE", "error", err)
			return
		}
		for _, r := range routes {
			select {
			case l.routeCh <- r:
			case <-ctx.Done():
				return
			}
		}
		for _, w := range withdrawals {
			select {
			case l.withdrawCh <- w:
			case <-ctx.Done():
				return
			}
		}

		// Update peer last-message time
		key := PeerKey{RouterAddr: routerAddr, PeerAddr: rm.PerPeer.PeerAddr}
		l.peerMu.Lock()
		if p, ok := l.peers[key]; ok {
			p.LastMsg = time.Now()
			p.RouteCount += uint64(len(routes))
		}
		l.peerMu.Unlock()

	case MsgTypeStatisticsReport:
		_, err := ParseStatsReport(body)
		if err != nil {
			log.Debug("failed to parse stats report", "error", err)
			return
		}
		// TODO: expose as Prometheus metrics

	case MsgTypeTermination:
		log.Info("BMP termination received")
		return

	default:
		log.Debug("unknown BMP message type", "type", hdr.MsgType)
	}
}

// parseRoutes converts a BMP Route Monitoring message into internal Route objects
// using GoBGP's BGP UPDATE parser.
func (l *Listener) parseRoutes(rm BMPRouteMonitoring, routerAddr netip.Addr) ([]types.Route, []types.Withdrawal, error) {
	bgpData := rm.BGPUpdateData

	// BGP message: 16-byte marker + 2-byte length + 1-byte type + body
	if len(bgpData) < 19 {
		return nil, nil, fmt.Errorf("BGP message too short: %d", len(bgpData))
	}

	// Verify BGP message type is UPDATE (type 2)
	bgpMsgType := bgpData[18]
	if bgpMsgType != 2 {
		// Not an UPDATE — could be KEEPALIVE, NOTIFICATION, etc. in BMP Route Monitoring
		return nil, nil, nil
	}

	bgpLength := binary.BigEndian.Uint16(bgpData[16:18])
	if int(bgpLength) > len(bgpData) {
		return nil, nil, fmt.Errorf("BGP length %d exceeds data %d", bgpLength, len(bgpData))
	}

	// Parse the BGP UPDATE body (after the 19-byte header)
	updateBody := bgpData[19:bgpLength]

	// Look up the monitoring router's own AS on this session, learned from
	// the Peer Up message's Sent OPEN (see ParsePeerUp). Needed for ASPA's
	// final path[0]-vs-local-AS check.
	key := PeerKey{RouterAddr: routerAddr, PeerAddr: rm.PerPeer.PeerAddr}
	l.peerMu.RLock()
	var localASN uint32
	if p, ok := l.peers[key]; ok {
		localASN = p.LocalASN
	}
	l.peerMu.RUnlock()

	routes, withdrawals, err := parseBGPUpdate(updateBody, rm.PerPeer, localASN)
	if err != nil {
		return nil, nil, fmt.Errorf("parse BGP UPDATE: %w", err)
	}
	return routes, withdrawals, nil
}

// parseBGPUpdate extracts routes from a BGP UPDATE message body.
//
// Handles both IPv4 NLRI (carried directly in the UPDATE body) and IPv6 NLRI
// (carried inside MP_REACH_NLRI / MP_UNREACH_NLRI path attributes per RFC 4760).
func parseBGPUpdate(data []byte, pph BMPPerPeerHeader, localASN uint32) ([]types.Route, []types.Withdrawal, error) {
	if len(data) < 4 {
		return nil, nil, nil
	}
	ribType := types.AdjRIBInPre
	if pph.IsPostPolicy() {
		ribType = types.AdjRIBInPost
	}

	// Parse IPv4 withdrawn prefixes (top of UPDATE body)
	withdrawnLen := binary.BigEndian.Uint16(data[0:2])
	var withdrawals []types.Withdrawal
	if withdrawnLen > 0 {
		v4Withdrawals := parseNLRI(data[2:2+int(withdrawnLen)], 4)
		for _, p := range v4Withdrawals {
			withdrawals = append(withdrawals, types.Withdrawal{
				PeerAddr: pph.PeerAddr,
				Prefix:   p,
				RIBType:  ribType,
			})
		}
	}

	offset := 2 + int(withdrawnLen)
	if offset+2 > len(data) {
		return nil, withdrawals, nil
	}

	// Total Path Attribute Length (2 bytes)
	pathAttrLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	pathAttrEnd := offset + int(pathAttrLen)

	if pathAttrEnd > len(data) {
		return nil, nil, fmt.Errorf("path attributes overflow: %d > %d", pathAttrEnd, len(data))
	}

	// Parse path attributes (extracts AS_PATH etc and the raw MP_REACH/MP_UNREACH bytes)
	attrs := parsePathAttributes(data[offset:pathAttrEnd])
	offset = pathAttrEnd

	// Parse IPv4 NLRI (remaining bytes after path attributes)
	var routes []types.Route
	v4Prefixes := parseNLRI(data[offset:], 4)
	for _, prefix := range v4Prefixes {
		routes = append(routes, makeRoute(prefix, attrs.nextHop, pph, attrs, ribType, localASN))
	}

	// Parse IPv6 NLRI carried inside MP_REACH_NLRI (AFI=2, SAFI=1)
	if len(attrs.mpReach) > 0 {
		nh, prefixes := parseMPReachNLRI(attrs.mpReach)
		for _, p := range prefixes {
			routes = append(routes, makeRoute(p, nh, pph, attrs, ribType, localASN))
		}
	}

	// Parse IPv6 withdrawals carried inside MP_UNREACH_NLRI (AFI=2, SAFI=1)
	if len(attrs.mpUnreach) > 0 {
		prefixes := parseMPUnreachNLRI(attrs.mpUnreach)
		for _, p := range prefixes {
			withdrawals = append(withdrawals, types.Withdrawal{
				PeerAddr: pph.PeerAddr,
				Prefix:   p,
				RIBType:  ribType,
			})
		}
	}

	return routes, withdrawals, nil
}

// makeRoute constructs a types.Route from a prefix, next hop, and extracted path attributes.
func makeRoute(prefix netip.Prefix, nextHop netip.Addr, pph BMPPerPeerHeader, attrs pathAttrs, ribType types.RIBType, localASN uint32) types.Route {
	return types.Route{
		Timestamp:        pph.Timestamp,
		PeerAddr:         pph.PeerAddr,
		PeerASN:          pph.PeerASN,
		LocalASN:         localASN,
		RouterID:         pph.PeerBGPID,
		Prefix:           prefix,
		ASPath:           attrs.asPath,
		ASPathRaw:        attrs.asPathRaw,
		Origin:           types.OriginType(attrs.origin),
		NextHop:          nextHop,
		Communities:      attrs.communities,
		LargeCommunities: attrs.largeCommunities,
		RIBType:          ribType,
	}
}

// parseNLRI iterates length-prefixed NLRI entries. addrLen is 4 for IPv4 NLRI
// or 16 for IPv6 NLRI; it bounds how many bytes are read into the address slot.
func parseNLRI(data []byte, addrLen int) []netip.Prefix {
	var out []netip.Prefix
	off := 0
	maxBits := addrLen * 8
	for off < len(data) {
		pLen := int(data[off])
		off++
		if pLen > maxBits {
			break
		}
		pBytes := (pLen + 7) / 8
		if off+pBytes > len(data) {
			break
		}
		buf := make([]byte, addrLen)
		copy(buf, data[off:off+pBytes])
		off += pBytes
		addr, ok := netip.AddrFromSlice(buf)
		if !ok {
			continue
		}
		out = append(out, netip.PrefixFrom(addr.Unmap(), pLen))
	}
	return out
}

// parseMPReachNLRI parses an MP_REACH_NLRI attribute payload (RFC 4760 §3).
// Layout:
//
//	AFI(2) | SAFI(1) | NH Len(1) | NH(variable) | Reserved(1) | NLRI(variable)
//
// Only AFI=2 (IPv6) SAFI=1 (unicast) is handled; other combinations are ignored.
// For IPv6 the next hop is 16 bytes (global) or 32 bytes (global + link-local);
// the link-local is dropped — RAVEN only records the global address.
func parseMPReachNLRI(data []byte) (netip.Addr, []netip.Prefix) {
	if len(data) < 5 {
		return netip.Addr{}, nil
	}
	afi := binary.BigEndian.Uint16(data[0:2])
	safi := data[2]
	if afi != 2 || safi != 1 {
		return netip.Addr{}, nil
	}
	nhLen := int(data[3])
	if 4+nhLen+1 > len(data) {
		return netip.Addr{}, nil
	}
	var nextHop netip.Addr
	if nhLen >= 16 {
		// Take the first 16 bytes as the global next hop. Per RFC 2545, a
		// 32-byte field carries the link-local in bytes 16..31; we drop it.
		if addr, ok := netip.AddrFromSlice(data[4 : 4+16]); ok {
			nextHop = addr
		}
	}
	nlriStart := 4 + nhLen + 1 // skip reserved byte
	if nlriStart > len(data) {
		return nextHop, nil
	}
	return nextHop, parseNLRI(data[nlriStart:], 16)
}

// parseMPUnreachNLRI parses an MP_UNREACH_NLRI attribute payload (RFC 4760 §4).
// Layout:
//
//	AFI(2) | SAFI(1) | Withdrawn NLRI(variable)
//
// Only AFI=2 (IPv6) SAFI=1 (unicast) is handled.
func parseMPUnreachNLRI(data []byte) []netip.Prefix {
	if len(data) < 3 {
		return nil
	}
	afi := binary.BigEndian.Uint16(data[0:2])
	safi := data[2]
	if afi != 2 || safi != 1 {
		return nil
	}
	return parseNLRI(data[3:], 16)
}

// pathAttrs collects the path-attribute fields RAVEN cares about, plus the raw
// MP_REACH/MP_UNREACH bodies for downstream multiprotocol NLRI parsing.
type pathAttrs struct {
	asPath           []uint32
	asPathRaw        []types.ASSegment
	origin           uint8
	nextHop          netip.Addr // IPv4 NEXT_HOP only; IPv6 next hop lives in MP_REACH
	communities      []types.Community
	largeCommunities []types.LargeCommunity
	mpReach          []byte // MP_REACH_NLRI body (attr type 14)
	mpUnreach        []byte // MP_UNREACH_NLRI body (attr type 15)
}

// parsePathAttributes walks the path attributes and extracts the fields
// RAVEN cares about: AS_PATH, ORIGIN, NEXT_HOP, COMMUNITIES, MP_REACH_NLRI,
// MP_UNREACH_NLRI.
func parsePathAttributes(data []byte) pathAttrs {
	var out pathAttrs
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		flags := data[offset]
		attrType := data[offset+1]
		offset += 2

		// Attribute length: 1 byte or 2 bytes depending on Extended Length flag
		var attrLen int
		if flags&0x10 != 0 { // Extended Length
			if offset+2 > len(data) {
				break
			}
			attrLen = int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
		} else {
			if offset+1 > len(data) {
				break
			}
			attrLen = int(data[offset])
			offset++
		}

		if offset+attrLen > len(data) {
			break
		}

		attrData := data[offset : offset+attrLen]
		offset += attrLen

		switch attrType {
		case 1: // ORIGIN
			if len(attrData) >= 1 {
				out.origin = attrData[0]
			}

		case 2: // AS_PATH
			out.asPath, out.asPathRaw = parseASPath(attrData)

		case 3: // NEXT_HOP (IPv4)
			if len(attrData) == 4 {
				if addr, ok := netip.AddrFromSlice(attrData); ok {
					out.nextHop = addr
				}
			}

		case 8: // COMMUNITIES
			for i := 0; i+4 <= len(attrData); i += 4 {
				out.communities = append(out.communities, types.Community{
					High: binary.BigEndian.Uint16(attrData[i : i+2]),
					Low:  binary.BigEndian.Uint16(attrData[i+2 : i+4]),
				})
			}

		case 14: // MP_REACH_NLRI (RFC 4760)
			out.mpReach = attrData

		case 15: // MP_UNREACH_NLRI (RFC 4760)
			out.mpUnreach = attrData

		case 32: // LARGE_COMMUNITIES
			for i := 0; i+12 <= len(attrData); i += 12 {
				out.largeCommunities = append(out.largeCommunities, types.LargeCommunity{
					GlobalAdmin: binary.BigEndian.Uint32(attrData[i : i+4]),
					LocalData1:  binary.BigEndian.Uint32(attrData[i+4 : i+8]),
					LocalData2:  binary.BigEndian.Uint32(attrData[i+8 : i+12]),
				})
			}
		}
	}

	return out
}

// parseASPath parses the AS_PATH attribute data into flat and raw forms.
func parseASPath(data []byte) (flat []uint32, raw []types.ASSegment) {
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		segType := types.ASSegmentType(data[offset])
		segLen := int(data[offset+1])
		offset += 2

		if offset+segLen*4 > len(data) {
			break
		}

		seg := types.ASSegment{
			Type: segType,
			ASNs: make([]uint32, segLen),
		}

		for i := 0; i < segLen; i++ {
			seg.ASNs[i] = binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4
		}

		raw = append(raw, seg)

		// Flatten: AS_SEQUENCE segments contribute to the flat path
		// AS_SET segments are expanded (all ASNs included)
		flat = append(flat, seg.ASNs...)
	}

	return
}
