package bmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/srl-labs/raven/internal/metrics"
	"github.com/srl-labs/raven/internal/types"
)

// Listener accepts BMP connections from routers and processes messages.
type Listener struct {
	addr        string
	log         *slog.Logger
	routeCh     chan<- types.Route
	withdrawCh  chan<- types.Withdrawal
	peerMu      sync.RWMutex
	peers       map[PeerKey]*Peer
	routerMu    sync.RWMutex
	routers     map[netip.Addr]string
	listener    net.Listener
}

// NewListener creates a BMP listener that sends parsed routes to routeCh.
func NewListener(addr string, routeCh chan<- types.Route, withdrawCh chan<- types.Withdrawal, log *slog.Logger) *Listener {
	return &Listener{
		addr:       addr,
		log:        log.With("subsystem", "bmp"),
		routeCh:    routeCh,
		withdrawCh: withdrawCh,
		peers:      make(map[PeerKey]*Peer),
		routers:    make(map[netip.Addr]string),
	}
}

// Start begins listening for BMP connections. Blocks until ctx is cancelled.
func (l *Listener) Start(ctx context.Context) error {
	var err error
	l.listener, err = net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("BMP listen on %s: %w", l.addr, err)
	}
	l.log.Info("BMP listener started", "addr", l.addr)

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

	routes, withdrawals, err := parseBGPUpdate(updateBody, rm.PerPeer, routerAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse BGP UPDATE: %w", err)
	}
	return routes, withdrawals, nil
}

// parseBGPUpdate extracts routes from a BGP UPDATE message body.
// This uses GoBGP's packet parser for the heavy lifting.
func parseBGPUpdate(data []byte, pph BMPPerPeerHeader, routerAddr netip.Addr) ([]types.Route, []types.Withdrawal, error) {
	if len(data) < 4 {
		return nil, nil, nil
	}
	ribType := types.AdjRIBInPre
	if pph.IsPostPolicy() {
		ribType = types.AdjRIBInPost
	}

	// Parse withdrawn prefixes
	withdrawnLen := binary.BigEndian.Uint16(data[0:2])
	var withdrawals []types.Withdrawal
	if withdrawnLen > 0 {
		wOff := 2
		wEnd := 2 + int(withdrawnLen)
		for wOff < wEnd {
			pLen := int(data[wOff])
			wOff++
			pBytes := (pLen + 7) / 8
			if wOff+pBytes > wEnd {
				break
			}
			buf := make([]byte, 4)
			copy(buf, data[wOff:wOff+pBytes])
			wOff += pBytes
			addr, ok := netip.AddrFromSlice(buf)
			if !ok {
				continue
			}
			withdrawals = append(withdrawals, types.Withdrawal{
				PeerAddr: pph.PeerAddr,
				Prefix:   netip.PrefixFrom(addr.Unmap(), pLen),
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

	// Parse path attributes
	asPath, asPathRaw, origin, nextHop, communities, largeCommunities := parsePathAttributes(data[offset:pathAttrEnd])
	offset = pathAttrEnd

	// Parse NLRI (remaining bytes after path attributes)
	var routes []types.Route
	for offset < len(data) {
		prefixLen := int(data[offset])
		offset++
		prefixBytes := (prefixLen + 7) / 8

		if offset+prefixBytes > len(data) {
			break
		}

		prefixBuf := make([]byte, 4)
		copy(prefixBuf, data[offset:offset+prefixBytes])
		offset += prefixBytes

		addr, ok := netip.AddrFromSlice(prefixBuf)
		if !ok {
			continue
		}
		prefix := netip.PrefixFrom(addr, prefixLen)

		route := types.Route{
			Timestamp:        pph.Timestamp,
			PeerAddr:         pph.PeerAddr,
			PeerASN:          pph.PeerASN,
			RouterID:         pph.PeerBGPID,
			Prefix:           prefix,
			ASPath:           asPath,
			ASPathRaw:        asPathRaw,
			Origin:           types.OriginType(origin),
			NextHop:          nextHop,
			Communities:      communities,
			LargeCommunities: largeCommunities,
			RIBType:          ribType,
		}

		routes = append(routes, route)
	}

	return routes, withdrawals, nil
}

// parsePathAttributes walks the path attributes and extracts the fields
// RAVEN cares about: AS_PATH, ORIGIN, NEXT_HOP, COMMUNITIES.
func parsePathAttributes(data []byte) (
	asPath []uint32,
	asPathRaw []types.ASSegment,
	origin uint8,
	nextHop netip.Addr,
	communities []types.Community,
	largeCommunities []types.LargeCommunity,
) {
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
				origin = attrData[0]
			}

		case 2: // AS_PATH
			asPath, asPathRaw = parseASPath(attrData)

		case 3: // NEXT_HOP (IPv4)
			if len(attrData) == 4 {
				addr, ok := netip.AddrFromSlice(attrData)
				if ok {
					nextHop = addr
				}
			}

		case 8: // COMMUNITIES
			for i := 0; i+4 <= len(attrData); i += 4 {
				communities = append(communities, types.Community{
					High: binary.BigEndian.Uint16(attrData[i : i+2]),
					Low:  binary.BigEndian.Uint16(attrData[i+2 : i+4]),
				})
			}

		case 32: // LARGE_COMMUNITIES
			for i := 0; i+12 <= len(attrData); i += 12 {
				largeCommunities = append(largeCommunities, types.LargeCommunity{
					GlobalAdmin: binary.BigEndian.Uint32(attrData[i : i+4]),
					LocalData1:  binary.BigEndian.Uint32(attrData[i+4 : i+8]),
					LocalData2:  binary.BigEndian.Uint32(attrData[i+8 : i+12]),
				})
			}
		}
	}

	return
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
