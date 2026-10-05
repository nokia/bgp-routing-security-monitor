package bmp

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// locRIBHeader builds an RFC 9069 per-peer header: peer type 3, zero peer
// address, and the router's own AS and BGP ID.
func locRIBHeader(flags uint8, asn uint32, bgpID netip.Addr) []byte {
	data := make([]byte, PerPeerHeaderLen)
	data[0] = PeerTypeLocRIB
	data[1] = flags
	binary.BigEndian.PutUint32(data[26:30], asn)
	id := bgpID.As4()
	copy(data[30:34], id[:])
	binary.BigEndian.PutUint32(data[34:38], 1710000000)
	return data
}

// bgpOpen builds a BGP OPEN message with a 2-byte My AS and no capabilities.
func bgpOpen(asn uint16, bgpID netip.Addr) []byte {
	msg := make([]byte, bgpHeaderLen+10)
	for i := 0; i < 16; i++ {
		msg[i] = 0xff
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(len(msg)))
	msg[18] = bgpMsgTypeOpen
	body := msg[bgpHeaderLen:]
	body[0] = 4
	binary.BigEndian.PutUint16(body[1:3], asn)
	binary.BigEndian.PutUint16(body[3:5], 90)
	id := bgpID.As4()
	copy(body[5:9], id[:])
	return msg
}

// locRIBPeerUpBody builds a Loc-RIB Peer Up: zero local address and ports,
// then the same fabricated OPEN as sent and received (RFC 9069 §5.2).
func locRIBPeerUpBody(asn uint16, bgpID netip.Addr) []byte {
	data := locRIBHeader(0, uint32(asn), bgpID)
	data = append(data, make([]byte, 20)...)
	open := bgpOpen(asn, bgpID)
	data = append(data, open...)
	return append(data, open...)
}

// bgpUpdate builds a BGP UPDATE that withdraws one IPv4 prefix and announces
// another with an AS_SEQUENCE path.
func bgpUpdate(withdrawn, announced netip.Prefix, asPath []uint32) []byte {
	nlri := func(p netip.Prefix) []byte {
		a := p.Addr().As4()
		return append([]byte{byte(p.Bits())}, a[:(p.Bits()+7)/8]...)
	}
	w := nlri(withdrawn)

	var attrs []byte
	attrs = append(attrs, 0x40, 1, 1, 0) // ORIGIN IGP
	seg := []byte{2, byte(len(asPath))}
	for _, asn := range asPath {
		seg = binary.BigEndian.AppendUint32(seg, asn)
	}
	attrs = append(attrs, 0x40, 2, byte(len(seg)))
	attrs = append(attrs, seg...)
	attrs = append(attrs, 0x40, 3, 4, 192, 0, 2, 1) // NEXT_HOP

	var body []byte
	body = binary.BigEndian.AppendUint16(body, uint16(len(w)))
	body = append(body, w...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	body = append(body, nlri(announced)...)

	msg := make([]byte, bgpHeaderLen, bgpHeaderLen+len(body))
	for i := 0; i < 16; i++ {
		msg[i] = 0xff
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(bgpHeaderLen+len(body)))
	msg[18] = 2
	return append(msg, body...)
}

// For peer type 3 the 0x80 flag is the F (filtered) flag and 0x40 is
// undefined: neither may turn the header into an IPv6 or post-policy one.
// The zero peer address is replaced by the router's BGP ID, so each
// router's Loc-RIB gets its own identity.
func TestParsePerPeerHeaderLocRIB(t *testing.T) {
	bgpID := netip.MustParseAddr("192.0.2.55")
	pph, err := ParsePerPeerHeader(locRIBHeader(0x80|0x40, 64500, bgpID))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pph.IsLocRIB() {
		t.Error("IsLocRIB() = false, want true")
	}
	if pph.IsIPv6() {
		t.Error("IsIPv6() = true for a Loc-RIB header with the F flag")
	}
	if pph.IsPostPolicy() {
		t.Error("IsPostPolicy() = true for a Loc-RIB header")
	}
	if pph.PeerAddr != bgpID {
		t.Errorf("peer addr = %s, want the router BGP ID %s", pph.PeerAddr, bgpID)
	}
}

func TestPeerTypeName(t *testing.T) {
	for typ, want := range map[uint8]string{
		PeerTypeGlobal:  "global",
		PeerTypeRDLocal: "rd",
		PeerTypeLocal:   "local",
		PeerTypeLocRIB:  "loc-rib",
		9:               "unknown",
	} {
		if got := PeerTypeName(typ); got != want {
			t.Errorf("PeerTypeName(%d) = %q, want %q", typ, got, want)
		}
	}
}

// A Loc-RIB session through the listener: Peer Up registers the router's
// Loc-RIB as a peer named by its BGP ID, Route Monitoring yields Loc-RIB
// routes and withdrawals, and Peer Down withdraws everything it held.
func TestLocRIBSessionThroughListener(t *testing.T) {
	router := netip.MustParseAddr("198.51.100.1")
	bgpID := netip.MustParseAddr("192.0.2.55")
	ingest := make(chan types.IngestEvent, 8)
	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	l.processMessage(ctx, l.log, router,
		BMPCommonHeader{Version: 3, MsgType: MsgTypePeerUp}, locRIBPeerUpBody(64500, bgpID))
	peers := l.GetPeers()
	if len(peers) != 1 {
		t.Fatalf("GetPeers returned %d peers, want 1", len(peers))
	}
	if peers[0].Addr != bgpID || peers[0].PeerType != PeerTypeLocRIB || peers[0].LocalASN != 64500 {
		t.Fatalf("peer = %+v, want addr %s, type loc-rib, local ASN 64500", peers[0], bgpID)
	}

	withdrawn := netip.MustParsePrefix("10.9.0.0/16")
	announced := netip.MustParsePrefix("10.1.0.0/24")
	rm := append(locRIBHeader(0x80, 64500, bgpID), bgpUpdate(withdrawn, announced, []uint32{174, 13335})...)
	l.processMessage(ctx, l.log, router, BMPCommonHeader{Version: 3, MsgType: MsgTypeRouteMonitoring}, rm)

	route := (<-ingest).Route
	if route == nil || route.Prefix != announced || route.PeerAddr != bgpID || route.RIBType != types.LocRIB {
		t.Fatalf("route = %+v, want %s from %s in the Loc-RIB", route, announced, bgpID)
	}
	if route.LocalASN != 64500 {
		t.Errorf("route local ASN = %d, want 64500", route.LocalASN)
	}
	w := (<-ingest).Withdrawal
	if w == nil || w.Prefix != withdrawn || w.PeerAddr != bgpID || w.RIBType != types.LocRIB {
		t.Fatalf("withdrawal = %+v, want %s from %s in the Loc-RIB", w, withdrawn, bgpID)
	}

	down := append(locRIBHeader(0, 64500, bgpID), 6)
	l.processMessage(ctx, l.log, router, BMPCommonHeader{Version: 3, MsgType: MsgTypePeerDown}, down)
	select {
	case ev := <-ingest:
		if !isLocRIBWithdrawAll(ev.Withdrawal, bgpID) {
			t.Fatalf("got %+v, want a Loc-RIB withdraw-all for %s", ev.Withdrawal, bgpID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no withdraw-all after the Loc-RIB Peer Down")
	}
}

// When the BMP session ends, each peer of the router gets a withdraw-all for
// the RIBs it fed, so a Loc-RIB peer withdraws only Loc-RIB routes.
func TestSessionEndWithdrawsLocRIBPeer(t *testing.T) {
	bgpID := netip.MustParseAddr("192.0.2.55")
	ingest := make(chan types.IngestEvent, 8)
	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(io.Discard, nil)))

	router, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.handleSession(context.Background(), router)
	}()

	body := locRIBPeerUpBody(64500, bgpID)
	msg := make([]byte, CommonHeaderLen, CommonHeaderLen+len(body))
	msg[0] = 3
	binary.BigEndian.PutUint32(msg[1:5], uint32(CommonHeaderLen+len(body)))
	msg[5] = MsgTypePeerUp
	if _, err := client.Write(append(msg, body...)); err != nil {
		t.Fatalf("write Peer Up: %v", err)
	}
	client.Close()

	select {
	case ev := <-ingest:
		w := ev.Withdrawal
		if !isLocRIBWithdrawAll(w, bgpID) {
			t.Fatalf("got %+v, want a Loc-RIB withdraw-all for %s", w, bgpID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no withdraw-all when the BMP session ended")
	}
	<-done
}

// bgpEndOfRIB builds an empty BGP UPDATE, the IPv4 End-of-RIB marker.
func bgpEndOfRIB() []byte {
	msg := make([]byte, bgpHeaderLen+4)
	for i := 0; i < 16; i++ {
		msg[i] = 0xff
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(len(msg)))
	msg[18] = 2
	return msg
}

// Some routers (FRR 10.2) send Loc-RIB Route Monitoring without a Peer Up.
// The first message that carries routes registers the Loc-RIB peer, with
// the router's own AS from the per-peer header, so its routes are counted
// and withdrawn when the BMP session ends. An End-of-RIB alone does not.
func TestLocRIBPeerRegisteredWithoutPeerUp(t *testing.T) {
	router := netip.MustParseAddr("198.51.100.1")
	bgpID := netip.MustParseAddr("192.0.2.55")
	ingest := make(chan types.IngestEvent, 8)
	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	rmHdr := BMPCommonHeader{Version: 3, MsgType: MsgTypeRouteMonitoring}

	l.processMessage(ctx, l.log, router, rmHdr, append(locRIBHeader(0, 64500, bgpID), bgpEndOfRIB()...))
	if peers := l.GetPeers(); len(peers) != 0 {
		t.Fatalf("an End-of-RIB registered %d peers, want 0", len(peers))
	}

	announced := netip.MustParsePrefix("10.1.0.0/24")
	update := bgpUpdate(netip.MustParsePrefix("10.9.0.0/16"), announced, []uint32{174, 13335})
	l.processMessage(ctx, l.log, router, rmHdr, append(locRIBHeader(0, 64500, bgpID), update...))

	peers := l.GetPeers()
	if len(peers) != 1 {
		t.Fatalf("GetPeers returned %d peers, want the Loc-RIB peer", len(peers))
	}
	p := peers[0]
	if p.Addr != bgpID || p.PeerType != PeerTypeLocRIB || p.ASN != 64500 || p.LocalASN != 64500 || p.State != "up" || p.RouteCount != 1 {
		t.Errorf("peer = %+v, want an up Loc-RIB peer %s, AS 64500, 1 route", p, bgpID)
	}
	route := (<-ingest).Route
	if route == nil || route.LocalASN != 64500 {
		t.Fatalf("route = %+v, want local ASN 64500 from the per-peer header", route)
	}
}

func isLocRIBWithdrawAll(w *types.Withdrawal, peer netip.Addr) bool {
	return w != nil && w.WithdrawAll && w.PeerAddr == peer && slices.Equal(w.RIBs, []types.RIBType{types.LocRIB})
}

func withDistinguisher(hdr []byte, d types.PeerDistinguisher) []byte {
	copy(hdr[2:10], d[:])
	return hdr
}

// VRF Loc-RIBs often share the router's BGP ID, so the Peer Distinguisher
// keeps each instance a separate peer, and a Peer Down withdraws only its
// own instance.
func TestLocRIBInstancesAreKeyedByDistinguisher(t *testing.T) {
	router := netip.MustParseAddr("198.51.100.1")
	bgpID := netip.MustParseAddr("192.0.2.55")
	vrf := types.PeerDistinguisherFromUint64(64500<<32 | 100)
	ingest := make(chan types.IngestEvent, 8)
	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	rmHdr := BMPCommonHeader{Version: 3, MsgType: MsgTypeRouteMonitoring}
	update := bgpUpdate(netip.MustParsePrefix("10.9.0.0/16"), netip.MustParsePrefix("10.1.0.0/24"), []uint32{64510})

	l.processMessage(ctx, l.log, router, rmHdr, append(locRIBHeader(0, 64500, bgpID), update...))
	l.processMessage(ctx, l.log, router, rmHdr, append(withDistinguisher(locRIBHeader(0, 64500, bgpID), vrf), update...))

	if peers := l.GetPeers(); len(peers) != 2 {
		t.Fatalf("GetPeers returned %d peers, want the global and the VRF Loc-RIB", len(peers))
	}
	got := map[types.PeerDistinguisher]bool{}
	for len(ingest) > 0 {
		if r := (<-ingest).Route; r != nil {
			got[r.PeerDistinguisher] = true
		}
	}
	if !got[types.PeerDistinguisher{}] || !got[vrf] {
		t.Errorf("route distinguishers = %v, want the global one and %s", got, vrf)
	}

	down := append(withDistinguisher(locRIBHeader(0, 64500, bgpID), vrf), 6)
	l.processMessage(ctx, l.log, router, BMPCommonHeader{Version: 3, MsgType: MsgTypePeerDown}, down)
	w := (<-ingest).Withdrawal
	if !isLocRIBWithdrawAll(w, bgpID) || w.PeerDistinguisher != vrf {
		t.Fatalf("got %+v, want a Loc-RIB withdraw-all for %s %s", w, bgpID, vrf)
	}
}

// A Loc-RIB that sends routes again after its Peer Down, still without a
// Peer Up, is up again.
func TestLocRIBPeerUpAgainAfterPeerDown(t *testing.T) {
	router := netip.MustParseAddr("198.51.100.1")
	bgpID := netip.MustParseAddr("192.0.2.55")
	ingest := make(chan types.IngestEvent, 8)
	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	rmHdr := BMPCommonHeader{Version: 3, MsgType: MsgTypeRouteMonitoring}
	update := bgpUpdate(netip.MustParsePrefix("10.9.0.0/16"), netip.MustParsePrefix("10.1.0.0/24"), []uint32{64510})

	l.processMessage(ctx, l.log, router, rmHdr, append(locRIBHeader(0, 64500, bgpID), update...))
	l.processMessage(ctx, l.log, router, BMPCommonHeader{Version: 3, MsgType: MsgTypePeerDown}, append(locRIBHeader(0, 64500, bgpID), 6))
	l.processMessage(ctx, l.log, router, rmHdr, append(locRIBHeader(0, 64500, bgpID), update...))

	peers := l.GetPeers()
	if len(peers) != 1 || peers[0].State != "up" || peers[0].RouteCount != 1 {
		t.Fatalf("peers = %+v, want one up Loc-RIB peer with 1 route", peers)
	}
}
