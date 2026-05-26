package rtr

import (
	"bufio"
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
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// RTR PDU types (RFC 8210)
const (
	PDUSerialNotify  uint8 = 0
	PDUSerialQuery   uint8 = 1
	PDUResetQuery    uint8 = 2
	PDUCacheResponse uint8 = 3
	PDUIPv4Prefix    uint8 = 4
	PDUIPv6Prefix    uint8 = 6
	PDUEndOfData     uint8 = 7
	PDUCacheReset    uint8 = 8
	PDUErrorReport   uint8 = 10
	PDUASPA          uint8 = 11 // RTR v2 (draft-ietf-sidrops-8210bis)
)

// RTR header is 8 bytes: version(1) + type(1) + sessionID(2) + length(4)
const rtrHeaderLen = 8

// Client maintains an RTR session with a single RPKI validator cache.
type Client struct {
	address         string
	transport       string // "tcp" (default) or "tls"
	tlsCfg          *tls.Config
	vrpStore        *store.VRPStore
	aspaStore       *store.ASPAStore
	log             *slog.Logger
	retryMin        time.Duration
	retryMax        time.Duration
	hasReset        bool
	fullSyncPending bool  // true between Reset Query send and EndOfData receive
	configVersion   uint8 // configured starting version; reset to this on each session
	protoVersion    uint8 // RTR protocol version (0, 1, or 2)
	onUpdate        func()
	readyOnce       sync.Once
	ready           chan struct{}
}

// NewClient creates an RTR client that syncs VRPs into the given store.
// transport selects the wire encoding: "tcp" (default, plaintext) or "tls".
// tlsCfg is consulted only when transport == "tls"; it may be nil, in which
// case the system root CA pool is used and no client certificate is presented.
func NewClient(address string, transport string, tlsCfg *config.TLSConfig, vrpStore *store.VRPStore, aspaStore *store.ASPAStore, configVersion uint8, log *slog.Logger) (*Client, error) {
	if transport == "" {
		transport = "tcp"
	}
	logger := log.With("subsystem", "rtr", "cache", address)

	c := &Client{
		address:       address,
		transport:     transport,
		vrpStore:      vrpStore,
		aspaStore:     aspaStore,
		log:           logger,
		retryMin:      5 * time.Second,
		retryMax:      60 * time.Second,
		configVersion: configVersion,
		protoVersion:  configVersion,
		ready:         make(chan struct{}),
	}

	if transport == "tls" {
		built, err := buildTLSConfig(tlsCfg, logger)
		if err != nil {
			return nil, err
		}
		c.tlsCfg = built
	}

	return c, nil
}

// buildTLSConfig assembles a *tls.Config from the user-supplied paths.
// A nil cfg or empty CA falls back to the system root pool.
func buildTLSConfig(cfg *config.TLSConfig, log *slog.Logger) (*tls.Config, error) {
	out := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg == nil || cfg.CA == "" {
		log.Warn("RTR TLS configured without a custom CA; using system root pool")
	} else {
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("read RTR TLS CA %q: %w", cfg.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse RTR TLS CA %q: no PEM certificates found", cfg.CA)
		}
		out.RootCAs = pool
	}

	if cfg != nil && cfg.Cert != "" && cfg.Key != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("load RTR TLS client cert: %w", err)
		}
		out.Certificates = []tls.Certificate{cert}
	}

	return out, nil
}

// Ready returns a channel that is closed after the first successful RTR sync.
func (c *Client) Ready() <-chan struct{} {
	return c.ready
}

// SetOnUpdate sets a callback invoked after each VRP store update.
func (c *Client) SetOnUpdate(fn func()) {
	c.onUpdate = fn
}

// Start connects to the RTR cache and maintains the session.
// Reconnects with exponential backoff on failure. Blocks until ctx is cancelled.
func (c *Client) Start(ctx context.Context) {
	retryDelay := c.retryMin

	for {
		if ctx.Err() != nil {
			return
		}

		err := c.runSession(ctx)
		if ctx.Err() != nil {
			return
		}

		c.log.Error("RTR session failed, reconnecting", "error", err, "retry_in", retryDelay)

		select {
		case <-time.After(retryDelay):
			retryDelay = retryDelay * 2
			if retryDelay > c.retryMax {
				retryDelay = c.retryMax
			}
		case <-ctx.Done():
			return
		}
	}
}

// runSession handles a single RTR connection lifecycle.
func (c *Client) runSession(ctx context.Context) error {
	// Reset to the configured starting version on each new session attempt.
	// Transient errors (e.g. "Running initial validation" during cache startup)
	// must not permanently downgrade the version across reconnects.
	// Version negotiation will still fall back within this session if the cache
	// genuinely rejects the starting version with an error report.
	c.protoVersion = c.configVersion

	var (
		conn   net.Conn
		tcpRaw *net.TCPConn
	)

	switch c.transport {
	case "tls":
		// tls.DialWithDialer ignores DialContext's deadline, so we bound the
		// handshake via the dialer's own Timeout.
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		tconn, err := tls.DialWithDialer(dialer, "tcp", c.address, c.tlsCfg)
		if err != nil {
			return fmt.Errorf("connect (tls): %w", err)
		}
		conn = tconn
		// Reach through tls.Conn to the underlying TCP socket so we can apply
		// the same buffer tunings used on plaintext sessions.
		if tc, ok := tconn.NetConn().(*net.TCPConn); ok {
			tcpRaw = tc
		}
	default:
		dialer := net.Dialer{Timeout: 10 * time.Second}
		pc, err := dialer.DialContext(ctx, "tcp", c.address)
		if err != nil {
			return fmt.Errorf("connect: %w", err)
		}
		conn = pc
		if tc, ok := pc.(*net.TCPConn); ok {
			tcpRaw = tc
		}
	}
	defer conn.Close()

	// Tune TCP buffers to handle large VRP table dumps
	if tcpRaw != nil && c.transport != "tls" {
		tcpRaw.SetNoDelay(true)
		tcpRaw.SetReadBuffer(4 * 1024 * 1024)
		tcpRaw.SetWriteBuffer(1 * 1024 * 1024)
	}

	c.log.Info("RTR session established", "transport", c.transport)
	metrics.RTRSessionState.WithLabelValues(c.address).Set(1)
	defer metrics.RTRSessionState.WithLabelValues(c.address).Set(0)
	metrics.RTRVRPCount.WithLabelValues(c.address).Set(float64(c.vrpStore.Count()))

	// Send Reset Query to get the full VRP set
	c.fullSyncPending = true
	if err := c.sendResetQuery(conn); err != nil {
		return fmt.Errorf("send reset query: %w", err)
	}

	// Buffered reader — critical for draining large VRP table dumps
	reader := bufio.NewReaderSize(conn, 4*1024*1024) // 4MB read buffer

	// Read PDUs until the session ends
	for {
		if ctx.Err() != nil {
			return nil
		}
		pduType, sessionID, payload, err := c.readPDU(reader)
		if err != nil {
			return fmt.Errorf("read PDU: %w", err)
		}

		switch pduType {
		case PDUCacheResponse:
			c.log.Debug("cache response", "session_id", sessionID)
			// If we're servicing a Reset Query, clear the stores so the
			// incoming full snapshot replaces rather than appends. Without
			// this, every reconnect doubles the VRP store size.
			if c.fullSyncPending {
				c.vrpStore.Clear()
				c.aspaStore.Clear()
			}

		case PDUIPv4Prefix:
			vrp, withdraw, err := c.parseIPv4Prefix(payload)
			if err != nil {
				c.log.Error("bad IPv4 prefix PDU", "error", err)
				continue
			}
			if withdraw {
				c.vrpStore.RemoveVRP(vrp)
			} else {
				c.vrpStore.AddVRP(vrp)
			}

		case PDUIPv6Prefix:
			vrp, withdraw, err := c.parseIPv6Prefix(payload)
			if err != nil {
				c.log.Error("bad IPv6 prefix PDU", "error", err)
				continue
			}
			if withdraw {
				c.vrpStore.RemoveVRP(vrp)
			} else {
				c.vrpStore.AddVRP(vrp)
			}

		case PDUASPA:
			customerASN, providerASNs, withdraw, err := c.parseASPAPDU(sessionID, payload)
			if err != nil {
				c.log.Error("bad ASPA PDU", "error", err)
				continue
			}
			if withdraw {
				for _, p := range providerASNs {
					c.aspaStore.RemoveProvider(customerASN, p)
				}
			} else {
				for _, p := range providerASNs {
					c.aspaStore.AddProvider(customerASN, p)
				}
			}

		case PDUEndOfData:
			serial, err := c.parseEndOfData(payload)
			if err != nil {
				c.log.Error("bad end-of-data PDU", "error", err)
				continue
			}
			c.vrpStore.SetSerial(serial, sessionID)
			c.vrpStore.RebuildIndex() // build index once after full sync
			c.fullSyncPending = false
			metrics.RTRVRPCount.WithLabelValues(c.address).Set(float64(c.vrpStore.Count()))
			metrics.RTRLastSync.WithLabelValues(c.address).Set(float64(time.Now().Unix()))
			c.log.Info("RTR sync complete",
				"vrp_count", c.vrpStore.Count(),
				"aspa_count", c.aspaStore.Count(),
				"serial", serial,
				"session_id", sessionID,
			)
			if c.onUpdate != nil {
				c.onUpdate()
				c.readyOnce.Do(func() { close(c.ready) })
			}

			// After initial sync, wait for Serial Notify from cache
			// and send Serial Query for incremental updates
			c.hasReset = true

		case PDUSerialNotify:
			if len(payload) >= 4 {
				serial := binary.BigEndian.Uint32(payload[0:4])
				c.log.Debug("serial notify", "serial", serial)
				// Send Serial Query for incremental update
				if err := c.sendSerialQuery(conn, sessionID, c.vrpStore.Serial()); err != nil {
					return fmt.Errorf("send serial query: %w", err)
				}
			}

		case PDUCacheReset:
			c.log.Warn("cache reset received, performing full sync")
			c.fullSyncPending = true
			if err := c.sendResetQuery(conn); err != nil {
				return fmt.Errorf("send reset query after cache reset: %w", err)
			}

		case PDUErrorReport:
			errMsg := c.parseErrorReport(payload)
			c.log.Error("RTR error report from cache", "error_text", errMsg)

			// Version negotiation fallback: 2 → 1 → 0
			switch c.protoVersion {
			case 2:
				c.log.Info("falling back to RTR protocol version 1")
				c.protoVersion = 1
				return fmt.Errorf("cache sent error report (trying version 1): %s", errMsg)
			case 1:
				c.log.Info("falling back to RTR protocol version 0")
				c.protoVersion = 0
				return fmt.Errorf("cache sent error report (trying version 0): %s", errMsg)
			default:
				return fmt.Errorf("cache sent error report: %s", errMsg)
			}

		default:
			c.log.Debug("unknown RTR PDU type", "type", pduType)
		}
	}
}

// readPDU reads a single RTR PDU from the connection.
func (c *Client) readPDU(r *bufio.Reader) (pduType uint8, sessionID uint16, payload []byte, err error) {
	hdr := make([]byte, rtrHeaderLen)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, 0, nil, err
	}
	pduType = hdr[1]
	sessionID = binary.BigEndian.Uint16(hdr[2:4])
	length := binary.BigEndian.Uint32(hdr[4:8])
	if length < rtrHeaderLen {
		return pduType, sessionID, nil, fmt.Errorf("PDU length %d < header size", length)
	}
	payloadLen := int(length) - rtrHeaderLen
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err = io.ReadFull(r, payload); err != nil {
			return pduType, sessionID, nil, err
		}
	}
	return pduType, sessionID, payload, nil
}

// parseASPAPDU parses an ASPA PDU (type 11) from RTR v2.
// Format per draft-ietf-sidrops-8210bis:
//
//	Flags (1) | AFI Flags (1) | Customer ASN (4) | Provider AS Count (2) | Provider ASNs (4 each)
func (c *Client) parseASPAPDU(sessionID uint16, data []byte) (customerASN uint32, providerASNs []uint32, withdraw bool, err error) {
	flags := uint8(sessionID >> 8)
	withdraw = flags&0x01 == 0

	if len(data) < 4 {
		return 0, nil, false, fmt.Errorf("ASPA PDU too short: %d", len(data))
	}
	customerASN = binary.BigEndian.Uint32(data[0:4])

	// No explicit provider count — derive from remaining payload length
	remaining := len(data) - 4
	if remaining%4 != 0 {
		return 0, nil, false, fmt.Errorf("ASPA PDU malformed: %d extra bytes after customerASN", remaining)
	}
	providerCount := remaining / 4
	providerASNs = make([]uint32, providerCount)
	for i := 0; i < providerCount; i++ {
		providerASNs[i] = binary.BigEndian.Uint32(data[4+i*4 : 8+i*4])
	}
	return customerASN, providerASNs, withdraw, nil
}

// sendResetQuery sends an RTR Reset Query PDU.
func (c *Client) sendResetQuery(conn net.Conn) error {
	pdu := make([]byte, 8)
	pdu[0] = c.protoVersion
	pdu[1] = PDUResetQuery
	// session_id = 0
	binary.BigEndian.PutUint32(pdu[4:8], 8) // length = 8
	_, err := conn.Write(pdu)
	return err
}

// sendSerialQuery sends an RTR Serial Query PDU.
func (c *Client) sendSerialQuery(conn net.Conn, sessionID uint16, serial uint32) error {
	pdu := make([]byte, 12)
	pdu[0] = c.protoVersion
	pdu[1] = PDUSerialQuery
	binary.BigEndian.PutUint16(pdu[2:4], sessionID)
	binary.BigEndian.PutUint32(pdu[4:8], 12) // length = 12
	binary.BigEndian.PutUint32(pdu[8:12], serial)
	_, err := conn.Write(pdu)
	return err
}

// parseIPv4Prefix parses an IPv4 Prefix PDU payload.
// Returns the VRP and whether this is a withdrawal (flags bit 0 = 0).
func (c *Client) parseIPv4Prefix(data []byte) (types.VRP, bool, error) {
	// IPv4 Prefix PDU payload (after header):
	// flags(1) + prefixLen(1) + maxLen(1) + zero(1) + prefix(4) + ASN(4)
	if len(data) < 12 {
		return types.VRP{}, false, fmt.Errorf("IPv4 prefix PDU too short: %d", len(data))
	}

	flags := data[0]
	prefixLen := int(data[1])
	maxLen := data[2]
	// data[3] is zero/reserved

	addr, ok := netip.AddrFromSlice(data[4:8])
	if !ok {
		return types.VRP{}, false, fmt.Errorf("invalid IPv4 address")
	}
	prefix := netip.PrefixFrom(addr, prefixLen)
	asn := binary.BigEndian.Uint32(data[8:12])

	withdraw := flags&0x01 == 0 // flags bit 0: 1=announce, 0=withdraw

	return types.VRP{
		Prefix:    prefix,
		ASN:       asn,
		MaxLength: maxLen,
	}, withdraw, nil
}

// parseIPv6Prefix parses an IPv6 Prefix PDU payload.
func (c *Client) parseIPv6Prefix(data []byte) (types.VRP, bool, error) {
	// IPv6 Prefix PDU payload (after header):
	// flags(1) + prefixLen(1) + maxLen(1) + zero(1) + prefix(16) + ASN(4)
	if len(data) < 24 {
		return types.VRP{}, false, fmt.Errorf("IPv6 prefix PDU too short: %d", len(data))
	}

	flags := data[0]
	prefixLen := int(data[1])
	maxLen := data[2]

	addr, ok := netip.AddrFromSlice(data[4:20])
	if !ok {
		return types.VRP{}, false, fmt.Errorf("invalid IPv6 address")
	}
	prefix := netip.PrefixFrom(addr, prefixLen)
	asn := binary.BigEndian.Uint32(data[20:24])

	withdraw := flags&0x01 == 0

	return types.VRP{
		Prefix:    prefix,
		ASN:       asn,
		MaxLength: maxLen,
	}, withdraw, nil
}

// parseEndOfData parses an End of Data PDU payload and returns the serial number.
func (c *Client) parseEndOfData(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("end-of-data PDU too short: %d", len(data))
	}
	return binary.BigEndian.Uint32(data[0:4]), nil
}

// parseErrorReport extracts the error text from an RTR Error Report PDU.
func (c *Client) parseErrorReport(data []byte) string {
	// Error Report payload:
	// Length of Encapsulated PDU (4 bytes)
	// Encapsulated PDU (variable)
	// Length of Error Text (4 bytes)
	// Error Text (variable)
	if len(data) < 4 {
		return "(empty error report)"
	}

	encapLen := binary.BigEndian.Uint32(data[0:4])
	offset := 4 + int(encapLen)

	if offset+4 > len(data) {
		return "(no error text)"
	}

	textLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset+int(textLen) > len(data) {
		return "(error text truncated)"
	}

	return string(data[offset : offset+int(textLen)])
}
