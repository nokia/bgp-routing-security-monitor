package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	snapshotv1 "github.com/nokia/bgp-routing-security-monitor/internal/snapshot/v1"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// ErrVersionMismatch is returned when the snapshot was written by a
// different RAVEN version. Callers should log a warning and continue
// with a cold start — never crash on this error.
var ErrVersionMismatch = errors.New("snapshot: version mismatch, discarding")

// Reader handles snapshot reads from disk.
type Reader struct {
	dir     string
	version string
}

// NewReader creates a Reader rooted at dir.
func NewReader(dir string, version string) *Reader {
	return &Reader{dir: expandHome(dir), version: version}
}

// ReadRoutes reads <dir>/routes.snap.
// Returns (nil, nil) if the file does not exist (first start).
// Returns ErrVersionMismatch if the snapshot was written by a different version.
// Returns a non-nil error if the file is unreadable or corrupt.
func (r *Reader) ReadRoutes() ([]*types.Route, error) {
	path := filepath.Join(r.dir, "routes.snap")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("snapshot: read routes.snap: %w", err)
	}

	var snap snapshotv1.RouteSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("snapshot: decode routes.snap: %w", err)
	}

	if snap.RavenVersion != r.version {
		return nil, ErrVersionMismatch
	}

	routes := make([]*types.Route, 0, len(snap.Routes))
	for i, rec := range snap.Routes {
		route, err := recordToRoute(rec)
		if err != nil {
			return nil, fmt.Errorf("snapshot: route record %d: %w", i, err)
		}
		routes = append(routes, route)
	}
	return routes, nil
}

// ReadRPKI reads <dir>/rpki.snap.
// Returns (nil, nil, 0, nil) if the file does not exist (first start).
// Returns ErrVersionMismatch if the snapshot was written by a different version.
func (r *Reader) ReadRPKI() (vrps []types.VRP, aspas []types.ASPARecord, serial uint32, err error) {
	path := filepath.Join(r.dir, "rpki.snap")
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return nil, nil, 0, nil
		}
		return nil, nil, 0, fmt.Errorf("snapshot: read rpki.snap: %w", readErr)
	}

	var snap snapshotv1.RPKISnapshot
	if jsonErr := json.Unmarshal(data, &snap); jsonErr != nil {
		return nil, nil, 0, fmt.Errorf("snapshot: decode rpki.snap: %w", jsonErr)
	}

	if snap.RavenVersion != r.version {
		return nil, nil, 0, ErrVersionMismatch
	}

	vrps = make([]types.VRP, 0, len(snap.VRPs))
	for _, v := range snap.VRPs {
		prefix, parseErr := netip.ParsePrefix(v.Prefix)
		if parseErr != nil {
			return nil, nil, 0, fmt.Errorf("snapshot: VRP prefix %q: %w", v.Prefix, parseErr)
		}
		vrps = append(vrps, types.VRP{
			Prefix:    prefix,
			ASN:       v.ASN,
			MaxLength: uint8(v.MaxLength),
		})
	}

	aspas = make([]types.ASPARecord, 0, len(snap.ASPAs))
	for _, a := range snap.ASPAs {
		aspas = append(aspas, types.ASPARecord{
			CustomerASN:  a.CustomerASN,
			ProviderASNs: a.ProviderASNs,
		})
	}

	return vrps, aspas, snap.RTRSerial, nil
}

// ── conversion helpers ──────────────────────────────────────────────────────

func recordToRoute(rec snapshotv1.RouteRecord) (*types.Route, error) {
	prefix, err := netip.ParsePrefix(rec.Prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid prefix %q: %w", rec.Prefix, err)
	}

	peerAddr, err := parseAddr(rec.PeerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid peer addr %q: %w", rec.PeerAddr, err)
	}

	routerID, _ := parseAddr(rec.RouterID)
	nextHop, _ := parseAddr(rec.NextHop)

	rib := parseRIBType(rec.RIBType)
	rovState := parseROVState(rec.ROVState)
	aspaState := parseASPAState(rec.ASPAState)

	return &types.Route{
		Prefix:          prefix,
		PeerAddr:        peerAddr,
		PeerASN:         rec.PeerASN,
		RouterID:        routerID,
		ASPath:          rec.ASPath,
		NextHop:         nextHop,
		Timestamp:       time.Unix(0, rec.TimestampUnix),
		RIBType:         rib,
		ROV:             types.ROVResult{State: rovState},
		ASPA:            types.ASPAResult{State: aspaState},
		SecurityPosture: types.SecurityPosture(rec.Posture),
		Stale:           true, // always stale on restore
	}, nil
}

func parseAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(s)
}

func parseRIBType(s string) types.RIBType {
	switch s {
	case "post-policy":
		return types.AdjRIBInPost
	case "loc-rib":
		return types.LocRIB
	default:
		return types.AdjRIBInPre
	}
}

func parseROVState(s string) types.ROVState {
	switch s {
	case "Invalid":
		return types.ROVInvalid
	case "NotFound":
		return types.ROVNotFound
	default:
		return types.ROVValid
	}
}

func parseASPAState(s string) types.ASPAState {
	switch s {
	case "Invalid":
		return types.ASPAInvalid
	case "Unknown":
		return types.ASPAUnknown
	case "Unverifiable":
		return types.ASPAUnverifiable
	default:
		return types.ASPAValid
	}
}
