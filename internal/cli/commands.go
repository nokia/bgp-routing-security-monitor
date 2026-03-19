package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/srl-labs/raven/internal/config"
	"github.com/srl-labs/raven/internal/server"
)

// ─── serve ───

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the RAVEN daemon (BMP receiver + RTR client + outputs)",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := initLogger()
		log.Info("starting raven", "version", version, "commit", commit)

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}

		demo, _ := cmd.Flags().GetBool("demo")

		srv := server.New(cfg, log)
		srv.SetDemoMode(demo)
		return srv.Run()
	},
}

// ─── version ───

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show RAVEN version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("raven %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
	},
}

// ─── status ───

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show BMP peer states, RTR cache health, and system status",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		resp, err := apiGet(addr, "/api/v1/status", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var status struct {
			Version string `json:"version"`
			Uptime  string `json:"uptime"`
			BMP     []struct {
				Addr       string `json:"addr"`
				ASN        uint32 `json:"asn"`
				State      string `json:"state"`
				RouteCount uint64 `json:"route_count"`
			} `json:"bmp_peers"`
			RTR struct {
				VRPCount uint64 `json:"vrp_count"`
				Serial   uint32 `json:"serial"`
			} `json:"rtr"`
			RouteTable struct {
				TotalRoutes uint64            `json:"total_routes"`
				ByPosture   map[string]uint64 `json:"by_posture"`
			} `json:"route_table"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return err
		}

		fmt.Printf("RAVEN %s  uptime %s\n\n", status.Version, status.Uptime)

		fmt.Printf("Route Table: %d routes\n", status.RouteTable.TotalRoutes)
		for posture, count := range status.RouteTable.ByPosture {
			fmt.Printf("  %-20s %d\n", posture, count)
		}

		fmt.Printf("\nRPKI: %d VRPs (serial %d)\n", status.RTR.VRPCount, status.RTR.Serial)

		fmt.Printf("\nBMP Peers: %d\n", len(status.BMP))
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  PEER\tASN\tSTATE\tROUTES\n")
		for _, p := range status.BMP {
			fmt.Fprintf(tw, "  %s\t%d\t%s\t%d\n", p.Addr, p.ASN, p.State, p.RouteCount)
		}
		tw.Flush()
		return nil
	},
}

// ─── peers ───

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List all BMP peers with session metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		resp, err := apiGet(addr, "/api/v1/peers", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var peers []struct {
			Addr       string `json:"addr"`
			ASN        uint32 `json:"asn"`
			RouterID   string `json:"router_id"`
			State      string `json:"state"`
			RouteCount uint64 `json:"route_count"`
			UpSince    string `json:"up_since"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
			return err
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "PEER\tASN\tROUTER ID\tSTATE\tROUTES\tUP SINCE\n")
		for _, p := range peers {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%d\t%s\n",
				p.Addr, p.ASN, p.RouterID, p.State, p.RouteCount, p.UpSince)
		}
		tw.Flush()
		return nil
	},
}

// ─── routes ───

var routesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Query the route table (filterable by prefix, ASN, peer, posture)",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		params := url.Values{}

		if v, _ := cmd.Flags().GetString("prefix"); v != "" {
			params.Set("prefix", v)
		}
		if v, _ := cmd.Flags().GetUint32("origin-asn"); v != 0 {
			params.Set("origin-asn", fmt.Sprintf("%d", v))
		}
		if v, _ := cmd.Flags().GetString("peer"); v != "" {
			params.Set("peer", v)
		}
		if v, _ := cmd.Flags().GetString("posture"); v != "" {
			params.Set("posture", v)
		}

		resp, err := apiGet(addr, "/api/v1/routes", params)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			io.Copy(os.Stdout, resp.Body)
			return nil
		}

		var routes []struct {
			Prefix    string   `json:"prefix"`
			PeerAddr  string   `json:"peer"`
			OriginASN uint32   `json:"origin_asn"`
			ASPath    []uint32 `json:"as_path"`
			ROV       string   `json:"rov"`
			ASPA      string   `json:"aspa"`
			Posture   string   `json:"posture"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
			return err
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "PREFIX\tPEER\tORIGIN\tROV\tASPA\tPOSTURE\n")
		for _, r := range routes {
			asPathStr := formatASPath(r.ASPath)
			origin := fmt.Sprintf("AS%d", r.OriginASN)
			if r.OriginASN == 0 {
				origin = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Prefix, r.PeerAddr, origin, r.ROV, r.ASPA, r.Posture)
			_ = asPathStr
		}
		tw.Flush()
		return nil
	},
}

// ─── validate ───

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "One-shot validation of a prefix against current RPKI state",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		prefix, _ := cmd.Flags().GetString("prefix")

		if prefix == "" {
			return fmt.Errorf("--prefix is required")
		}

		params := url.Values{"prefix": {prefix}}
		resp, err := apiGet(addr, "/api/v1/routes", params)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var routes []struct {
			Prefix    string `json:"prefix"`
			PeerAddr  string `json:"peer"`
			OriginASN uint32 `json:"origin_asn"`
			ROV       string `json:"rov"`
			ROVReason string `json:"rov_reason"`
			Posture   string `json:"posture"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
			return err
		}

		if len(routes) == 0 {
			fmt.Println("no routes found for prefix", prefix)
			return nil
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "PREFIX\tPEER\tORIGIN\tROV\tPOSTURE\tREASON\n")
		for _, r := range routes {
			origin := fmt.Sprintf("AS%d", r.OriginASN)
			if r.OriginASN == 0 {
				origin = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Prefix, r.PeerAddr, origin, r.ROV, r.Posture, r.ROVReason)
		}
		tw.Flush()
		return nil
	},
}

// ─── watch ───

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Stream live validation state changes",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		params := url.Values{}
		if v, _ := cmd.Flags().GetString("posture"); v != "" {
			params.Set("posture", v)
		}

		u := fmt.Sprintf("http://%s/api/v1/watch", addr)
		if len(params) > 0 {
			u += "?" + params.Encode()
		}

		resp, err := http.Get(u)
		if err != nil {
			return fmt.Errorf("connect to daemon: %w\n  is 'raven serve' running?", err)
		}
		defer resp.Body.Close()

		fmt.Println("watching for route events... (Ctrl+C to stop)")
		fmt.Println()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := line[6:]

			var r struct {
				Prefix    string   `json:"prefix"`
				PeerAddr  string   `json:"peer"`
				OriginASN uint32   `json:"origin_asn"`
				ASPath    []uint32 `json:"as_path"`
				ROV       string   `json:"rov"`
				Posture   string   `json:"posture"`
			}
			if err := json.Unmarshal([]byte(data), &r); err != nil {
				continue
			}

			origin := fmt.Sprintf("AS%d", r.OriginASN)
			if r.OriginASN == 0 {
				origin = "-"
			}
			fmt.Printf("[%s] %s via %s origin:%s AS_PATH:%v rov:%s posture:%s\n",
				r.Posture, r.Prefix, r.PeerAddr, origin,
				r.ASPath, r.ROV, r.Posture)
		}
		return scanner.Err()
	},
}

// ─── helpers ───

func apiGet(addr string, path string, params url.Values) (*http.Response, error) {
	u := fmt.Sprintf("http://%s%s", addr, path)
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	resp, err := http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon at %s: %w\n  is 'raven serve' running?", addr, err)
	}
	return resp, nil
}

func formatASPath(path []uint32) string {
	if len(path) == 0 {
		return "-"
	}
	parts := make([]string, len(path))
	for i, asn := range path {
		parts[i] = fmt.Sprintf("%d", asn)
	}
	return strings.Join(parts, " ")
}

func init() {
	// serve flags
	serveCmd.Flags().Bool("demo", false, "use test VRPs instead of live RTR connection")

	// routes flags
	routesCmd.Flags().String("prefix", "", "filter by prefix (e.g. 1.0.0.0/24)")
	routesCmd.Flags().Uint32("origin-asn", 0, "filter by origin ASN")
	routesCmd.Flags().String("peer", "", "filter by BMP peer address")
	routesCmd.Flags().String("posture", "", "filter by security posture")
	routesCmd.Flags().String("format", "table", "output format: table, json")

	// validate flags
	validateCmd.Flags().String("prefix", "", "prefix to validate (required)")
	validateCmd.Flags().Uint32("origin-asn", 0, "origin ASN to validate")
	validateCmd.Flags().String("rtr", "", "RTR cache address (for one-shot mode)")

	// watch flags
	watchCmd.Flags().String("prefix", "", "filter by prefix")
	watchCmd.Flags().Uint32("origin-asn", 0, "filter by origin ASN")
	watchCmd.Flags().String("peer", "", "filter by peer")
	watchCmd.Flags().String("posture", "", "filter by posture")
}