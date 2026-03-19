#!/usr/bin/env bash
# Deploy the RAVEN demo lab and start RAVEN
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== RAVEN Demo Lab ==="
echo ""

# Step 1: Build RAVEN if needed
if [ ! -f "$PROJECT_DIR/raven" ]; then
    echo "Building RAVEN..."
    cd "$PROJECT_DIR"
    go build -o raven ./cmd/raven
    echo "✓ RAVEN built"
fi

# Step 2: Deploy the containerlab topology
echo ""
echo "Deploying containerlab topology..."
cd "$SCRIPT_DIR"
sudo containerlab deploy -t raven-demo.clab.yaml --reconfigure

echo ""
echo "Waiting 10s for BGP sessions to establish..."
sleep 10

# Step 3: Check BGP is up
echo ""
echo "=== BGP Status on edge router ==="
sudo docker exec clab-raven-demo-edge vtysh -c "show bgp summary"

echo ""
echo "=== Routes on edge router ==="
sudo docker exec clab-raven-demo-edge vtysh -c "show ip bgp"

echo ""
echo "=== BMP Status on edge router ==="
sudo docker exec clab-raven-demo-edge vtysh -c "show bmp"

# Step 4: Print instructions
echo ""
echo "============================================"
echo "  Lab is running!"
echo ""
echo "  Now start RAVEN in another terminal:"
echo ""
echo "    cd $PROJECT_DIR"
echo "    ./raven serve --config raven.yaml"
echo ""
echo "  Then check routes:"
echo "    # (in a third terminal)"
echo "    # Watch RAVEN logs for BMP messages"
echo ""
echo "  To destroy the lab:"
echo "    cd $SCRIPT_DIR"
echo "    sudo containerlab destroy -t raven-demo.clab.yaml"
echo "============================================"
