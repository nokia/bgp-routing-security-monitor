#!/usr/bin/env bash
# 02-route-leak.sh — demonstrate ASPA route leak detection
#
# Scenario: AS2121 (internet) originates 193.0.0.0/21
# AS2121's ASPA says only AS3333 is its authorized provider
# But the route reaches edge via AS65000 (unauthorized provider)
# RAVEN detects: AS2121→AS65000 hop is UNAUTHORIZED → path-suspect
#
# This route is ALWAYS present in the demo lab — no injection needed.
# Run this script to highlight it and explain the detection.

RAVEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAVEN_BIN="$RAVEN_DIR/raven"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           ASPA ROUTE LEAK DETECTION DEMO                ║${NC}"
echo -e "${BLUE}║                                                          ║${NC}"
echo -e "${BLUE}║  Prefix:   193.0.0.0/21                                  ║${NC}"
echo -e "${BLUE}║  Origin:   AS2121                                        ║${NC}"
echo -e "${BLUE}║  AS2121 ASPA providers: AS3333 only                      ║${NC}"
echo -e "${BLUE}║  Actual path: AS2121 → AS65000 → AS65001                 ║${NC}"
echo -e "${BLUE}║  Violation: AS65000 is NOT an authorized provider        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}Full route table:${NC}"
"$RAVEN_BIN" routes
echo ""

echo -e "${RED}Path-suspect routes (ASPA violations):${NC}"
"$RAVEN_BIN" routes --posture path-suspect
echo ""

echo -e "${GREEN}RAVEN detected the route leak via ASPA validation.${NC}"
echo -e "${GREEN}ROV alone would not catch this — the origin AS2121 is valid.${NC}"
echo -e "${GREEN}Only ASPA reveals the unauthorized AS path.${NC}"
