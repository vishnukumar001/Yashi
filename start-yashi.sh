#!/usr/bin/env bash
# ===========================================================================
# Yashi — macOS Development Launcher
# ===========================================================================
# Starts both the Desktop Control Agent (Python) and the Node web server,
# then opens the browser to the UI.
#
# Usage:
#   chmod +x start-yashi.sh       # first time only
#   ./start-yashi.sh              # launch everything
# ===========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}              YASHI ALL-IN-ONE LAUNCHER (macOS)${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""

# --- 1. Find Python interpreter -----------------------------------------------
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "${RED}ERROR: No Python interpreter found. Install Python 3 from python.org or Homebrew.${NC}"
    exit 1
fi

echo -e "${BLUE}[1/4] Cleaning up any old instances...${NC}"
# Kill any existing processes on our ports
lsof -ti :3000 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -ti :8765 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1
echo -e "      Done."
echo ""

# --- 2. Check Python dependencies --------------------------------------------
echo -e "${BLUE}[2/4] Checking Python dependencies...${NC}"
if ! "$PYTHON" -c "import fastapi" 2>/dev/null; then
    echo -e "${YELLOW}      Installing desktop agent dependencies...${NC}"
    "$PYTHON" -m pip install -r desktop_agent/requirements.txt --quiet
fi
echo -e "${GREEN}      Desktop agent dependencies OK.${NC}"
echo ""

# --- 3. Start the Desktop Control Agent (Python, port 8765) ------------------
echo -e "${BLUE}[3/4] Starting Desktop Control Agent (Python, port 8765)...${NC}"

AGENT_PID=""
"$PYTHON" -m uvicorn desktop_agent.main:app --host 127.0.0.1 --port 8765 &
AGENT_PID=$!

# Wait for agent to be ready
READY=false
for i in $(seq 1 15); do
    sleep 1
    if curl -sf http://127.0.0.1:8765/health >/dev/null 2>&1; then
        READY=true
        echo -e "${GREEN}      Desktop Agent is ONLINE — tools ready!${NC}"
        break
    fi
    echo -e "      ...waiting $i/15"
done

if [ "$READY" = false ]; then
    echo -e "${YELLOW}      [WARNING] Desktop Agent did not respond in time.${NC}"
    echo -e "${YELLOW}      Yashi will still run, but desktop control may be unavailable.${NC}"
fi
echo ""

# --- 4. Start the Node web server and open the UI ----------------------------
echo -e "${BLUE}[4/4] Starting Yashi Server (Node, port 3000)...${NC}"

# Check for production bundle vs development mode
USE_DEV=false
for arg in "$@"; do
    if [ "$arg" = "--dev" ]; then
        USE_DEV=true
    fi
done

SERVER_PID=""
if [ "$USE_DEV" = false ] && [ -f "dist/server.cjs" ] && [ -f "dist/index.html" ]; then
    echo -e "${GREEN}      Running optimized production server (dist/server.cjs)...${NC}"
    NODE_ENV=production node dist/server.cjs &
    SERVER_PID=$!
else
    echo -e "${YELLOW}      Running development server (Vite + tsx)...${NC}"
    npx tsx server.ts &
    SERVER_PID=$!
fi

# Poll until port 3000 responds before opening Safari/browser
echo -e "      Waiting for Yashi UI to become ready..."
SERVER_READY=false
for i in $(seq 1 30); do
    sleep 0.5
    if curl -sf http://localhost:3000 >/dev/null 2>&1 || curl -sf http://127.0.0.1:3000 >/dev/null 2>&1; then
        SERVER_READY=true
        echo -e "${GREEN}      Yashi Server is ONLINE!${NC}"
        break
    fi
    echo -e "      ...waiting for server ($i/30)"
done

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "  Desktop Agent : http://127.0.0.1:8765"
echo -e "  Yashi UI      : http://localhost:3000"
echo -e "${GREEN}============================================================${NC}"
echo ""

if [ "$SERVER_READY" = true ]; then
    echo -e "${GREEN}Opening Yashi in your default browser...${NC}"
    open http://localhost:3000 &
else
    echo -e "${YELLOW}[WARNING] Server did not respond within 15 seconds.${NC}"
    echo -e "${YELLOW}Opening browser anyway — you may need to refresh once started.${NC}"
    open http://localhost:3000 &
fi

echo -e "  Press Ctrl+C to stop both servers."
echo ""

# Handle cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    kill "$SERVER_PID" 2>/dev/null || true
    kill "$AGENT_PID" 2>/dev/null || true
    lsof -ti :3000 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti :8765 2>/dev/null | xargs kill -9 2>/dev/null || true
    echo -e "${GREEN}Yashi stopped.${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for either process to exit
wait -n "$SERVER_PID" "$AGENT_PID" 2>/dev/null || true
cleanup
