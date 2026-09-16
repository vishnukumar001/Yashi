#!/usr/bin/env bash
# ===========================================================================
# Yashi — macOS All-in-One Launcher
# ===========================================================================
# Automatically installs dependencies, sets up isolated Python virtualenv,
# starts both the Desktop Control Agent and Node server, and opens the UI.
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
CYAN='\033[0;36m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}             ⚡ YASHI ALL-IN-ONE LAUNCHER (macOS)${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# --- 1. Clean up old instances on ports 3000 and 8765 ------------------------
echo -e "${BLUE}[1/5] Cleaning up any stale ports...${NC}"
lsof -ti :3000 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -ti :8765 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1
echo -e "${GREEN}      Ports 3000 and 8765 cleared.${NC}"
echo ""

# --- 2. Check Node.js and dependencies ---------------------------------------
echo -e "${BLUE}[2/5] Checking Node.js dependencies...${NC}"
if ! command -v node &>/dev/null; then
    echo -e "${RED}ERROR: Node.js is not installed. Please install Node.js 20+ from https://nodejs.org${NC}"
    exit 1
fi

if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}      node_modules not found. Running npm install...${NC}"
    npm install
    echo -e "${GREEN}      Node dependencies installed successfully.${NC}"
else
    echo -e "${GREEN}      Node dependencies OK.${NC}"
fi
echo ""

# --- 3. Check Python and setup isolated virtual environment ------------------
echo -e "${BLUE}[3/5] Setting up Python desktop agent environment...${NC}"
SYSTEM_PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        SYSTEM_PYTHON="$candidate"
        break
    fi
done

if [ -z "$SYSTEM_PYTHON" ]; then
    echo -e "${RED}ERROR: Python 3 was not found. Please install Python 3.10+ from https://python.org or 'brew install python'.${NC}"
    exit 1
fi

# Create a local virtual environment (.venv) if one doesn't exist
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}      Creating isolated Python virtual environment in .venv...${NC}"
    "$SYSTEM_PYTHON" -m venv .venv
fi

VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"
VENV_PIP="$SCRIPT_DIR/.venv/bin/pip"

if [ ! -f "$VENV_PYTHON" ]; then
    VENV_PYTHON="$SYSTEM_PYTHON"
    VENV_PIP="$SYSTEM_PYTHON -m pip"
fi

# Install requirements into .venv if fastapi is missing
if ! "$VENV_PYTHON" -c "import fastapi" 2>/dev/null; then
    echo -e "${YELLOW}      Installing Python agent dependencies in .venv...${NC}"
    "$VENV_PIP" install -r desktop_agent/requirements.txt --quiet || "$VENV_PIP" install -r desktop_agent/requirements.txt
    echo -e "${GREEN}      Python dependencies installed.${NC}"
else
    echo -e "${GREEN}      Python desktop agent dependencies OK.${NC}"
fi

export YASHI_PYTHON="$VENV_PYTHON"
echo ""

# --- 4. Start Desktop Control Agent (FastAPI on port 8765) -------------------
echo -e "${BLUE}[4/5] Starting Desktop Control Agent (port 8765)...${NC}"
AGENT_PID=""
"$VENV_PYTHON" -m uvicorn desktop_agent.main:app --host 127.0.0.1 --port 8765 &
AGENT_PID=$!

READY=false
for i in $(seq 1 15); do
    sleep 1
    if curl -sf http://127.0.0.1:8765/health >/dev/null 2>&1; then
        READY=true
        echo -e "${GREEN}      Desktop Agent is ONLINE — 240 tools ready!${NC}"
        break
    fi
    echo -e "      ...waiting for desktop agent ($i/15)"
done

if [ "$READY" = false ]; then
    echo -e "${YELLOW}      [WARNING] Desktop Agent did not respond in time.${NC}"
    echo -e "${YELLOW}      Yashi will still run voice & web features, but local desktop control may be delayed.${NC}"
fi
echo ""

# --- 5. Start Yashi Node Server (port 3000) -----------------------------------
echo -e "${BLUE}[5/5] Starting Yashi Server (port 3000)...${NC}"
SERVER_PID=""

if [ -f "dist/server.cjs" ] && [ -f "dist/index.html" ]; then
    echo -e "${GREEN}      Running production server...${NC}"
    NODE_ENV=production node dist/server.cjs &
    SERVER_PID=$!
else
    echo -e "${GREEN}      Running development server (tsx + Vite)...${NC}"
    npm run dev &
    SERVER_PID=$!
fi

# Poll until port 3000 responds before opening browser
echo -e "      Waiting for Yashi UI to become ready..."
SERVER_READY=false
for i in $(seq 1 30); do
    sleep 0.5
    if curl -sf http://localhost:3000 >/dev/null 2>&1 || curl -sf http://127.0.0.1:3000 >/dev/null 2>&1; then
        SERVER_READY=true
        echo -e "${GREEN}      Yashi Server is ONLINE!${NC}"
        break
    fi
done

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "  Desktop Agent : http://127.0.0.1:8765"
echo -e "  Yashi UI      : http://localhost:3000"
echo -e "${CYAN}============================================================${NC}"
echo ""

if [ "$SERVER_READY" = true ]; then
    echo -e "${GREEN}Opening Yashi in your default browser...${NC}"
    open http://localhost:3000 &
else
    echo -e "${YELLOW}[NOTE] Server taking a moment to compile. Opening browser...${NC}"
    open http://localhost:3000 &
fi

echo -e "  Press Ctrl+C to stop both servers."
echo ""

cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down Yashi...${NC}"
    kill "$SERVER_PID" 2>/dev/null || true
    kill "$AGENT_PID" 2>/dev/null || true
    lsof -ti :3000 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti :8765 2>/dev/null | xargs kill -9 2>/dev/null || true
    echo -e "${GREEN}Yashi stopped.${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

wait -n "$SERVER_PID" "$AGENT_PID" 2>/dev/null || true
cleanup
