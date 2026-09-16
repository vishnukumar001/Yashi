"""
Yashi Desktop Control Agent — FastAPI entrypoint.

Single dispatch endpoint POST /execute { tool, args } -> { result } | { error }.
Yashi's Node bridge (server.ts) calls this over HTTP on 127.0.0.1:8765.

Run:
    uvicorn desktop_agent.main:app --host 127.0.0.1 --port 8765
or:
    python -m desktop_agent.main
"""

from __future__ import annotations

import logging
import os
import sys
import traceback
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import __version__
from .registry import DESKTOP_TOOL_NAMES, TOOLS, ToolError, load_all

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("yashi.desktop")

# Load the expected auth token from environment (set by Electron -> Node -> Python)
EXPECTED_TOKEN = os.environ.get("YASHI_AGENT_TOKEN", "")

async def verify_token(authorization: str | None = Header(None)) -> None:
    """Verify the Bearer token on protected endpoints."""
    if not EXPECTED_TOKEN:
        # Token not configured — allow in dev but log warning
        log.warning("AGENT_TOKEN not set; authentication disabled")
        return
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization format")
    token = authorization[7:]  # Remove "Bearer "
    if token != EXPECTED_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


# Load all tool modules so their handlers register before the app starts.
load_all()
log.info("Loaded %d desktop tools: %s", len(TOOLS), ", ".join(sorted(TOOLS)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Yashi Desktop Control Agent v%s starting up.", __version__)
    yield
    # Clean shutdown of the Playwright browser if it was started.
    try:
        from .tools_browser import shutdown_browser

        shutdown_browser()
    except Exception as e:  # noqa: BLE001
        log.warning("Browser shutdown error: %s", e)
    log.info("Yashi Desktop Control Agent stopped.")


app = FastAPI(
    title="Yashi Desktop Control Agent",
    version=__version__,
    description="JARVIS-style desktop automation backend for Yashi.",
    lifespan=lifespan,
)

# Same-origin Node bridge is the only caller; allow localhost origins flexibly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ExecuteRequest(BaseModel):
    tool: str
    args: Dict[str, Any] = {}


class ExecuteResponse(BaseModel):
    ok: bool
    result: Any = None
    error: str | None = None
    tool: str


@app.get("/health")
async def health(authorization: str | None = Header(None)) -> Dict[str, Any]:
    await verify_token(authorization)
    return {
        "status": "ok",
        "name": "Yashi Desktop Control Agent",
        "version": __version__,
        "tools": sorted(TOOLS.keys()),
        "tool_count": len(TOOLS),
    }


@app.get("/tools")
async def list_tools(authorization: str | None = Header(None)) -> Dict[str, Any]:
    await verify_token(authorization)
    return {"tools": sorted(TOOLS.keys()), "count": len(TOOLS)}


@app.post("/execute", response_model=ExecuteResponse)
async def execute(
    req: ExecuteRequest,
    authorization: str | None = Header(None),
) -> ExecuteResponse:
    await verify_token(authorization)
    tool = req.tool
    args = req.args or {}
    log.info("EXEC tool=%s args=%s", tool, _short_args(args))

    if tool not in TOOLS:
        known = ", ".join(sorted(TOOLS.keys()))
        return ExecuteResponse(
            ok=False,
            error=f"Unknown tool '{tool}'. Known tools: {known}",
            tool=tool,
        )

    handler = TOOLS[tool]
    try:
        out = handler(args)
    except ToolError as e:
        log.warning("ToolError in %s: %s", tool, e.message)
        return ExecuteResponse(ok=False, error=e.message, tool=tool)
    except Exception as e:  # noqa: BLE001
        log.error("Unhandled error in %s: %s\n%s", tool, e, traceback.format_exc())
        return ExecuteResponse(
            ok=False,
            error=f"Internal error in {tool}: {e}",
            tool=tool,
        )

    # Handlers return dicts like {"result": "..."}; pass the whole payload.
    result_text = ""
    if isinstance(out, dict):
        result_text = str(out.get("result", out))
    else:
        result_text = str(out)
    log.info("DONE tool=%s -> %s", tool, result_text[:160])

    return ExecuteResponse(ok=True, result=out, tool=tool)


def _short_args(args: Dict[str, Any]) -> str:
    """Compact, log-safe representation of args (truncate long values)."""
    parts = []
    for k, v in args.items():
        s = repr(v)
        if len(s) > 60:
            s = s[:60] + "…"
        parts.append(f"{k}={s}")
    return "{" + ", ".join(parts) + "}"


def main() -> None:
    """Allow `python -m desktop_agent.main` to launch uvicorn."""
    import uvicorn

    host = os.environ.get("YASHI_AGENT_HOST", "127.0.0.1")
    port = int(os.environ.get("YASHI_AGENT_PORT", "8765"))
    log.info("Launching uvicorn on %s:%d", host, port)
    uvicorn.run(
        "desktop_agent.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
