"""
cipherDNS FastAPI Web Application
Provides the real-time dark-mode dashboard, WebSocket event streamer,
cache controller, and Zeek privacy analysis interface.
"""

import os
import json
import asyncio
from typing import Set, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import dns.message
import dns.rdatatype

from cipherdns.config import DOH_PROVIDERS
from cipherdns.core.server import DNSServer
from cipherdns.core.cache import DNSCache
from cipherdns.core.doh_client import DoHClient
from cipherdns.analysis.zeek_analyzer import ZeekAnalyzer
from cipherdns.core.system_dns import (
    get_system_dns_status,
    enable_system_dns,
    disable_system_dns,
)

# Initialize FastAPI App
app = FastAPI(title="cipherDNS Dashboard", version="1.0.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Shared Global Server Reference (injected at startup)
dns_server: Optional[DNSServer] = None
zeek_analyzer = ZeekAnalyzer()


class ConnectionManager:
    """Manages active WebSocket client connections for real-time live events."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        msg_str = json.dumps(message)
        dead = []
        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_text(msg_str)
                except Exception:
                    dead.append(connection)
            for d in dead:
                self.active_connections.discard(d)


ws_manager = ConnectionManager()


def event_broadcaster(event: Dict[str, Any]):
    """Dispatches server events to all connected WebSocket clients."""
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            asyncio.create_task(ws_manager.broadcast(event))
    except RuntimeError:
        pass


class ModePayload(BaseModel):
    enabled: bool


class ProviderPayload(BaseModel):
    provider: str


class TestQueryPayload(BaseModel):
    domain: str
    record_type: str = "A"


class ZeekAuditPayload(BaseModel):
    domain: str = "netflix.com"


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """Renders the main dashboard."""
    status = dns_server.get_status() if dns_server else {}
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "providers": DOH_PROVIDERS,
            "status": status,
        },
    )


@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket stream for real-time status, circular loading state, and cache table updates."""
    await ws_manager.connect(websocket)
    try:
        # Send initial status & cache state upon connecting
        if dns_server:
            init_event = {
                "type": "init_state",
                "status": dns_server.get_status(),
                "cache_entries": dns_server.cache.get_entries(),
                "recent_history": dns_server.query_history[:15],
            }
            await websocket.send_text(json.dumps(init_event))

        while True:
            # Keep connection alive & handle incoming pings
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)


@app.get("/api/status")
async def get_status():
    """Returns DNS server status and stats."""
    if not dns_server:
        return JSONResponse({"error": "DNS Server not initialized"}, status_code=500)
    return JSONResponse(dns_server.get_status())


@app.post("/api/mode")
async def set_mode(payload: ModePayload):
    """Toggles cipherDNS (DoH) vs Plaintext mode."""
    if not dns_server:
        return JSONResponse({"error": "DNS Server not initialized"}, status_code=500)
    dns_server.set_mode(payload.enabled)
    return JSONResponse({"success": True, "cipher_mode_enabled": dns_server.cipher_mode_enabled})


@app.post("/api/provider")
async def set_provider(payload: ProviderPayload):
    """Switches active upstream DoH provider."""
    if not dns_server:
        return JSONResponse({"error": "DNS Server not initialized"}, status_code=500)
    ok = dns_server.set_doh_provider(payload.provider)
    if not ok:
        return JSONResponse({"error": "Invalid provider key"}, status_code=400)
    return JSONResponse({
        "success": True,
        "provider": dns_server.doh_client.current_provider,
        "provider_info": dns_server.doh_client.get_provider_info(),
    })


@app.get("/api/cache")
async def get_cache():
    """Returns all active cached entries with remaining TTLs, most recent at top."""
    if not dns_server:
        return JSONResponse({"error": "DNS Server not initialized"}, status_code=500)
    entries = dns_server.cache.get_entries()
    stats = dns_server.cache.get_stats()
    return JSONResponse({"entries": entries, "stats": stats})


@app.post("/api/cache/clear")
async def clear_cache():
    """Clears all cached entries."""
    if not dns_server:
        return JSONResponse({"error": "DNS Server not initialized"}, status_code=500)
    count = dns_server.cache.clear()
    await ws_manager.broadcast({
        "type": "cache_cleared",
        "count": count,
        "stats": dns_server.cache.get_stats(),
    })
    return JSONResponse({"success": True, "cleared_entries": count})


@app.post("/api/test-query")
async def execute_test_query(payload: TestQueryPayload):
    """Executes a test DNS query internally to simulate incoming queries for testing/demo."""
    if not dns_server:
        return JSONResponse({"error": "DNS Server not initialized"}, status_code=500)

    domain = payload.domain.strip().rstrip(".")
    qtype = dns.rdatatype.from_text(payload.record_type.upper())
    req_msg = dns.message.make_query(domain, qtype)
    req_wire = req_msg.to_wire()

    # Process query through internal pipeline (simulating local client)
    fake_addr = ("127.0.0.1", 54321)
    await dns_server.handle_query(req_wire, fake_addr, transport=None)

    # Return updated cache entries
    return JSONResponse({
        "success": True,
        "domain": domain,
        "record_type": payload.record_type.upper(),
        "entries": dns_server.cache.get_entries(),
        "stats": dns_server.cache.get_stats(),
    })


@app.post("/api/zeek/audit")
async def run_zeek_audit(payload: ZeekAuditPayload):
    """Executes comparative Zeek packet analysis on chosen domain."""
    domain = payload.domain.strip() or "netflix.com"
    loop = asyncio.get_running_loop()
    report = await loop.run_in_executor(None, zeek_analyzer.audit_privacy_comparison, domain)
    return JSONResponse(report)


@app.get("/api/tls/evidence")
async def get_tls_evidence():
    """Fetches cryptographic TLS validation details for active DoH provider."""
    if not dns_server:
        return JSONResponse({"error": "DNS Server not initialized"}, status_code=500)
    loop = asyncio.get_running_loop()
    evidence = await loop.run_in_executor(
        None, dns_server.doh_client.get_tls_certificate_evidence
    )
    return JSONResponse(evidence)


class SystemDnsPayload(BaseModel):
    enable: bool


@app.get("/api/system-dns")
async def api_get_system_dns():
    """Checks whether the operating system DNS is routed to cipherDNS."""
    loop = asyncio.get_running_loop()
    status = await loop.run_in_executor(None, get_system_dns_status)
    return JSONResponse(status)


@app.post("/api/system-dns")
async def api_set_system_dns(payload: SystemDnsPayload):
    """Enables or disables system-wide DNS routing to cipherDNS (127.0.0.1)."""
    loop = asyncio.get_running_loop()
    if payload.enable:
        res = await loop.run_in_executor(None, enable_system_dns)
    else:
        res = await loop.run_in_executor(None, disable_system_dns)
    await ws_manager.broadcast({
        "type": "system_dns_change",
        "status": res.get("status", {}),
    })
    return JSONResponse(res)

