"""
cipherDNS Async UDP DNS Server
Asynchronous DNS Server receiving standard UDP queries on port 53,
managing cache lookup, DoH forwarding, and real-time event broadcasting.
"""

import asyncio
import logging
import time
from typing import Optional, Callable, Dict, Any, List
import dns.message
import dns.rdatatype
import dns.rcode

from cipherdns.config import (
    DEFAULT_DNS_HOST,
    DEFAULT_DNS_PORT,
    DEFAULT_DOH_PROVIDER,
)
from cipherdns.core.cache import DNSCache
from cipherdns.core.doh_client import DoHClient
from cipherdns.core.plaintext_client import PlaintextClient

logger = logging.getLogger("cipherdns.server")


class DNSProtocol(asyncio.DatagramProtocol):
    """Async UDP Protocol for receiving and responding to DNS datagrams."""

    def __init__(self, server: "DNSServer"):
        self.server = server
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        # Process query in async task
        asyncio.create_task(self.server.handle_query(data, addr, self.transport))

    def error_received(self, exc: Exception):
        logger.error(f"UDP datagram error: {exc}")


class DNSServer:
    """Core DNS Server managing resolution pipeline and state."""

    def __init__(
        self,
        host: str = DEFAULT_DNS_HOST,
        port: int = DEFAULT_DNS_PORT,
        cache: Optional[DNSCache] = None,
        doh_client: Optional[DoHClient] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.host: str = host
        self.port: int = port
        self.actual_port: int = port
        self.cache: DNSCache = cache or DNSCache()
        self.doh_client: DoHClient = doh_client or DoHClient()
        self.plaintext_client: PlaintextClient = PlaintextClient()
        self.event_callback: Optional[Callable[[Dict[str, Any]], None]] = event_callback

        # Mode: True = cipherDNS (DoH enabled), False = Standard Plaintext DNS
        self.cipher_mode_enabled: bool = True
        self.is_running: bool = False
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.query_history: List[Dict[str, Any]] = []

    def set_mode(self, cipher_enabled: bool):
        """Toggles between cipherDNS (DoH) and Plaintext DNS mode."""
        self.cipher_mode_enabled = cipher_enabled
        self._notify_event({
            "type": "mode_change",
            "cipher_mode": self.cipher_mode_enabled,
            "provider": self.doh_client.current_provider,
            "timestamp": time.time(),
        })

    def set_doh_provider(self, provider_key: str) -> bool:
        """Changes active upstream DoH provider."""
        ok = self.doh_client.set_provider(provider_key)
        if ok:
            self._notify_event({
                "type": "provider_change",
                "cipher_mode": self.cipher_mode_enabled,
                "provider": provider_key,
                "provider_info": self.doh_client.get_provider_info(),
                "timestamp": time.time(),
            })
        return ok

    def _notify_event(self, event: Dict[str, Any]):
        """Dispatches event to callback (e.g. WebSocket manager)."""
        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception as e:
                logger.debug(f"Event callback error: {e}")

    async def start(self) -> int:
        """Starts the UDP DNS listener. Returns actual bound port."""
        loop = asyncio.get_running_loop()

        # Try desired host & port, and candidate fallback (e.g. 127.0.0.1:53 if 0.0.0.0:53 is occupied by systemd-resolved)
        candidates = [(self.host, self.port)]
        if self.host == "0.0.0.0" and self.port == 53:
            candidates.append(("127.0.0.1", 53))

        last_error = None
        for host, port in candidates:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: DNSProtocol(self),
                    local_addr=(host, port),
                )
                self.transport = transport
                self.host = host
                self.actual_port = port
                self.is_running = True
                logger.info(f"cipherDNS server listening on {self.host}:{self.actual_port}")
                return self.actual_port
            except (PermissionError, OSError) as e:
                last_error = e
                continue

        # Fallback for unprivileged or unavailable port
        fallback_port = 5300 if self.port in (53, 5353) else self.port + 1000
        logger.warning(
            f"Cannot bind to port {self.port} on {self.host} ({last_error}). "
            f"Falling back to unprivileged port {fallback_port}."
        )
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DNSProtocol(self),
            local_addr=(self.host, fallback_port),
        )
        self.transport = transport
        self.actual_port = fallback_port
        self.is_running = True
        logger.info(f"cipherDNS server listening on {self.host}:{self.actual_port} (Fallback)")
        return self.actual_port

    async def stop(self):
        """Stops the DNS listener and closes resources."""
        if self.transport:
            self.transport.close()
            self.transport = None
        self.is_running = False
        await self.doh_client.close()
        logger.info("cipherDNS server stopped")

    async def handle_query(
        self, data: bytes, addr: tuple, transport: Optional[asyncio.DatagramTransport]
    ):
        """Handles an incoming DNS query datagram."""
        start_time = time.perf_counter()
        client_ip, client_port = addr[0], addr[1]

        try:
            req_msg = dns.message.from_wire(data)
        except Exception as e:
            logger.warning(f"Malformed DNS query received from {addr}: {e}")
            return

        if not req_msg.question:
            return

        question = req_msg.question[0]
        qname = question.name.to_text().rstrip(".").lower()
        qtype = question.rdtype
        qtype_name = dns.rdatatype.to_text(qtype)
        qclass = question.rdclass
        query_id = req_msg.id

        # 1. Check TTL Cache
        is_hit, cached_wire, rem_ttl, cached_answers = self.cache.get(
            qname, qtype, qclass, query_id
        )

        if is_hit and cached_wire is not None:
            # Cache Hit!
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            if transport and not transport.is_closing():
                transport.sendto(cached_wire, addr)

            event = {
                "type": "query_resolved",
                "action": "CACHE_HIT",
                "domain": qname,
                "qtype": qtype_name,
                "answers": cached_answers,
                "latency_ms": round(elapsed_ms, 2),
                "remaining_ttl": rem_ttl,
                "client_ip": client_ip,
                "timestamp": time.time(),
                "message": f"Successfully delivered the cached entry for {qname}",
            }
            self._record_history(event)
            self._notify_event(event)
            return

        # 2. Cache Miss: Initiate Upstream Query
        provider_name = (
            self.doh_client.get_provider_info()["name"]
            if self.cipher_mode_enabled
            else "Standard DNS (Plaintext)"
        )

        start_event = {
            "type": "query_start",
            "action": "DOH_START" if self.cipher_mode_enabled else "PLAINTEXT_START",
            "domain": qname,
            "qtype": qtype_name,
            "client_ip": client_ip,
            "provider": provider_name,
            "timestamp": time.time(),
            "message": (
                f"Making a DoH request to {provider_name}..."
                if self.cipher_mode_enabled
                else f"Making a plaintext DNS request to {provider_name}..."
            ),
        }
        self._notify_event(start_event)

        # Forward query
        if self.cipher_mode_enabled:
            resp_msg, wire_resp, upstream_latency, err = await self.doh_client.query(
                data, query_id
            )
        else:
            resp_msg, wire_resp, upstream_latency, err = await self.plaintext_client.query(
                data, query_id
            )

        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Send response back to client
        if wire_resp and transport and not transport.is_closing():
            transport.sendto(wire_resp, addr)

        # Process answers
        answers: List[str] = []
        if resp_msg and resp_msg.answer:
            for rrset in resp_msg.answer:
                for rdata in rrset:
                    answers.append(rdata.to_text())

        # Update cache if valid response (NOERROR or NXDOMAIN)
        if resp_msg and wire_resp and err is None:
            if resp_msg.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                self.cache.put(qname, qtype, qclass, resp_msg, wire_resp)

        success_event = {
            "type": "query_resolved",
            "action": (
                "DOH_RESOLVE" if self.cipher_mode_enabled else "PLAINTEXT_RESOLVE"
            ),
            "domain": qname,
            "qtype": qtype_name,
            "answers": answers,
            "latency_ms": round(total_latency_ms, 2),
            "client_ip": client_ip,
            "provider": provider_name,
            "error": err,
            "timestamp": time.time(),
            "message": (
                f"Securely retrieved IP for {qname}"
                if (self.cipher_mode_enabled and not err)
                else (
                    f"Retrieved IP for {qname} via plaintext DNS"
                    if not err
                    else f"Resolution error for {qname}: {err}"
                )
            ),
        }
        self._record_history(success_event)
        self._notify_event(success_event)

    def _record_history(self, event: Dict[str, Any]):
        """Records query event in recent history (max 200)."""
        self.query_history.insert(0, event)
        if len(self.query_history) > 200:
            self.query_history.pop()

    def get_status(self) -> Dict[str, Any]:
        """Returns complete server status snapshot."""
        return {
            "is_running": self.is_running,
            "host": self.host,
            "port": self.actual_port,
            "cipher_mode_enabled": self.cipher_mode_enabled,
            "current_provider": self.doh_client.current_provider,
            "provider_info": self.doh_client.get_provider_info(),
            "stats": self.cache.get_stats(),
        }
