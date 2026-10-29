"""
cipherDNS Standard Plaintext DNS Client
Implements standard unencrypted UDP DNS resolution over port 53.
Used for comparative demonstration and demonstrating cleartext information leakage.
"""

import time
import socket
import asyncio
from typing import Optional, Tuple
import dns.message
import dns.rcode

from cipherdns.config import PLAINTEXT_UPSTREAMS, PLAINTEXT_TIMEOUT_SECONDS


class PlaintextClient:
    """Standard UDP DNS client for unencrypted query forwarding."""

    def __init__(self, upstream_host: str = "8.8.8.8", upstream_port: int = 53):
        self.upstream_host: str = upstream_host
        self.upstream_port: int = upstream_port

    async def query(
        self, wire_query: bytes, query_id: int
    ) -> Tuple[Optional[dns.message.Message], Optional[bytes], float, Optional[str]]:
        """
        Sends query over unencrypted standard UDP port 53.
        Returns: (parsed_response_msg, raw_wire_response, latency_ms, error_message)
        """
        start_time = time.perf_counter()
        loop = asyncio.get_running_loop()

        def _sync_query():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(PLAINTEXT_TIMEOUT_SECONDS)
            try:
                sock.sendto(wire_query, (self.upstream_host, self.upstream_port))
                data, _ = sock.recvfrom(4096)
                return data, None
            except socket.timeout:
                return None, f"Plaintext DNS query to {self.upstream_host}:53 timed out ({PLAINTEXT_TIMEOUT_SECONDS}s)"
            except Exception as e:
                return None, f"Plaintext DNS socket error: {e}"
            finally:
                sock.close()

        try:
            raw_data, err = await loop.run_in_executor(None, _sync_query)
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if err or raw_data is None:
                servfail = self._build_servfail(query_id)
                return servfail, servfail.to_wire(), latency_ms, err or "No data received"

            parsed_msg = dns.message.from_wire(raw_data)
            parsed_msg.id = query_id
            return parsed_msg, parsed_msg.to_wire(), latency_ms, None

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            servfail = self._build_servfail(query_id)
            return servfail, servfail.to_wire(), latency_ms, str(e)

    def _build_servfail(self, query_id: int) -> dns.message.Message:
        msg = dns.message.Message(id=query_id)
        msg.set_rcode(dns.rcode.SERVFAIL)
        msg.flags |= dns.flags.QR
        msg.flags |= dns.flags.RA
        return msg

