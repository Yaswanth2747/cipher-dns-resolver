"""
cipherDNS DNS-over-HTTPS (DoH) Client
Implements RFC 8484 (DNS Queries over HTTPS) with strict TLS certificate verification,
detailed cryptographic evidence extraction, and resilient error/timeout handling.
"""

import time
import ssl
import socket
import certifi
import httpx
from typing import Optional, Dict, Any, Tuple
import dns.message
import dns.rcode

from cipherdns.config import (
    DOH_PROVIDERS,
    DEFAULT_DOH_PROVIDER,
    DOH_TIMEOUT_SECONDS,
)


class DoHClient:
    """High-performance async DNS-over-HTTPS client."""

    def __init__(self, current_provider: str = DEFAULT_DOH_PROVIDER):
        self.current_provider: str = current_provider
        self._http_client: Optional[httpx.AsyncClient] = None
        self._tls_cache: Dict[str, Dict[str, Any]] = {}

    async def _get_client(self) -> httpx.AsyncClient:
        """Initializes or returns the cached async HTTP/2 client with strict TLS verification."""
        if self._http_client is None or self._http_client.is_closed:
            # Create SSL context with verified root CA store
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            self._http_client = httpx.AsyncClient(
                http2=True,
                verify=ssl_context,
                timeout=httpx.Timeout(DOH_TIMEOUT_SECONDS, connect=2.0),
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                    "User-Agent": "cipherDNS/1.0 (+https://github.com/cipherdns)",
                },
            )
        return self._http_client

    def set_provider(self, provider_key: str) -> bool:
        """Switches active DoH provider dynamically."""
        if provider_key in DOH_PROVIDERS:
            self.current_provider = provider_key
            return True
        return False

    def get_provider_info(self) -> Dict[str, Any]:
        """Returns metadata for the current provider."""
        return DOH_PROVIDERS.get(self.current_provider, DOH_PROVIDERS[DEFAULT_DOH_PROVIDER])

    async def query(
        self, wire_query: bytes, query_id: int
    ) -> Tuple[Optional[dns.message.Message], Optional[bytes], float, Optional[str]]:
        """
        Executes a DoH query against the active provider.
        Returns: (parsed_response_msg, raw_wire_response, latency_ms, error_message)
        """
        provider = self.get_provider_info()
        url = provider["url"]
        client = await self._get_client()

        # Extract hostname and path
        host_and_path = url.split("://")[1]
        hostname = host_and_path.split("/")[0]
        path = "/" + host_and_path.split("/", 1)[1] if "/" in host_and_path else "/dns-query"
        bootstrap_ips = provider.get("bootstrap_ips", [])

        start_time = time.perf_counter()

        try:
            # If bootstrap IP is configured, connect directly to IP with SNI extension
            # to avoid recursive DNS lookup deadlocks when system DNS points to localhost
            if bootstrap_ips:
                target_url = f"https://{bootstrap_ips[0]}{path}"
                req = client.build_request(
                    "POST",
                    target_url,
                    content=wire_query,
                    headers={"Host": hostname},
                )
                req.extensions["sni_hostname"] = hostname
                response = await client.send(req)
            else:
                response = await client.post(url, content=wire_query)

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if response.status_code != 200:
                err_msg = f"Upstream DoH HTTP error {response.status_code} from {provider['name']}"
                servfail = self._build_servfail(query_id)
                return servfail, servfail.to_wire(), latency_ms, err_msg

            wire_response = response.content

            # Validate wire-format response
            try:
                parsed_msg = dns.message.from_wire(wire_response)
                # Match query ID to client's query ID
                parsed_msg.id = query_id
                matched_wire = parsed_msg.to_wire()
                return parsed_msg, matched_wire, latency_ms, None
            except Exception as e:
                err_msg = f"Invalid/corrupted wire-format response from {provider['name']}: {e}"
                servfail = self._build_servfail(query_id)
                return servfail, servfail.to_wire(), latency_ms, err_msg

        except httpx.TimeoutException:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            err_msg = f"Timeout ({DOH_TIMEOUT_SECONDS}s) querying upstream {provider['name']}"
            servfail = self._build_servfail(query_id)
            return servfail, servfail.to_wire(), latency_ms, err_msg

        except httpx.ConnectError as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            err_msg = f"Connection failure to {provider['name']}: {e}"
            servfail = self._build_servfail(query_id)
            return servfail, servfail.to_wire(), latency_ms, err_msg

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            err_msg = f"Unexpected upstream error from {provider['name']}: {e}"
            servfail = self._build_servfail(query_id)
            return servfail, servfail.to_wire(), latency_ms, err_msg

    def _build_servfail(self, query_id: int) -> dns.message.Message:
        """Constructs a RFC-compliant DNS SERVFAIL message."""
        msg = dns.message.Message(id=query_id)
        msg.set_rcode(dns.rcode.SERVFAIL)
        msg.flags |= dns.flags.QR  # Query Response flag
        msg.flags |= dns.flags.RA  # Recursion Available
        return msg

    def get_tls_certificate_evidence(self, provider_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspects and validates the upstream DoH server's TLS certificate chain.
        Provides technical evidence for the report Appendix and security audit.
        """
        target_provider_key = provider_key or self.current_provider
        provider = DOH_PROVIDERS.get(target_provider_key, DOH_PROVIDERS[DEFAULT_DOH_PROVIDER])

        # Parse host from URL
        url = provider["url"]
        hostname = url.split("://")[1].split("/")[0]
        port = 443
        bootstrap_ips = provider.get("bootstrap_ips", [])
        connect_target = bootstrap_ips[0] if bootstrap_ips else hostname

        try:
            # Build verified SSL context
            context = ssl.create_default_context(cafile=certifi.where())
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((connect_target, port), timeout=4.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    san = [x[1] for x in cert.get("subjectAltName", ()) if x[0] == "DNS"]

                    evidence = {
                        "provider": provider["name"],
                        "hostname": hostname,
                        "port": port,
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "cipher_protocol": cipher[1] if cipher else "Unknown",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "validation_status": "VALID_TRUSTED",
                        "ca_bundle": "certifi (Mozilla Root CA Store)",
                        "subject_cn": subject.get("commonName", ""),
                        "issuer_org": issuer.get("organizationName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "subject_alt_names": san[:6],  # first few SANs
                        "serial_number": cert.get("serialNumber", ""),
                    }
                    self._tls_cache[target_provider_key] = evidence
                    return evidence

        except Exception as e:
            return {
                "provider": provider["name"],
                "hostname": hostname,
                "port": port,
                "validation_status": "FAILED",
                "error": str(e),
            }

    async def close(self):
        """Closes HTTP client connection pool."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

