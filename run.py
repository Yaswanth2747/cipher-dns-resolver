#!/usr/bin/env python3
"""
cipherDNS Application Launcher
Starts both the Async UDP DNS Server and the FastAPI Real-Time Dashboard.
"""

import sys
import os
import argparse
import asyncio
import logging
import uvicorn

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cipherdns.config import (
    DEFAULT_DNS_HOST,
    DEFAULT_DNS_PORT,
    DEFAULT_WEB_HOST,
    DEFAULT_WEB_PORT,
    DEFAULT_DOH_PROVIDER,
    DOH_PROVIDERS,
)
from cipherdns.core.cache import DNSCache
from cipherdns.core.doh_client import DoHClient
from cipherdns.core.server import DNSServer
import cipherdns.web.app as web_module

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cipherdns.main")


async def main():
    parser = argparse.ArgumentParser(
        description="cipherDNS — Encrypted DNS-over-HTTPS Caching Resolver"
    )
    parser.add_argument(
        "--dns-host",
        default=DEFAULT_DNS_HOST,
        help=f"DNS Server listen address (default: {DEFAULT_DNS_HOST})",
    )
    parser.add_argument(
        "--dns-port",
        type=int,
        default=DEFAULT_DNS_PORT,
        help=f"DNS Server UDP port (default: {DEFAULT_DNS_PORT})",
    )
    parser.add_argument(
        "--web-host",
        default=DEFAULT_WEB_HOST,
        help=f"Web Dashboard listen address (default: {DEFAULT_WEB_HOST})",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=DEFAULT_WEB_PORT,
        help=f"Web Dashboard HTTP port (default: {DEFAULT_WEB_PORT})",
    )
    parser.add_argument(
        "--provider",
        choices=list(DOH_PROVIDERS.keys()),
        default=DEFAULT_DOH_PROVIDER,
        help=f"Default upstream DoH resolver (default: {DEFAULT_DOH_PROVIDER})",
    )
    args = parser.parse_args()

    # 1. Initialize Core Components
    cache = DNSCache()
    doh_client = DoHClient(current_provider=args.provider)

    dns_server = DNSServer(
        host=args.dns_host,
        port=args.dns_port,
        cache=cache,
        doh_client=doh_client,
        event_callback=web_module.event_broadcaster,
    )

    # Inject DNS server reference into Web App
    web_module.dns_server = dns_server

    # 2. Start UDP DNS Server
    actual_dns_port = await dns_server.start()

    logger.info("=" * 60)
    logger.info("  🚀 cipherDNS Encrypted Resolver Initialized")
    logger.info(f"  • Inbound DNS:  udp://{args.dns_host}:{actual_dns_port}")
    logger.info(f"  • Web Dashboard: http://localhost:{args.web_port}")
    logger.info(f"  • Upstream DoH:  {DOH_PROVIDERS[args.provider]['name']}")
    if actual_dns_port != 53:
        logger.info(f"  ℹ Note: Running on unprivileged port {actual_dns_port}.")
        logger.info(f"    To run on standard port 53, start with: sudo python3 run.py")
    logger.info("=" * 60)

    # 3. Start Uvicorn ASGI Server
    config = uvicorn.Config(
        app=web_module.app,
        host=args.web_host,
        port=args.web_port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    try:
        await server.serve()
    finally:
        await dns_server.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("cipherDNS shutting down gracefully.")

