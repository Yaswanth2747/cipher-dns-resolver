"""
cipherDNS Configuration Module
Centralized configuration for ports, DoH providers, caching parameters, and paths.
"""

import os
from typing import Dict, Any

# Network & Server Config
DEFAULT_DNS_HOST = os.getenv("CIPHERDNS_DNS_HOST", "0.0.0.0")
DEFAULT_DNS_PORT = int(os.getenv("CIPHERDNS_DNS_PORT", "53"))
DEFAULT_WEB_HOST = os.getenv("CIPHERDNS_WEB_HOST", "0.0.0.0")
DEFAULT_WEB_PORT = int(os.getenv("CIPHERDNS_WEB_PORT", "8000"))

# Upstream DoH Providers
DOH_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "name": "Cloudflare",
        "url": "https://cloudflare-dns.com/dns-query",
        "bootstrap_ips": ["1.1.1.1", "1.0.0.1"],
        "description": "Privacy-first resolver (1.1.1.1) with global Anycast routing.",
        "icon": "cloudflare",
    },
    "google": {
        "name": "Google Public DNS",
        "url": "https://dns.google/dns-query",
        "bootstrap_ips": ["8.8.8.8", "8.8.4.4"],
        "description": "High-availability, geographically distributed DNS service.",
        "icon": "google",
    },
    "quad9": {
        "name": "Quad9 (Malware Blocking)",
        "url": "https://dns.quad9.net/dns-query",
        "bootstrap_ips": ["9.9.9.9", "149.112.112.112"],
        "description": "Swiss-based non-profit resolver with threat intelligence filtering.",
        "icon": "shield",
    },
    "adguard": {
        "name": "AdGuard DNS",
        "url": "https://dns.adguard-dns.com/dns-query",
        "bootstrap_ips": ["94.140.14.14", "94.140.15.15"],
        "description": "Ad-blocking and tracking prevention DoH resolver.",
        "icon": "adblock",
    },
}

DEFAULT_DOH_PROVIDER = "cloudflare"

# Upstream Plaintext DNS (for demonstration & comparison)
PLAINTEXT_UPSTREAMS = [
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
]

# Cache Configuration
CACHE_MAX_ENTRIES = 5000
MIN_CACHE_TTL = 5        # seconds (floor to protect against zero-TTL spam)
MAX_CACHE_TTL = 86400    # seconds (cap at 24 hours)

# Timeouts & Network
DOH_TIMEOUT_SECONDS = 3.5
PLAINTEXT_TIMEOUT_SECONDS = 3.0

# Zeek binary path
ZEEK_BINARY = os.getenv("ZEEK_PATH", "/opt/zeek/bin/zeek")
PCAP_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "pcaps")
ZEEK_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "zeek_logs")

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(ZEEK_LOG_DIR, exist_ok=True)

