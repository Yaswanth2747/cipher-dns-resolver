"""
cipherDNS GeoIP & Autonomous System (ASN) Intelligence Engine
Enriches resolved IP addresses with country flags, country names,
and Autonomous System (ASN) organization details.
"""

import time
import socket
import ipaddress
import urllib.request
import json
from typing import Dict, Any, Optional


def country_code_to_flag(code: str) -> str:
    """Converts 2-letter ISO country code to Unicode flag emoji."""
    if not code or len(code) != 2:
        return "🌐"
    code = code.upper()
    if code == "LO" or code == "LOCAL":
        return "💻"
    try:
        # Standard Regional Indicator Symbol conversion
        return "".join(chr(127397 + ord(c)) for c in code)
    except Exception:
        return "🌐"


class GeoIPResolver:
    """Fast, thread-safe GeoIP and ASN resolver with local in-memory caching."""

    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        # Pre-seed known local and common ranges
        self._cache["127.0.0.1"] = {
            "country": "Localhost",
            "country_code": "LOCAL",
            "flag": "💻",
            "org": "Loopback Interface",
            "as": "Loopback",
            "city": "Local Machine",
        }

    def _offline_lookup(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """Fallback lookup for major CDNs and cloud providers if offline."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback:
                return {
                    "country": "Local Network",
                    "country_code": "LOCAL",
                    "flag": "💻",
                    "org": "Private RFC 1918 / Loopback",
                    "as": "Internal",
                    "city": "LAN",
                }

            # Netflix ranges
            if ip_str.startswith("207.45.") or ip_str.startswith("198.38."):
                return {
                    "country": "United States",
                    "country_code": "US",
                    "flag": "🇺🇸",
                    "org": "Netflix Open Connect",
                    "as": "AS40027 Netflix",
                    "city": "Global Edge",
                }

            # Cloudflare ranges
            if ip_str.startswith("104.") or ip_str.startswith("172.64.") or ip_str.startswith("1.1.") or ip_str.startswith("1.0."):
                return {
                    "country": "United States",
                    "country_code": "US",
                    "flag": "🇺🇸",
                    "org": "Cloudflare Anycast CDN",
                    "as": "AS13335 Cloudflare",
                    "city": "Anycast Edge",
                }

            # Google ranges
            if ip_str.startswith("142.250.") or ip_str.startswith("172.217.") or ip_str.startswith("8.8."):
                return {
                    "country": "United States",
                    "country_code": "US",
                    "flag": "🇺🇸",
                    "org": "Google LLC",
                    "as": "AS15169 Google",
                    "city": "Global Edge",
                }

            # GitHub ranges
            if ip_str.startswith("140.82."):
                return {
                    "country": "United States",
                    "country_code": "US",
                    "flag": "🇺🇸",
                    "org": "GitHub / Microsoft",
                    "as": "AS36459 GitHub",
                    "city": "Seattle",
                }

            # Quad9
            if ip_str.startswith("9.9.9."):
                return {
                    "country": "Switzerland",
                    "country_code": "CH",
                    "flag": "🇨🇭",
                    "org": "Quad9 DNS",
                    "as": "AS19281 Quad9",
                    "city": "Zurich",
                }
        except Exception:
            pass
        return None

    def resolve(self, ip_str: str) -> Dict[str, Any]:
        """Resolves an IPv4 address to GeoIP country flag, country name, and ASN."""
        clean_ip = ip_str.strip()
        if not clean_ip:
            return {"country": "Unknown", "country_code": "", "flag": "🌐", "org": "", "as": ""}

        # 1. Check in-memory cache
        if clean_ip in self._cache:
            return self._cache[clean_ip]

        # 2. Check offline well-known tables
        known = self._offline_lookup(clean_ip)
        if known and not clean_ip.startswith("192.") and not clean_ip.startswith("10.") and not clean_ip.startswith("172.16."):
            # We can use known, but also try online lookup for city/regional accuracy
            pass

        # 3. Attempt online lookup via ip-api.com (timeout: 1.2s)
        try:
            req = urllib.request.Request(
                f"http://ip-api.com/json/{clean_ip}?fields=status,country,countryCode,city,org,as",
                headers={"User-Agent": "cipherDNS/1.0 (+https://github.com/cipherdns)"},
            )
            with urllib.request.urlopen(req, timeout=1.2) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    cc = data.get("countryCode", "US")
                    info = {
                        "country": data.get("country", "Unknown"),
                        "country_code": cc,
                        "flag": country_code_to_flag(cc),
                        "org": data.get("org") or data.get("as", ""),
                        "as": data.get("as", ""),
                        "city": data.get("city", ""),
                    }
                    self._cache[clean_ip] = info
                    return info
        except Exception:
            pass

        # 4. Fall back to offline heuristics or generic default
        if known:
            self._cache[clean_ip] = known
            return known

        default_info = {
            "country": "Global Internet",
            "country_code": "US",
            "flag": "🌐",
            "org": "Autonomous System",
            "as": "AS-External",
            "city": "Global",
        }
        self._cache[clean_ip] = default_info
        return default_info


# Global singleton instance
geoip_resolver = GeoIPResolver()
