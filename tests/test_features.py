"""
Unit and Integration Tests for Speed Duel Benchmark, Wire Inspector, and GeoIP Engines
"""

import pytest
import dns.message
import dns.rdatatype
from cipherdns.core.cache import DNSCache
from cipherdns.core.doh_client import DoHClient
from cipherdns.core.geoip import geoip_resolver, country_code_to_flag
from cipherdns.core.wire_inspector import wire_inspector
from cipherdns.core.benchmark import SpeedDuelBenchmark


def test_geoip_resolution_and_flags():
    """Tests GeoIP country code, flag emoji, and ASN lookup."""
    assert country_code_to_flag("US") == "🇺🇸"
    assert country_code_to_flag("IN") == "🇮🇳"
    assert country_code_to_flag("CH") == "🇨🇭"

    # Localhost
    local = geoip_resolver.resolve("127.0.0.1")
    assert local["flag"] == "💻"
    assert "Local" in local["country"]

    # Public IP
    netflix_ip = geoip_resolver.resolve("207.45.72.1")
    assert netflix_ip["country_code"] == "US"
    assert netflix_ip["flag"] == "🇺🇸"
    assert "Netflix" in netflix_ip["org"] or "Netflix" in netflix_ip["as"]


def test_wire_packet_inspector_rfc1035():
    """Tests binary hexdump formatting and RFC 1035 bit-field parsing."""
    msg = dns.message.make_query("netflix.com", dns.rdatatype.A)
    msg.id = 0xbeef

    dissection = wire_inspector.inspect_message(msg)

    # Check Hexdump
    assert "0000" in dissection["wire_hex"]
    assert "net" in dissection["wire_hex"]
    assert "flix" in dissection["wire_hex"]

    # Check Header
    hdr = dissection["header"]
    assert hdr["transaction_id_hex"] == "0xbeef"
    assert hdr["transaction_id_dec"] == 48879
    assert hdr["qr"] == 0
    assert hdr["qr_desc"] == "Query (0)"
    assert hdr["qdcount"] == 1
    assert hdr["wire_size_bytes"] > 0

    # Check Questions
    assert len(dissection["questions"]) == 1
    assert dissection["questions"][0]["name"] == "netflix.com"
    assert dissection["questions"][0]["type"] == "A"

    # Check DoH Framing
    doh = dissection["doh_framing"]
    assert doh["http_version"] == "HTTP/2 (h2)"
    assert "TLS 1.3" in doh["transport_security"]
    assert doh["pseudo_headers"][":method"] == "POST"


@pytest.mark.asyncio
async def test_speed_duel_benchmark():
    """Tests multi-resolver speed duel benchmark engine."""
    cache = DNSCache()
    doh_client = DoHClient(current_provider="cloudflare")
    bench = SpeedDuelBenchmark(cache=cache, doh_client=doh_client)

    duel = await bench.run_duel("netflix.com")

    assert duel["domain"] == "netflix.com"
    assert "winner_name" in duel
    assert duel["winner_latency_ms"] >= 0
    assert len(duel["contestants"]) >= 4

    keys = [c["key"] for c in duel["contestants"]]
    assert "cache" in keys
    assert "cloudflare" in keys
    assert "plaintext" in keys

    # Verify contestant metrics
    for c in duel["contestants"]:
        assert "latency_ms" in c
        assert "answers" in c
        assert "enriched_ips" in c
        assert len(c["enriched_ips"]) >= 1
        assert "flag" in c["enriched_ips"][0]
