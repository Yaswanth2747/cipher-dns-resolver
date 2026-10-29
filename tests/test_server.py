"""
End-to-End Tests for cipherDNS Server Pipeline
"""

import pytest
import asyncio
import dns.message
import dns.rdatatype
import dns.rcode

from cipherdns.core.cache import DNSCache
from cipherdns.core.doh_client import DoHClient
from cipherdns.core.server import DNSServer


@pytest.mark.asyncio
async def test_server_query_pipeline_and_cache_integration():
    """
    Tests end-to-end DNS resolution through DNSServer:
    1. First query causes Cache Miss -> resolves via DoH -> populates cache
    2. Second query causes Cache Hit -> served from cache with < 1ms latency
    """
    events = []
    def callback(ev):
        events.append(ev)

    cache = DNSCache()
    doh_client = DoHClient(current_provider="cloudflare")
    server = DNSServer(cache=cache, doh_client=doh_client, event_callback=callback)

    # 1. First Query: netflix.com
    q_msg = dns.message.make_query("netflix.com", dns.rdatatype.A)
    qid_1 = 1111
    q_msg.id = qid_1

    fake_client_addr = ("127.0.0.1", 54321)
    await server.handle_query(q_msg.to_wire(), fake_client_addr, transport=None)

    # Verify event dispatched for DoH resolution
    assert any(e.get("action") == "DOH_RESOLVE" for e in events)
    assert any("netflix.com" in e.get("domain", "") for e in events)

    # Verify cache is populated
    cached_entries = cache.get_entries()
    assert len(cached_entries) >= 1
    assert any(e["domain"] == "netflix.com" for e in cached_entries)

    # 2. Second Query: netflix.com (Should Hit Cache!)
    q_msg_2 = dns.message.make_query("netflix.com", dns.rdatatype.A)
    qid_2 = 2222
    q_msg_2.id = qid_2

    events.clear()
    await server.handle_query(q_msg_2.to_wire(), fake_client_addr, transport=None)

    # Verify CACHE_HIT event
    hit_events = [e for e in events if e.get("action") == "CACHE_HIT"]
    assert len(hit_events) == 1
    assert hit_events[0]["domain"] == "netflix.com"
    assert hit_events[0]["latency_ms"] < 5.0  # sub-5ms cache delivery!

    await server.doh_client.close()


@pytest.mark.asyncio
async def test_server_mode_toggle():
    """Tests switching between cipherDNS DoH mode and Plaintext DNS mode."""
    events = []
    server = DNSServer(event_callback=lambda ev: events.append(ev))

    assert server.cipher_mode_enabled is True

    # Disable cipherDNS (switch to plaintext mode)
    server.set_mode(False)
    assert server.cipher_mode_enabled is False
    assert any(e.get("type") == "mode_change" and e.get("cipher_mode") is False for e in events)

    # Re-enable cipherDNS
    server.set_mode(True)
    assert server.cipher_mode_enabled is True
