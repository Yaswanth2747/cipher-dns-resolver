"""
Unit Tests for cipherDNS TTL Cache Engine
"""

import time
import pytest
import dns.message
import dns.rdatatype
import dns.rcode
import dns.rrset

from cipherdns.core.cache import DNSCache, CacheEntry


def create_sample_response(qname: str, ip: str = "198.51.100.1", ttl: int = 60, qid: int = 12345):
    """Helper to synthesize a standard DNS A-record response."""
    msg = dns.message.make_response(dns.message.make_query(qname, dns.rdatatype.A))
    msg.id = qid
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip)
    rrset = dns.rrset.from_rdata(dns.name.from_text(qname), ttl, rdata)
    msg.answer.append(rrset)
    return msg


def test_cache_miss_initially():
    cache = DNSCache()
    is_hit, wire, rem_ttl, answers = cache.get("netflix.com", dns.rdatatype.A, 1, 999)
    assert not is_hit
    assert wire is None
    assert rem_ttl == 0
    assert cache.total_misses == 1


def test_cache_put_and_hit():
    cache = DNSCache()
    msg = create_sample_response("netflix.com", "198.51.100.10", ttl=120, qid=100)
    raw_wire = msg.to_wire()

    entry = cache.put("netflix.com", dns.rdatatype.A, 1, msg, raw_wire)
    assert entry is not None
    assert entry.original_ttl == 120
    assert "198.51.100.10" in entry.answers

    # Query with new transaction ID
    client_qid = 54321
    is_hit, hit_wire, rem_ttl, answers = cache.get("netflix.com", dns.rdatatype.A, 1, client_qid)

    assert is_hit is True
    assert hit_wire is not None
    assert 115 <= rem_ttl <= 120
    assert "198.51.100.10" in answers

    # Verify returned response has updated query ID
    hit_msg = dns.message.from_wire(hit_wire)
    assert hit_msg.id == client_qid
    # Verify TTL is decremented
    assert hit_msg.answer[0].ttl <= 120


def test_cache_ttl_decrement():
    cache = DNSCache()
    msg = create_sample_response("netflix.com", "198.51.100.1", ttl=10, qid=1)
    cache.put("netflix.com", dns.rdatatype.A, 1, msg, msg.to_wire())

    # Simulate 3 seconds elapsed
    key = ("netflix.com", dns.rdatatype.A, 1)
    cache._cache[key].expires_at -= 3

    is_hit, hit_wire, rem_ttl, _ = cache.get("netflix.com", dns.rdatatype.A, 1, 2)
    assert is_hit is True
    assert 6 <= rem_ttl <= 7
    hit_msg = dns.message.from_wire(hit_wire)
    assert hit_msg.answer[0].ttl <= 7


def test_cache_expiration():
    cache = DNSCache()
    msg = create_sample_response("expired.example.com", "192.0.2.1", ttl=5, qid=1)
    cache.put("expired.example.com", dns.rdatatype.A, 1, msg, msg.to_wire())

    # Fast forward past expiration
    key = ("expired.example.com", dns.rdatatype.A, 1)
    cache._cache[key].expires_at = time.time() - 1

    is_hit, wire, rem_ttl, _ = cache.get("expired.example.com", dns.rdatatype.A, 1, 3)
    assert not is_hit
    assert wire is None


def test_cache_most_recent_ordering():
    cache = DNSCache()
    msg1 = create_sample_response("first.com", "1.1.1.1", ttl=60)
    msg2 = create_sample_response("second.com", "2.2.2.2", ttl=60)

    cache.put("first.com", dns.rdatatype.A, 1, msg1, msg1.to_wire())
    time.sleep(0.01)
    cache.put("second.com", dns.rdatatype.A, 1, msg2, msg2.to_wire())

    entries = cache.get_entries()
    assert len(entries) == 2
    # Most recently added site must be at the top!
    assert entries[0]["domain"] == "second.com"
    assert entries[1]["domain"] == "first.com"


def test_cache_clear():
    cache = DNSCache()
    msg = create_sample_response("site.com", "1.2.3.4", ttl=60)
    cache.put("site.com", dns.rdatatype.A, 1, msg, msg.to_wire())
    assert len(cache.get_entries()) == 1

    cleared = cache.clear()
    assert cleared == 1
    assert len(cache.get_entries()) == 0

