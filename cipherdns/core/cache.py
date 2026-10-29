"""
cipherDNS TTL-Aware In-Memory Cache
Implements standard-compliant DNS response caching with dynamic TTL decrementing.
"""

import time
import threading
from typing import Dict, Tuple, Optional, List, Any
import dns.message
import dns.rdatatype
import dns.rcode

from cipherdns.config import CACHE_MAX_ENTRIES, MIN_CACHE_TTL, MAX_CACHE_TTL


class CacheEntry:
    """Represents a cached DNS response entry."""

    def __init__(
        self,
        qname: str,
        qtype: int,
        qclass: int,
        raw_wire: bytes,
        original_ttl: int,
        answers: List[str],
        rcode: int = dns.rcode.NOERROR,
    ):
        self.qname: str = qname.rstrip(".").lower()
        self.qtype: int = qtype
        self.qtype_name: str = dns.rdatatype.to_text(qtype)
        self.qclass: int = qclass
        self.raw_wire: bytes = raw_wire
        self.original_ttl: int = max(MIN_CACHE_TTL, min(original_ttl, MAX_CACHE_TTL))
        self.inserted_at: float = time.time()
        self.expires_at: float = self.inserted_at + self.original_ttl
        self.answers: List[str] = answers
        self.hit_count: int = 0
        self.rcode: int = rcode
        self.last_accessed_at: float = self.inserted_at

    @property
    def remaining_ttl(self) -> int:
        """Computes current remaining TTL in seconds."""
        rem = int(self.expires_at - time.time())
        return max(0, rem)

    @property
    def is_expired(self) -> bool:
        """Returns True if current time has passed expiry timestamp."""
        return time.time() >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Serializes entry for the web frontend."""
        rem_ttl = self.remaining_ttl
        pct = 0
        if self.original_ttl > 0:
            pct = max(0, min(100, int((rem_ttl / self.original_ttl) * 100)))

        return {
            "domain": self.qname,
            "type": self.qtype_name,
            "answers": self.answers,
            "remaining_ttl": rem_ttl,
            "original_ttl": self.original_ttl,
            "ttl_percent": pct,
            "hit_count": self.hit_count,
            "inserted_at": self.inserted_at,
            "inserted_at_iso": time.strftime(
                "%H:%M:%S", time.localtime(self.inserted_at)
            ),
            "status": "expired" if rem_ttl <= 0 else ("expiring" if rem_ttl < 15 else "active"),
            "rcode": dns.rcode.to_text(self.rcode),
        }


class DNSCache:
    """Thread-safe TTL-aware DNS cache."""

    def __init__(self, max_entries: int = CACHE_MAX_ENTRIES):
        self.max_entries: int = max_entries
        self._cache: Dict[Tuple[str, int, int], CacheEntry] = {}
        self._lock: threading.RLock = threading.RLock()
        self.total_hits: int = 0
        self.total_misses: int = 0

    def _normalize_key(self, qname: str, qtype: int, qclass: int) -> Tuple[str, int, int]:
        return (qname.rstrip(".").lower(), qtype, qclass)

    def get(self, qname: str, qtype: int, qclass: int, query_id: int) -> Tuple[bool, Optional[bytes], int, List[str]]:
        """
        Retrieves a cached DNS response.
        If found and valid, rewrites the response with decremented remaining TTL
        and sets the query ID to match the client's query.
        Returns: (hit_status, wire_bytes, remaining_ttl, answers)
        """
        key = self._normalize_key(qname, qtype, qclass)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self.total_misses += 1
                return False, None, 0, []

            if entry.is_expired:
                del self._cache[key]
                self.total_misses += 1
                return False, None, 0, []

            # Cache Hit!
            entry.hit_count += 1
            entry.last_accessed_at = time.time()
            self.total_hits += 1
            rem_ttl = entry.remaining_ttl

            try:
                # Reconstruct DNS response with matched query ID and decremented TTL
                resp_msg = dns.message.from_wire(entry.raw_wire)
                resp_msg.id = query_id

                # Rewrite TTLs in all sections to remaining TTL
                for section in (resp_msg.answer, resp_msg.authority, resp_msg.additional):
                    for rrset in section:
                        rrset.ttl = min(rrset.ttl, max(1, rem_ttl))

                rewritten_wire = resp_msg.to_wire()
                return True, rewritten_wire, rem_ttl, entry.answers
            except Exception:
                # Fallback to stored wire with simple ID replacement if parsing fails
                if len(entry.raw_wire) >= 2:
                    wire = bytearray(entry.raw_wire)
                    wire[0] = (query_id >> 8) & 0xFF
                    wire[1] = query_id & 0xFF
                    return True, bytes(wire), rem_ttl, entry.answers
                return False, None, 0, []

    def put(
        self,
        qname: str,
        qtype: int,
        qclass: int,
        resp_msg: dns.message.Message,
        raw_wire: bytes,
    ) -> Optional[CacheEntry]:
        """
        Caches a newly resolved DNS response.
        Extracts answer records and calculates minimum TTL.
        """
        key = self._normalize_key(qname, qtype, qclass)
        answers: List[str] = []
        min_ttl = MAX_CACHE_TTL

        # Inspect answer section
        if resp_msg.answer:
            for rrset in resp_msg.answer:
                min_ttl = min(min_ttl, rrset.ttl)
                for rdata in rrset:
                    answers.append(rdata.to_text())
        elif resp_msg.authority:
            # Negative caching (SOA TTL)
            for rrset in resp_msg.authority:
                if rrset.rdtype == dns.rdatatype.SOA:
                    min_ttl = min(min_ttl, rrset.ttl)
                    answers.append(f"SOA: {rrset.name.to_text()}")
        else:
            min_ttl = MIN_CACHE_TTL

        # Don't cache zero or negative TTLs beyond minimal floor
        effective_ttl = max(MIN_CACHE_TTL, min(min_ttl, MAX_CACHE_TTL))

        entry = CacheEntry(
            qname=qname,
            qtype=qtype,
            qclass=qclass,
            raw_wire=raw_wire,
            original_ttl=effective_ttl,
            answers=answers,
            rcode=resp_msg.rcode(),
        )

        with self._lock:
            # Enforce max entries via basic pruning if full
            if len(self._cache) >= self.max_entries:
                self._prune_expired()
                if len(self._cache) >= self.max_entries:
                    # Evict oldest accessed entry
                    oldest_key = min(self._cache, key=lambda k: self._cache[k].last_accessed_at)
                    del self._cache[oldest_key]

            self._cache[key] = entry

        return entry

    def _prune_expired(self) -> int:
        """Prunes expired entries from cache. Must be called with lock held."""
        expired_keys = [k for k, v in self._cache.items() if v.is_expired]
        for k in expired_keys:
            del self._cache[k]
        return len(expired_keys)

    def clear(self) -> int:
        """Clears all cached entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def get_entries(self) -> List[Dict[str, Any]]:
        """
        Returns all valid cache entries formatted for frontend,
        sorted with the most recently inserted/accessed at the top.
        """
        with self._lock:
            self._prune_expired()
            # Sort by inserted_at descending (most recently added site at the top)
            sorted_entries = sorted(
                self._cache.values(),
                key=lambda e: e.inserted_at,
                reverse=True,
            )
            return [e.to_dict() for e in sorted_entries]

    def get_stats(self) -> Dict[str, Any]:
        """Returns cache efficiency metrics."""
        with self._lock:
            total_requests = self.total_hits + self.total_misses
            hit_ratio = (
                round((self.total_hits / total_requests) * 100, 1)
                if total_requests > 0
                else 0.0
            )
            return {
                "total_entries": len(self._cache),
                "total_hits": self.total_hits,
                "total_misses": self.total_misses,
                "hit_ratio_pct": hit_ratio,
            }

