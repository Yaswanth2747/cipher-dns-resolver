"""
Unit and Integration Tests for cipherDNS Zeek Privacy Verification Engine
"""

import os
import pytest
from cipherdns.analysis.zeek_analyzer import ZeekAnalyzer
from cipherdns.config import ZEEK_BINARY


def test_zeek_installed():
    """Verifies Zeek binary is present and executable."""
    za = ZeekAnalyzer()
    assert za._check_zeek_installed() is True
    assert os.path.exists(ZEEK_BINARY)


def test_zeek_privacy_comparison_with_response_ips_and_tls():
    """
    Tests Zeek comparative analysis for netflix.com:
    - Traditional DNS leaks query domain and response IPs in dns.log
    - cipherDNS DoH has zero leaks in dns.log and records TLS 1.3 session in ssl.log
    """
    za = ZeekAnalyzer()
    report = za.audit_privacy_comparison("netflix.com")

    # 1. Target and resolved IPs
    assert report["target_domain"] == "netflix.com"
    assert "resolved_ips" in report
    assert len(report["resolved_ips"]) >= 1

    # 2. Traditional Plaintext DNS checks
    trad = report["traditional_dns"]
    assert trad["privacy_compromised"] is True
    assert "netflix.com" in trad["leaked_queries"]
    assert len(trad["leaked_response_ips"]) >= 1
    assert "dns.log" in trad["zeek_logs"]

    # 3. cipherDNS Encrypted DoH checks
    cipher = report["cipher_dns"]
    assert cipher["privacy_compromised"] is False
    assert len(cipher["leaked_queries"]) == 0
    assert len(cipher["leaked_response_ips"]) == 0
    assert len(cipher["client_received_ips"]) >= 1

    # TLS summary checks
    tls_sum = cipher["tls_summary"]
    assert tls_sum["sni_hostname"] == "cloudflare-dns.com"
    assert "TLSv1" in tls_sum["tls_version"]
    assert "TLS_AES_256_GCM_SHA384" in tls_sum["cipher_suite"]
    assert tls_sum["handshake_established"] is True

    # Zeek SSL log records
    assert "ssl.log" in cipher["zeek_logs"]
    assert len(cipher["tls_records"]) >= 1
    assert cipher["tls_records"][0].get("server_name") == "cloudflare-dns.com"

    # Verdict
    assert "PASS" in report["verdict"]

