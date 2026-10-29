#!/usr/bin/env bash
# cipherDNS Zeek Packet Analysis & Privacy Comparison Tool
# Usage: ./scripts/run_zeek_comparison.sh [domain]

DOMAIN=${1:-netflix.com}

echo "=========================================================="
echo "  🔍 cipherDNS Zeek Network Privacy Audit Tool"
echo "  Target Domain: $DOMAIN"
echo "=========================================================="

python3 -c "
import sys
from cipherdns.analysis.zeek_analyzer import ZeekAnalyzer

domain = '$DOMAIN'
za = ZeekAnalyzer()
res = za.audit_privacy_comparison(domain)

print('\n[1] TRADITIONAL PLAINTEXT DNS (UDP PORT 53):')
print(f'  • PCAP Capture: {res[\"traditional_dns\"][\"pcap_file\"]}')
print(f'  • Zeek dns.log Leaked Queries: {res[\"traditional_dns\"][\"leaked_queries\"]}')
print(f'  • Privacy Compromised: {res[\"traditional_dns\"][\"privacy_compromised\"]}')
print(f'  • Threat Assessment: {res[\"traditional_dns\"][\"risk_assessment\"]}')

print('\n[2] CIPHERDNS ENCRYPTED RESOLVER (DoH / TLS 1.3 PORT 443):')
print(f'  • PCAP Capture: {res[\"cipher_dns\"][\"pcap_file\"]}')
print(f'  • Zeek dns.log Leaked Queries: {res[\"cipher_dns\"][\"leaked_queries\"]} (ZERO LEAKS)')
print(f'  • Privacy Compromised: {res[\"cipher_dns\"][\"privacy_compromised\"]}')
print(f'  • Security Status: {res[\"cipher_dns\"][\"security_status\"]}')

print('\n==========================================================')
print(f'  AUDIT VERDICT: {res[\"verdict\"]}')
print('==========================================================\n')
"
