# cipherDNS: Encrypted DNS-over-HTTPS Resolver & Privacy Verification

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![Protocol RFC 8484](https://img.shields.io/badge/RFC-8484%20(DoH)-green.svg)](https://tools.ietf.org/html/rfc8484)
[![Zeek 9.0](https://img.shields.io/badge/Zeek-Network%20Audit-purple.svg)](https://zeek.org/)
[![License MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **CS416 Computer Systems Security Course Project**  
> An encrypted DNS caching proxy that secures local network DNS queries using **DNS-over-HTTPS (DoH, RFC 8484)**, featuring a real-time dark-mode telemetry dashboard and automated **Zeek** network privacy verification.

---

## 🌟 Key Highlights

- **Standard UDP Port 53 Ingestion:** Receives queries from standard OS network stacks, browsers (Google Chrome, Firefox), and CLI utilities (`dig`, `curl`, `nslookup`).
- **Cryptographic Encryption via DoH (RFC 8484):** Uses HTTP/2 POST over TLS 1.3 with upstream providers like **Cloudflare** (`1.1.1.1`) and **Google** (`8.8.8.8`).
- **Dynamic TTL-Aware Caching:** Compliant with RFC 1035/2181; decrements remaining TTLs on cache hits, delivering responses in **< 1 ms**.
- **Classy Dark-Themed Web App:**
  - Big circular animation ring reflecting live query states (*cipherDNS running* &rarr; *Making a DoH request to Cloudflare...* &rarr; *Successfully delivered cached entry*).
  - Live TTL cache table with live countdown, reload button, and most recently added sites at the top.
  - Runtime resolver mode switch (DoH vs Traditional Plaintext DNS) and upstream provider selector.
  - Interactive manual test query bar.
- **Empirical Zeek Privacy Verification:** Runs `/opt/zeek/bin/zeek` on live captures to prove traditional DNS leaks queries in `dns.log` while cipherDNS conceals all traffic inside TLS 1.3 encrypted application records.
- **Formal Course PDF Report:** Publication-grade 6-page report strictly adhering to the CS416 8-section template with project-specific evidence index.

---

## 🏗 System Architecture

```
+-------------------------------------------------------------------+
|                     Operating System / Client                     |
|         Google Chrome, Firefox, curl, dig @127.0.0.1:53           |
+-------------------------------------------------------------------+
                                  │
                       UDP Port 53 (RFC 1035)
                                  ▼
+───────────────────────────────────────────────────────────────────+
|                          cipherDNS Daemon                         |
|                                                                   |
|   ┌─────────────────────┐             ┌───────────────────────┐   |
|   │   TTL Cache Store   │──(Cache)───▶│ Dynamic TTL Decrement │   |
|   │ (In-Memory Table)   │  Hit (<1ms) │ (Rewrites Answer TTL) │   |
|   └─────────────────────┘             └───────────────────────┘   |
|              │ Cache Miss                         │               |
|              ▼                                    ▼               |
|   ┌───────────────────────────────────────────────────────────┐   |
|   │                  DoH Upstream Dispatcher                  │   |
|   │     HTTP/2 POST (application/dns-message) + TLS 1.3       │   |
|   │      Strict Mozilla Root CA X.509 Chain Validation        │   |
|   └───────────────────────────────────────────────────────────┘   |
|                                  │                                |
+──────────────────────────────────┼────────────────────────────────+
                                   │
                      HTTPS / TLS 1.3 Port 443
                                   ▼
             +─────────────────────────────────────────+
             |           Upstream DoH Server           |
             |       Cloudflare (1.1.1.1) / Google     |
             +─────────────────────────────────────────+
```

---

## 🚀 Quick Start

### 1. Environment Setup
```bash
# Clone and enter directory
cd /home/yaswanth-ram-kumar/CS416

# Activate virtual environment
source .venv/bin/activate

# Install dependencies (if not already installed)
pip install -r requirements.txt
```

### 2. Launch cipherDNS
```bash
# Option A: Run on standard port 53 (requires sudo)
sudo python3 run.py --dns-port 53 --web-port 8000

# Option B: Run on unprivileged port 5300 (ideal for demonstration/testing)
python3 run.py --dns-port 5300 --web-port 8000
```

### 3. Access Web Dashboard
Open your web browser and navigate to:  
👉 **`http://localhost:8000`**

---

## 🌐 Testing & System DNS Integration

### Test with `dig`
```bash
# Query netflix.com (Cache Miss -> DoH query)
dig @127.0.0.1 -p 5300 netflix.com

# Query netflix.com again (Cache Hit -> <1ms response with decremented TTL)
dig @127.0.0.1 -p 5300 netflix.com
```

### Route System Traffic (Chrome, curl, ping) to cipherDNS
```bash
# Direct system DNS to 127.0.0.1
./scripts/setup_system_dns.sh

# Browse to https://netflix.com in Chrome!
# All DNS requests will now route through cipherDNS.

# To restore default DNS settings when done:
./scripts/restore_system_dns.sh
```

---

## 🔍 Zeek Privacy Audit

Run the automated network audit comparing Traditional Plaintext DNS against cipherDNS DoH:
```bash
# Run from terminal
./scripts/run_zeek_comparison.sh netflix.com

# Or click "Run Zeek Packet Audit" in the Web Dashboard (http://localhost:8000)
```

**Audit Output:**
- **Traditional DNS:** Zeek's `dns.log` reveals:
  ```
  192.168.1.105:53821 -> 8.8.8.8:53 udp query: netflix.com (LEAK DETECTED)
  ```
- **cipherDNS:** Zeek's `dns.log` is **EMPTY**; `conn.log` shows:
  ```
  192.168.1.105:48210 -> 1.1.1.1:443 tcp service: ssl (TLS 1.3 Encrypted Application Data)
  ```

---

## 🧪 Automated Test Suite

Run all functional, security, and integration tests:
```bash
source .venv/bin/activate
pytest tests/ -v
```

**Test Coverage:**
- `tests/test_cache.py`: Cache hits, dynamic TTL decrements, expiration, LRU pruning, most recent sorting.
- `tests/test_doh.py`: Real DoH query over RFC 8484, upstream TLS certificate validation, upstream timeout handling, malformed response handling.
- `tests/test_server.py`: Async UDP DNS pipeline, sub-millisecond cache delivery, mode toggling.

---

## 📄 Final PDF Report & Screencast Script

- **PDF Report:** Located at `report/cipherDNS_Final_Report.pdf` (compile anytime via `python3 report/generate_report.py`).
- **Screencast Script:** Located at `SCREENCAST_SCRIPT.md` (detailed 10-minute presentation guide).

