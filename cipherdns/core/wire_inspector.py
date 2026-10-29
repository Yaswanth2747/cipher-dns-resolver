"""
cipherDNS RFC 1035 Wire & Hex Packet Inspector ("Mini-Wireshark")
Generates formatted binary hexdumps, bit-level header dissections,
and RFC 8484 DoH HTTP/2 encapsulation metadata for in-browser packet analysis.
"""

from typing import Dict, Any, List, Optional
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.flags

from cipherdns.core.geoip import geoip_resolver


def format_hexdump(data: bytes) -> str:
    """Formats bytes into a standard Wireshark/xxd hexdump string."""
    lines = []
    length = len(data)
    for i in range(0, length, 16):
        chunk = data[i:i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part to 48 chars (16 * 3 - 1 = 47, plus padding)
        hex_part = f"{hex_bytes:<48}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_part}   |{ascii_part}|")
    return "\n".join(lines)


class WirePacketInspector:
    """Dissects RFC 1035 DNS datagrams and formats deep protocol representations."""

    @staticmethod
    def inspect_message(msg: dns.message.Message, raw_wire: Optional[bytes] = None, provider_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Dissects a dns.message.Message and returns structured Wireshark-like dissection."""
        wire_bytes = raw_wire or msg.to_wire()
        wire_hex = format_hexdump(wire_bytes)

        # 1. Header bit dissection
        qr_val = bool(msg.flags & dns.flags.QR)
        aa_val = bool(msg.flags & dns.flags.AA)
        tc_val = bool(msg.flags & dns.flags.TC)
        rd_val = bool(msg.flags & dns.flags.RD)
        ra_val = bool(msg.flags & dns.flags.RA)

        header_info = {
            "transaction_id_hex": f"0x{msg.id:04x}",
            "transaction_id_dec": msg.id,
            "qr": 1 if qr_val else 0,
            "qr_desc": "Response (1)" if qr_val else "Query (0)",
            "opcode": msg.opcode(),
            "opcode_name": dns.opcode.to_text(msg.opcode()),
            "aa": 1 if aa_val else 0,
            "aa_desc": "Authoritative Answer" if aa_val else "Non-authoritative",
            "tc": 1 if tc_val else 0,
            "tc_desc": "Message Truncated" if tc_val else "Not Truncated",
            "rd": 1 if rd_val else 0,
            "rd_desc": "Recursion Desired",
            "ra": 1 if ra_val else 0,
            "ra_desc": "Recursion Available" if ra_val else "Recursion Not Available",
            "rcode": msg.rcode(),
            "rcode_name": dns.rcode.to_text(msg.rcode()),
            "qdcount": len(msg.question),
            "ancount": len(msg.answer),
            "nscount": len(msg.authority),
            "arcount": len(msg.additional),
            "wire_size_bytes": len(wire_bytes),
        }

        # 2. Questions Section
        questions = []
        for q in msg.question:
            questions.append({
                "name": str(q.name).rstrip("."),
                "type": dns.rdatatype.to_text(q.rdtype),
                "type_code": q.rdtype,
                "class": dns.rdataclass.to_text(q.rdclass),
                "class_code": q.rdclass,
            })

        # 3. Answers Section
        answers = []
        for rrset in msg.answer:
            rr_name = str(rrset.name).rstrip(".")
            rr_type = dns.rdatatype.to_text(rrset.rdtype)
            rr_class = dns.rdataclass.to_text(rrset.rdclass)
            rr_ttl = rrset.ttl

            for rdata in rrset:
                rdata_str = str(rdata)
                geo = {}
                if rr_type == "A":
                    geo = geoip_resolver.resolve(rdata_str)

                answers.append({
                    "name": rr_name,
                    "type": rr_type,
                    "class": rr_class,
                    "ttl": rr_ttl,
                    "data": rdata_str,
                    "geoip": geo,
                })

        # 4. DoH RFC 8484 HTTP/2 Frame Encapsulation Metadata
        prov_name = (provider_info or {}).get("name", "Cloudflare")
        prov_url = (provider_info or {}).get("url", "https://cloudflare-dns.com/dns-query")
        authority = prov_url.split("://")[1].split("/")[0]

        doh_framing = {
            "rfc": "RFC 8484 (DNS Queries over HTTPS)",
            "http_version": "HTTP/2 (h2)",
            "transport_security": "TLS 1.3 (RFC 8446)",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "pseudo_headers": {
                ":method": "POST",
                ":scheme": "https",
                ":authority": authority,
                ":path": "/dns-query",
            },
            "headers": {
                "content-type": "application/dns-message",
                "accept": "application/dns-message",
                "content-length": f"{len(wire_bytes)} bytes",
                "user-agent": "cipherDNS/1.0",
            },
            "tls_record": {
                "record_type": "ContentType 23 (Application Data)",
                "record_length": f"{len(wire_bytes) + 16} bytes (includes AEAD tag)",
                "encryption": "AES-256-GCM authenticated encryption",
            },
            "provider": prov_name,
        }

        return {
            "wire_hex": wire_hex,
            "header": header_info,
            "questions": questions,
            "answers": answers,
            "doh_framing": doh_framing,
        }


# Global singleton instance
wire_inspector = WirePacketInspector()

