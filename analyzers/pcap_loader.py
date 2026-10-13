"""
PCAP Loader
============
Loads packets from a PCAP file using Scapy and extracts relevant
information for forensic analysis.

Supported protocols:
  - Ethernet / IP / TCP / UDP / ICMP
  - DNS queries and responses
  - HTTP requests (basic parsing)
"""

import os
from collections import Counter
from datetime import datetime

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw


def load_packets(filepath):
    """Load packets from PCAP file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP not found: {filepath}")

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        raise RuntimeError(f"Failed to read PCAP: {e}")

    return packets


def packet_to_dict(pkt):
    """Convert a Scapy packet into a flat dict for analysis."""
    info = {
        "timestamp": float(pkt.time),
        "datetime": datetime.fromtimestamp(float(pkt.time)).isoformat(timespec="seconds"),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "length": len(pkt),
        "flags": None,
        "dns_query": None,
        "dns_type": None,
        "payload": None,
    }

    if IP in pkt:
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst
        info["protocol"] = _proto_name(pkt[IP].proto)

    if TCP in pkt:
        info["protocol"] = "TCP"
        info["src_port"] = int(pkt[TCP].sport)
        info["dst_port"] = int(pkt[TCP].dport)
        info["flags"] = str(pkt[TCP].flags)
        if Raw in pkt:
            info["payload"] = bytes(pkt[Raw].load)[:512]

    elif UDP in pkt:
        info["protocol"] = "UDP"
        info["src_port"] = int(pkt[UDP].sport)
        info["dst_port"] = int(pkt[UDP].dport)

        if DNS in pkt and pkt[DNS].qd is not None:
            try:
                qname = pkt[DNS].qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="ignore")
                info["dns_query"] = qname.rstrip(".")
                info["dns_type"] = _dns_type_name(pkt[DNS].qd.qtype)
            except Exception:
                pass

    return info


def _proto_name(num):
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(num, str(num))


def _dns_type_name(num):
    return {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
        12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
        33: "SRV", 255: "ANY",
    }.get(num, str(num))


def extract_all(packets):
    """Convert all packets into flat dicts."""
    return [packet_to_dict(p) for p in packets]


def get_summary(events):
    """Build basic traffic summary."""
    protocols = Counter(e["protocol"] for e in events if e["protocol"])
    src_ips = Counter(e["src_ip"] for e in events if e["src_ip"])
    dst_ips = Counter(e["dst_ip"] for e in events if e["dst_ip"])
    dst_ports = Counter(
        e["dst_port"] for e in events if e["dst_port"] is not None
    )

    return {
        "total_packets": len(events),
        "protocols": dict(protocols),
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "top_src_ips": src_ips.most_common(10),
        "top_dst_ips": dst_ips.most_common(10),
        "top_dst_ports": dst_ports.most_common(10),
    }