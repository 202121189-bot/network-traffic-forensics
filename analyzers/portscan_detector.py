"""
Port Scan Detector
===================
Detects port scanning activity based on:
  - Many distinct destination ports hit by the same source IP
  - Many SYN packets without completing handshakes
  - Fast scan rate within a short time window

Heuristic:
  - >= 15 distinct ports from same src IP => scan
  - >= 20 SYN-only packets from same src IP => scan
"""

from collections import defaultdict


MIN_DISTINCT_PORTS = 15
MIN_SYN_PACKETS = 20
TIME_WINDOW_SECONDS = 60


def _severity(port_count, syn_count):
    score = 0
    if port_count >= 100:
        score += 50
    elif port_count >= 50:
        score += 35
    elif port_count >= 15:
        score += 20

    if syn_count >= 100:
        score += 40
    elif syn_count >= 50:
        score += 30
    elif syn_count >= 20:
        score += 20

    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def detect(events):
    """Detect port scans from raw events."""
    # Group per source IP
    src_stats = defaultdict(lambda: {
        "distinct_ports": set(),
        "syn_count": 0,
        "scan_targets": set(),
        "timestamps": [],
        "total_packets": 0,
    })

    for e in events:
        if e["protocol"] != "TCP":
            continue

        src = e.get("src_ip")
        dst = e.get("dst_ip")
        dst_port = e.get("dst_port")
        flags = e.get("flags") or ""

        if not src or dst_port is None:
            continue

        entry = src_stats[src]
        entry["total_packets"] += 1
        entry["distinct_ports"].add(dst_port)
        entry["scan_targets"].add(dst)
        entry["timestamps"].append(e["timestamp"])

        # SYN without ACK = scan-like
        if "S" in flags and "A" not in flags:
            entry["syn_count"] += 1

    findings = []
    for src, data in src_stats.items():
        port_count = len(data["distinct_ports"])
        syn_count = data["syn_count"]

        if port_count < MIN_DISTINCT_PORTS and syn_count < MIN_SYN_PACKETS:
            continue

        # Time window analysis
        ts_sorted = sorted(data["timestamps"])
        window_ports = port_count
        window_duration = 0.0

        if ts_sorted:
            first = ts_sorted[0]
            last = first
            for t in ts_sorted:
                if t - first <= TIME_WINDOW_SECONDS:
                    last = t
                else:
                    break
            window_duration = round(last - first, 2)

        reasons = []
        if port_count >= MIN_DISTINCT_PORTS:
            reasons.append(f"{port_count} distinct destination ports probed")
        if syn_count >= MIN_SYN_PACKETS:
            reasons.append(f"{syn_count} SYN-only packets (no handshake)")
        if window_duration > 0 and window_duration <= TIME_WINDOW_SECONDS:
            reasons.append(f"All within {window_duration}s (fast scan)")
        if len(data["scan_targets"]) > 1:
            reasons.append(f"Targeted {len(data['scan_targets'])} distinct hosts")

        severity = _severity(port_count, syn_count)

        findings.append({
            "src_ip": src,
            "distinct_ports": port_count,
            "syn_packets": syn_count,
            "targets": len(data["scan_targets"]),
            "total_packets": data["total_packets"],
            "window_seconds": window_duration,
            "severity": severity,
            "reasons": reasons,
            "ports_sample": sorted(list(data["distinct_ports"]))[:30],
        })

    findings.sort(
        key=lambda x: (x["distinct_ports"] + x["syn_packets"]),
        reverse=True,
    )
    return findings