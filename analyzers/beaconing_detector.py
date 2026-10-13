"""
Beaconing Detector
===================
Detects C2 (Command & Control) beaconing behavior:
  - Regular periodic connections to the same destination
  - Low jitter in inter-arrival times
  - Many small connections over long periods

Heuristic:
  For each (src, dst, dst_port) tuple:
    - collect timestamps of connections
    - compute intervals between consecutive connections
    - if >= MIN_CONNECTIONS and std(intervals) is low => beacon
"""

import math
from collections import defaultdict


MIN_CONNECTIONS = 8
MAX_MEAN_INTERVAL = 300   # seconds (5 minutes)
MAX_COEFFICIENT_VARIATION = 0.35  # std/mean


def _std(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _severity(cv, count):
    score = 0
    if cv <= 0.10:
        score += 50
    elif cv <= 0.20:
        score += 35
    elif cv <= 0.35:
        score += 20

    if count >= 50:
        score += 30
    elif count >= 20:
        score += 20
    elif count >= 8:
        score += 10

    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def detect(events):
    """Detect beaconing behavior from raw events."""
    # Group by (src, dst, dst_port)
    flows = defaultdict(list)

    for e in events:
        src = e.get("src_ip")
        dst = e.get("dst_ip")
        dport = e.get("dst_port")
        ts = e.get("timestamp")

        if not (src and dst and dport is not None and ts):
            continue

        # Focus on outbound-like flows (skip well-known responses)
        key = (src, dst, dport)
        flows[key].append(ts)

    findings = []

    for (src, dst, dport), timestamps in flows.items():
        if len(timestamps) < MIN_CONNECTIONS:
            continue

        ts_sorted = sorted(timestamps)
        intervals = [
            ts_sorted[i + 1] - ts_sorted[i]
            for i in range(len(ts_sorted) - 1)
        ]

        if not intervals:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0 or mean_interval > MAX_MEAN_INTERVAL:
            continue

        std_interval = _std(intervals)
        cv = std_interval / mean_interval

        if cv > MAX_COEFFICIENT_VARIATION:
            continue

        # Duration
        duration = round(ts_sorted[-1] - ts_sorted[0], 1)

        reasons = [
            f"{len(timestamps)} connections to {dst}:{dport}",
            f"Mean interval: {mean_interval:.1f}s (std: {std_interval:.1f}s)",
            f"Coefficient of variation: {cv:.3f}",
            f"Duration: {duration}s",
        ]

        findings.append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": dport,
            "connection_count": len(timestamps),
            "mean_interval_s": round(mean_interval, 2),
            "std_interval_s": round(std_interval, 2),
            "coefficient_variation": round(cv, 3),
            "duration_s": duration,
            "severity": _severity(cv, len(timestamps)),
            "reasons": reasons,
        })

    findings.sort(
        key=lambda x: (x["connection_count"], -x["coefficient_variation"]),
        reverse=True,
    )
    return findings