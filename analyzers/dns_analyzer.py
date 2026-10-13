"""
DNS Analyzer
=============
Detects suspicious DNS activity:
  - Very long domain names (DGA / tunneling)
  - High-entropy subdomains (encoded data)
  - DNS queries for known-bad TLDs
  - TXT queries (common in exfiltration)
  - Excessive queries to a single domain
"""

import math
from collections import Counter


SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".ru", ".cn", ".su", ".onion", ".bit", ".bazar",
    ".click", ".download", ".stream", ".rest", ".pw",
}

WHITELIST_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "wikipedia.org", "github.com", "microsoft.com", "apple.com",
    "cloudflare.com", "office.com", "live.com", "bing.com",
    "netflix.com", "linkedin.com", "twitter.com", "x.com",
}

MIN_DOMAIN_LENGTH = 40
ENTROPY_THRESHOLD = 3.8
EXCESSIVE_QUERY_COUNT = 20


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _base_domain(name: str) -> str:
    parts = name.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def _is_whitelisted(name: str) -> bool:
    return _base_domain(name).lower() in WHITELIST_DOMAINS


def _tld(name: str) -> str:
    parts = name.strip(".").split(".")
    return "." + parts[-1].lower() if parts else ""


def _severity(score):
    if score >= 60:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def detect(events):
    """Analyze DNS events and return findings."""
    dns_events = [e for e in events if e.get("dns_query")]
    findings = []
    domain_counter = Counter()

    for e in dns_events:
        domain_counter[e["dns_query"]] += 1

    # Rule 1: long / high-entropy domains
    for e in dns_events:
        name = e["dns_query"]
        if _is_whitelisted(name):
            continue

        reasons = []
        score = 0

        if len(name) >= MIN_DOMAIN_LENGTH:
            reasons.append(f"Very long domain ({len(name)} chars)")
            score += 25

        ent = _entropy(name.replace(".", ""))
        if ent >= ENTROPY_THRESHOLD:
            reasons.append(f"High entropy ({ent:.2f} bits/char)")
            score += 30

        tld = _tld(name)
        if tld in SUSPICIOUS_TLDS:
            reasons.append(f"Suspicious TLD ({tld})")
            score += 20

        if e.get("dns_type") == "TXT":
            reasons.append("TXT query (exfiltration vector)")
            score += 15

        if score > 0:
            findings.append({
                "timestamp": e["datetime"],
                "src_ip": e["src_ip"],
                "query": name,
                "dns_type": e.get("dns_type"),
                "entropy": round(ent, 2),
                "score": min(score, 100),
                "severity": _severity(score),
                "reasons": reasons,
            })

    # Rule 2: excessive queries to same base domain
    base_counter = Counter(_base_domain(n) for n in domain_counter)
    for base, count in base_counter.items():
        if count >= EXCESSIVE_QUERY_COUNT and base not in WHITELIST_DOMAINS:
            findings.append({
                "timestamp": "",
                "src_ip": "multiple",
                "query": base,
                "dns_type": "multi",
                "entropy": 0.0,
                "score": 40,
                "severity": "MEDIUM",
                "reasons": [f"{count} queries to same base domain"],
            })

    findings.sort(key=lambda x: x["score"], reverse=True)
    return findings


def get_dns_stats(events):
    dns_events = [e for e in events if e.get("dns_query")]
    queries = [e["dns_query"] for e in dns_events]
    types = Counter(e.get("dns_type") for e in dns_events if e.get("dns_type"))
    return {
        "total_queries": len(queries),
        "unique_domains": len(set(queries)),
        "types": dict(types),
    }