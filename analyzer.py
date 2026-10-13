#!/usr/bin/env python3
"""
Network Traffic Forensics
==========================
Analyzes PCAP files to detect malicious network activity:
  - DNS anomalies (DGA / tunneling)
  - Port scans
  - C2 beaconing
  - Cleartext credential leaks

Outputs:
  - HTML report
  - JSON results
  - CSV files

Author: batool jameel
License: MIT
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from analyzers.pcap_loader import load_packets, extract_all, get_summary
from analyzers import (
    dns_analyzer,
    portscan_detector,
    beaconing_detector,
    credentials_detector,
)


# --------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------

def banner(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def write_csv(path, rows, fieldnames=None):
    if not rows:
        return
    if fieldnames is None:
        fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Convert lists to strings for CSV
            clean = {k: (", ".join(map(str, v)) if isinstance(v, list) else v)
                     for k, v in row.items()}
            writer.writerow(clean)


# --------------------------------------------------------------------
# Main analysis
# --------------------------------------------------------------------

def analyze(pcap_file, output_dir=None):
    if not os.path.exists(pcap_file):
        print(f"[!] PCAP not found: {pcap_file}")
        sys.exit(1)

    if output_dir is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"reports/analysis_{ts}"

    banner("[1/6] Loading PCAP file")
    packets = load_packets(pcap_file)
    events = extract_all(packets)
    print(f"  [+] Packets loaded: {len(events)}")

    # Strip payload for JSON-serializability (keep as string)
    for e in events:
        if isinstance(e.get("payload"), (bytes, bytearray)):
            e["payload"] = bytes(e["payload"])

    banner("[2/6] Traffic summary")
    summary = get_summary(events)
    print(f"  [+] Protocols:       {summary['protocols']}")
    print(f"  [+] Unique src IPs:  {summary['unique_src_ips']}")
    print(f"  [+] Unique dst IPs:  {summary['unique_dst_ips']}")

    banner("[3/6] DNS analysis")
    dns_findings = dns_analyzer.detect(events)
    dns_stats = dns_analyzer.get_dns_stats(events)
    print(f"  [+] DNS queries:  {dns_stats['total_queries']}")
    print(f"  [+] Findings:     {len(dns_findings)}")

    banner("[4/6] Port scan detection")
    scan_findings = portscan_detector.detect(events)
    print(f"  [+] Port scans detected: {len(scan_findings)}")

    banner("[5/6] Beaconing + credentials")
    beacon_findings = beaconing_detector.detect(events)
    cred_findings = credentials_detector.detect(events)
    print(f"  [+] Beaconing flows:     {len(beacon_findings)}")
    print(f"  [+] Credential leaks:    {len(cred_findings)}")

    banner("[6/6] Generating report")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    data = {
        "metadata": {
            "pcap_file": pcap_file,
            "analyzed_at": datetime.now().isoformat(timespec="seconds"),
        },
        "summary": summary,
        "dns_stats": dns_stats,
        "dns_findings": dns_findings,
        "port_scans": scan_findings,
        "beaconing": beacon_findings,
        "credential_leaks": cred_findings,
    }

    # JSON
    write_json(out / "analysis.json", data)

    # CSVs
    if dns_findings:
        write_csv(out / "dns_findings.csv", dns_findings)
    if scan_findings:
        write_csv(out / "port_scans.csv", scan_findings)
    if beacon_findings:
        write_csv(out / "beaconing.csv", beacon_findings)
    if cred_findings:
        write_csv(out / "credential_leaks.csv", cred_findings)

    # HTML
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("report_template.html")

    total_findings = (
        len(dns_findings) + len(scan_findings)
        + len(beacon_findings) + len(cred_findings)
    )

    html = template.render(
        data=data,
        generated_at=data["metadata"]["analyzed_at"],
        pcap_file=pcap_file,
        total_findings=total_findings,
    )

    with open(out / "report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  [+] HTML:  {out}/report.html")
    print(f"  [+] JSON:  {out}/analysis.json")
    print(f"  [+] CSVs:  dns_findings.csv, port_scans.csv, beaconing.csv, credential_leaks.csv")

    banner("DONE")
    print(f"  Total findings: {total_findings}")
    print(f"  Open the report: {out}\\report.html\n")

    return data


# --------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Forensics — PCAP analyzer"
    )
    parser.add_argument("pcap_file", help="Path to .pcap / .pcapng file")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output dir (default: reports/analysis_YYYYMMDD_HHMMSS)"
    )
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  NETWORK TRAFFIC FORENSICS")
    print("=" * 60)
    print(f"  PCAP:     {args.pcap_file}")
    print(f"  Started:  {datetime.now().isoformat(timespec='seconds')}")

    analyze(args.pcap_file, args.output)


if __name__ == "__main__":
    main()