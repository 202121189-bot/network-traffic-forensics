# 🌐 Network Traffic Forensics

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green.svg)
![Domain](https://img.shields.io/badge/Domain-DFIR-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A DFIR tool that analyzes PCAP files to detect malicious network activity — port scans, C2 beaconing, DNS anomalies, and cleartext credential leaks.

Built for **Network Security** and **Incident Response** workflows.

## ✨ Features

- 🚪 **Port Scan Detection** — many distinct ports, SYN-only packets
- 📡 **Beaconing Detection** — periodic C2-like callbacks (low jitter)
- 🌐 **DNS Anomaly Detection** — DGA, tunneling, suspicious TLDs, high entropy
- 🔓 **Cleartext Credentials** — HTTP Basic Auth, FTP, Telnet, form POSTs
- 📊 **Traffic Summary** — protocols, top IPs, top ports
- 📄 **Multi-format Output** — HTML, JSON, CSV
- 🎯 **Severity Scoring** — CRITICAL / HIGH / MEDIUM / LOW

## 🛠️ Requirements

- Python 3.8+
- `scapy`, `jinja2`

Install:

```bash
pip install -r requirements.txt