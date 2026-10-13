"""
Credentials Detector
=====================
Detects cleartext credentials transmitted over insecure protocols:
  - HTTP Basic Auth (Authorization: Basic ...)
  - FTP USER/PASS commands
  - Telnet login prompts
  - Form POSTs with password fields (heuristic)
  - HTTP Cookies with common session names (heuristic)

Analyzes raw payload bytes from the PCAP.
"""

import re
from base64 import b64decode


# HTTP Basic auth header
RE_HTTP_BASIC = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.I)

# FTP commands
RE_FTP_USER = re.compile(rb"^USER\s+(\S+)", re.I | re.M)
RE_FTP_PASS = re.compile(rb"^PASS\s+(\S+)", re.I | re.M)

# Telnet/SSH prompt hints
RE_TELNET_LOGIN = re.compile(rb"(login|username)\s*:", re.I)
RE_TELNET_PASS = re.compile(rb"password\s*:", re.I)

# Form POST with password field
RE_FORM_PASS = re.compile(rb"password=([^&\s]+)", re.I)

# HTTP request line (to detect plain HTTP)
RE_HTTP_REQUEST = re.compile(rb"^(GET|POST|PUT|HEAD|OPTIONS|DELETE)\s+\S+\s+HTTP", re.I)


def _try_b64_decode(token: bytes):
    """Try to decode base64 basic-auth token to 'user:pass'."""
    try:
        decoded = b64decode(token + b"===").decode("utf-8", errors="ignore")
        if ":" in decoded:
            return decoded
    except Exception:
        pass
    return None


def detect(events):
    """Detect cleartext credential leaks in packet payloads."""
    findings = []

    for e in events:
        payload = e.get("payload")
        if not payload:
            continue

        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="ignore")

        src = e.get("src_ip", "")
        dst = e.get("dst_ip", "")
        ts = e.get("datetime", "")

        # --- HTTP Basic Auth ---
        m = RE_HTTP_BASIC.search(payload)
        if m:
            decoded = _try_b64_decode(m.group(1))
            findings.append({
                "timestamp": ts,
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "HTTP",
                "type": "basic_auth",
                "evidence": decoded or "(unable to decode)",
                "severity": "CRITICAL",
                "reasons": [
                    "HTTP Basic Auth sent over cleartext",
                    "Credentials can be trivially decoded",
                ],
            })

        # --- FTP credentials ---
        for cmd, kind in ((RE_FTP_USER, "ftp_user"), (RE_FTP_PASS, "ftp_pass")):
            m = cmd.search(payload)
            if m:
                findings.append({
                    "timestamp": ts,
                    "src_ip": src,
                    "dst_ip": dst,
                    "protocol": "FTP",
                    "type": kind,
                    "evidence": m.group(1).decode("utf-8", errors="ignore"),
                    "severity": "CRITICAL",
                    "reasons": ["FTP transmits credentials in cleartext"],
                })

        # --- Telnet prompts (payload containing login/password) ---
        if RE_TELNET_LOGIN.search(payload) or RE_TELNET_PASS.search(payload):
            findings.append({
                "timestamp": ts,
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "TELNET",
                "type": "login_prompt",
                "evidence": payload[:120].decode("utf-8", errors="ignore"),
                "severity": "HIGH",
                "reasons": ["Possible Telnet login prompt in cleartext"],
            })

        # --- Form POST with password ---
        m = RE_FORM_PASS.search(payload)
        if m:
            findings.append({
                "timestamp": ts,
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "HTTP",
                "type": "form_password",
                "evidence": f"password={m.group(1).decode('utf-8', errors='ignore')[:40]}",
                "severity": "HIGH",
                "reasons": ["HTTP form POST contains password field in cleartext"],
            })

    return findings