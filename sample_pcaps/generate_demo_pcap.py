"""
Generate Demo PCAP
===================
Creates a synthetic PCAP file with:
  - Normal HTTP traffic
  - HTTP Basic Auth (credential leak)
  - Port scan (SYN to many ports)
  - Suspicious DNS (long DGA domain)
  - C2 beaconing (regular intervals)
"""

from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR, Raw

packets = []
base_time = 1700000000.0

# 1. Normal HTTP traffic (benign)
for i in range(5):
    p = Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/TCP(
        sport=50000 + i, dport=80, flags="PA"
    )/Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    p.time = base_time + i * 0.5
    packets.append(p)

# 2. HTTP Basic Auth (CREDENTIAL LEAK)
p = Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/TCP(
    sport=50100, dport=80, flags="PA"
)/Raw(load=(
    b"GET /admin HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=\r\n"
    b"\r\n"
))
p.time = base_time + 10
packets.append(p)

# 3. Port Scan (SYN to many ports)
for i, port in enumerate([22, 23, 25, 80, 110, 135, 139, 143, 443, 445,
                          1433, 1521, 3306, 3389, 5432, 5900, 6379,
                          8080, 8443, 27017]):
    p = Ether()/IP(src="185.220.101.5", dst="192.168.1.10")/TCP(
        sport=40000 + i, dport=port, flags="S"
    )
    p.time = base_time + 20 + i * 0.1
    packets.append(p)

# 4. Suspicious DNS (DGA-like, long domain)
long_domain = (
    "a8f3k2j9x1m5n7p4q8r2t6y9w3e5d7c1b4a6s8f2g9h3j5k7l1"
    ".evil-c2.top"
)
p = Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(
    sport=53000, dport=53
)/DNS(rd=1, qd=DNSQR(qname=long_domain, qtype="A"))
p.time = base_time + 30
packets.append(p)

# 5. C2 Beaconing (regular 60s intervals)
for i in range(10):
    p = Ether()/IP(src="192.168.1.10", dst="203.0.113.99")/TCP(
        sport=55000 + i, dport=4444, flags="PA"
    )/Raw(load=b"\x00\x01\x02\x03")
    p.time = base_time + 60 + i * 60
    packets.append(p)

wrpcap("sample_pcaps/capture.pcap", packets)
print(f"Created sample_pcaps/capture.pcap with {len(packets)} packets")