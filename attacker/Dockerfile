# Lab attacker toolbox. Used only to drive scripts/run_attacks.sh against the
# demo targets on the isolated sentrix_lab network. Not started by default
# (compose profile "attack"); nothing here is installed on the host.
FROM alpine:3.20

RUN echo "https://dl-cdn.alpinelinux.org/alpine/v3.20/community" >> /etc/apk/repositories \
    && apk add --no-cache \
        bash nmap nmap-scripts hydra tcpdump iproute2 libpcap \
        python3 py3-pip \
    && pip install --no-cache-dir --break-system-packages scapy

COPY scapy_arp_poison.py scapy_dns_tunnel.py wordlist.txt /attacker/
WORKDIR /attacker

# Idle; the scenarios are launched with `docker compose run/exec`.
CMD ["sleep", "infinity"]
