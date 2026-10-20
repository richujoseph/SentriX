#!/bin/sh
# Container entrypoint: reprocess every capture in /pcaps on each start.
# The previous eve.json is rotated to eve.json.prev so the new run starts a fresh
# file, which the backend watcher detects and ingests from the beginning.
# Single runmode keeps packet order (and so threshold alerts) deterministic.
set -e

LOG_DIR=/var/log/suricata

if [ -z "$(ls -A /pcaps 2>/dev/null)" ]; then
  echo "No captures in /pcaps; run scripts/get_sample_pcap.sh or add your own .pcap"
  exit 0
fi

rm -f "$LOG_DIR/eve.json.prev"
[ -f "$LOG_DIR/eve.json" ] && mv "$LOG_DIR/eve.json" "$LOG_DIR/eve.json.prev"

exec /docker-entrypoint.sh -c /etc/suricata/suricata.yaml -r /pcaps -l "$LOG_DIR" -k none --runmode single
