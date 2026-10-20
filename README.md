# SentriX

Network alert triage: Suricata analyses packet captures, the backend ingests its
alerts into Postgres, and a React frontend displays them.

| Service    | What it does                                                    | Port |
|------------|-----------------------------------------------------------------|------|
| `db`       | Postgres 16                                                     | –    |
| `backend`  | FastAPI app; tails `logs/eve.json` and stores alerts            | 8000 |
| `frontend` | Vite + React dev server                                         | 5173 |
| `suricata` | Processes every capture in `pcaps/` into `logs/eve.json`, exits | –    |

## Quick start

```sh
cp .env.example .env              # set a password; keep DATABASE_URL in sync with it
./scripts/get_sample_pcap.sh      # downloads a sample Nmap scan into pcaps/sample.pcap
docker compose up --build
```

Then open http://localhost:5173, or list ingested alerts at
http://localhost:8000/alerts.

## Analysing your own PCAP

1. Copy the capture into `pcaps/` (any filename; `.pcap`, `.pcapng` and `.cap`
   all work). Suricata processes **every** file in the folder, so remove ones you
   don't want analysed.
2. Re-run Suricata:

   ```sh
   docker compose restart suricata
   ```

3. Watch the alerts arrive at http://localhost:8000/alerts.

On each start, the Suricata container moves the previous `logs/eve.json` to
`logs/eve.json.prev`, reprocesses all captures from scratch, and exits. The
backend notices the new file and ingests its alerts within a second or two.

Notes:

- **Re-running is safe.** Each alert is fingerprinted (timestamp, endpoints,
  protocol, rule), so reprocessing a capture doesn't duplicate rows in
  `raw_alerts`; only alerts from new captures are added.
- **Home network.** The rules only fire for traffic *to* `HOME_NET`, which is
  set to the private ranges (10/8, 172.16/12, 192.168/16) in
  `suricata/suricata.yaml`. Adjust it if your capture's targets use other
  addresses.
- **Captures stay local.** `pcaps/` is gitignored, since captures can contain
  sensitive traffic.

## Detection rules

Custom rules live in `suricata/rules/local.rules` (SIDs 1000001+): ICMP ping,
SSH connection attempts, SYN port scans (20+ SYNs from one source in 10s), and
TCP NULL / Xmas scans. After editing them, run `docker compose restart suricata`.

## Sample capture

`scripts/get_sample_pcap.sh` fetches `NMap-Captures.zip` from the
[Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures), checks
its SHA-256, and extracts `nmap_OS_scan_succesful`: an `nmap -O` OS-detection
scan that triggers all of the local rules.
