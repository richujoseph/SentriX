import { useCallback, useEffect, useState } from "react";
import { fetchAssets, scanAssets } from "../api.js";
import { formatDateTime, shortHostname } from "../format.js";

function PortList({ ports, scanned }) {
  if (scanned && !ports) return <span className="muted not-seen">not seen in last scan</span>;
  if (!ports) return <span className="muted">—</span>;
  if (ports.length === 0) return <span className="muted">none open</span>;
  return (
    <span className="port-list">
      {ports.map((p) => (
        <span key={`${p.protocol}/${p.port}`} className="tag port-tag" title={[p.product, p.version].filter(Boolean).join(" ")}>
          {p.port}
          {p.service && <span className="port-service">{p.service}</span>}
        </span>
      ))}
    </span>
  );
}

function ScanPanel({ onScanned }) {
  const [subnet, setSubnet] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const run = async (e) => {
    e.preventDefault();
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const data = await scanAssets(subnet.trim() || null);
      setResult(data);
      onScanned(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  return (
    <form className="scan-panel" onSubmit={run}>
      <label className="filter-group">
        <span className="filter-label">Subnet</span>
        <input
          type="text"
          value={subnet}
          onChange={(e) => setSubnet(e.target.value)}
          placeholder="Default (SCAN_SUBNET)"
          aria-label="Subnet to scan, e.g. 172.30.0.0/24"
          disabled={scanning}
          spellCheck={false}
        />
      </label>
      <button type="submit" className="primary-button scan-button" disabled={scanning}>
        {scanning ? (
          <>
            <span className="spinner" aria-hidden="true" /> Scanning…
          </>
        ) : (
          "Run asset scan"
        )}
      </button>
      <span className="scan-status" role="status">
        {scanning && "This can take a minute for a full /24."}
        {result && `Scanned ${result.subnet}: ${result.hosts_found} host${result.hosts_found === 1 ? "" : "s"} found.`}
      </span>
      {error && <div className="banner banner-error scan-error">Scan failed: {error}</div>}
    </form>
  );
}

export default function Assets() {
  const [page, setPage] = useState(null);
  const [error, setError] = useState(null);
  // Open ports aren't stored, so they come from the last scan run on this page.
  const [portsByIp, setPortsByIp] = useState(null);

  const load = useCallback(async (signal) => {
    try {
      setPage(await fetchAssets(signal));
      setError(null);
    } catch (err) {
      if (err.name !== "AbortError") setError(err.message);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const onScanned = (result) => {
    setPortsByIp(new Map(result.hosts.map((h) => [h.ip, h.open_ports])));
    load();
  };

  const assets = page?.items ?? [];

  return (
    <main className="content">
      <ScanPanel onScanned={onScanned} />

      {error && <div className="banner banner-error">Couldn't load assets: {error}</div>}
      {page && (
        <p className="result-count">
          {page.total} asset{page.total === 1 ? "" : "s"} · most critical first
        </p>
      )}

      {!page && !error ? (
        <p className="empty">Loading assets…</p>
      ) : assets.length === 0 && !error ? (
        <p className="empty">No assets yet. Run a scan to discover hosts.</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>IP</th>
                <th>Role</th>
                <th>Criticality</th>
                <th>MAC</th>
                <th>Open ports {portsByIp ? "(last scan)" : ""}</th>
                <th>First seen</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.id}>
                  <td className="host-cell">{shortHostname(a.hostname) ?? <span className="muted">unknown</span>}</td>
                  <td className="mono">{a.ip}</td>
                  <td className="capitalize">{a.role?.replace("_", " ") ?? "—"}</td>
                  <td>
                    <span className={`crit-meter crit-${a.criticality}`} title={`Criticality ${a.criticality} of 5`}>
                      {[1, 2, 3, 4, 5].map((n) => (
                        <span key={n} className={n <= a.criticality ? "on" : ""} />
                      ))}
                      <span className="crit-num">{a.criticality}</span>
                    </span>
                  </td>
                  <td className="mono muted">{a.mac ?? "—"}</td>
                  <td>
                    <PortList ports={portsByIp?.get(a.ip) ?? null} scanned={portsByIp !== null} />
                  </td>
                  <td className="nowrap muted">{formatDateTime(a.first_seen)}</td>
                  <td className="nowrap muted">{formatDateTime(a.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
