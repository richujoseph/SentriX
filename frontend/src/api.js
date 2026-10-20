export const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export async function fetchIncidents({ status, minSeverity, maxSeverity, limit = 100 } = {}, signal) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (status) params.set("status", status);
  if (minSeverity != null) params.set("min_severity", String(minSeverity));
  if (maxSeverity != null) params.set("max_severity", String(maxSeverity));

  const res = await fetch(`${API_URL}/incidents?${params}`, { signal });
  if (!res.ok) throw new Error(`GET /incidents failed (${res.status})`);
  return res.json();
}

export const incidentReportUrl = (id) => `${API_URL}/incidents/${id}/report.pdf`;

export async function fetchIncident(id, signal) {
  const res = await fetch(`${API_URL}/incidents/${id}`, { signal });
  if (res.status === 404) throw new Error("Incident not found");
  if (!res.ok) throw new Error(`GET /incidents/${id} failed (${res.status})`);
  return res.json();
}

// Blocks until the LLM answers, which can take a minute with a local model.
export async function summarizeIncident(id) {
  const res = await fetch(`${API_URL}/incidents/${id}/summarize`, { method: "POST" });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.detail ?? `Summarize failed (${res.status})`);
  }
  return res.json();
}

async function totalOf(path, signal) {
  const res = await fetch(`${API_URL}${path}`, { signal });
  if (!res.ok) throw new Error(`GET ${path} failed (${res.status})`);
  return (await res.json()).total;
}

// Overview counts, read from the `total` of each list endpoint.
export async function fetchOverview(signal) {
  const [alerts, incidents, highOpen] = await Promise.all([
    totalOf("/alerts?limit=1", signal),
    totalOf("/incidents?limit=1", signal),
    totalOf("/incidents?limit=1&status=open&min_severity=50", signal),
  ]);
  return { alerts, incidents, highOpen };
}

export async function fetchAssets(signal) {
  const res = await fetch(`${API_URL}/assets?limit=500`, { signal });
  if (!res.ok) throw new Error(`GET /assets failed (${res.status})`);
  return res.json();
}

// Blocks until nmap finishes (tens of seconds for a /24).
export async function scanAssets(subnet) {
  const res = await fetch(`${API_URL}/assets/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(subnet ? { subnet } : {}),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error(body?.detail ?? `Scan failed (${res.status})`);
  return body;
}
