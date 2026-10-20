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
