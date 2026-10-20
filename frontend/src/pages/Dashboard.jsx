import { useCallback, useEffect, useState } from "react";
import { fetchIncidents } from "../api.js";
import FilterBar from "../components/FilterBar.jsx";
import IncidentCard from "../components/IncidentCard.jsx";
import { SEVERITY_LEVELS } from "../severity.js";

const REFRESH_MS = 15000;

export default function Dashboard({ severity, status, onSeverityChange, onStatusChange, onStatus }) {
  const [page, setPage] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(
    async (signal) => {
      const level = SEVERITY_LEVELS.find((l) => l.key === severity);
      try {
        const data = await fetchIncidents(
          { status, minSeverity: level?.min, maxSeverity: level?.max ?? undefined },
          signal,
        );
        setPage(data);
        setError(null);
        onStatus({ error: null, updatedAt: new Date(), refresh: load });
      } catch (err) {
        if (err.name === "AbortError") return;
        setError(err.message);
        onStatus({ error: err.message, updatedAt: null, refresh: load });
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [severity, status, onStatus],
  );

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    load(controller.signal);
    const timer = setInterval(() => load(controller.signal), REFRESH_MS);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [load]);

  const incidents = page?.items ?? [];
  const filtered = severity !== null || status !== null;

  return (
    <main className="content">
      <FilterBar severity={severity} status={status} onSeverityChange={onSeverityChange} onStatusChange={onStatusChange} />

      {error && <div className="banner banner-error">Couldn't load incidents: {error}</div>}

      {page && (
        <p className="result-count">
          {page.total} incident{page.total === 1 ? "" : "s"}
          {page.total > incidents.length && ` · showing the ${incidents.length} most severe`}
        </p>
      )}

      {loading && !page ? (
        <p className="empty">Loading incidents…</p>
      ) : incidents.length === 0 && !error ? (
        <p className="empty">{filtered ? "No incidents match these filters." : "No incidents yet."}</p>
      ) : (
        <div className="card-grid">
          {incidents.map((incident) => (
            <IncidentCard key={incident.id} incident={incident} />
          ))}
        </div>
      )}
    </main>
  );
}
