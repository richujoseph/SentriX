import { useCallback, useEffect, useState } from "react";
import { fetchIncidents } from "./api.js";
import FilterBar from "./components/FilterBar.jsx";
import IncidentCard from "./components/IncidentCard.jsx";
import { SEVERITY_LEVELS } from "./severity.js";

const REFRESH_MS = 15000;

export default function App() {
  const [severity, setSeverity] = useState(null);
  const [status, setStatus] = useState(null);
  const [page, setPage] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState(null);

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
        setUpdatedAt(new Date());
      } catch (err) {
        if (err.name !== "AbortError") setError(err.message);
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [severity, status],
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
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">◆</span>
          SentriX
          <span className="brand-sub">Incidents</span>
        </div>
        <div className="topbar-status">
          <span className={`live-dot ${error ? "live-down" : "live-up"}`} aria-hidden="true" />
          {error ? "Backend unreachable" : updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : "Connecting…"}
          <button type="button" className="ghost-button" onClick={() => load()}>
            Refresh
          </button>
        </div>
      </header>

      <main className="content">
        <FilterBar severity={severity} status={status} onSeverityChange={setSeverity} onStatusChange={setStatus} />

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
    </div>
  );
}
