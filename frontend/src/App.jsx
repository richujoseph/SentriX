import { useState } from "react";
import Dashboard from "./pages/Dashboard.jsx";
import IncidentDetail from "./pages/IncidentDetail.jsx";
import { useHashPath } from "./router.js";

export default function App() {
  const path = useHashPath();
  // Kept here so the dashboard's filters survive a trip to a detail page.
  const [severity, setSeverity] = useState(null);
  const [status, setStatus] = useState(null);
  const [live, setLive] = useState({ error: null, updatedAt: null, refresh: null });

  const incidentMatch = path.match(/^\/incidents\/(\d+)$/);

  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href="#/">
          <span className="brand-mark" aria-hidden="true">◆</span>
          SentriX
          <span className="brand-sub">{incidentMatch ? `Incident #${incidentMatch[1]}` : "Incidents"}</span>
        </a>
        {!incidentMatch && (
          <div className="topbar-status">
            <span className={`live-dot ${live.error ? "live-down" : "live-up"}`} aria-hidden="true" />
            {live.error
              ? "Backend unreachable"
              : live.updatedAt
                ? `Updated ${live.updatedAt.toLocaleTimeString()}`
                : "Connecting…"}
            <button type="button" className="ghost-button" onClick={() => live.refresh?.()}>
              Refresh
            </button>
          </div>
        )}
      </header>

      {incidentMatch ? (
        <IncidentDetail id={Number(incidentMatch[1])} />
      ) : (
        <Dashboard
          severity={severity}
          status={status}
          onSeverityChange={setSeverity}
          onStatusChange={setStatus}
          onStatus={setLive}
        />
      )}
    </div>
  );
}
