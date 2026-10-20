import { useState } from "react";
import Overview from "./components/Overview.jsx";
import Assets from "./pages/Assets.jsx";
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
  const onAssets = path === "/assets";
  const onDashboard = !incidentMatch && !onAssets;

  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-left">
          <a className="brand" href="#/">
            <span className="brand-mark" aria-hidden="true">◆</span>
            SentriX
          </a>
          <nav className="nav" aria-label="Main">
            <a href="#/" aria-current={!onAssets ? "page" : undefined}>
              Incidents
            </a>
            <a href="#/assets" aria-current={onAssets ? "page" : undefined}>
              Assets
            </a>
          </nav>
        </div>
        {onDashboard && (
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

      {!incidentMatch && <Overview />}

      {incidentMatch ? (
        <IncidentDetail id={Number(incidentMatch[1])} />
      ) : onAssets ? (
        <Assets />
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
