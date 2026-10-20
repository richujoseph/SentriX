import { useCallback, useEffect, useState } from "react";
import { fetchIncident, incidentReportUrl, summarizeIncident } from "../api.js";
import AssetPanel from "../components/AssetPanel.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import Timeline from "../components/Timeline.jsx";
import { formatDateTime, formatDuration } from "../format.js";
import { severityLevel } from "../severity.js";
import { isFallbackSummary, stripFallbackPrefix } from "../summary.js";

function Narrative({ incident, onSummarize, summarizing, summarizeError }) {
  const fallback = isFallbackSummary(incident.summary);
  const hasAiSummary = incident.summary && !fallback;

  return (
    <section className="panel narrative">
      <div className="panel-title-row">
        <h2 className="panel-title">{hasAiSummary ? "AI narrative" : "Narrative"}</h2>
        <button type="button" className="ghost-button" onClick={onSummarize} disabled={summarizing}>
          {summarizing ? "Generating… (can take a minute)" : hasAiSummary ? "Regenerate" : "Generate AI summary"}
        </button>
      </div>

      {fallback && (
        <p className="notice">The AI model was unavailable, so this is an automatic digest. It will be retried.</p>
      )}
      {incident.summary ? (
        <p className="narrative-text">{stripFallbackPrefix(incident.summary)}</p>
      ) : (
        <p className="muted">No summary yet.</p>
      )}
      {summarizeError && <div className="banner banner-error">{summarizeError}</div>}

      {incident.recommended_action && (
        <div className={`action-callout ${fallback ? "action-fallback" : ""}`}>
          <span className="action-label">Recommended action</span>
          <p>{incident.recommended_action}</p>
        </div>
      )}
    </section>
  );
}

export default function IncidentDetail({ id }) {
  const [incident, setIncident] = useState(null);
  const [error, setError] = useState(null);
  const [summarizing, setSummarizing] = useState(false);
  const [summarizeError, setSummarizeError] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    setIncident(null);
    setError(null);
    fetchIncident(id, controller.signal)
      .then(setIncident)
      .catch((err) => err.name !== "AbortError" && setError(err.message));
    return () => controller.abort();
  }, [id]);

  const onSummarize = useCallback(async () => {
    setSummarizing(true);
    setSummarizeError(null);
    try {
      const updated = await summarizeIncident(id);
      setIncident((prev) => ({ ...prev, summary: updated.summary, recommended_action: updated.recommended_action }));
    } catch (err) {
      setSummarizeError(err.message);
    } finally {
      setSummarizing(false);
    }
  }, [id]);

  const back = (
    <a className="back-link" href="#/">
      ← All incidents
    </a>
  );

  if (error) {
    return (
      <main className="content">
        {back}
        <div className="banner banner-error">Couldn't load incident #{id}: {error}</div>
      </main>
    );
  }
  if (!incident) {
    return (
      <main className="content">
        {back}
        <p className="empty">Loading incident…</p>
      </main>
    );
  }

  const level = severityLevel(incident.severity_score);
  return (
    <main className="content">
      {back}

      <header className={`detail-header card-${level.key}`}>
        <div className="detail-title-row">
          <SeverityBadge score={incident.severity_score} />
          <h1>Incident #{incident.id}</h1>
          <span className={`status status-${incident.status}`}>{incident.status}</span>
          <a className="primary-button" href={incidentReportUrl(incident.id)} download>
            Download report
          </a>
        </div>
        <dl className="detail-facts">
          <div>
            <dt>Source</dt>
            <dd className="mono src-ip">{incident.src_ip}</dd>
          </div>
          <div>
            <dt>Started</dt>
            <dd>{formatDateTime(incident.start_time)}</dd>
          </div>
          <div>
            <dt>Duration</dt>
            <dd>{formatDuration(incident.start_time, incident.end_time)}</dd>
          </div>
          <div>
            <dt>Alerts</dt>
            <dd>{incident.alert_count}</dd>
          </div>
          <div>
            <dt>Tactics</dt>
            <dd>{incident.mitre_tactics.length}</dd>
          </div>
        </dl>
      </header>

      <div className="detail-grid">
        <div className="detail-main">
          <Narrative
            incident={incident}
            onSummarize={onSummarize}
            summarizing={summarizing}
            summarizeError={summarizeError}
          />
          <section className="panel">
            <h2 className="panel-title">Attack timeline</h2>
            <Timeline alerts={incident.alerts} tactics={incident.mitre_tactics} />
          </section>
        </div>
        <aside className="detail-side">
          <AssetPanel targets={incident.targets} alerts={incident.alerts} />
        </aside>
      </div>
    </main>
  );
}
