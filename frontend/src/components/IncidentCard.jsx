import SeverityBadge from "./SeverityBadge.jsx";
import { formatDateTime, formatDuration, shortHostname } from "../format.js";
import { incidentHref } from "../router.js";
import { severityLevel } from "../severity.js";
import { stripFallbackPrefix } from "../summary.js";

function Target({ target }) {
  if (!target) return <span className="muted">No recorded target</span>;
  return (
    <span className="target">
      <span className="mono">{target.ip}</span>
      {target.known_asset ? (
        <>
          {target.hostname && <span className="target-host">{shortHostname(target.hostname)}</span>}
          <span className="tag">{target.role?.replace("_", " ") ?? "asset"}</span>
          <span className={`tag crit-${target.criticality}`}>crit {target.criticality}</span>
        </>
      ) : (
        <span className="tag tag-unknown">not in inventory</span>
      )}
    </span>
  );
}

export default function IncidentCard({ incident }) {
  const [primary, ...others] = incident.targets;
  const level = severityLevel(incident.severity_score);

  return (
    <a className={`card card-${level.key}`} href={incidentHref(incident.id)}>
      <header className="card-header">
        <SeverityBadge score={incident.severity_score} />
        <span className="card-meta">
          #{incident.id} · <span className={`status status-${incident.status}`}>{incident.status}</span>
        </span>
      </header>

      <div className="card-route">
        <div className="field">
          <span className="field-label">Source</span>
          <span className="mono src-ip">{incident.src_ip}</span>
        </div>
        <span className="arrow" aria-hidden="true">→</span>
        <div className="field">
          <span className="field-label">Target</span>
          <span>
            <Target target={primary} />
            {others.length > 0 && <span className="muted"> +{others.length} more</span>}
          </span>
        </div>
      </div>

      <p className="card-stats">
        {incident.alert_count} alert{incident.alert_count === 1 ? "" : "s"} ·{" "}
        {formatDateTime(incident.start_time)} · lasted {formatDuration(incident.start_time, incident.end_time)}
      </p>

      {incident.mitre_tactics.length > 0 && (
        <ol className="tactics" aria-label="MITRE ATT&CK tactics in order">
          {incident.mitre_tactics.map((tactic, i) => (
            <li key={tactic.id} className="tactic">
              {i > 0 && (
                <span className="tactic-arrow" aria-hidden="true">
                  →
                </span>
              )}
              <span className="tactic-chip" title={`First seen ${formatDateTime(tactic.first_seen)}`}>
                <span className="tactic-id">{tactic.id}</span>
                {tactic.name}
              </span>
            </li>
          ))}
        </ol>
      )}

      {incident.summary && <p className="summary">{stripFallbackPrefix(incident.summary)}</p>}
    </a>
  );
}
