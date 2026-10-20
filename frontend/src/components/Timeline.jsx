import { formatDuration, formatTime } from "../format.js";
import { buildTimeline } from "../timeline.js";

function portsLabel(ports) {
  const list = [...ports].sort((a, b) => a - b);
  if (list.length === 0) return "";
  if (list.length <= 4) return `:${list.join(", ")}`;
  return ` (${list.length} ports)`;
}

export default function Timeline({ alerts, tactics }) {
  const phases = buildTimeline(alerts, tactics);
  if (phases.length === 0) return <p className="muted">No alerts recorded.</p>;

  return (
    <ol className="timeline">
      {phases.map((phase) => (
        <li key={phase.key} className={`phase ${phase.tactic.id ? "" : "phase-unmapped"}`}>
          <div className="phase-header">
            <span className="phase-node" aria-hidden="true" />
            <span className="tactic-chip">
              {phase.tactic.id && <span className="tactic-id">{phase.tactic.id}</span>}
              {phase.tactic.name}
            </span>
            <span className="phase-time">{formatTime(phase.start)}</span>
          </div>
          <ul className="phase-rows">
            {phase.rows.map((row) => (
              <li key={row.key} className="event">
                <span className="event-time mono">{formatTime(row.start)}</span>
                <div className="event-body">
                  <div className="event-title">
                    <span className={`sev-pill sev-${row.severity ?? "na"}`} title="Suricata severity (1 = most severe)">
                      S{row.severity ?? "?"}
                    </span>
                    {row.signature}
                    {row.count > 1 && <span className="event-count">×{row.count}</span>}
                  </div>
                  <div className="event-meta">
                    {row.dest_ip && (
                      <span className="mono">
                        → {row.dest_ip}
                        {portsLabel(row.ports)}
                      </span>
                    )}
                    {row.category && <span>{row.category}</span>}
                    {row.count > 1 && <span>over {formatDuration(row.start, row.end)}</span>}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ol>
  );
}
