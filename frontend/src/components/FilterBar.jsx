import { SEVERITY_LEVELS } from "../severity.js";

export const STATUSES = ["open", "investigating", "resolved", "closed"];

export default function FilterBar({ severity, status, onSeverityChange, onStatusChange }) {
  return (
    <div className="filter-bar">
      <div className="filter-group" role="group" aria-label="Filter by severity">
        <span className="filter-label">Severity</span>
        <div className="segmented">
          <button type="button" aria-pressed={severity === null} onClick={() => onSeverityChange(null)}>
            All
          </button>
          {SEVERITY_LEVELS.map((level) => (
            <button
              key={level.key}
              type="button"
              className={`seg-${level.key}`}
              aria-pressed={severity === level.key}
              onClick={() => onSeverityChange(level.key)}
            >
              <span className={`dot dot-${level.key}`} aria-hidden="true" />
              {level.label}
            </button>
          ))}
        </div>
      </div>

      <label className="filter-group">
        <span className="filter-label">Status</span>
        <select value={status ?? ""} onChange={(e) => onStatusChange(e.target.value || null)}>
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s[0].toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}
