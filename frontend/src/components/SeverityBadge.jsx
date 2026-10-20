import { severityLevel } from "../severity.js";

export default function SeverityBadge({ score }) {
  const level = severityLevel(score);
  return (
    <span className={`severity-badge severity-${level.key}`} title={`Severity score ${score} / 100`}>
      <span className="severity-label">{level.label}</span>
      <span className="severity-score">{score.toFixed(1)}</span>
    </span>
  );
}
