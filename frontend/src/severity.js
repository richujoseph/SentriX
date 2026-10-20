// Severity bands over the 0-100 incident score. `max` is exclusive.
export const SEVERITY_LEVELS = [
  { key: "critical", label: "Critical", min: 75, max: null },
  { key: "high", label: "High", min: 50, max: 75 },
  { key: "medium", label: "Medium", min: 25, max: 50 },
  { key: "low", label: "Low", min: 0, max: 25 },
];

export function severityLevel(score) {
  return SEVERITY_LEVELS.find((level) => score >= level.min) ?? SEVERITY_LEVELS.at(-1);
}
